"""OAuth2 授权码流程。

只依赖核心的存储抽象，不依赖任何 Web 框架，因此协议逻辑可以在单测里
纯函数式地跑通；HTTP 端点由使用方按自己的框架挂载。

签发出来的 access_token 是**有状态**的：存储里删掉即刻失效，
与本项目「服务端必须能即时作废凭证」的整体语义一致。
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import TYPE_CHECKING

from ..exception import SaTokenException
from .model import AccessTokenInfo, AuthorizationCode, OAuth2Client, TokenResponse

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from ..manager import SaTokenManager

__all__ = ["OAuth2Error", "OAuth2Server", "generate_pkce_pair"]

logger = logging.getLogger("sa_token.oauth2")


_OAUTH2_STATUS = {
    "invalid_client": 401,
    "invalid_token": 401,
    "insufficient_scope": 403,
}


class OAuth2Error(SaTokenException):
    """OAuth2 协议错误，``error`` 为规范定义的错误码。"""

    http_status = 400

    def __init__(self, error: str, description: str) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.http_status = _OAUTH2_STATUS.get(error, 400)


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class OAuth2Server:
    """授权服务端。

    支持 ``authorization_code``（含 PKCE）与 ``refresh_token`` 两种授权类型。
    """

    def __init__(
        self,
        manager: SaTokenManager,
        *,
        code_timeout: int = 300,
        access_token_timeout: int = 7200,
        refresh_token_timeout: int = 2592000,
        allow_plain_pkce: bool = False,
    ) -> None:
        self._manager = manager
        self.code_timeout = code_timeout
        self.access_token_timeout = access_token_timeout
        self.refresh_token_timeout = refresh_token_timeout
        self.allow_plain_pkce = allow_plain_pkce

    # 存储键 ---------------------------------------------------------------

    def _key(self, suffix: str, identifier: str) -> str:
        return self._manager.config.make_key("oauth2", suffix, identifier)

    @property
    def _storage(self):
        return self._manager.storage

    # 客户端 ---------------------------------------------------------------

    async def register_client(self, client: OAuth2Client) -> None:
        await self._storage.set(self._key("client", client.client_id), client.to_json())

    async def get_client(self, client_id: str) -> OAuth2Client | None:
        raw = await self._storage.get(self._key("client", client_id))
        return OAuth2Client.from_json(raw) if raw else None

    async def remove_client(self, client_id: str) -> None:
        await self._storage.delete(self._key("client", client_id))

    async def _require_client(self, client_id: str) -> OAuth2Client:
        client = await self.get_client(client_id)
        if client is None:
            raise OAuth2Error("invalid_client", f"未注册的 client_id: {client_id}")
        return client

    async def authenticate_client(
        self,
        client_id: str,
        client_secret: str | None,
    ) -> OAuth2Client:
        """校验已注册客户端。机密客户端必须带正确的 client_secret。"""
        client = await self._require_client(client_id)
        self._verify_client_secret(client, client_secret)
        return client

    # 授权码 ---------------------------------------------------------------

    async def create_authorization_code(
        self,
        *,
        client_id: str,
        login_id: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str = "S256",
        state: str | None = None,
    ) -> AuthorizationCode:
        """用户在授权页点击「同意」之后调用。"""
        client = await self._require_client(client_id)
        if not client.allows_redirect(redirect_uri):
            raise OAuth2Error("invalid_request", "redirect_uri 未在客户端注册列表中")
        if "authorization_code" not in client.grant_types:
            raise OAuth2Error("unauthorized_client", "客户端不支持 authorization_code")
        if client.is_public and not code_challenge:
            raise OAuth2Error("invalid_request", "公开客户端必须使用 PKCE")
        self._check_pkce_method(code_challenge_method)

        requested = list(scopes or client.scopes)
        invalid = [scope for scope in requested if scope not in client.scopes]
        if invalid:
            raise OAuth2Error("invalid_scope", f"未授权的 scope: {', '.join(invalid)}")

        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            client_id=client_id,
            login_id=login_id,
            redirect_uri=redirect_uri,
            scopes=requested,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            state=state,
        )
        await self._storage.set(self._key("code", code.code), code.to_json(), self.code_timeout)
        return code

    async def _consume_code(self, code: str) -> AuthorizationCode:
        """原子消费授权码：读取即删除，防止重放。"""
        key = self._key("code", code)
        raw = await self._storage.get(key)
        if raw is None:
            raise OAuth2Error("invalid_grant", "授权码无效或已过期")
        if not await self._storage.compare_and_delete(key, raw):
            # 删除失败说明已被并发请求取走，同样按重放处理。
            raise OAuth2Error("invalid_grant", "授权码已被使用")
        parsed = AuthorizationCode.from_json(raw)
        if parsed is None:
            raise OAuth2Error("invalid_grant", "授权码数据损坏")
        return parsed

    # 令牌 -----------------------------------------------------------------

    async def exchange_code_for_token(
        self,
        *,
        code: str,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        client = await self._require_client(client_id)
        self._verify_client_secret(client, client_secret)

        authorization_code = await self._consume_code(code)
        if authorization_code.client_id != client_id:
            raise OAuth2Error("invalid_grant", "授权码不属于该客户端")
        # 授权码签发时一定绑定了 redirect_uri。RFC 6749 4.1.3 要求换令牌时
        # 原样带回并逐字比较，缺省不能兑换。
        if redirect_uri is None or authorization_code.redirect_uri != redirect_uri:
            raise OAuth2Error("invalid_grant", "redirect_uri 与申请时不一致")
        self._verify_pkce(authorization_code, code_verifier)

        return await self._issue_tokens(
            client_id=client_id,
            login_id=authorization_code.login_id,
            scopes=authorization_code.scopes,
        )

    async def refresh_access_token(
        self,
        *,
        refresh_token: str,
        client_id: str,
        client_secret: str | None = None,
    ) -> TokenResponse:
        client = await self._require_client(client_id)
        self._verify_client_secret(client, client_secret)

        key = self._key("refresh", refresh_token)
        raw = await self._storage.get(key)
        if raw is None:
            raise OAuth2Error("invalid_grant", "refresh_token 无效或已过期")
        info = AccessTokenInfo.from_json(raw)
        if info is None or info.client_id != client_id:
            raise OAuth2Error("invalid_grant", "refresh_token 不属于该客户端")

        # 原子消费并轮转：并发刷新时只能有一个请求成功。
        if not await self._storage.compare_and_delete(key, raw):
            raise OAuth2Error("invalid_grant", "refresh_token 已被使用")
        try:
            response = await self._issue_tokens(
                client_id=client_id, login_id=info.login_id, scopes=info.scopes
            )
        except Exception:
            await self._storage.set(key, raw, self.refresh_token_timeout)
            raise
        try:
            await self._storage.delete(self._key("access", info.access_token))
        except Exception:
            logger.exception("旧 access_token 清理失败：client_id=%s", client_id)
        return response

    async def client_credentials_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        scopes: list[str] | None = None,
    ) -> TokenResponse:
        """机器到机器的 ``client_credentials`` 授权。

        公开客户端不能使用该模式；返回的 access token 不签发 refresh token，
        因为客户端可随时用自己的凭证重新申请。
        """
        client = await self._require_client(client_id)
        if client.is_public:
            raise OAuth2Error("unauthorized_client", "公开客户端不能使用 client_credentials")
        self._verify_client_secret(client, client_secret)
        if "client_credentials" not in client.grant_types:
            raise OAuth2Error("unauthorized_client", "客户端未启用 client_credentials")
        requested = list(scopes or client.scopes)
        invalid = [scope for scope in requested if scope not in client.scopes]
        if invalid:
            raise OAuth2Error("invalid_scope", f"未授权的 scope: {', '.join(invalid)}")

        access_token = secrets.token_urlsafe(32)
        info = AccessTokenInfo(
            access_token=access_token,
            client_id=client_id,
            login_id=f"client:{client_id}",
            scopes=requested,
            expires_in=self.access_token_timeout,
        )
        await self._storage.set(
            self._key("access", access_token),
            info.to_json(),
            self.access_token_timeout,
        )
        return TokenResponse(
            access_token=access_token,
            expires_in=self.access_token_timeout,
            scope=" ".join(requested),
        )

    async def introspect(self, access_token: str) -> dict[str, object]:
        """返回适合 RFC 7662 introspection 端点的结果。"""
        raw = await self._storage.get(self._key("access", access_token))
        info = AccessTokenInfo.from_json(raw) if raw else None
        if info is None:
            return {"active": False}
        return {
            "active": True,
            "client_id": info.client_id,
            "sub": info.login_id,
            "scope": " ".join(info.scopes),
            "token_type": "Bearer",
        }

    async def _issue_tokens(
        self,
        *,
        client_id: str,
        login_id: str,
        scopes: list[str],
    ) -> TokenResponse:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        info = AccessTokenInfo(
            access_token=access_token,
            client_id=client_id,
            login_id=login_id,
            scopes=scopes,
            expires_in=self.access_token_timeout,
            refresh_token=refresh_token,
        )
        await self._storage.set(
            self._key("access", access_token), info.to_json(), self.access_token_timeout
        )
        await self._storage.set(
            self._key("refresh", refresh_token), info.to_json(), self.refresh_token_timeout
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_token_timeout,
            scope=" ".join(scopes),
        )

    async def verify_access_token(self, access_token: str) -> AccessTokenInfo:
        raw = await self._storage.get(self._key("access", access_token))
        if raw is None:
            raise OAuth2Error("invalid_token", "access_token 无效或已过期")
        info = AccessTokenInfo.from_json(raw)
        if info is None:
            raise OAuth2Error("invalid_token", "access_token 数据损坏")
        return info

    async def check_scope(self, access_token: str, scope: str) -> AccessTokenInfo:
        info = await self.verify_access_token(access_token)
        if scope not in info.scopes:
            raise OAuth2Error("insufficient_scope", f"缺少 scope: {scope}")
        return info

    async def revoke_token(self, token: str) -> bool:
        """吊销 access_token 或 refresh_token，并一并作废配对的另一张凭证。"""
        revoked = False
        for suffix in ("access", "refresh"):
            key = self._key(suffix, token)
            raw = await self._storage.get(key)
            if raw is None:
                continue
            info = AccessTokenInfo.from_json(raw)
            await self._storage.delete(key)
            revoked = True
            if info is None:
                continue
            if suffix == "access" and info.refresh_token:
                await self._storage.delete(self._key("refresh", info.refresh_token))
            elif suffix == "refresh" and info.access_token:
                await self._storage.delete(self._key("access", info.access_token))
        return revoked

    def build_authorize_url(
        self,
        *,
        authorize_endpoint: str,
        client_id: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str = "S256",
    ) -> str:
        """给客户端生成跳转到授权页的 URL。"""
        from urllib.parse import urlencode

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        }
        if scopes:
            params["scope"] = " ".join(scopes)
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method
        separator = "&" if "?" in authorize_endpoint else "?"
        return f"{authorize_endpoint}{separator}{urlencode(params)}"

    # 校验 -----------------------------------------------------------------

    @staticmethod
    def _verify_client_secret(client: OAuth2Client, client_secret: str | None) -> None:
        if client.is_public:
            return
        if not client_secret or not secrets.compare_digest(
            client.client_secret or "", client_secret
        ):
            raise OAuth2Error("invalid_client", "client_secret 不正确")

    def _check_pkce_method(self, method: str) -> None:
        if method == "S256":
            return
        if method == "plain" and self.allow_plain_pkce:
            return
        if method == "plain":
            raise OAuth2Error("invalid_request", "不支持 plain 方式的 PKCE")
        raise OAuth2Error("invalid_request", "未知的 code_challenge_method")

    def _verify_pkce(self, code: AuthorizationCode, code_verifier: str | None) -> None:
        if not code.code_challenge:
            return
        if not code_verifier:
            raise OAuth2Error("invalid_grant", "缺少 code_verifier")
        self._check_pkce_method(code.code_challenge_method)
        expected = code_verifier if code.code_challenge_method == "plain" else _s256(code_verifier)
        if not secrets.compare_digest(expected, code.code_challenge):
            raise OAuth2Error("invalid_grant", "code_verifier 校验失败")


def generate_pkce_pair() -> tuple[str, str]:
    """生成 ``(code_verifier, code_challenge)``，供客户端使用。"""
    verifier = secrets.token_urlsafe(48)
    return verifier, _s256(verifier)
