"""OAuth2 的 FastAPI HTTP 端点适配。

协议引擎仍在 :mod:`sa_token.oauth2`；这里仅处理 HTTP 表单/JSON 和标准错误响应。
授权页的 UI 与「用户是否同意」属于业务，本模块只提供授权成功后的跳转函数。
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode

try:
    from fastapi import APIRouter, Request
    from fastapi.params import Depends
    from fastapi.responses import JSONResponse, RedirectResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "该模块需要 fastapi，请执行：pip install fastapi"
    ) from exc

from ..oauth2 import OAuth2Error, OAuth2Server

__all__ = ["create_oauth2_router", "authorization_redirect"]


_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


async def _read_parameters(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except ValueError as exc:
            raise OAuth2Error("invalid_request", "请求体不是合法 JSON") from exc
        return payload if isinstance(payload, dict) else {}
    try:
        body = (await request.body()).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OAuth2Error("invalid_request", "请求体编码非法") from exc
    return dict(parse_qsl(body, keep_blank_values=True))


def _text(value: Any) -> str:
    """缺失、JSON null 和非字符串都当成空字符串，避免 ``str(None)`` 变成字面量 ``"None"``。"""
    return value if isinstance(value, str) else ""


def _scopes(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return str(value or "").split()


def _oauth_error(error: OAuth2Error) -> JSONResponse:
    status = 401 if error.error == "invalid_client" else error.http_status
    headers = dict(_NO_STORE_HEADERS)
    if status == 401:
        headers["WWW-Authenticate"] = 'Basic realm="oauth2"'
    return JSONResponse(
        {
            "error": error.error,
            "error_description": error.description,
        },
        status_code=status,
        headers=headers,
    )


def _client_credentials(
    request: Request,
    parameters: dict[str, Any],
) -> tuple[str, str | None]:
    """从 HTTP Basic 或请求体读取客户端身份。Basic 优先补上表单里缺的字段。"""
    client_id = parameters.get("client_id")
    client_secret = parameters.get("client_secret")
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        encoded = authorization.split(" ", 1)[1].strip()
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise OAuth2Error("invalid_client", "客户端认证格式无效") from exc
        basic_id, separator, basic_secret = decoded.partition(":")
        if separator:
            if not client_id:
                client_id = basic_id
            if client_secret in (None, ""):
                client_secret = basic_secret
    resolved_id = str(client_id or "")
    if not resolved_id:
        raise OAuth2Error("invalid_client", "缺少客户端认证")
    if client_secret is None:
        return resolved_id, None
    return resolved_id, str(client_secret)


def create_oauth2_router(
    server: OAuth2Server,
    *,
    prefix: str = "/oauth2",
    dependencies: Sequence[Depends] | None = None,
) -> APIRouter:
    """创建 token / introspect / revoke 路由。

    `/token` 同时接受 JSON 与 `application/x-www-form-urlencoded`，无需额外安装
    `python-multipart`。`/introspect` 与 `/revoke` 要求客户端认证。
    """
    router = APIRouter(prefix=prefix, tags=["OAuth2"], dependencies=list(dependencies or []))

    @router.post("/token")
    async def token_endpoint(request: Request) -> JSONResponse:
        try:
            parameters = await _read_parameters(request)
            grant_type = str(parameters.get("grant_type", ""))
            if grant_type == "authorization_code":
                response = await server.exchange_code_for_token(
                    code=str(parameters.get("code", "")),
                    client_id=str(parameters.get("client_id", "")),
                    client_secret=parameters.get("client_secret"),
                    redirect_uri=parameters.get("redirect_uri"),
                    code_verifier=parameters.get("code_verifier"),
                )
            elif grant_type == "refresh_token":
                response = await server.refresh_access_token(
                    refresh_token=str(parameters.get("refresh_token", "")),
                    client_id=str(parameters.get("client_id", "")),
                    client_secret=parameters.get("client_secret"),
                )
            elif grant_type == "client_credentials":
                response = await server.client_credentials_token(
                    client_id=str(parameters.get("client_id", "")),
                    client_secret=_text(parameters.get("client_secret")),
                    scopes=_scopes(parameters.get("scope")),
                )
            else:
                raise OAuth2Error("unsupported_grant_type", f"不支持的 grant_type: {grant_type}")
            return JSONResponse(response.to_dict(), headers=_NO_STORE_HEADERS)
        except OAuth2Error as error:
            return _oauth_error(error)

    async def _require_client(request: Request, parameters: dict[str, Any]) -> None:
        client_id, client_secret = _client_credentials(request, parameters)
        await server.authenticate_client(client_id, client_secret)

    @router.post("/introspect")
    async def introspect_endpoint(request: Request) -> JSONResponse:
        try:
            parameters = await _read_parameters(request)
            await _require_client(request, parameters)
            return JSONResponse(
                await server.introspect(str(parameters.get("token", ""))),
                headers=_NO_STORE_HEADERS,
            )
        except OAuth2Error as error:
            return _oauth_error(error)

    @router.post("/revoke")
    async def revoke_endpoint(request: Request) -> JSONResponse:
        try:
            parameters = await _read_parameters(request)
            await _require_client(request, parameters)
            await server.revoke_token(str(parameters.get("token", "")))
        except OAuth2Error as error:
            return _oauth_error(error)
        # RFC 7009：token 不存在时同样返回 200，避免泄露有效性。
        return JSONResponse({}, headers=_NO_STORE_HEADERS)

    return router


async def authorization_redirect(
    server: OAuth2Server,
    *,
    login_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
) -> RedirectResponse:
    """用户在业务授权页点击同意后，签发授权码并跳回客户端。"""
    code = await server.create_authorization_code(
        client_id=client_id,
        login_id=login_id,
        redirect_uri=redirect_uri,
        scopes=_scopes(scope),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        state=state,
    )
    parameters = {"code": code.code}
    if state:
        parameters["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(parameters)}")
