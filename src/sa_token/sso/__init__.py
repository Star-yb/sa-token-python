"""SSO 单点登录：ticket 换登录态 + 统一登出。

Server 与 Client 都只依赖核心存储与 ``StpLogic``，HTTP 跳转由使用方实现，
因此整条流程可以在单测里不起服务地跑通。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from ..exception import SaTokenException

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from ..manager import SaTokenManager

__all__ = ["SsoConfig", "SsoError", "SsoTicket", "SsoServer", "SsoClient"]


class SsoError(SaTokenException):
    http_status = 400


@dataclass
class SsoConfig:
    server_url: str = ""
    """认证中心的登录页地址。"""

    ticket_timeout: int = 300
    """ticket 有效期，应当很短：它只用于一次跳转。"""

    allowed_services: list[str] = field(default_factory=list)
    """允许接入的 service 白名单，空列表表示不限制（仅建议内网使用）。"""

    secret_key: str | None = None
    """跨进程 ticket 校验的 HMAC 密钥；生产环境建议配置至少 32 字节。"""

    def is_allowed_service(self, service: str) -> bool:
        return not self.allowed_services or service in self.allowed_services


@dataclass(frozen=True)
class SsoTicket:
    ticket: str
    service: str
    signature: str | None = None


class SsoServer:
    """认证中心。"""

    def __init__(self, manager: SaTokenManager, config: SsoConfig | None = None) -> None:
        self._manager = manager
        self.config = config or SsoConfig()

    def _key(self, suffix: str, identifier: str) -> str:
        return self._manager.config.make_key("sso", suffix, identifier)

    @property
    def _storage(self):
        return self._manager.storage

    async def create_ticket(self, login_id: str, service: str) -> str:
        """用户在认证中心登录后，为目标应用签发一次性 ticket。"""
        if not self.config.is_allowed_service(service):
            raise SsoError(f"service 未在白名单中：{service}")
        ticket = secrets.token_urlsafe(24)
        # ticket 绑定 service，避免 A 应用拿到的 ticket 被拿去登录 B 应用。
        await self._storage.set(
            self._key("ticket", ticket),
            f"{login_id}\n{service}",
            self.config.ticket_timeout,
        )
        await self._register_service(login_id, service)
        return ticket

    async def create_signed_ticket(self, login_id: str, service: str) -> SsoTicket:
        """签发 ticket，并在配置密钥时附带 HMAC 签名。"""
        ticket = await self.create_ticket(login_id, service)
        return SsoTicket(
            ticket=ticket,
            service=service,
            signature=self.sign_ticket(ticket, service),
        )

    def sign_ticket(self, ticket: str, service: str) -> str | None:
        if not self.config.secret_key:
            return None
        payload = f"{ticket}\n{service}".encode()
        return hmac.new(
            self.config.secret_key.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

    def verify_ticket_signature(
        self, ticket: str, service: str, signature: str | None
    ) -> None:
        expected = self.sign_ticket(ticket, service)
        if expected is None:
            return
        if signature is None or not hmac.compare_digest(expected, signature):
            raise SsoError("ticket 签名无效")

    async def validate_ticket(
        self,
        ticket: str,
        service: str,
        *,
        signature: str | None = None,
    ) -> str:
        """校验并消费 ticket，返回 ``login_id``。

        读取即删除：ticket 必须一次性，否则中间人可以重放它换取会话。
        """
        self.verify_ticket_signature(ticket, service, signature)
        key = self._key("ticket", ticket)
        raw = await self._storage.get(key)
        if raw is None:
            raise SsoError("ticket 无效或已过期")
        if not await self._storage.compare_and_delete(key, raw):
            raise SsoError("ticket 已被使用")
        login_id, bound_service = raw.split("\n", 1)
        if bound_service != service:
            raise SsoError("ticket 与 service 不匹配")
        return login_id

    async def _register_service(self, login_id: str, service: str) -> None:
        """记录该用户在哪些应用登录过，统一登出时需要逐个通知。"""
        key = self._key("services", login_id)
        for _ in range(12):
            raw = await self._storage.get(key)
            services = raw.split("\n") if raw else []
            if service in services:
                return
            services.append(service)
            new_raw = "\n".join(services)
            if raw is None:
                if await self._storage.set_if_absent(key, new_raw):
                    return
            elif await self._storage.compare_and_set(key, raw, new_raw):
                return
        raise SsoError("并发登记 SSO service 失败，请稍后重试")

    async def get_registered_services(self, login_id: str) -> list[str]:
        raw = await self._storage.get(self._key("services", login_id))
        return raw.split("\n") if raw else []

    async def logout(self, login_id: str) -> list[str]:
        """统一登出：清掉认证中心会话，返回需要通知的客户端列表。

        实际的 HTTP 回调由使用方发起——通知方式（同步 HTTP、消息队列）
        取决于部署形态，不应该由库来替用户决定。
        """
        services = await self.get_registered_services(login_id)
        await self._manager.stp().logout(login_id)
        await self._storage.delete(self._key("services", login_id))
        return services

    def build_login_url(self, service: str, *, redirect: str | None = None) -> str:
        params = {"service": service}
        if redirect:
            params["redirect"] = redirect
        separator = "&" if "?" in self.config.server_url else "?"
        return f"{self.config.server_url}{separator}{urlencode(params)}"


class SsoClient:
    """接入方应用。"""

    def __init__(
        self,
        manager: SaTokenManager,
        *,
        server_url: str,
        service: str,
        login_type: str = "login",
    ) -> None:
        self._manager = manager
        self.server_url = server_url
        self.service = service
        self.login_type = login_type

    def get_login_url(self, redirect: str | None = None) -> str:
        params = {"service": self.service}
        if redirect:
            params["redirect"] = redirect
        separator = "&" if "?" in self.server_url else "?"
        return f"{self.server_url}{separator}{urlencode(params)}"

    async def login_by_ticket(
        self,
        server: SsoServer,
        ticket: str,
        *,
        device: str | None = None,
        signature: str | None = None,
    ) -> str:
        """同进程部署时直接校验 ticket 并建立本地登录态。"""
        login_id = await server.validate_ticket(
            ticket,
            self.service,
            signature=signature,
        )
        return await self._manager.stp(self.login_type).login(login_id, device=device)

    async def login_by_login_id(self, login_id: str, *, device: str | None = None) -> str:
        """跨进程部署时，ticket 已由 HTTP 调用认证中心换成 login_id。"""
        return await self._manager.stp(self.login_type).login(login_id, device=device)

    async def handle_logout(self, login_id: str) -> None:
        """收到认证中心的登出通知后，清掉本地会话。"""
        await self._manager.stp(self.login_type).logout(login_id)
