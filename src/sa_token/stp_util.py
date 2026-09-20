"""StpUtil：全局静态门面。

方法签名与 :class:`~sa_token.stp_logic.StpLogic` 一一对应，只是省去了手动
传递 Manager。这里刻意逐个显式声明而不是用 ``__getattr__`` 转发，
这样 IDE 补全、类型检查和文档都能正常工作。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .context import get_current_login_id, get_current_token
from .exception import SaTokenNotInitializedException
from .model import DEFAULT_LOGIN_TYPE, TerminalInfo, TokenInfo
from .permission import MatchMode

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from .manager import SaTokenManager
    from .security import LoginTokenPair
    from .session import SaSession
    from .stp_logic import StpLogic

__all__ = ["StpUtil", "set_manager", "get_manager", "clear_manager"]

_manager: SaTokenManager | None = None


def set_manager(manager: SaTokenManager) -> None:
    """设置全局 Manager，一般由 ``SaTokenBuilder.build()`` 自动调用。"""
    global _manager
    _manager = manager


def get_manager() -> SaTokenManager:
    if _manager is None:
        raise SaTokenNotInitializedException()
    return _manager


def clear_manager() -> None:
    """清除全局实例，主要给测试做隔离。"""
    global _manager
    _manager = None


class StpUtil:
    """默认账号体系（``login``）的静态门面。"""

    @staticmethod
    def logic(login_type: str = DEFAULT_LOGIN_TYPE) -> StpLogic:
        """取得底层 StpLogic，用于访问门面未暴露的高级能力。"""
        return get_manager().stp(login_type)

    # 认证 -----------------------------------------------------------------

    @staticmethod
    async def login(
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
        tag: str | None = None,
        extra: dict[str, Any] | None = None,
        token_value: str | None = None,
    ) -> str:
        return await StpUtil.logic().login(
            login_id,
            device=device,
            timeout=timeout,
            tag=tag,
            extra=extra,
            token_value=token_value,
        )

    @staticmethod
    async def login_with_refresh(
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
        tag: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> LoginTokenPair:
        return await StpUtil.logic().login_with_refresh(
            login_id,
            device=device,
            timeout=timeout,
            tag=tag,
            extra=extra,
        )

    @staticmethod
    async def refresh_access_token(refresh_token: str) -> LoginTokenPair:
        return await get_manager().refresh_tokens.refresh(refresh_token)

    @staticmethod
    async def logout(login_id: Any, *, device: str | None = None) -> None:
        await StpUtil.logic().logout(login_id, device=device)

    @staticmethod
    async def logout_by_token(token: str | None = None) -> None:
        await StpUtil.logic().logout_by_token(token)

    @staticmethod
    async def kickout(login_id: Any, *, device: str | None = None) -> None:
        await StpUtil.logic().kickout(login_id, device=device)

    @staticmethod
    async def kickout_by_token(token: str | None = None) -> None:
        await StpUtil.logic().kickout_by_token(token)

    @staticmethod
    async def replaced(login_id: Any, *, device: str | None = None) -> None:
        await StpUtil.logic().replaced(login_id, device=device)

    @staticmethod
    async def is_login(token: str | None = None) -> bool:
        return await StpUtil.logic().is_login(token)

    @staticmethod
    async def check_login(token: str | None = None) -> str:
        return await StpUtil.logic().check_login(token)

    @staticmethod
    async def get_login_id(token: str | None = None) -> str:
        return await StpUtil.logic().get_login_id(token)

    @staticmethod
    async def get_login_id_or_none(token: str | None = None) -> str | None:
        return await StpUtil.logic().get_login_id_or_none(token)

    @staticmethod
    def get_token_value() -> str | None:
        """当前调用链绑定的 token（由中间件或 ``sa_token_context`` 写入）。"""
        return get_current_token()

    @staticmethod
    def get_login_id_from_context() -> str | None:
        """当前调用链已校验过的 login_id，不产生任何存储访问。"""
        return get_current_login_id()

    @staticmethod
    async def get_token_info(token: str | None = None) -> TokenInfo | None:
        return await StpUtil.logic().get_token_info(token)

    @staticmethod
    async def get_offline_reason(token: str) -> dict[str, Any] | None:
        return await StpUtil.logic().get_offline_reason(token)

    @staticmethod
    async def renew_timeout(token: str, timeout: int) -> bool:
        return await StpUtil.logic().renew_timeout(token, timeout)

    # 权限 / 角色 -----------------------------------------------------------

    @staticmethod
    async def get_permissions(login_id: Any) -> list[str]:
        return await StpUtil.logic().get_permissions(login_id)

    @staticmethod
    async def set_permissions(login_id: Any, permissions: list[str]) -> None:
        await StpUtil.logic().set_permissions(login_id, permissions)

    @staticmethod
    async def add_permission(login_id: Any, permission: str) -> None:
        await StpUtil.logic().add_permission(login_id, permission)

    @staticmethod
    async def remove_permission(login_id: Any, permission: str) -> None:
        await StpUtil.logic().remove_permission(login_id, permission)

    @staticmethod
    async def clear_permissions(login_id: Any) -> None:
        await StpUtil.logic().clear_permissions(login_id)

    @staticmethod
    async def has_permission(login_id: Any, permission: str) -> bool:
        return await StpUtil.logic().has_permission(login_id, permission)

    @staticmethod
    async def has_permissions_and(login_id: Any, permissions: list[str]) -> bool:
        return await StpUtil.logic().has_permissions_and(login_id, permissions)

    @staticmethod
    async def has_permissions_or(login_id: Any, permissions: list[str]) -> bool:
        return await StpUtil.logic().has_permissions_or(login_id, permissions)

    @staticmethod
    async def check_permission(
        login_id: Any,
        permissions: str | list[str],
        *,
        mode: MatchMode = "OR",
    ) -> None:
        await StpUtil.logic().check_permission(login_id, permissions, mode=mode)

    @staticmethod
    async def get_roles(login_id: Any) -> list[str]:
        return await StpUtil.logic().get_roles(login_id)

    @staticmethod
    async def set_roles(login_id: Any, roles: list[str]) -> None:
        await StpUtil.logic().set_roles(login_id, roles)

    @staticmethod
    async def add_role(login_id: Any, role: str) -> None:
        await StpUtil.logic().add_role(login_id, role)

    @staticmethod
    async def remove_role(login_id: Any, role: str) -> None:
        await StpUtil.logic().remove_role(login_id, role)

    @staticmethod
    async def has_role(login_id: Any, role: str) -> bool:
        return await StpUtil.logic().has_role(login_id, role)

    @staticmethod
    async def has_roles_and(login_id: Any, roles: list[str]) -> bool:
        return await StpUtil.logic().has_roles_and(login_id, roles)

    @staticmethod
    async def has_roles_or(login_id: Any, roles: list[str]) -> bool:
        return await StpUtil.logic().has_roles_or(login_id, roles)

    @staticmethod
    async def check_role(
        login_id: Any,
        roles: str | list[str],
        *,
        mode: MatchMode = "OR",
    ) -> None:
        await StpUtil.logic().check_role(login_id, roles, mode=mode)

    # Session ---------------------------------------------------------------

    @staticmethod
    async def get_session(login_id: Any, *, create: bool = True) -> SaSession | None:
        return await StpUtil.logic().get_session(login_id, create=create)

    @staticmethod
    async def get_token_session(token: str | None = None) -> SaSession | None:
        return await StpUtil.logic().get_token_session(token)

    @staticmethod
    async def delete_session(login_id: Any) -> None:
        await StpUtil.logic().delete_session(login_id)

    # 封禁 -----------------------------------------------------------------

    @staticmethod
    async def disable(
        login_id: Any,
        seconds: int,
        *,
        service: str = "login",
        level: int = 1,
    ) -> None:
        await StpUtil.logic().disable(login_id, seconds, service=service, level=level)

    @staticmethod
    async def untie(login_id: Any, *, service: str = "login") -> None:
        await StpUtil.logic().untie(login_id, service=service)

    @staticmethod
    async def is_disable(login_id: Any, *, service: str = "login", level: int = 1) -> bool:
        return await StpUtil.logic().is_disable(login_id, service=service, level=level)

    @staticmethod
    async def get_disable_time(login_id: Any, *, service: str = "login") -> int:
        return await StpUtil.logic().get_disable_time(login_id, service=service)

    @staticmethod
    async def get_disable_level(login_id: Any, *, service: str = "login") -> int:
        return await StpUtil.logic().get_disable_level(login_id, service=service)

    @staticmethod
    async def check_disable(login_id: Any, *, service: str = "login", level: int = 1) -> None:
        await StpUtil.logic().check_disable(login_id, service=service, level=level)

    # 二级认证 --------------------------------------------------------------

    @staticmethod
    async def open_safe(token: str, business: str, seconds: int) -> None:
        await StpUtil.logic().open_safe(token, business, seconds)

    @staticmethod
    async def is_safe(token: str | None, business: str) -> bool:
        return await StpUtil.logic().is_safe(token, business)

    @staticmethod
    async def check_safe(token: str | None, business: str) -> None:
        await StpUtil.logic().check_safe(token, business)

    @staticmethod
    async def close_safe(token: str, business: str) -> None:
        await StpUtil.logic().close_safe(token, business)

    # 查询 -----------------------------------------------------------------

    @staticmethod
    async def get_terminal_list(login_id: Any, *, device: str | None = None) -> list[TerminalInfo]:
        return await StpUtil.logic().get_terminal_list(login_id, device=device)

    @staticmethod
    async def get_token_value_list_by_login_id(
        login_id: Any,
        *,
        device: str | None = None,
    ) -> list[str]:
        return await StpUtil.logic().get_token_value_list_by_login_id(login_id, device=device)

    @staticmethod
    async def search_token_value(
        keyword: str = "",
        *,
        start: int = 0,
        size: int = 100,
    ) -> list[str]:
        return await StpUtil.logic().search_token_value(keyword, start=start, size=size)

    @staticmethod
    async def search_session(
        keyword: str = "",
        *,
        start: int = 0,
        size: int = 100,
    ) -> list[str]:
        return await StpUtil.logic().search_session(keyword, start=start, size=size)

    # 安全工具 -------------------------------------------------------------

    @staticmethod
    async def issue_nonce(subject: Any, *, purpose: str = "default") -> str:
        return await get_manager().nonces.issue(str(subject), purpose=purpose)

    @staticmethod
    async def consume_nonce(
        nonce: str, subject: Any, *, purpose: str = "default"
    ) -> None:
        await get_manager().nonces.consume(nonce, str(subject), purpose=purpose)

    @staticmethod
    async def create_temp_token(
        value: Any,
        timeout: int,
        *,
        namespace: str = "default",
        record_index: bool = False,
    ) -> str:
        return await get_manager().temp_tokens.create(
            value,
            timeout,
            namespace=namespace,
            record_index=record_index,
        )

    @staticmethod
    async def parse_temp_token(token: str, *, namespace: str = "default") -> Any | None:
        return await get_manager().temp_tokens.parse(token, namespace=namespace)

    @staticmethod
    async def consume_temp_token(token: str, *, namespace: str = "default") -> Any | None:
        return await get_manager().temp_tokens.consume(token, namespace=namespace)

    @staticmethod
    async def delete_temp_token(token: str, *, namespace: str = "default") -> bool:
        return await get_manager().temp_tokens.delete(token, namespace=namespace)
