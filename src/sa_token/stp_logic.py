"""StpLogic：认证鉴权的唯一实现。

这是整个项目的核心。框架适配层、OAuth2、SSO、在线用户全部复用这里的方法，
禁止在上层重新实现登录校验或权限匹配，否则语义一定会分叉。

所有方法都不感知 HTTP：参数要么是 ``login_id``，要么是 ``token`` 字符串。
因此脚本、定时任务、RPC 与 Web 接口用的是同一套逻辑。
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .context import get_current_token, set_current
from .exception import (
    DisableException,
    NotLoginException,
    NotLoginType,
    NotPermissionException,
    NotRoleException,
    NotSafeException,
    SaTokenException,
)
from .listener import Event, EventData, fingerprint
from .model import (
    DEFAULT_DEVICE,
    SessionData,
    TerminalInfo,
    TokenInfo,
    now_ms,
)
from .permission import MatchMode, has_element, match_all, match_any
from .session import SaSession

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from .config import SaTokenConfig
    from .manager import SaTokenManager
    from .security import LoginTokenPair
    from .storage.base import SaStorage

__all__ = ["StpLogic"]

#: 默认的封禁服务名，对应「整个账号被封」。
DEFAULT_DISABLE_SERVICE = "login"


class StpLogic:
    """单个账号体系（``login_type``）的认证逻辑。

    同一个 Manager 下可以有多个 ``StpLogic``（如 ``user`` 与 ``admin``），
    它们的存储键互相隔离，同一个 ``login_id`` 在两套体系里是两个独立身份。
    """

    def __init__(self, manager: SaTokenManager, login_type: str = "login") -> None:
        self._manager = manager
        self.login_type = login_type

    # ------------------------------------------------------------------ 基础设施

    @property
    def config(self) -> SaTokenConfig:
        return self._manager.config

    @property
    def storage(self) -> SaStorage:
        return self._manager.storage

    def _token_key(self, token: str) -> str:
        return self.config.make_key(self.login_type, "token", token)

    def _session_key(self, login_id: str) -> str:
        return self.config.make_key(self.login_type, "session", login_id)

    def _token_session_key(self, token: str) -> str:
        return self.config.make_key(self.login_type, "token-session", token)

    def _last_active_key(self, token: str) -> str:
        return self.config.make_key(self.login_type, "last-active", token)

    def _permission_key(self, login_id: str) -> str:
        return self.config.make_key(self.login_type, "permission", login_id)

    def _role_key(self, login_id: str) -> str:
        return self.config.make_key(self.login_type, "role", login_id)

    def _permission_cache_key(self, login_id: str, kind: str) -> str:
        return self.config.make_key(self.login_type, f"{kind}-cache", login_id)

    def _disable_key(self, login_id: str, service: str) -> str:
        return self.config.make_key(self.login_type, "disable", f"{login_id}:{service}")

    def _safe_key(self, token: str, business: str) -> str:
        return self.config.make_key(self.login_type, "safe", f"{token}:{business}")

    def _session_ttl(self) -> int | None:
        return None if self.config.timeout < 0 else self.config.timeout

    @staticmethod
    def normalize_login_id(login_id: Any) -> str:
        """统一成字符串并拒绝会破坏存储键的取值。"""
        if login_id is None:
            raise SaTokenException("login_id 不能为空")
        normalized = str(login_id).strip()
        if not normalized:
            raise SaTokenException("login_id 不能为空")
        if ":" in normalized:
            raise SaTokenException("login_id 不能包含冒号，它与存储键分隔符冲突")
        return normalized

    async def _emit(
        self,
        event: Event,
        *,
        login_id: str | None = None,
        device: str | None = None,
        token: str | None = None,
        **detail: Any,
    ) -> None:
        await self._manager.events.emit(
            EventData(
                event=event,
                login_id=login_id,
                login_type=self.login_type,
                device=device,
                token_fingerprint=fingerprint(token),
                detail=detail,
            )
        )

    # ------------------------------------------------------------------ 登录

    async def login(
        self,
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
        tag: str | None = None,
        extra: dict[str, Any] | None = None,
        token_value: str | None = None,
    ) -> str:
        """登录并返回 token。

        业务侧负责校验账号密码，本方法只负责签发与记录登录态。
        """
        normalized_id = self.normalize_login_id(login_id)
        device_name = device or DEFAULT_DEVICE
        await self.check_disable(normalized_id)

        effective_timeout = self.config.timeout if timeout is None else timeout
        session = await self.get_session(normalized_id, create=True)
        assert session is not None

        reused_token = await self._apply_concurrent_policy(session, normalized_id, device_name)
        if reused_token is not None:
            return reused_token

        token, info = await self._allocate_token(
            normalized_id,
            device_name,
            effective_timeout,
            tag,
            extra,
            token_value,
        )
        await self._touch_active(token, effective_timeout)

        session.raw.history_terminal_count += 1
        session.raw.terminal_list.append(
            TerminalInfo(
                token=token,
                device=device_name,
                index=session.raw.history_terminal_count,
            )
        )
        await self._enforce_max_login_count(session)
        await session.save()

        await self._emit(Event.LOGIN, login_id=normalized_id, device=device_name, token=token)
        return token

    async def login_with_refresh(
        self,
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
        tag: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> LoginTokenPair:
        """登录并签发 access/refresh token 对。"""
        normalized_id = self.normalize_login_id(login_id)
        device_name = device or DEFAULT_DEVICE
        access_token = await self.login(
            normalized_id,
            device=device_name,
            timeout=timeout,
            tag=tag,
            extra=extra,
        )
        return await self._manager.refresh_tokens.issue(
            access_token,
            normalized_id,
            login_type=self.login_type,
            device=device_name,
        )

    async def _allocate_token(
        self,
        login_id: str,
        device: str,
        timeout: int | None,
        tag: str | None,
        extra: dict[str, Any] | None,
        token_value: str | None,
    ) -> tuple[str, TokenInfo]:
        """原子占用 token；自定义值冲突时报错，随机值冲突则重试。"""
        if token_value is not None and not token_value.strip():
            raise SaTokenException("指定的 token_value 不能为空")
        attempts = 1 if token_value is not None else 12
        for _ in range(attempts):
            token = token_value or self._manager.strategy.generate(login_id, extra)
            info = TokenInfo(
                login_id=login_id,
                device=device,
                login_type=self.login_type,
                timeout=timeout,
                tag=tag,
            )
            if await self.storage.set_if_absent(self._token_key(token), info.to_json(), timeout):
                return token, info
        if token_value is not None:
            raise SaTokenException("指定的 token_value 已被占用")
        raise SaTokenException("无法分配唯一 token，请检查自定义 TokenStrategy")

    async def _apply_concurrent_policy(
        self,
        session: SaSession,
        login_id: str,
        device: str,
    ) -> str | None:
        """按 is_concurrent / is_share 处理已有登录，返回可复用的 token。"""
        if not self.config.is_concurrent:
            # 不允许并发在线：旧登录一律顶下线。
            scope_all = self.config.replaced_range == "all_device"
            await self._offline_terminals(
                session,
                login_id,
                device=None if scope_all else device,
                state=NotLoginType.BE_REPLACED,
            )
            return None

        if not self.config.is_share:
            return None

        # 共享模式：同设备类型复用同一个 token，前提是它仍然有效。
        for terminal in session.raw.terminal_list:
            if terminal.device != device:
                continue
            info = await self._read_token_info(terminal.token)
            if info is not None and not info.is_offline:
                return terminal.token
        return None

    async def _enforce_max_login_count(self, session: SaSession) -> None:
        limit = self.config.max_login_count
        if limit is None or limit <= 0:
            return
        overflow = len(session.raw.terminal_list) - limit
        if overflow <= 0:
            return

        mode = self.config.overflow_logout_mode
        state = {
            "kickout": NotLoginType.KICK_OUT,
            "replaced": NotLoginType.BE_REPLACED,
        }.get(mode)
        # 终端列表按登录时间追加，队首即最旧的登录。
        for terminal in session.raw.terminal_list[:overflow]:
            if state is None:
                await self._destroy_token(terminal.token)
            else:
                await self._mark_token_offline(terminal.token, state)
        session.raw.terminal_list = session.raw.terminal_list[overflow:]

    # ------------------------------------------------------------------ 登出 / 踢人

    async def logout(self, login_id: Any, *, device: str | None = None) -> None:
        """主动登出：token 记录直接删除，不留下线原因。"""
        normalized_id = self.normalize_login_id(login_id)
        session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        removed = await self._remove_terminals(session, device, destroy=True)
        await self._save_or_drop_session(session, normalized_id)
        if device is None:
            await self._manager.refresh_tokens.revoke_all_for_login(
                self.login_type, normalized_id
            )
        if removed:
            await self._emit(Event.LOGOUT, login_id=normalized_id, device=device)

    async def logout_by_token(
        self, token: str | None = None, *, revoke_refresh: bool = True
    ) -> None:
        """登出单个 token，常用于「只退出当前设备」。"""
        token = token or get_current_token()
        if not token:
            return
        info = await self._read_token_info(token)
        if revoke_refresh:
            await self._manager.refresh_tokens.revoke_for_access(token)
        await self._destroy_token(token)
        if info is None:
            return
        session = await self.get_session(info.login_id, create=False)
        if session is not None:
            session.raw.terminal_list = [
                terminal for terminal in session.raw.terminal_list if terminal.token != token
            ]
            await self._save_or_drop_session(session, info.login_id)
        await self._emit(
            Event.LOGOUT, login_id=info.login_id, device=info.device, token=token
        )

    async def kickout(self, login_id: Any, *, device: str | None = None) -> None:
        """踢人下线：保留下线原因，用户下次请求会收到 ``KICK_OUT``。"""
        await self._offline_by_login_id(login_id, device, NotLoginType.KICK_OUT, Event.KICKOUT)

    async def kickout_by_token(self, token: str | None = None) -> None:
        """按 token 踢人，保留 ``KICK_OUT`` 原因并移除对应终端。"""
        token = token or get_current_token()
        if not token:
            return
        info = await self._read_token_info(token)
        if info is None:
            return
        await self._manager.refresh_tokens.revoke_for_access(token)
        await self._mark_token_offline(token, NotLoginType.KICK_OUT)
        session = await self.get_session(info.login_id, create=False)
        if session is not None:
            session.raw.terminal_list = [
                terminal for terminal in session.raw.terminal_list if terminal.token != token
            ]
            await self._save_or_drop_session(session, info.login_id)
        await self._emit(
            Event.KICKOUT,
            login_id=info.login_id,
            device=info.device,
            token=token,
        )

    async def replaced(self, login_id: Any, *, device: str | None = None) -> None:
        """顶号下线：语义上「被新登录挤掉」，与踢人区分开便于前端提示。"""
        await self._offline_by_login_id(login_id, device, NotLoginType.BE_REPLACED, Event.REPLACED)

    async def _offline_by_login_id(
        self,
        login_id: Any,
        device: str | None,
        state: NotLoginType,
        event: Event,
    ) -> None:
        normalized_id = self.normalize_login_id(login_id)
        session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        offline_count = await self._offline_terminals(session, normalized_id, device, state)
        await self._save_or_drop_session(session, normalized_id)
        if device is None:
            await self._manager.refresh_tokens.revoke_all_for_login(
                self.login_type, normalized_id
            )
        if offline_count:
            await self._emit(event, login_id=normalized_id, device=device)

    async def _offline_terminals(
        self,
        session: SaSession,
        login_id: str,
        device: str | None,
        state: NotLoginType,
    ) -> int:
        """把匹配的终端标记为下线状态，并从终端列表移除。"""
        matched = [
            terminal
            for terminal in session.raw.terminal_list
            if device is None or terminal.device == device
        ]
        for terminal in matched:
            await self._mark_token_offline(terminal.token, state)
        if matched:
            removed = {terminal.token for terminal in matched}
            session.raw.terminal_list = [
                terminal
                for terminal in session.raw.terminal_list
                if terminal.token not in removed
            ]
        return len(matched)

    async def _remove_terminals(
        self,
        session: SaSession,
        device: str | None,
        *,
        destroy: bool,
    ) -> int:
        matched = [
            terminal
            for terminal in session.raw.terminal_list
            if device is None or terminal.device == device
        ]
        for terminal in matched:
            if destroy:
                await self._destroy_token(terminal.token)
        if matched:
            removed = {terminal.token for terminal in matched}
            session.raw.terminal_list = [
                terminal
                for terminal in session.raw.terminal_list
                if terminal.token not in removed
            ]
        return len(matched)

    async def _save_or_drop_session(self, session: SaSession, login_id: str) -> None:
        """没有终端在线且未配置保留时，顺手清掉 Account-Session。"""
        if not session.raw.terminal_list and not self.config.is_logout_keep_session:
            await self.storage.delete(self._session_key(login_id))
            return
        await session.save()

    async def _destroy_token(self, token: str) -> None:
        await self.storage.delete(self._token_key(token))
        await self.storage.delete(self._token_session_key(token))
        await self.storage.delete(self._last_active_key(token))

    async def _mark_token_offline(self, token: str, state: NotLoginType) -> None:
        if not self.config.offline_record_enabled:
            await self._destroy_token(token)
            return
        info = await self._read_token_info(token)
        if info is None:
            return
        info.state = state.value
        info.offline_time = now_ms()
        await self.storage.set(
            self._token_key(token), info.to_json(), self.config.offline_record_timeout
        )
        await self.storage.delete(self._token_session_key(token))
        await self.storage.delete(self._last_active_key(token))

    # ------------------------------------------------------------------ 校验

    async def check_login(self, token: str | None = None) -> str:
        """校验登录态，返回 ``login_id``；失败抛 :class:`NotLoginException`。"""
        token = token or get_current_token()
        if not token:
            raise NotLoginException(NotLoginType.NOT_TOKEN, login_type=self.login_type)

        info = await self._read_token_info(token)
        if info is None:
            raise NotLoginException(
                NotLoginType.INVALID_TOKEN, login_type=self.login_type, token=token
            )
        if info.is_offline:
            offline_type = info.offline_type
            assert offline_type is not None
            raise NotLoginException(offline_type, login_type=self.login_type, token=token)

        await self._check_active_timeout(token, info)
        await self.check_disable(info.login_id)
        await self._renew(token, info)

        set_current(token, info.login_id)
        return info.login_id

    async def is_login(self, token: str | None = None) -> bool:
        """:meth:`check_login` 的布尔包装，不抛异常。"""
        try:
            await self.check_login(token)
            return True
        except (NotLoginException, DisableException):
            return False

    async def get_login_id(self, token: str | None = None) -> str:
        return await self.check_login(token)

    async def get_login_id_or_none(self, token: str | None = None) -> str | None:
        try:
            return await self.check_login(token)
        except (NotLoginException, DisableException):
            return None

    async def get_token_info(self, token: str | None = None) -> TokenInfo | None:
        token = token or get_current_token()
        if not token:
            return None
        return await self._read_token_info(token)

    async def get_offline_reason(self, token: str) -> dict[str, Any] | None:
        """查询被踢 / 被顶的下线原因与时间。"""
        info = await self._read_token_info(token)
        if info is None or not info.is_offline:
            return None
        return {"reason": info.state, "time": info.offline_time}

    async def _read_token_info(self, token: str) -> TokenInfo | None:
        raw = await self.storage.get(self._token_key(token))
        if raw is None:
            return None
        return TokenInfo.from_json(raw)

    async def _write_token_info(self, token: str, info: TokenInfo, timeout: int | None) -> None:
        await self.storage.set(self._token_key(token), info.to_json(), timeout)

    async def _check_active_timeout(self, token: str, info: TokenInfo) -> None:
        active_timeout = (
            info.active_timeout
            if self.config.dynamic_active_timeout and info.active_timeout is not None
            else self.config.active_timeout
        )
        if active_timeout is None or active_timeout < 0:
            return
        raw = await self.storage.get(self._last_active_key(token))
        last_active = int(raw) if raw and raw.isdigit() else info.active_time
        if now_ms() - last_active > active_timeout * 1000:
            await self._mark_token_offline(token, NotLoginType.TOKEN_FREEZE)
            raise NotLoginException(
                NotLoginType.TOKEN_FREEZE, login_type=self.login_type, token=token
            )

    async def _touch_active(self, token: str, timeout: int | None) -> None:
        if self.config.active_timeout < 0 and not self.config.dynamic_active_timeout:
            return
        await self.storage.set(self._last_active_key(token), str(now_ms()), timeout)

    async def _renew(self, token: str, info: TokenInfo) -> None:
        """续期在校验通过后同步执行。

        这里刻意不用后台任务：``asyncio.create_task`` 产生的孤儿任务在请求
        结束、事件循环关闭时可能被丢弃，导致续期静默失败，排查成本远高于
        它省下的那点延迟。
        """
        timeout = info.timeout if info.timeout is not None else self.config.timeout
        if timeout is not None and timeout >= 0:
            await self._touch_active(token, timeout)
        if not self.config.auto_renew or timeout is None or timeout < 0:
            return
        await self.storage.expire(self._token_key(token), timeout)
        await self.storage.expire(self._session_key(info.login_id), timeout)
        await self.storage.expire(self._token_session_key(token), timeout)
        await self._emit(Event.RENEW, login_id=info.login_id, token=token, timeout=timeout)

    async def renew_timeout(self, token: str, timeout: int) -> bool:
        """手动续签指定 token。"""
        info = await self._read_token_info(token)
        if info is None or info.is_offline:
            return False
        info.timeout = timeout
        await self._write_token_info(token, info, timeout)
        await self.storage.expire(self._session_key(info.login_id), timeout)
        return True

    # ------------------------------------------------------------------ Session

    async def get_session(self, login_id: Any, *, create: bool = True) -> SaSession | None:
        normalized_id = self.normalize_login_id(login_id)
        key = self._session_key(normalized_id)
        raw = await self.storage.get(key)
        data = SessionData.from_json(raw) if raw else None
        if data is None:
            if not create:
                return None
            data = SessionData(id=normalized_id)
            await self.storage.set(key, data.to_json(), self._session_ttl())
        return SaSession(self.storage, key, data, self._session_ttl())

    async def get_token_session(self, token: str | None = None) -> SaSession | None:
        token = token or get_current_token()
        if not token:
            return None
        info = await self._read_token_info(token)
        if info is None or info.is_offline:
            return None
        key = self._token_session_key(token)
        raw = await self.storage.get(key)
        data = SessionData.from_json(raw) if raw else None
        if data is None:
            data = SessionData(id=token)
            await self.storage.set(key, data.to_json(), info.timeout)
        return SaSession(self.storage, key, data, info.timeout)

    async def delete_session(self, login_id: Any) -> None:
        normalized_id = self.normalize_login_id(login_id)
        await self.storage.delete(self._session_key(normalized_id))

    # ------------------------------------------------------------------ 权限 / 角色

    async def get_permissions(self, login_id: Any) -> list[str]:
        return await self._load_auth_list(login_id, "permission")

    async def get_roles(self, login_id: Any) -> list[str]:
        return await self._load_auth_list(login_id, "role")

    async def _load_auth_list(self, login_id: Any, kind: str) -> list[str]:
        normalized_id = self.normalize_login_id(login_id)
        interface = self._manager.stp_interface
        if interface is None:
            key = self._permission_key(normalized_id) if kind == "permission" else self._role_key(
                normalized_id
            )
            return self._decode_list(await self.storage.get(key))

        cache_timeout = self.config.perm_cache_timeout
        cache_key = self._permission_cache_key(normalized_id, kind)
        if cache_timeout > 0:
            cached = await self.storage.get(cache_key)
            if cached is not None:
                return self._decode_list(cached)

        if kind == "permission":
            values = await interface.get_permission_list(normalized_id, self.login_type)
        else:
            values = await interface.get_role_list(normalized_id, self.login_type)
        values = [str(item) for item in values]
        if cache_timeout > 0:
            await self.storage.set(cache_key, json.dumps(values), cache_timeout)
        return values

    @staticmethod
    def _decode_list(raw: str | None) -> list[str]:
        if not raw:
            return []
        try:
            values = json.loads(raw)
        except ValueError:
            return []
        return [str(item) for item in values] if isinstance(values, list) else []

    async def set_permissions(self, login_id: Any, permissions: list[str]) -> None:
        await self._store_auth_list(login_id, "permission", permissions)

    async def set_roles(self, login_id: Any, roles: list[str]) -> None:
        await self._store_auth_list(login_id, "role", roles)

    async def _store_auth_list(self, login_id: Any, kind: str, values: list[str]) -> None:
        normalized_id = self.normalize_login_id(login_id)
        key = (
            self._permission_key(normalized_id)
            if kind == "permission"
            else self._role_key(normalized_id)
        )
        await self.storage.set(key, json.dumps([str(item) for item in values]))
        # 配置了 StpInterface 时，写入必须让缓存立刻失效，否则改权限不会即时生效。
        await self.storage.delete(self._permission_cache_key(normalized_id, kind))

    async def add_permission(self, login_id: Any, permission: str) -> None:
        current = await self.get_permissions(login_id)
        if permission not in current:
            await self.set_permissions(login_id, [*current, permission])

    async def remove_permission(self, login_id: Any, permission: str) -> None:
        current = await self.get_permissions(login_id)
        await self.set_permissions(login_id, [item for item in current if item != permission])

    async def clear_permissions(self, login_id: Any) -> None:
        await self.set_permissions(login_id, [])

    async def add_role(self, login_id: Any, role: str) -> None:
        current = await self.get_roles(login_id)
        if role not in current:
            await self.set_roles(login_id, [*current, role])

    async def remove_role(self, login_id: Any, role: str) -> None:
        current = await self.get_roles(login_id)
        await self.set_roles(login_id, [item for item in current if item != role])

    async def clear_roles(self, login_id: Any) -> None:
        await self.set_roles(login_id, [])

    async def has_permission(self, login_id: Any, permission: str) -> bool:
        return has_element(await self.get_permissions(login_id), permission)

    async def has_permissions_and(self, login_id: Any, permissions: list[str]) -> bool:
        return match_all(await self.get_permissions(login_id), permissions) is None

    async def has_permissions_or(self, login_id: Any, permissions: list[str]) -> bool:
        return match_any(await self.get_permissions(login_id), permissions)

    async def has_role(self, login_id: Any, role: str) -> bool:
        return has_element(await self.get_roles(login_id), role)

    async def has_roles_and(self, login_id: Any, roles: list[str]) -> bool:
        return match_all(await self.get_roles(login_id), roles) is None

    async def has_roles_or(self, login_id: Any, roles: list[str]) -> bool:
        return match_any(await self.get_roles(login_id), roles)

    async def check_permission(
        self,
        login_id: Any,
        permissions: str | list[str],
        *,
        mode: MatchMode = "OR",
    ) -> None:
        required = [permissions] if isinstance(permissions, str) else list(permissions)
        if not required:
            return
        granted = await self.get_permissions(login_id)
        await self._emit(
            Event.PERMISSION_CHECK,
            login_id=str(login_id),
            required=required,
            mode=mode,
        )
        if mode == "AND":
            missing = match_all(granted, required)
            if missing is not None:
                raise NotPermissionException(missing, login_type=self.login_type)
            return
        if not match_any(granted, required):
            raise NotPermissionException(" | ".join(required), login_type=self.login_type)

    async def check_role(
        self,
        login_id: Any,
        roles: str | list[str],
        *,
        mode: MatchMode = "OR",
    ) -> None:
        required = [roles] if isinstance(roles, str) else list(roles)
        if not required:
            return
        granted = await self.get_roles(login_id)
        await self._emit(Event.ROLE_CHECK, login_id=str(login_id), required=required, mode=mode)
        if mode == "AND":
            missing = match_all(granted, required)
            if missing is not None:
                raise NotRoleException(missing, login_type=self.login_type)
            return
        if not match_any(granted, required):
            raise NotRoleException(" | ".join(required), login_type=self.login_type)

    # ------------------------------------------------------------------ 封禁

    async def disable(
        self,
        login_id: Any,
        seconds: int,
        *,
        service: str = DEFAULT_DISABLE_SERVICE,
        level: int = 1,
    ) -> None:
        """封禁账号的某项服务，``seconds=-1`` 表示永久封禁。"""
        if level < 1:
            raise SaTokenException("封禁等级必须大于等于 1")
        normalized_id = self.normalize_login_id(login_id)
        await self.storage.set(
            self._disable_key(normalized_id, service),
            str(level),
            None if seconds < 0 else seconds,
        )
        await self._emit(
            Event.DISABLE, login_id=normalized_id, service=service, level=level, seconds=seconds
        )

    async def untie(self, login_id: Any, *, service: str = DEFAULT_DISABLE_SERVICE) -> None:
        normalized_id = self.normalize_login_id(login_id)
        await self.storage.delete(self._disable_key(normalized_id, service))
        await self._emit(Event.UNTIE, login_id=normalized_id, service=service)

    async def get_disable_level(
        self,
        login_id: Any,
        *,
        service: str = DEFAULT_DISABLE_SERVICE,
    ) -> int:
        """返回封禁等级，未封禁时返回 0。"""
        normalized_id = self.normalize_login_id(login_id)
        raw = await self.storage.get(self._disable_key(normalized_id, service))
        if raw is None:
            return 0
        try:
            return int(raw)
        except ValueError:
            return 0

    async def is_disable(
        self,
        login_id: Any,
        *,
        service: str = DEFAULT_DISABLE_SERVICE,
        level: int = 1,
    ) -> bool:
        return await self.get_disable_level(login_id, service=service) >= level

    async def get_disable_time(
        self,
        login_id: Any,
        *,
        service: str = DEFAULT_DISABLE_SERVICE,
    ) -> int:
        """剩余封禁秒数；-1 永久，-2 未封禁。"""
        normalized_id = self.normalize_login_id(login_id)
        return await self.storage.ttl(self._disable_key(normalized_id, service))

    async def check_disable(
        self,
        login_id: Any,
        *,
        service: str = DEFAULT_DISABLE_SERVICE,
        level: int = 1,
    ) -> None:
        normalized_id = self.normalize_login_id(login_id)
        current_level = await self.get_disable_level(normalized_id, service=service)
        if current_level >= level:
            remaining = await self.get_disable_time(normalized_id, service=service)
            raise DisableException(
                normalized_id, service, current_level, remaining, login_type=self.login_type
            )

    # ------------------------------------------------------------------ 二级认证

    async def open_safe(self, token: str, business: str, seconds: int) -> None:
        """打开二级认证窗口，用于支付、改密等敏感操作。"""
        await self.storage.set(self._safe_key(token, business), str(now_ms()), seconds)

    async def is_safe(self, token: str | None, business: str) -> bool:
        token = token or get_current_token()
        if not token:
            return False
        return await self.storage.exists(self._safe_key(token, business))

    async def check_safe(self, token: str | None, business: str) -> None:
        if not await self.is_safe(token, business):
            raise NotSafeException(business, login_type=self.login_type)

    async def close_safe(self, token: str, business: str) -> None:
        await self.storage.delete(self._safe_key(token, business))

    # ------------------------------------------------------------------ 查询

    async def get_terminal_list(
        self,
        login_id: Any,
        *,
        device: str | None = None,
    ) -> list[TerminalInfo]:
        session = await self.get_session(login_id, create=False)
        if session is None:
            return []
        return [
            terminal
            for terminal in session.raw.terminal_list
            if device is None or terminal.device == device
        ]

    async def get_token_value_list_by_login_id(
        self,
        login_id: Any,
        *,
        device: str | None = None,
    ) -> list[str]:
        return [
            terminal.token for terminal in await self.get_terminal_list(login_id, device=device)
        ]

    async def search_token_value(
        self,
        keyword: str = "",
        *,
        start: int = 0,
        size: int = 100,
    ) -> list[str]:
        """管理端用：按关键字扫描在线 token。

        依赖存储的 ``scan``，在大规模 Redis 上属于重操作，不要放进请求热路径。
        """
        prefix = f"{self.config.key_prefix(self.login_type)}token:"
        pattern = f"{prefix}*{keyword}*" if keyword else f"{prefix}*"
        found: list[str] = []
        cursor: str | None = None
        while True:
            cursor, keys = await self.storage.scan(pattern, cursor, 200)
            found.extend(key[len(prefix) :] for key in keys)
            if cursor is None:
                break
        found.sort()
        return found[start : start + size] if size > 0 else found[start:]

    async def search_session(
        self,
        keyword: str = "",
        *,
        start: int = 0,
        size: int = 100,
    ) -> list[str]:
        """管理端用：扫描 Account-Session ID。"""
        prefix = f"{self.config.key_prefix(self.login_type)}session:"
        pattern = f"{prefix}*{keyword}*" if keyword else f"{prefix}*"
        found: list[str] = []
        cursor: str | None = None
        while True:
            cursor, keys = await self.storage.scan(pattern, cursor, 200)
            found.extend(key[len(prefix) :] for key in keys)
            if cursor is None:
                break
        found.sort()
        return found[start : start + size] if size > 0 else found[start:]
