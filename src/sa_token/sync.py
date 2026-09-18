"""同步门面。

本项目内核默认是异步：``await StpUtil.login()``。
WSGI 框架（Flask、Django 同步视图）和普通脚本没有事件循环，
用这里的 ``StpUtilSync`` 把同一套 :class:`~sa_token.stp_logic.StpLogic`
放到后台 loop 里跑，语义与异步版完全一致。

``Sync`` = English *synchronous*（同步），不是 asyncio / 异步。
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from .model import TerminalInfo, TokenInfo
from .permission import MatchMode
from .security import LoginTokenPair
from .session import SaSession
from .stp_util import StpUtil

__all__ = ["run_sync", "StpUtilSync", "shutdown_sync_loop"]

_T = TypeVar("_T")

_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_loop_lock = threading.Lock()


def _get_background_loop() -> asyncio.AbstractEventLoop:
    """懒启动一个后台事件循环，供同步代码复用。

    每次调用都新建 loop 的话，``MemoryStorage`` 里的 ``asyncio.Lock`` 会绑定到
    已关闭的 loop 上并报错；共用一个常驻 loop 可以规避这个问题。
    """
    global _loop, _loop_thread
    with _loop_lock:
        if _loop is not None and not _loop.is_closed():
            return _loop
        loop = asyncio.new_event_loop()
        thread = threading.Thread(
            target=loop.run_forever,
            name="sa-token-sync-loop",
            daemon=True,
        )
        thread.start()
        _loop, _loop_thread = loop, thread
        return loop


def shutdown_sync_loop() -> None:
    """关闭后台事件循环，一般只在测试或进程退出时调用。"""
    global _loop, _loop_thread
    with _loop_lock:
        if _loop is None:
            return
        _loop.call_soon_threadsafe(_loop.stop)
        if _loop_thread is not None:
            _loop_thread.join(timeout=5)
        _loop.close()
        _loop, _loop_thread = None, None


def run_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """在同步代码里执行协程。

    已经处于事件循环中时直接调用会死锁，因此这里明确报错而不是悄悄挂起——
    异步环境请直接 ``await`` 异步版 API。
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run_coroutine_threadsafe(coro, _get_background_loop()).result()
    coro.close()
    raise RuntimeError(
        "run_sync 不能在事件循环中调用，异步环境请直接 await StpUtil 的异步方法"
    )


class StpUtilSync:
    """``StpUtil`` 的同步版本，方法名与参数完全一致。"""

    @staticmethod
    def login(
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
        tag: str | None = None,
        extra: dict[str, Any] | None = None,
        token_value: str | None = None,
    ) -> str:
        return run_sync(
            StpUtil.login(
                login_id,
                device=device,
                timeout=timeout,
                tag=tag,
                extra=extra,
                token_value=token_value,
            )
        )

    @staticmethod
    def login_with_refresh(
        login_id: Any,
        *,
        device: str | None = None,
        timeout: int | None = None,
    ) -> LoginTokenPair:
        return run_sync(
            StpUtil.login_with_refresh(login_id, device=device, timeout=timeout)
        )

    @staticmethod
    def refresh_access_token(refresh_token: str) -> LoginTokenPair:
        return run_sync(StpUtil.refresh_access_token(refresh_token))

    @staticmethod
    def logout(login_id: Any, *, device: str | None = None) -> None:
        run_sync(StpUtil.logout(login_id, device=device))

    @staticmethod
    def logout_by_token(token: str | None = None) -> None:
        run_sync(StpUtil.logout_by_token(token))

    @staticmethod
    def kickout(login_id: Any, *, device: str | None = None) -> None:
        run_sync(StpUtil.kickout(login_id, device=device))

    @staticmethod
    def kickout_by_token(token: str | None = None) -> None:
        run_sync(StpUtil.kickout_by_token(token))

    @staticmethod
    def replaced(login_id: Any, *, device: str | None = None) -> None:
        run_sync(StpUtil.replaced(login_id, device=device))

    @staticmethod
    def is_login(token: str | None = None) -> bool:
        return run_sync(StpUtil.is_login(token))

    @staticmethod
    def check_login(token: str | None = None) -> str:
        return run_sync(StpUtil.check_login(token))

    @staticmethod
    def get_login_id(token: str | None = None) -> str:
        return run_sync(StpUtil.get_login_id(token))

    @staticmethod
    def get_login_id_or_none(token: str | None = None) -> str | None:
        return run_sync(StpUtil.get_login_id_or_none(token))

    @staticmethod
    def get_token_value() -> str | None:
        return StpUtil.get_token_value()

    @staticmethod
    def get_login_id_from_context() -> str | None:
        return StpUtil.get_login_id_from_context()

    @staticmethod
    def get_token_info(token: str | None = None) -> TokenInfo | None:
        return run_sync(StpUtil.get_token_info(token))

    @staticmethod
    def get_offline_reason(token: str) -> dict[str, Any] | None:
        return run_sync(StpUtil.get_offline_reason(token))

    @staticmethod
    def get_permissions(login_id: Any) -> list[str]:
        return run_sync(StpUtil.get_permissions(login_id))

    @staticmethod
    def set_permissions(login_id: Any, permissions: list[str]) -> None:
        run_sync(StpUtil.set_permissions(login_id, permissions))

    @staticmethod
    def has_permission(login_id: Any, permission: str) -> bool:
        return run_sync(StpUtil.has_permission(login_id, permission))

    @staticmethod
    def check_permission(
        login_id: Any,
        permissions: str | list[str],
        *,
        mode: MatchMode = "OR",
    ) -> None:
        run_sync(StpUtil.check_permission(login_id, permissions, mode=mode))

    @staticmethod
    def get_roles(login_id: Any) -> list[str]:
        return run_sync(StpUtil.get_roles(login_id))

    @staticmethod
    def set_roles(login_id: Any, roles: list[str]) -> None:
        run_sync(StpUtil.set_roles(login_id, roles))

    @staticmethod
    def has_role(login_id: Any, role: str) -> bool:
        return run_sync(StpUtil.has_role(login_id, role))

    @staticmethod
    def check_role(login_id: Any, roles: str | list[str], *, mode: MatchMode = "OR") -> None:
        run_sync(StpUtil.check_role(login_id, roles, mode=mode))

    @staticmethod
    def get_session(login_id: Any, *, create: bool = True) -> SaSession | None:
        return run_sync(StpUtil.get_session(login_id, create=create))

    @staticmethod
    def get_token_session(token: str | None = None) -> SaSession | None:
        return run_sync(StpUtil.get_token_session(token))

    @staticmethod
    def disable(login_id: Any, seconds: int, *, service: str = "login", level: int = 1) -> None:
        run_sync(StpUtil.disable(login_id, seconds, service=service, level=level))

    @staticmethod
    def untie(login_id: Any, *, service: str = "login") -> None:
        run_sync(StpUtil.untie(login_id, service=service))

    @staticmethod
    def is_disable(login_id: Any, *, service: str = "login", level: int = 1) -> bool:
        return run_sync(StpUtil.is_disable(login_id, service=service, level=level))

    @staticmethod
    def open_safe(token: str, business: str, seconds: int) -> None:
        run_sync(StpUtil.open_safe(token, business, seconds))

    @staticmethod
    def check_safe(token: str | None, business: str) -> None:
        run_sync(StpUtil.check_safe(token, business))

    @staticmethod
    def is_safe(token: str | None, business: str) -> bool:
        return run_sync(StpUtil.is_safe(token, business))

    @staticmethod
    def get_terminal_list(login_id: Any, *, device: str | None = None) -> list[TerminalInfo]:
        return run_sync(StpUtil.get_terminal_list(login_id, device=device))

    @staticmethod
    def issue_nonce(subject: Any, *, purpose: str = "default") -> str:
        return run_sync(StpUtil.issue_nonce(subject, purpose=purpose))

    @staticmethod
    def consume_nonce(nonce: str, subject: Any, *, purpose: str = "default") -> None:
        run_sync(StpUtil.consume_nonce(nonce, subject, purpose=purpose))

    @staticmethod
    def create_temp_token(
        value: Any,
        timeout: int,
        *,
        namespace: str = "default",
    ) -> str:
        return run_sync(
            StpUtil.create_temp_token(value, timeout, namespace=namespace)
        )

    @staticmethod
    def consume_temp_token(token: str, *, namespace: str = "default") -> Any | None:
        return run_sync(StpUtil.consume_temp_token(token, namespace=namespace))
