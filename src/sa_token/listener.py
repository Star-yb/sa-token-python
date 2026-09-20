"""事件系统：用于审计日志、指标、消息推送。

监听器异常不会影响主流程——审计失败不该导致用户登录失败。
事件载荷只带 token 指纹，避免把原始 token 写进日志文件。
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .model import now_ms

__all__ = ["Event", "EventData", "EventBus", "Listener"]

logger = logging.getLogger("sa_token.listener")


class Event(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    KICKOUT = "kickout"
    REPLACED = "replaced"
    DISABLE = "disable"
    UNTIE = "untie"
    RENEW = "renew"
    PERMISSION_CHECK = "permission_check"
    ROLE_CHECK = "role_check"
    ALL = "*"


@dataclass
class EventData:
    event: Event
    login_id: str | None = None
    login_type: str = "login"
    device: str | None = None
    token_fingerprint: str | None = None
    timestamp: int = field(default_factory=now_ms)
    detail: dict[str, Any] = field(default_factory=dict)


Listener = Callable[[EventData], Any | Awaitable[Any]]


def fingerprint(token: str | None) -> str | None:
    """token 的短指纹：可用于关联同一条会话，但无法还原出 token。"""
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


@dataclass(order=True)
class _Registration:
    # 先按优先级倒序，再按注册序号，保证同优先级下注册顺序稳定。
    sort_key: tuple[int, int]
    listener: Listener = field(compare=False)
    is_async: bool = field(compare=False, default=False)


class EventBus:
    def __init__(self) -> None:
        self._listeners: dict[Event, list[_Registration]] = {}
        self._counter = 0

    def on(self, event: Event, listener: Listener, *, priority: int = 0) -> None:
        """注册监听器，``priority`` 越大越先执行。"""
        self._counter += 1
        registration = _Registration(
            sort_key=(-priority, self._counter),
            listener=listener,
            is_async=asyncio.iscoroutinefunction(listener),
        )
        bucket = self._listeners.setdefault(event, [])
        bucket.append(registration)
        bucket.sort()

    def off(self, event: Event, listener: Listener) -> None:
        bucket = self._listeners.get(event)
        if not bucket:
            return
        self._listeners[event] = [item for item in bucket if item.listener is not listener]

    def clear(self) -> None:
        self._listeners.clear()

    async def emit(self, data: EventData) -> None:
        matched = [*self._listeners.get(data.event, []), *self._listeners.get(Event.ALL, [])]
        for registration in matched:
            try:
                result = registration.listener(data)
                if registration.is_async or asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("sa-token 事件监听器执行失败：event=%s", data.event.value)
