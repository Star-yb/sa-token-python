"""请求级上下文。

Java 用 ThreadLocal，Go 用 context.Context。Python 的异步场景里必须用
:mod:`contextvars`：``threading.local`` 在同一个事件循环线程上会被多个并发
请求共用，直接导致身份串号。
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

__all__ = [
    "get_current_token",
    "get_current_login_id",
    "set_current",
    "clear_current",
    "sa_token_context",
]

_current_token: ContextVar[str | None] = ContextVar("sa_token_current_token", default=None)
_current_login_id: ContextVar[str | None] = ContextVar("sa_token_current_login_id", default=None)


def get_current_token() -> str | None:
    """当前调用链绑定的 token。"""
    return _current_token.get()


def get_current_login_id() -> str | None:
    """当前调用链绑定的 login_id（已通过校验）。"""
    return _current_login_id.get()


def set_current(token: str | None, login_id: str | None = None) -> tuple[Token, Token]:
    """绑定当前身份，返回可用于还原的 reset token。"""
    return _current_token.set(token), _current_login_id.set(login_id)


def clear_current(tokens: tuple[Token, Token] | None = None) -> None:
    """还原到绑定前的状态。"""
    if tokens is None:
        _current_token.set(None)
        _current_login_id.set(None)
        return
    token_ref, login_id_ref = tokens
    _current_token.reset(token_ref)
    _current_login_id.reset(login_id_ref)


@contextmanager
def sa_token_context(token: str | None, login_id: str | None = None) -> Iterator[None]:
    """在一段代码内绑定身份，退出时自动还原。

    同步与异步代码都能用（``with`` 与 ``async with`` 场景下 contextvars 的
    传播规则一致），因此不必再提供一个异步版本。
    """
    refs = set_current(token, login_id)
    try:
        yield
    finally:
        clear_current(refs)
