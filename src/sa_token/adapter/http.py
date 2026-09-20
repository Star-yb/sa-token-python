"""HttpContext：对「一次请求」的最小抽象。

核心层只认这个协议，不认 ``fastapi.Request`` 或 ``flask.request``。
新增一个框架支持 = 实现这个协议，而不是重写鉴权。
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["HttpContext", "SimpleHttpContext"]


@runtime_checkable
class HttpContext(Protocol):
    """请求上下文协议。

    ``state`` 用于把校验结果回传给上层（``stp_login_id`` / ``stp_token``）。
    """

    state: dict[str, Any]

    def get_header(self, name: str) -> str | None: ...

    def get_cookie(self, name: str) -> str | None: ...

    def get_query(self, name: str) -> str | None: ...

    def get_path(self) -> str: ...

    def get_method(self) -> str: ...


class SimpleHttpContext:
    """字典驱动的上下文实现。

    适用于测试、非 HTTP 协议（gRPC metadata、MQ 消息头）以及任何
    还没有官方适配器的框架。
    """

    def __init__(
        self,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        path: str = "/",
        method: str = "GET",
    ) -> None:
        # Header 名大小写不敏感，统一转小写存储。
        self._headers = {key.lower(): value for key, value in (headers or {}).items()}
        self._cookies = dict(cookies or {})
        self._query = dict(query or {})
        self._path = path
        self._method = method.upper()
        self.state: dict[str, Any] = {}

    def get_header(self, name: str) -> str | None:
        return self._headers.get(name.lower())

    def get_cookie(self, name: str) -> str | None:
        return self._cookies.get(name)

    def get_query(self, name: str) -> str | None:
        return self._query.get(name)

    def get_path(self) -> str:
        return self._path

    def get_method(self) -> str:
        return self._method
