"""Session：挂在账号或单个 token 上的 KV 数据。

Session 对象本身是「远端数据的把手」，每次写操作都会落存储，
这样多进程部署下不会出现各自持有过期副本的问题。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from .model import SessionData, TerminalInfo

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from .storage.base import SaStorage

__all__ = ["SaSession"]

_T = TypeVar("_T")
_MISSING = object()


class SaSession:
    """会话对象。

    Account-Session（``get_session``）同时承担在线终端索引；
    Token-Session（``get_token_session``）只放本次登录相关的数据。
    """

    def __init__(
        self,
        storage: SaStorage,
        key: str,
        data: SessionData,
        timeout: int | None,
    ) -> None:
        self._storage = storage
        self._key = key
        self._data = data
        self._timeout = timeout

    @property
    def id(self) -> str:
        return self._data.id

    @property
    def create_time(self) -> int:
        return self._data.create_time

    @property
    def raw(self) -> SessionData:
        """底层数据，供核心内部（如终端列表）使用。"""
        return self._data

    async def get(self, name: str, default: Any = None) -> Any:
        return self._data.data.get(name, default)

    async def get_typed(
        self,
        name: str,
        expected: type[_T],
        default: _T | None = None,
    ) -> _T | None:
        """按类型取值，类型不符时回落到 ``default``，避免把脏数据带进业务。"""
        value = self._data.data.get(name, _MISSING)
        if value is _MISSING or not isinstance(value, expected):
            return default
        return value

    async def set(self, name: str, value: Any) -> None:
        self._data.data[name] = value
        await self.save()

    async def update(self, values: dict[str, Any]) -> None:
        self._data.data.update(values)
        await self.save()

    async def delete(self, name: str) -> None:
        if self._data.data.pop(name, _MISSING) is not _MISSING:
            await self.save()

    async def has(self, name: str) -> bool:
        return name in self._data.data

    async def keys(self) -> list[str]:
        return list(self._data.data.keys())

    async def clear(self) -> None:
        self._data.data.clear()
        await self.save()

    @property
    def terminal_list(self) -> list[TerminalInfo]:
        return self._data.terminal_list

    async def save(self) -> None:
        await self._storage.set(self._key, self._data.to_json(), self._timeout)
