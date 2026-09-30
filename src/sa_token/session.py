"""Session：挂在账号或单个 token 上的 KV 数据。

Session 对象本身是「远端数据的把手」，每次写操作都会落存储，
这样多进程部署下不会出现各自持有过期副本的问题。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from .exception import SaTokenException
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
        *,
        loaded_raw: str | None = None,
    ) -> None:
        self._storage = storage
        self._key = key
        self._data = data
        self._timeout = timeout
        self._loaded_raw = loaded_raw
        self._base = SessionData.from_json(loaded_raw) if loaded_raw else None

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

    def _snapshot(self) -> SessionData | None:
        return SessionData.from_json(self._data.to_json())

    async def _write(self, snapshot: SessionData | None) -> None:
        try:
            await self.save()
        except Exception:
            if snapshot is not None:
                self._data = snapshot
            raise

    async def set(self, name: str, value: Any) -> None:
        snapshot = self._snapshot()
        self._data.data[name] = value
        await self._write(snapshot)

    async def update(self, values: dict[str, Any]) -> None:
        snapshot = self._snapshot()
        self._data.data.update(values)
        await self._write(snapshot)

    async def delete(self, name: str) -> None:
        if name not in self._data.data:
            return
        snapshot = self._snapshot()
        self._data.data.pop(name, None)
        await self._write(snapshot)

    async def has(self, name: str) -> bool:
        return name in self._data.data

    async def keys(self) -> list[str]:
        return list(self._data.data.keys())

    async def clear(self) -> None:
        snapshot = self._snapshot()
        self._data.data.clear()
        await self._write(snapshot)

    @property
    def terminal_list(self) -> list[TerminalInfo]:
        """当前在线终端的副本。修改这份列表不会写入存储。"""
        return list(self._data.terminal_list)

    async def save(self) -> None:
        payload = self._data.to_json()
        for _ in range(12):
            if self._loaded_raw is None:
                created = await self._storage.set_if_absent(self._key, payload, self._timeout)
                if created:
                    self._loaded_raw = payload
                    self._base = SessionData.from_json(payload)
                    return
            else:
                updated = await self._storage.compare_and_set(
                    self._key,
                    self._loaded_raw,
                    payload,
                    self._timeout,
                )
                if updated:
                    self._loaded_raw = payload
                    self._base = SessionData.from_json(payload)
                    return
            current = await self._storage.get(self._key)
            if current is None:
                return
            merged = self._merge(current)
            if merged is None:
                return
            self._data = merged
            self._loaded_raw = current
            payload = self._data.to_json()
        raise SaTokenException("会话并发更新失败")

    def _merge(self, current_raw: str) -> SessionData | None:
        remote = SessionData.from_json(current_raw)
        if remote is None:
            return None
        data = dict(remote.data)
        base = self._base
        if base is None:
            data.update(self._data.data)
        else:
            for key, value in self._data.data.items():
                if base.data.get(key) != value:
                    data[key] = value
            for key in base.data:
                if key not in self._data.data:
                    data.pop(key, None)
        by_token = {item.token: item for item in remote.terminal_list}
        local_by_token = {item.token: item for item in self._data.terminal_list}
        if base is None:
            for item in self._data.terminal_list:
                by_token[item.token] = item
        else:
            base_by_token = {item.token: item for item in base.terminal_list}
            for token in base_by_token.keys() - local_by_token.keys():
                by_token.pop(token, None)
            # 只合入相对 base 新增或改过的终端。未改动的本地副本不能把
            # 并发登出已经摘掉的终端写回去。
            for token, item in local_by_token.items():
                previous = base_by_token.get(token)
                if previous is None or previous != item:
                    by_token[token] = item
        return SessionData(
            id=self._data.id or remote.id,
            create_time=remote.create_time or self._data.create_time,
            data=data,
            terminal_list=list(by_token.values()),
            history_terminal_count=max(
                remote.history_terminal_count,
                self._data.history_terminal_count,
            ),
        )
