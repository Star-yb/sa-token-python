"""内存存储：开发、测试与单机场景的默认实现。

过期采用惰性清理 + 可选的后台清扫，避免为了精确过期而引入常驻线程。
"""

from __future__ import annotations

import asyncio
import fnmatch
import time
from dataclasses import dataclass

from .base import TTL_NEVER_EXPIRE

__all__ = ["MemoryStorage"]


@dataclass
class _Entry:
    value: str
    expire_at: float | None

    def is_expired(self, now: float) -> bool:
        return self.expire_at is not None and self.expire_at <= now


def _to_expire_at(ttl: int | None) -> float | None:
    if ttl is None or ttl == TTL_NEVER_EXPIRE:
        return None
    if ttl <= 0:
        # 传入 0 或负数（-1 以外）视为立即过期，避免写入永不清理的脏数据。
        return time.monotonic()
    return time.monotonic() + ttl


class MemoryStorage:
    """进程内存储。

    注意：数据随进程退出而丢失，多进程部署（gunicorn 多 worker）下各进程互相看不见
    对方的登录态，生产环境请改用 ``RedisStorage``。
    """

    def __init__(self, *, cleanup_interval: float = 60.0) -> None:
        self._data: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.monotonic()

    async def get(self, key: str) -> str | None:
        async with self._lock:
            return self._get_unlocked(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        async with self._lock:
            self._data[key] = _Entry(value, _to_expire_at(ttl))
            self._maybe_cleanup()

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def exists(self, key: str) -> bool:
        async with self._lock:
            return self._get_unlocked(key) is not None

    async def expire(self, key: str, ttl: int | None) -> bool:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None or entry.is_expired(time.monotonic()):
                self._data.pop(key, None)
                return False
            entry.expire_at = _to_expire_at(ttl)
            return True

    async def ttl(self, key: str) -> int:
        async with self._lock:
            now = time.monotonic()
            entry = self._data.get(key)
            if entry is None or entry.is_expired(now):
                self._data.pop(key, None)
                return -2
            if entry.expire_at is None:
                return TTL_NEVER_EXPIRE
            return max(0, int(round(entry.expire_at - now)))

    async def set_if_absent(self, key: str, value: str, ttl: int | None = None) -> bool:
        async with self._lock:
            if self._get_unlocked(key) is not None:
                return False
            self._data[key] = _Entry(value, _to_expire_at(ttl))
            return True

    async def compare_and_set(
        self,
        key: str,
        expected: str,
        new_value: str,
        ttl: int | None = None,
    ) -> bool:
        async with self._lock:
            if self._get_unlocked(key) != expected:
                return False
            self._data[key] = _Entry(new_value, _to_expire_at(ttl))
            return True

    async def compare_and_delete(self, key: str, expected: str) -> bool:
        async with self._lock:
            if self._get_unlocked(key) != expected:
                return False
            self._data.pop(key, None)
            return True

    async def scan(
        self,
        pattern: str,
        cursor: str | None = None,
        count: int = 100,
    ) -> tuple[str | None, list[str]]:
        async with self._lock:
            now = time.monotonic()
            keys = sorted(
                key
                for key, entry in self._data.items()
                if not entry.is_expired(now) and fnmatch.fnmatchcase(key, pattern)
            )
        start = int(cursor) if cursor else 0
        page = keys[start : start + count]
        next_cursor = str(start + count) if start + count < len(keys) else None
        return next_cursor, page

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    async def close(self) -> None:
        await self.clear()

    def _get_unlocked(self, key: str) -> str | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        if entry.is_expired(time.monotonic()):
            self._data.pop(key, None)
            return None
        return entry.value

    def _maybe_cleanup(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        expired = [key for key, entry in self._data.items() if entry.is_expired(now)]
        for key in expired:
            self._data.pop(key, None)
