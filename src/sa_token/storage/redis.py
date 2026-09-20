"""Redis 存储：生产环境实现。

需要额外安装：``pip install "sa-token-python-core[redis]"``。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import TTL_NEVER_EXPIRE

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from redis.asyncio import Redis

__all__ = ["RedisStorage"]

#: 值相等才删除，避免误删被其它请求刷新过的键。
_COMPARE_AND_DELETE = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""

#: 值相等才更新；ARGV[3] 为 -1 时保持 key 永不过期。
_COMPARE_AND_SET = """
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end
if tonumber(ARGV[3]) < 0 then
    redis.call('SET', KEYS[1], ARGV[2])
else
    redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
end
return 1
"""


def _normalize_ttl(ttl: int | None) -> int | None:
    """把 ``None`` / ``-1`` 统一成「不设置过期」。"""
    if ttl is None or ttl == TTL_NEVER_EXPIRE:
        return None
    return max(1, ttl)


class RedisStorage:
    """基于 ``redis.asyncio`` 的存储实现。

    要求客户端以字符串模式解码（``decode_responses=True``）；使用 :meth:`from_url`
    构造时会自动设置。
    """

    def __init__(self, client: Redis) -> None:
        self._redis = client
        self._compare_and_delete = client.register_script(_COMPARE_AND_DELETE)
        self._compare_and_set = client.register_script(_COMPARE_AND_SET)

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisStorage:
        """``RedisStorage.from_url("redis://localhost:6379/0")``"""
        try:
            from redis.asyncio import Redis
        except ImportError as exc:  # pragma: no cover - 依赖缺失路径
            raise ImportError(
                'RedisStorage 需要 redis 依赖，请执行：pip install "sa-token-python-core[redis]"'
            ) from exc
        kwargs.setdefault("decode_responses", True)
        return cls(Redis.from_url(url, **kwargs))

    async def get(self, key: str) -> str | None:
        return await self._redis.get(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        seconds = _normalize_ttl(ttl)
        if seconds is None:
            await self._redis.set(key, value)
        else:
            await self._redis.set(key, value, ex=seconds)

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)

    async def exists(self, key: str) -> bool:
        return bool(await self._redis.exists(key))

    async def expire(self, key: str, ttl: int | None) -> bool:
        seconds = _normalize_ttl(ttl)
        if seconds is None:
            return bool(await self._redis.persist(key))
        return bool(await self._redis.expire(key, seconds))

    async def ttl(self, key: str) -> int:
        return int(await self._redis.ttl(key))

    async def set_if_absent(self, key: str, value: str, ttl: int | None = None) -> bool:
        seconds = _normalize_ttl(ttl)
        if seconds is None:
            return bool(await self._redis.set(key, value, nx=True))
        return bool(await self._redis.set(key, value, ex=seconds, nx=True))

    async def compare_and_set(
        self,
        key: str,
        expected: str,
        new_value: str,
        ttl: int | None = None,
    ) -> bool:
        seconds = _normalize_ttl(ttl)
        result = await self._compare_and_set(
            keys=[key],
            args=[expected, new_value, TTL_NEVER_EXPIRE if seconds is None else seconds],
        )
        return bool(result)

    async def compare_and_delete(self, key: str, expected: str) -> bool:
        return bool(await self._compare_and_delete(keys=[key], args=[expected]))

    async def scan(
        self,
        pattern: str,
        cursor: str | None = None,
        count: int = 100,
    ) -> tuple[str | None, list[str]]:
        next_cursor, keys = await self._redis.scan(
            cursor=int(cursor) if cursor else 0,
            match=pattern,
            count=count,
        )
        return (str(next_cursor) if next_cursor else None), list(keys)

    async def clear(self) -> None:
        """清空当前库，仅供测试使用。"""
        await self._redis.flushdb()

    async def close(self) -> None:
        await self._redis.aclose()
