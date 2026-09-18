"""存储契约。

核心层只依赖这套接口，因此内存、Redis、数据库甚至自研存储都能平替。
所有值都是字符串（JSON），这样 Redis 里的数据可以被其它语言的 sa-token 读写。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["SaStorage", "TTL_NEVER_EXPIRE"]

#: ttl 传入该值（或 None）表示永不过期。
TTL_NEVER_EXPIRE = -1


@runtime_checkable
class SaStorage(Protocol):
    """键值存储接口。

    ``ttl`` 单位为秒；``None`` 与 ``-1`` 等价，均表示永不过期。
    """

    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl: int | None = None) -> None: ...

    async def delete(self, key: str) -> None: ...

    async def exists(self, key: str) -> bool: ...

    async def expire(self, key: str, ttl: int | None) -> bool:
        """更新 TTL，键不存在时返回 False。"""
        ...

    async def ttl(self, key: str) -> int:
        """返回剩余秒数；-1 表示永不过期，-2 表示键不存在。"""
        ...

    async def set_if_absent(self, key: str, value: str, ttl: int | None = None) -> bool:
        """键不存在时写入，返回是否写入成功。用于一次性 token 的原子占位。"""
        ...

    async def compare_and_set(
        self,
        key: str,
        expected: str,
        new_value: str,
        ttl: int | None = None,
    ) -> bool:
        """当前值等于 expected 时才写入，用于并发下的安全更新。"""
        ...

    async def compare_and_delete(self, key: str, expected: str) -> bool: ...

    async def scan(self, pattern: str, cursor: str | None = None, count: int = 100) -> tuple[
        str | None, list[str]
    ]:
        """按 glob 模式游标扫描键，返回 ``(下一个游标, 键列表)``；游标为 None 表示结束。"""
        ...

    async def clear(self) -> None:
        """清空全部数据，仅用于测试与开发。"""
        ...

    async def close(self) -> None: ...
