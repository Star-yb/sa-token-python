"""存储契约。

核心层只依赖这套接口，因此内存、Redis、数据库甚至自研存储都能平替。
所有值都是字符串（JSON），这样 Redis 里的数据可以被其它语言的 sa-token 读写。
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["SaStorage", "TTL_NEVER_EXPIRE"]

#: ttl 传入该值（或 None）表示永不过期。
TTL_NEVER_EXPIRE = -1


class SaStorage(Protocol):
    """键值存储接口。

    ``ttl`` 单位为秒。``None`` 与 ``-1`` 表示永不过期。
    ``0`` 以及其它负数表示立即过期：写入后读取不到该键。
    各实现必须遵守这套语义，不能把 ``0`` 悄悄改成 1 秒或永不过期。
    """

    async def get(self, key: str) -> str | None:
        raise NotImplementedError

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        raise NotImplementedError

    async def delete(self, key: str) -> None:
        raise NotImplementedError

    async def exists(self, key: str) -> bool:
        raise NotImplementedError

    async def expire(self, key: str, ttl: int | None) -> bool:
        """尝试更新 TTL。

        返回值只表示这次 TTL 修改是否被存储接受，不能用来判断键是否存在。
        Redis 对「键存在但本来就没有过期时间」执行取消过期时也可能返回 False。
        键是否存在请用 ``exists()``，或看 ``ttl() == -2``。
        """
        raise NotImplementedError

    async def ttl(self, key: str) -> int:
        """返回剩余秒数；-1 表示永不过期，-2 表示键不存在。"""
        raise NotImplementedError

    async def set_if_absent(self, key: str, value: str, ttl: int | None = None) -> bool:
        """键不存在时写入，返回是否写入成功。用于一次性 token 的原子占位。"""
        raise NotImplementedError

    async def compare_and_set(
        self,
        key: str,
        expected: str,
        new_value: str,
        ttl: int | None = None,
    ) -> bool:
        """当前值等于 expected 时才写入，用于并发下的安全更新。"""
        raise NotImplementedError

    async def compare_and_delete(self, key: str, expected: str) -> bool:
        raise NotImplementedError

    async def scan(
        self,
        pattern: str,
        cursor: str | None = None,
        count: int = 100,
    ) -> tuple[str | None, list[str]]:
        """按 glob 模式扫描键，返回 ``(下一个游标, 本页键)``。

        传入 ``cursor=None`` 表示从头开始。返回的游标为 ``None`` 表示扫描结束。
        游标是不透明值：调用方不要自己构造或解析，也不能拿到别的实现或进程上复用。
        实现必须把「结束」统一映射成 ``None``。
        """
        raise NotImplementedError

    async def clear(self) -> None:
        """清空全部数据，仅用于测试与开发。"""
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError
