"""存储层：契约 + 内置实现。

``RedisStorage`` 依赖可选的 redis 包，因此这里按需惰性导入，
保证只装了核心包的用户 ``import sa_token.storage`` 不会报错。
"""

from __future__ import annotations

from typing import Any

from .base import TTL_NEVER_EXPIRE, SaStorage
from .memory import MemoryStorage

__all__ = ["SaStorage", "MemoryStorage", "RedisStorage", "TTL_NEVER_EXPIRE"]


def __getattr__(name: str) -> Any:
    if name == "RedisStorage":
        from .redis import RedisStorage

        return RedisStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
