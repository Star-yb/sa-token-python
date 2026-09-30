"""存储层：契约 + 内置实现。

``RedisStorage`` 依赖可选的 redis 包，因此这里按需惰性导入，
保证未安装 Redis 时 ``import sa_token.storage`` 不会报错。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import TTL_NEVER_EXPIRE, SaStorage
from .memory import MemoryStorage

__all__ = ["SaStorage", "MemoryStorage", "RedisStorage", "TTL_NEVER_EXPIRE"]

if TYPE_CHECKING:  # 仅供静态类型检查，运行时仍惰性导入
    from .redis import RedisStorage


def __getattr__(name: str) -> Any:
    if name == "RedisStorage":
        from .redis import RedisStorage

        globals()["RedisStorage"] = RedisStorage
        return RedisStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
