"""Token 生成策略契约。

生成什么样的字符串是策略的事；这个字符串代表谁，永远以存储为准。
因此非 JWT 策略的 :meth:`parse` 返回 ``None`` 是完全正常的。
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["TokenStrategy"]


@runtime_checkable
class TokenStrategy(Protocol):
    name: str

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str: ...

    def parse(self, token: str) -> dict[str, Any] | None:
        """自解释 token（如 JWT）返回载荷，其余返回 ``None``。"""
        ...
