"""Token 生成策略。

``create_strategy`` 把配置里的字符串风格名翻译成具体实现，
这样用户既可以用 ``token_style="uuid"``，也能直接注入自定义策略对象。
"""

from __future__ import annotations

from ..config import SaTokenConfig
from .base import TokenStrategy
from .builtin import (
    HashStrategy,
    RandomStrategy,
    SimpleUuidStrategy,
    TikStrategy,
    TimestampStrategy,
    UuidStrategy,
)

__all__ = [
    "TokenStrategy",
    "UuidStrategy",
    "SimpleUuidStrategy",
    "RandomStrategy",
    "HashStrategy",
    "TimestampStrategy",
    "TikStrategy",
    "JwtStrategy",
    "create_strategy",
    "BUILTIN_STYLES",
]

BUILTIN_STYLES = (
    "uuid",
    "simple-uuid",
    "random32",
    "random64",
    "random128",
    "hash",
    "timestamp",
    "tik",
    "jwt",
)


def create_strategy(config: SaTokenConfig) -> TokenStrategy:
    """按 ``config.token_style`` 创建策略实例。"""
    style = config.token_style.strip().lower()
    if style == "uuid":
        return UuidStrategy()
    if style in ("simple-uuid", "simple_uuid"):
        return SimpleUuidStrategy()
    if style.startswith("random"):
        suffix = style[len("random") :]
        return RandomStrategy(int(suffix) if suffix.isdigit() else 32)
    if style == "hash":
        return HashStrategy()
    if style == "timestamp":
        return TimestampStrategy()
    if style == "tik":
        return TikStrategy()
    if style == "jwt":
        from .jwt import JwtStrategy

        return JwtStrategy(
            config.jwt_secret_key or "",
            algorithm=config.jwt_algorithm,
        )
    raise ValueError(f"未知的 token_style: {config.token_style}，可选：{', '.join(BUILTIN_STYLES)}")


def __getattr__(name: str):
    if name == "JwtStrategy":
        from .jwt import JwtStrategy

        return JwtStrategy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
