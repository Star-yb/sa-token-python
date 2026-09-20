"""内置的不透明 token 生成策略。

全部使用 :mod:`secrets` 而非 :mod:`random`，保证 token 不可预测。
"""

from __future__ import annotations

import hashlib
import secrets
import string
import uuid
from typing import Any

from ..model import now_ms

__all__ = [
    "UuidStrategy",
    "SimpleUuidStrategy",
    "RandomStrategy",
    "HashStrategy",
    "TimestampStrategy",
    "TikStrategy",
]

_TIK_ALPHABET = string.ascii_letters + string.digits


class _OpaqueStrategy:
    """不透明 token 的公共基类：无法从 token 本身反推身份。"""

    name = "opaque"

    def parse(self, token: str) -> dict[str, Any] | None:
        return None


class UuidStrategy(_OpaqueStrategy):
    name = "uuid"

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        return str(uuid.uuid4())


class SimpleUuidStrategy(_OpaqueStrategy):
    name = "simple-uuid"

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        return uuid.uuid4().hex


class RandomStrategy(_OpaqueStrategy):
    """定长随机 hex 串，``length`` 为字符数。"""

    def __init__(self, length: int = 32) -> None:
        if length < 8:
            raise ValueError("随机 token 长度不得小于 8")
        self.length = length
        self.name = f"random{length}"

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        return secrets.token_hex((self.length + 1) // 2)[: self.length]


class HashStrategy(_OpaqueStrategy):
    """SHA256(login_id + 随机盐)，长度固定 64。

    掺入随机盐是必须的：否则同一个 login_id 永远得到同一个 token，
    多端登录与顶号语义会直接失效。
    """

    name = "hash"

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        material = f"{login_id}:{now_ms()}:{secrets.token_hex(16)}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


class TimestampStrategy(_OpaqueStrategy):
    """``{毫秒时间戳}_{随机串}``，便于从 token 直接看出签发时间。"""

    name = "timestamp"

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        return f"{now_ms()}_{secrets.token_hex(8)}"


class TikStrategy(_OpaqueStrategy):
    """短 token，适合放进 URL 或口令分享。

    长度短意味着熵低，仅建议用于短期 / 一次性场景。
    """

    name = "tik"

    def __init__(self, length: int = 8) -> None:
        self.length = length

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        return "".join(secrets.choice(_TIK_ALPHABET) for _ in range(self.length))
