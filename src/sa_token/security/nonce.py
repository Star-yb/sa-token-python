"""一次性 Nonce：防止登录、支付等请求被重放。"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from ..exception import SecurityException
from ..model import now_ms

if TYPE_CHECKING:
    from ..storage.base import SaStorage

__all__ = ["NonceManager", "NonceRecord"]


@dataclass(frozen=True)
class NonceRecord:
    nonce: str
    subject: str
    purpose: str
    created_at: int
    state: str = "issued"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> NonceRecord | None:
        try:
            payload = json.loads(raw)
            return cls(**payload) if isinstance(payload, dict) else None
        except (TypeError, ValueError):
            return None


class NonceManager:
    """签发并原子消费服务端 Nonce。

    与「客户端随便给一个从未见过的字符串」不同，``consume`` 只接受本服务
    通过 ``issue`` 签发的值，并校验 subject 与 purpose，防止跨用户、跨业务复用。
    """

    def __init__(
        self,
        storage: SaStorage,
        *,
        key_prefix: str = "satoken:",
        timeout: int = 60,
    ) -> None:
        if timeout <= 0:
            raise ValueError("nonce timeout 必须大于 0")
        self._storage = storage
        self._key_prefix = key_prefix
        self.timeout = timeout

    def _key(self, nonce: str) -> str:
        return f"{self._key_prefix}security:nonce:{nonce}"

    @staticmethod
    def generate() -> str:
        return f"nonce_{now_ms()}_{secrets.token_urlsafe(24)}"

    async def issue(self, subject: str, *, purpose: str = "default") -> str:
        """签发短时 Nonce；极小概率随机冲突时自动重试。"""
        normalized_subject = str(subject).strip()
        if not normalized_subject:
            raise SecurityException("INVALID_NONCE_SUBJECT", "nonce subject 不能为空")
        for _ in range(12):
            nonce = self.generate()
            record = NonceRecord(nonce, normalized_subject, purpose, now_ms())
            if await self._storage.set_if_absent(self._key(nonce), record.to_json(), self.timeout):
                return nonce
        raise SecurityException("NONCE_ALLOCATION_FAILED", "无法分配唯一 nonce")

    async def consume(self, nonce: str, subject: str, *, purpose: str = "default") -> None:
        """原子消费 Nonce；并发请求中恰好一次成功。"""
        key = self._key(nonce)
        raw = await self._storage.get(key)
        if raw is None:
            raise SecurityException("INVALID_NONCE", "nonce 无效、已使用或已过期")
        record = NonceRecord.from_json(raw)
        if record is None:
            raise SecurityException("INVALID_NONCE", "nonce 数据损坏")
        if record.subject != str(subject) or record.purpose != purpose:
            raise SecurityException("NONCE_MISMATCH", "nonce 与用户或业务不匹配")
        if not await self._storage.compare_and_delete(key, raw):
            raise SecurityException("NONCE_REPLAYED", "nonce 已被其它请求使用")

    async def exists(self, nonce: str) -> bool:
        return await self._storage.exists(self._key(nonce))
