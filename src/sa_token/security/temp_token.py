"""短时业务 Token：邀请、重置密码、邮箱验证等一次性动作。"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from ..exception import SecurityException
from ..model import now_ms

if TYPE_CHECKING:
    from ..storage.base import SaStorage

__all__ = ["TempTokenManager", "TempTokenRecord"]


@dataclass(frozen=True)
class TempTokenRecord:
    value: Any
    namespace: str
    created_at: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> TempTokenRecord | None:
        try:
            payload = json.loads(raw)
            return cls(**payload) if isinstance(payload, dict) else None
        except (TypeError, ValueError):
            return None


class TempTokenManager:
    """命名空间隔离的临时 Token 管理器。"""

    def __init__(self, storage: SaStorage, *, key_prefix: str = "satoken:") -> None:
        self._storage = storage
        self._key_prefix = key_prefix

    def _require_namespace(self, namespace: str) -> None:
        if not namespace or ":" in namespace:
            raise SecurityException("INVALID_TEMP_NAMESPACE", "namespace 不能为空或包含冒号")

    def _key(self, namespace: str, token: str) -> str:
        self._require_namespace(namespace)
        if not token or ":" in token:
            raise SecurityException("INVALID_TEMP_TOKEN", "token 不能为空或包含冒号")
        return f"{self._key_prefix}security:temp:{namespace}:{token}"

    def _index_key(self, namespace: str, value: str) -> str:
        self._require_namespace(namespace)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return f"{self._key_prefix}security:temp-index:{namespace}:{digest}"

    def _validate(self, namespace: str, timeout: int) -> None:
        self._require_namespace(namespace)
        if timeout == 0 or timeout < -1:
            raise SecurityException("INVALID_TEMP_TIMEOUT", "timeout 必须为正数或 -1")

    async def create(
        self,
        value: Any,
        timeout: int,
        *,
        namespace: str = "default",
        record_index: bool = False,
    ) -> str:
        """创建临时 Token；``record_index`` 可按字符串业务值反查最新 Token。"""
        self._validate(namespace, timeout)
        if value is None:
            raise SecurityException("TEMP_TOKEN_VALUE_NONE", "value 不能为 None")
        record = TempTokenRecord(value=value, namespace=namespace, created_at=now_ms())
        ttl = None if timeout == -1 else timeout
        for _ in range(12):
            token = secrets.token_urlsafe(32)
            if await self._storage.set_if_absent(
                self._key(namespace, token),
                record.to_json(),
                ttl,
            ):
                if record_index and isinstance(value, str):
                    index_key = self._index_key(namespace, value)
                    previous = await self._storage.get(index_key)
                    if previous and previous != token:
                        await self._storage.delete(self._key(namespace, previous))
                    await self._storage.set(index_key, token, ttl)
                return token
        raise SecurityException("TEMP_TOKEN_ALLOCATION_FAILED", "无法分配唯一临时 token")

    async def parse(self, token: str, *, namespace: str = "default") -> Any | None:
        raw = await self._storage.get(self._key(namespace, token))
        record = TempTokenRecord.from_json(raw) if raw else None
        return record.value if record is not None else None

    async def consume(self, token: str, *, namespace: str = "default") -> Any | None:
        """原子读取并销毁；并发重复提交时恰好一个调用取得业务值。"""
        key = self._key(namespace, token)
        raw = await self._storage.get(key)
        if raw is None:
            return None
        record = TempTokenRecord.from_json(raw)
        if record is None:
            return None
        if not await self._storage.compare_and_delete(key, raw):
            return None
        if isinstance(record.value, str):
            index_key = self._index_key(namespace, record.value)
            await self._storage.compare_and_delete(index_key, token)
        return record.value

    async def delete(self, token: str, *, namespace: str = "default") -> bool:
        key = self._key(namespace, token)
        raw = await self._storage.get(key)
        if raw is None:
            return False
        record = TempTokenRecord.from_json(raw)
        deleted = await self._storage.compare_and_delete(key, raw)
        if deleted and record is not None and isinstance(record.value, str):
            await self._storage.compare_and_delete(self._index_key(namespace, record.value), token)
        return deleted

    async def find_token(self, value: str, *, namespace: str = "default") -> str | None:
        return await self._storage.get(self._index_key(namespace, value))
