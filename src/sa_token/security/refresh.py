"""登录态 Refresh Token：与 OAuth2 Refresh Token 相互独立。"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from ..exception import SecurityException
from ..model import DEFAULT_DEVICE, now_ms

if TYPE_CHECKING:
    from ..manager import SaTokenManager

__all__ = ["LoginTokenPair", "RefreshTokenManager"]


@dataclass(frozen=True)
class LoginTokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 0
    refresh_expires_in: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _RefreshRecord:
    refresh_token: str
    access_token: str
    login_id: str
    login_type: str
    device: str
    family_id: str
    generation: int
    created_at: int = field(default_factory=now_ms)
    state: str = "active"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> _RefreshRecord | None:
        try:
            payload = json.loads(raw)
            return cls(**payload) if isinstance(payload, dict) else None
        except (TypeError, ValueError):
            return None


@dataclass
class _FamilyRecord:
    login_id: str
    login_type: str
    access_tokens: list[str] = field(default_factory=list)
    refresh_tokens: list[str] = field(default_factory=list)
    revoked: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> _FamilyRecord | None:
        try:
            payload = json.loads(raw)
            return cls(**payload) if isinstance(payload, dict) else None
        except (TypeError, ValueError):
            return None


class RefreshTokenManager:
    """登录态 access/refresh 生命周期管理。

    旧 refresh token 会保留为 ``used`` 墓碑直到有效期结束。再次使用旧值时，
    视为泄漏并吊销同一 family 的全部 access/refresh token。
    """

    def __init__(self, manager: SaTokenManager) -> None:
        self._manager = manager

    @property
    def _storage(self):
        return self._manager.storage

    def _refresh_key(self, token: str) -> str:
        return self._manager.config.make_key("security", "refresh", token)

    def _family_key(self, family_id: str) -> str:
        return self._manager.config.make_key("security", "refresh-family", family_id)

    def _user_index_key(self, login_type: str, login_id: str) -> str:
        return self._manager.config.make_key(
            "security", "refresh-user", f"{login_type}:{login_id}"
        )

    async def issue(
        self,
        access_token: str,
        login_id: str,
        *,
        login_type: str = "login",
        device: str = DEFAULT_DEVICE,
        family_id: str | None = None,
        generation: int = 0,
    ) -> LoginTokenPair:
        resolved_family = family_id or secrets.token_urlsafe(24)
        for _ in range(12):
            refresh_token = f"refresh_{secrets.token_urlsafe(36)}"
            record = _RefreshRecord(
                refresh_token=refresh_token,
                access_token=access_token,
                login_id=login_id,
                login_type=login_type,
                device=device,
                family_id=resolved_family,
                generation=generation,
            )
            if await self._storage.set_if_absent(
                self._refresh_key(refresh_token),
                record.to_json(),
                self._manager.config.refresh_token_timeout,
            ):
                break
        else:
            raise SecurityException("REFRESH_ALLOCATION_FAILED", "无法分配 refresh token")

        await self._update_family(resolved_family, record)
        await self._add_user_family(login_type, login_id, resolved_family)
        access_timeout = self._manager.config.timeout
        return LoginTokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=access_timeout,
            refresh_expires_in=self._manager.config.refresh_token_timeout,
        )

    async def refresh(self, refresh_token: str) -> LoginTokenPair:
        key = self._refresh_key(refresh_token)
        raw = await self._storage.get(key)
        record = _RefreshRecord.from_json(raw) if raw else None
        if record is None:
            raise SecurityException("INVALID_REFRESH_TOKEN", "refresh token 无效或已过期")
        if record.state != "active":
            if self._manager.config.refresh_token_reuse_detection:
                await self.revoke_family(record.family_id)
            raise SecurityException(
                "REFRESH_TOKEN_REUSED",
                "检测到旧 refresh token 重放，整个 token family 已吊销",
                login_type=record.login_type,
            )

        used_record = _RefreshRecord(**{**asdict(record), "state": "used"})
        if not await self._storage.compare_and_set(
            key,
            raw,
            used_record.to_json(),
            self._manager.config.refresh_token_timeout,
        ):
            if self._manager.config.refresh_token_reuse_detection:
                await self.revoke_family(record.family_id)
            raise SecurityException("REFRESH_TOKEN_REUSED", "refresh token 已被并发使用")

        logic = self._manager.stp(record.login_type)
        await logic.logout_by_token(record.access_token, revoke_refresh=False)
        new_access = await logic.login(
            record.login_id,
            device=record.device,
            timeout=self._manager.config.timeout,
        )

        if not self._manager.config.refresh_token_rotate:
            active_record = _RefreshRecord(
                **{
                    **asdict(record),
                    "access_token": new_access,
                    "created_at": now_ms(),
                    "state": "active",
                }
            )
            await self._storage.set(
                key,
                active_record.to_json(),
                self._manager.config.refresh_token_timeout,
            )
            await self._update_family(record.family_id, active_record)
            return LoginTokenPair(
                access_token=new_access,
                refresh_token=refresh_token,
                expires_in=self._manager.config.timeout,
                refresh_expires_in=self._manager.config.refresh_token_timeout,
            )

        return await self.issue(
            new_access,
            record.login_id,
            login_type=record.login_type,
            device=record.device,
            family_id=record.family_id,
            generation=record.generation + 1,
        )

    async def revoke(self, refresh_token: str) -> bool:
        key = self._refresh_key(refresh_token)
        raw = await self._storage.get(key)
        record = _RefreshRecord.from_json(raw) if raw else None
        if record is None:
            return False
        await self._storage.delete(key)
        await self._manager.stp(record.login_type).logout_by_token(
            record.access_token, revoke_refresh=False
        )
        return True

    async def revoke_for_access(self, access_token: str) -> None:
        prefix = self._manager.config.key_prefix("security")
        cursor: str | None = None
        while True:
            cursor, keys = await self._storage.scan(f"{prefix}refresh:*", cursor, 200)
            for key in keys:
                raw = await self._storage.get(key)
                record = _RefreshRecord.from_json(raw) if raw else None
                if record is not None and record.access_token == access_token:
                    await self._storage.delete(key)
            if cursor is None:
                return

    async def revoke_all_for_login(self, login_type: str, login_id: str) -> None:
        raw = await self._storage.get(self._user_index_key(login_type, login_id))
        families = json.loads(raw) if raw else []
        if isinstance(families, list):
            for family_id in families:
                await self.revoke_family(str(family_id))
        await self._storage.delete(self._user_index_key(login_type, login_id))

    async def revoke_family(self, family_id: str) -> None:
        key = self._family_key(family_id)
        raw = await self._storage.get(key)
        family = _FamilyRecord.from_json(raw) if raw else None
        if family is None:
            return
        family.revoked = True
        await self._storage.set(key, family.to_json(), self._manager.config.refresh_token_timeout)
        logic = self._manager.stp(family.login_type)
        for access_token in set(family.access_tokens):
            await logic.logout_by_token(access_token, revoke_refresh=False)
        for token in set(family.refresh_tokens):
            await self._storage.delete(self._refresh_key(token))

    async def _update_family(self, family_id: str, record: _RefreshRecord) -> None:
        key = self._family_key(family_id)
        for _ in range(12):
            raw = await self._storage.get(key)
            if raw is None:
                family = _FamilyRecord(record.login_id, record.login_type)
                family.access_tokens.append(record.access_token)
                family.refresh_tokens.append(record.refresh_token)
                if await self._storage.set_if_absent(
                    key, family.to_json(), self._manager.config.refresh_token_timeout
                ):
                    return
                continue
            family = _FamilyRecord.from_json(raw)
            if family is None or family.revoked:
                raise SecurityException("REFRESH_FAMILY_REVOKED", "token family 已被吊销")
            if record.access_token not in family.access_tokens:
                family.access_tokens.append(record.access_token)
            if record.refresh_token not in family.refresh_tokens:
                family.refresh_tokens.append(record.refresh_token)
            if await self._storage.compare_and_set(
                key,
                raw,
                family.to_json(),
                self._manager.config.refresh_token_timeout,
            ):
                return
        raise SecurityException("REFRESH_CONFLICT", "更新 token family 时发生并发冲突")

    async def _add_user_family(self, login_type: str, login_id: str, family_id: str) -> None:
        key = self._user_index_key(login_type, login_id)
        for _ in range(12):
            raw = await self._storage.get(key)
            families = json.loads(raw) if raw else []
            if family_id in families:
                return
            families.append(family_id)
            new_raw = json.dumps(families, separators=(",", ":"))
            if raw is None:
                if await self._storage.set_if_absent(
                    key, new_raw, self._manager.config.refresh_token_timeout
                ):
                    return
            elif await self._storage.compare_and_set(
                key, raw, new_raw, self._manager.config.refresh_token_timeout
            ):
                return
        raise SecurityException("REFRESH_CONFLICT", "更新用户 refresh 索引时发生并发冲突")
