"""OAuth2 数据模型。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from ..model import now_ms

__all__ = ["OAuth2Client", "AuthorizationCode", "AccessTokenInfo", "TokenResponse"]


@dataclass
class OAuth2Client:
    """已注册的客户端。

    ``client_secret`` 为空表示公开客户端（SPA / 移动端），此类客户端
    **必须**使用 PKCE，否则授权码可能被同设备上的恶意应用截获。
    """

    client_id: str
    client_secret: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=lambda: ["authorization_code"])
    scopes: list[str] = field(default_factory=list)
    name: str | None = None

    @property
    def is_public(self) -> bool:
        return not self.client_secret

    def allows_redirect(self, redirect_uri: str) -> bool:
        # 精确匹配，不做前缀匹配：前缀匹配是经典的开放重定向漏洞来源。
        return redirect_uri in self.redirect_uris

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> OAuth2Client | None:
        try:
            payload = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(payload, dict) or "client_id" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class AuthorizationCode:
    code: str
    client_id: str
    login_id: str
    redirect_uri: str
    scopes: list[str] = field(default_factory=list)
    create_time: int = field(default_factory=now_ms)
    code_challenge: str | None = None
    code_challenge_method: str = "S256"
    state: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> AuthorizationCode | None:
        try:
            payload = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(payload, dict) or "code" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class AccessTokenInfo:
    access_token: str
    client_id: str
    login_id: str
    scopes: list[str] = field(default_factory=list)
    create_time: int = field(default_factory=now_ms)
    expires_in: int = 7200

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> AccessTokenInfo | None:
        try:
            payload = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(payload, dict) or "access_token" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class TokenResponse:
    """``/oauth2/token`` 端点的标准响应体。"""

    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int = 7200
    scope: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token:
            payload["refresh_token"] = self.refresh_token
        return payload
