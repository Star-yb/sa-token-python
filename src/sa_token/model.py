"""核心数据模型。

所有模型都能无损地 JSON 序列化：存储层只接受字符串，这样才能跨进程、
跨语言共享同一份 Redis 数据，也避免 pickle 带来的反序列化风险。
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .exception import NotLoginType

__all__ = [
    "DEFAULT_DEVICE",
    "DEFAULT_LOGIN_TYPE",
    "TokenInfo",
    "TerminalInfo",
    "SessionData",
    "now_ms",
]

DEFAULT_DEVICE = "default"
DEFAULT_LOGIN_TYPE = "login"

#: token 记录里允许出现的下线状态，与 NotLoginType 中的子集一一对应。
_OFFLINE_STATES = {
    NotLoginType.KICK_OUT.value,
    NotLoginType.BE_REPLACED.value,
    NotLoginType.TOKEN_FREEZE.value,
}


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class TokenInfo:
    """``token -> 身份`` 的存储记录。

    被踢 / 被顶时不删除该记录，而是把 ``state`` 置为下线原因并缩短 TTL，
    这样下一次请求能返回明确原因，而不是笼统的「未登录」。
    """

    login_id: str
    device: str = DEFAULT_DEVICE
    login_type: str = DEFAULT_LOGIN_TYPE
    create_time: int = field(default_factory=now_ms)
    active_time: int = field(default_factory=now_ms)
    timeout: int | None = None
    active_timeout: int | None = None
    tag: str | None = None
    state: str | None = None
    offline_time: int | None = None

    @property
    def is_offline(self) -> bool:
        return self.state in _OFFLINE_STATES

    @property
    def offline_type(self) -> NotLoginType | None:
        if not self.is_offline:
            return None
        return NotLoginType(self.state)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> TokenInfo | None:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, dict) or "login_id" not in payload:
            return None
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class TerminalInfo:
    """Account-Session 中的一条在线终端记录。"""

    token: str
    device: str = DEFAULT_DEVICE
    login_time: int = field(default_factory=now_ms)
    index: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TerminalInfo:
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class SessionData:
    """Session 的可序列化载荷。

    Account-Session 额外承担「该账号当前有哪些终端在线」的索引职责，
    避免为多端登录再维护一份容易和 Session 失配的索引键。
    """

    id: str
    create_time: int = field(default_factory=now_ms)
    data: dict[str, Any] = field(default_factory=dict)
    terminal_list: list[TerminalInfo] = field(default_factory=list)
    history_terminal_count: int = 0

    def to_json(self) -> str:
        payload = {
            "id": self.id,
            "create_time": self.create_time,
            "data": self.data,
            "terminal_list": [terminal.to_dict() for terminal in self.terminal_list],
            "history_terminal_count": self.history_terminal_count,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> SessionData | None:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, dict) or "id" not in payload:
            return None
        terminals = [
            TerminalInfo.from_dict(item)
            for item in payload.get("terminal_list", [])
            if isinstance(item, dict)
        ]
        return cls(
            id=payload["id"],
            create_time=payload.get("create_time", now_ms()),
            data=payload.get("data", {}),
            terminal_list=terminals,
            history_terminal_count=payload.get("history_terminal_count", len(terminals)),
        )
