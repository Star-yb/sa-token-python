"""在线用户管理与 WebSocket 鉴权。

连接鉴权复用 ``token_io`` + ``StpLogic.check_login``，不另起一套校验；
在线状态分两层：

- **存储层**：跨进程可见的在线记录，用于「谁在线」这类查询
- **进程内**：真实的连接对象，用于推送与断开

之所以拆两层：连接对象本身没法序列化进 Redis，跨进程踢人只能靠存储层
标记 + 各进程自己断开本地连接。
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from ..adapter.http import HttpContext
from ..exception import NotLoginException, NotLoginType
from ..listener import Event, EventData
from ..model import now_ms
from ..token_io import read_token

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from ..manager import SaTokenManager

__all__ = ["OnlineUser", "OnlineManager", "WebSocketAuthenticator"]

#: 推送回调：接收 (连接对象, 消息文本)。
Sender = Callable[[Any, str], Awaitable[None]]


@dataclass
class OnlineUser:
    login_id: str
    device: str = "default"
    connection_id: str = ""
    connect_time: int = field(default_factory=now_ms)
    last_heartbeat: int = field(default_factory=now_ms)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> OnlineUser | None:
        try:
            payload = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(payload, dict) or "login_id" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})


class OnlineManager:
    """在线用户注册表。"""

    def __init__(
        self,
        manager: SaTokenManager,
        *,
        heartbeat_timeout: int = 300,
        sender: Sender | None = None,
        closer: Callable[[Any], Awaitable[None]] | None = None,
    ) -> None:
        self._manager = manager
        self.heartbeat_timeout = heartbeat_timeout
        self._sender = sender
        self._closer = closer
        # login_id -> {connection_id: 连接对象}
        self._connections: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        manager.on(Event.KICKOUT, self._on_offline_event)
        manager.on(Event.REPLACED, self._on_offline_event)

    def _key(self, login_id: str, connection_id: str) -> str:
        return self._manager.config.make_key("online", "user", f"{login_id}:{connection_id}")

    @property
    def _storage(self):
        return self._manager.storage

    async def register(
        self,
        login_id: str,
        connection: Any,
        *,
        connection_id: str | None = None,
        device: str = "default",
    ) -> OnlineUser:
        """登记一条在线连接。"""
        resolved_id = connection_id or f"{id(connection):x}"
        user = OnlineUser(
            login_id=login_id,
            device=device,
            connection_id=resolved_id,
        )
        await self._storage.set(
            self._key(login_id, resolved_id), user.to_json(), self.heartbeat_timeout
        )
        async with self._lock:
            self._connections.setdefault(login_id, {})[resolved_id] = connection
        return user

    async def unregister(self, login_id: str, connection_id: str) -> None:
        await self._storage.delete(self._key(login_id, connection_id))
        async with self._lock:
            bucket = self._connections.get(login_id)
            if bucket is not None:
                bucket.pop(connection_id, None)
                if not bucket:
                    self._connections.pop(login_id, None)

    async def heartbeat(self, login_id: str, connection_id: str) -> bool:
        """刷新心跳，连接记录已过期时返回 False。"""
        key = self._key(login_id, connection_id)
        raw = await self._storage.get(key)
        if raw is None:
            return False
        user = OnlineUser.from_json(raw)
        if user is None:
            return False
        user.last_heartbeat = now_ms()
        await self._storage.set(key, user.to_json(), self.heartbeat_timeout)
        return True

    async def is_online(self, login_id: str) -> bool:
        cursor: str | None = None
        pattern = self._key(login_id, "*")
        while True:
            cursor, keys = await self._storage.scan(pattern, cursor, 50)
            if keys:
                return True
            if cursor is None:
                return False

    async def get_online_users(self, login_id: str) -> list[OnlineUser]:
        users: list[OnlineUser] = []
        cursor: str | None = None
        pattern = self._key(login_id, "*")
        while True:
            cursor, keys = await self._storage.scan(pattern, cursor, 100)
            for key in keys:
                raw = await self._storage.get(key)
                user = OnlineUser.from_json(raw) if raw else None
                if user is not None:
                    users.append(user)
            if cursor is None:
                return users

    def local_connections(self, login_id: str) -> list[Any]:
        """本进程持有的连接对象。"""
        return list(self._connections.get(login_id, {}).values())

    async def send_to_user(self, login_id: str, message: str) -> int:
        """向该用户在本进程上的所有连接推送，返回成功条数。"""
        if self._sender is None:
            raise RuntimeError("未配置 sender，无法推送消息")
        sent = 0
        for connection in self.local_connections(login_id):
            try:
                await self._sender(connection, message)
                sent += 1
            except Exception:
                # 推送失败通常意味着连接已断，交给连接自身的清理流程处理。
                continue
        return sent

    async def send_to_device(self, login_id: str, device: str, message: str) -> int:
        """只向指定设备类型推送。"""
        if self._sender is None:
            raise RuntimeError("未配置 sender，无法推送消息")
        online_users = await self.get_online_users(login_id)
        allowed_ids = {
            user.connection_id for user in online_users if user.device == device
        }
        sent = 0
        local = self._connections.get(login_id, {})
        for connection_id, connection in local.items():
            if connection_id not in allowed_ids:
                continue
            try:
                await self._sender(connection, message)
                sent += 1
            except Exception:
                continue
        return sent

    async def kickout(self, login_id: str) -> None:
        """踢人并断开该用户的连接。

        先走核心的 ``kickout`` 让 token 失效，再断开连接：顺序反了的话，
        客户端可能在断线重连的瞬间用旧 token 重新连上。
        """
        await self._manager.stp().kickout(login_id)

    async def disconnect_user(self, login_id: str) -> None:
        connections = self.local_connections(login_id)
        async with self._lock:
            connection_ids = list(self._connections.get(login_id, {}).keys())
            self._connections.pop(login_id, None)
        for connection_id in connection_ids:
            await self._storage.delete(self._key(login_id, connection_id))
        if self._closer is None:
            return
        for connection in connections:
            try:
                await self._closer(connection)
            except Exception:
                continue

    async def disconnect_device(self, login_id: str, device: str) -> None:
        """断开本进程中该用户指定设备的连接。"""
        online_users = await self.get_online_users(login_id)
        connection_ids = {
            user.connection_id for user in online_users if user.device == device
        }
        async with self._lock:
            bucket = self._connections.get(login_id, {})
            connections = [
                bucket.pop(connection_id)
                for connection_id in list(connection_ids)
                if connection_id in bucket
            ]
            if not bucket:
                self._connections.pop(login_id, None)
        for connection_id in connection_ids:
            await self._storage.delete(self._key(login_id, connection_id))
        if self._closer is not None:
            for connection in connections:
                try:
                    await self._closer(connection)
                except Exception:
                    continue

    async def cleanup_stale_connections(self) -> int:
        """清理 Storage TTL 已过期、但本进程仍残留的连接对象。"""
        stale: list[tuple[str, str, Any]] = []
        async with self._lock:
            for login_id, bucket in list(self._connections.items()):
                for connection_id, connection in list(bucket.items()):
                    if not await self._storage.exists(self._key(login_id, connection_id)):
                        stale.append((login_id, connection_id, connection))
                        bucket.pop(connection_id, None)
                if not bucket:
                    self._connections.pop(login_id, None)
        if self._closer is not None:
            for _, _, connection in stale:
                try:
                    await self._closer(connection)
                except Exception:
                    continue
        return len(stale)

    async def _on_offline_event(self, data: EventData) -> None:
        """StpUtil.kickout/replaced 也能自动断开本进程连接。"""
        if data.login_id is None:
            return
        if data.device:
            await self.disconnect_device(data.login_id, data.device)
        else:
            await self.disconnect_user(data.login_id)


class WebSocketAuthenticator:
    """WebSocket 连接鉴权。

    token 来源与 HTTP 完全一致（Header → Cookie → Query），因为浏览器
    WebSocket API 不能自定义 Header，Query 往往是唯一可用的通道。
    """

    def __init__(self, manager: SaTokenManager, *, login_type: str = "login") -> None:
        self._manager = manager
        self.login_type = login_type

    async def authenticate(self, ctx: HttpContext) -> str:
        """握手阶段鉴权，返回 ``login_id``，失败抛 :class:`NotLoginException`。"""
        token = read_token(ctx, self._manager.config)
        login_id = await self._manager.stp(self.login_type).check_login(token)
        ctx.state["stp_token"] = token
        ctx.state["stp_login_id"] = login_id
        return login_id

    async def authenticate_token(self, token: str | None) -> str:
        """已经自行取到 token（例如从首条消息里读）时使用。"""
        if not token:
            raise NotLoginException(NotLoginType.NOT_TOKEN, login_type=self.login_type)
        return await self._manager.stp(self.login_type).check_login(token)
