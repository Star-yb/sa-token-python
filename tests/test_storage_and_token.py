"""存储契约、Token 风格、事件、活跃超时。"""

from __future__ import annotations

import asyncio

import pytest

from sa_token import Event, EventData, NotLoginException, NotLoginType
from sa_token.config import SaTokenConfig
from sa_token.storage import MemoryStorage
from sa_token.strategy import BUILTIN_STYLES, create_strategy


async def test_memory_storage_basic_roundtrip() -> None:
    storage = MemoryStorage()
    await storage.set("a", "1")
    assert await storage.get("a") == "1"
    assert await storage.exists("a") is True
    await storage.delete("a")
    assert await storage.get("a") is None


async def test_memory_storage_expiry() -> None:
    storage = MemoryStorage()
    await storage.set("a", "1", 1)
    assert await storage.ttl("a") <= 1
    await storage.set("b", "1", -1)
    assert await storage.ttl("b") == -1
    assert await storage.ttl("missing") == -2


async def test_memory_storage_expires_value() -> None:
    storage = MemoryStorage()
    await storage.set("a", "1", 1)
    await asyncio.sleep(1.05)
    assert await storage.get("a") is None


async def test_memory_storage_atomic_helpers() -> None:
    storage = MemoryStorage()
    assert await storage.set_if_absent("k", "v1") is True
    assert await storage.set_if_absent("k", "v2") is False

    assert await storage.compare_and_set("k", "wrong", "v3") is False
    assert await storage.compare_and_set("k", "v1", "v3") is True
    assert await storage.get("k") == "v3"

    assert await storage.compare_and_delete("k", "wrong") is False
    assert await storage.compare_and_delete("k", "v3") is True
    assert await storage.get("k") is None


async def test_memory_storage_scan() -> None:
    storage = MemoryStorage()
    for index in range(5):
        await storage.set(f"sa:token:{index}", "x")
    await storage.set("other", "x")

    cursor, keys = await storage.scan("sa:token:*", None, 100)
    assert cursor is None
    assert len(keys) == 5


@pytest.mark.parametrize("style", [s for s in BUILTIN_STYLES if s != "jwt"])
def test_token_styles_generate_unique_values(style: str) -> None:
    strategy = create_strategy(SaTokenConfig(token_style=style))
    tokens = {strategy.generate("10001") for _ in range(50)}
    # 同一个 login_id 反复生成必须得到不同 token，否则多端 / 顶号会失效。
    assert len(tokens) == 50
    assert all(token for token in tokens)


def test_unknown_token_style_is_rejected() -> None:
    with pytest.raises(ValueError):
        create_strategy(SaTokenConfig(token_style="nope"))


def test_config_normalizes_key_prefix() -> None:
    config = SaTokenConfig(storage_key_prefix="myapp")
    assert config.storage_key_prefix == "myapp:"
    assert config.make_key("login", "token", "abc") == "myapp:login:token:abc"


def test_config_from_dict_ignores_unknown_keys() -> None:
    config = SaTokenConfig.from_dict({"timeout": 60, "nope": 1})
    assert config.timeout == 60


async def test_events_are_emitted(build_manager) -> None:
    received: list[EventData] = []
    manager = build_manager()
    manager.on(Event.ALL, lambda data: received.append(data))

    stp = manager.stp()
    token = await stp.login(10001)
    await stp.kickout(10001)

    names = [item.event for item in received]
    assert Event.LOGIN in names
    assert Event.KICKOUT in names
    # 事件里只暴露指纹，不泄露原始 token。
    login_event = next(item for item in received if item.event is Event.LOGIN)
    assert login_event.token_fingerprint is not None
    assert login_event.token_fingerprint != token


async def test_listener_failure_does_not_break_login(build_manager) -> None:
    manager = build_manager()

    def broken_listener(data: EventData) -> None:
        raise RuntimeError("审计系统挂了")

    manager.on(Event.LOGIN, broken_listener)
    assert await manager.stp().login(10001)


async def test_active_timeout_freezes_token(build_manager) -> None:
    manager = build_manager(active_timeout=1, auto_renew=False)
    stp = manager.stp()
    token = await stp.login(10001)

    await asyncio.sleep(1.1)
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(token)
    assert excinfo.value.type is NotLoginType.TOKEN_FREEZE
    token_info = await stp.get_token_info(token)
    assert token_info is not None
    assert await stp.get_offline_reason(token) == {
        "reason": NotLoginType.TOKEN_FREEZE.value,
        "time": token_info.offline_time,
    }

    with pytest.raises(NotLoginException) as second_excinfo:
        await stp.check_login(token)
    assert second_excinfo.value.type is NotLoginType.TOKEN_FREEZE


async def test_auto_renew_keeps_token_active(build_manager) -> None:
    manager = build_manager(active_timeout=2, auto_renew=True)
    stp = manager.stp()
    token = await stp.login(10001)

    for _ in range(3):
        await asyncio.sleep(0.8)
        assert await stp.is_login(token) is True
