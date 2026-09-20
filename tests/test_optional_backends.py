"""可选依赖：JWT 策略与 Redis 存储。

这两项都通过同一套核心语义验证——换了 token 外观或换了存储，
踢人、顶号、封禁的行为都不能变。
"""

from __future__ import annotations

import pytest

from sa_token import NotLoginException, NotLoginType, SaToken
from sa_token.storage import MemoryStorage

# ------------------------------------------------------------------ JWT

pyjwt = pytest.importorskip("jwt")

#: HS256 要求至少 32 字节密钥，短密钥会被 PyJWT 警告。
JWT_SECRET = "test-secret-key-that-is-long-enough-for-hs256"


@pytest.fixture
def jwt_manager():
    from sa_token.stp_util import clear_manager

    manager = (
        SaToken.builder()
        .storage(MemoryStorage())
        .print_banner(False)
        .token_style("jwt")
        .jwt_secret_key(JWT_SECRET)
        .build()
    )
    yield manager
    clear_manager()


async def test_jwt_token_carries_claims(jwt_manager) -> None:
    stp = jwt_manager.stp()
    token = await stp.login(10001)

    payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    assert payload["loginId"] == "10001"


async def test_jwt_is_stateful_so_kickout_still_works(jwt_manager) -> None:
    """JWT 只是 token 的外观，身份仍以存储为准。"""
    stp = jwt_manager.stp()
    token = await stp.login(10001)
    assert await stp.is_login(token) is True

    await stp.kickout(10001)

    # token 本身签名依然有效，但服务端已经作废它。
    assert pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(token)
    assert excinfo.value.type is NotLoginType.KICK_OUT


async def test_jwt_multi_login_gets_distinct_tokens(jwt_manager) -> None:
    stp = jwt_manager.stp()
    first = await stp.login(10001, device="web")
    second = await stp.login(10001, device="app")
    assert first != second


def test_jwt_requires_secret_key() -> None:
    from sa_token.config import SaTokenConfig
    from sa_token.strategy import create_strategy

    with pytest.raises(ValueError):
        create_strategy(SaTokenConfig(token_style="jwt"))


# ---------------------------------------------------------------- Redis


@pytest.fixture
def redis_storage():
    fakeredis = pytest.importorskip("fakeredis")
    from sa_token.storage.redis import RedisStorage

    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisStorage(client)


async def test_redis_storage_satisfies_contract(redis_storage) -> None:
    await redis_storage.set("a", "1")
    assert await redis_storage.get("a") == "1"
    assert await redis_storage.exists("a") is True

    assert await redis_storage.set_if_absent("a", "2") is False
    assert await redis_storage.compare_and_set("a", "1", "3") is True
    assert await redis_storage.get("a") == "3"
    assert await redis_storage.compare_and_delete("a", "3") is True
    assert await redis_storage.get("a") is None


async def test_redis_storage_ttl(redis_storage) -> None:
    await redis_storage.set("a", "1", 60)
    assert 0 < await redis_storage.ttl("a") <= 60

    await redis_storage.set("b", "1", -1)
    assert await redis_storage.ttl("b") == -1
    assert await redis_storage.ttl("missing") == -2


async def test_redis_storage_scan(redis_storage) -> None:
    for index in range(5):
        await redis_storage.set(f"sa:token:{index}", "x")

    found: list[str] = []
    cursor: str | None = None
    while True:
        cursor, keys = await redis_storage.scan("sa:token:*", cursor, 10)
        found.extend(keys)
        if cursor is None:
            break
    assert len(found) == 5


async def test_full_auth_flow_on_redis(redis_storage) -> None:
    from sa_token.stp_util import clear_manager

    manager = SaToken.builder().storage(redis_storage).print_banner(False).build()
    try:
        stp = manager.stp()
        token = await stp.login(10001, device="web")
        await stp.set_permissions(10001, ["order:*"])

        assert await stp.check_login(token) == "10001"
        assert await stp.has_permission(10001, "order:delete") is True

        await stp.kickout(10001)
        with pytest.raises(NotLoginException) as excinfo:
            await stp.check_login(token)
        assert excinfo.value.type is NotLoginType.KICK_OUT
    finally:
        clear_manager()
