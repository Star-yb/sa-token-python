"""Nonce、登录 Refresh Token、Temp Token 与新增登录 API。"""

from __future__ import annotations

import asyncio

import pytest

from sa_token import NotLoginException, NotLoginType, SaTokenException, SecurityException


async def test_server_issued_nonce_is_bound_and_single_use(manager) -> None:
    nonce = await manager.nonces.issue("10001", purpose="login")
    assert await manager.nonces.exists(nonce)

    await manager.nonces.consume(nonce, "10001", purpose="login")
    assert not await manager.nonces.exists(nonce)

    with pytest.raises(SecurityException) as error:
        await manager.nonces.consume(nonce, "10001", purpose="login")
    assert error.value.code == "INVALID_NONCE"


async def test_nonce_rejects_cross_subject_or_purpose(manager) -> None:
    nonce = await manager.nonces.issue("10001", purpose="pay")
    with pytest.raises(SecurityException) as error:
        await manager.nonces.consume(nonce, "10002", purpose="pay")
    assert error.value.code == "NONCE_MISMATCH"
    assert await manager.nonces.exists(nonce)


async def test_temp_token_parse_does_not_consume(manager) -> None:
    token = await manager.temp_tokens.create(
        {"user_id": "10001"}, 300, namespace="reset"
    )
    assert await manager.temp_tokens.parse(token, namespace="reset") == {
        "user_id": "10001"
    }
    assert await manager.temp_tokens.consume(token, namespace="reset") == {
        "user_id": "10001"
    }
    assert await manager.temp_tokens.consume(token, namespace="reset") is None


async def test_temp_token_concurrent_consume_succeeds_once(manager) -> None:
    token = await manager.temp_tokens.create("invite:10001", 300)
    results = await asyncio.gather(
        *(manager.temp_tokens.consume(token) for _ in range(20))
    )
    assert results.count("invite:10001") == 1
    assert results.count(None) == 19


async def test_temp_token_value_index(manager) -> None:
    token = await manager.temp_tokens.create(
        "reset:10001", 300, namespace="reset", record_index=True
    )
    assert (
        await manager.temp_tokens.find_token("reset:10001", namespace="reset")
        == token
    )
    await manager.temp_tokens.consume(token, namespace="reset")
    assert (
        await manager.temp_tokens.find_token("reset:10001", namespace="reset")
        is None
    )


async def test_login_accepts_explicit_token(stp) -> None:
    token = await stp.login("10001", token_value="legacy-token")
    assert token == "legacy-token"
    assert await stp.check_login(token) == "10001"
    with pytest.raises(SaTokenException):
        await stp.login("10002", token_value="legacy-token")


async def test_kickout_by_token_only_affects_one_terminal(stp) -> None:
    web = await stp.login("10001", device="web")
    app = await stp.login("10001", device="app")
    await stp.kickout_by_token(web)

    with pytest.raises(NotLoginException) as error:
        await stp.check_login(web)
    assert error.value.type is NotLoginType.KICK_OUT
    assert await stp.is_login(app)


async def test_search_session(stp) -> None:
    await stp.login("user-100")
    await stp.login("admin-200")
    assert await stp.search_session("user") == ["user-100"]


async def test_login_refresh_rotation_and_replay_detection(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001", device="web")
    assert await stp.is_login(pair.access_token)

    rotated = await manager.refresh_tokens.refresh(pair.refresh_token)
    assert rotated.access_token != pair.access_token
    assert rotated.refresh_token != pair.refresh_token
    assert not await stp.is_login(pair.access_token)
    assert await stp.is_login(rotated.access_token)

    with pytest.raises(SecurityException) as error:
        await manager.refresh_tokens.refresh(pair.refresh_token)
    assert error.value.code == "REFRESH_TOKEN_REUSED"
    assert not await stp.is_login(rotated.access_token)


async def test_kickout_revokes_refresh_family(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001")
    await stp.kickout("10001")
    with pytest.raises(SecurityException):
        await manager.refresh_tokens.refresh(pair.refresh_token)
