"""Nonce、登录 Refresh Token、Temp Token 与新增登录 API。"""

from __future__ import annotations

import asyncio
import json

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


async def test_nonce_strips_subject_and_rejects_revoked_state(manager) -> None:
    nonce = await manager.nonces.issue(" 10001 ", purpose="pay")
    await manager.nonces.consume(nonce, "10001", purpose="pay")

    issued = await manager.nonces.issue("10001")
    key = manager.nonces._key(issued)
    raw = await manager.storage.get(key)
    payload = json.loads(raw or "")
    payload["state"] = "revoked"
    await manager.storage.set(key, json.dumps(payload), 60)
    with pytest.raises(SecurityException) as error:
        await manager.nonces.consume(issued, "10001")
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


async def test_kickout_without_session_still_revokes_refresh(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001", device="web")
    await stp.logout("10001", device="web")
    await stp.kickout("10001")
    with pytest.raises(SecurityException):
        await manager.refresh_tokens.refresh(pair.refresh_token)


async def test_temp_token_rejects_none_and_keeps_corrupt_record(manager) -> None:
    with pytest.raises(SecurityException) as error:
        await manager.temp_tokens.create(None, 60)
    assert error.value.code == "TEMP_TOKEN_VALUE_NONE"

    token = "corrupt-token"
    key = f"{manager.config.storage_key_prefix}security:temp:default:{token}"
    await manager.storage.set(key, "not-json", 60)
    assert await manager.temp_tokens.consume(token) is None
    assert await manager.storage.get(key) == "not-json"

    with pytest.raises(SecurityException) as namespace_error:
        await manager.temp_tokens.parse("b:c", namespace="a")
    assert namespace_error.value.code == "INVALID_TEMP_TOKEN"


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


async def test_refresh_family_drops_logged_out_access(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001")
    rotated = await manager.refresh_tokens.refresh(pair.refresh_token)
    raw = await manager.storage.get(manager.refresh_tokens._refresh_key(rotated.refresh_token))
    family_id = json.loads(raw or "")["family_id"]
    family = json.loads(
        await manager.storage.get(manager.refresh_tokens._family_key(family_id)) or ""
    )
    assert pair.access_token not in family["access_tokens"]
    assert rotated.access_token in family["access_tokens"]


async def test_logout_without_session_still_revokes_refresh(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001", device="web")
    await stp.logout("10001", device="web")
    await stp.logout("10001")
    with pytest.raises(SecurityException) as error:
        await manager.refresh_tokens.refresh(pair.refresh_token)
    assert error.value.code == "INVALID_REFRESH_TOKEN"


async def test_issue_drops_refresh_when_family_update_fails(stp, manager, monkeypatch) -> None:
    async def fail_update(*args, **kwargs):
        raise SecurityException("REFRESH_CONFLICT", "conflict")

    monkeypatch.setattr(manager.refresh_tokens, "_update_family", fail_update)
    with pytest.raises(SecurityException) as error:
        await stp.login_with_refresh("10001")
    assert error.value.code == "REFRESH_CONFLICT"
    assert await stp.get_session("10001", create=False) is None


async def test_refresh_does_not_revive_deleted_record(stp, manager, monkeypatch) -> None:
    manager.config.refresh_token_rotate = False
    pair = await stp.login_with_refresh("10001")
    logic = manager.stp()
    original_login = logic.login
    refresh_key = manager.config.make_key("security", "refresh", pair.refresh_token)

    async def login_then_delete(*args, **kwargs):
        token = await original_login(*args, **kwargs)
        await manager.storage.delete(refresh_key)
        return token

    monkeypatch.setattr(logic, "login", login_then_delete)
    with pytest.raises(SecurityException):
        await manager.refresh_tokens.refresh(pair.refresh_token)
    assert await manager.storage.get(refresh_key) is None


async def test_kickout_revokes_refresh_family(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001")
    await stp.kickout("10001")
    with pytest.raises(SecurityException):
        await manager.refresh_tokens.refresh(pair.refresh_token)


async def test_refresh_rejects_missing_family(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001")
    raw = await manager.storage.get(
        manager.config.make_key("security", "refresh", pair.refresh_token)
    )
    family_id = json.loads(raw)["family_id"]
    await manager.storage.delete(
        manager.config.make_key("security", "refresh-family", family_id)
    )
    with pytest.raises(SecurityException) as error:
        await manager.refresh_tokens.refresh(pair.refresh_token)
    assert error.value.code == "REFRESH_FAMILY_REVOKED"
    assert await stp.is_login(pair.access_token)


async def test_refresh_restores_token_when_login_fails(stp, manager, monkeypatch) -> None:
    pair = await stp.login_with_refresh("10001")
    logic = manager.stp()

    async def fail_login(*args, **kwargs):
        raise RuntimeError("login failed")

    monkeypatch.setattr(logic, "login", fail_login)
    with pytest.raises(RuntimeError, match="login failed"):
        await manager.refresh_tokens.refresh(pair.refresh_token)

    monkeypatch.undo()
    rotated = await manager.refresh_tokens.refresh(pair.refresh_token)
    assert await stp.is_login(rotated.access_token)


async def test_kickout_after_refresh_login_keeps_kick_out_reason(stp, manager) -> None:
    pair = await stp.login_with_refresh("10001")
    await stp.kickout("10001")

    with pytest.raises(NotLoginException) as error:
        await stp.check_login(pair.access_token)
    assert error.value.type is NotLoginType.KICK_OUT

    reason = await stp.get_offline_reason(pair.access_token)
    assert reason is not None
    assert reason["reason"] == "KICK_OUT"

    with pytest.raises(SecurityException):
        await manager.refresh_tokens.refresh(pair.refresh_token)


async def test_replaced_after_refresh_login_keeps_replaced_reason(stp) -> None:
    pair = await stp.login_with_refresh("10001")
    await stp.replaced("10001")

    with pytest.raises(NotLoginException) as error:
        await stp.check_login(pair.access_token)
    assert error.value.type is NotLoginType.BE_REPLACED


async def test_kickout_by_token_after_refresh_login_keeps_kick_out_reason(stp) -> None:
    pair = await stp.login_with_refresh("10001")
    await stp.kickout_by_token(pair.access_token)

    with pytest.raises(NotLoginException) as error:
        await stp.check_login(pair.access_token)
    assert error.value.type is NotLoginType.KICK_OUT
