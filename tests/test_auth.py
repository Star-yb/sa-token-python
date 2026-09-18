"""核心认证语义：登录、校验、登出、踢人、顶号、多端。"""

from __future__ import annotations

import pytest

from sa_token import (
    NotLoginException,
    NotLoginType,
    SaTokenException,
    StpUtil,
    sa_token_context,
)


async def test_login_and_check(stp) -> None:
    token = await stp.login(10001)
    assert await stp.is_login(token) is True
    assert await stp.check_login(token) == "10001"


async def test_login_id_is_normalized_to_str(stp) -> None:
    token = await stp.login(10001)
    assert await stp.get_login_id(token) == "10001"


@pytest.mark.parametrize("bad_login_id", ["", "   ", None, "a:b"])
async def test_invalid_login_id_rejected(stp, bad_login_id) -> None:
    with pytest.raises(SaTokenException):
        await stp.login(bad_login_id)


async def test_missing_token_reports_not_token(stp) -> None:
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(None)
    assert excinfo.value.type is NotLoginType.NOT_TOKEN


async def test_unknown_token_reports_invalid(stp) -> None:
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login("not-a-real-token")
    assert excinfo.value.type is NotLoginType.INVALID_TOKEN


async def test_logout_removes_token_without_offline_reason(stp) -> None:
    token = await stp.login(10001)
    await stp.logout(10001)
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(token)
    assert excinfo.value.type is NotLoginType.INVALID_TOKEN
    assert await stp.get_offline_reason(token) is None


async def test_kickout_keeps_reason(stp) -> None:
    token = await stp.login(10001)
    await stp.kickout(10001)
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(token)
    assert excinfo.value.type is NotLoginType.KICK_OUT

    reason = await stp.get_offline_reason(token)
    assert reason is not None
    assert reason["reason"] == "KICK_OUT"


async def test_replaced_is_distinguishable_from_kickout(stp) -> None:
    token = await stp.login(10001)
    await stp.replaced(10001)
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(token)
    assert excinfo.value.type is NotLoginType.BE_REPLACED


async def test_logout_by_token_only_affects_that_device(stp) -> None:
    web_token = await stp.login(10001, device="web")
    app_token = await stp.login(10001, device="app")

    await stp.logout_by_token(web_token)

    assert await stp.is_login(web_token) is False
    assert await stp.is_login(app_token) is True


async def test_kickout_by_device(stp) -> None:
    web_token = await stp.login(10001, device="web")
    app_token = await stp.login(10001, device="app")

    await stp.kickout(10001, device="web")

    assert await stp.is_login(web_token) is False
    assert await stp.is_login(app_token) is True


# 多端矩阵：is_concurrent × is_share 决定了三种截然不同的产品行为。


async def test_not_concurrent_replaces_old_login(build_manager) -> None:
    stp = build_manager(is_concurrent=False).stp()
    first = await stp.login(10001, device="web")
    second = await stp.login(10001, device="web")

    assert first != second
    assert await stp.is_login(second) is True
    with pytest.raises(NotLoginException) as excinfo:
        await stp.check_login(first)
    assert excinfo.value.type is NotLoginType.BE_REPLACED


async def test_concurrent_share_reuses_token(build_manager) -> None:
    stp = build_manager(is_concurrent=True, is_share=True).stp()
    first = await stp.login(10001, device="web")
    second = await stp.login(10001, device="web")
    assert first == second


async def test_concurrent_share_is_per_device(build_manager) -> None:
    stp = build_manager(is_concurrent=True, is_share=True).stp()
    web = await stp.login(10001, device="web")
    app = await stp.login(10001, device="app")
    assert web != app


async def test_concurrent_without_share_issues_independent_tokens(build_manager) -> None:
    stp = build_manager(is_concurrent=True, is_share=False).stp()
    first = await stp.login(10001, device="web")
    second = await stp.login(10001, device="web")

    assert first != second
    assert await stp.is_login(first) is True
    assert await stp.is_login(second) is True


async def test_max_login_count_evicts_oldest(build_manager) -> None:
    stp = build_manager(is_concurrent=True, is_share=False, max_login_count=2).stp()
    first = await stp.login(10001, device="web")
    second = await stp.login(10001, device="web")
    third = await stp.login(10001, device="web")

    assert await stp.is_login(first) is False
    assert await stp.is_login(second) is True
    assert await stp.is_login(third) is True
    assert len(await stp.get_terminal_list(10001)) == 2


async def test_terminal_list_tracks_devices(stp) -> None:
    await stp.login(10001, device="web")
    await stp.login(10001, device="app")

    all_terminals = await stp.get_terminal_list(10001)
    assert {terminal.device for terminal in all_terminals} == {"web", "app"}
    assert len(await stp.get_terminal_list(10001, device="web")) == 1


async def test_token_list_by_login_id(stp) -> None:
    web = await stp.login(10001, device="web")
    app = await stp.login(10001, device="app")
    tokens = await stp.get_token_value_list_by_login_id(10001)
    assert set(tokens) == {web, app}


async def test_context_binding_removes_need_to_pass_token(manager) -> None:
    token = await StpUtil.login(10001)
    with sa_token_context(token):
        assert await StpUtil.check_login() == "10001"
        assert StpUtil.get_token_value() == token


async def test_login_types_are_isolated(manager) -> None:
    user_token = await manager.stp("user").login(10001)
    admin_token = await manager.stp("admin").login(10001)

    assert user_token != admin_token
    # 同一个 login_id 在两套体系里是两个独立身份，token 不可跨用。
    assert await manager.stp("admin").is_login(user_token) is False
    assert await manager.stp("user").is_login(admin_token) is False


async def test_search_token_value(stp) -> None:
    token = await stp.login(10001)
    found = await stp.search_token_value()
    assert token in found
