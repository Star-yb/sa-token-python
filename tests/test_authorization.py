"""权限、角色、Session、封禁、二级认证。"""

from __future__ import annotations

import pytest

from sa_token import (
    DisableException,
    NotPermissionException,
    NotRoleException,
    NotSafeException,
)


async def test_permissions_support_wildcard(stp) -> None:
    await stp.set_permissions(10001, ["user:read", "order:*"])
    assert await stp.has_permission(10001, "order:delete") is True
    assert await stp.has_permission(10001, "user:write") is False


async def test_permission_and_or_modes(stp) -> None:
    await stp.set_permissions(10001, ["user:read", "order:*"])
    assert await stp.has_permissions_and(10001, ["user:read", "order:delete"]) is True
    assert await stp.has_permissions_and(10001, ["user:read", "admin:all"]) is False
    assert await stp.has_permissions_or(10001, ["admin:all", "order:read"]) is True


async def test_check_permission_raises_with_missing_item(stp) -> None:
    await stp.set_permissions(10001, ["user:read"])
    with pytest.raises(NotPermissionException) as excinfo:
        await stp.check_permission(10001, ["user:read", "admin:all"], mode="AND")
    assert excinfo.value.permission == "admin:all"


async def test_check_role(stp) -> None:
    await stp.set_roles(10001, ["admin"])
    await stp.check_role(10001, "admin")
    with pytest.raises(NotRoleException):
        await stp.check_role(10001, "super")


async def test_permission_mutation_helpers(stp) -> None:
    await stp.add_permission(10001, "user:read")
    await stp.add_permission(10001, "user:read")  # 幂等
    assert await stp.get_permissions(10001) == ["user:read"]

    await stp.remove_permission(10001, "user:read")
    assert await stp.get_permissions(10001) == []


async def test_stp_interface_is_used_when_configured(build_manager) -> None:
    calls: list[str] = []

    class DatabaseStpInterface:
        async def get_permission_list(self, login_id: str, login_type: str) -> list[str]:
            calls.append(login_id)
            return ["order:*"]

        async def get_role_list(self, login_id: str, login_type: str) -> list[str]:
            return ["manager"]

    from sa_token import SaToken
    from sa_token.storage import MemoryStorage

    manager = (
        SaToken.builder()
        .storage(MemoryStorage())
        .print_banner(False)
        .stp_interface(DatabaseStpInterface())
        .build()
    )
    stp = manager.stp()

    assert await stp.has_permission(10001, "order:delete") is True
    assert await stp.has_role(10001, "manager") is True
    assert calls == ["10001"]


async def test_session_roundtrip(stp) -> None:
    session = await stp.get_session(10001)
    assert session is not None
    await session.set("nickname", "alice")

    reloaded = await stp.get_session(10001)
    assert reloaded is not None
    assert await reloaded.get("nickname") == "alice"


async def test_session_not_created_when_create_false(stp) -> None:
    assert await stp.get_session(99999, create=False) is None


async def test_token_session_is_bound_to_single_token(stp) -> None:
    token = await stp.login(10001)
    session = await stp.get_token_session(token)
    assert session is not None
    await session.set("step", 1)

    await stp.logout_by_token(token)
    assert await stp.get_token_session(token) is None


async def test_disable_blocks_login(stp) -> None:
    await stp.disable(10001, 3600)
    assert await stp.is_disable(10001) is True
    with pytest.raises(DisableException):
        await stp.login(10001)

    await stp.untie(10001)
    assert await stp.is_disable(10001) is False
    assert await stp.login(10001)


async def test_disable_invalidates_existing_token(stp) -> None:
    token = await stp.login(10001)
    await stp.disable(10001, 3600)
    # 封禁必须立刻生效，不能等 token 自然过期。
    assert await stp.is_login(token) is False


async def test_disable_is_scoped_by_service_and_level(stp) -> None:
    await stp.disable(10001, 3600, service="comment", level=2)

    assert await stp.is_disable(10001, service="comment", level=1) is True
    assert await stp.is_disable(10001, service="comment", level=3) is False
    # 只封了评论服务，不影响登录。
    assert await stp.is_disable(10001) is False
    assert await stp.login(10001)


async def test_safe_auth_window(stp) -> None:
    token = await stp.login(10001)
    with pytest.raises(NotSafeException):
        await stp.check_safe(token, "pay")

    await stp.open_safe(token, "pay", 300)
    await stp.check_safe(token, "pay")

    await stp.close_safe(token, "pay")
    with pytest.raises(NotSafeException):
        await stp.check_safe(token, "pay")
