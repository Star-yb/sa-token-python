"""适配层：token 读取顺序、路径匹配、统一管道。

这些用例是防止「各框架行为分叉」的护栏。
"""

from __future__ import annotations

import pytest

from sa_token import NotLoginException, NotPermissionException
from sa_token.adapter import (
    PathAuthConfig,
    SimpleHttpContext,
    ant_match,
    build_rule,
    run_auth_flow,
    run_path_auth,
)
from sa_token.config import SaTokenConfig
from sa_token.token_io import cut_token_prefix, read_token


def test_read_token_prefers_header() -> None:
    ctx = SimpleHttpContext(
        headers={"Authorization": "Bearer header-token"},
        cookies={"Authorization": "cookie-token"},
        query={"Authorization": "query-token"},
    )
    assert read_token(ctx, SaTokenConfig()) == "header-token"


def test_read_token_falls_back_to_cookie_then_query() -> None:
    config = SaTokenConfig()
    cookie_ctx = SimpleHttpContext(
        cookies={"Authorization": "cookie-token"},
        query={"Authorization": "query-token"},
    )
    assert read_token(cookie_ctx, config) == "cookie-token"

    query_ctx = SimpleHttpContext(query={"Authorization": "query-token"})
    assert read_token(query_ctx, config) == "query-token"


def test_custom_token_name_still_accepts_authorization_header() -> None:
    config = SaTokenConfig(token_name="X-Token")
    ctx = SimpleHttpContext(headers={"Authorization": "Bearer abc"})
    assert read_token(ctx, config) == "abc"


def test_header_lookup_is_case_insensitive() -> None:
    ctx = SimpleHttpContext(headers={"authorization": "Bearer abc"})
    assert read_token(ctx, SaTokenConfig()) == "abc"


def test_disabled_sources_are_respected() -> None:
    config = SaTokenConfig(is_read_header=False, is_read_cookie=False)
    ctx = SimpleHttpContext(
        headers={"Authorization": "header"},
        cookies={"Authorization": "cookie"},
        query={"Authorization": "query"},
    )
    assert read_token(ctx, config) == "query"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("abc", "abc"),  # 不带前缀同样接受
        ("   ", None),
        (None, None),
    ],
)
def test_cut_token_prefix(raw: str | None, expected: str | None) -> None:
    assert cut_token_prefix(raw, "Bearer ") == expected


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/admin/**", "/admin/user/list", True),
        ("/admin/**", "/admin", True),
        ("/admin/*", "/admin/user", True),
        ("/admin/*", "/admin/user/list", False),
        ("/**", "/anything/deep", True),
        ("/health", "/health", True),
        ("/health", "/healthz", False),
        ("/api/*/detail", "/api/user/detail", True),
    ],
)
def test_ant_match(pattern: str, path: str, expected: bool) -> None:
    assert ant_match(pattern, path) is expected


def test_path_auth_filters_by_http_method() -> None:
    """同一路径可以对 GET / POST 施加不同规则，对应 Java SaRouter.match(SaHttpMethod.POST)。"""
    path_auth = (
        PathAuthConfig()
        .ignore("/article", methods=["GET"])
        .permission("/article", "article:write", methods=["POST", "PUT"])
        .login("/**")
    )

    get_rule = path_auth.resolve("/article", "GET")
    assert get_rule.ignore is True

    post_rule = path_auth.resolve("/article", "POST")
    assert post_rule.ignore is False
    assert post_rule.require_login is True
    assert post_rule.permissions == ["article:write"]

    delete_rule = path_auth.resolve("/article", "DELETE")
    assert delete_rule.require_login is True
    assert delete_rule.permissions == []


def test_path_auth_ignore_without_methods_covers_all_verbs() -> None:
    path_auth = PathAuthConfig().ignore("/login").login("/**")
    assert path_auth.resolve("/login", "POST").ignore is True
    assert path_auth.resolve("/login", "GET").ignore is True
    assert path_auth.resolve("/user", "GET").require_login is True


def test_path_auth_merges_matching_rules() -> None:
    path_auth = (
        PathAuthConfig()
        .login("/admin/**")
        .permission("/admin/user/**", "user:manage")
    )
    rule = path_auth.resolve("/admin/user/list", "GET")
    assert rule.require_login is True
    assert rule.permissions == ["user:manage"]


async def test_run_auth_flow_binds_state(manager) -> None:
    token = await manager.stp().login(10001)
    ctx = SimpleHttpContext(headers={"Authorization": f"Bearer {token}"})

    result = await run_auth_flow(ctx, manager, build_rule())

    assert result.login_id == "10001"
    assert ctx.state["stp_login_id"] == "10001"
    assert ctx.state["stp_token"] == token


async def test_run_auth_flow_rejects_missing_token(manager) -> None:
    with pytest.raises(NotLoginException):
        await run_auth_flow(SimpleHttpContext(), manager, build_rule())


async def test_run_auth_flow_checks_permission(manager) -> None:
    token = await manager.stp().login(10001)
    await manager.stp().set_permissions(10001, ["user:read"])
    ctx = SimpleHttpContext(headers={"Authorization": f"Bearer {token}"})

    with pytest.raises(NotPermissionException):
        await run_auth_flow(ctx, manager, build_rule(permissions=["user:delete"]))


async def test_run_path_auth_allows_ignored_path(manager) -> None:
    path_auth = PathAuthConfig().ignore("/login").login("/**")
    ctx = SimpleHttpContext(path="/login", method="POST")

    result = await run_path_auth(ctx, manager, path_auth)
    assert result.anonymous is True
