"""统一鉴权管道：所有框架适配层的唯一入口。

框架适配只做三件事：Request → HttpContext、调用这里、异常翻译成响应。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..context import set_current
from ..permission import MatchMode
from ..token_io import read_token
from .path import PathAuthConfig, PathRule

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from ..manager import SaTokenManager
    from .http import HttpContext

__all__ = ["AuthResult", "resolve_token", "run_auth_flow", "run_path_auth"]


@dataclass
class AuthResult:
    """鉴权结果。``login_id`` 为 None 表示匿名放行。"""

    token: str | None = None
    login_id: str | None = None
    anonymous: bool = False


def resolve_token(ctx: HttpContext, manager: SaTokenManager) -> str | None:
    """读取 token 并写入上下文，但**不做登录校验**。

    对应 Go 版的 ``TokenInterceptor``：让业务能拿到 token，同时保持接口公开。
    """
    token = read_token(ctx, manager.config)
    ctx.state["stp_token"] = token
    set_current(token, None)
    return token


async def run_auth_flow(
    ctx: HttpContext,
    manager: SaTokenManager,
    rule: PathRule,
    *,
    login_type: str = "login",
) -> AuthResult:
    """执行一条规则的完整鉴权流程。"""
    token = resolve_token(ctx, manager)
    if rule.ignore:
        return AuthResult(token=token, anonymous=True)
    if not (rule.require_login or rule.permissions or rule.roles):
        return AuthResult(token=token, anonymous=True)

    logic = manager.stp(login_type)
    login_id = await logic.check_login(token)

    if rule.permissions:
        await logic.check_permission(login_id, rule.permissions, mode=rule.mode)
    if rule.roles:
        await logic.check_role(login_id, rule.roles, mode=rule.mode)

    ctx.state["stp_login_id"] = login_id
    ctx.state["stp_token"] = token
    set_current(token, login_id)
    return AuthResult(token=token, login_id=login_id)


async def run_path_auth(
    ctx: HttpContext,
    manager: SaTokenManager,
    path_auth: PathAuthConfig,
    *,
    login_type: str = "login",
) -> AuthResult:
    """按路径规则表鉴权。"""
    rule = path_auth.resolve(ctx.get_path(), ctx.get_method())
    return await run_auth_flow(ctx, manager, rule, login_type=login_type)


def build_rule(
    *,
    require_login: bool = True,
    permissions: list[str] | None = None,
    roles: list[str] | None = None,
    mode: MatchMode = "OR",
) -> PathRule:
    """给装饰器 / Depends 用的临时规则。"""
    return PathRule(
        pattern="",
        require_login=require_login,
        permissions=list(permissions or []),
        roles=list(roles or []),
        mode=mode,
    )
