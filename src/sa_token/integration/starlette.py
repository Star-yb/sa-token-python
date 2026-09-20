"""Starlette / FastAPI 共用的适配层。

职责严格限定在三件事：Request → HttpContext、调用统一管道、异常翻译。
鉴权逻辑一行都不在这里实现。

注意：这里必须在**运行时**导入 Starlette 的 ``Request``，不能放进
``TYPE_CHECKING``。FastAPI 依靠运行时类型注解判断依赖项参数，
拿不到真实类型时会把 ``request`` 当成查询参数，返回 422。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

try:
    from starlette.applications import Starlette
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError as exc:  # pragma: no cover - 依赖缺失路径
    raise ImportError(
        '该模块需要 starlette，请执行：pip install "sa-token-python-core[fastapi]"'
    ) from exc

from ..adapter.http import HttpContext
from ..adapter.path import PathAuthConfig
from ..adapter.pipeline import build_rule, resolve_token, run_auth_flow, run_path_auth
from ..exception import SaTokenException
from ..permission import MatchMode
from ..stp_util import get_manager

__all__ = [
    "StarletteHttpContext",
    "SaTokenMiddleware",
    "install_exception_handlers",
    "sa_token_exception_handler",
    "check_login",
    "check_permission",
    "check_role",
    "check_disable",
    "check_safe",
    "current_login_id",
    "current_login_id_or_none",
    "current_token",
]


class StarletteHttpContext(HttpContext):
    """把 Starlette ``Request`` 包装成框架无关的上下文。"""

    def __init__(self, request: Request) -> None:
        self._request = request
        self.state: dict[str, Any] = {}

    def get_header(self, name: str) -> str | None:
        return self._request.headers.get(name)

    def get_cookie(self, name: str) -> str | None:
        return self._request.cookies.get(name)

    def get_query(self, name: str) -> str | None:
        return self._request.query_params.get(name)

    def get_path(self) -> str:
        return self._request.url.path

    def get_method(self) -> str:
        return self._request.method


def _error_response(exc: SaTokenException) -> Response:
    payload: dict[str, Any] = {
        "code": exc.http_status,
        "message": exc.message,
        "error": type(exc).__name__,
    }
    detail_type = getattr(exc, "type", None)
    if detail_type is not None:
        payload["type"] = detail_type.value
    return JSONResponse(payload, status_code=exc.http_status)


class SaTokenMiddleware(BaseHTTPMiddleware):
    """请求级中间件。

    默认只解析 token 并绑定上下文，**不强制登录**：登录接口、健康检查这类
    公开路由永远存在，默认拦截会逼用户到处写例外。传入 ``path_auth``
    后才按规则表执行鉴权。
    """

    def __init__(
        self,
        app: Any,
        *,
        path_auth: PathAuthConfig | None = None,
        login_type: str = "login",
    ) -> None:
        super().__init__(app)
        self.path_auth = path_auth
        self.login_type = login_type

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        ctx = StarletteHttpContext(request)
        manager = get_manager()
        try:
            if self.path_auth is None:
                resolve_token(ctx, manager)
            else:
                await run_path_auth(ctx, manager, self.path_auth, login_type=self.login_type)
        except SaTokenException as exc:
            return _error_response(exc)

        request.state.sa_token = ctx.state.get("stp_token")
        request.state.sa_login_id = ctx.state.get("stp_login_id")
        return await call_next(request)


async def sa_token_exception_handler(request: Request, exc: Exception) -> Response:
    """把核心异常翻译成 401 / 403 / 500。"""
    assert isinstance(exc, SaTokenException)
    return _error_response(exc)


def install_exception_handlers(app: Starlette) -> None:
    """注册异常处理器，让路由里抛出的鉴权异常也能正确变成 HTTP 状态码。"""
    app.add_exception_handler(SaTokenException, sa_token_exception_handler)


# FastAPI / Starlette 的 Depends 工厂（扩展写法）。
# 各框架标准鉴权是注解：FastAPI 用 @sa.check_login，见 SaTokenFastAPI。


async def _authorize(
    request: Request,
    *,
    permissions: list[str] | None = None,
    roles: list[str] | None = None,
    mode: MatchMode = "OR",
) -> tuple[str, str | None]:
    ctx = StarletteHttpContext(request)
    rule = build_rule(permissions=permissions, roles=roles, mode=mode)
    result = await run_auth_flow(ctx, get_manager(), rule)
    assert result.login_id is not None
    request.state.sa_login_id = result.login_id
    request.state.sa_token = result.token
    return result.login_id, result.token


def check_login() -> Callable[[Request], Awaitable[str]]:
    """Depends 扩展：``Depends(check_login())``。标准写法是 ``@sa.check_login``。"""

    async def dependency(request: Request) -> str:
        login_id, _ = await _authorize(request)
        return login_id

    return dependency


def check_permission(
    *permissions: str,
    mode: MatchMode = "OR",
) -> Callable[[Request], Awaitable[str]]:
    """Depends 扩展：``Depends(check_permission("order:delete"))``。"""

    async def dependency(request: Request) -> str:
        login_id, _ = await _authorize(request, permissions=list(permissions), mode=mode)
        return login_id

    return dependency


def check_role(*roles: str, mode: MatchMode = "OR") -> Callable[[Request], Awaitable[str]]:
    """Depends 扩展：``Depends(check_role("admin"))``。"""

    async def dependency(request: Request) -> str:
        login_id, _ = await _authorize(request, roles=list(roles), mode=mode)
        return login_id

    return dependency


def check_disable(
    service: str = "login",
    level: int = 1,
) -> Callable[[Request], Awaitable[str]]:
    """Depends 扩展：``Depends(check_disable("comment"))``。"""

    async def dependency(request: Request) -> str:
        login_id, _ = await _authorize(request)
        await get_manager().stp().check_disable(login_id, service=service, level=level)
        return login_id

    return dependency


def check_safe(business: str) -> Callable[[Request], Awaitable[str]]:
    """Depends 扩展：``Depends(check_safe("pay"))``。"""

    async def dependency(request: Request) -> str:
        login_id, token = await _authorize(request)
        await get_manager().stp().check_safe(token, business)
        return login_id

    return dependency


async def current_login_id(request: Request) -> str:
    """Depends 扩展：``Depends(current_login_id)``。标准写法是 ``@sa.check_login``。"""
    login_id, _ = await _authorize(request)
    return login_id


async def current_login_id_or_none(request: Request) -> str | None:
    """Depends 扩展：未登录时返回 None。"""
    ctx = StarletteHttpContext(request)
    token = resolve_token(ctx, get_manager())
    return await get_manager().stp().get_login_id_or_none(token)


async def current_token(request: Request) -> str | None:
    """Depends 扩展：只取 token，不做校验。"""
    return resolve_token(StarletteHttpContext(request), get_manager())
