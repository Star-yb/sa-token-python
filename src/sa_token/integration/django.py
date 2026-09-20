"""Django 适配（同步中间件 + 装饰器）。

Django 自带一套完整的 Session/User 体系，因此这里的定位是：
给**纯 API 项目**（DRF / 无模板）提供与 FastAPI、Flask 一致的 Token 鉴权，
而不是替换 ``django.contrib.auth``。
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from ..adapter.http import HttpContext
from ..adapter.path import PathAuthConfig
from ..adapter.pipeline import build_rule, resolve_token, run_auth_flow, run_path_auth
from ..exception import SaTokenException
from ..permission import MatchMode
from ..stp_util import get_manager
from ..sync import run_sync

__all__ = [
    "DjangoHttpContext",
    "SaTokenDjangoMiddleware",
    "check_login",
    "check_permission",
    "check_role",
    "to_json_response",
]

_F = TypeVar("_F", bound=Callable[..., Any])

#: 由项目在 settings 里赋值，用于开启路径鉴权。
PATH_AUTH: PathAuthConfig | None = None


class DjangoHttpContext(HttpContext):
    def __init__(self, request: Any) -> None:
        self._request = request
        self.state: dict[str, Any] = {}

    def get_header(self, name: str) -> str | None:
        return self._request.headers.get(name)

    def get_cookie(self, name: str) -> str | None:
        return self._request.COOKIES.get(name)

    def get_query(self, name: str) -> str | None:
        return self._request.GET.get(name)

    def get_path(self) -> str:
        return self._request.path

    def get_method(self) -> str:
        return self._request.method


def to_json_response(exc: SaTokenException) -> Any:
    from django.http import JsonResponse

    payload: dict[str, Any] = {
        "code": exc.http_status,
        "message": exc.message,
        "error": type(exc).__name__,
    }
    detail_type = getattr(exc, "type", None)
    if detail_type is not None:
        payload["type"] = detail_type.value
    return JsonResponse(payload, status=exc.http_status)


class SaTokenDjangoMiddleware:
    """加入 ``MIDDLEWARE`` 即可。

    默认只解析 token 并挂到 ``request.sa_token`` / ``request.sa_login_id``；
    把 :data:`PATH_AUTH` 设为规则表后才执行强制鉴权。
    """

    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        self._get_response = get_response

    def __call__(self, request: Any) -> Any:
        ctx = DjangoHttpContext(request)
        manager = get_manager()
        try:
            if PATH_AUTH is None:
                resolve_token(ctx, manager)
            else:
                run_sync(run_path_auth(ctx, manager, PATH_AUTH))
        except SaTokenException as exc:
            return to_json_response(exc)

        request.sa_token = ctx.state.get("stp_token")
        request.sa_login_id = ctx.state.get("stp_login_id")
        return self._get_response(request)

    def process_exception(self, request: Any, exception: Exception) -> Any:
        if isinstance(exception, SaTokenException):
            return to_json_response(exception)
        return None


def _guard(rule_factory: Callable[[], Any]) -> Callable[[_F], _F]:
    def decorator(view: _F) -> _F:
        @functools.wraps(view)
        def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            ctx = DjangoHttpContext(request)
            try:
                result = run_sync(run_auth_flow(ctx, get_manager(), rule_factory()))
            except SaTokenException as exc:
                return to_json_response(exc)
            request.sa_login_id = result.login_id
            request.sa_token = result.token
            return view(request, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def check_login(view: _F) -> _F:
    """标准注解：``@check_login``。"""
    return _guard(build_rule)(view)


def check_permission(*permissions: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
    return _guard(lambda: build_rule(permissions=list(permissions), mode=mode))


def check_role(*roles: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
    return _guard(lambda: build_rule(roles=list(roles), mode=mode))
