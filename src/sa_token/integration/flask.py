"""Flask 适配。

Flask 是 WSGI 同步框架，所有调用经由 :mod:`sa_token.sync` 的同步桥接进入
同一套 ``StpLogic``，不存在第二份鉴权实现。
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

from ..adapter.http import HttpContext
from ..adapter.path import PathAuthConfig
from ..adapter.pipeline import build_rule, resolve_token, run_auth_flow, run_path_auth
from ..exception import SaTokenException
from ..permission import MatchMode
from ..stp_util import get_manager
from ..sync import run_sync

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from flask import Flask

__all__ = ["FlaskHttpContext", "SaTokenFlask"]

_F = TypeVar("_F", bound=Callable[..., Any])


class FlaskHttpContext(HttpContext):
    """把 Flask ``request`` 包装成框架无关的上下文。"""

    def __init__(self, request: Any) -> None:
        self._request = request
        self.state: dict[str, Any] = {}

    def get_header(self, name: str) -> str | None:
        return self._request.headers.get(name)

    def get_cookie(self, name: str) -> str | None:
        return self._request.cookies.get(name)

    def get_query(self, name: str) -> str | None:
        return self._request.args.get(name)

    def get_path(self) -> str:
        return self._request.path

    def get_method(self) -> str:
        return self._request.method


class SaTokenFlask:
    """Flask 的标准注解鉴权，与 FastAPI / Django 同一套语义。

    用法::

        sa = SaTokenFlask(app)

        @app.get("/user")
        @sa.check_login
        def user_info():
            return {"id": sa.login_id()}
    """

    def __init__(
        self,
        app: Flask | None = None,
        *,
        path_auth: PathAuthConfig | None = None,
        login_type: str = "login",
    ) -> None:
        self.path_auth = path_auth
        self.login_type = login_type
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.before_request(self._before_request)
        app.register_error_handler(SaTokenException, self._handle_exception)

    # 请求钩子 --------------------------------------------------------------

    def _context(self) -> FlaskHttpContext:
        from flask import request

        return FlaskHttpContext(request)

    def _before_request(self) -> Any:
        from flask import g

        ctx = self._context()
        manager = get_manager()
        if self.path_auth is None:
            resolve_token(ctx, manager)
        else:
            run_sync(run_path_auth(ctx, manager, self.path_auth, login_type=self.login_type))
        g.sa_token = ctx.state.get("stp_token")
        g.sa_login_id = ctx.state.get("stp_login_id")
        return None

    def _handle_exception(self, exc: SaTokenException) -> Any:
        from flask import jsonify

        payload: dict[str, Any] = {
            "code": exc.http_status,
            "message": exc.message,
            "error": type(exc).__name__,
        }
        detail_type = getattr(exc, "type", None)
        if detail_type is not None:
            payload["type"] = detail_type.value
        return jsonify(payload), exc.http_status

    # 取值 -----------------------------------------------------------------

    def token(self) -> str | None:
        return resolve_token(self._context(), get_manager())

    def login_id(self) -> str:
        """当前登录用户；未登录抛异常（会被错误处理器转成 401）。"""
        from flask import g

        cached = getattr(g, "sa_login_id", None)
        if cached:
            return cached
        result = run_sync(run_auth_flow(self._context(), get_manager(), build_rule()))
        assert result.login_id is not None
        g.sa_login_id = result.login_id
        return result.login_id

    def login_id_or_none(self) -> str | None:
        return run_sync(get_manager().stp(self.login_type).get_login_id_or_none(self.token()))

    # 装饰器 ----------------------------------------------------------------

    def _guard(self, rule_factory: Callable[[], Any]) -> Callable[[_F], _F]:
        def decorator(view: _F) -> _F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                from flask import g

                result = run_sync(
                    run_auth_flow(
                        self._context(),
                        get_manager(),
                        rule_factory(),
                        login_type=self.login_type,
                    )
                )
                g.sa_login_id = result.login_id
                g.sa_token = result.token
                return view(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    @property
    def check_login(self) -> Callable[[_F], _F]:
        """标准注解：``@sa.check_login``。"""
        return self._guard(build_rule)

    def check_permission(self, *permissions: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
        return self._guard(lambda: build_rule(permissions=list(permissions), mode=mode))

    def check_role(self, *roles: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
        return self._guard(lambda: build_rule(roles=list(roles), mode=mode))

    def check_safe(self, business: str) -> Callable[[_F], _F]:
        def decorator(view: _F) -> _F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logic = get_manager().stp(self.login_type)
                run_sync(logic.check_safe(self.token(), business))
                return view(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def check_disable(self, service: str = "login", level: int = 1) -> Callable[[_F], _F]:
        def decorator(view: _F) -> _F:
            @functools.wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logic = get_manager().stp(self.login_type)
                run_sync(logic.check_disable(self.login_id(), service=service, level=level))
                return view(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator
