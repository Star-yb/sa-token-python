"""FastAPI 适配。

各框架的标准鉴权写法都是注解：``@sa.check_login`` / ``@sa.check_permission``。
:class:`SaTokenFastAPI` 提供这一套，与 Flask、Django 同一套 ``StpLogic``。

FastAPI 作为主要适配框架，额外提供 ``Depends`` / ``Annotated``（``LoginId``、
``BearerLoginId`` 等），方便按 FastAPI 习惯写依赖注入。
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Annotated, Any, TypeVar

try:
    from fastapi import Depends, FastAPI, Request, Response, WebSocket
    from fastapi.security import (  # pyright: ignore[reportMissingImports]
        HTTPAuthorizationCredentials,
        HTTPBearer,
    )
except ImportError as exc:  # pragma: no cover - 依赖缺失路径
    raise ImportError(
        '该模块需要 fastapi，请执行：pip install "sa-token-python-core[fastapi]"'
    ) from exc

from ..adapter.path import PathAuthConfig
from ..adapter.pipeline import build_rule, run_auth_flow
from ..context import get_current_login_id, get_current_token
from ..exception import NotLoginException, NotLoginType
from ..permission import MatchMode
from ..stp_util import get_manager
from .starlette import (
    SaTokenMiddleware,
    StarletteHttpContext,
    check_disable,
    check_login,
    check_permission,
    check_role,
    check_safe,
    current_login_id,
    current_login_id_or_none,
    current_token,
    install_exception_handlers,
    sa_token_exception_handler,
)

_F = TypeVar("_F", bound=Callable[..., Any])

__all__ = [
    "SaTokenFastAPI",
    "SaTokenMiddleware",
    "StarletteHttpContext",
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
    "LoginId",
    "OptionalLoginId",
    "TokenValue",
    "BearerLoginId",
    "set_token_cookie",
    "delete_token_cookie",
    "FastAPIWebSocketContext",
    "authenticate_websocket",
]


def _extract_request(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Request:
    request = kwargs.get("request")
    if isinstance(request, Request):
        return request
    for value in args:
        if isinstance(value, Request):
            return value
    for value in kwargs.values():
        if isinstance(value, Request):
            return value
    raise RuntimeError("未找到 Request")


def _endpoint_signature(view: Callable[..., Any]) -> inspect.Signature:
    signature = inspect.signature(view)
    if "request" in signature.parameters:
        return signature
    request_param = inspect.Parameter(
        "request",
        inspect.Parameter.KEYWORD_ONLY,
        annotation=Request,
    )
    return signature.replace(parameters=[*signature.parameters.values(), request_param])


class SaTokenFastAPI:
    """FastAPI 的标准注解鉴权，与 Flask / Django 同一套语义。

    用法::

        app = FastAPI()
        sa = SaTokenFastAPI(app)

        @app.get("/user")
        @sa.check_login
        async def user_info():
            return {"id": sa.login_id()}
    """

    def __init__(
        self,
        app: FastAPI | None = None,
        *,
        path_auth: PathAuthConfig | None = None,
        login_type: str = "login",
    ) -> None:
        self.path_auth = path_auth
        self.login_type = login_type
        if app is not None:
            self.init_app(app)

    def init_app(self, app: FastAPI) -> None:
        app.add_middleware(
            SaTokenMiddleware,
            path_auth=self.path_auth,
            login_type=self.login_type,
        )
        install_exception_handlers(app)

    def login_id(self) -> str:
        login_id = get_current_login_id()
        if login_id:
            return login_id
        raise NotLoginException(NotLoginType.NOT_TOKEN, login_type=self.login_type)

    def token(self) -> str | None:
        return get_current_token()

    def _guard(
        self,
        rule_factory: Callable[[], Any],
        extra: Callable[[Any], Any] | None = None,
    ) -> Callable[[_F], _F]:
        def decorator(view: _F) -> _F:
            had_request = "request" in inspect.signature(view).parameters

            @functools.wraps(view)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                request = _extract_request(args, kwargs)
                ctx = StarletteHttpContext(request)
                result = await run_auth_flow(
                    ctx,
                    get_manager(),
                    rule_factory(),
                    login_type=self.login_type,
                )
                request.state.sa_login_id = result.login_id
                request.state.sa_token = result.token
                if extra is not None:
                    extra_result = extra(result)
                    if inspect.isawaitable(extra_result):
                        await extra_result
                call_kwargs = kwargs
                call_args = args
                if not had_request:
                    call_kwargs = dict(kwargs)
                    call_kwargs.pop("request", None)
                    call_args = tuple(item for item in args if not isinstance(item, Request))
                outcome = view(*call_args, **call_kwargs)
                if inspect.isawaitable(outcome):
                    return await outcome
                return outcome

            wrapper.__signature__ = _endpoint_signature(view)
            return wrapper  # type: ignore[return-value]

        return decorator

    @property
    def check_login(self) -> Callable[[_F], _F]:
        """标准注解：``@sa.check_login``。"""
        return self._guard(build_rule)

    def check_permission(self, *permissions: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
        """标准注解：``@sa.check_permission("order:delete")``。"""
        return self._guard(lambda: build_rule(permissions=list(permissions), mode=mode))

    def check_role(self, *roles: str, mode: MatchMode = "OR") -> Callable[[_F], _F]:
        return self._guard(lambda: build_rule(roles=list(roles), mode=mode))

    def check_safe(self, business: str) -> Callable[[_F], _F]:
        async def extra(result: Any) -> None:
            await get_manager().stp(self.login_type).check_safe(result.token, business)

        return self._guard(build_rule, extra=extra)

    def check_disable(self, service: str = "login", level: int = 1) -> Callable[[_F], _F]:
        async def extra(result: Any) -> None:
            await get_manager().stp(self.login_type).check_disable(
                result.login_id,
                service=service,
                level=level,
            )

        return self._guard(build_rule, extra=extra)


# FastAPI 惯用扩展：Depends / Annotated。

LoginId = Annotated[str, Depends(current_login_id)]
OptionalLoginId = Annotated[str | None, Depends(current_login_id_or_none)]
TokenValue = Annotated[str | None, Depends(current_token)]

_bearer_scheme = HTTPBearer(auto_error=False)


async def _bearer_login_id(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    """Depends 扩展：把 Bearer 写进 OpenAPI，读取逻辑与注解鉴权相同。"""
    del credentials
    return await current_login_id(request)


BearerLoginId = Annotated[str, Depends(_bearer_login_id)]


def set_token_cookie(
    response: Response,
    token: str,
    *,
    max_age: int | None = None,
) -> None:
    """按全局 Cookie 配置把登录 token 写入响应。

    这是显式函数而不是自动拦截 ``StpUtil.login``：核心层没有 Response，
    自动写入会破坏框架无关边界。
    """
    from ..stp_util import get_manager

    config = get_manager().config
    if not config.is_write_cookie:
        return
    resolved_max_age = config.timeout if max_age is None else max_age
    response.set_cookie(
        key=config.token_name,
        value=token,
        max_age=None if resolved_max_age < 0 else resolved_max_age,
        path=config.cookie_path,
        domain=config.cookie_domain,
        secure=config.cookie_secure,
        httponly=config.cookie_http_only,
        samesite=config.cookie_same_site,
    )


def delete_token_cookie(response: Response) -> None:
    """删除登录 Cookie，参数与写入时保持一致。"""
    from ..stp_util import get_manager

    config = get_manager().config
    response.delete_cookie(
        key=config.token_name,
        path=config.cookie_path,
        domain=config.cookie_domain,
        secure=config.cookie_secure,
        httponly=config.cookie_http_only,
        samesite=config.cookie_same_site,
    )


class FastAPIWebSocketContext:
    """把 FastAPI / Starlette WebSocket 包装成核心 HttpContext。"""

    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket
        self.state: dict[str, Any] = {}

    def get_header(self, name: str) -> str | None:
        return self.websocket.headers.get(name)

    def get_cookie(self, name: str) -> str | None:
        return self.websocket.cookies.get(name)

    def get_query(self, name: str) -> str | None:
        return self.websocket.query_params.get(name)

    def get_path(self) -> str:
        return self.websocket.url.path

    def get_method(self) -> str:
        return "WEBSOCKET"


async def authenticate_websocket(
    websocket: WebSocket,
    *,
    login_type: str = "login",
) -> tuple[str, str]:
    """在 ``accept`` 之前校验 WebSocket，返回 ``(login_id, token)``。"""
    from ..online import WebSocketAuthenticator
    from ..stp_util import get_manager

    context = FastAPIWebSocketContext(websocket)
    login_id = await WebSocketAuthenticator(
        get_manager(), login_type=login_type
    ).authenticate(context)
    token = context.state["stp_token"]
    return login_id, token
