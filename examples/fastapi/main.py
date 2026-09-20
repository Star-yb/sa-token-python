"""FastAPI 示例。

运行：``uvicorn examples.fastapi.main:app --reload``

标准写法是注解 ``@sa.check_login``；``Depends`` / ``LoginId`` / ``BearerLoginId``
是 FastAPI 额外提供的依赖注入写法，语义相同。
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from sa_token import SaToken, SaTokenException, StpUtil, get_manager
from sa_token.integration.fastapi import (
    BearerLoginId,
    LoginId,
    SaTokenFastAPI,
    SaTokenMiddleware,
    authenticate_websocket,
    check_permission,
    check_role,
    check_safe,
    delete_token_cookie,
    install_exception_handlers,
    set_token_cookie,
)
from sa_token.online import OnlineManager
from sa_token.storage import MemoryStorage

SaToken.builder().storage(MemoryStorage()).timeout(7200).set_option(
    is_write_cookie=True,
    cookie_http_only=True,
    cookie_same_site="Lax",
).build()

app = FastAPI(title="sa-token-python FastAPI 示例")
app.add_middleware(SaTokenMiddleware)
install_exception_handlers(app)
sa = SaTokenFastAPI()


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


async def send_websocket(websocket: WebSocket, message: str) -> None:
    await websocket.send_text(message)


async def close_websocket(websocket: WebSocket) -> None:
    await websocket.close(code=4001, reason="登录态已失效")


online = OnlineManager(get_manager(), sender=send_websocket, closer=close_websocket)


@app.post("/login")
async def login(payload: LoginRequest, response: Response) -> dict:
    """账号密码校验由业务负责，sa-token 只管签发登录态。"""
    if payload.password != "123456":
        return {"code": 400, "message": "账号或密码错误"}

    tokens = await StpUtil.login_with_refresh(payload.username, device="web")
    await StpUtil.set_permissions(payload.username, ["user:read", "order:*"])
    await StpUtil.set_roles(payload.username, ["admin"])
    set_token_cookie(response, tokens.access_token)
    return tokens.to_dict()


@app.post("/refresh")
async def refresh(payload: RefreshRequest, response: Response) -> dict:
    tokens = await StpUtil.refresh_access_token(payload.refresh_token)
    set_token_cookie(response, tokens.access_token)
    return tokens.to_dict()


@app.get("/me")
@sa.check_login
async def me() -> dict:
    login_id = sa.login_id()
    session = await StpUtil.get_session(login_id)
    assert session is not None
    return {
        "login_id": login_id,
        "permissions": await StpUtil.get_permissions(login_id),
        "nickname": await session.get("nickname"),
    }


@app.get("/me-bearer")
async def me_bearer(login_id: BearerLoginId) -> dict:
    return {"login_id": login_id}


@app.delete("/order/{order_id}")
async def delete_order(order_id: str, _: str = Depends(check_permission("order:delete"))) -> dict:
    return {"deleted": order_id}


@app.get("/admin/panel")
async def admin_panel(_: str = Depends(check_role("admin"))) -> dict:
    return {"ok": True}


@app.post("/pay")
async def pay(_: str = Depends(check_safe("pay"))) -> dict:
    """敏感操作：需要先调用 /open-safe 通过二级认证。"""
    return {"paid": True}


@app.post("/open-safe")
async def open_safe(login_id: LoginId) -> dict:
    token = StpUtil.get_token_value()
    assert token is not None
    await StpUtil.open_safe(token, "pay", 300)
    return {"ok": True}


@app.post("/logout")
async def logout(response: Response, login_id: LoginId) -> dict:
    await StpUtil.logout_by_token()
    delete_token_cookie(response)
    return {"ok": True}


@app.post("/kickout/{user_id}")
async def kickout(user_id: str, _: str = Depends(check_role("admin"))) -> dict:
    """踢人立刻生效——这是无状态 JWT 做不到的事。"""
    await StpUtil.kickout(user_id)
    return {"ok": True}


@app.get("/nonce/{purpose}")
async def issue_nonce(purpose: str, login_id: LoginId) -> dict:
    return {"nonce": await StpUtil.issue_nonce(login_id, purpose=purpose)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """浏览器连接：``ws://localhost:8000/ws?Authorization=<token>``。"""
    try:
        login_id, _ = await authenticate_websocket(websocket)
    except SaTokenException:
        await websocket.close(code=4401, reason="未登录")
        return

    await websocket.accept()
    connection = await online.register(login_id, websocket, device="web")
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await online.heartbeat(login_id, connection.connection_id)
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await online.unregister(login_id, connection.connection_id)


# 配置式鉴权：不想逐个路由挂 Depends 时，用一张规则表。
# 同一路径可按 HTTP 方法区分，对应 Java 的 SaRouter.match(SaHttpMethod.POST, "/user/**")。
#
# from sa_token.adapter import PathAuthConfig
#
# path_auth = (
#     PathAuthConfig()
#     .ignore("/login", "/docs", "/openapi.json")
#     .ignore("/article", methods=["GET"])                      # 公开阅读
#     .permission("/article", "article:write", methods=["POST", "PUT", "DELETE"])
#     .permission("/order/**", "order:*", methods=["DELETE"])
#     .role("/admin/**", "admin")
#     .login("/**")                                             # 其余全部要登录
# )
# app.add_middleware(SaTokenMiddleware, path_auth=path_auth)
