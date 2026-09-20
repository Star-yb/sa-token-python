"""FastAPI 集成：注解是标准写法，Depends 是 FastAPI 扩展。

框架层要验证的只有：token 读得到、异常翻译成正确的状态码。
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI, Response, WebSocket  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sa_token import StpUtil  # noqa: E402
from sa_token.adapter import PathAuthConfig  # noqa: E402
from sa_token.integration.fastapi import (  # noqa: E402
    BearerLoginId,
    SaTokenFastAPI,
    SaTokenMiddleware,
    authenticate_websocket,
    check_permission,
    check_role,
    current_login_id,
    current_login_id_or_none,
    delete_token_cookie,
    install_exception_handlers,
    set_token_cookie,
)


def build_app(path_auth: PathAuthConfig | None = None) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SaTokenMiddleware, path_auth=path_auth)
    install_exception_handlers(app)

    @app.post("/login/{user_id}")
    async def login(user_id: str) -> dict:
        return {"token": await StpUtil.login(user_id)}

    @app.get("/public")
    async def public() -> dict:
        return {"ok": True}

    @app.get("/me")
    async def me(login_id: str = Depends(current_login_id)) -> dict:
        return {"login_id": login_id}

    @app.get("/maybe")
    async def maybe(login_id: str | None = Depends(current_login_id_or_none)) -> dict:
        return {"login_id": login_id}

    @app.delete("/order/{order_id}")
    async def delete_order(
        order_id: str,
        _: str = Depends(check_permission("order:delete")),
    ) -> dict:
        return {"deleted": order_id}

    @app.get("/admin")
    async def admin(_: str = Depends(check_role("admin"))) -> dict:
        return {"ok": True}

    sa = SaTokenFastAPI()

    @app.get("/decorated/me")
    @sa.check_login
    async def decorated_me() -> dict:
        return {"login_id": sa.login_id()}

    @app.delete("/decorated/order/{order_id}")
    @sa.check_permission("order:delete")
    async def decorated_delete_order(order_id: str) -> dict:
        return {"deleted": order_id}

    return app


@pytest.fixture
def client(manager):
    with TestClient(build_app()) as test_client:
        yield test_client


def test_public_route_is_open(client) -> None:
    assert client.get("/public").status_code == 200


def test_protected_route_requires_login(client) -> None:
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["type"] == "NOT_TOKEN"


def test_decorator_login_then_access(client) -> None:
    token = client.post("/login/10001").json()["token"]
    response = client.get("/decorated/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["login_id"] == "10001"


def test_decorator_requires_login(client) -> None:
    response = client.get("/decorated/me")
    assert response.status_code == 401


def test_decorator_permission_granted(client, manager) -> None:
    import asyncio

    token = client.post("/login/10001").json()["token"]
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        manager.stp().set_permissions("10001", ["order:*"])
    )
    response = client.delete(
        "/decorated/order/1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["deleted"] == "1"


def test_token_from_query_is_accepted(client) -> None:
    token = client.post("/login/10001").json()["token"]
    response = client.get("/me", params={"Authorization": token})
    assert response.status_code == 200


def test_optional_login(client) -> None:
    assert client.get("/maybe").json()["login_id"] is None
    token = client.post("/login/10001").json()["token"]
    response = client.get("/maybe", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["login_id"] == "10001"


def test_permission_denied_returns_403(client) -> None:
    token = client.post("/login/10001").json()["token"]
    response = client.delete("/order/1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["error"] == "NotPermissionException"


def test_permission_granted(client, manager) -> None:
    import asyncio

    token = client.post("/login/10001").json()["token"]
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        manager.stp().set_permissions("10001", ["order:*"])
    )
    response = client.delete("/order/1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_role_check(client) -> None:
    token = client.post("/login/10001").json()["token"]
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_kicked_token_reports_reason(client, manager) -> None:
    import asyncio

    token = client.post("/login/10001").json()["token"]
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        manager.stp().kickout("10001")
    )
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["type"] == "KICK_OUT"


def test_path_auth_middleware(manager) -> None:
    path_auth = PathAuthConfig().ignore("/login/**", "/public").login("/**")
    with TestClient(build_app(path_auth)) as client:
        assert client.get("/public").status_code == 200
        assert client.get("/me").status_code == 401

        token = client.post("/login/10001").json()["token"]
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200


def test_cookie_helpers_write_and_delete_token(manager) -> None:
    manager.config.is_write_cookie = True
    app = FastAPI()

    @app.post("/login")
    async def login(response: Response) -> dict:
        token = await manager.stp().login("10001")
        set_token_cookie(response, token)
        return {"token": token}

    @app.post("/logout")
    async def logout(response: Response) -> dict:
        delete_token_cookie(response)
        return {"ok": True}

    with TestClient(app) as test_client:
        login_response = test_client.post("/login")
        assert manager.config.token_name in login_response.cookies
        logout_response = test_client.post("/logout")
        assert logout_response.headers["set-cookie"].startswith("Authorization=")
        assert "Max-Age=0" in logout_response.headers["set-cookie"]


def test_bearer_login_id_adds_openapi_security_scheme(manager) -> None:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/secure")
    async def secure(login_id: BearerLoginId) -> dict:
        return {"login_id": login_id}

    schema = app.openapi()
    assert "HTTPBearer" in schema["components"]["securitySchemes"]
    token = manager.strategy.generate("10001")
    # 未落存储的 token 仍然必须被拒绝。
    with TestClient(app) as test_client:
        assert (
            test_client.get(
                "/secure", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 401
        )


def test_fastapi_websocket_authentication(manager) -> None:
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        try:
            login_id, _ = await authenticate_websocket(websocket)
        except Exception:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        await websocket.send_text(login_id)
        await websocket.close()

    import asyncio

    token = asyncio.run(manager.stp().login("10001"))
    with (
        TestClient(app) as test_client,
        test_client.websocket_connect(f"/ws?Authorization={token}") as websocket,
    ):
        assert websocket.receive_text() == "10001"
