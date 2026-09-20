"""Flask 集成：验证同步桥接确实走的是同一套 StpLogic。"""

from __future__ import annotations

import pytest

pytest.importorskip("flask")

from flask import Flask  # noqa: E402

from sa_token import SaToken  # noqa: E402
from sa_token.integration.flask import SaTokenFlask  # noqa: E402
from sa_token.storage import MemoryStorage  # noqa: E402
from sa_token.stp_util import clear_manager  # noqa: E402
from sa_token.sync import StpUtilSync, shutdown_sync_loop  # noqa: E402


@pytest.fixture
def flask_client():
    # Flask 是同步框架，登录态由后台事件循环托管，因此这里不用异步 fixture。
    SaToken.builder().storage(MemoryStorage()).print_banner(False).build()

    app = Flask(__name__)
    app.config["TESTING"] = True
    sa = SaTokenFlask(app)

    @app.post("/login/<user_id>")
    def login(user_id: str):
        return {"token": StpUtilSync.login(user_id)}

    @app.get("/public")
    def public():
        return {"ok": True}

    @app.get("/me")
    @sa.check_login
    def me():
        return {"login_id": sa.login_id()}

    @app.delete("/order/<order_id>")
    @sa.check_permission("order:delete")
    def delete_order(order_id: str):
        return {"deleted": order_id}

    @app.get("/admin")
    @sa.check_role("admin")
    def admin():
        return {"ok": True}

    with app.test_client() as client:
        yield client

    clear_manager()
    shutdown_sync_loop()


def test_public_route_is_open(flask_client) -> None:
    assert flask_client.get("/public").status_code == 200


def test_protected_route_requires_login(flask_client) -> None:
    response = flask_client.get("/me")
    assert response.status_code == 401
    assert response.get_json()["type"] == "NOT_TOKEN"


def test_login_then_access(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    response = flask_client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json()["login_id"] == "10001"


def test_permission_denied_returns_403(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    response = flask_client.delete("/order/1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_permission_granted(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    StpUtilSync.set_permissions("10001", ["order:*"])
    response = flask_client.delete("/order/1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_role_denied(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    response = flask_client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_kickout_reason_surfaces(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    StpUtilSync.kickout("10001")
    response = flask_client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.get_json()["type"] == "KICK_OUT"


def test_sync_facade_shares_state_with_flask(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    # 同步门面与 Flask 请求读到的是同一份登录态，而不是各自一套。
    assert StpUtilSync.is_login(token) is True
    assert StpUtilSync.get_login_id(token) == "10001"
