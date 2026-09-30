"""Flask 集成：验证同步桥接确实走的是同一套 StpLogic。"""

from __future__ import annotations

import pytest

pytest.importorskip("flask")

from flask import Flask  # noqa: E402

from sa_token import SaToken  # noqa: E402
from sa_token.context import clear_current, get_current_login_id  # noqa: E402
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

    @app.get("/context")
    @sa.check_login
    def context():
        return {"login_id": get_current_login_id()}

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
    clear_current()
    shutdown_sync_loop()


def test_public_route_is_open(flask_client) -> None:
    assert flask_client.get("/public").status_code == 200


def test_decorator_binds_login_id_on_request_thread(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    response = flask_client.get("/context", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json()["login_id"] == "10001"


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


def test_token_getter_keeps_bound_login_id() -> None:
    from sa_token.context import get_current_login_id

    SaToken.builder().storage(MemoryStorage()).print_banner(False).build()
    try:
        app = Flask(__name__)
        app.config["TESTING"] = True
        sa = SaTokenFlask(app)

        @app.post("/login/<user_id>")
        def login(user_id: str):
            return {"token": StpUtilSync.login(user_id)}

        @app.get("/who")
        def who():
            from sa_token.context import set_current

            set_current("keep", "10001")
            sa.token()
            return {"login_id": get_current_login_id()}

        with app.test_client() as client:
            response = client.get("/who", headers={"Authorization": "Bearer present"})
        assert response.status_code == 200
        assert response.get_json()["login_id"] == "10001"
    finally:
        clear_manager()
        clear_current()
        shutdown_sync_loop()


def test_request_clears_identity_on_the_worker_thread(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    response = flask_client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert get_current_login_id() is None


def test_sync_facade_shares_state_with_flask(flask_client) -> None:
    token = flask_client.post("/login/10001").get_json()["token"]
    # 同步门面与 Flask 请求读到的是同一份登录态，而不是各自一套。
    assert StpUtilSync.is_login(token) is True
    assert StpUtilSync.get_login_id(token) == "10001"


def test_login_type_does_not_share_cached_identity() -> None:
    from sa_token.exception import NotLoginException
    from sa_token.stp_util import get_manager
    from sa_token.sync import run_sync

    SaToken.builder().storage(MemoryStorage()).print_banner(False).build()
    try:
        app = Flask(__name__)
        app.config["TESTING"] = True
        user_auth = SaTokenFlask(app, login_type="user")
        admin_auth = SaTokenFlask(app, login_type="admin")
        admin_token = run_sync(get_manager().stp("admin").login("9"))

        @app.get("/who")
        def who():
            try:
                user_id = user_auth.login_id()
            except NotLoginException:
                user_id = None
            return {"user": user_id, "admin": admin_auth.login_id()}

        with app.test_client() as client:
            response = client.get("/who", headers={"Authorization": f"Bearer {admin_token}"})
        assert response.status_code == 200
        assert response.get_json() == {"user": None, "admin": "9"}
    finally:
        clear_manager()
        clear_current()
        shutdown_sync_loop()
