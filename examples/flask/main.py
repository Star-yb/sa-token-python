"""Flask 示例。

运行：``python examples/flask/main.py``

本项目内核默认是异步：``await StpUtil.login()``。
Flask 是 WSGI 同步框架，没有事件循环，所以这里用 ``StpUtilSync``——
它只是同一套 ``StpLogic`` 的同步桥接，不是第二份鉴权实现。

命名约定：``Sync`` = English *synchronous*（同步），不是 asyncio。
"""

from __future__ import annotations

from flask import Flask, request

from sa_token import SaToken
from sa_token.integration.flask import SaTokenFlask
from sa_token.storage import MemoryStorage
from sa_token.sync import StpUtilSync

SaToken.builder().storage(MemoryStorage()).timeout(7200).build()

app = Flask(__name__)
sa = SaTokenFlask(app)


@app.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    if payload.get("password") != "123456":
        return {"code": 400, "message": "账号或密码错误"}, 400

    token = StpUtilSync.login(username, device="web")
    StpUtilSync.set_permissions(username, ["user:read", "order:*"])
    StpUtilSync.set_roles(username, ["admin"])
    return {"token": token}


@app.get("/me")
@sa.check_login
def me():
    login_id = sa.login_id()
    return {
        "login_id": login_id,
        "permissions": StpUtilSync.get_permissions(login_id),
    }


@app.delete("/order/<order_id>")
@sa.check_permission("order:delete")
def delete_order(order_id: str):
    return {"deleted": order_id}


@app.get("/admin/panel")
@sa.check_role("admin")
def admin_panel():
    return {"ok": True}


@app.post("/logout")
@sa.check_login
def logout():
    StpUtilSync.logout_by_token(sa.token())
    return {"ok": True}


if __name__ == "__main__":
    app.run(debug=True)
