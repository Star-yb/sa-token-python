"""原生用法示例：完全不涉及任何 Web 框架。

运行：``python examples/native/quick_start.py``
"""

from __future__ import annotations

import asyncio

from sa_token import (
    Event,
    EventData,
    NotLoginException,
    NotLoginType,
    SaToken,
    StpUtil,
    sa_token_context,
)
from sa_token.storage import MemoryStorage


def on_auth_event(data: EventData) -> None:
    print(f"  [事件] {data.event.value:<10} login_id={data.login_id} device={data.device}")


async def main() -> None:
    SaToken.builder().storage(MemoryStorage()).timeout(7200).print_banner(False).on(
        Event.ALL, on_auth_event
    ).build()

    print("== 登录 ==")
    token = await StpUtil.login("10001", device="cli")
    print(f"  token = {token}")
    print(f"  is_login = {await StpUtil.is_login(token)}")

    print("== 权限 ==")
    await StpUtil.set_permissions("10001", ["user:read", "order:*"])
    await StpUtil.set_roles("10001", ["admin"])
    print(f"  order:delete 命中 order:* -> {await StpUtil.has_permission('10001', 'order:delete')}")
    print(f"  user:write 未授权      -> {await StpUtil.has_permission('10001', 'user:write')}")
    print(f"  角色 admin             -> {await StpUtil.has_role('10001', 'admin')}")

    print("== Session ==")
    session = await StpUtil.get_session("10001")
    assert session is not None
    await session.set("nickname", "alice")
    print(f"  nickname = {await session.get('nickname')}")

    print("== 上下文绑定（免去手动传 token）==")
    with sa_token_context(token):
        print(f"  当前 login_id = {await StpUtil.check_login()}")

    print("== 多端 ==")
    app_token = await StpUtil.login("10001", device="app")
    terminals = await StpUtil.get_terminal_list("10001")
    print(f"  在线终端 = {[(t.device, t.token[:8]) for t in terminals]}")

    print("== 二级认证 ==")
    await StpUtil.open_safe(token, "pay", 60)
    print(f"  pay 窗口已开启 -> {await StpUtil.is_safe(token, 'pay')}")

    print("== 踢人 ==")
    await StpUtil.kickout("10001")
    try:
        await StpUtil.check_login(token)
    except NotLoginException as exc:
        assert exc.type is NotLoginType.KICK_OUT
        print(f"  被踢原因可追溯 -> {exc.type.value}")
    print(f"  app 端同样下线 -> {await StpUtil.is_login(app_token)}")

    print("== 封禁 ==")
    await StpUtil.disable("10001", 3600)
    print(f"  is_disable = {await StpUtil.is_disable('10001')}")
    print(f"  剩余秒数   = {await StpUtil.get_disable_time('10001')}")
    await StpUtil.untie("10001")
    print(f"  解封后 is_disable = {await StpUtil.is_disable('10001')}")


if __name__ == "__main__":
    asyncio.run(main())
