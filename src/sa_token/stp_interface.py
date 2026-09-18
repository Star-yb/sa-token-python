"""权限数据源。

默认实现从存储里读 ``set_permissions`` 写入的数据，适合中小项目与网关；
已有 RBAC 表的项目应实现本接口，直接从数据库读，避免两份权限数据不同步。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["StpInterface"]


@runtime_checkable
class StpInterface(Protocol):
    """业务侧权限 / 角色数据源。"""

    async def get_permission_list(self, login_id: str, login_type: str) -> list[str]: ...

    async def get_role_list(self, login_id: str, login_type: str) -> list[str]: ...
