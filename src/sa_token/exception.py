"""sa-token 异常体系。

核心层只抛这些异常，框架适配层负责把它们翻译成各自的 HTTP 响应，
禁止在适配层重新发明错误码。
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "NotLoginType",
    "SaTokenException",
    "SaTokenNotInitializedException",
    "NotLoginException",
    "NotPermissionException",
    "NotRoleException",
    "DisableException",
    "NotSafeException",
    "SecurityException",
]


class NotLoginType(str, Enum):
    """未登录的细分原因，用于让调用方区分「没带 token」和「被踢下线」。"""

    NOT_TOKEN = "NOT_TOKEN"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_TIMEOUT = "TOKEN_TIMEOUT"
    TOKEN_FREEZE = "TOKEN_FREEZE"
    BE_REPLACED = "BE_REPLACED"
    KICK_OUT = "KICK_OUT"


_NOT_LOGIN_MESSAGES: dict[NotLoginType, str] = {
    NotLoginType.NOT_TOKEN: "未提供 token",
    NotLoginType.INVALID_TOKEN: "token 无效",
    NotLoginType.TOKEN_TIMEOUT: "token 已过期",
    NotLoginType.TOKEN_FREEZE: "token 已被冻结（长时间未活跃）",
    NotLoginType.BE_REPLACED: "token 已被顶下线",
    NotLoginType.KICK_OUT: "token 已被踢下线",
}


class SaTokenException(Exception):
    """所有 sa-token 异常的基类。"""

    http_status = 500

    def __init__(self, message: str, *, login_type: str = "login") -> None:
        super().__init__(message)
        self.message = message
        self.login_type = login_type


class SaTokenNotInitializedException(SaTokenException):
    """在调用 StpUtil 之前没有构建 Manager。"""

    def __init__(self) -> None:
        super().__init__(
            "sa-token 尚未初始化，请先调用 SaToken.builder()...build() 或 set_manager()"
        )


class NotLoginException(SaTokenException):
    """未登录、token 失效、被踢、被顶、被冻结。"""

    http_status = 401

    def __init__(
        self,
        not_login_type: NotLoginType,
        *,
        login_type: str = "login",
        token: str | None = None,
    ) -> None:
        super().__init__(_NOT_LOGIN_MESSAGES[not_login_type], login_type=login_type)
        self.type = not_login_type
        self.token = token


class NotPermissionException(SaTokenException):
    """权限不足。"""

    http_status = 403

    def __init__(self, permission: str, *, login_type: str = "login") -> None:
        super().__init__(f"缺少权限：{permission}", login_type=login_type)
        self.permission = permission


class NotRoleException(SaTokenException):
    """角色不足。"""

    http_status = 403

    def __init__(self, role: str, *, login_type: str = "login") -> None:
        super().__init__(f"缺少角色：{role}", login_type=login_type)
        self.role = role


class DisableException(SaTokenException):
    """账号（或账号的某项服务）被封禁。"""

    http_status = 403

    def __init__(
        self,
        login_id: str,
        service: str,
        level: int,
        remaining: int,
        *,
        login_type: str = "login",
    ) -> None:
        super().__init__(
            f"账号 {login_id} 的服务 {service} 已被封禁（等级 {level}，剩余 {remaining} 秒）",
            login_type=login_type,
        )
        self.login_id = login_id
        self.service = service
        self.level = level
        self.remaining = remaining


class NotSafeException(SaTokenException):
    """二级认证未通过。"""

    http_status = 403

    def __init__(self, business: str, *, login_type: str = "login") -> None:
        super().__init__(f"二级认证未通过：{business}", login_type=login_type)
        self.business = business


class SecurityException(SaTokenException):
    """Nonce、Refresh Token、Temp Token 等安全流程错误。"""

    http_status = 400

    def __init__(self, code: str, message: str, *, login_type: str = "login") -> None:
        super().__init__(message, login_type=login_type)
        self.code = code
