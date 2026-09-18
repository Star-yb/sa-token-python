"""sa-token-python：有状态 Token 认证与权限鉴权框架。

核心不依赖任何 Web 框架，脚本、定时任务、RPC 与 Web 接口共用同一套语义::

    from sa_token import SaToken, StpUtil
    from sa_token.storage import MemoryStorage

    SaToken.builder().storage(MemoryStorage()).build()
    token = await StpUtil.login(10001)
"""

from __future__ import annotations

from .config import NEVER_EXPIRE, SaTokenConfig
from .context import (
    get_current_login_id,
    get_current_token,
    sa_token_context,
)
from .exception import (
    DisableException,
    NotLoginException,
    NotLoginType,
    NotPermissionException,
    NotRoleException,
    NotSafeException,
    SaTokenException,
    SaTokenNotInitializedException,
    SecurityException,
)
from .listener import Event, EventBus, EventData
from .manager import SaToken, SaTokenBuilder, SaTokenManager, __version__
from .model import TerminalInfo, TokenInfo
from .permission import has_element, vague_match
from .security import (
    LoginTokenPair,
    NonceManager,
    RefreshTokenManager,
    TempTokenManager,
)
from .session import SaSession
from .stp_interface import StpInterface
from .stp_logic import StpLogic
from .stp_util import StpUtil, clear_manager, get_manager, set_manager

__all__ = [
    "__version__",
    # 入口
    "SaToken",
    "SaTokenBuilder",
    "SaTokenManager",
    "StpUtil",
    "StpLogic",
    "set_manager",
    "get_manager",
    "clear_manager",
    # 配置与模型
    "SaTokenConfig",
    "NEVER_EXPIRE",
    "TokenInfo",
    "TerminalInfo",
    "SaSession",
    "StpInterface",
    "LoginTokenPair",
    "NonceManager",
    "RefreshTokenManager",
    "TempTokenManager",
    # 上下文
    "sa_token_context",
    "get_current_token",
    "get_current_login_id",
    # 事件
    "Event",
    "EventBus",
    "EventData",
    # 权限工具
    "vague_match",
    "has_element",
    # 异常
    "SaTokenException",
    "SaTokenNotInitializedException",
    "NotLoginException",
    "NotLoginType",
    "NotPermissionException",
    "NotRoleException",
    "DisableException",
    "NotSafeException",
    "SecurityException",
]
