"""框架无关的适配基础设施。

这一层定义「共同写法」：HttpContext 抽象 + 统一鉴权管道 + 路径规则。
具体框架绑定放在 :mod:`sa_token.integration`。
"""

from __future__ import annotations

from .http import HttpContext, SimpleHttpContext
from .path import PathAuthConfig, PathRule, ant_match
from .pipeline import AuthResult, build_rule, resolve_token, run_auth_flow, run_path_auth

__all__ = [
    "HttpContext",
    "SimpleHttpContext",
    "PathAuthConfig",
    "PathRule",
    "ant_match",
    "AuthResult",
    "build_rule",
    "resolve_token",
    "run_auth_flow",
    "run_path_auth",
]
