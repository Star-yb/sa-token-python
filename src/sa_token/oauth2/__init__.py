"""OAuth2 授权码流程（含 PKCE）。

框架无关：协议引擎只依赖核心存储，HTTP 端点由使用方挂载。
"""

from __future__ import annotations

from .model import AccessTokenInfo, AuthorizationCode, OAuth2Client, TokenResponse
from .server import OAuth2Error, OAuth2Server, generate_pkce_pair

__all__ = [
    "OAuth2Client",
    "AuthorizationCode",
    "AccessTokenInfo",
    "TokenResponse",
    "OAuth2Server",
    "OAuth2Error",
    "generate_pkce_pair",
]
