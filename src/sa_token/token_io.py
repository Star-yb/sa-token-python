"""统一的 token 读取。

读取顺序是全局唯一的一份实现，任何框架适配层都**禁止**自己再解析一遍 Header，
否则会出现「Gin 支持 Query 但 Echo 不支持」这类跨适配器行为不一致的老问题。

顺序：Header → Authorization 兜底 → Cookie → Query，最后统一剥离前缀。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from .adapter.http import HttpContext
    from .config import SaTokenConfig

__all__ = ["AUTH_HEADER", "read_token", "cut_token_prefix"]

AUTH_HEADER = "Authorization"


def cut_token_prefix(raw: str | None, prefix: str) -> str | None:
    """剥离 ``Bearer `` 之类的前缀。

    配置了前缀时，**不带前缀的值同样接受**：很多客户端（尤其是 Cookie 与
    Query 场景）不会带前缀，直接拒绝会造成大量难以排查的 401。
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if not prefix:
        return value
    normalized_prefix = prefix.strip()
    if value.lower().startswith(normalized_prefix.lower()):
        value = value[len(normalized_prefix) :].strip()
    return value or None


def read_token(ctx: HttpContext, config: SaTokenConfig) -> str | None:
    """按固定顺序从请求中提取 token。"""
    token_name = config.token_name
    prefix = config.token_prefix

    if config.is_read_header:
        value = cut_token_prefix(ctx.get_header(token_name), prefix)
        if value:
            return value
        # 自定义了 token_name 时，仍然兼容标准 Authorization 头。
        if token_name.lower() != AUTH_HEADER.lower():
            value = cut_token_prefix(ctx.get_header(AUTH_HEADER), prefix)
            if value:
                return value

    if config.is_read_cookie:
        value = cut_token_prefix(ctx.get_cookie(token_name), prefix)
        if value:
            return value

    if config.is_read_query:
        value = cut_token_prefix(ctx.get_query(token_name), prefix)
        if value:
            return value

    return None
