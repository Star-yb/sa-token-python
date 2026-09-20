"""权限匹配引擎。

规则刻意保持简单、可预测：只有 ``*`` 一种通配符，按 ``:`` 分段匹配。
复杂策略（ABAC / ReBAC）请通过 :class:`~sa_token.stp_interface.StpInterface`
对接 Casbin 等专门的策略引擎，不要把策略语言塞进核心。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Literal

__all__ = ["MatchMode", "vague_match", "has_element", "match_all", "match_any"]

MatchMode = Literal["AND", "OR"]


def vague_match(pattern: str, target: str) -> bool:
    """判断单条已授权的 ``pattern`` 是否覆盖所需的 ``target``。

    - 完全相同：``user:read`` 命中 ``user:read``
    - 末尾通配：``user:*`` 命中 ``user:read``、``user:read:self``
    - 中间通配：``user:*:view`` 命中 ``user:admin:view``
    - 全局通配：``*`` 命中任意权限
    """
    if not pattern or not target:
        return False
    if pattern == target:
        return True
    if "*" not in pattern:
        return False

    pattern_parts = pattern.split(":")
    target_parts = target.split(":")

    for index, pattern_part in enumerate(pattern_parts):
        is_last_pattern_part = index == len(pattern_parts) - 1
        if pattern_part == "*" and is_last_pattern_part:
            # 末尾的 * 吃掉剩余全部层级，但至少要有一层可吃。
            return len(target_parts) > index
        if index >= len(target_parts):
            return False
        if pattern_part != "*" and pattern_part != target_parts[index]:
            return False

    # 模式已用尽：只有层级数完全相同才算命中，避免 a:b 命中 a:b:c。
    return len(pattern_parts) == len(target_parts)


def has_element(granted: Iterable[str], required: str) -> bool:
    """已授权集合中是否存在覆盖 ``required`` 的条目。"""
    return any(vague_match(item, required) for item in granted)


def match_all(granted: Iterable[str], required: Sequence[str]) -> str | None:
    """AND 语义：返回第一个未命中的条目，全部命中时返回 ``None``。"""
    granted_list = list(granted)
    for item in required:
        if not has_element(granted_list, item):
            return item
    return None


def match_any(granted: Iterable[str], required: Sequence[str]) -> bool:
    """OR 语义：命中任意一个即可。"""
    granted_list = list(granted)
    return any(has_element(granted_list, item) for item in required)
