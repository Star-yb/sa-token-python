"""权限匹配是鉴权的地基，这里用表格用例把语义钉死。"""

from __future__ import annotations

import pytest

from sa_token.permission import has_element, match_all, match_any, vague_match


@pytest.mark.parametrize(
    ("pattern", "target", "expected"),
    [
        ("user:read", "user:read", True),
        ("user:read", "user:write", False),
        ("user:*", "user:read", True),
        ("user:*", "user:read:self", True),
        ("user:*", "order:read", False),
        ("user:*", "user", False),
        ("*", "anything", True),
        ("*", "a:b:c", True),
        ("user:*:view", "user:admin:view", True),
        ("user:*:view", "user:admin:edit", False),
        ("user:*:view", "user:view", False),
        ("a:b", "a:b:c", False),
        ("a:b:c", "a:b", False),
        ("", "a", False),
        ("a", "", False),
    ],
)
def test_vague_match(pattern: str, target: str, expected: bool) -> None:
    assert vague_match(pattern, target) is expected


def test_has_element() -> None:
    granted = ["user:read", "order:*"]
    assert has_element(granted, "order:delete") is True
    assert has_element(granted, "user:read") is True
    assert has_element(granted, "user:write") is False


def test_match_all_returns_first_missing() -> None:
    granted = ["user:read", "order:*"]
    assert match_all(granted, ["user:read", "order:delete"]) is None
    assert match_all(granted, ["user:read", "admin:all"]) == "admin:all"


def test_match_any() -> None:
    granted = ["order:*"]
    assert match_any(granted, ["admin:all", "order:read"]) is True
    assert match_any(granted, ["admin:all", "user:read"]) is False
