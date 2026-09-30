"""Ant 风格路径匹配与路径鉴权规则表。

适合网关式、配置驱动的鉴权：不想给每个路由挂装饰器时，用一张规则表描述即可。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..permission import MatchMode

__all__ = ["ant_match", "PathRule", "PathAuthConfig"]


def ant_match(pattern: str, path: str) -> bool:
    """Ant 风格匹配。

    - ``*`` 匹配单层路径
    - ``**`` 匹配任意层（含 0 层）
    - 其余为字面量

    请求路径里的 ``.`` 会去掉，``..`` 会向上退一层。退到根之外时，具体路径
    模式不命中，避免 ``/public/../admin`` 命中 ``/public/**``。整段都是 ``**``
    的模式（例如 ``/**``）仍然命中，这样登录兜底规则不会把这些路径放行。
    """
    pattern_parts = [part for part in pattern.strip("/").split("/") if part != ""]
    path_parts = _normalize_segments(path)
    if path_parts is None:
        return bool(pattern_parts) and all(part == "**" for part in pattern_parts)
    if pattern_parts == path_parts:
        return True
    return _match_parts(pattern_parts, 0, path_parts, 0, set())


def _normalize_segments(path: str) -> list[str] | None:
    parts: list[str] = []
    for part in path.strip("/").split("/"):
        if part == "" or part == ".":
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return parts


def _match_parts(
    pattern_parts: list[str],
    pattern_index: int,
    path_parts: list[str],
    path_index: int,
    seen: set[tuple[int, int]],
) -> bool:
    while pattern_index < len(pattern_parts):
        part = pattern_parts[pattern_index]
        if part == "**":
            # ** 可以吞掉 0..n 层。记下已尝试的位置，避免多段 ** 组合爆炸。
            if pattern_index == len(pattern_parts) - 1:
                return True
            for skip in range(path_index, len(path_parts) + 1):
                state = (pattern_index + 1, skip)
                if state in seen:
                    continue
                seen.add(state)
                if _match_parts(pattern_parts, pattern_index + 1, path_parts, skip, seen):
                    return True
            return False
        if path_index >= len(path_parts):
            return False
        if part != "*" and part != path_parts[path_index]:
            return False
        pattern_index += 1
        path_index += 1
    return path_index == len(path_parts)


@dataclass
class CheckGroup:
    """一组需要按同一模式校验的权限或角色。

    多条规则命中同一路径时，各组独立判断，不能把 AND 粘到其它 OR 组上。
    """

    values: list[str]
    mode: MatchMode = "OR"


@dataclass
class PathRule:
    """一条路径规则。

    ``ignore=True`` 的规则优先级最高，用于放行登录页、健康检查等公开接口。
    ``permission_groups`` / ``role_groups`` 按来源规则分开保存匹配模式。
    ``permissions`` / ``roles`` 仍是全部取值的并集，便于查看命中了哪些项。
    """

    pattern: str
    ignore: bool = False
    require_login: bool = False
    permissions: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    mode: MatchMode = "OR"
    methods: list[str] = field(default_factory=list)
    permission_groups: list[CheckGroup] = field(default_factory=list)
    role_groups: list[CheckGroup] = field(default_factory=list)
    _methods: frozenset[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._methods = frozenset(method.upper() for method in self.methods)

    def matches(self, path: str, method: str) -> bool:
        if self._methods and method.upper() not in self._methods:
            return False
        return ant_match(self.pattern, path)


class PathAuthConfig:
    """路径规则表。

    匹配策略：先看是否命中任一 ``ignore`` 规则；否则把全部命中的规则合并。
    权限与角色取值取并集，但每一条规则的 AND/OR 单独成组，互不改写。

    没有命中任何规则时默认放行，不要求登录。需要「没写到的路径也要登录」时，
    在表末尾加上 ``.login("/**")``。
    """

    def __init__(self) -> None:
        self._rules: list[PathRule] = []

    @property
    def rules(self) -> list[PathRule]:
        return list(self._rules)

    def add(self, rule: PathRule) -> PathAuthConfig:
        self._rules.append(rule)
        return self

    def ignore(self, *patterns: str, methods: list[str] | None = None) -> PathAuthConfig:
        """放行指定路径。``methods`` 为空表示所有 HTTP 方法都放行。

        同一路径要对不同方法区别对待时，必须给 ignore 也加上 ``methods``：
        ignore 优先级最高，不限方法的 ``.ignore("/article")`` 会把
        ``POST /article`` 一并放行。
        """
        for pattern in patterns:
            self._rules.append(
                PathRule(pattern, ignore=True, methods=list(methods or []))
            )
        return self

    def login(self, *patterns: str, methods: list[str] | None = None) -> PathAuthConfig:
        for pattern in patterns:
            self._rules.append(
                PathRule(pattern, require_login=True, methods=list(methods or []))
            )
        return self

    def permission(
        self,
        pattern: str,
        *permissions: str,
        mode: MatchMode = "OR",
        methods: list[str] | None = None,
    ) -> PathAuthConfig:
        self._rules.append(
            PathRule(
                pattern,
                require_login=True,
                permissions=list(permissions),
                mode=mode,
                methods=list(methods or []),
            )
        )
        return self

    def role(
        self,
        pattern: str,
        *roles: str,
        mode: MatchMode = "OR",
        methods: list[str] | None = None,
    ) -> PathAuthConfig:
        self._rules.append(
            PathRule(
                pattern,
                require_login=True,
                roles=list(roles),
                mode=mode,
                methods=list(methods or []),
            )
        )
        return self

    def resolve(self, path: str, method: str) -> PathRule:
        """把命中的规则合并成一条待执行规则。"""
        matched = [rule for rule in self._rules if rule.matches(path, method)]
        if not matched:
            return PathRule(path)
        if any(rule.ignore for rule in matched):
            return PathRule(path, ignore=True)

        merged = PathRule(path, require_login=any(rule.require_login for rule in matched))
        for rule in matched:
            if rule.permission_groups:
                merged.permission_groups.extend(rule.permission_groups)
                merged.permissions.extend(
                    value for group in rule.permission_groups for value in group.values
                )
            elif rule.permissions:
                merged.permission_groups.append(CheckGroup(list(rule.permissions), rule.mode))
                merged.permissions.extend(rule.permissions)
            if rule.role_groups:
                merged.role_groups.extend(rule.role_groups)
                merged.roles.extend(value for group in rule.role_groups for value in group.values)
            elif rule.roles:
                merged.role_groups.append(CheckGroup(list(rule.roles), rule.mode))
                merged.roles.extend(rule.roles)
        return merged
