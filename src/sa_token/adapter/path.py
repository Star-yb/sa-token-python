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
    """
    if pattern == path:
        return True
    pattern_parts = [part for part in pattern.strip("/").split("/") if part != ""]
    path_parts = [part for part in path.strip("/").split("/") if part != ""]
    return _match_parts(pattern_parts, 0, path_parts, 0)


def _match_parts(
    pattern_parts: list[str],
    pattern_index: int,
    path_parts: list[str],
    path_index: int,
) -> bool:
    while pattern_index < len(pattern_parts):
        part = pattern_parts[pattern_index]
        if part == "**":
            # ** 可以吞掉 0..n 层，逐个位置回溯尝试。
            if pattern_index == len(pattern_parts) - 1:
                return True
            for skip in range(path_index, len(path_parts) + 1):
                if _match_parts(pattern_parts, pattern_index + 1, path_parts, skip):
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
class PathRule:
    """一条路径规则。

    ``ignore=True`` 的规则优先级最高，用于放行登录页、健康检查等公开接口。
    """

    pattern: str
    ignore: bool = False
    require_login: bool = False
    permissions: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    mode: MatchMode = "OR"
    methods: list[str] = field(default_factory=list)

    def matches(self, path: str, method: str) -> bool:
        if self.methods and method.upper() not in {m.upper() for m in self.methods}:
            return False
        return ant_match(self.pattern, path)


class PathAuthConfig:
    """路径规则表。

    匹配策略：先看是否命中任一 ``ignore`` 规则；否则把全部命中的规则合并，
    权限与角色取并集。这样 ``/admin/**`` 与 ``/admin/user/**`` 可以叠加约束。
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
            merged.permissions.extend(rule.permissions)
            merged.roles.extend(rule.roles)
            if rule.mode == "AND":
                merged.mode = "AND"
        return merged
