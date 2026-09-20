"""硬性约束：核心层不得依赖任何 Web 框架。

这条约束一旦破了，「原生可用」就成了空话，而且很难在 code review 里发现，
所以用测试固化下来。
"""

from __future__ import annotations

import subprocess
import sys

WEB_FRAMEWORKS = ("fastapi", "starlette", "flask", "django")

CORE_MODULES = (
    "sa_token",
    "sa_token.adapter",
    "sa_token.storage",
    "sa_token.strategy",
    "sa_token.oauth2",
    "sa_token.sso",
    "sa_token.online",
    "sa_token.sync",
)


def test_core_imports_no_web_framework() -> None:
    """在干净的子进程里导入核心，检查有没有把 Web 框架带进来。"""
    script = (
        "import sys\n"
        f"for name in {CORE_MODULES!r}:\n"
        "    __import__(name)\n"
        f"leaked = [f for f in {WEB_FRAMEWORKS!r} if f in sys.modules]\n"
        "print(','.join(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "", f"核心层泄漏了 Web 框架依赖：{result.stdout.strip()}"


def test_core_imports_no_optional_deps() -> None:
    """只装核心包也必须能 import，redis / pyjwt 只在真正使用时才加载。"""
    script = (
        "import sys\n"
        "import sa_token, sa_token.storage, sa_token.strategy\n"
        "leaked = [f for f in ('redis', 'jwt') if f in sys.modules]\n"
        "print(','.join(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "", f"核心层泄漏了可选依赖：{result.stdout.strip()}"
