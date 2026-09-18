"""框架绑定。

每个子模块都只做「Request → HttpContext、调用统一管道、异常翻译」三件事，
因此各框架的行为天然一致。这些模块依赖对应的可选 extra，
不在这里做顶层导入，避免只装了核心包的用户 import 失败。
"""

from __future__ import annotations

__all__ = ["fastapi", "starlette", "flask", "django"]
