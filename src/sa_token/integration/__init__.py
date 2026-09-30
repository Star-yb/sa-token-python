"""框架绑定。

每个子模块都只做「Request → HttpContext、调用统一管道、异常翻译」三件事，
因此各框架的行为天然一致。适配代码随主包发布，但不会安装 FastAPI / Flask / Django。
这里不做顶层导入；进入具体子模块时，若对应框架未安装，会抛出 ImportError。
"""

from __future__ import annotations

__all__ = ["fastapi", "starlette", "flask", "django", "fastapi_oauth2"]
