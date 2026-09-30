"""Django 中间件：路径鉴权跑在后台循环里，身份必须回到请求线程。"""

from __future__ import annotations

import pytest

pytest.importorskip("django")

from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(DEBUG=True, SECRET_KEY="test")

import django  # noqa: E402

django.setup()

from django.http import HttpResponse  # noqa: E402
from django.test import RequestFactory  # noqa: E402

from sa_token.adapter import PathAuthConfig  # noqa: E402
from sa_token.context import clear_current, get_current_login_id, get_current_token  # noqa: E402
from sa_token.integration import django as django_integration  # noqa: E402


async def test_path_auth_rebinds_identity_on_the_request_thread(manager) -> None:
    token = await manager.stp().login("10001")
    seen: dict[str, str | None] = {}

    def get_response(request):
        seen["login_id"] = get_current_login_id()
        seen["token"] = get_current_token()
        return HttpResponse("ok")

    django_integration.PATH_AUTH = PathAuthConfig().login("/**")
    try:
        middleware = django_integration.SaTokenDjangoMiddleware(get_response)
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = middleware(request)
    finally:
        django_integration.PATH_AUTH = None
        clear_current()

    assert response.status_code == 200
    assert seen["login_id"] == "10001"
    assert seen["token"] == token
    assert get_current_login_id() is None


async def test_decorator_rebinds_identity_on_the_request_thread(manager) -> None:
    token = await manager.stp().login("10001")
    seen: dict[str, str | None] = {}

    @django_integration.check_login
    def view(request):
        seen["login_id"] = get_current_login_id()
        return HttpResponse("ok")

    request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = view(request)

    assert response.status_code == 200
    assert seen["login_id"] == "10001"
    assert get_current_login_id() is None


async def test_async_view_is_awaited(manager) -> None:
    token = await manager.stp().login("10001")
    seen: dict[str, str | None] = {}

    @django_integration.check_login
    async def view(request):
        seen["login_id"] = get_current_login_id()
        return HttpResponse("ok")

    request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = await view(request)

    assert response.status_code == 200
    assert seen["login_id"] == "10001"
    assert get_current_login_id() is None
