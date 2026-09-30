"""OAuth2 FastAPI 路由：标准表单、错误体、introspection、revoke。"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sa_token.integration.fastapi_oauth2 import create_oauth2_router  # noqa: E402
from sa_token.oauth2 import OAuth2Client, OAuth2Server  # noqa: E402


def test_oauth2_fastapi_client_credentials(manager) -> None:
    server = OAuth2Server(manager)
    asyncio.run(
        server.register_client(
            OAuth2Client(
                client_id="backend",
                client_secret="secret",
                grant_types=["client_credentials"],
                scopes=["order:read"],
            )
        )
    )
    app = FastAPI()
    app.include_router(create_oauth2_router(server))

    with TestClient(app) as client:
        token_response = client.post(
            "/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "backend",
                "client_secret": "secret",
                "scope": "order:read",
            },
        )
        assert token_response.status_code == 200
        payload = token_response.json()
        assert "refresh_token" not in payload

        unauthenticated = client.post(
            "/oauth2/introspect", data={"token": payload["access_token"]}
        )
        assert unauthenticated.status_code == 401

        introspection = client.post(
            "/oauth2/introspect",
            data={
                "token": payload["access_token"],
                "client_id": "backend",
                "client_secret": "secret",
            },
        )
        assert introspection.json()["active"] is True

        assert (
            client.post(
                "/oauth2/revoke",
                data={
                    "token": payload["access_token"],
                    "client_id": "backend",
                    "client_secret": "secret",
                },
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/oauth2/introspect",
                data={
                    "token": payload["access_token"],
                    "client_id": "backend",
                    "client_secret": "secret",
                },
            ).json()
            == {"active": False}
        )


def test_oauth2_fastapi_standard_error(manager) -> None:
    server = OAuth2Server(manager)
    app = FastAPI()
    app.include_router(create_oauth2_router(server))

    with TestClient(app) as client:
        response = client.post(
            "/oauth2/token",
            json={"grant_type": "unknown"},
        )
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "error": "unsupported_grant_type",
            "error_description": "不支持的 grant_type: unknown",
        }

        invalid = client.post(
            "/oauth2/token",
            content=b"{",
            headers={"content-type": "application/json"},
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"] == "invalid_request"
