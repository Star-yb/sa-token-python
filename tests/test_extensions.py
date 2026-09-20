"""扩展模块：OAuth2、SSO、在线用户。全部不启动 HTTP 服务。"""

from __future__ import annotations

import asyncio

import pytest

from sa_token.adapter import SimpleHttpContext
from sa_token.exception import NotLoginException
from sa_token.oauth2 import OAuth2Client, OAuth2Error, OAuth2Server, generate_pkce_pair
from sa_token.online import OnlineManager, WebSocketAuthenticator
from sa_token.sso import SsoClient, SsoConfig, SsoError, SsoServer

# ----------------------------------------------------------------- OAuth2


@pytest.fixture
async def oauth2(manager):
    server = OAuth2Server(manager)
    await server.register_client(
        OAuth2Client(
            client_id="web-app",
            client_secret="secret-123",
            redirect_uris=["https://app.example/callback"],
            scopes=["read", "write"],
        )
    )
    return server


async def test_authorization_code_flow(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app",
        login_id="10001",
        redirect_uri="https://app.example/callback",
        scopes=["read"],
    )
    tokens = await oauth2.exchange_code_for_token(
        code=code.code,
        client_id="web-app",
        client_secret="secret-123",
        redirect_uri="https://app.example/callback",
    )

    assert tokens.access_token
    info = await oauth2.verify_access_token(tokens.access_token)
    assert info.login_id == "10001"
    assert info.scopes == ["read"]


async def test_authorization_code_is_single_use(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app",
        login_id="10001",
        redirect_uri="https://app.example/callback",
    )
    await oauth2.exchange_code_for_token(
        code=code.code, client_id="web-app", client_secret="secret-123"
    )
    with pytest.raises(OAuth2Error) as excinfo:
        await oauth2.exchange_code_for_token(
            code=code.code, client_id="web-app", client_secret="secret-123"
        )
    assert excinfo.value.error == "invalid_grant"


async def test_wrong_client_secret_rejected(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app",
        login_id="10001",
        redirect_uri="https://app.example/callback",
    )
    with pytest.raises(OAuth2Error) as excinfo:
        await oauth2.exchange_code_for_token(
            code=code.code, client_id="web-app", client_secret="wrong"
        )
    assert excinfo.value.error == "invalid_client"


async def test_unregistered_redirect_uri_rejected(oauth2) -> None:
    with pytest.raises(OAuth2Error) as excinfo:
        await oauth2.create_authorization_code(
            client_id="web-app",
            login_id="10001",
            redirect_uri="https://evil.example/callback",
        )
    assert excinfo.value.error == "invalid_request"


async def test_public_client_requires_pkce(manager) -> None:
    server = OAuth2Server(manager)
    await server.register_client(
        OAuth2Client(
            client_id="spa",
            redirect_uris=["https://spa.example/cb"],
            scopes=["read"],
        )
    )
    with pytest.raises(OAuth2Error):
        await server.create_authorization_code(
            client_id="spa", login_id="10001", redirect_uri="https://spa.example/cb"
        )

    verifier, challenge = generate_pkce_pair()
    code = await server.create_authorization_code(
        client_id="spa",
        login_id="10001",
        redirect_uri="https://spa.example/cb",
        code_challenge=challenge,
    )
    tokens = await server.exchange_code_for_token(
        code=code.code, client_id="spa", code_verifier=verifier
    )
    assert tokens.access_token


async def test_pkce_wrong_verifier_rejected(manager) -> None:
    server = OAuth2Server(manager)
    await server.register_client(
        OAuth2Client(client_id="spa", redirect_uris=["https://spa.example/cb"], scopes=[])
    )
    _, challenge = generate_pkce_pair()
    code = await server.create_authorization_code(
        client_id="spa",
        login_id="10001",
        redirect_uri="https://spa.example/cb",
        code_challenge=challenge,
    )
    with pytest.raises(OAuth2Error):
        await server.exchange_code_for_token(
            code=code.code, client_id="spa", code_verifier="wrong-verifier"
        )


async def test_refresh_token_rotates(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app", login_id="10001", redirect_uri="https://app.example/callback"
    )
    first = await oauth2.exchange_code_for_token(
        code=code.code, client_id="web-app", client_secret="secret-123"
    )
    second = await oauth2.refresh_access_token(
        refresh_token=first.refresh_token, client_id="web-app", client_secret="secret-123"
    )

    assert second.access_token != first.access_token
    # 旧的 refresh token 必须立刻失效。
    with pytest.raises(OAuth2Error):
        await oauth2.refresh_access_token(
            refresh_token=first.refresh_token, client_id="web-app", client_secret="secret-123"
        )


async def test_access_token_can_be_revoked(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app", login_id="10001", redirect_uri="https://app.example/callback"
    )
    tokens = await oauth2.exchange_code_for_token(
        code=code.code, client_id="web-app", client_secret="secret-123"
    )
    assert await oauth2.revoke_token(tokens.access_token) is True
    with pytest.raises(OAuth2Error):
        await oauth2.verify_access_token(tokens.access_token)


async def test_scope_check(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app",
        login_id="10001",
        redirect_uri="https://app.example/callback",
        scopes=["read"],
    )
    tokens = await oauth2.exchange_code_for_token(
        code=code.code, client_id="web-app", client_secret="secret-123"
    )
    await oauth2.check_scope(tokens.access_token, "read")
    with pytest.raises(OAuth2Error):
        await oauth2.check_scope(tokens.access_token, "write")


# -------------------------------------------------------------------- SSO


async def test_sso_ticket_flow(manager) -> None:
    server = SsoServer(manager, SsoConfig(server_url="https://sso.example/auth"))
    client = SsoClient(manager, server_url="https://sso.example/auth", service="https://app.example")

    ticket = await server.create_ticket("10001", "https://app.example")
    local_token = await client.login_by_ticket(server, ticket)

    assert await manager.stp().check_login(local_token) == "10001"


async def test_sso_ticket_is_single_use(manager) -> None:
    server = SsoServer(manager)
    await server.create_ticket("10001", "https://app.example")
    ticket = await server.create_ticket("10001", "https://app.example")

    assert await server.validate_ticket(ticket, "https://app.example") == "10001"
    with pytest.raises(SsoError):
        await server.validate_ticket(ticket, "https://app.example")


async def test_sso_ticket_bound_to_service(manager) -> None:
    server = SsoServer(manager)
    ticket = await server.create_ticket("10001", "https://app-a.example")
    with pytest.raises(SsoError):
        await server.validate_ticket(ticket, "https://app-b.example")


async def test_sso_service_whitelist(manager) -> None:
    server = SsoServer(manager, SsoConfig(allowed_services=["https://app.example"]))
    with pytest.raises(SsoError):
        await server.create_ticket("10001", "https://evil.example")


async def test_sso_unified_logout_returns_clients(manager) -> None:
    server = SsoServer(manager)
    await server.create_ticket("10001", "https://app-a.example")
    await server.create_ticket("10001", "https://app-b.example")

    services = await server.logout("10001")
    assert set(services) == {"https://app-a.example", "https://app-b.example"}


# ------------------------------------------------------------- 在线用户 / WS


class FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed = False


async def test_websocket_authenticate_reads_token_from_query(manager) -> None:
    token = await manager.stp().login(10001)
    authenticator = WebSocketAuthenticator(manager)
    # 浏览器 WebSocket 不能自定义 Header，query 往往是唯一通道。
    ctx = SimpleHttpContext(query={"Authorization": token})

    assert await authenticator.authenticate(ctx) == "10001"


async def test_websocket_authenticate_rejects_bad_token(manager) -> None:
    authenticator = WebSocketAuthenticator(manager)
    with pytest.raises(NotLoginException):
        await authenticator.authenticate(SimpleHttpContext())


async def test_online_manager_tracks_and_pushes(manager) -> None:
    async def send(connection: FakeWebSocket, message: str) -> None:
        connection.sent.append(message)

    async def close(connection: FakeWebSocket) -> None:
        connection.closed = True

    online = OnlineManager(manager, sender=send, closer=close)
    socket = FakeWebSocket()
    await online.register("10001", socket, connection_id="c1")

    assert await online.is_online("10001") is True
    assert await online.send_to_user("10001", "hello") == 1
    assert socket.sent == ["hello"]


async def test_online_kickout_closes_connection(manager) -> None:
    async def close(connection: FakeWebSocket) -> None:
        connection.closed = True

    online = OnlineManager(manager, closer=close)
    token = await manager.stp().login(10001)
    socket = FakeWebSocket()
    await online.register("10001", socket, connection_id="c1")

    await online.kickout("10001")

    assert socket.closed is True
    assert await online.is_online("10001") is False
    assert await manager.stp().is_login(token) is False


async def test_online_unregister(manager) -> None:
    online = OnlineManager(manager)
    await online.register("10001", FakeWebSocket(), connection_id="c1")
    await online.unregister("10001", "c1")
    assert await online.is_online("10001") is False


async def test_oauth2_client_credentials_and_introspection(manager) -> None:
    server = OAuth2Server(manager)
    await server.register_client(
        OAuth2Client(
            client_id="backend",
            client_secret="backend-secret",
            grant_types=["client_credentials"],
            scopes=["order:read"],
        )
    )
    response = await server.client_credentials_token(
        client_id="backend",
        client_secret="backend-secret",
        scopes=["order:read"],
    )
    assert response.refresh_token is None
    introspection = await server.introspect(response.access_token)
    assert introspection["active"] is True
    assert introspection["sub"] == "client:backend"
    await server.revoke_token(response.access_token)
    assert await server.introspect(response.access_token) == {"active": False}


async def test_oauth2_concurrent_refresh_succeeds_once(oauth2) -> None:
    code = await oauth2.create_authorization_code(
        client_id="web-app",
        login_id="10001",
        redirect_uri="https://app.example/callback",
    )
    first = await oauth2.exchange_code_for_token(
        code=code.code, client_id="web-app", client_secret="secret-123"
    )
    results = await asyncio.gather(
        *(
            oauth2.refresh_access_token(
                refresh_token=first.refresh_token,
                client_id="web-app",
                client_secret="secret-123",
            )
            for _ in range(10)
        ),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1


async def test_sso_signed_ticket(manager) -> None:
    server = SsoServer(
        manager,
        SsoConfig(
            secret_key="a-secure-sso-secret-key-that-is-long",
            allowed_services=["https://app.example"],
        ),
    )
    signed = await server.create_signed_ticket("10001", "https://app.example")
    with pytest.raises(SsoError):
        await server.validate_ticket(
            signed.ticket,
            signed.service,
            signature="invalid",
        )
    assert (
        await server.validate_ticket(
            signed.ticket,
            signed.service,
            signature=signed.signature,
        )
        == "10001"
    )


async def test_sso_concurrent_service_registration_keeps_every_service(manager) -> None:
    server = SsoServer(manager)
    services = [f"https://app-{index}.example" for index in range(20)]
    await asyncio.gather(
        *(server.create_ticket("10001", service) for service in services)
    )
    assert set(await server.get_registered_services("10001")) == set(services)


async def test_core_kickout_automatically_closes_online_connection(manager) -> None:
    async def close(connection: FakeWebSocket) -> None:
        connection.closed = True

    online = OnlineManager(manager, closer=close)
    socket = FakeWebSocket()
    await online.register("10001", socket, connection_id="web-1", device="web")
    await manager.stp().login("10001")

    await manager.stp().kickout("10001")
    assert socket.closed is True


async def test_online_send_and_disconnect_by_device(manager) -> None:
    async def send(connection: FakeWebSocket, message: str) -> None:
        connection.sent.append(message)

    async def close(connection: FakeWebSocket) -> None:
        connection.closed = True

    online = OnlineManager(manager, sender=send, closer=close)
    web = FakeWebSocket()
    app = FakeWebSocket()
    await online.register("10001", web, connection_id="web-1", device="web")
    await online.register("10001", app, connection_id="app-1", device="app")

    assert await online.send_to_device("10001", "web", "hello") == 1
    assert web.sent == ["hello"]
    assert app.sent == []
    await online.disconnect_device("10001", "web")
    assert web.closed is True
    assert app.closed is False
