import asyncio

import pytest

from murx import (
    AuthenticationError,
    MurxClient,
    MurxServer,
    NodeRegistry,
    NodeRegistryRouter,
    ReasonCode,
    StaticAuthBackend,
    TokenGatedServer,
    TokenStore,
)
from murx.node_registry import BackendAnnouncer
from murx.packets import NodeAnnounce

CREDENTIALS = {"alice@example.com": "hunter2"}


async def _start_murx_server(node_registry=None, token_store=None):
    server = MurxServer(
        auth_backend=StaticAuthBackend(CREDENTIALS),
        router=NodeRegistryRouter(node_registry or NodeRegistry()),
        host="127.0.0.1",
        port=0,
        node_registry=node_registry,
        token_store=token_store,
    )
    await server.start()
    return server


async def _echo_backend(token_store) -> TokenGatedServer:
    async def handle_session(client_id, reader, writer):
        writer.write(f"hello {client_id}\n".encode())
        await writer.drain()

    backend = TokenGatedServer(token_store, handle_session, host="127.0.0.1", port=0)
    await backend.start()
    return backend


@pytest.mark.asyncio
async def test_auth_reject_on_bad_password():
    server = await _start_murx_server()
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await MurxClient.authenticate(
                host=server.address[0],
                port=server.address[1],
                client_id="alice@example.com",
                auth_data=b"wrong-password",
            )
        assert exc_info.value.reason_code == ReasonCode.INVALID_CREDENTIALS
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_auth_reject_on_unknown_client():
    server = await _start_murx_server()
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await MurxClient.authenticate(
                host=server.address[0],
                port=server.address[1],
                client_id="ghost@example.com",
                auth_data=b"anything",
            )
        assert exc_info.value.reason_code == ReasonCode.INVALID_CREDENTIALS
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_auth_reject_when_no_backend_available():
    registry = NodeRegistry()
    server = await _start_murx_server(node_registry=registry)
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await MurxClient.authenticate(
                host=server.address[0],
                port=server.address[1],
                client_id="alice@example.com",
                auth_data=b"hunter2",
            )
        assert exc_info.value.reason_code == ReasonCode.NO_ROUTE
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_full_flow_with_manually_registered_node():
    registry = NodeRegistry()
    token_store = TokenStore()
    server = await _start_murx_server(node_registry=registry, token_store=token_store)
    backend = await _echo_backend(token_store)
    try:
        registry.record_announce(
            NodeAnnounce(
                node_id="erp-1",
                node_ip=backend.address[0],
                node_port=backend.address[1],
                capacity=100,
            )
        )

        route = await MurxClient.authenticate(
            host=server.address[0],
            port=server.address[1],
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )
        assert (route.target_ip, route.target_port) == backend.address

        reader, writer = await MurxClient.connect_to_backend(route)
        greeting = await reader.readline()
        assert greeting == b"hello alice@example.com\n"
        writer.close()
        await writer.wait_closed()
    finally:
        await backend.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_token_is_single_use():
    registry = NodeRegistry()
    token_store = TokenStore()
    server = await _start_murx_server(node_registry=registry, token_store=token_store)
    backend = await _echo_backend(token_store)
    try:
        registry.record_announce(
            NodeAnnounce(
                node_id="erp-1",
                node_ip=backend.address[0],
                node_port=backend.address[1],
                capacity=100,
            )
        )
        route = await MurxClient.authenticate(
            host=server.address[0],
            port=server.address[1],
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )

        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
        await writer.wait_closed()

        # Reusing the same token should be rejected (backend closes with no data).
        reader2, writer2 = await MurxClient.connect_to_backend(route)
        second_attempt = await reader2.readline()
        assert second_attempt == b""
        writer2.close()
        await writer2.wait_closed()
    finally:
        await backend.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_end_to_end_with_udp_backend_announcer():
    """Full stack: UDP NODE_ANNOUNCE/NODE_HEARTBEAT feed the registry that
    the TCP AUTH_CONNECT flow then routes against -- no manual registry
    poking."""
    registry = NodeRegistry(ttl=5.0)
    token_store = TokenStore()
    server = await _start_murx_server(node_registry=registry, token_store=token_store)
    backend = await _echo_backend(token_store)

    stop_event = asyncio.Event()
    announcer = BackendAnnouncer(
        node_id="erp-1",
        node_ip=backend.address[0],
        node_port=backend.address[1],
        capacity=100,
        server_host=server.address[0],
        server_port=server.address[1],
        heartbeat_interval=0.1,
    )
    announcer_task = asyncio.create_task(announcer.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if registry.live_nodes():
                break
            await asyncio.sleep(0.02)
        assert registry.live_nodes(), "node never showed up in the registry via UDP"

        route = await MurxClient.authenticate(
            host=server.address[0],
            port=server.address[1],
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )
        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
        await writer.wait_closed()
    finally:
        stop_event.set()
        await announcer_task
        await backend.stop()
        await server.stop()
