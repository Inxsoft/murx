import asyncio
import shutil
import struct
import subprocess

import pytest

from murx import (
    AuthenticationError,
    MurxClient,
    MurxServer,
    NodeRegistry,
    NodeRegistryRouter,
    ReasonCode,
    SignedTokenIssuer,
    SignedTokenVerifier,
    StaticAuthBackend,
    TokenGatedServer,
)
from murx import tls
from murx.node_registry import BackendAnnouncer
from murx.packets import AuthReject, NodeAnnounce

CREDENTIALS = {"alice@example.com": "hunter2"}
SECRETS = {"erp-1": b"erp-1-secret-0123456789abcdef!!"}


async def _start_murx_server(registry=None, issuer=None, ssl_context=None, host="127.0.0.1"):
    registry = registry if registry is not None else NodeRegistry(node_secrets=SECRETS)
    server = MurxServer(
        auth_backend=StaticAuthBackend(CREDENTIALS),
        router=NodeRegistryRouter(registry),
        host=host,
        port=0,
        node_registry=registry,
        token_issuer=issuer or SignedTokenIssuer(SECRETS),
        ssl_context=ssl_context,
    )
    await server.start()
    return server


async def _echo_backend(ssl_context=None) -> TokenGatedServer:
    async def handle_session(client_id, reader, writer):
        writer.write(f"hello {client_id}\n".encode())
        await writer.drain()

    backend = TokenGatedServer(
        SignedTokenVerifier("erp-1", SECRETS["erp-1"]),
        handle_session,
        host="127.0.0.1",
        port=0,
        ssl_context=ssl_context,
    )
    await backend.start()
    return backend


def _register(registry, backend, host=None):
    registry.record_announce(
        NodeAnnounce(
            node_id="erp-1",
            node_host=host or backend.address[0],
            node_port=backend.address[1],
            capacity=100,
        )
    )


async def _auth(server, password=b"hunter2", client_id="alice@example.com", **kw):
    host, port = server.address
    return await MurxClient.authenticate(
        host=kw.pop("host", host), port=port, client_id=client_id, auth_data=password, **kw
    )


async def test_auth_reject_on_bad_password():
    server = await _start_murx_server()
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await _auth(server, password=b"wrong")
        assert exc_info.value.reason_code == ReasonCode.INVALID_CREDENTIALS
    finally:
        await server.stop()


async def test_auth_reject_on_unknown_client():
    server = await _start_murx_server()
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await _auth(server, client_id="ghost@example.com")
        assert exc_info.value.reason_code == ReasonCode.INVALID_CREDENTIALS
    finally:
        await server.stop()


async def test_auth_reject_when_no_backend_available():
    server = await _start_murx_server()
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await _auth(server)
        assert exc_info.value.reason_code == ReasonCode.NO_ROUTE
    finally:
        await server.stop()


async def test_unsupported_version_lists_supported_versions():
    server = await _start_murx_server()
    try:
        reader, writer = await asyncio.open_connection(*server.address)
        bogus = b"\x09\x01\x01a\x00\x00"
        writer.write(struct.pack("!H", len(bogus)) + bogus)
        await writer.drain()
        (length,) = struct.unpack("!H", await reader.readexactly(2))
        reply = AuthReject.decode(await reader.readexactly(length))
        writer.close()
        assert reply.reason_code == ReasonCode.UNSUPPORTED_VERSION
        assert reply.reason_text == "1"
    finally:
        await server.stop()


async def test_full_flow_with_signed_token():
    registry = NodeRegistry(node_secrets=SECRETS)
    server = await _start_murx_server(registry)
    backend = await _echo_backend()
    try:
        _register(registry, backend)
        route = await _auth(server)
        assert (route.target_host, route.target_port) == backend.address

        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
        await writer.wait_closed()
    finally:
        await backend.stop()
        await server.stop()


async def test_hostname_redirect():
    registry = NodeRegistry(node_secrets=SECRETS)
    server = await _start_murx_server(registry)
    backend = await _echo_backend()
    try:
        _register(registry, backend, host="localhost")
        route = await _auth(server)
        assert route.target_host == "localhost"
        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
    finally:
        await backend.stop()
        await server.stop()


async def test_token_is_single_use_across_connections():
    registry = NodeRegistry(node_secrets=SECRETS)
    server = await _start_murx_server(registry)
    backend = await _echo_backend()
    try:
        _register(registry, backend)
        route = await _auth(server)

        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()

        reader2, writer2 = await MurxClient.connect_to_backend(route)
        assert await reader2.readline() == b""
        writer2.close()
    finally:
        await backend.stop()
        await server.stop()


async def test_end_to_end_with_authenticated_udp_announcer():
    registry = NodeRegistry(ttl=5.0, node_secrets=SECRETS)
    server = await _start_murx_server(registry)
    backend = await _echo_backend()

    stop_event = asyncio.Event()
    announcer = BackendAnnouncer(
        node_id="erp-1",
        node_host=backend.address[0],
        node_port=backend.address[1],
        capacity=100,
        server_host=server.address[0],
        server_port=server.address[1],
        secret=SECRETS["erp-1"],
        heartbeat_interval=0.05,
    )
    task = asyncio.create_task(announcer.run(stop_event=stop_event))
    try:
        for _ in range(50):
            if registry.live_nodes():
                break
            await asyncio.sleep(0.02)
        assert registry.live_nodes(), "node never registered over authenticated UDP"
        await asyncio.sleep(0.2)  # a few heartbeats must also be accepted
        assert registry.live_nodes()

        route = await _auth(server)
        reader, writer = await MurxClient.connect_to_backend(route)
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
    finally:
        stop_event.set()
        await task
        await backend.stop()
        await server.stop()


async def test_announcer_with_wrong_secret_never_registers():
    registry = NodeRegistry(ttl=5.0, node_secrets=SECRETS)
    server = await _start_murx_server(registry)
    stop_event = asyncio.Event()
    announcer = BackendAnnouncer(
        node_id="erp-1",
        node_host="127.0.0.1",
        node_port=9999,
        capacity=100,
        server_host=server.address[0],
        server_port=server.address[1],
        secret=b"not-the-real-secret",
        heartbeat_interval=0.05,
    )
    task = asyncio.create_task(announcer.run(stop_event=stop_event))
    try:
        await asyncio.sleep(0.3)
        assert registry.live_nodes() == []
    finally:
        stop_event.set()
        await task
        await server.stop()


@pytest.fixture(scope="module")
def tls_cert(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


async def test_tls_on_both_legs(tls_cert):
    cert, key = tls_cert
    registry = NodeRegistry(node_secrets=SECRETS)
    server = await _start_murx_server(registry, ssl_context=tls.server_context(cert, key))
    backend = await _echo_backend(ssl_context=tls.server_context(cert, key))
    client_ctx = tls.client_context(cafile=cert)
    try:
        _register(registry, backend, host="localhost")
        route = await _auth(server, host="localhost", ssl_context=client_ctx)
        reader, writer = await MurxClient.connect_to_backend(route, ssl_context=client_ctx)
        assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == tls.ALPN
        assert await reader.readline() == b"hello alice@example.com\n"
        writer.close()
    finally:
        await backend.stop()
        await server.stop()


async def test_tls_rejects_untrusted_server(tls_cert):
    cert, key = tls_cert
    server = await _start_murx_server(ssl_context=tls.server_context(cert, key))
    try:
        import ssl

        with pytest.raises(ssl.SSLCertVerificationError):
            await _auth(server, host="localhost", ssl_context=tls.client_context())
    finally:
        await server.stop()
