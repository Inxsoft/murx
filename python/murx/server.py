"""MURX server: the TCP-facing authenticated routing gateway.

See docs/SPEC.md sections 4-8. This module implements the AUTH_CONNECT ->
ROUTE_REDIRECT/AUTH_REJECT exchange and wires it up to a pluggable
AuthBackend and a Router (by default, backed by a NodeRegistry fed over
UDP -- see node_registry.py).
"""

from __future__ import annotations

import asyncio
import secrets
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .errors import NoRouteError
from .node_registry import NodeRegistry, serve_node_registry
from .packets import (
    AuthConnect,
    AuthReject,
    MurxProtocolError,
    Opcode,
    ReasonCode,
    RouteRedirect,
    peek_opcode,
)

__all__ = [
    "AuthBackend",
    "StaticAuthBackend",
    "Router",
    "NodeRegistryRouter",
    "TokenStore",
    "MurxServer",
]

DEFAULT_TOKEN_TTL = 30.0
MAX_TCP_PAYLOAD = 0xFFFF


class AuthBackend(ABC):
    """Pluggable credential verification. Auth Data's meaning is up to this."""

    @abstractmethod
    async def authenticate(self, client_id: str, auth_data: bytes) -> bool:
        """Return True if the credentials are valid for client_id."""


class StaticAuthBackend(AuthBackend):
    """Demo/test-only AuthBackend backed by an in-memory client_id -> password map.

    Do NOT use this for anything handling real credentials: passwords are
    compared in memory as plain UTF-8 bytes with no hashing, salting, or
    rate limiting. It exists to make the ERP walkthrough and the test
    suite self-contained.
    """

    def __init__(self, credentials: dict[str, str]):
        self._credentials = credentials

    async def authenticate(self, client_id: str, auth_data: bytes) -> bool:
        expected = self._credentials.get(client_id)
        if expected is None:
            return False
        return secrets.compare_digest(auth_data, expected.encode("utf-8"))


class Router(Protocol):
    async def route(self, client_id: str) -> tuple[str, int]:
        """Return (ip, port) of the backend node to send client_id to.

        Raise NoRouteError if no backend is available.
        """


class NodeRegistryRouter:
    """Router backed by a NodeRegistry (nodes discovered via UDP heartbeats)."""

    def __init__(self, registry: NodeRegistry):
        self.registry = registry

    async def route(self, client_id: str) -> tuple[str, int]:
        entry = self.registry.choose_node()
        return entry.ip, entry.port


@dataclass
class _TokenRecord:
    client_id: str
    expires_at: float


class TokenStore:
    """Shared token store between the MURX server and backend nodes.

    In a real deployment this would be a distributed cache (Redis, etc.)
    reachable by both the MURX server and every backend node. For the
    reference implementation and tests, a single in-memory instance is
    passed to both sides directly.
    """

    def __init__(self, ttl: float = DEFAULT_TOKEN_TTL, loop_time=None):
        self.ttl = ttl
        self._loop_time = loop_time
        self._tokens: dict[bytes, _TokenRecord] = {}

    def _now(self) -> float:
        if self._loop_time is not None:
            return self._loop_time()
        return asyncio.get_running_loop().time()

    def issue(self, client_id: str) -> bytes:
        token = secrets.token_bytes(16)
        self._tokens[token] = _TokenRecord(client_id=client_id, expires_at=self._now() + self.ttl)
        return token

    def redeem(self, token: bytes) -> Optional[str]:
        """Consume a token, returning its client_id, or None if invalid/expired/used."""
        record = self._tokens.pop(token, None)
        if record is None:
            return None
        if self._now() > record.expires_at:
            return None
        return record.client_id


class MurxServer:
    def __init__(
        self,
        auth_backend: AuthBackend,
        router: Router,
        host: str = "0.0.0.0",
        port: int = 2743,
        node_registry: Optional[NodeRegistry] = None,
        token_store: Optional[TokenStore] = None,
    ):
        self.auth_backend = auth_backend
        self.router = router
        self.host = host
        self.port = port
        self.node_registry = node_registry
        self.token_store = token_store if token_store is not None else TokenStore()
        self._tcp_server: Optional[asyncio.base_events.Server] = None
        self._udp_transport = None

    @property
    def address(self) -> tuple[str, int]:
        assert self._tcp_server is not None, "server not started"
        sock = self._tcp_server.sockets[0]
        return sock.getsockname()[:2]

    async def start(self) -> None:
        self._tcp_server = await asyncio.start_server(self._handle_client, self.host, self.port)
        # TCP and UDP have independent port namespaces, so binding both
        # sockets to the same port number is always possible even when
        # self.port == 0 (OS-assigned): resolve the actual TCP port first so
        # the UDP node-registry listener uses that same number, keeping both
        # transports on "port 2743" (or its ephemeral stand-in) as the spec
        # models it.
        bound_port = self._tcp_server.sockets[0].getsockname()[1]
        if self.node_registry is not None:
            self._udp_transport, _ = await serve_node_registry(
                self.node_registry, self.host, bound_port
            )

    async def serve_forever(self) -> None:
        if self._tcp_server is None:
            await self.start()
        async with self._tcp_server:
            await self._tcp_server.serve_forever()

    async def stop(self) -> None:
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        if self._udp_transport is not None:
            self._udp_transport.close()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            payload = await _read_tcp_message(reader)
            if payload is None:
                return
            reply = await self._process(payload)
            await _write_tcp_message(writer, reply)
        except MurxProtocolError:
            reply = AuthReject(reason_code=ReasonCode.MALFORMED_REQUEST).encode()
            try:
                await _write_tcp_message(writer, reply)
            except (ConnectionError, OSError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _process(self, payload: bytes) -> bytes:
        opcode = peek_opcode(payload)
        if opcode != Opcode.AUTH_CONNECT:
            return AuthReject(
                reason_code=ReasonCode.MALFORMED_REQUEST,
                reason_text=f"unexpected opcode {opcode:#x}",
            ).encode()

        request = AuthConnect.decode(payload)
        ok = await self.auth_backend.authenticate(request.client_id, request.auth_data)
        if not ok:
            return AuthReject(reason_code=ReasonCode.INVALID_CREDENTIALS).encode()

        try:
            ip, port = await self.router.route(request.client_id)
        except NoRouteError as exc:
            return AuthReject(reason_code=ReasonCode.NO_ROUTE, reason_text=str(exc)).encode()

        token = self.token_store.issue(request.client_id)
        return RouteRedirect(target_ip=ip, target_port=port, token=token).encode()


async def _read_tcp_message(reader: asyncio.StreamReader) -> Optional[bytes]:
    header = await reader.readexactly(2)
    (length,) = struct.unpack("!H", header)
    if length == 0:
        return b""
    return await reader.readexactly(length)


async def _write_tcp_message(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if len(payload) > MAX_TCP_PAYLOAD:
        raise MurxProtocolError("payload exceeds maximum TCP message size")
    writer.write(struct.pack("!H", len(payload)) + payload)
    await writer.drain()
