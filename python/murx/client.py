"""MURX client: the TCP-facing side of AUTH_CONNECT -> ROUTE_REDIRECT/AUTH_REJECT."""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

from .errors import AuthenticationError
from .packets import (
    AuthConnect,
    AuthReject,
    MurxProtocolError,
    Opcode,
    RouteRedirect,
    peek_opcode,
)

MAX_TCP_PAYLOAD = 0xFFFF
DEFAULT_PORT = 2743


@dataclass(frozen=True)
class RouteInfo:
    """What a client needs to open its actual backend session."""

    target_ip: str
    target_port: int
    token: bytes


class MurxClient:
    """One-shot MURX client: connect, authenticate, get routed, disconnect.

    Usage::

        route = await MurxClient.authenticate(
            host="murx.example.com",
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )
        # route.target_ip, route.target_port, route.token
    """

    @staticmethod
    async def authenticate(
        host: str,
        client_id: str,
        auth_data: bytes,
        port: int = DEFAULT_PORT,
        timeout: float = 10.0,
    ) -> RouteInfo:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        try:
            request = AuthConnect(client_id=client_id, auth_data=auth_data)
            await _write_tcp_message(writer, request.encode())
            payload = await asyncio.wait_for(_read_tcp_message(reader), timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

        opcode = peek_opcode(payload)
        if opcode == Opcode.ROUTE_REDIRECT:
            redirect = RouteRedirect.decode(payload)
            return RouteInfo(
                target_ip=redirect.target_ip,
                target_port=redirect.target_port,
                token=redirect.token,
            )
        if opcode == Opcode.AUTH_REJECT:
            reject = AuthReject.decode(payload)
            raise AuthenticationError(reject.reason_code, reject.reason_text)
        raise MurxProtocolError(f"unexpected opcode {opcode:#x} from MURX server")

    @staticmethod
    async def connect_to_backend(
        route: RouteInfo, timeout: float = 10.0
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open the post-redirect session and present the token.

        How a token is presented to a backend node is not part of the MURX
        wire protocol (section 2 of docs/SPEC.md: backend nodes aren't MURX
        peers). This uses a minimal reference convention -- a 1-byte length
        prefix followed by the raw token -- shared with
        murx.backend.TokenGatedServer, which real deployments are free to
        replace with their own backend-facing handshake.
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(route.target_ip, route.target_port), timeout
        )
        writer.write(struct.pack("!B", len(route.token)) + route.token)
        await writer.drain()
        return reader, writer


async def _read_tcp_message(reader: asyncio.StreamReader) -> bytes:
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
