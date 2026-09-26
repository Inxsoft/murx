"""Backend-node-side helper for redeeming MURX tokens.

Presenting a token to a backend node is deliberately outside the MURX
wire protocol (docs/SPEC.md section 2: backend nodes are not MURX
peers). ``TokenGatedServer`` implements the same minimal reference
convention as ``MurxClient.connect_to_backend`` -- a 1-byte token length
prefix followed by the raw token -- so the sample ERP backend and the
test suite have something concrete to run against. Real deployments are
free to use any backend-facing handshake they like, as long as the token
is redeemed exactly once.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from .server import TokenStore

SessionHandler = Callable[[str, asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class TokenGatedServer:
    """A backend node that only accepts sessions carrying a valid MURX token."""

    def __init__(
        self,
        token_store: TokenStore,
        session_handler: SessionHandler,
        host: str = "0.0.0.0",
        port: int = 0,
    ):
        self.token_store = token_store
        self.session_handler = session_handler
        self.host = host
        self.port = port
        self._server: Optional[asyncio.base_events.Server] = None

    @property
    def address(self) -> tuple[str, int]:
        assert self._server is not None, "server not started"
        return self._server.sockets[0].getsockname()[:2]

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            token_len = (await reader.readexactly(1))[0]
            token = await reader.readexactly(token_len)
        except asyncio.IncompleteReadError:
            writer.close()
            return

        client_id = self.token_store.redeem(token)
        if client_id is None:
            writer.close()
            return

        try:
            await self.session_handler(client_id, reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
