#!/usr/bin/env python3
"""End-to-end MURX demo, no external services required.

Spins up, on loopback:
  - one MurxServer (TCP auth/redirect + authenticated UDP node registry)
  - two toy "ERP" backend nodes, each announcing itself over UDP with
    its own shared secret and verifying signed tokens locally
  - one MurxClient authenticating as alice@example.com and following
    the redirect to whichever node MURX picked

Run with: python examples/erp_backend_demo.py
"""

from __future__ import annotations

import asyncio
import secrets

from murx import (
    BackendAnnouncer,
    MurxClient,
    MurxServer,
    NodeRegistry,
    NodeRegistryRouter,
    SignedTokenIssuer,
    SignedTokenVerifier,
    StaticAuthBackend,
    TokenGatedServer,
)

CREDENTIALS = {"alice@example.com": "hunter2"}
NODES = {"erp-1": 100, "erp-2": 50}  # node_id -> capacity


def make_session_handler(node_id: str):
    async def handle_session(client_id, reader, writer):
        writer.write(f"ERP[{node_id}]: welcome, {client_id}\n".encode())
        await writer.drain()

    return handle_session


async def main() -> None:
    # One shared secret per node, known to that node and the MURX server.
    node_secrets = {node_id: secrets.token_bytes(32) for node_id in NODES}

    registry = NodeRegistry(node_secrets=node_secrets)
    murx_server = MurxServer(
        auth_backend=StaticAuthBackend(CREDENTIALS),
        router=NodeRegistryRouter(registry),
        host="127.0.0.1",
        port=0,
        node_registry=registry,
        token_issuer=SignedTokenIssuer(node_secrets),
    )
    await murx_server.start()
    murx_host, murx_port = murx_server.address
    print(f"MURX server listening on {murx_host}:{murx_port} (tcp+udp)")

    backends = {}
    for node_id in NODES:
        backend = TokenGatedServer(
            SignedTokenVerifier(node_id, node_secrets[node_id]),
            make_session_handler(node_id),
            host="127.0.0.1",
            port=0,
        )
        await backend.start()
        backends[node_id] = backend

    stop = asyncio.Event()
    announcers = [
        BackendAnnouncer(
            node_id=node_id,
            node_host="127.0.0.1",
            node_port=backends[node_id].address[1],
            capacity=capacity,
            server_host=murx_host,
            server_port=murx_port,
            secret=node_secrets[node_id],
            heartbeat_interval=1.0,
        )
        for node_id, capacity in NODES.items()
    ]
    tasks = [asyncio.create_task(a.run(stop_event=stop)) for a in announcers]

    # Give the UDP NODE_ANNOUNCE datagrams a moment to land in the registry.
    await asyncio.sleep(0.3)

    try:
        route = await MurxClient.authenticate(
            host=murx_host,
            port=murx_port,
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )
        print(f"Routed to {route.target_host}:{route.target_port} ({len(route.token)}-byte signed token)")

        reader, writer = await MurxClient.connect_to_backend(route)
        greeting = await reader.readline()
        print("Backend says:", greeting.decode().strip())
        writer.close()
        await writer.wait_closed()
    finally:
        stop.set()
        await asyncio.gather(*tasks)
        for backend in backends.values():
            await backend.stop()
        await murx_server.stop()


if __name__ == "__main__":
    asyncio.run(main())
