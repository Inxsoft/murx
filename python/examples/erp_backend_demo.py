#!/usr/bin/env python3
"""End-to-end MURX demo, no external services required.

Spins up, on loopback:
  - one MurxServer (TCP auth/redirect + UDP node registry)
  - two toy "ERP" backend nodes, each announcing/heartbeating itself
    over UDP via BackendAnnouncer
  - one MurxClient authenticating as alice@example.com and following
    the redirect to whichever node MURX picked

Run with: python examples/erp_backend_demo.py
"""

from __future__ import annotations

import asyncio

from murx import (
    MurxClient,
    MurxServer,
    NodeRegistry,
    NodeRegistryRouter,
    StaticAuthBackend,
    TokenGatedServer,
    TokenStore,
)
from murx.node_registry import BackendAnnouncer

CREDENTIALS = {"alice@example.com": "hunter2"}


def make_erp_session_handler(node_name: str):
    async def handle_session(client_id, reader, writer):
        writer.write(f"ERP[{node_name}]: welcome, {client_id}\n".encode())
        await writer.drain()

    return handle_session


async def start_backend_node(node_name: str, token_store: TokenStore) -> TokenGatedServer:
    server = TokenGatedServer(
        token_store=token_store,
        session_handler=make_erp_session_handler(node_name),
        host="127.0.0.1",
        port=0,
    )
    await server.start()
    return server


async def main() -> None:
    token_store = TokenStore()
    registry = NodeRegistry()

    murx_server = MurxServer(
        auth_backend=StaticAuthBackend(CREDENTIALS),
        router=NodeRegistryRouter(registry),
        host="127.0.0.1",
        port=0,
        node_registry=registry,
        token_store=token_store,
    )
    await murx_server.start()
    murx_host, murx_port = murx_server.address
    print(f"MURX server listening on {murx_host}:{murx_port} (tcp+udp)")

    node_a = await start_backend_node("erp-1", token_store)
    node_b = await start_backend_node("erp-2", token_store)

    stop_events = [asyncio.Event(), asyncio.Event()]
    announcers = [
        BackendAnnouncer(
            node_id="erp-1",
            node_ip="127.0.0.1",
            node_port=node_a.address[1],
            capacity=100,
            server_host=murx_host,
            server_port=murx_port,
            heartbeat_interval=1.0,
        ),
        BackendAnnouncer(
            node_id="erp-2",
            node_ip="127.0.0.1",
            node_port=node_b.address[1],
            capacity=50,
            server_host=murx_host,
            server_port=murx_port,
            heartbeat_interval=1.0,
        ),
    ]
    announcer_tasks = [
        asyncio.create_task(a.run(stop_event=e)) for a, e in zip(announcers, stop_events)
    ]

    # Give the UDP NODE_ANNOUNCE datagrams a moment to land in the registry.
    await asyncio.sleep(0.3)

    try:
        route = await MurxClient.authenticate(
            host=murx_host,
            port=murx_port,
            client_id="alice@example.com",
            auth_data=b"hunter2",
        )
        print(f"Routed to {route.target_ip}:{route.target_port} with token {route.token.hex()}")

        reader, writer = await MurxClient.connect_to_backend(route)
        greeting = await reader.readline()
        print("Backend says:", greeting.decode().strip())
        writer.close()
        await writer.wait_closed()
    finally:
        for e in stop_events:
            e.set()
        for t in announcer_tasks:
            await t
        await node_a.stop()
        await node_b.stop()
        await murx_server.stop()


if __name__ == "__main__":
    asyncio.run(main())
