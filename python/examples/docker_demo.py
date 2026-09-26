#!/usr/bin/env python3
"""Role-based entry point for the docker compose demo.

    python examples/docker_demo.py server
    python examples/docker_demo.py node
    python examples/docker_demo.py client

Configuration comes from environment variables (see docker-compose.yml).
Demo only: plain TCP, a static test credential, and secrets passed via
environment variables.
"""

from __future__ import annotations

import asyncio
import os
import sys

from murx import (
    AuthenticationError,
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


def _node_secrets() -> dict[str, bytes]:
    # NODE_SECRETS="erp-1:<hex>,erp-2:<hex>"
    pairs = (item.split(":", 1) for item in os.environ["NODE_SECRETS"].split(","))
    return {node_id: bytes.fromhex(secret) for node_id, secret in pairs}


async def run_server() -> None:
    node_secrets = _node_secrets()
    registry = NodeRegistry(node_secrets=node_secrets)
    server = MurxServer(
        auth_backend=StaticAuthBackend({"alice@example.com": "hunter2"}),
        router=NodeRegistryRouter(registry),
        host="0.0.0.0",
        port=2743,
        node_registry=registry,
        token_issuer=SignedTokenIssuer(node_secrets),
    )
    await server.start()
    print(f"murx-server: listening on 2743/tcp+udp, {len(node_secrets)} node secrets loaded", flush=True)
    await server.serve_forever()


async def run_node() -> None:
    node_id = os.environ["NODE_ID"]
    secret = bytes.fromhex(os.environ["NODE_SECRET"])
    port = int(os.environ.get("NODE_PORT", "9200"))

    async def session(client_id, reader, writer):
        print(f"{node_id}: session for {client_id}", flush=True)
        writer.write(f"ERP[{node_id}]: welcome, {client_id}\n".encode())
        await writer.drain()

    backend = TokenGatedServer(SignedTokenVerifier(node_id, secret), session, host="0.0.0.0", port=port)
    await backend.start()
    announcer = BackendAnnouncer(
        node_id=node_id,
        node_host=os.environ.get("NODE_HOST", node_id),
        node_port=port,
        capacity=int(os.environ.get("NODE_CAPACITY", "100")),
        server_host=os.environ.get("MURX_SERVER", "murx-server"),
        secret=secret,
        heartbeat_interval=2.0,
    )
    print(f"{node_id}: serving on {port}/tcp, announcing to MURX server", flush=True)
    await asyncio.gather(backend.serve_forever(), announcer.run())


async def run_client() -> int:
    host = os.environ.get("MURX_SERVER", "murx-server")
    for attempt in range(20):
        try:
            route = await MurxClient.authenticate(
                host=host, client_id="alice@example.com", auth_data=b"hunter2"
            )
            break
        except (OSError, AuthenticationError) as exc:
            print(f"client: not ready yet ({exc}), retrying", flush=True)
            await asyncio.sleep(1)
    else:
        print("client: gave up", flush=True)
        return 1

    print(f"client: redirected to {route.target_host}:{route.target_port}", flush=True)
    reader, writer = await MurxClient.connect_to_backend(route)
    print("client: backend says:", (await reader.readline()).decode().strip(), flush=True)
    writer.close()
    return 0


def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else ""
    if role == "server":
        asyncio.run(run_server())
    elif role == "node":
        asyncio.run(run_node())
    elif role == "client":
        sys.exit(asyncio.run(run_client()))
    else:
        sys.exit("usage: docker_demo.py server|node|client")


if __name__ == "__main__":
    main()
