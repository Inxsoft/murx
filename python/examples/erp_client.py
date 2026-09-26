#!/usr/bin/env python3
"""Sample MURX client CLI for the user@domain / ERP use case.

    python examples/erp_client.py alice@example.com --murx-host 127.0.0.1 --murx-port 27430

If --murx-host/--murx-port are omitted, the domain part of the client id
is resolved via murx.discovery.resolve_murx_server (murx.<domain>:2743
by default, or an SRV record if one is published and dnspython is
installed).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from murx import AuthenticationError, MurxClient, resolve_murx_server, split_client_id


async def run(client_id: str, password: str, murx_host: str | None, murx_port: int | None) -> int:
    if murx_host is None:
        _, domain = split_client_id(client_id)
        murx_host, resolved_port = await resolve_murx_server(domain)
        if murx_port is None:
            murx_port = resolved_port
    if murx_port is None:
        murx_port = 2743

    try:
        route = await MurxClient.authenticate(
            host=murx_host,
            port=murx_port,
            client_id=client_id,
            auth_data=password.encode("utf-8"),
        )
    except AuthenticationError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return 1

    print(f"Routed to {route.target_host}:{route.target_port}")

    reader, writer = await MurxClient.connect_to_backend(route)
    try:
        greeting = await reader.readline()
        if greeting:
            print(greeting.decode(errors="replace").rstrip())
    finally:
        writer.close()
        await writer.wait_closed()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client_id", help="user@domain, e.g. alice@example.com")
    parser.add_argument("--murx-host", default=None, help="skip discovery, connect here directly")
    parser.add_argument("--murx-port", type=int, default=None)
    args = parser.parse_args()

    password = getpass.getpass(f"Password for {args.client_id}: ")
    exit_code = asyncio.run(run(args.client_id, password, args.murx_host, args.murx_port))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
