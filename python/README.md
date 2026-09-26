# murx

Reference implementation of **MURX** (Multi-User Resource eXchange), an
authenticated routing gateway protocol: a client authenticates once
against a MURX server, which then redirects it (IP, port, one-time token)
to the right backend node instead of proxying traffic itself.

Full wire-format specification: [`../spec/SPEC.md`](../spec/SPEC.md).

Port 2743 is used for both transports:

- **TCP** — client-facing: `AUTH_CONNECT` -> `ROUTE_REDIRECT` / `AUTH_REJECT`.
- **UDP** — backend-node-facing: `NODE_ANNOUNCE` / `NODE_HEARTBEAT` /
  `HEARTBEAT_ACK`, used to keep the server's live node registry current.

## Install

```bash
pip install -e ".[dev]"       # library + test dependencies
pip install -e ".[dev,srv]"   # also pulls in dnspython for SRV discovery
```

## Quick example: user@domain login

This example authenticates to an ERP system, but the same shape applies
to database connection brokering, game server matchmaking, chat
homeserver routing, and other cases where a client needs to be
authenticated once and pointed at the right backend node (see
[`../spec/SPEC.md`](../spec/SPEC.md) section 9 for more deployment
examples).

A user authenticates with `user@domain` + password. The client resolves
which MURX server handles `domain` (default: connect directly to
`murx.<domain>` on port 2743 — an SRV record is an optional override, not
a requirement, per [`../spec/SPEC.md`](../spec/SPEC.md) section 9),
authenticates, and is redirected to whichever backend node is currently
least loaded:

```python
import asyncio
from murx import MurxClient, resolve_murx_server, split_client_id

async def main():
    client_id = "alice@example.com"
    _, domain = split_client_id(client_id)
    host, port = await resolve_murx_server(domain)

    route = await MurxClient.authenticate(
        host=host, port=port,
        client_id=client_id, auth_data=b"hunter2",
    )
    reader, writer = await MurxClient.connect_to_backend(route)
    # `reader`/`writer` are now an authenticated session with the ERP
    # backend node MURX picked for this client.

asyncio.run(main())
```

See [`examples/erp_client.py`](examples/erp_client.py) for a runnable CLI
version, and [`examples/erp_backend_demo.py`](examples/erp_backend_demo.py)
for a minimal end-to-end demo (MURX server + a couple of fake ERP nodes +
the client) you can run locally with no external services.

## Running the demo locally

```bash
python examples/erp_backend_demo.py
```

This starts a `MurxServer` plus two toy "ERP" backend nodes on loopback,
authenticates a client against a built-in credential, and prints the
node it got routed to and the echoed response from that node.

## Tests

```bash
pytest
```

## Status

This is a reference/example implementation for the protocol spec, not a
hardened production gateway. In particular `StaticAuthBackend` and the
in-memory `TokenStore`/`NodeRegistry` are meant for demos and tests —
real deployments should plug in their own `AuthBackend`, a distributed
token store shared with backend nodes, and TLS on the client-facing TCP
listener (see Security Considerations in the spec).

## License

Copyright © 1999 Thomas Kuiper. MIT, see [`../LICENSE`](../LICENSE).
