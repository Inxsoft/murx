# murx

Reference implementation of **MURX** (Multi-User Resource eXchange), an
authenticated routing gateway protocol. A client authenticates once
against a MURX server, which redirects it (host, port, one-time signed
token) to the right backend node instead of proxying traffic itself.

- Specification: [spec/SPEC.md](https://github.com/Inxsoft/murx/blob/main/spec/SPEC.md) (revision 1.1)
- Conformance test vectors: [spec/test-vectors.md](https://github.com/Inxsoft/murx/blob/main/spec/test-vectors.md)
- Website: [murx.ai](https://murx.ai/)

Pure standard library, Python 3.9+.

Port 2743 is used for both transports:

- **TCP (with TLS)**, client-facing: `AUTH_CONNECT` -> `ROUTE_REDIRECT` / `AUTH_REJECT`.
- **UDP (authenticated)**, backend-facing: `NODE_ANNOUNCE` / `NODE_HEARTBEAT` /
  `HEARTBEAT_ACK`, keeping the server's live node registry current.

## Install

```bash
git clone https://github.com/Inxsoft/murx.git
cd murx/python
pip install -e ".[dev]"       # library + test dependencies
pip install -e ".[dev,srv]"   # also pulls in dnspython for SRV discovery
```

## Try it

**One process, no setup:**

```bash
python examples/erp_backend_demo.py
```

**Separate containers**: a MURX server, two backend nodes, and a client.
The nodes announce their service names, so the client is redirected to a
DNS name:

```bash
docker compose up --build --abort-on-container-exit --exit-code-from client
```

## Client

```python
import asyncio
from murx import MurxClient, resolve_murx_server, split_client_id, tls

async def main():
    client_id = "alice@example.com"
    _, domain = split_client_id(client_id)
    host, port = await resolve_murx_server(domain)   # murx.<domain>:2743 by default
    ctx = tls.client_context()                       # ALPN murx/1, verifies certificates

    route = await MurxClient.authenticate(
        host=host, port=port, client_id=client_id,
        auth_data=b"hunter2", ssl_context=ctx,
    )
    reader, writer = await MurxClient.connect_to_backend(route, ssl_context=ctx)
    # reader/writer is now an authenticated session with the chosen backend

asyncio.run(main())
```

The same shape works for ERP logins, database connection brokering, game
matchmaking, chat homeserver routing, and anything else where a client
should be authenticated once and pointed at the right node.

## Server and backend nodes

Each backend node shares one secret with the MURX server. It is used for
two things: signing tokens and authenticating UDP datagrams.

```python
from murx import (MurxServer, NodeRegistry, NodeRegistryRouter, SignedTokenIssuer,
                  SignedTokenVerifier, TokenGatedServer, BackendAnnouncer, tls)

node_secrets = {"erp-1": SECRET_1, "erp-2": SECRET_2}   # 32+ random bytes each

# MURX server
registry = NodeRegistry(node_secrets=node_secrets)
server = MurxServer(
    auth_backend=my_auth_backend,              # subclass murx.AuthBackend
    router=NodeRegistryRouter(registry),
    node_registry=registry,
    token_issuer=SignedTokenIssuer(node_secrets),
    ssl_context=tls.server_context("cert.pem", "key.pem"),
)

# On backend node erp-1
backend = TokenGatedServer(SignedTokenVerifier("erp-1", SECRET_1), handle_session)
announcer = BackendAnnouncer(node_id="erp-1", node_host="erp-1.internal", node_port=9200,
                             capacity=100, server_host="murx.example.com", secret=SECRET_1)
```

What the implementation enforces:

- **Tokens** are signed with HMAC-SHA256, bound to one node, expire after
  30s, and are single-use. Backends verify them locally, so there is no
  shared token store.
- **UDP datagrams** carry a timestamp and MAC. Unknown nodes, bad MACs,
  clock skew over 30s, and replays are dropped.
- **TLS** on both legs, with ALPN `murx/1`. Redirects can carry DNS names,
  so the client can verify the backend's certificate.
- **Decoders** raise only `MurxProtocolError` on any input. Hypothesis
  fuzz tests check this.

## Tests

```bash
pytest
```

This covers unit tests, end-to-end TLS, forged, expired and replayed
tokens, bad and stale UDP MACs, fuzzing, and the conformance vectors. CI
runs it on Python 3.9–3.13.

## Status

This is a reference implementation, not a hardened production gateway.
`StaticAuthBackend` is for demos and tests only; plug in your own
`AuthBackend`, and add rate limiting in front of it (spec section 8).

## License

Copyright © 1999 Thomas Kuiper. MIT, see [LICENSE](https://github.com/Inxsoft/murx/blob/main/LICENSE).
