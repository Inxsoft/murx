# MURX

**MURX** (Multi-User Resource eXchange) is an authenticated routing
gateway protocol: a client authenticates once against a MURX server,
which computes the right backend node for that client and redirects it
there (IP, port, one-time token) instead of proxying traffic itself.
Registered on port 2743 (TCP for client-facing auth/routing, UDP for the
backend-node registry). Author: Thomas Kuiper.

This is the **public** repository: specification and reference
implementations/sample libraries only.

## Repository layout

| Path | What it is |
|------|------------|
| [`spec/SPEC.md`](spec/SPEC.md) | The protocol specification — wire format, packet types, flows, security considerations. Start here. |
| [`python/`](python/) | Reference implementation (client, server, node registry, sample ERP client/backend, tests). See [`python/README.md`](python/README.md). |
| `LICENSE` | MIT. |

## Quick links

- Read the spec: [`spec/SPEC.md`](spec/SPEC.md)
- Try it: `cd python && pip install -e ".[dev]" && python examples/erp_backend_demo.py`

## License

Copyright © 1999 Thomas Kuiper. MIT, see [`LICENSE`](LICENSE).
