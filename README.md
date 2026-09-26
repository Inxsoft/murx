# MURX

**MURX** (Multi-User Resource eXchange) is an authenticated routing
gateway protocol. A client authenticates once against a MURX server,
which picks the right backend node for that client and redirects it
there (host, port, one-time signed token) instead of proxying traffic
itself. Registered on port 2743: TCP (with TLS) for client-facing auth
and routing, authenticated UDP for the backend-node registry. Author:
Thomas Kuiper.

This is the **public** repository: the specification, conformance test
vectors, reference implementation and tools. Website: [murx.ai](https://murx.ai/).

## Repository layout

| Path | What it is |
|------|------------|
| [`spec/SPEC.md`](spec/SPEC.md) | The protocol specification (revision 1.1): wire format, tokens, node registry, security considerations. Start here. |
| [`spec/test-vectors.md`](spec/test-vectors.md) | Byte-exact encodings of every packet type, signed token and sealed datagram, for checking any implementation. |
| [`python/`](python/) | Python reference implementation: client, server, node registry, TLS, examples, Docker demo, tests. See [`python/README.md`](python/README.md). |
| [`tools/wireshark/`](tools/wireshark/) | Wireshark/tshark dissector and a sample-capture generator. |
| `LICENSE` | MIT. |

## Quick start

```bash
cd python
pip install -e ".[dev]"
python examples/erp_backend_demo.py          # everything in one process
docker compose up --build --abort-on-container-exit --exit-code-from client
pytest                                       # the full suite
```

## License

Copyright © 1999 Thomas Kuiper. MIT, see [`LICENSE`](LICENSE).
