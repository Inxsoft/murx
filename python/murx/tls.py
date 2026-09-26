"""TLS helpers that set the MURX ALPN identifier (spec/SPEC.md section 3.3)."""

from __future__ import annotations

import ssl
from typing import Optional

ALPN = "murx/1"


def server_context(certfile: str, keyfile: Optional[str] = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    ctx.set_alpn_protocols([ALPN])
    return ctx


def client_context(cafile: Optional[str] = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols([ALPN])
    return ctx
