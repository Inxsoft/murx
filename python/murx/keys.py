"""Per-node secret handling (docs/SPEC.md section 6.2).

Each backend node shares one secret with the MURX server. Purpose-specific
subkeys are derived from it so the same secret never directly keys two
different MACs.
"""

from __future__ import annotations

import hashlib
import hmac

TOKEN_KEY_LABEL = b"murx token v1"
UDP_KEY_LABEL = b"murx udp v1"
MAC_LEN = 16


def derive_key(secret: bytes, label: bytes) -> bytes:
    return hmac.new(secret, label, hashlib.sha256).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:MAC_LEN]


def mac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(key, data), tag)
