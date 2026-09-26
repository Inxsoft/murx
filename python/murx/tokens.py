"""Signed, self-verifying MURX tokens (docs/SPEC.md section 6.1).

Token layout (all integers big-endian)::

    Version (1) | Expiry (8, unix seconds) | Nonce (16)
    | Node ID Length (1) | Node ID | Client ID Length (1) | Client ID
    | MAC (16, truncated HMAC-SHA256 over every preceding byte)

The backend node verifies the MAC with its own derived token key, so no
token store has to be shared between the MURX server and the backends.
"""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .errors import NoRouteError
from .keys import MAC_LEN, TOKEN_KEY_LABEL, derive_key, mac, mac_ok

TOKEN_VERSION = 1
NONCE_LEN = 16
MAX_TOKEN_LEN = 255
DEFAULT_TOKEN_TTL = 30


@dataclass(frozen=True)
class TokenClaims:
    node_id: str
    client_id: str
    expiry: int
    nonce: bytes


def encode_token(claims: TokenClaims, token_key: bytes) -> bytes:
    node_id = claims.node_id.encode("utf-8")
    client_id = claims.client_id.encode("utf-8")
    if len(claims.nonce) != NONCE_LEN:
        raise ValueError("nonce must be 16 bytes")
    body = (
        struct.pack("!BQ", TOKEN_VERSION, claims.expiry)
        + claims.nonce
        + struct.pack("!B", len(node_id))
        + node_id
        + struct.pack("!B", len(client_id))
        + client_id
    )
    token = body + mac(token_key, body)
    if len(token) > MAX_TOKEN_LEN:
        raise ValueError("node_id + client_id too long to fit in a 255-byte token")
    return token


def decode_token(token: bytes, token_key: bytes) -> Optional[TokenClaims]:
    """Return the claims if the token is well-formed and the MAC checks out."""
    if len(token) < 1 + 8 + NONCE_LEN + 1 + 1 + MAC_LEN:
        return None
    body, tag = token[:-MAC_LEN], token[-MAC_LEN:]
    if not mac_ok(token_key, body, tag):
        return None
    version, expiry = struct.unpack("!BQ", body[:9])
    if version != TOKEN_VERSION:
        return None
    nonce = body[9 : 9 + NONCE_LEN]
    offset = 9 + NONCE_LEN
    nid_len = body[offset]
    offset += 1
    if len(body) < offset + nid_len + 1:
        return None
    node_id = body[offset : offset + nid_len]
    offset += nid_len
    cid_len = body[offset]
    offset += 1
    if len(body) != offset + cid_len:
        return None
    client_id = body[offset : offset + cid_len]
    try:
        return TokenClaims(
            node_id=node_id.decode("utf-8"),
            client_id=client_id.decode("utf-8"),
            expiry=expiry,
            nonce=nonce,
        )
    except UnicodeDecodeError:
        return None


class SignedTokenIssuer:
    """MURX-server side: mints a token for the node a client is routed to."""

    def __init__(
        self,
        node_secrets: Mapping[str, bytes],
        ttl: int = DEFAULT_TOKEN_TTL,
        clock: Callable[[], float] = time.time,
    ):
        self._keys = {nid: derive_key(s, TOKEN_KEY_LABEL) for nid, s in node_secrets.items()}
        self.ttl = ttl
        self._clock = clock

    def issue(self, client_id: str, node_id: Optional[str] = None) -> bytes:
        key = self._keys.get(node_id) if node_id is not None else None
        if key is None:
            raise NoRouteError(f"no token key configured for node {node_id!r}")
        claims = TokenClaims(
            node_id=node_id,
            client_id=client_id,
            expiry=int(self._clock()) + self.ttl,
            nonce=secrets.token_bytes(NONCE_LEN),
        )
        return encode_token(claims, key)


class SignedTokenVerifier:
    """Backend-node side: verifies tokens and enforces single use."""

    def __init__(self, node_id: str, node_secret: bytes, clock: Callable[[], float] = time.time):
        self.node_id = node_id
        self._key = derive_key(node_secret, TOKEN_KEY_LABEL)
        self._clock = clock
        self._used: dict[bytes, int] = {}

    def redeem(self, token: bytes) -> Optional[str]:
        """Return the client_id for a valid, unexpired, unused token for this node."""
        claims = decode_token(token, self._key)
        if claims is None or claims.node_id != self.node_id:
            return None
        now = int(self._clock())
        if now > claims.expiry:
            return None
        self._purge(now)
        if claims.nonce in self._used:
            return None
        self._used[claims.nonce] = claims.expiry
        return claims.client_id

    def _purge(self, now: int) -> None:
        expired = [n for n, exp in self._used.items() if exp < now]
        for n in expired:
            del self._used[n]
