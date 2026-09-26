"""Check the implementation against spec/test-vectors.md."""

import json
import re
import struct
from pathlib import Path

import pytest

from murx import packets
from murx.keys import TOKEN_KEY_LABEL, UDP_KEY_LABEL, derive_key
from murx.node_registry import seal_datagram
from murx.tokens import TokenClaims, decode_token, encode_token

VECTORS_FILE = Path(__file__).resolve().parents[2] / "spec" / "test-vectors.md"
VECTORS = [
    json.loads(block)
    for block in re.findall(r"```json\n(.*?)\n```", VECTORS_FILE.read_text(encoding="utf-8"), re.S)
]
PACKET_TYPES = {
    "AuthConnect",
    "RouteRedirect",
    "AuthReject",
    "NodeAnnounce",
    "NodeHeartbeat",
    "HeartbeatAck",
}


def _kwargs(fields):
    return {
        (k[:-4] if k.endswith("_hex") else k): (bytes.fromhex(v) if k.endswith("_hex") else v)
        for k, v in fields.items()
    }


def test_vector_file_is_complete():
    assert {v["type"] for v in VECTORS} >= PACKET_TYPES | {
        "TcpFrame",
        "KeyDerivation",
        "SignedToken",
        "SealedDatagram",
    }


@pytest.mark.parametrize("vec", [v for v in VECTORS if v["type"] in PACKET_TYPES], ids=lambda v: v["name"])
def test_packet_vector(vec):
    cls = getattr(packets, vec["type"])
    expected = bytes.fromhex(vec["hex"])
    obj = cls(**_kwargs(vec["fields"]))
    assert obj.encode() == expected
    assert cls.decode(expected) == obj


def _one(kind):
    return next(v for v in VECTORS if v["type"] == kind)


def test_tcp_frame_vector():
    vec = _one("TcpFrame")
    payload = bytes.fromhex(vec["fields"]["payload_hex"])
    assert (struct.pack("!H", len(payload)) + payload).hex() == vec["hex"]


def test_key_derivation_vector():
    f = _one("KeyDerivation")["fields"]
    secret = bytes.fromhex(f["node_secret_hex"])
    assert derive_key(secret, TOKEN_KEY_LABEL).hex() == f["token_key_hex"]
    assert derive_key(secret, UDP_KEY_LABEL).hex() == f["udp_key_hex"]


def test_signed_token_vector():
    vec = _one("SignedToken")
    f = vec["fields"]
    key = derive_key(bytes.fromhex(f["node_secret_hex"]), TOKEN_KEY_LABEL)
    claims = TokenClaims(
        node_id=f["node_id"],
        client_id=f["client_id"],
        expiry=f["expiry"],
        nonce=bytes.fromhex(f["nonce_hex"]),
    )
    assert encode_token(claims, key).hex() == vec["hex"]
    assert decode_token(bytes.fromhex(vec["hex"]), key) == claims


def test_sealed_datagram_vector():
    vec = _one("SealedDatagram")
    f = vec["fields"]
    key = derive_key(bytes.fromhex(f["node_secret_hex"]), UDP_KEY_LABEL)
    sealed = seal_datagram(bytes.fromhex(f["packet_hex"]), f["timestamp_ms"], key)
    assert sealed.hex() == vec["hex"]
