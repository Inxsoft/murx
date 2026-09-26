import pytest

from murx.errors import NoRouteError
from murx.keys import TOKEN_KEY_LABEL, derive_key
from murx.tokens import (
    SignedTokenIssuer,
    SignedTokenVerifier,
    TokenClaims,
    decode_token,
    encode_token,
)

SECRET = b"k" * 32
NOW = 1_800_000_000


def issuer(now=NOW):
    return SignedTokenIssuer({"erp-1": SECRET}, ttl=30, clock=lambda: now)


def verifier(now=NOW, node_id="erp-1", secret=SECRET):
    return SignedTokenVerifier(node_id, secret, clock=lambda: now)


def test_issue_and_redeem():
    token = issuer().issue("alice@example.com", "erp-1")
    assert len(token) <= 255
    assert verifier().redeem(token) == "alice@example.com"


def test_token_is_single_use():
    token = issuer().issue("alice@example.com", "erp-1")
    v = verifier()
    assert v.redeem(token) == "alice@example.com"
    assert v.redeem(token) is None


def test_expired_token_rejected():
    token = issuer().issue("alice@example.com", "erp-1")
    assert verifier(now=NOW + 31).redeem(token) is None


def test_token_for_other_node_rejected():
    token = SignedTokenIssuer({"erp-2": SECRET}, clock=lambda: NOW).issue("alice", "erp-2")
    assert verifier(node_id="erp-1").redeem(token) is None


def test_forged_token_rejected():
    forged = SignedTokenIssuer({"erp-1": b"attacker"}, clock=lambda: NOW).issue("mallory", "erp-1")
    assert verifier().redeem(forged) is None


def test_tampered_token_rejected():
    token = bytearray(issuer().issue("alice@example.com", "erp-1"))
    token[-20] ^= 0x01  # inside the client_id
    assert verifier().redeem(bytes(token)) is None


def test_truncated_and_garbage_tokens_rejected():
    token = issuer().issue("alice@example.com", "erp-1")
    v = verifier()
    assert v.redeem(token[:-1]) is None
    assert v.redeem(b"") is None
    assert v.redeem(b"\x00" * 60) is None


def test_issue_for_node_without_key_is_no_route():
    with pytest.raises(NoRouteError):
        issuer().issue("alice", "unknown-node")


def test_used_nonce_cache_is_purged_after_expiry():
    clock = [NOW]
    v = SignedTokenVerifier("erp-1", SECRET, clock=lambda: clock[0])
    v.redeem(issuer().issue("alice", "erp-1"))
    assert len(v._used) == 1
    clock[0] = NOW + 60
    v.redeem(b"")  # malformed tokens do not trigger a purge
    v.redeem(SignedTokenIssuer({"erp-1": SECRET}, clock=lambda: NOW + 60).issue("bob", "erp-1"))
    assert len(v._used) == 1


def test_encode_decode_roundtrip_with_explicit_fields():
    key = derive_key(SECRET, TOKEN_KEY_LABEL)
    claims = TokenClaims(node_id="n", client_id="c", expiry=NOW, nonce=bytes(range(16)))
    assert decode_token(encode_token(claims, key), key) == claims


def test_oversized_identifiers_rejected():
    key = derive_key(SECRET, TOKEN_KEY_LABEL)
    claims = TokenClaims(node_id="n" * 150, client_id="c" * 150, expiry=NOW, nonce=bytes(16))
    with pytest.raises(ValueError):
        encode_token(claims, key)
