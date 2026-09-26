"""Property tests: decoders must never crash with anything but MurxProtocolError."""

from hypothesis import given, settings
from hypothesis import strategies as st

from murx.keys import UDP_KEY_LABEL, derive_key
from murx.node_registry import NodeRegistry
from murx.packets import (
    AuthConnect,
    AuthReject,
    HeartbeatAck,
    MurxProtocolError,
    NodeAnnounce,
    NodeHeartbeat,
    RouteRedirect,
)
from murx.tokens import SignedTokenVerifier

DECODERS = [AuthConnect, RouteRedirect, AuthReject, NodeAnnounce, NodeHeartbeat, HeartbeatAck]

hostnames = st.from_regex(r"\A[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?){0,3}\Z")
hosts = st.one_of(
    st.ip_addresses(v=4).map(str),
    st.ip_addresses(v=6).map(str),
    hostnames,
)
ids = st.text(min_size=0, max_size=60).filter(lambda s: len(s.encode()) <= 255)
ports = st.integers(0, 0xFFFF)


@settings(max_examples=500)
@given(st.binary(max_size=300))
def test_decoders_only_raise_protocol_error(data):
    for cls in DECODERS:
        for payload in (data, b"\x01" + data, b"\x01" + bytes([data[0] if data else 0]) + data):
            try:
                cls.decode(payload)
            except MurxProtocolError:
                pass


@settings(max_examples=300)
@given(st.binary(max_size=300))
def test_registry_never_crashes_on_garbage(data):
    registry = NodeRegistry(node_secrets={"a": b"secret"})
    assert registry.handle_datagram(data) is None


@settings(max_examples=300)
@given(st.binary(max_size=300))
def test_token_verifier_never_crashes_on_garbage(data):
    assert SignedTokenVerifier("a", b"secret").redeem(data) is None


@given(ids, st.binary(max_size=500))
def test_auth_connect_roundtrip(client_id, auth_data):
    pkt = AuthConnect(client_id=client_id, auth_data=auth_data)
    assert AuthConnect.decode(pkt.encode()) == pkt


@given(hosts, ports, st.binary(max_size=255))
def test_route_redirect_roundtrip(host, port, token):
    pkt = RouteRedirect(target_host=host, target_port=port, token=token)
    decoded = RouteRedirect.decode(pkt.encode())
    assert decoded.target_port == port and decoded.token == token


@given(ids, hosts, ports, st.integers(0, 0xFFFF))
def test_node_announce_roundtrip(node_id, host, port, capacity):
    pkt = NodeAnnounce(node_id=node_id, node_host=host, node_port=port, capacity=capacity)
    assert NodeAnnounce.decode(pkt.encode()).node_id == node_id


@given(st.integers(0, 0xFF), st.text(max_size=80).filter(lambda s: len(s.encode()) <= 255))
def test_auth_reject_roundtrip(code, text):
    decoded = AuthReject.decode(AuthReject(reason_code=code, reason_text=text).encode())
    assert int(decoded.reason_code) == code and decoded.reason_text == text


@given(ids, st.integers(0, 0xFF))
def test_node_heartbeat_roundtrip(node_id, load):
    pkt = NodeHeartbeat(node_id=node_id, load=load)
    assert NodeHeartbeat.decode(pkt.encode()) == pkt


def test_udp_key_label_is_distinct():
    assert derive_key(b"s", UDP_KEY_LABEL) != derive_key(b"s", b"murx token v1")
