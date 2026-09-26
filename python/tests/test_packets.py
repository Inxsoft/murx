import pytest

from murx.packets import (
    AuthConnect,
    AuthReject,
    HeartbeatAck,
    MurxProtocolError,
    NodeAnnounce,
    NodeHeartbeat,
    Opcode,
    ReasonCode,
    RouteRedirect,
    peek_opcode,
)


def test_auth_connect_roundtrip():
    pkt = AuthConnect(client_id="alice@example.com", auth_data=b"hunter2")
    encoded = pkt.encode()
    assert peek_opcode(encoded) == Opcode.AUTH_CONNECT
    assert AuthConnect.decode(encoded) == pkt


def test_auth_connect_empty_auth_data():
    pkt = AuthConnect(client_id="bob@example.com", auth_data=b"")
    assert AuthConnect.decode(pkt.encode()) == pkt


def test_route_redirect_roundtrip_ipv4():
    pkt = RouteRedirect(target_ip="10.0.0.5", target_port=9200, token=b"\x01\x02\x03\x04")
    encoded = pkt.encode()
    assert peek_opcode(encoded) == Opcode.ROUTE_REDIRECT
    assert RouteRedirect.decode(encoded) == pkt


def test_route_redirect_roundtrip_ipv6():
    pkt = RouteRedirect(target_ip="::1", target_port=443, token=b"tok")
    assert RouteRedirect.decode(pkt.encode()) == pkt


def test_auth_reject_roundtrip():
    pkt = AuthReject(reason_code=ReasonCode.INVALID_CREDENTIALS, reason_text="bad password")
    assert AuthReject.decode(pkt.encode()) == pkt


def test_auth_reject_empty_reason():
    pkt = AuthReject(reason_code=ReasonCode.NO_ROUTE)
    decoded = AuthReject.decode(pkt.encode())
    assert decoded.reason_code == ReasonCode.NO_ROUTE
    assert decoded.reason_text == ""


def test_node_announce_roundtrip():
    pkt = NodeAnnounce(node_id="erp-1", node_ip="192.168.1.10", node_port=9200, capacity=100)
    assert NodeAnnounce.decode(pkt.encode()) == pkt


def test_node_heartbeat_roundtrip():
    pkt = NodeHeartbeat(node_id="erp-1", load=42)
    assert NodeHeartbeat.decode(pkt.encode()) == pkt


def test_heartbeat_ack_roundtrip():
    pkt = HeartbeatAck()
    assert HeartbeatAck.decode(pkt.encode()) == pkt


def test_decode_rejects_wrong_version():
    encoded = bytearray(AuthConnect(client_id="a", auth_data=b"x").encode())
    encoded[0] = 99
    with pytest.raises(MurxProtocolError):
        AuthConnect.decode(bytes(encoded))


def test_decode_rejects_truncated_packet():
    encoded = AuthConnect(client_id="alice@example.com", auth_data=b"hunter2").encode()
    with pytest.raises(MurxProtocolError):
        AuthConnect.decode(encoded[:-2])


def test_decode_rejects_wrong_opcode():
    encoded = AuthConnect(client_id="a", auth_data=b"x").encode()
    with pytest.raises(MurxProtocolError):
        RouteRedirect.decode(encoded)


def test_peek_opcode_on_empty_bytes():
    with pytest.raises(MurxProtocolError):
        peek_opcode(b"\x01")
