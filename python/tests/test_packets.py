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


@pytest.mark.parametrize("host", ["10.0.0.5", "::1", "erp-1.example.com", "localhost"])
def test_route_redirect_roundtrip(host):
    pkt = RouteRedirect(target_host=host, target_port=9200, token=b"\x01\x02\x03\x04")
    assert RouteRedirect.decode(pkt.encode()) == pkt


def test_route_redirect_hostname_wire_layout():
    encoded = RouteRedirect(target_host="erp-1", target_port=9200, token=b"t").encode()
    # version, opcode, family=0x03, len=5, "erp-1", port, token len, token
    assert encoded == b"\x01\x02\x03\x05erp-1" + b"\x23\xf0" + b"\x01t"


@pytest.mark.parametrize("bad", ["bad host", "-leading.example", "a" * 64 + ".com", ""])
def test_invalid_hostnames_rejected(bad):
    with pytest.raises(MurxProtocolError):
        RouteRedirect(target_host=bad, target_port=1, token=b"").encode()


def test_auth_reject_roundtrip():
    pkt = AuthReject(reason_code=ReasonCode.INVALID_CREDENTIALS, reason_text="bad password")
    assert AuthReject.decode(pkt.encode()) == pkt


def test_auth_reject_empty_reason():
    decoded = AuthReject.decode(AuthReject(reason_code=ReasonCode.NO_ROUTE).encode())
    assert decoded.reason_code == ReasonCode.NO_ROUTE
    assert decoded.reason_text == ""


def test_auth_reject_unknown_code_is_kept_as_int():
    decoded = AuthReject.decode(b"\x01\x03\x77\x00")
    assert decoded.reason_code == 0x77


@pytest.mark.parametrize("host", ["192.168.1.10", "2001:db8::1", "erp-1.internal"])
def test_node_announce_roundtrip(host):
    pkt = NodeAnnounce(node_id="erp-1", node_host=host, node_port=9200, capacity=100)
    assert NodeAnnounce.decode(pkt.encode()) == pkt


def test_node_heartbeat_roundtrip():
    pkt = NodeHeartbeat(node_id="erp-1", load=42)
    assert NodeHeartbeat.decode(pkt.encode()) == pkt


def test_heartbeat_ack_roundtrip():
    assert HeartbeatAck.decode(HeartbeatAck().encode()) == HeartbeatAck()


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


def test_invalid_utf8_raises_protocol_error():
    with pytest.raises(MurxProtocolError):
        AuthConnect.decode(b"\x01\x01\x01\xff\x00\x00")


def test_peek_opcode_on_short_input():
    with pytest.raises(MurxProtocolError):
        peek_opcode(b"\x01")
