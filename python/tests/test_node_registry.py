import pytest

from murx.errors import NoRouteError
from murx.keys import UDP_KEY_LABEL, derive_key
from murx.node_registry import NodeRegistry, open_datagram, seal_datagram
from murx.packets import HeartbeatAck, NodeAnnounce, NodeHeartbeat

SECRET = b"s" * 32
UDP_KEY = derive_key(SECRET, UDP_KEY_LABEL)
NOW_MS = 1_800_000_000_000


def announce(node_id="a", host="10.0.0.1", capacity=100):
    return NodeAnnounce(node_id=node_id, node_host=host, node_port=1000, capacity=capacity)


def keyed_registry(**kw):
    return NodeRegistry(node_secrets={"a": SECRET}, wall_ms=lambda: NOW_MS, **kw)


def test_choose_node_raises_with_empty_registry():
    with pytest.raises(NoRouteError):
        NodeRegistry().choose_node(now=0.0)


def test_choose_node_picks_least_loaded():
    registry = NodeRegistry()
    registry.record_announce(announce("a"), now=0.0)
    registry.record_announce(announce("b", "10.0.0.2"), now=0.0)
    registry.record_heartbeat(NodeHeartbeat(node_id="a", load=200), now=0.0)
    registry.record_heartbeat(NodeHeartbeat(node_id="b", load=10), now=0.0)
    assert registry.choose_node(now=0.0).node_id == "b"


def test_choose_node_ties_break_on_capacity():
    registry = NodeRegistry()
    registry.record_announce(announce("low", capacity=10), now=0.0)
    registry.record_announce(announce("high", capacity=999), now=0.0)
    assert registry.choose_node(now=0.0).node_id == "high"


def test_heartbeat_for_unknown_node_is_ignored():
    registry = NodeRegistry()
    assert registry.record_heartbeat(NodeHeartbeat(node_id="ghost", load=1), now=0.0) is False


def test_expired_node_is_dropped():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(announce(), now=0.0)
    assert len(registry.live_nodes(now=14.9)) == 1
    with pytest.raises(NoRouteError):
        registry.choose_node(now=20.0)


def test_heartbeat_refreshes_ttl():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(announce(), now=0.0)
    registry.record_heartbeat(NodeHeartbeat(node_id="a", load=5), now=10.0)
    assert len(registry.live_nodes(now=20.0)) == 1


def test_sealed_announce_then_heartbeat_accepted():
    registry = keyed_registry()
    reply = registry.handle_datagram(seal_datagram(announce().encode(), NOW_MS, UDP_KEY))
    assert reply is not None
    packet, _, _ = open_datagram(reply)
    assert HeartbeatAck.decode(packet) == HeartbeatAck()

    hb = NodeHeartbeat(node_id="a", load=7).encode()
    assert registry.handle_datagram(seal_datagram(hb, NOW_MS + 1, UDP_KEY)) is not None
    assert registry.choose_node().load == 7


def test_unsealed_datagram_rejected():
    registry = keyed_registry()
    assert registry.handle_datagram(announce().encode()) is None
    assert registry.live_nodes() == []


def test_bad_mac_rejected():
    registry = keyed_registry()
    forged = seal_datagram(announce().encode(), NOW_MS, derive_key(b"wrong", UDP_KEY_LABEL))
    assert registry.handle_datagram(forged) is None
    assert registry.live_nodes() == []


def test_tampered_packet_rejected():
    registry = keyed_registry()
    sealed = bytearray(seal_datagram(announce().encode(), NOW_MS, UDP_KEY))
    sealed[5] ^= 0x01  # flip a bit in the node address
    assert registry.handle_datagram(bytes(sealed)) is None


def test_unknown_node_rejected_even_with_valid_format():
    registry = keyed_registry()
    other = announce(node_id="intruder").encode()
    assert registry.handle_datagram(seal_datagram(other, NOW_MS, UDP_KEY)) is None


def test_stale_timestamp_rejected():
    registry = keyed_registry()
    old = seal_datagram(announce().encode(), NOW_MS - 31_000, UDP_KEY)
    assert registry.handle_datagram(old) is None
    future = seal_datagram(announce().encode(), NOW_MS + 31_000, UDP_KEY)
    assert registry.handle_datagram(future) is None


def test_replayed_datagram_rejected():
    registry = keyed_registry()
    sealed = seal_datagram(announce().encode(), NOW_MS, UDP_KEY)
    assert registry.handle_datagram(sealed) is not None
    assert registry.handle_datagram(sealed) is None


def test_registry_without_secrets_accepts_nothing():
    registry = NodeRegistry(wall_ms=lambda: NOW_MS)
    assert registry.handle_datagram(seal_datagram(announce().encode(), NOW_MS, UDP_KEY)) is None


def test_garbage_datagram_ignored():
    assert keyed_registry().handle_datagram(b"\x01") is None
