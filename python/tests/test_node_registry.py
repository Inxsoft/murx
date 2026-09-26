import pytest

from murx.errors import NoRouteError
from murx.node_registry import NodeRegistry
from murx.packets import NodeAnnounce, NodeHeartbeat


def test_choose_node_raises_with_empty_registry():
    registry = NodeRegistry(ttl=15.0)
    with pytest.raises(NoRouteError):
        registry.choose_node(now=0.0)


def test_choose_node_picks_least_loaded():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(
        NodeAnnounce(node_id="a", node_ip="10.0.0.1", node_port=1000, capacity=100), now=0.0
    )
    registry.record_announce(
        NodeAnnounce(node_id="b", node_ip="10.0.0.2", node_port=1000, capacity=100), now=0.0
    )
    registry.record_heartbeat(NodeHeartbeat(node_id="a", load=200), now=0.0)
    registry.record_heartbeat(NodeHeartbeat(node_id="b", load=10), now=0.0)

    chosen = registry.choose_node(now=0.0)
    assert chosen.node_id == "b"


def test_choose_node_ties_break_on_capacity():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(
        NodeAnnounce(node_id="low-cap", node_ip="10.0.0.1", node_port=1000, capacity=10), now=0.0
    )
    registry.record_announce(
        NodeAnnounce(node_id="high-cap", node_ip="10.0.0.2", node_port=1000, capacity=999), now=0.0
    )

    chosen = registry.choose_node(now=0.0)
    assert chosen.node_id == "high-cap"


def test_heartbeat_for_unknown_node_is_ignored():
    registry = NodeRegistry(ttl=15.0)
    updated = registry.record_heartbeat(NodeHeartbeat(node_id="ghost", load=1), now=0.0)
    assert updated is False
    with pytest.raises(NoRouteError):
        registry.choose_node(now=0.0)


def test_expired_node_is_dropped():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(
        NodeAnnounce(node_id="a", node_ip="10.0.0.1", node_port=1000, capacity=100), now=0.0
    )
    # still alive just before ttl
    assert len(registry.live_nodes(now=14.9)) == 1
    # expired well past ttl
    with pytest.raises(NoRouteError):
        registry.choose_node(now=20.0)


def test_heartbeat_refreshes_ttl():
    registry = NodeRegistry(ttl=15.0)
    registry.record_announce(
        NodeAnnounce(node_id="a", node_ip="10.0.0.1", node_port=1000, capacity=100), now=0.0
    )
    registry.record_heartbeat(NodeHeartbeat(node_id="a", load=5), now=10.0)
    # would have expired at t=15 from the announce alone, but heartbeat at
    # t=10 pushes the deadline to t=25
    assert len(registry.live_nodes(now=20.0)) == 1


def test_handle_datagram_announce_then_heartbeat():
    registry = NodeRegistry(ttl=15.0)
    announce = NodeAnnounce(node_id="a", node_ip="10.0.0.1", node_port=1000, capacity=100)
    reply = registry.handle_datagram(announce.encode())
    assert reply is not None  # HEARTBEAT_ACK bytes

    heartbeat = NodeHeartbeat(node_id="a", load=7)
    reply = registry.handle_datagram(heartbeat.encode())
    assert reply is not None

    node = registry.choose_node()
    assert node.load == 7


def test_handle_datagram_ignores_malformed_input():
    registry = NodeRegistry(ttl=15.0)
    assert registry.handle_datagram(b"\x01") is None
    assert registry.live_nodes() == []
