"""Server-side node registry (spec/SPEC.md section 7) and the
backend-node-side helper that keeps a node registered with it.

Every UDP datagram carries an authentication trailer::

    Packet | Timestamp (8, uint64 ms since Unix epoch) | MAC (16)

where MAC = truncated HMAC-SHA256(udp_key, Packet || Timestamp) and
udp_key is derived from the node's shared secret. The registry drops
datagrams with an unknown node, a bad MAC, a timestamp outside the
allowed skew, or a timestamp not strictly newer than the last accepted
one for that node (replay).
"""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .errors import NoRouteError
from .keys import MAC_LEN, UDP_KEY_LABEL, derive_key, mac, mac_ok
from .packets import (
    HeartbeatAck,
    MurxProtocolError,
    NodeAnnounce,
    NodeHeartbeat,
    Opcode,
    peek_opcode,
)

DEFAULT_NODE_TTL = 15.0
DEFAULT_MAX_SKEW_MS = 30_000
TRAILER_LEN = 8 + MAC_LEN


def seal_datagram(packet: bytes, timestamp_ms: int, udp_key: bytes) -> bytes:
    ts = struct.pack("!Q", timestamp_ms)
    return packet + ts + mac(udp_key, packet + ts)


def open_datagram(datagram: bytes) -> tuple[bytes, int, bytes]:
    """Split a datagram into (packet, timestamp_ms, mac) without verifying it."""
    if len(datagram) < TRAILER_LEN + 2:
        raise MurxProtocolError("datagram too short for authentication trailer")
    packet = datagram[:-TRAILER_LEN]
    (ts,) = struct.unpack("!Q", datagram[-TRAILER_LEN:-MAC_LEN])
    return packet, ts, datagram[-MAC_LEN:]


def _wall_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class NodeEntry:
    node_id: str
    host: str
    port: int
    capacity: int
    load: int
    last_seen: float


class NodeRegistry:
    """In-memory table of live backend nodes, fed by authenticated UDP datagrams.

    ``node_secrets`` maps node_id to that node's shared secret. A node with
    no configured secret can never register over UDP.

    Thread-unsafe by design (intended for use from a single asyncio event
    loop, matching MurxServer).
    """

    def __init__(
        self,
        ttl: float = DEFAULT_NODE_TTL,
        node_secrets: Optional[Mapping[str, bytes]] = None,
        max_skew_ms: int = DEFAULT_MAX_SKEW_MS,
        wall_ms: Callable[[], int] = _wall_ms,
    ):
        self.ttl = ttl
        self.max_skew_ms = max_skew_ms
        self._wall_ms = wall_ms
        self._udp_keys = {
            nid: derive_key(secret, UDP_KEY_LABEL) for nid, secret in (node_secrets or {}).items()
        }
        self._last_ts: dict[str, int] = {}
        self._nodes: dict[str, NodeEntry] = {}

    def record_announce(self, announce: NodeAnnounce, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        self._nodes[announce.node_id] = NodeEntry(
            node_id=announce.node_id,
            host=announce.node_host,
            port=announce.node_port,
            capacity=announce.capacity,
            load=0,
            last_seen=now,
        )

    def record_heartbeat(self, heartbeat: NodeHeartbeat, now: Optional[float] = None) -> bool:
        entry = self._nodes.get(heartbeat.node_id)
        if entry is None:
            return False
        entry.load = heartbeat.load
        entry.last_seen = time.monotonic() if now is None else now
        return True

    def purge_expired(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        expired = [nid for nid, e in self._nodes.items() if now - e.last_seen > self.ttl]
        for nid in expired:
            del self._nodes[nid]

    def live_nodes(self, now: Optional[float] = None) -> list[NodeEntry]:
        self.purge_expired(now)
        return list(self._nodes.values())

    def choose_node(self, now: Optional[float] = None) -> NodeEntry:
        """Pick the least-loaded live node, tie-broken by highest capacity."""
        candidates = self.live_nodes(now)
        if not candidates:
            raise NoRouteError("no eligible backend nodes in registry")
        return min(candidates, key=lambda e: (e.load, -e.capacity))

    def handle_datagram(self, data: bytes) -> Optional[bytes]:
        """Verify and apply one inbound UDP datagram.

        Returns a sealed HEARTBEAT_ACK to send back, or None if the datagram
        was rejected. Rejected datagrams are dropped silently.
        """
        try:
            packet, ts, tag = open_datagram(data)
            opcode = peek_opcode(packet)
            if opcode == Opcode.NODE_ANNOUNCE:
                msg = NodeAnnounce.decode(packet)
            elif opcode == Opcode.NODE_HEARTBEAT:
                msg = NodeHeartbeat.decode(packet)
            else:
                return None
        except MurxProtocolError:
            return None

        key = self._udp_keys.get(msg.node_id)
        if key is None or not mac_ok(key, data[: -MAC_LEN], tag):
            return None
        now_ms = self._wall_ms()
        if abs(now_ms - ts) > self.max_skew_ms:
            return None
        if ts <= self._last_ts.get(msg.node_id, -1):
            return None
        self._last_ts[msg.node_id] = ts

        if isinstance(msg, NodeAnnounce):
            self.record_announce(msg)
        else:
            self.record_heartbeat(msg)
        return seal_datagram(HeartbeatAck().encode(), now_ms, key)


class _RegistryDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, registry: NodeRegistry):
        self._registry = registry
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        reply = self._registry.handle_datagram(data)
        if reply is not None and self.transport is not None:
            self.transport.sendto(reply, addr)


async def serve_node_registry(
    registry: NodeRegistry, host: str, port: int
) -> tuple[asyncio.DatagramTransport, _RegistryDatagramProtocol]:
    """Start the UDP listener that feeds ``registry``. Caller owns the transport."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _RegistryDatagramProtocol(registry),
        local_addr=(host, port),
    )
    return transport, protocol


class BackendAnnouncer:
    """Runs on a backend node: periodically announces/heartbeats to a MURX server.

    Example::

        announcer = BackendAnnouncer(
            node_id="erp-1", node_host="erp-1.internal", node_port=9200,
            capacity=100, server_host="murx.example.com", secret=NODE_SECRET,
        )
        await announcer.run(load_fn=current_load, stop_event=stop)
    """

    def __init__(
        self,
        node_id: str,
        node_host: str,
        node_port: int,
        capacity: int,
        server_host: str,
        secret: bytes,
        server_port: int = 2743,
        heartbeat_interval: float = 5.0,
        announce_every: int = 6,
        wall_ms: Callable[[], int] = _wall_ms,
    ):
        self.node_id = node_id
        self.node_host = node_host
        self.node_port = node_port
        self.capacity = capacity
        self.server_host = server_host
        self.server_port = server_port
        self.heartbeat_interval = heartbeat_interval
        self.announce_every = announce_every
        self._udp_key = derive_key(secret, UDP_KEY_LABEL)
        self._wall_ms = wall_ms
        self._last_ts = -1

    def _seal(self, packet: bytes) -> bytes:
        ts = max(self._wall_ms(), self._last_ts + 1)
        self._last_ts = ts
        return seal_datagram(packet, ts, self._udp_key)

    def _announce(self) -> bytes:
        return NodeAnnounce(
            node_id=self.node_id,
            node_host=self.node_host,
            node_port=self.node_port,
            capacity=self.capacity,
        ).encode()

    async def run(
        self,
        load_fn: Callable[[], int] = lambda: 0,
        stop_event: Optional[asyncio.Event] = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(self.server_host, self.server_port),
        )
        stop_event = stop_event or asyncio.Event()
        try:
            transport.sendto(self._seal(self._announce()))
            tick = 0
            while not stop_event.is_set():
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=self.heartbeat_interval)
                except asyncio.TimeoutError:
                    pass
                if stop_event.is_set():
                    break
                tick += 1
                # Re-announce periodically so a restarted server relearns the node.
                if tick % self.announce_every == 0:
                    transport.sendto(self._seal(self._announce()))
                else:
                    heartbeat = NodeHeartbeat(node_id=self.node_id, load=load_fn())
                    transport.sendto(self._seal(heartbeat.encode()))
        finally:
            transport.close()
