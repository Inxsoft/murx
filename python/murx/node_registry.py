"""Server-side node registry (section 7 of docs/SPEC.md) and the
backend-node-side helper that keeps a node registered with it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .errors import NoRouteError
from .packets import (
    HeartbeatAck,
    MurxProtocolError,
    NodeAnnounce,
    NodeHeartbeat,
    Opcode,
    peek_opcode,
)

DEFAULT_NODE_TTL = 15.0


@dataclass
class NodeEntry:
    node_id: str
    ip: str
    port: int
    capacity: int
    load: int
    last_seen: float


class NodeRegistry:
    """In-memory table of live backend nodes, fed by UDP announce/heartbeat.

    Thread-unsafe by design (intended for use from a single asyncio event
    loop, matching MurxServer).
    """

    def __init__(self, ttl: float = DEFAULT_NODE_TTL):
        self.ttl = ttl
        self._nodes: dict[str, NodeEntry] = {}

    def record_announce(self, announce: NodeAnnounce, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        self._nodes[announce.node_id] = NodeEntry(
            node_id=announce.node_id,
            ip=announce.node_ip,
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
        """Decode one inbound UDP datagram and update the registry.

        Returns the bytes to send back to the sender (a HEARTBEAT_ACK), or
        None if no reply is warranted (malformed datagrams are dropped
        silently, matching UDP's unreliable/no-retry-on-us semantics).
        """
        try:
            opcode = peek_opcode(data)
            if opcode == Opcode.NODE_ANNOUNCE:
                self.record_announce(NodeAnnounce.decode(data))
                return HeartbeatAck().encode()
            if opcode == Opcode.NODE_HEARTBEAT:
                self.record_heartbeat(NodeHeartbeat.decode(data))
                return HeartbeatAck().encode()
        except MurxProtocolError:
            pass
        return None


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
            node_id="erp-1", node_ip="10.0.0.5", node_port=9200,
            capacity=100, server_host="murx.example.com",
        )
        await announcer.run(load_fn=lambda: current_load(), stop_event=stop)
    """

    def __init__(
        self,
        node_id: str,
        node_ip: str,
        node_port: int,
        capacity: int,
        server_host: str,
        server_port: int = 2743,
        heartbeat_interval: float = 5.0,
    ):
        self.node_id = node_id
        self.node_ip = node_ip
        self.node_port = node_port
        self.capacity = capacity
        self.server_host = server_host
        self.server_port = server_port
        self.heartbeat_interval = heartbeat_interval

    async def _send(self, transport: asyncio.DatagramTransport, payload: bytes) -> None:
        transport.sendto(payload)

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
        try:
            announce = NodeAnnounce(
                node_id=self.node_id,
                node_ip=self.node_ip,
                node_port=self.node_port,
                capacity=self.capacity,
            )
            await self._send(transport, announce.encode())
            stop_event = stop_event or asyncio.Event()
            while not stop_event.is_set():
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=self.heartbeat_interval)
                except asyncio.TimeoutError:
                    pass
                if stop_event.is_set():
                    break
                heartbeat = NodeHeartbeat(node_id=self.node_id, load=load_fn())
                await self._send(transport, heartbeat.encode())
        finally:
            transport.close()
