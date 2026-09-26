"""Wire format for MURX packets, as specified in docs/SPEC.md.

Every packet type here implements ``encode() -> bytes`` and a
``decode(payload: bytes) -> <Type>`` classmethod. Encoding never includes
the TCP length prefix or UDP datagram boundary -- that framing is handled
by the transport layer in server.py / client.py / node_registry.py.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from enum import IntEnum

PROTOCOL_VERSION = 1


class MurxProtocolError(ValueError):
    """Raised when a packet cannot be decoded (malformed / truncated)."""


class Opcode(IntEnum):
    AUTH_CONNECT = 0x01
    ROUTE_REDIRECT = 0x02
    AUTH_REJECT = 0x03
    NODE_ANNOUNCE = 0x10
    NODE_HEARTBEAT = 0x11
    HEARTBEAT_ACK = 0x12


class AddressFamily(IntEnum):
    IPV4 = 0x04
    IPV6 = 0x06


class ReasonCode(IntEnum):
    INVALID_CREDENTIALS = 0x01
    NO_ROUTE = 0x02
    MALFORMED_REQUEST = 0x03
    INTERNAL_ERROR = 0xFF


def _family_for(ip: str) -> AddressFamily:
    addr = ipaddress.ip_address(ip)
    return AddressFamily.IPV4 if addr.version == 4 else AddressFamily.IPV6


def _pack_ip(ip: str, family: AddressFamily) -> bytes:
    addr = ipaddress.ip_address(ip)
    packed = addr.packed
    expected = 4 if family == AddressFamily.IPV4 else 16
    if len(packed) != expected:
        raise MurxProtocolError(
            f"address {ip!r} does not match declared family {family!r}"
        )
    return packed


def _unpack_ip(family: int, raw: bytes) -> str:
    if family == AddressFamily.IPV4:
        return str(ipaddress.IPv4Address(raw))
    if family == AddressFamily.IPV6:
        return str(ipaddress.IPv6Address(raw))
    raise MurxProtocolError(f"unknown address family {family:#x}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MurxProtocolError(message)


def _read_header(payload: bytes, expected_opcode: Opcode):
    _require(len(payload) >= 2, "packet shorter than version+opcode header")
    version, opcode = payload[0], payload[1]
    _require(version == PROTOCOL_VERSION, f"unsupported protocol version {version}")
    _require(
        opcode == expected_opcode,
        f"expected opcode {expected_opcode!r}, got {opcode:#x}",
    )
    return payload[2:]


@dataclass(frozen=True)
class AuthConnect:
    client_id: str
    auth_data: bytes

    def encode(self) -> bytes:
        client_id_bytes = self.client_id.encode("utf-8")
        _require(len(client_id_bytes) <= 0xFF, "client_id too long (max 255 bytes)")
        _require(len(self.auth_data) <= 0xFFFF, "auth_data too long (max 65535 bytes)")
        return (
            struct.pack("!BBB", PROTOCOL_VERSION, Opcode.AUTH_CONNECT, len(client_id_bytes))
            + client_id_bytes
            + struct.pack("!H", len(self.auth_data))
            + self.auth_data
        )

    @classmethod
    def decode(cls, payload: bytes) -> "AuthConnect":
        body = _read_header(payload, Opcode.AUTH_CONNECT)
        _require(len(body) >= 1, "truncated AUTH_CONNECT: missing client_id length")
        client_id_len = body[0]
        offset = 1
        _require(
            len(body) >= offset + client_id_len + 2,
            "truncated AUTH_CONNECT: client_id/auth_data missing",
        )
        client_id = body[offset : offset + client_id_len].decode("utf-8")
        offset += client_id_len
        (auth_data_len,) = struct.unpack("!H", body[offset : offset + 2])
        offset += 2
        _require(
            len(body) == offset + auth_data_len,
            "truncated or overlong AUTH_CONNECT: auth_data length mismatch",
        )
        auth_data = body[offset : offset + auth_data_len]
        return cls(client_id=client_id, auth_data=auth_data)


@dataclass(frozen=True)
class RouteRedirect:
    target_ip: str
    target_port: int
    token: bytes

    def encode(self) -> bytes:
        family = _family_for(self.target_ip)
        ip_bytes = _pack_ip(self.target_ip, family)
        _require(0 <= self.target_port <= 0xFFFF, "target_port out of range")
        _require(len(self.token) <= 0xFF, "token too long (max 255 bytes)")
        return (
            struct.pack("!BBB", PROTOCOL_VERSION, Opcode.ROUTE_REDIRECT, family)
            + ip_bytes
            + struct.pack("!H", self.target_port)
            + struct.pack("!B", len(self.token))
            + self.token
        )

    @classmethod
    def decode(cls, payload: bytes) -> "RouteRedirect":
        body = _read_header(payload, Opcode.ROUTE_REDIRECT)
        _require(len(body) >= 1, "truncated ROUTE_REDIRECT: missing address family")
        family = body[0]
        ip_len = 4 if family == AddressFamily.IPV4 else 16 if family == AddressFamily.IPV6 else None
        _require(ip_len is not None, f"unknown address family {family:#x}")
        offset = 1
        _require(len(body) >= offset + ip_len + 3, "truncated ROUTE_REDIRECT")
        target_ip = _unpack_ip(family, body[offset : offset + ip_len])
        offset += ip_len
        (target_port,) = struct.unpack("!H", body[offset : offset + 2])
        offset += 2
        token_len = body[offset]
        offset += 1
        _require(len(body) == offset + token_len, "truncated ROUTE_REDIRECT: token length mismatch")
        token = body[offset : offset + token_len]
        return cls(target_ip=target_ip, target_port=target_port, token=token)


@dataclass(frozen=True)
class AuthReject:
    reason_code: ReasonCode
    reason_text: str = ""

    def encode(self) -> bytes:
        reason_bytes = self.reason_text.encode("utf-8")
        _require(len(reason_bytes) <= 0xFF, "reason_text too long (max 255 bytes)")
        return (
            struct.pack(
                "!BBBB",
                PROTOCOL_VERSION,
                Opcode.AUTH_REJECT,
                self.reason_code,
                len(reason_bytes),
            )
            + reason_bytes
        )

    @classmethod
    def decode(cls, payload: bytes) -> "AuthReject":
        body = _read_header(payload, Opcode.AUTH_REJECT)
        _require(len(body) >= 2, "truncated AUTH_REJECT")
        reason_code, reason_len = body[0], body[1]
        _require(len(body) == 2 + reason_len, "truncated AUTH_REJECT: reason_text length mismatch")
        reason_text = body[2 : 2 + reason_len].decode("utf-8")
        return cls(reason_code=ReasonCode(reason_code), reason_text=reason_text)


@dataclass(frozen=True)
class NodeAnnounce:
    node_id: str
    node_ip: str
    node_port: int
    capacity: int

    def encode(self) -> bytes:
        family = _family_for(self.node_ip)
        ip_bytes = _pack_ip(self.node_ip, family)
        node_id_bytes = self.node_id.encode("utf-8")
        _require(len(node_id_bytes) <= 0xFF, "node_id too long (max 255 bytes)")
        _require(0 <= self.node_port <= 0xFFFF, "node_port out of range")
        _require(0 <= self.capacity <= 0xFFFF, "capacity out of range")
        return (
            struct.pack("!BBB", PROTOCOL_VERSION, Opcode.NODE_ANNOUNCE, family)
            + ip_bytes
            + struct.pack("!HH", self.node_port, self.capacity)
            + struct.pack("!B", len(node_id_bytes))
            + node_id_bytes
        )

    @classmethod
    def decode(cls, payload: bytes) -> "NodeAnnounce":
        body = _read_header(payload, Opcode.NODE_ANNOUNCE)
        _require(len(body) >= 1, "truncated NODE_ANNOUNCE: missing address family")
        family = body[0]
        ip_len = 4 if family == AddressFamily.IPV4 else 16 if family == AddressFamily.IPV6 else None
        _require(ip_len is not None, f"unknown address family {family:#x}")
        offset = 1
        _require(len(body) >= offset + ip_len + 5, "truncated NODE_ANNOUNCE")
        node_ip = _unpack_ip(family, body[offset : offset + ip_len])
        offset += ip_len
        node_port, capacity = struct.unpack("!HH", body[offset : offset + 4])
        offset += 4
        node_id_len = body[offset]
        offset += 1
        _require(len(body) == offset + node_id_len, "truncated NODE_ANNOUNCE: node_id length mismatch")
        node_id = body[offset : offset + node_id_len].decode("utf-8")
        return cls(node_id=node_id, node_ip=node_ip, node_port=node_port, capacity=capacity)


@dataclass(frozen=True)
class NodeHeartbeat:
    node_id: str
    load: int

    def encode(self) -> bytes:
        node_id_bytes = self.node_id.encode("utf-8")
        _require(len(node_id_bytes) <= 0xFF, "node_id too long (max 255 bytes)")
        _require(0 <= self.load <= 0xFF, "load out of range")
        return (
            struct.pack("!BBB", PROTOCOL_VERSION, Opcode.NODE_HEARTBEAT, len(node_id_bytes))
            + node_id_bytes
            + struct.pack("!B", self.load)
        )

    @classmethod
    def decode(cls, payload: bytes) -> "NodeHeartbeat":
        body = _read_header(payload, Opcode.NODE_HEARTBEAT)
        _require(len(body) >= 1, "truncated NODE_HEARTBEAT: missing node_id length")
        node_id_len = body[0]
        offset = 1
        _require(len(body) == offset + node_id_len + 1, "truncated NODE_HEARTBEAT")
        node_id = body[offset : offset + node_id_len].decode("utf-8")
        offset += node_id_len
        load = body[offset]
        return cls(node_id=node_id, load=load)


@dataclass(frozen=True)
class HeartbeatAck:
    def encode(self) -> bytes:
        return struct.pack("!BB", PROTOCOL_VERSION, Opcode.HEARTBEAT_ACK)

    @classmethod
    def decode(cls, payload: bytes) -> "HeartbeatAck":
        _read_header(payload, Opcode.HEARTBEAT_ACK)
        return cls()


def peek_opcode(payload: bytes) -> int:
    """Return the opcode byte without fully decoding the packet."""
    _require(len(payload) >= 2, "packet shorter than version+opcode header")
    return payload[1]
