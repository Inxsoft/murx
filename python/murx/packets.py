"""Wire format for MURX packets, as specified in spec/SPEC.md.

Every packet type here implements ``encode() -> bytes`` and a
``decode(payload: bytes) -> <Type>`` classmethod. Encoding never includes
the TCP length prefix or the UDP authentication trailer; those are
handled by the transport layer (server.py, client.py, node_registry.py).

Decoders raise only ``MurxProtocolError`` on bad input.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Union

PROTOCOL_VERSION = 1
SUPPORTED_VERSIONS = (1,)


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
    HOSTNAME = 0x03
    IPV4 = 0x04
    IPV6 = 0x06


class ReasonCode(IntEnum):
    INVALID_CREDENTIALS = 0x01
    NO_ROUTE = 0x02
    MALFORMED_REQUEST = 0x03
    UNSUPPORTED_VERSION = 0x04
    INTERNAL_ERROR = 0xFF


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MurxProtocolError(message)


def _utf8(raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise MurxProtocolError(f"{what} is not valid UTF-8") from None


def _pack_host(host: str) -> bytes:
    """Encode Address Family + address. Accepts an IPv4/IPv6 literal or a DNS name."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        _require(bool(_HOSTNAME_RE.match(host)), f"invalid hostname {host!r}")
        raw = host.encode("ascii")
        return struct.pack("!BB", AddressFamily.HOSTNAME, len(raw)) + raw
    family = AddressFamily.IPV4 if addr.version == 4 else AddressFamily.IPV6
    return struct.pack("!B", family) + addr.packed


def _unpack_host(body: bytes, offset: int) -> tuple[str, int]:
    """Decode Address Family + address at ``offset``; return (host, new_offset)."""
    _require(len(body) > offset, "truncated: missing address family")
    family = body[offset]
    offset += 1
    if family == AddressFamily.IPV4:
        _require(len(body) >= offset + 4, "truncated IPv4 address")
        return str(ipaddress.IPv4Address(body[offset : offset + 4])), offset + 4
    if family == AddressFamily.IPV6:
        _require(len(body) >= offset + 16, "truncated IPv6 address")
        return str(ipaddress.IPv6Address(body[offset : offset + 16])), offset + 16
    if family == AddressFamily.HOSTNAME:
        _require(len(body) > offset, "truncated hostname length")
        n = body[offset]
        offset += 1
        _require(len(body) >= offset + n, "truncated hostname")
        try:
            host = body[offset : offset + n].decode("ascii")
        except UnicodeDecodeError:
            raise MurxProtocolError("hostname is not ASCII") from None
        _require(bool(_HOSTNAME_RE.match(host)), f"invalid hostname {host!r}")
        return host, offset + n
    raise MurxProtocolError(f"unknown address family {family:#x}")


def _read_header(payload: bytes, expected_opcode: Opcode) -> bytes:
    _require(len(payload) >= 2, "packet shorter than version+opcode header")
    version, opcode = payload[0], payload[1]
    _require(version in SUPPORTED_VERSIONS, f"unsupported protocol version {version}")
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
        client_id = _utf8(body[offset : offset + client_id_len], "client_id")
        offset += client_id_len
        (auth_data_len,) = struct.unpack("!H", body[offset : offset + 2])
        offset += 2
        _require(
            len(body) == offset + auth_data_len,
            "truncated or overlong AUTH_CONNECT: auth_data length mismatch",
        )
        return cls(client_id=client_id, auth_data=body[offset:])


@dataclass(frozen=True)
class RouteRedirect:
    target_host: str
    target_port: int
    token: bytes

    def encode(self) -> bytes:
        _require(0 <= self.target_port <= 0xFFFF, "target_port out of range")
        _require(len(self.token) <= 0xFF, "token too long (max 255 bytes)")
        return (
            struct.pack("!BB", PROTOCOL_VERSION, Opcode.ROUTE_REDIRECT)
            + _pack_host(self.target_host)
            + struct.pack("!HB", self.target_port, len(self.token))
            + self.token
        )

    @classmethod
    def decode(cls, payload: bytes) -> "RouteRedirect":
        body = _read_header(payload, Opcode.ROUTE_REDIRECT)
        target_host, offset = _unpack_host(body, 0)
        _require(len(body) >= offset + 3, "truncated ROUTE_REDIRECT")
        target_port, token_len = struct.unpack("!HB", body[offset : offset + 3])
        offset += 3
        _require(len(body) == offset + token_len, "truncated ROUTE_REDIRECT: token length mismatch")
        return cls(target_host=target_host, target_port=target_port, token=body[offset:])


@dataclass(frozen=True)
class AuthReject:
    reason_code: Union[ReasonCode, int]
    reason_text: str = ""

    def encode(self) -> bytes:
        reason_bytes = self.reason_text.encode("utf-8")
        _require(len(reason_bytes) <= 0xFF, "reason_text too long (max 255 bytes)")
        _require(0 <= int(self.reason_code) <= 0xFF, "reason_code out of range")
        return (
            struct.pack("!BBBB", PROTOCOL_VERSION, Opcode.AUTH_REJECT, self.reason_code, len(reason_bytes))
            + reason_bytes
        )

    @classmethod
    def decode(cls, payload: bytes) -> "AuthReject":
        body = _read_header(payload, Opcode.AUTH_REJECT)
        _require(len(body) >= 2, "truncated AUTH_REJECT")
        code, reason_len = body[0], body[1]
        _require(len(body) == 2 + reason_len, "truncated AUTH_REJECT: reason_text length mismatch")
        try:
            reason_code: Union[ReasonCode, int] = ReasonCode(code)
        except ValueError:
            reason_code = code
        return cls(reason_code=reason_code, reason_text=_utf8(body[2:], "reason_text"))


@dataclass(frozen=True)
class NodeAnnounce:
    node_id: str
    node_host: str
    node_port: int
    capacity: int

    def encode(self) -> bytes:
        node_id_bytes = self.node_id.encode("utf-8")
        _require(len(node_id_bytes) <= 0xFF, "node_id too long (max 255 bytes)")
        _require(0 <= self.node_port <= 0xFFFF, "node_port out of range")
        _require(0 <= self.capacity <= 0xFFFF, "capacity out of range")
        return (
            struct.pack("!BB", PROTOCOL_VERSION, Opcode.NODE_ANNOUNCE)
            + _pack_host(self.node_host)
            + struct.pack("!HHB", self.node_port, self.capacity, len(node_id_bytes))
            + node_id_bytes
        )

    @classmethod
    def decode(cls, payload: bytes) -> "NodeAnnounce":
        body = _read_header(payload, Opcode.NODE_ANNOUNCE)
        node_host, offset = _unpack_host(body, 0)
        _require(len(body) >= offset + 5, "truncated NODE_ANNOUNCE")
        node_port, capacity, node_id_len = struct.unpack("!HHB", body[offset : offset + 5])
        offset += 5
        _require(len(body) == offset + node_id_len, "truncated NODE_ANNOUNCE: node_id length mismatch")
        return cls(
            node_id=_utf8(body[offset:], "node_id"),
            node_host=node_host,
            node_port=node_port,
            capacity=capacity,
        )


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
        _require(len(body) == 1 + node_id_len + 1, "truncated NODE_HEARTBEAT")
        return cls(node_id=_utf8(body[1 : 1 + node_id_len], "node_id"), load=body[1 + node_id_len])


@dataclass(frozen=True)
class HeartbeatAck:
    def encode(self) -> bytes:
        return struct.pack("!BB", PROTOCOL_VERSION, Opcode.HEARTBEAT_ACK)

    @classmethod
    def decode(cls, payload: bytes) -> "HeartbeatAck":
        body = _read_header(payload, Opcode.HEARTBEAT_ACK)
        _require(len(body) == 0, "HEARTBEAT_ACK carries no body")
        return cls()


def peek_opcode(payload: bytes) -> int:
    """Return the opcode byte without fully decoding the packet."""
    _require(len(payload) >= 2, "packet shorter than version+opcode header")
    return payload[1]
