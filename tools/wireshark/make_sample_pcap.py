#!/usr/bin/env python3
"""Write a sample capture of a full MURX exchange, for trying the dissector.

    python tools/wireshark/make_sample_pcap.py murx-sample.pcap
    tshark -X lua_script:tools/wireshark/murx.lua -r murx-sample.pcap

Uses the reference implementation (python/) to build real packets. Frames
are raw IPv4 (pcap link type 101), so no Ethernet header is needed.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from murx.keys import UDP_KEY_LABEL, derive_key  # noqa: E402
from murx.node_registry import seal_datagram  # noqa: E402
from murx.packets import (  # noqa: E402
    AuthConnect,
    AuthReject,
    HeartbeatAck,
    NodeAnnounce,
    NodeHeartbeat,
    ReasonCode,
    RouteRedirect,
)
from murx.tokens import SignedTokenIssuer  # noqa: E402

SERVER, CLIENT, NODE = "10.0.0.1", "10.0.0.2", "10.0.0.5"
T0 = 1_800_000_000
SECRET = bytes(range(32))


def ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0, ip(src), ip(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 6, len(seg))
    seg = seg[:16] + struct.pack("!H", checksum(pseudo + seg)) + seg[18:]
    return ipv4(src, dst, 6, seg)


def udp(src, sport, dst, dport, payload):
    dgram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 17, len(dgram))
    dgram = dgram[:6] + struct.pack("!H", checksum(pseudo + dgram) or 0xFFFF) + dgram[8:]
    return ipv4(src, dst, 17, dgram)


def framed(pkt: bytes) -> bytes:
    return struct.pack("!H", len(pkt)) + pkt


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def tcp_exchange(cport, request: bytes, reply: bytes):
    c, s = 1000, 5000
    yield tcp(CLIENT, cport, SERVER, 2743, c, 0, SYN)
    yield tcp(SERVER, 2743, CLIENT, cport, s, c + 1, SYN | ACK)
    c += 1
    s += 1
    yield tcp(CLIENT, cport, SERVER, 2743, c, s, ACK)
    yield tcp(CLIENT, cport, SERVER, 2743, c, s, PSH | ACK, request)
    c += len(request)
    yield tcp(SERVER, 2743, CLIENT, cport, s, c, PSH | ACK, reply)
    s += len(reply)
    yield tcp(SERVER, 2743, CLIENT, cport, s, c, FIN | ACK)


def frames():
    ukey = derive_key(SECRET, UDP_KEY_LABEL)
    ms = T0 * 1000
    announce = NodeAnnounce(node_id="erp-1", node_host="erp-1.internal", node_port=9200, capacity=100)
    yield udp(NODE, 40000, SERVER, 2743, seal_datagram(announce.encode(), ms, ukey))
    yield udp(SERVER, 2743, NODE, 40000, seal_datagram(HeartbeatAck().encode(), ms + 1, ukey))
    yield udp(NODE, 40000, SERVER, 2743, seal_datagram(NodeHeartbeat("erp-1", 12).encode(), ms + 5000, ukey))

    issuer = SignedTokenIssuer({"erp-1": SECRET}, clock=lambda: T0)
    ok = RouteRedirect(target_host="erp-1.internal", target_port=9200, token=issuer.issue("alice@example.com", "erp-1"))
    yield from tcp_exchange(50000, framed(AuthConnect("alice@example.com", b"hunter2").encode()), framed(ok.encode()))
    yield from tcp_exchange(
        50001,
        framed(AuthConnect("alice@example.com", b"wrong").encode()),
        framed(AuthReject(ReasonCode.INVALID_CREDENTIALS).encode()),
    )


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "murx-sample.pcap")
    with out.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for i, frame in enumerate(frames()):
            fh.write(struct.pack("<IIII", T0 + i, 0, len(frame), len(frame)) + frame)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
