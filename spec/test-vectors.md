# MURX conformance test vectors

Byte-exact encodings for spec revision 1.1. Each vector has a
human-readable summary and a fenced `json` block. The JSON blocks are
machine-readable: `python/tests/test_vectors.py` parses this file and
checks the reference implementation against every one of them, and
other implementations can do the same.

Conventions in the JSON: fields ending in `_hex` are byte strings in
lowercase hex; `hex` is the expected encoding. The key-derivation and
MAC values were cross-checked against `openssl dgst -sha256 -mac HMAC`.

The test secret used below is the 32 bytes `00 01 02 … 1f`. It is for
test vectors only.

## AUTH_CONNECT

- `client_id`: `alice@example.com`
- `auth_data_hex`: `68756e74657232`

```
01 01 11 61 6c 69 63 65 40 65 78 61 6d 70 6c 65
2e 63 6f 6d 00 07 68 75 6e 74 65 72 32
```

```json
{
  "name": "AUTH_CONNECT",
  "type": "AuthConnect",
  "fields": {
    "client_id": "alice@example.com",
    "auth_data_hex": "68756e74657232"
  },
  "hex": "010111616c696365406578616d706c652e636f6d000768756e74657232"
}
```

## ROUTE_REDIRECT (IPv4)

- `target_host`: `192.0.2.10`
- `target_port`: `9200`
- `token_hex`: `01020304`

```
01 02 04 c0 00 02 0a 23 f0 04 01 02 03 04
```

```json
{
  "name": "ROUTE_REDIRECT (IPv4)",
  "type": "RouteRedirect",
  "fields": {
    "target_host": "192.0.2.10",
    "target_port": 9200,
    "token_hex": "01020304"
  },
  "hex": "010204c000020a23f00401020304"
}
```

## ROUTE_REDIRECT (IPv6)

- `target_host`: `2001:db8::10`
- `target_port`: `9200`
- `token_hex`: `01020304`

```
01 02 06 20 01 0d b8 00 00 00 00 00 00 00 00 00
00 00 10 23 f0 04 01 02 03 04
```

```json
{
  "name": "ROUTE_REDIRECT (IPv6)",
  "type": "RouteRedirect",
  "fields": {
    "target_host": "2001:db8::10",
    "target_port": 9200,
    "token_hex": "01020304"
  },
  "hex": "01020620010db800000000000000000000001023f00401020304"
}
```

## ROUTE_REDIRECT (DNS name)

- `target_host`: `erp-1.example.com`
- `target_port`: `9200`
- `token_hex`: `01020304`

```
01 02 03 11 65 72 70 2d 31 2e 65 78 61 6d 70 6c
65 2e 63 6f 6d 23 f0 04 01 02 03 04
```

```json
{
  "name": "ROUTE_REDIRECT (DNS name)",
  "type": "RouteRedirect",
  "fields": {
    "target_host": "erp-1.example.com",
    "target_port": 9200,
    "token_hex": "01020304"
  },
  "hex": "010203116572702d312e6578616d706c652e636f6d23f00401020304"
}
```

## AUTH_REJECT (invalid credentials)

- `reason_code`: `1`
- `reason_text`: ``

```
01 03 01 00
```

```json
{
  "name": "AUTH_REJECT (invalid credentials)",
  "type": "AuthReject",
  "fields": {
    "reason_code": 1,
    "reason_text": ""
  },
  "hex": "01030100"
}
```

## AUTH_REJECT (unsupported version)

- `reason_code`: `4`
- `reason_text`: `1`

```
01 03 04 01 31
```

```json
{
  "name": "AUTH_REJECT (unsupported version)",
  "type": "AuthReject",
  "fields": {
    "reason_code": 4,
    "reason_text": "1"
  },
  "hex": "0103040131"
}
```

## NODE_ANNOUNCE (IPv4)

- `node_id`: `erp-1`
- `node_host`: `10.0.0.5`
- `node_port`: `9200`
- `capacity`: `100`

```
01 10 04 0a 00 00 05 23 f0 00 64 05 65 72 70 2d
31
```

```json
{
  "name": "NODE_ANNOUNCE (IPv4)",
  "type": "NodeAnnounce",
  "fields": {
    "node_id": "erp-1",
    "node_host": "10.0.0.5",
    "node_port": 9200,
    "capacity": 100
  },
  "hex": "0110040a00000523f00064056572702d31"
}
```

## NODE_ANNOUNCE (DNS name)

- `node_id`: `erp-1`
- `node_host`: `erp-1.internal`
- `node_port`: `9200`
- `capacity`: `100`

```
01 10 03 0e 65 72 70 2d 31 2e 69 6e 74 65 72 6e
61 6c 23 f0 00 64 05 65 72 70 2d 31
```

```json
{
  "name": "NODE_ANNOUNCE (DNS name)",
  "type": "NodeAnnounce",
  "fields": {
    "node_id": "erp-1",
    "node_host": "erp-1.internal",
    "node_port": 9200,
    "capacity": 100
  },
  "hex": "0110030e6572702d312e696e7465726e616c23f00064056572702d31"
}
```

## NODE_HEARTBEAT

- `node_id`: `erp-1`
- `load`: `42`

```
01 11 05 65 72 70 2d 31 2a
```

```json
{
  "name": "NODE_HEARTBEAT",
  "type": "NodeHeartbeat",
  "fields": {
    "node_id": "erp-1",
    "load": 42
  },
  "hex": "0111056572702d312a"
}
```

## HEARTBEAT_ACK


```
01 12
```

```json
{
  "name": "HEARTBEAT_ACK",
  "type": "HeartbeatAck",
  "fields": {},
  "hex": "0112"
}
```

## TCP framing of AUTH_CONNECT

- `payload_hex`: `010111616c696365406578616d706c652e636f6d000768756e74657232`

```
00 1d 01 01 11 61 6c 69 63 65 40 65 78 61 6d 70
6c 65 2e 63 6f 6d 00 07 68 75 6e 74 65 72 32
```

```json
{
  "name": "TCP framing of AUTH_CONNECT",
  "type": "TcpFrame",
  "fields": {
    "payload_hex": "010111616c696365406578616d706c652e636f6d000768756e74657232"
  },
  "hex": "001d010111616c696365406578616d706c652e636f6d000768756e74657232"
}
```

## Key derivation

- `node_secret_hex`: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `token_key_hex`: `f72cf0e5de2b6f1dd8f3ae5f534f5968b5c85e20ca936efbd4388d32ed47296b`
- `udp_key_hex`: `bdef32997e42854878ddd83992ec5e6f7a9d0375b06d734b6f2db9d9514f0f9b`

```json
{
  "name": "Key derivation",
  "type": "KeyDerivation",
  "fields": {
    "node_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "token_key_hex": "f72cf0e5de2b6f1dd8f3ae5f534f5968b5c85e20ca936efbd4388d32ed47296b",
    "udp_key_hex": "bdef32997e42854878ddd83992ec5e6f7a9d0375b06d734b6f2db9d9514f0f9b"
  }
}
```

## Signed token

- `node_secret_hex`: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `node_id`: `erp-1`
- `client_id`: `alice@example.com`
- `expiry`: `1800000000`
- `nonce_hex`: `000102030405060708090a0b0c0d0e0f`

```
01 00 00 00 00 6b 49 d2 00 00 01 02 03 04 05 06
07 08 09 0a 0b 0c 0d 0e 0f 05 65 72 70 2d 31 11
61 6c 69 63 65 40 65 78 61 6d 70 6c 65 2e 63 6f
6d 84 ff c3 da 0b 71 2d b3 24 e0 ff 3a 25 9d 2b
4f
```

```json
{
  "name": "Signed token",
  "type": "SignedToken",
  "fields": {
    "node_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "node_id": "erp-1",
    "client_id": "alice@example.com",
    "expiry": 1800000000,
    "nonce_hex": "000102030405060708090a0b0c0d0e0f"
  },
  "hex": "01000000006b49d200000102030405060708090a0b0c0d0e0f056572702d3111616c696365406578616d706c652e636f6d84ffc3da0b712db324e0ff3a259d2b4f"
}
```

## Sealed UDP datagram (NODE_HEARTBEAT)

- `node_secret_hex`: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `packet_hex`: `0111056572702d312a`
- `timestamp_ms`: `1800000000000`

```
01 11 05 65 72 70 2d 31 2a 00 00 01 a3 18 5c 50
00 a5 8a ac 30 92 f4 36 2d 47 c2 7a 22 70 c2 1b
10
```

```json
{
  "name": "Sealed UDP datagram (NODE_HEARTBEAT)",
  "type": "SealedDatagram",
  "fields": {
    "node_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "packet_hex": "0111056572702d312a",
    "timestamp_ms": 1800000000000
  },
  "hex": "0111056572702d312a000001a3185c5000a58aac3092f4362d47c27a2270c21b10"
}
```
