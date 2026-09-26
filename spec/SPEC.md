# MURX Protocol Specification

**MURX** = Multi-User Resource eXchange.

- **Revision:** 1.1 (wire version `1`)
- **Status:** Reference draft
- **Port:** 2743/tcp, 2743/udp (registered)
- **Transport:** Hybrid TCP (with TLS) + authenticated UDP
- **Author:** Thomas Kuiper

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

## 1. Overview

MURX is an authenticated routing gateway protocol. A MURX server sits in
front of a pool of backend application servers — anything from an ERP
system to a database cluster, a game server fleet, or a chat homeserver
pool — and performs two jobs that are normally split across separate
systems:

1. **Authentication** of a connecting client.
2. **Directory / routing**: telling the client which backend node to use.

The MURX server never proxies application data itself. After a client
authenticates, the server calculates the best backend node for that client
and returns its network coordinates plus a one-time token. The client then
opens a *separate* connection directly to the backend and presents the
token to prove it already cleared MURX authentication. The MURX connection
is closed as soon as the routing reply is sent.

This keeps the (potentially expensive) auth/directory logic out of the
data path, and keeps backend servers from ever needing to see client
credentials directly.

## 2. Terminology

- **Client**: entity requesting access to a backend service.
- **MURX server**: the gatekeeper described in this document, listening on
  port 2743.
- **Backend node**: the application server the client is ultimately routed
  to. Backend nodes are not MURX peers on the client-facing side; they
  verify the client's token locally (section 6) and keep themselves
  registered over UDP (section 7).
- **Node secret**: a secret shared between the MURX server and one backend
  node, from which that node's token key and UDP key are derived
  (section 6.2).
- **Auth token**: short-lived, single-use, signed credential minted by the
  MURX server and redeemed by the client at the backend node.
- **Node registry**: the MURX server's live table of backend nodes and
  their health/capacity, built from the UDP sub-protocol in section 7.

## 3. Transport

MURX is a hybrid-transport protocol. Both transports share port 2743:

| Transport | Port      | Used for | Peers |
|-----------|-----------|----------|-------|
| TCP       | 2743/tcp  | Client authentication and routing, and (via redirect) the resulting backend session. | Client <-> MURX server, then Client <-> Backend node |
| UDP       | 2743/udp  | Backend node announcements and heartbeats that feed the node registry. | Backend node <-> MURX server |

A client never speaks UDP MURX. UDP is used strictly between the MURX
server and the backend node pool to keep the node registry current, so
routing decisions never block on a liveness check.

### 3.1 TCP framing

Each TCP exchange runs over a single, short-lived connection. Every MURX
TCP message is wrapped in a 2-byte big-endian length prefix giving the
length of the payload that follows (the prefix itself is not counted).

```
+----------------+----------------------------+
| Length (2)     | Payload (Length bytes)     |
+----------------+----------------------------+
```

Maximum payload length is 65535 bytes.

### 3.2 UDP framing

Each UDP datagram carries exactly one packet followed by an
authentication trailer (section 7.5). There is no length prefix; the
datagram boundary provides framing.

### 3.3 TLS

`AUTH_CONNECT` carries credentials. The client-facing TCP connection
MUST be protected with TLS 1.2 or later in any deployment handling real
credentials; plain TCP is acceptable only for local testing.

- The ALPN protocol identifier for MURX is `murx/1`. Clients and servers
  using TLS SHOULD offer it, which lets MURX share port 443 or 2743 with
  other TLS services.
- Clients MUST verify the server certificate against the host name they
  connected to.
- The backend leg SHOULD also use TLS. When it does, the client verifies
  the backend's certificate against the host name from `ROUTE_REDIRECT`,
  which is why section 4.5 allows the redirect to carry a DNS name.

## 4. Packet structure (TCP, client-facing)

All multi-byte integer fields are big-endian ("network order"). All
packets begin with:

| Field   | Size    | Description                        |
|---------|---------|-------------------------------------|
| Version | 1 byte  | Protocol version. This document defines version `1`. |
| Opcode  | 1 byte  | Packet type, see section 4.1        |

### 4.1 Opcodes

| Opcode | Name            | Direction        | Meaning |
|--------|-----------------|------------------|---------|
| 0x01   | `AUTH_CONNECT`  | client -> server | Client requests authentication and routing. |
| 0x02   | `ROUTE_REDIRECT`| server -> client | Authentication succeeded; here is your backend and token. |
| 0x03   | `AUTH_REJECT`   | server -> client | Authentication failed, no route, or unsupported version. |

### 4.2 `AUTH_CONNECT` (0x01)

Sent by the client to open the exchange.

| Field              | Size      | Description |
|--------------------|-----------|--------------|
| Version            | 1 byte    | `1` |
| Opcode             | 1 byte    | `0x01` |
| Client ID Length   | 1 byte    | Length of Client ID, in bytes |
| Client ID          | variable  | UTF-8 identifier for the client (e.g. `user@domain`, device ID) |
| Auth Data Length   | 2 bytes   | Length of Auth Data, in bytes |
| Auth Data          | variable  | Authentication material (password, hashed credential, signed assertion, ...). Opaque to the wire format; its interpretation is server policy. |

### 4.3 `ROUTE_REDIRECT` (0x02)

Sent by the server after successful authentication. The server closes
the connection immediately after sending it.

| Field           | Size          | Description |
|-----------------|---------------|--------------|
| Version         | 1 byte        | `1` |
| Opcode          | 1 byte        | `0x02` |
| Target Address  | variable      | Backend address, encoded per section 4.5 |
| Target Port     | 2 bytes       | Backend TCP port |
| Token Length    | 1 byte        | Length of Auth Token, in bytes |
| Auth Token      | variable      | One-time authorization token (section 6), presented by the client to the backend node |

### 4.4 `AUTH_REJECT` (0x03)

Sent by the server when authentication fails, no backend route can be
computed, or the request is malformed. The server closes the connection
immediately after sending it.

| Field         | Size     | Description |
|---------------|----------|--------------|
| Version       | 1 byte   | `1` |
| Opcode        | 1 byte   | `0x03` |
| Reason Code   | 1 byte   | See section 4.4.1 |
| Reason Length | 1 byte   | Length of Reason Text, in bytes |
| Reason Text   | variable | UTF-8 human-readable detail (may be empty) |

#### 4.4.1 Reason codes

| Code | Meaning |
|------|---------|
| 0x01 | Invalid or unrecognized credentials |
| 0x02 | Client authenticated but no eligible backend route exists |
| 0x03 | Malformed request |
| 0x04 | Unsupported protocol version (section 4.6) |
| 0xFF | Internal server error |

Clients MUST treat unknown reason codes as a generic failure.

### 4.5 Address encoding

Used by `ROUTE_REDIRECT` (Target Address) and `NODE_ANNOUNCE` (Node
Address). The first byte is the Address Family:

| Family | Meaning   | Following bytes |
|--------|-----------|------------------|
| 0x03   | DNS name  | Length (1 byte), then that many ASCII bytes: a host name of 1–253 characters, dot-separated labels of 1–63 letters, digits or hyphens, not starting or ending with a hyphen |
| 0x04   | IPv4      | 4 bytes |
| 0x06   | IPv6      | 16 bytes |

Receivers MUST reject an unknown family or a malformed DNS name as a
malformed packet.

### 4.6 Version handling

A server that receives a packet whose Version byte it does not support
MUST reply with `AUTH_REJECT` reason `0x04`. The Reason Text MUST list the
versions the server supports as comma-separated decimal numbers (e.g.
`1` or `1,2`). The reply itself uses the highest version the server
supports.

## 5. Protocol flow

```
 Client                          MURX server                 Backend node
   |                                   |                            |
   |                                   |<== NODE_ANNOUNCE/HEARTBEAT |
   |                                   |    (UDP, authenticated)    |
   |--- TLS connect (port 2743) ------>|                            |
   |--- AUTH_CONNECT ----------------->|                            |
   |                                   |-- verify credentials       |
   |                                   |-- pick a live node         |
   |                                   |-- sign token for that node |
   |<-- ROUTE_REDIRECT ----------------|                            |
   |<-- (MURX connection closed) ------|                            |
   |                                                                |
   |--- TLS connect (target host:port) ---------------------------->|
   |--- present Auth Token ---------------------------------------->|
   |                                           -- verify signature, |
   |                                              expiry, single use|
   |<========================== application session ===============>|
```

If authentication fails, or no backend is available, the server replies
with `AUTH_REJECT` instead of `ROUTE_REDIRECT` and closes the connection;
no token is minted.

## 6. Tokens

### 6.1 Signed token format

The Auth Token is self-verifying: the backend node checks it using only
its own token key, so the MURX server and the backends share no token
state.

| Field            | Size     | Description |
|------------------|----------|--------------|
| Token Version    | 1 byte   | `1` |
| Expiry           | 8 bytes  | Unix time in seconds after which the token is invalid |
| Nonce            | 16 bytes | Random, unique per token |
| Node ID Length   | 1 byte   | |
| Node ID          | variable | UTF-8 ID of the node the token is valid at |
| Client ID Length | 1 byte   | |
| Client ID        | variable | UTF-8 ID of the authenticated client |
| MAC              | 16 bytes | First 16 bytes of HMAC-SHA256(token key, all preceding bytes) |

The total token MUST fit in 255 bytes, so Node ID and Client ID together
are limited to 212 bytes.

A backend node MUST reject a token unless all of the following hold:

1. The MAC verifies under the node's token key (constant-time compare).
2. Token Version is `1`.
3. Node ID equals the node's own ID.
4. The current time is not later than Expiry.
5. The Nonce has not been redeemed before at this node. Nodes keep
   redeemed nonces at least until their Expiry passes.

The MURX server SHOULD issue tokens with a short lifetime; the reference
implementation uses 30 seconds. Node and server clocks need to agree to
within a few seconds.

### 6.2 Key derivation

Each backend node shares one secret (at least 32 random bytes) with the
MURX server. Keys are derived from it per purpose, so a single secret
never directly keys two different MACs:

```
token key = HMAC-SHA256(node secret, "murx token v1")
UDP key   = HMAC-SHA256(node secret, "murx udp v1")
```

The labels are ASCII, without a trailing NUL. How node secrets are
provisioned is a deployment matter.

### 6.3 Presenting the token

How a client presents the token to a backend node belongs to the backend
service, not to MURX. The reference implementation sends a 1-byte length
followed by the token as the first bytes of the backend connection.

## 7. Node registry (UDP, backend-facing)

Backend nodes keep their entry in the MURX server's node registry using
authenticated UDP datagrams on port 2743/udp.

### 7.1 Opcodes

| Opcode | Name              | Direction              | Meaning |
|--------|-------------------|-------------------------|---------|
| 0x10   | `NODE_ANNOUNCE`   | backend node -> server  | "I exist and am eligible for routing"; sent on startup and re-sent periodically. |
| 0x11   | `NODE_HEARTBEAT`  | backend node -> server  | Lightweight liveness/load update between announcements. |
| 0x12   | `HEARTBEAT_ACK`   | server -> backend node  | Acknowledgement of an accepted datagram. Nodes MAY ignore it. |

### 7.2 `NODE_ANNOUNCE` (0x10)

| Field            | Size          | Description |
|------------------|---------------|--------------|
| Version          | 1 byte        | `1` |
| Opcode           | 1 byte        | `0x10` |
| Node Address     | variable      | Address clients should connect to, per section 4.5 (may differ from the UDP source address, e.g. behind NAT) |
| Node Port        | 2 bytes       | TCP port the node accepts redirected client sessions on |
| Capacity         | 2 bytes       | Node-reported free capacity, used as a routing weight |
| Node ID Length   | 1 byte        | Length of Node ID |
| Node ID          | variable      | UTF-8 identifier for the backend node |

### 7.3 `NODE_HEARTBEAT` (0x11)

| Field          | Size     | Description |
|----------------|----------|--------------|
| Version        | 1 byte   | `1` |
| Opcode         | 1 byte   | `0x11` |
| Node ID Length | 1 byte   | Length of Node ID |
| Node ID        | variable | Must match a previously announced Node ID |
| Load           | 1 byte   | Current load, 0 (idle) - 255 (saturated) |

A node not heard from within a server-configured TTL (reference
implementation: 15 seconds) is removed from the registry and MUST NOT be
used as a routing target. Nodes SHOULD re-send `NODE_ANNOUNCE`
periodically so that a restarted server relearns them.

### 7.4 `HEARTBEAT_ACK` (0x12)

| Field   | Size   | Description |
|---------|--------|--------------|
| Version | 1 byte | `1` |
| Opcode  | 1 byte | `0x12` |

UDP is unreliable and unordered: senders MUST NOT assume delivery, and
periodic re-sending is the only reliability mechanism.

### 7.5 Datagram authentication

Every UDP datagram, in both directions, is the packet followed by an
authentication trailer:

```
+-----------+---------------------+-----------+
| Packet    | Timestamp (8 bytes) | MAC (16)  |
+-----------+---------------------+-----------+
```

- **Timestamp** is milliseconds since the Unix epoch, as an unsigned
  64-bit integer.
- **MAC** is the first 16 bytes of HMAC-SHA256(UDP key, Packet ||
  Timestamp), using the UDP key of the node named in the packet (for
  `HEARTBEAT_ACK`, the node it is sent to).

The server MUST silently drop a datagram if any of these hold:

1. The Node ID has no configured node secret.
2. The MAC does not verify (constant-time compare).
3. The Timestamp differs from the server's clock by more than the
   allowed skew (reference implementation: 30 seconds).
4. The Timestamp is not strictly greater than the last accepted
   Timestamp for that Node ID (replay protection). Senders MUST
   therefore send strictly increasing timestamps.

## 8. Security considerations

- **Credentials in transit.** Run the client-facing side over TLS
  (section 3.3). Without it, Auth Data is exposed to anyone on the path.
- **Bearer tokens.** A token is usable by whoever holds it until it
  expires or is redeemed. Short lifetimes, single-use enforcement and TLS
  on both legs limit that window. Tokens are bound to one node, so a
  token stolen for one node cannot be used at another.
- **Node secrets.** A leaked node secret lets an attacker both register a
  fake node under that ID and mint tokens that node would accept. Treat
  node secrets like private keys and rotate them if a node is
  compromised.
- **Node registry.** Datagram authentication (section 7.5) stops
  untrusted hosts from registering as backends. Deployments SHOULD still
  restrict 2743/udp to the backend network.
- **Reject reasons.** Servers SHOULD NOT reveal whether a Client ID
  exists; using reason `0x01` for both unknown clients and wrong
  credentials is RECOMMENDED.
- **Brute force.** Servers SHOULD rate-limit `AUTH_CONNECT` attempts per
  Client ID and per source address.
- **Parsing.** Every length field is bounded by the enclosing message.
  Implementations MUST reject packets whose lengths are inconsistent,
  instead of reading past the end.

## 9. Client ID conventions, server discovery, and example deployments (informative)

This section is non-normative; it describes common deployment patterns
rather than wire-format requirements. Client ID and Auth Data (section
4.2) are opaque to the wire format on purpose -- MURX doesn't assume
anything about what kind of backend service it's gatekeeping.

### 9.1 The `user@domain` convention

A frequent Client ID convention is `user@domain` (e.g. authenticating as
`alice@example.com`), mirroring email/XMPP-style addressing. In this
pattern:

- **Client ID** (section 4.2) is the full `user@domain` string.
- **Auth Data** is the credential for that user — in the simplest case,
  a UTF-8-encoded password (sent only over TLS).
- The `domain` part is also used by the *client* before it ever sends
  `AUTH_CONNECT`, to discover which MURX server to connect to. The
  default, always-available path requires no DNS lookup beyond an
  ordinary address record: connect to `murx.<domain>` on the registered
  port, 2743/tcp.
- An SRV record `_murx._tcp.<domain>` is an OPTIONAL, supported override
  for deployments that want a different host and/or port. A client MAY
  look one up; a domain that publishes no SRV record just gets the
  default.

### 9.2 Client IDs beyond `user@domain`

The Client ID is just a server-interpreted identifier -- other shapes
are equally valid:

- a device serial number or client certificate subject, for machine
  clients with no notion of a "domain";
- an opaque session or matchmaking-ticket ID, for a client that already
  authenticated elsewhere and is just asking MURX where to connect next;
- a tenant/account key, where routing depends on which customer's data
  a request belongs to rather than on an individual end user.

### 9.3 Example deployments

| Deployment | What the backend node is | What routing decides |
|------------|---------------------------|------------------------|
| ERP / business applications | A regional or per-tenant ERP instance | Which instance holds this user's company/tenant data |
| Database connection brokering | A database shard or read replica | Which shard owns this tenant's data, or which replica has spare capacity |
| Multiplayer game matchmaking | A game server instance running a match | Which instance has room, and is geographically closest |
| Real-time voice/video | A media relay/SFU node | Which node is closest to the participant, or least loaded |
| Chat / messaging | The homeserver hosting a user's account | Which homeserver owns `user` |
| IoT device fleets | A regional ingestion server | Which region a device should stream to |

In every case the exchange is identical: `AUTH_CONNECT` in,
`ROUTE_REDIRECT`/`AUTH_REJECT` out, then a direct client-to-node session
authorized by the one-time token.

## 10. Conformance test vectors

[`test-vectors.md`](test-vectors.md) lists byte-exact encodings of every
packet type, a signed token, key derivation and a sealed UDP datagram.
Implementations SHOULD check their encoders and decoders against it.

## 11. IANA considerations

Port 2743 is registered for the MURX protocol described in this document,
for both the tcp and udp transport protocols. This document additionally
uses the ALPN identifier `murx/1` (section 3.3).

## 12. Changes in revision 1.1

- Tokens are signed and verified locally by the backend node (section 6);
  the shared token store is no longer needed.
- UDP datagrams carry a timestamp and MAC, with replay protection
  (section 7.5).
- TLS is required for real deployments, with ALPN `murx/1` (section 3.3).
- Addresses may be DNS names (section 4.5), so clients can verify backend
  TLS certificates.
- Defined version handling and reason code `0x04` (section 4.6).
