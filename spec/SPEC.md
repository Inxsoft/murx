# MURX Protocol Specification

**MURX** = Multi-User Resource eXchange.

- **Status:** Reference draft
- **Port:** 2743/tcp, 2743/udp (registered)
- **Transport:** Hybrid TCP + UDP
- **Author:** Thomas Kuiper

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
  to. Backend nodes are not part of the MURX protocol itself; they receive
  the token out of band (e.g. a shared token store) and validate it
  against the client's incoming connection.
- **Auth token**: short-lived, single-use credential minted by the MURX
  server and redeemed by the client against the backend node.
- **Node registry**: the MURX server's live table of backend nodes and
  their health/capacity, built from the UDP sub-protocol in section 9.

## 3. Transport

MURX is a hybrid-transport protocol. Both transports share port 2743:

| Transport | Port      | Used for | Peers |
|-----------|-----------|----------|-------|
| TCP       | 2743/tcp  | Stateful, reliable operations: client authentication, routing/resource-lock decisions, and (via redirect) the resulting backend data session. | Client <-> MURX server, then Client <-> Backend node |
| UDP       | 2743/udp  | Stateless, lightweight operations: backend node discovery announcements and health-check heartbeats that feed the node registry used for routing decisions. | Backend node <-> MURX server |

Client-facing behavior (auth + routing) is always over TCP; a client never
speaks UDP MURX. UDP is used strictly between the MURX server and the
backend node pool to keep the node registry current, which is what lets
"Dynamic Connection Routing" (section 1) make load/health-aware decisions
without a client request blocking on a slow liveness check.

### 3.1 TCP framing

MURX runs each TCP exchange over a single, short-lived connection.
Because TCP is a byte stream, every MURX TCP message is wrapped in a
2-byte big-endian length prefix giving the length of the payload that
follows (the payload is the "Version/Opcode/..." structure described in
section 4; the length prefix itself is not counted).

```
+----------------+----------------------------+
| Length (2)     | Payload (Length bytes)     |
+----------------+----------------------------+
```

Maximum payload length is 65535 bytes.

### 3.2 UDP framing

Each MURX UDP datagram *is* one packet; there is no length prefix (the
UDP datagram boundary provides framing). See section 9 for the packet
formats used on this transport.

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
| 0x03   | `AUTH_REJECT`   | server -> client | Authentication failed or no route available. |

### 4.2 `AUTH_CONNECT` (0x01)

Sent by the client to open the exchange.

| Field              | Size      | Description |
|--------------------|-----------|--------------|
| Version            | 1 byte    | `1` |
| Opcode             | 1 byte    | `0x01` |
| Client ID Length   | 1 byte    | Length of Client ID, in bytes |
| Client ID          | variable  | Opaque identifier for the client (e.g. username, device ID) |
| Auth Data Length   | 2 bytes   | Length of Auth Data, in bytes |
| Auth Data          | variable  | Encapsulated authentication material (hashed credential, certificate, signed assertion, etc.). Opaque to the wire format; interpretation is a matter of server policy/configuration. |

### 4.3 `ROUTE_REDIRECT` (0x02)

Sent by the server after successful authentication. Closes the MURX
connection immediately after sending.

| Field           | Size          | Description |
|-----------------|---------------|--------------|
| Version         | 1 byte        | `1` |
| Opcode          | 1 byte        | `0x02` |
| Address Family  | 1 byte        | `0x04` = IPv4, `0x06` = IPv6 |
| Target IP       | 4 or 16 bytes | Backend address, per Address Family |
| Target Port     | 2 bytes       | Backend TCP port |
| Token Length    | 1 byte        | Length of Auth Token, in bytes |
| Auth Token      | variable      | One-time authorization token, presented by the client to the backend node |

### 4.4 `AUTH_REJECT` (0x03)

Sent by the server when authentication fails or no backend route can be
computed for the client. Closes the MURX connection immediately after
sending. (Not present in earlier informal descriptions of MURX; specified
here so implementations have a defined failure path instead of silently
dropping the connection.)

| Field         | Size     | Description |
|---------------|----------|--------------|
| Version       | 1 byte   | `1` |
| Opcode        | 1 byte   | `0x03` |
| Reason Code   | 1 byte   | See section 4.4.1 |
| Reason Length | 1 byte   | Length of Reason Text, in bytes |
| Reason Text   | variable | UTF-8 human-readable detail (may be empty, length 0) |

#### 4.4.1 Reason codes

| Code | Meaning |
|------|---------|
| 0x01 | Invalid or unrecognized credentials |
| 0x02 | Client authenticated but no eligible backend route exists |
| 0x03 | Malformed request |
| 0xFF | Internal server error |

## 5. Protocol flow

```
 Client                          MURX server                 Backend node
   |                                   |                            |
   |--- TCP connect (port 2743) ------>|                            |
   |--- AUTH_CONNECT ------------------>|                            |
   |                                   |-- verify credentials       |
   |                                   |-- compute route            |
   |                                   |-- mint one-time token       |
   |                                   |-- publish token to backend  |
   |                                   |   (out of band)  --------->|
   |<-- ROUTE_REDIRECT ------------------|                            |
   |<-- (MURX connection closed) -------|                            |
   |                                                                |
   |--- TCP connect (target IP:port) ------------------------------>|
   |--- present Auth Token ----------------------------------------->|
   |                                                       -- validate token
   |<=========================== application session ================>|
```

If authentication fails, or no backend is available, the server replies
with `AUTH_REJECT` instead of `ROUTE_REDIRECT` and closes the connection;
no token is minted.

## 6. Token semantics

- Tokens are single-use. A backend node MUST reject a second presentation
  of the same token.
- Tokens MUST have a short expiry (implementation-defined; this reference
  implementation defaults to 30 seconds) to bound the window between
  `ROUTE_REDIRECT` and the client's connection to the backend.
- How tokens are distributed from the MURX server to backend nodes is
  outside the scope of the wire protocol (shared cache, database, internal
  RPC, etc.), but the distribution mechanism MUST complete before the
  server sends `ROUTE_REDIRECT`, so the backend is never asked to validate
  a token it doesn't know about yet.

## 7. Node registry (UDP, backend-facing)

Backend nodes maintain their presence in the MURX server's node registry
using two UDP message types on port 2743/udp. These packets share the
Version/Opcode envelope from section 4 but are never length-prefixed
(section 3.2).

### 7.1 Opcodes

| Opcode | Name              | Direction              | Meaning |
|--------|-------------------|-------------------------|---------|
| 0x10   | `NODE_ANNOUNCE`   | backend node -> server  | "I exist and am eligible for routing"; sent on startup and periodically re-sent as a keepalive. |
| 0x11   | `NODE_HEARTBEAT`  | backend node -> server  | Lightweight liveness/load update between full announcements. |
| 0x12   | `HEARTBEAT_ACK`   | server -> backend node  | Optional acknowledgement; a node MAY operate without waiting for this. |

### 7.2 `NODE_ANNOUNCE` (0x10)

| Field            | Size          | Description |
|------------------|---------------|--------------|
| Version          | 1 byte        | `1` |
| Opcode           | 1 byte        | `0x10` |
| Address Family   | 1 byte        | `0x04` = IPv4, `0x06` = IPv6 |
| Node IP          | 4 or 16 bytes | Address the node is reachable at (may differ from the UDP source address, e.g. behind NAT) |
| Node Port        | 2 bytes       | TCP port the node accepts redirected client sessions on |
| Capacity         | 2 bytes       | Node-reported free capacity/slots, used as a routing weight |
| Node ID Length   | 1 byte        | Length of Node ID |
| Node ID          | variable      | Opaque identifier for the backend node |

### 7.3 `NODE_HEARTBEAT` (0x11)

| Field          | Size     | Description |
|----------------|----------|--------------|
| Version        | 1 byte   | `1` |
| Opcode         | 1 byte   | `0x11` |
| Node ID Length | 1 byte   | Length of Node ID |
| Node ID        | variable | Must match a previously announced Node ID |
| Load           | 1 byte   | Current load, 0 (idle) - 255 (saturated) |

A node not heard from (announce or heartbeat) within a server-configured
TTL (reference implementation default: 15 seconds) is removed from the
registry and MUST NOT be used as a routing target.

### 7.4 `HEARTBEAT_ACK` (0x12)

| Field   | Size   | Description |
|---------|--------|--------------|
| Version | 1 byte | `1` |
| Opcode  | 1 byte | `0x12` |

Since UDP is unreliable and unordered, `NODE_ANNOUNCE`/`NODE_HEARTBEAT`
senders MUST NOT assume delivery; the periodic re-send behavior is the
protocol's only reliability mechanism. `HEARTBEAT_ACK` is a convenience
for nodes that want faster confirmation than waiting for the next TTL
window, not a substitute for it.

## 8. Security considerations

- `AUTH_CONNECT` carries authentication material; the MURX connection
  SHOULD be protected by a transport-layer encryption wrapper (e.g. TLS)
  in any deployment handling real credentials. This document specifies the
  MURX application-layer framing only and does not preclude running it
  inside TLS.
- Because the MURX server closes its connection immediately after
  `ROUTE_REDIRECT`/`AUTH_REJECT`, it cannot itself observe whether the
  client successfully redeemed the token; backend nodes are responsible
  for token single-use enforcement and expiry.
- Reason codes in `AUTH_REJECT` should avoid leaking information that
  distinguishes "user does not exist" from "wrong credentials" in
  deployments where that distinction is sensitive.
- The UDP node registry channel (section 7) is unauthenticated at the
  wire-format level. Deployments MUST restrict it (network segmentation,
  IPsec, or an out-of-band shared secret checked by the server's node
  registry implementation) so an untrusted host cannot announce itself as
  a backend node and receive redirected client sessions.

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
- **Auth Data** is the opaque credential for that user — in the simplest
  case, a UTF-8-encoded password.
- The `domain` part is also used by the *client* before it ever sends
  `AUTH_CONNECT`, to discover which MURX server to connect to in the
  first place. The default, always-available path requires no DNS
  lookup beyond an ordinary address record: connect to `murx.<domain>`
  on the registered port, 2743/tcp -- this is what a fixed, registered
  port is for in the first place.
- An SRV record `_murx._tcp.<domain>` is an OPTIONAL, supported
  override for deployments that want a different host and/or port than
  the `murx.<domain>`:2743 default (e.g. multiple domains sharing one
  MURX server, or running it on a non-default port). A client MAY look
  one up; it is never required to, and a domain that publishes no SRV
  record is not a protocol violation -- it just means the default
  applies.

  This discovery step is outside the MURX wire protocol itself (it's
  ordinary DNS), but implementations SHOULD understand the
  `murx.<domain>`:2743 default so that MURX clients are interoperable
  across independently-run domains without any special configuration.

### 9.2 Client IDs beyond `user@domain`

Not every deployment has a human user or a domain to hang a Client ID
off of. The Client ID is just an opaque, server-interpreted identifier
-- other shapes are equally valid:

- a device serial number or client certificate subject, for machine
  clients with no notion of a "domain";
- an opaque session or matchmaking-ticket ID, for a client that already
  authenticated elsewhere and is just asking MURX where to connect next;
- a tenant/account key, where routing depends on which customer's data
  a request belongs to rather than on an individual end user.

### 9.3 Example deployments

MURX's core trade -- authenticate once, get redirected, then talk
directly to the assigned node -- shows up in more places than one:

| Deployment | What the backend node is | What routing decides |
|------------|---------------------------|------------------------|
| ERP / business applications | A regional or per-tenant ERP instance | Which instance holds this user's company/tenant data |
| Database connection brokering | A database shard or read replica | Which shard owns this tenant's/key's data, or which replica has spare capacity |
| Multiplayer game matchmaking | A game server instance running a match | Which instance has room, and is geographically closest |
| Real-time voice/video | A media relay/SFU node | Which node is closest to the participant, or least loaded |
| Chat / messaging | The homeserver actually hosting a user's account | Which homeserver owns `user`, mirroring how XMPP/email resolve `user@domain` |
| IoT device fleets | A regional ingestion server | Which region a device (identified by certificate or serial) should stream to |

In every case, the shape of the exchange is identical: `AUTH_CONNECT` in,
`ROUTE_REDIRECT`/`AUTH_REJECT` out, then a direct client-to-node session
authorized by the one-time token -- only what counts as a valid
credential, and how routing is computed, changes per deployment.

## 10. IANA considerations

Port 2743 is registered for the MURX protocol described in this document,
for both the tcp and udp transport protocols.
