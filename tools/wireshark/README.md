# MURX Wireshark dissector

`murx.lua` decodes MURX on TCP and UDP port 2743, following spec revision
1.1. It covers every packet field, the internals of signed tokens
(expiry, node, client) and the UDP authentication trailer. It doesn't
check MACs, because that needs the node secrets.

## Use

Try it without installing:

```bash
tshark -X lua_script:murx.lua -r capture.pcap -Y murx
wireshark -X lua_script:murx.lua capture.pcap
```

To install permanently, copy `murx.lua` into your personal plugins folder:

- Linux/macOS: `~/.local/lib/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

## Sample capture

`make_sample_pcap.py` writes a capture built from real packets produced
by the reference implementation:

- an authenticated node announce, ack and heartbeat;
- a successful login that ends in a DNS-name redirect with a signed token;
- a rejected login.

```bash
python make_sample_pcap.py murx-sample.pcap
tshark -X lua_script:murx.lua -r murx-sample.pcap -Y murx
```

```
1  10.0.0.5 → 10.0.0.1  MURX  NODE_ANNOUNCE node=erp-1 at erp-1.internal:9200
2  10.0.0.1 → 10.0.0.5  MURX  HEARTBEAT_ACK
3  10.0.0.5 → 10.0.0.1  MURX  NODE_HEARTBEAT node=erp-1 load=12
7  10.0.0.2 → 10.0.0.1  MURX  AUTH_CONNECT client=alice@example.com
8  10.0.0.1 → 10.0.0.2  MURX  ROUTE_REDIRECT -> erp-1.internal:9200
13 10.0.0.2 → 10.0.0.1  MURX  AUTH_CONNECT client=alice@example.com
14 10.0.0.1 → 10.0.0.2  MURX  AUTH_REJECT Invalid credentials
```

Tested with TShark 4.0.
