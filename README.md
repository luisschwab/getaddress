getaddress
---

Builds a list of reachable Bitcoin nodes by impersonating one and sending `getaddr` messages to known nodes.

Supports all networks: `mainnet`, `testnet4`, `signet`, `regtest`.

Takes a while: a handshake must be made to a potential peer in order for it to be considered valid.

Usage
---

```shell
~$ cargo run -- --network mainnet
[2024-10-22 20:25:16 INFO getaddress] starting handshake with 2001:4060:4419:8001::42:8333
[2024-10-22 20:25:16 INFO getaddress] successful handshake with 2001:4060:4419:8001::42:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 111.22.174.235:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 120.202.91.178:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 91.44.107.42:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ [2001:9e8:20c:ce00:ad60:1561:ffee:d898]:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 222.71.166.242:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ [2001:1620:542c:210::100]:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 82.16.56.226:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 35.240.132.22:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 185.65.134.247:8333
[2024-10-22 20:25:17 INFO getaddress] new peer discovered @ 86.120.131.172:8333
^C[2024-10-22 20:25:18 INFO getaddress] received SIGINT, shutting down...
[2024-10-22 20:25:18 INFO getaddress] found 3003 peers
[2024-10-22 20:25:18 INFO getaddress] wrote 3003 peers to output/mainnet-nodes.txt
[2024-10-22 20:25:18 INFO getaddress] done!
```


Sequence Diagram
---
This is the sequence diagram for the handshake and address exchange:

```
LOCAL              REMOTE
  ┬                   ┬
  | version           |
  |------------------>|
  |                   |
  |           version |
  |<------------------|
  |                   |
  |            verack |
  |<------------------|
  |                   |
  | verack            |
  |------------------>|
  |                   |
  | getaddr           |
  |------------------>|
  |                   |
  |              addr |
  |<------------------|
  ┴                   ┴
```

Message Structure
---
All P2P messages have a standard format, consisting of:
- Header (24 bytes)
- Payload (Variable lenght, including 0)

Header Structure
---
```
┌──────────────┬─────────────────┬──────┬──────────────────────────────────────────────┐
│ Field        │ Format          │ Size │ Description                                  │
├──────────────┼─────────────────┼──────┼──────────────────────────────────────────────┤
│ Magic Bytes  │ bytes           │ 4    │ Network-specific magic bytes                 │
│ Command      │ ascii bytes     │ 12   │ ASCII-encoded command                        |
│ Size         │ little-endian   │ 4    │ Payload size                                 │
│ Checksum     │ bytes           │ 4    │ Checksum (first 4 bytes of HASH256(payload)) |
└──────────────┴─────────────────┴──────┴──────────────────────────────────────────────┘
```

addr Payload Structure
---
```
┌──────────────┬─────────────────┬──────┬──────────────────────────────────────────────┐
│ Field        │ Format          │ Size │ Description                                  │
├──────────────┼─────────────────┼──────┼──────────────────────────────────────────────┤
│ IP count     │ compact size    │ *    │ IP count encoded in compactSize              │
│ IP addresses │ Vec<network_IP> | *    │ IP address entries (format below)            │
└──────────────┴─────────────────┴──────┴──────────────────────────────────────────────┘
```

network_IP Structure
---
```
┌──────────────┬─────────────────┬──────┬──────────────────────────────────────────────┐
│ Field        │ Format          │ Size │ Description                                  │
├──────────────┼─────────────────┼──────┼──────────────────────────────────────────────┤
│ Time         │ little-endian   │ 4    │ Unix Epoch time                              │
│ Services     │ little-endian   | 8    │ Advertised services                          │
| IP address   | big-endian      | 16   | IPv6 or IPv6-wrapped-IPv4                    |
| Port         | big-endian      | 2    | Port                                         |
└──────────────┴─────────────────┴──────┴──────────────────────────────────────────────┘
```

TODO
---
- [ ] Use GeoLite2-ASN.mmdb to determine AS's stakes in node hosting
- [ ] Add `addrv2` support
- [ ] Add Tor support
- [ ] Add I2P support
- [ ] Add CJDNS supoort
- [ ] Add Yggdrasil support
