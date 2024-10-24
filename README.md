getaddress
---

Builds a list of reachable Bitcoin nodes by impersonating one and continuously sending `getaddr` messages to other known nodes.

Supports all networks: `mainnet`, `testnet4`, `signet`, `regtest`.

Takes a while: a handshake must be made with a potential peer in order for it to be considered valid and added to the list.

Usage
---

```shell
~$ cargo run -- --network mainnet
[2024-10-24 01:05:53 WARN getaddress] failed to connect to 2001:4060:4419:8001::42:8333: Network is unreachable (os error 101)
[2024-10-24 01:05:54 INFO getaddress] starting handshake with 5.128.87.126:8333
[2024-10-24 01:05:54 INFO getaddress] successful handshake with 5.128.87.126:8333
[2024-10-24 01:05:56 INFO getaddress] starting handshake with 174.71.24.107:8333
[2024-10-24 01:05:56 INFO getaddress] starting handshake with 109.123.235.225:8333
[2024-10-24 01:05:56 INFO getaddress] successful handshake with 174.71.24.107:8333
[2024-10-24 01:05:56 INFO getaddress] new peer discovered @ 174.71.24.107:8333
[2024-10-24 01:05:57 INFO getaddress] starting handshake with 3.138.158.248:8333
[2024-10-24 01:05:57 INFO getaddress] successful handshake with 109.123.235.225:8333
[2024-10-24 01:05:57 INFO getaddress] new peer discovered @ 109.123.235.225:8333
[2024-10-24 01:05:57 INFO getaddress] successful handshake with 3.138.158.248:8333
[2024-10-24 01:05:57 INFO getaddress] new peer discovered @ 3.138.158.248:8333
[2024-10-24 01:05:57 INFO getaddress] starting handshake with 185.250.243.159:8333
^C[2024-10-24 01:05:57 INFO getaddress] received SIGINT, shutting down...
[2024-10-24 01:05:57 INFO getaddress] successful handshake with 185.250.243.159:8333
[2024-10-24 01:05:57 INFO getaddress] new peer discovered @ 185.250.243.159:8333
[2024-10-24 01:05:59 INFO getaddress] found 43 peers in 00h00m24s
[2024-10-24 01:05:59 INFO getaddress] wrote 43 peers to output/mainnet-nodes.txt
[2024-10-24 01:05:59 INFO getaddress] done!
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
