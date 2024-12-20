getaddress
---

Builds a list of reachable Bitcoin nodes by impersonating one and continuously sending `getaddr` messages to other known nodes.

Supports all networks: `mainnet`, `testnet4`, `signet`, `regtest`.

Takes a while: a handshake must be made with a potential peer in order for it to be considered valid and added to the list.

Usage
---

```
~$ cargo run -- --net testnet4
[2024-10-24 21:07:05 INFO getaddress] starting handshake with 203.132.94.196:48333
[2024-10-24 21:07:05 INFO getaddress] starting handshake with 85.208.69.71:48333
[2024-10-24 21:07:05 INFO getaddress] successful handshake with 203.132.94.196:48333
[2024-10-24 21:07:05 INFO getaddress] new peer discovered @ 203.132.94.196:48333
[2024-10-24 21:07:05 INFO getaddress] successful handshake with 85.208.69.71:48333
[2024-10-24 21:07:05 INFO getaddress] new peer discovered @ 85.208.69.71:48333
[2024-10-24 21:07:05 INFO getaddress] 51 non-unique peers in the db
[2024-10-24 21:07:06 INFO getaddress] starting handshake with 103.99.171.211:48333
[2024-10-24 21:07:06 INFO getaddress] successful handshake with 103.99.171.211:48333
[2024-10-24 21:07:06 INFO getaddress] new peer discovered @ 103.99.171.211:48333
[2024-10-24 21:07:06 INFO getaddress] 52 non-unique peers in the db
[2024-10-24 21:07:15 INFO getaddress] starting handshake with 176.112.177.138:48333
[2024-10-24 21:07:15 INFO getaddress] successful handshake with 176.112.177.138:48333
[2024-10-24 21:07:15 INFO getaddress] new peer discovered @ 176.112.177.138:48333
[2024-10-24 21:07:16 INFO getaddress] starting handshake with 103.165.192.214:48333
[2024-10-24 21:07:17 INFO getaddress] successful handshake with 103.165.192.214:48333
[2024-10-24 21:07:17 INFO getaddress] new peer discovered @ 103.165.192.214:48333
^C[2024-10-24 21:07:19 INFO getaddress] received SIGINT. shutting down, this may take a while...
[2024-10-24 21:07:19 INFO getaddress] starting handshake with 2001:df6:7280::92:207:48333
[2024-10-24 21:07:19 INFO getaddress] successful handshake with [2001:df6:7280::92:207]:48333
[2024-10-24 21:07:19 INFO getaddress] new peer discovered @ [2001:df6:7280::92:207]:48333
[2024-10-24 21:07:19 INFO getaddress] 55 non-unique peers in the db
[2024-10-24 21:07:21 INFO getaddress] deduped peers list: from 55 to 44 peers
[2024-10-24 21:07:21 INFO getaddress] discovered unique 44 peers in 00h01m12s
[2024-10-24 21:07:21 INFO getaddress] looking up peer's ASNs...
[2024-10-24 21:07:21 INFO getaddress] peers ASNs filled!
[2024-10-24 21:07:21 INFO getaddress] 44 peers written to "output/testnet4/testnet4-20241024210608.txt"
[2024-10-24 21:07:21 INFO getaddress] done!

~$ cat output/testnet4/testnet4-2024102421021.txt
2.59.134.244:48333 / AS58212 / dataforest GmbH
18.189.156.102:48333 / AS16509 / AMAZON-02
45.142.17.140:48333 / AS206238 / Freedom Internet BV
50.126.96.22:48333 / AS20055 / AS-WHOLESAIL
89.117.52.73:48333 / AS51167 / Contabo GmbH
103.99.168.203:48333 / AS54415 / WIZ K.K.
103.99.168.204:48333 / AS54415 / WIZ K.K.
103.99.168.205:48333 / AS54415 / WIZ K.K.
103.99.168.207:48333 / AS54415 / WIZ K.K.
103.99.168.210:48333 / AS54415 / WIZ K.K.
103.99.168.212:48333 / AS54415 / WIZ K.K.
103.99.168.214:48333 / AS54415 / WIZ K.K.
103.99.171.204:48333 / AS54415 / WIZ K.K.
103.99.171.207:48333 / AS54415 / WIZ K.K.
103.99.171.208:48333 / AS54415 / WIZ K.K.
103.99.171.209:48333 / AS54415 / WIZ K.K.
103.99.171.212:48333 / AS54415 / WIZ K.K.
103.99.171.213:48333 / AS54415 / WIZ K.K.
103.99.171.214:48333 / AS54415 / WIZ K.K.
103.165.192.202:48333 / AS142052 / Mempool Space K.K.
103.165.192.207:48333 / AS142052 / Mempool Space K.K.
148.51.196.40:48333 / AS12025 / IMDC-AS12025
186.233.184.40:48333 / AS262287 / Latitude.sh LTDA
2001:df6:7280::92:204:48333 / AS142052 / Mempool Space K.K.
2001:df6:7280::92:208:48333 / AS142052 / Mempool Space K.K.
2001:df6:7280::92:211:48333 / AS142052 / Mempool Space K.K.
2001:df6:7280::92:212:48333 / AS142052 / Mempool Space K.K.
2401:b140:2::92:202:48333 / AS54415 / WIZ K.K.
...
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
- [X] Use GeoLite2-ASN.mmdb to determine AS's stakes in node hosting
- [ ] Export peer's user agent to file
- [ ] Add `addrv2` support
- [ ] Add Tor support
- [ ] Add I2P support
- [ ] Add CJDNS supoort
- [ ] Add Yggdrasil support
