getaddress
---

Builds a list of reachable Bitcoin nodes by impersonating one and continuously sending `getaddr` messages to other known nodes.

Supports all networks: `mainnet`, `testnet4`, `signet`, `regtest`.

Takes a while: a handshake must be made with a potential peer in order for it to be considered valid and added to the list.

Usage
---

```
~$ just crawl testnet4
[2025-03-18 21:59:57 INFO getaddress::network] found 34 potential seed nodes, making handshakes...
[2025-03-18 21:59:57 INFO getaddress::network] [thread 0] starting handshake with 103.99.168.208:48333
[2025-03-18 21:59:57 INFO getaddress::network] [thread 0] successful handshake with 103.99.168.208:48333
[2025-03-18 21:59:57 INFO getaddress::network] [thread 0] starting handshake with 209.146.50.202:48333
[2025-03-18 21:59:57 INFO getaddress::network] [thread 0] successful handshake with 209.146.50.202:48333
[2025-03-18 21:59:58 INFO getaddress::network] [thread 0] starting handshake with 77.247.127.71:48333
[2025-03-18 21:59:58 INFO getaddress::network] [thread 0] successful handshake with 77.247.127.71:48333
[2025-03-18 21:59:58 INFO getaddress::network] [thread 0] starting handshake with 199.119.138.36:48333
[2025-03-18 21:59:58 INFO getaddress::network] [thread 0] successful handshake with 199.119.138.36:48333
[2025-03-18 21:59:58 INFO getaddress::network] [thread 0] starting handshake with 80.253.94.252:48333
[2025-03-18 22:00:02 INFO getaddress::network] successful handshakes with 10 seed nodes
[2025-03-18 22:00:02 INFO getaddress] using 10 peers from seed nodes as bootstrap peers
[2025-03-18 22:00:02 INFO getaddress] starting crawl from 10 bootstrap peers
[2025-03-18 22:00:02 INFO getaddress] creating thread pool with 6 threads
[2025-03-18 22:00:02 INFO getaddress::network] [thread 0] starting handshake with 45.41.204.28:48333
...
[2025-03-18 22:01:48 INFO getaddress] discovered 29 unique peers in 00:01:51
[2025-03-18 22:01:49 INFO getaddress::network] [thread 1] starting handshake with 103.99.168.209:48333
[2025-03-18 22:01:49 INFO getaddress::network] [thread 5] starting handshake with 209.146.50.202:48333
[2025-03-18 22:01:49 INFO getaddress::network] [thread 1] successful handshake with 103.99.168.209:48333
[2025-03-18 22:01:49 INFO getaddress::network] [thread 5] successful handshake with 209.146.50.202:48333
[2025-03-18 22:01:52 INFO getaddress::network] [thread 0] starting handshake with 209.146.51.204:48333
[2025-03-18 22:01:53 INFO getaddress::network] [thread 0] successful handshake with 209.146.51.204:48333
[2025-03-18 22:01:53 INFO getaddress] discovered 30 unique peers in 00:01:56
[2025-03-18 22:01:53 INFO getaddress::network] [thread 2] starting handshake with 103.99.171.209:48333
[2025-03-18 22:01:53 INFO getaddress::network] [thread 2] successful handshake with 103.99.171.209:48333
[2025-03-18 22:01:55 INFO getaddress] discovered 31 unique peers in 00:01:58
[2025-03-18 22:01:55 INFO getaddress::network] [thread 1] starting handshake with 103.99.168.209:48333
[2025-03-18 22:01:55 INFO getaddress::network] [thread 1] successful handshake with 103.99.168.209:48333
^C[2025-03-18 22:02:01 INFO getaddress] Received SIGINT: shutting down, this may take a while...
[2025-03-18 22:02:03 INFO getaddress] discovered 32 unique peers in 00:02:05
[2025-03-18 22:02:03 INFO getaddress::util] filling up peer ASNs
[2025-03-18 22:02:03 INFO getaddress::util] peer ASNs filled
[2025-03-18 22:02:03 INFO getaddress] AS node hosting stakes:
[2025-03-18 22:02:03 INFO getaddress]  AS142052 Mempool Space K.K.: 7 (21.88%)
[2025-03-18 22:02:03 INFO getaddress]  AS54415 WIZ K.K.: 6 (18.75%)
[2025-03-18 22:02:03 INFO getaddress]  AS174 COGENT-174: 4 (12.50%)
[2025-03-18 22:02:03 INFO getaddress]  AS16276 OVH SAS: 4 (12.50%)
[2025-03-18 22:02:03 INFO getaddress]  AS24940 Hetzner Online GmbH: 3 (9.38%)
[2025-03-18 22:02:03 INFO getaddress]  AS51167 Contabo GmbH: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS400810 BREEZETECH: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS49505 JSC Selectel: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS0 NO DATA: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS63949 Akamai Connected Cloud: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS833 SWN-AS: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS212477 RoyaleHosting BV: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS20278 NEXEON: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS216382 Layer Marketing Services L.L.C: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS197540 netcup GmbH: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS18450 WEBNX: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS32489 AMANAHA-NEW: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress]  AS16509 AMAZON-02: 2 (6.25%)
[2025-03-18 22:02:03 INFO getaddress] 32 peers written to "output/testnet4/testnet4-20250318215957.txt"
[2025-03-18 22:02:03 INFO getaddress] done!

~$ cat output/testnet4/testnet4-20250318215957.txt
3.250.145.197:48333 / AS16509 / AMAZON-02
5.182.4.106:48333 / AS49505 / JSC Selectel
37.187.149.92:48333 / AS16276 / OVH SAS
45.94.168.5:48333 / AS400810 / BREEZETECH
51.81.245.218:48333 / AS16276 / OVH SAS
57.128.176.163:48333 / AS16276 / OVH SAS
77.247.127.71:48333
89.117.50.252:48333 / AS51167 / Contabo GmbH
95.217.106.33:48333 / AS24940 / Hetzner Online GmbH
103.99.168.209:48333 / AS54415 / WIZ K.K.
103.99.168.212:48333 / AS54415 / WIZ K.K.
103.99.168.214:48333 / AS54415 / WIZ K.K.
103.99.169.201:48333 / AS54415 / WIZ K.K.
103.99.171.205:48333 / AS54415 / WIZ K.K.
103.165.192.202:48333 / AS142052 / Mempool Space K.K.
103.165.192.203:48333 / AS142052 / Mempool Space K.K.
103.165.192.204:48333 / AS142052 / Mempool Space K.K.
103.165.192.205:48333 / AS142052 / Mempool Space K.K.
103.165.192.208:48333 / AS142052 / Mempool Space K.K.
103.165.192.211:48333 / AS142052 / Mempool Space K.K.
104.237.131.138:48333 / AS63949 / Akamai Connected Cloud
107.175.40.61:48333 / AS20278 / NEXEON
108.171.193.104:48333 / AS18450 / WEBNX
138.199.156.168:48333 / AS24940 / Hetzner Online GmbH
165.140.203.156:48333 / AS833 / SWN-AS
172.93.167.89:48333 / AS32489 / AMANAHA-NEW
185.198.234.15:48333 / AS212477 / RoyaleHosting BV
185.232.70.226:48333 / AS197540 / netcup GmbH
199.119.138.36:48333 / AS216382 / Layer Marketing Services L.L.C
209.146.50.202:48333 / AS174 / COGENT-174
209.146.51.203:48333 / AS174 / COGENT-174
209.146.51.204:48333 / AS174 / COGENT-174
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
