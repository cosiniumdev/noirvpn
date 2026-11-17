# The userspace DCO interface

This document specifies the local socket protocol between noirvpn and a
userspace DCO (data channel offload) service. The service is a separate process
that runs the data channel: the tun device, the encryption and decryption of
data packets, replay protection, forwarding and keepalive. noirvpn keeps the
control channel (TLS, authentication, push, key negotiation) and the
configuration of the device through netlink.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119.
They state requirements on the service. "noirvpn" is the daemon in client or
server mode. Both modes use the same protocol.

Contents:

1. [Configuration](#1-configuration)
2. [Transport](#2-transport)
3. [Version and capabilities](#3-version-and-capabilities)
4. [Messages](#4-messages)
5. [The data channel](#5-the-data-channel)
6. [Sequences](#6-sequences)
7. [Security rules](#7-security-rules)
8. [Testing](#8-testing)

## 1. Configuration

| Option | Values | Default | Meaning |
|--------|--------|---------|---------|
| `datapath` | `userspace`, `udco`, `auto` | `userspace` | `udco`: the service runs the data channel. `auto`: the service when it is there and can handle the transport, else the noirvpn process. |
| `dco-socket PATH` | a file system path | `/run/udco/udco.sock` | The Unix socket of the service. |

```
datapath udco
dco-socket /run/udco/udco.sock
```

- When the service cannot be used, noirvpn runs the data channel in its own
  process and logs a warning.
- Client mode uses one peer and a point-to-point device. Server mode uses a
  multi-peer device.
- With `datapath udco`, a server has exactly one listening socket besides its
  `tls-server` listeners. Clients of the outer TLS transport never use the
  service.

## 2. Transport

### 2.1 The socket

- The service listens on a Unix domain socket of type `SOCK_SEQPACKET`. One
  message is one datagram.
- One connection controls one device. The service MAY accept several
  connections. A service that accepts one only MUST close a second connection
  cleanly and MUST NOT disturb the first.

### 2.2 Message header

Every message starts with an 8-byte header. The body follows it.

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 2 | `type` | The message type (section 4.1). |
| 2 | 2 | `flags` | Bit 0 (1) `F_REPLY`: a reply. Bit 1 (2) `F_FD`: a file descriptor is attached. Other bits MUST be 0 when sent and MUST be ignored when received. |
| 4 | 4 | `status` | Signed. In a reply: 0, or a negative errno. Else 0. |

A reply has the `type` of its request and `F_REPLY`. A reply never has `F_FD`.

### 2.3 Byte order and alignment

- Integers in the header and the body are in host byte order (little endian on
  x86-64 and arm64).
- Inside a socket address, the family is in host order. The port and the
  address are in network order.
- A body is the fields of its table, in order. Offsets in the tables are body
  offsets (add 8 for the message offset). Fields are naturally aligned. Padding
  MUST be sent as 0 and MUST be ignored.

### 2.4 Sizes

| Item | Value |
|------|-------|
| `MSG_MAX`: the largest message, header and body | 1024 bytes |
| `STREAM_REC_MAX`: the largest TCP record | 65535 bytes |
| `MSG_MAX_STREAM`: the largest `NEW_PEER` (TCP), `CTRL_TX` or `CTRL_RX` | 8 + 288 + 65535 = 65831 bytes |
| `LOG_MAX`: the largest log text, with its NUL | 512 bytes |
| `IFNAME_MAX`: the largest interface name, with its NUL | 16 bytes |

- Only `NEW_PEER` for a TCP peer, `CTRL_TX` and `CTRL_RX` may be longer than
  `MSG_MAX`. A receiver needs a buffer of `MSG_MAX_STREAM` bytes.
- A request body has exactly the size in this document (`NEW_PEER` for TCP and
  `CTRL_TX` have a tail). The service MUST reply `-EINVAL` to a request body
  that is shorter.
- A reply body may be longer or shorter than the layout. noirvpn reads a
  missing field as 0 and ignores extra bytes.

### 2.5 File descriptors and socket addresses

- Only `NEW_PEER` passes a descriptor: one `SCM_RIGHTS` descriptor in the same
  `sendmsg`, with `F_FD` set.
- The service MUST close an unexpected descriptor at once, and MUST NOT leak a
  descriptor on any error path.
- The service MUST check the socket type and reply `-EPROTONOSUPPORT` to a type
  it does not support.

A socket address is a `sockaddr_storage` of 128 bytes, aligned to 8 bytes:

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 2 | `family` | Host order. `AF_INET` = 2 or `AF_INET6` = 10. |
| 2 | 2 | `port` | Network order. |
| 4 | 4 | IPv4 address (`AF_INET`) | Network order. The rest is 0. |
| 4 | 4 | flow info (`AF_INET6`) | 0. |
| 8 | 16 | IPv6 address (`AF_INET6`) | Network order. |
| 24 | 4 | scope id (`AF_INET6`) | 0. |
| 28 | 100 | unused | 0. |

The service SHOULD accept an IPv4-mapped IPv6 remote address on a dual-stack
socket.

### 2.6 Requests and replies

- noirvpn has at most one request open. The service MUST read requests in
  order and MUST reply to each one before it reads the next.
- There are no sequence numbers. The service MUST send exactly one reply for
  each request, with the type of the request.
- A reply with a non-zero `status` has no body.
- noirvpn waits at most 10 seconds for a reply. The service MUST reply within a
  few seconds at most.

### 2.7 Messages without a request

The service MAY send these at any time, also between a request and its reply.
They have no `F_REPLY`.

| Type | Name | Purpose |
|------|------|---------|
| 64 | `EVENT` | A peer was removed, a peer moved, a key is nearly used up. |
| 65 | `LOG` | A line for the noirvpn log. |
| 66 | `CTRL_RX` | A control record from a TCP stream. |

- The service MUST keep `EVENT` and `CTRL_RX` in the order of what happened,
  for each peer.
- The service SHOULD NOT send faster than noirvpn reads, and SHOULD bound its
  own queues.

### 2.8 The life of a connection

The connection starts with `HELLO`. The service MUST reply `-EPROTO` to every
other request before a successful `HELLO`.

When the connection closes, for any reason, the service MUST:

1. stop all forwarding for the device;
2. remove every peer of the connection;
3. close every descriptor that it received on this connection, which closes
   the TCP connections;
4. remove the tun device;
5. wipe every key.

The service MUST NOT depend on a `CLOSE` or a `DEL_PEER` before the end.

### 2.9 Errors

The `status` of a reply is 0 or a negative Linux errno.

| Name | Value | Used for |
|------|-------|----------|
| `ENOENT` | -2 | No such peer, no such key, an empty slot. |
| `EIO` | -5 | General failure. |
| `EBUSY` | -16 | `OPEN` on a connection that has a device. |
| `EEXIST` | -17 | A device, a peer id or an address that exists. |
| `ENODEV` | -19 | A request that needs a device, before `OPEN`. |
| `EINVAL` | -22 | A bad field or a bad length. |
| `EPROTO` | -71 | A request before `HELLO`. |
| `EMSGSIZE` | -90 | A message or a record that is too long. |
| `EPROTONOSUPPORT` | -93 | A version, a socket type or a transport that the service does not support. |
| `EAFNOSUPPORT` | -97 | An address that is not IPv4 or IPv6. |
| `ENOBUFS` | -105 | Too many control records wait for a stream. |
| `ENOTCONN` | -107 | The TCP stream of the peer is closed. |

noirvpn treats every non-zero status as a failure, except:

- `DEL_KEY` and `KEY_DROP` with `ENOENT`;
- `DEL_PEER` with `ENOENT` or `ENOTCONN`;
- `CLOSE` with `ENOTCONN`;
- `CTRL_TX` with `ENOENT` or `ENOTCONN`.

A failure during the setup makes noirvpn run the data channel in its own
process. A failure of a key message, `SET_PEER` or `CTRL_TX` ends the session
of that peer.

## 3. Version and capabilities

The protocol version is **1**. noirvpn sends version 1 in `HELLO` and accepts
only version 1 in the reply. A service that does not speak the requested
version MUST reply `-EPROTONOSUPPORT`.

The `caps` field of the `HELLO` reply is a set of bits:

| Bit | Value | Name | What it promises |
|-----|-------|------|------------------|
| 0 | 1 | `CAP_KEY_TABLE` | `KEY_ADD`, `KEY_TX`, `KEY_DROP`: up to 8 keys per peer. |
| 1 | 2 | `CAP_STATS_REASONS` | The `PEER_STATS` reply has the drop reasons (128 bytes). |
| 2 | 4 | `CAP_TCP` | `NEW_PEER` takes a TCP stream. `CTRL_TX` and `CTRL_RX`. |
| 3 | 8 | `CAP_PEER_ID` | `SET_PEER_ID`. |
| 4 | 16 | `CAP_PEER_ADDR` | `SET_PEER_ADDR`. |
| 5 | 32 | `CAP_BLOCK_IPV6` | `SET_FILTER`: the service drops IPv6 at the device. |

- A service that sets a bit MUST implement the whole feature.
- A service MUST NOT set a bit that this document does not define.
- noirvpn sends a capability message only when the bit is set. A service that
  gets one anyway SHOULD reply `-EINVAL`.
- Without a capability, noirvpn falls back: two key slots without
  `CAP_KEY_TABLE`, a late TCP handover without `CAP_PEER_ID` or
  `CAP_PEER_ADDR`, and its own data path for TCP without `CAP_TCP` or for
  `block-ipv6` without `CAP_BLOCK_IPV6`.

The protocol grows this way: a message type and its request layout never
change. A new type comes with a new capability bit. A reply may grow at the
end, and a new field is 0 when it is not there.

## 4. Messages

### 4.1 Overview

Sizes are body sizes in bytes. "-" means no body.

| Type | Name | Direction | Request body | Reply body | Needs |
|------|------|-----------|--------------|------------|-------|
| 1 | `HELLO` | to service | 4 | 44 | |
| 2 | `OPEN` | to service | 32 | 8 | |
| 3 | `CLOSE` | to service | - | - | |
| 4 | `NEW_PEER` | to service | 288 (+ tail) | - | |
| 5 | `SET_PEER` | to service | 16 | - | |
| 6 | `DEL_PEER` | to service | 4 | - | |
| 7 | `DETACH` | to service | - | - | |
| 8 | `NEW_KEY` | to service | 164 | - | |
| 9 | `DEL_KEY` | to service | 8 | - | |
| 10 | `SWAP_KEYS` | to service | 4 | - | |
| 11 | `PEER_STATS` | to service | 4 | 128 | |
| 12 to 16 | `LINK_SET`, `ADDR_ADD`, `ADDR_DEL`, `ROUTE_ADD`, `ROUTE_DEL` | to service | 8, 44, 44, 48, 48 | - | not sent by noirvpn |
| 17 | `PING` | to service | - | - | |
| 18 | `KEY_ADD` | to service | 160 | - | `CAP_KEY_TABLE` |
| 19 | `KEY_TX` | to service | 8 | - | `CAP_KEY_TABLE` |
| 20 | `KEY_DROP` | to service | 8 | - | `CAP_KEY_TABLE` |
| 21 | `CTRL_TX` | to service | 4 + record | - | `CAP_TCP` |
| 22 | `SET_PEER_ID` | to service | 8 | - | `CAP_PEER_ID` |
| 23 | `SET_PEER_ADDR` | to service | 28 | - | `CAP_PEER_ADDR` |
| 24 | `SET_FILTER` | to service | 4 | 16 | `CAP_BLOCK_IPV6` |
| 64 | `EVENT` | to noirvpn | 144 | | |
| 65 | `LOG` | to noirvpn | 4 + text | | |
| 66 | `CTRL_RX` | to noirvpn | 4 + record | | `CAP_TCP` |

A service that does not implement the types 12 to 16 MUST still reply to them
with `F_REPLY` and a negative status, for example `-EINVAL`. Their layouts:
`LINK_SET` is `up`, `mtu` (`u32` each). `ADDR_ADD` and `ADDR_DEL` are `family`,
`plen`, `has_peer` (`u32` each), `addr` (16), `peer` (16). `ROUTE_ADD` and
`ROUTE_DEL` are `family`, `plen`, `has_gw`, `metric` (`u32` each), `dst` (16),
`gw` (16).

### 4.2 `HELLO` (1)

The first request of every connection.

Request (4 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `version` | 1. |

Reply (44 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `version` | 1. |
| 4 | 4 | `max_pairs` | The most worker pairs. noirvpn does not use it. |
| 8 | 32 | `daemon` | The name and version of the service, NUL-terminated. noirvpn logs it. |
| 40 | 4 | `caps` | The capability bits. A 40-byte reply reads as 0. |

Status: 0, or `-EPROTONOSUPPORT`.

### 4.3 `OPEN` (2) and `CLOSE` (3)

`OPEN` creates the tun device. Request (32 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 16 | `ifname` | The device name, NUL-terminated, 1 to 15 characters. |
| 16 | 4 | `dataplane` | 1: the OpenVPN data packet format. No other value is defined. |
| 20 | 4 | `mode` | 0: point to point (a new peer replaces the old one). 1: multi-peer. |
| 24 | 4 | `n_pairs` | Worker pairs. noirvpn sends 0: the service chooses. |
| 28 | 4 | `flags` | Bits, below. |

| Value | Name | Meaning |
|-------|------|---------|
| 1 | `OPT_NO_GSO` | Do not use UDP GSO. |
| 2 | `OPT_NO_GRO` | Do not use UDP GRO. |
| 4 | `OPT_PIN_CPUS` | Pin the workers to CPUs. noirvpn does not set it. |
| 8 | `OPT_FORCE_EVP` | Use the generic crypto library. noirvpn does not set it. |
| 16 | `OPT_NO_TUN_OFFLOAD` | Do not use the virtio-net offloads on the tun device. |
| 64 | `OPT_NO_C2C` | Reserved. noirvpn does not send it. |

The service MUST stop using an offload that a flag turns off, and MUST ignore
unknown bits.

Reply (8 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `ifindex` | The interface index. MUST NOT be 0. |
| 4 | 4 | `n_pairs` | Worker pairs started. noirvpn does not use it. |

Status: `-EEXIST` (the device name exists), `-EBUSY` (the connection has a
device), `-EINVAL` (a bad name, `dataplane` or `mode`), or another negative
errno.

- The device MUST be a layer 3 tun device (IP packets, no header).
- noirvpn sets the MTU, the transmit queue length, the addresses, the routes
  and the link state by `ifindex` through netlink. The service MUST NOT depend
  on these at the time of `OPEN`.

`CLOSE` (no body) removes the device and every peer, and allows a new `OPEN`.
Status 0, or a negative errno if there is no device.

### 4.4 Peer ids

- A peer has a 24-bit id, the same in both directions of the data packets.
- A service MUST accept every id from 0 to `0x00fffffe`, and SHOULD accept
  `0x00ffffff`. An id above `0x00ffffff` is `-EINVAL`.
- Two peers of one connection MUST NOT have the same id (`-EEXIST`).
- A TCP peer that reaches the service before its id is known has a provisional
  id from the top of the range. `SET_PEER_ID` sets the real id later.

### 4.5 `NEW_PEER` (4)

Adds a peer. Request (288 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `peer_id` | The id of the peer. |
| 4 | 4 | `flags` | Which optional fields are set. |
| 8 | 128 | `local` | Socket address: the local address of the peer's packets (`PEER_LOCAL`). |
| 136 | 128 | `remote` | Socket address: the endpoint of the peer (`PEER_REMOTE`). |
| 264 | 4 | `vpn4` | The tunnel IPv4 address of the peer (`PEER_VPN4`). |
| 268 | 16 | `vpn6` | The tunnel IPv6 address of the peer (`PEER_VPN6`). |
| 284 | 4 | (padding) | 0. |

| Value | Name |
|-------|------|
| 1 | `PEER_LOCAL` |
| 2 | `PEER_REMOTE` |
| 4 | `PEER_VPN4` |
| 8 | `PEER_VPN6` |

- A field that is not flagged is 0 and MUST be ignored. An unknown flag bit
  MUST give `-EINVAL`.
- A UDP service SHOULD send the packets of the peer from `local`. It MAY learn
  the local address from received datagrams, but MUST NOT change it for a
  packet that did not authenticate.

The descriptor:

- **UDP.** The bound, unconnected UDP socket of the data channel. The first
  `NEW_PEER` after `OPEN` or `DETACH` MUST pass it. In multi-peer mode, later
  peers share it. In point-to-point mode, every new peer passes a socket.
  noirvpn keeps its own descriptor of the socket for the control packets. The
  service MUST NOT close, shut down, rebind or reconfigure the socket for
  noirvpn. It MUST release its descriptor on `DETACH`, `CLOSE`, the end of the
  connection, and (point to point) when the last peer is deleted.
- **TCP** (`CAP_TCP`). A connected stream. The service owns the stream from the
  reply on. The bytes that noirvpn read and did not use (the read-ahead, up to
  65535 bytes, raw records with their length prefixes, maybe a partial record)
  follow the 288 bytes. The service MUST treat them as the first bytes of the
  stream. The service MUST hold its own descriptor before it replies.

Status:

| Status | When |
|--------|------|
| 0 | The peer exists. |
| `-EINVAL` | A bad id, an unknown flag, a missing or bad descriptor. |
| `-EEXIST` | Another peer has the id (multi-peer mode). |
| `-EAFNOSUPPORT` | An address that is not IPv4 or IPv6. |
| `-EPROTONOSUPPORT` | A socket that is not UDP or TCP, or TCP without `CAP_TCP`. |

### 4.6 `DEL_PEER` (6) and `DETACH` (7)

`DEL_PEER` (4 bytes: `peer_id`) removes the peer, wipes its keys and closes its
TCP stream. Status 0 or `-ENOENT`.

- The service SHOULD NOT send `PEER_DEL` for a peer that noirvpn deleted.
- The service SHOULD drop the events and records that it queued for the
  deleted peer. noirvpn may reuse the id.

`DETACH` (no body) makes the service release the UDP socket of the first
`NEW_PEER`. The next `NEW_PEER` passes a socket again. Status 0, also when the
service holds no socket.

### 4.7 `SET_PEER` (5)

Sets the keepalive timers and the MSS clamp of a peer. noirvpn MAY send it
again at any time. Request (16 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `peer_id` | The peer. |
| 4 | 4 | `keepalive_interval` | Seconds. 0: no keepalive packets. |
| 8 | 4 | `keepalive_timeout` | Seconds. 0: never end a silent peer. |
| 12 | 4 | `mss` | The TCP MSS clamp inside the tunnel. 0: no clamp. |

- After `keepalive_interval` seconds without a data packet sent to the peer,
  the service MUST send a keepalive packet (section 5.6).
- After `keepalive_timeout` seconds without an authenticated data packet from
  the peer, the service MUST remove the peer and send `PEER_DEL` with reason 2.
  Control packets do not count.
- `SET_PEER` restarts the receive clock. A peer has no timers before it.
- The service lowers the MSS option of inner TCP SYN segments, in both
  directions, to `mss` for IPv4 and `mss - 20` for IPv6, and fixes the
  checksum. A service MAY ignore `mss`.

Status: 0 or `-ENOENT`.

### 4.8 `SET_PEER_ID` (22) and `SET_PEER_ADDR` (23)

`SET_PEER_ID` (`CAP_PEER_ID`, 8 bytes) gives a peer a new id:

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `peer_id` | The current id. |
| 4 | 4 | `new_id` | The new id. |

- Keys, stream, counters and timers stay. The same id is a no-op.
- Status: 0, `-ENOENT` (no peer), `-EEXIST` (`new_id` in use), `-EINVAL`
  (`new_id` above `0x00ffffff`).
- After the reply, data packets with the old id are unknown. The service MUST
  NOT create a message with the old id after the rename. Messages queued
  before it may still carry the old id.

`SET_PEER_ADDR` (`CAP_PEER_ADDR`, 28 bytes) sets the tunnel addresses of a peer
after it exists:

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `peer_id` | The peer. |
| 4 | 4 | `flags` | `PEER_VPN4` (4) and `PEER_VPN6` (8). |
| 8 | 4 | `vpn4` | The IPv4 address. |
| 12 | 16 | `vpn6` | The IPv6 address. |

An address that `flags` does not specify is cleared. Status: 0, `-ENOENT`,
`-EEXIST` (another peer has the address), `-EINVAL` (another flag bit).

### 4.9 Keys

noirvpn negotiates the keys and sends them. The service never derives a key. A
key has a key id (0 to 7) and two halves: `enc` seals packets to the peer and
`dec` opens packets from the peer. Each half is a cipher key and an 8-byte
implicit IV.

| `cipher` | Name | `key_len` |
|----------|------|-----------|
| 0 | none: MUST be `-EINVAL` | |
| 1 | AES-GCM | 16, 24 or 32 |
| 2 | ChaCha20-Poly1305 | 32 |

Key fields are 64 bytes: the first `key_len` bytes are the key, the rest is 0.
The service MUST reply `-EINVAL` to a cipher or `key_len` it cannot use. The
service MUST NOT send a data packet to a peer that has no sealing key.

**Two slots (base protocol).** Slot 0 (primary) seals. Both slots open,
chosen by the key id of the packet.

`NEW_KEY` (164 bytes):

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 4 | `peer_id` |
| 4 | 4 | `slot` (0 or 1) |
| 8 | 4 | `key_id` (0 to 7) |
| 12 | 4 | `cipher` |
| 16 | 4 | `key_len` |
| 20 | 64 | `enc_key` |
| 84 | 8 | `enc_nonce` |
| 92 | 64 | `dec_key` |
| 156 | 8 | `dec_nonce` |

- `NEW_KEY` replaces the key of the slot. A new key starts with packet id 1 and
  an empty replay window. Status: 0, `-ENOENT`, `-EINVAL`.
- `SWAP_KEYS` (4 bytes: `peer_id`) exchanges the slots. Status 0, `-ENOENT`, or
  a negative status if slot 1 is empty.
- `DEL_KEY` (8 bytes: `peer_id`, `slot`) removes and wipes a key. `-ENOENT` if
  the peer or the slot is empty.

**Key table** (`CAP_KEY_TABLE`). Up to 8 keys, one per key id. Each key opens
packets with its id. The key that `KEY_TX` names seals.

`KEY_ADD` (160 bytes) is `NEW_KEY` without `slot`:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 4 | `peer_id` |
| 4 | 4 | `key_id` |
| 8 | 4 | `cipher` |
| 12 | 4 | `key_len` |
| 16 | 64 | `enc_key` |
| 80 | 8 | `enc_nonce` |
| 88 | 64 | `dec_key` |
| 152 | 8 | `dec_nonce` |

- `KEY_ADD` adds or replaces the key of that id, with a fresh counter and
  window. The key opens packets at once and does not seal until `KEY_TX`.
- `KEY_TX` (8 bytes: `peer_id`, `key_id`) names the sealing key. `-ENOENT` for
  an unknown peer or key id.
- `KEY_DROP` (8 bytes: `peer_id`, `key_id`) removes and wipes a key. If it was
  the sealing key, the service sends nothing to the peer until the next
  `KEY_TX` and counts the drops in `tx_drops` and `tx_no_key`.
- The service MUST NOT remove a key by itself, except when it removes the
  peer. A connection MAY mix slots and the table.

### 4.10 `PEER_STATS` (11)

Request (4 bytes): `peer_id`. Reply: 128 bytes with `CAP_STATS_REASONS`, else
80 bytes. All counters are `u64`, monotonic from the creation of the peer, and
`SET_PEER_ID` does not reset them.

| Offset | Field | Counts |
|--------|-------|--------|
| 0 | `vpn_rx_bytes` | Bytes of inner packets written to the tun device. |
| 8 | `vpn_tx_bytes` | Bytes of inner packets read from the tun device and sent to the peer. |
| 16 | `vpn_rx_packets` | Packets of `vpn_rx_bytes`. |
| 24 | `vpn_tx_packets` | Packets of `vpn_tx_bytes`. |
| 32 | `link_rx_bytes` | Bytes of data packets received. |
| 40 | `link_tx_bytes` | Bytes of data packets sent. |
| 48 | `link_rx_packets` | Data packets received. |
| 56 | `link_tx_packets` | Data packets sent. |
| 64 | `rx_drops` | All dropped packets from the peer. |
| 72 | `tx_drops` | All dropped packets to the peer. |
| 80 | `rx_no_key` | No key for the key id. Part of `rx_drops`. |
| 88 | `rx_replay` | Replayed or too old. Part of `rx_drops`. |
| 96 | `rx_auth` | Failed authentication. Part of `rx_drops`. |
| 104 | `rx_bad` | Authentic but not an IP packet. Part of `rx_drops`. |
| 112 | `tx_no_key` | Not sent for want of a key. Part of `tx_drops`. |
| 120 | `rx_src` | Multi-peer: a wrong inner source address. Part of `rx_drops`. |

noirvpn uses the `vpn_*` counters for `reneg-bytes` and `reneg-pkts`, so the
service MUST count them exactly. Status: 0 or `-ENOENT`.

### 4.11 `PING` (17)

No body. The service MUST reply at once with an empty reply (status 0).

### 4.12 TCP peers, `CTRL_TX` (21) and `CTRL_RX` (66)

With `CAP_TCP`, noirvpn passes a connected stream in `NEW_PEER` and never reads
or writes it again.

- **Early handover** (with `CAP_PEER_ID`, and on a server also
  `CAP_PEER_ADDR`): the stream goes to the service as soon as it exists, under
  a provisional id. The whole control channel goes through `CTRL_TX` and
  `CTRL_RX`.
- **Late handover** (otherwise): the stream goes to the service at the push
  reply (client) or at the login (server).

Framing is the OpenVPN TCP framing: a 2-byte length in network order, then a
record of 1 to 65535 bytes.

- A record whose first byte is `0x48` to `0x4f` (`P_DATA_V2`) is a data packet
  for the service.
- Every other record goes to noirvpn in `CTRL_RX`. The service does not look
  inside it, and does not forward a record of length 0.
- The service MUST NOT write anything to the stream except records.
- While the stream cannot take more, the service drops data packets (count
  `tx_drops`) and queues `CTRL_TX` records, up to 1 MiB per peer.
- The service sends `PEER_DEL` with reason 4 (EOF), 3 (stream error) or 2
  (keepalive).

`CTRL_TX` and `CTRL_RX` have the same body:

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `peer_id` | The peer. |
| 4 | n | `record` | One record without its length prefix, 1 to 65535 bytes. |

`CTRL_TX` is a request. The service MUST write the records in order, after the
records it queued before, and MUST NOT drop, merge, split or change one.

| Status | When |
|--------|------|
| 0 | Queued or written. |
| `-ENOENT` | No such peer. |
| `-ENOTCONN` | The stream is closed. A `PEER_DEL` follows or came. |
| `-ENOBUFS` | 1 MiB of control records waits already. |
| `-EMSGSIZE` | The record is empty or too long. |

`CTRL_RX` is sent without a request. The service MUST deliver the records of
one stream in the order they arrived.

### 4.13 `EVENT` (64)

Body (144 bytes):

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `kind` | Below. |
| 4 | 4 | `peer_id` | The peer. |
| 8 | 4 | `key_id` | `KEY_SWAP`: the key id. Else 0. |
| 12 | 4 | `reason` | `PEER_DEL`: the reason. Else 0. |
| 16 | 128 | `addr` | `PEER_FLOAT`: the new endpoint. Else 0. |

| `kind` | Name | Meaning |
|--------|------|---------|
| 1 | `PEER_DEL` | The service removed the peer by itself. |
| 2 | `PEER_FLOAT` | An authenticated data packet came from another address. |
| 3 | `KEY_SWAP` | The sealing key `key_id` is nearly used up. |

The service MUST NOT send kind 66. noirvpn ignores other unknown kinds.

| `reason` | Name | Meaning |
|----------|------|---------|
| 0 | `Teardown` | The service tore the peer down. |
| 1 | `Userspace` | noirvpn asked for it. |
| 2 | `Expired` | `keepalive_timeout` ran out. |
| 3 | `Transport_Error` | A TCP stream failed. |
| 4 | `Transport_Disconnect` | The other end closed the TCP stream. |

- The service MUST send `PEER_DEL` for the reasons 2, 3 and 4, and at most one
  `PEER_DEL` for a peer. noirvpn sends no `DEL_PEER` after it.
- `PEER_FLOAT` (UDP only): the service MUST send it when an authenticated,
  replay-checked data packet arrives from a new source address, and sends data
  there from then on.
- `KEY_SWAP`: the service sends it once for each key (section 5.5). noirvpn
  then starts a renegotiation.

### 4.14 `LOG` (65)

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 4 | `level` | 0 error, 1 warning, 2 info, 3 debug. |
| 4 | n | `text` | NUL-terminated, at most 512 bytes with the NUL. |

The message is as long as its text. noirvpn logs it with the prefix
"dco service: ". A log line MUST NOT hold key material or packet content.

### 4.15 `SET_FILTER` (24)

`CAP_BLOCK_IPV6`. It switches the IPv6 filter of the device and returns its
counters. Request (4 bytes): `flags`, bit 0 `FILTER_IPV6` (1) drops IPv6, 0 is
no filter.

Reply (16 bytes):

| Offset | Field | Counts |
|--------|-------|--------|
| 0 | `rx_v6` | IPv6 inner packets from peers, dropped before the tun write. |
| 8 | `tx_v6` | IPv6 packets from the tun device, dropped before the peer lookup. |

- While `FILTER_IPV6` is set, the service MUST drop every packet whose first
  nibble is 6, from the tun device and from peers. The check comes before the
  multi-peer source check.
- These drops count only in `rx_v6` and `tx_v6`. The service sends no ICMPv6.
- The filter stays until `SET_FILTER` with 0, `CLOSE` or the end of the
  connection. `OPEN` starts with the filter off and the counters at 0. The
  counters are totals since `OPEN`. noirvpn sends the same `flags` again to
  read them.
- Status: 0, `-ENODEV` (before `OPEN`), `-EINVAL` (another bit; the filter
  does not change).

## 5. The data channel

The packets are the OpenVPN 2.6 `P_DATA_V2` packets with AEAD ciphers, so a
service works with stock OpenVPN peers. The service uses only this baseline
AEAD format. There is no epoch format (noirvpn does not negotiate it when a
service owns the data channel), no CBC, no HMAC, no `P_DATA_V1`, no compression
and no fragmentation.

### 5.1 The packet

Multi-byte fields are big endian.

| Offset | Length | Field | Meaning |
|--------|--------|-------|---------|
| 0 | 1 | `op/kid` | `0x48 + key_id`: opcode 9 in the high 5 bits, the key id in the low 3 bits. |
| 1 | 3 | `peer-id` | The 24-bit peer id. |
| 4 | 4 | `packet-id` | The first packet of a key has id 1. |
| 8 | 16 | `tag` | The AEAD tag, **before** the ciphertext. |
| 24 | n | `ciphertext` | The same length as the plaintext. |

- The associated data is the first 8 bytes as on the wire.
- The nonce is `packet-id` (4 bytes, big endian) followed by the 8-byte
  implicit IV (`enc_nonce` to seal, `dec_nonce` to open).
- AES-GCM uses the standard 96-bit nonce. ChaCha20-Poly1305 is RFC 8439. Both
  have a 16-byte tag.
- A valid packet has at least 25 bytes. A sender never sends an empty
  plaintext.

### 5.2 Sending

1. Take the sealing key. If there is none, drop and count `tx_drops` and
   `tx_no_key`.
2. Take the next packet id of the key, starting at 1.
3. Seal and write `AD || tag || ciphertext`.
4. On UDP, send one datagram to the peer endpoint from the passed socket. On
   TCP, send one record with its length prefix.

The service MUST NEVER use a packet id twice with one key. The counter never
wraps and never goes back.

### 5.3 Receiving and the replay window

1. Drop a packet shorter than 25 bytes (`rx_bad`).
2. Find the peer by peer id, and the key by key id. Drop an unknown peer. Drop
   an unknown key (`rx_no_key`).
3. Open the packet. Drop a tag failure (`rx_auth`).
4. **Only after** a good tag, check the replay window. Drop a failure
   (`rx_replay`).
5. Only then update the window, the receive time for `keepalive_timeout`, and
   on UDP the endpoint (float).
6. Handle the plaintext (section 5.4).

The replay window is per key and direction. With `h` the highest accepted id,
`p` the packet id and `w` the window size:

| Case | Action |
|------|--------|
| `p == 0` | drop |
| `p > h` | accept, `h = p` |
| `h - p >= w` | drop |
| `h - p < w` | accept if not seen yet and mark it, else drop |

`w` MUST be at least 64. A larger window (for example 2048) is RECOMMENDED.

### 5.4 The plaintext

| Plaintext | Action |
|-----------|--------|
| Exactly the 16-byte keepalive magic | Do not write it to the tun device. It counts as received for the timeout, not in `vpn_rx_*`. |
| First nibble 6 and `FILTER_IPV6` set | Drop, count `rx_v6`. |
| First nibble 4 or 6 | In multi-peer mode, check the source. Write it to the tun device. Count `vpn_rx_*`. |
| Anything else (also OCC messages) | Drop, count `rx_bad`. |

The keepalive magic is `2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f c7 48`. A
keepalive is a normal data packet with a normal packet id and tag.

### 5.5 Key lifetime and exhaustion

- The service MUST be able to open packets with a new key at once.
- It seals with a new key only from `KEY_TX` or `SWAP_KEYS`.
- The old key opens packets until noirvpn removes it. The service MUST NOT
  remove a key on its own timer.

| Limit | Rule |
|-------|------|
| Packet id of the sealing key | The service MUST send `KEY_SWAP` before `0xFFFFFFFF`, and SHOULD send it at `0xFF000000`. At the limit it MUST stop sealing with the key. |
| AES-GCM usage | SHOULD send `KEY_SWAP` at 7/8 of 2^36 - 1 "blocks plus packets" (60129542137) per key and direction. A packet counts `ceil((payload + 24) / 16)` blocks. |
| Failed tag checks of a receive key | Above 2^35: SHOULD send `KEY_SWAP`. Above 2^36: SHOULD drop the key's packets without trying them. |

### 5.6 Keepalive

- Send: after `keepalive_interval` seconds with no data packet sent, send one
  keepalive packet.
- Receive: after `keepalive_timeout` seconds with no authenticated data packet
  (traffic or keepalive), remove the peer and send `PEER_DEL` reason 2.
- noirvpn runs no keepalive of its own for a peer of the service.

### 5.7 Control packets on the UDP socket

The UDP socket carries data packets and control packets.

- The service MUST handle the data packets (opcode 9) of its peers.
- The service MUST NOT consume, delay or reply to any other packet. noirvpn
  reads them on its own descriptor.
- The service MUST NOT send anything but data packets on the socket.
- A data packet never creates a peer.

A RECOMMENDED way on Linux: join your own sockets to the passed socket in a
`SO_REUSEPORT` group (create them as the user that owns the passed socket),
and attach a classic BPF program (`SO_ATTACH_REUSEPORT_CBPF`) that returns
index 0 (the passed socket) for every packet whose first byte shifted right
by 3 is not 9. Read and send data packets only on your sockets, and close them
when you stop using the passed socket.

### 5.8 Float

An authenticated, replay-checked data packet from a new source address moves
the peer. The service processes the packet, sends data to the new address from
then on, and sends `PEER_FLOAT`. A packet that did not authenticate MUST NOT
move a peer. A service SHOULD NOT move a peer to the address of another peer.

### 5.9 Multi-peer forwarding

From the tun device, the service finds the peer of an inner packet:

1. the peer whose `vpn4` or `vpn6` is the destination;
2. else the peer whose tunnel address is the gateway of the kernel route for
   the destination on this device (noirvpn installs a route for each `iroute`
   network of a client);
3. else drop.

From a peer, the inner source address MUST be the tunnel address of the peer
or in a network behind it. Else the service drops the packet (`rx_src`). The
service does not forward between peers itself. It writes the packet to the tun
device, and the kernel routes it.

### 5.10 Sizes

- One inner packet becomes one data packet, 24 bytes longer. noirvpn sets the
  device MTU so that it fits.
- The service MUST NOT send an inner packet larger than the device MTU. With
  tun or UDP offloads on, it MUST segment a large packet before it seals.

## 6. Sequences

`N` is noirvpn and `S` is the service. `>` is a request, `<` its reply, `<<` a
message without a request.

Connect:

```
N > HELLO(version 1)
S < HELLO(version 1, max_pairs, daemon, caps)
```

Client, UDP:

```
N: TLS handshake on its UDP socket, reads the push reply
N > OPEN(ifname, mode 0, flags)                  (if there is no device yet)
S < OPEN(ifindex)
N: sets MTU, addresses, routes, link up by ifindex
N > NEW_PEER(pushed id, PEER_REMOTE|PEER_VPN4|PEER_VPN6, F_FD = UDP socket)
N > KEY_ADD(key 0) ; KEY_TX(0)                    (or NEW_KEY slot 0)
N > SET_PEER(interval, timeout, mss)
N > SET_FILTER(FILTER_IPV6)                       (with block-ipv6)
```

Client, TCP, early handover:

```
N > OPEN(mode 0)
N > NEW_PEER(provisional id, PEER_REMOTE, F_FD = stream, tail = read-ahead)
N > CTRL_TX(hard reset) ; S << CTRL_RX(...)       (the whole handshake)
N > KEY_ADD / KEY_TX                              (under the provisional id)
N > SET_PEER_ID(provisional id, pushed id)
N > SET_PEER(...)
```

Server, UDP:

```
N > OPEN(ifname, mode 1, flags)                   (before the listener opens)
N: a client logs in on the listener
N > NEW_PEER(id, PEER_REMOTE|[PEER_LOCAL]|PEER_VPN4|PEER_VPN6, F_FD = listener for the first peer only)
N > KEY_ADD / KEY_TX                              (or NEW_KEY)
N > SET_PEER(...)
N: adds iroute routes, sends the push reply
```

Server, TCP, early handover:

```
N > NEW_PEER(provisional id, PEER_REMOTE|[PEER_LOCAL], F_FD = stream)
N > CTRL_TX ; S << CTRL_RX                        (the handshake)
N > SET_PEER_ID(provisional id, id) ; SET_PEER_ADDR(id, addresses) ; SET_PEER(...)
N > CTRL_TX(push reply)
```

Rekey with the key table, and with two slots:

```
N > KEY_ADD(new id)      N > DEL_KEY(slot 1)       (only if slot 1 is full)
N > KEY_TX(new id)       N > NEW_KEY(slot 1, new id)
N > KEY_DROP(old id)     N > SWAP_KEYS
                         N > DEL_KEY(slot 1)       (when the old key may no longer open)
```

Removing a peer:

```
N > DEL_PEER(peer)                                (noirvpn removes it)
S << EVENT(PEER_DEL, peer, reason 2|3|4)          (the service removes it)
```

Shutdown:

```
Client: PEER_STATS ; DEL_PEER ; CLOSE (not with persist-tun) ; close
Server: PEER_STATS and DEL_PEER for each client ; DETACH (UDP) ; close
```

## 7. Security rules

The service holds the data keys of every peer and sees all traffic in clear
text. Treat it as the most sensitive part of the VPN.

**The socket**

- The service MUST create the socket in a directory that only trusted users
  can write to, with a mode that only trusted users can use (for example
  `0600`, or `0660` with a dedicated group).
- It MUST remove a stale socket file only if nothing listens on it, and MUST
  NOT follow a symbolic link at the socket path.
- It SHOULD read the credentials of each connection (`SO_PEERCRED`) and accept
  only allowed user ids (by default root).
- noirvpn does not check who owns the socket. The operator MUST make sure that
  only trusted users can create the `dco-socket` path.

**Keys**

- The service MUST wipe a key, its IVs and every derived structure when the key
  is replaced or removed, its peer is removed, or the connection ends. The
  wipe MUST NOT be optimised away. It MUST also wipe the buffer of a key
  message after use.
- It MUST NOT write a key, an IV or packet content to a log, a core dump, a
  file or swap. It SHOULD `mlock` key memory and SHOULD disable core dumps.
- It MUST NOT keep a key after its peer is removed, and MUST NOT send a key to
  anyone.

**Validation and resources**

- Check every length, id, enum value and flag. Never read beyond the message.
  Reply `-EINVAL` to a bad value.
- Check the type and family of every received descriptor. Close a descriptor
  that comes with a refused message or a message that takes none.
- Bound the number of peers, every queue, and the control records (1 MiB per
  peer). A limit MUST give an error or end the peer.
- Do not allocate memory or keep state for unauthenticated packets. Rate-limit
  log lines about bad packets.
- Never block all peers for one slow stream, one slow reader or one full
  queue.

**Behaviour**

- Never send a data packet with a key that has no unused packet id.
- Never take control packets from the UDP socket, and send only data packets on
  the passed sockets.
- Never use a descriptor after you released it.
- Never open the tun device for another process, and never create a device
  that noirvpn did not ask for.

## 8. Testing

1. Start the service. Set `datapath udco` and `dco-socket PATH` in the noirvpn
   config. Use `udco`, not `auto`: `auto` silently falls back. Run with
   `verb 2` or higher.
2. A client logs these lines when it uses the service:

   ```
   DCO service at PATH: NAME
   noirvpn VERSION starting (pid N), 1 remote(s), verb 2, datapath udco
   tun device tunX (index N) created by the DCO service
   DCO peer ID: keepalive I/T s
   ```

3. The status and the [management interface](management.md) report the data
   path as `udco` (`userspace` after a fallback).
4. Check traffic, counters, rekey (`reneg-sec 60`), keepalive (`PEER_DEL`
   reason 2), replay and tamper (`rx_replay`, `rx_auth`), and a service stop
   while noirvpn runs. Connect to and from stock OpenVPN 2.6 or 2.7 peers.

The message types, layouts and constants are in `platform/dco/proto.odin` in
the source tree. If this document and the code differ, the code is right.
