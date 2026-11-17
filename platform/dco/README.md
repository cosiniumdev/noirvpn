# platform/dco

The data channel backends of the daemon. One `Backend` interface, two implementations,
and a hook for a third.

| File | Backend |
|------|---------|
| `socket_linux.odin`, `proto.odin` | the DCO service on a Unix socket |
| `kernel_linux.odin`, `kernel_proto.odin` | the Linux `ovpn` driver (kernel 6.16 and later) |
| `backend.odin` (`in_process`) | a data channel in this process that a build may provide; empty in this tree |
| `none.odin` | the stub of the other systems: each connect fails, so the daemon uses the userspace data path |

## The hook for a data channel in this process

`dco.in_process` holds three fields: `make`, `destroy` and `name`. They are empty, and
no package in this tree fills them. A build can fill them in an `@(init)` procedure.
Then `in_process_ready` is true, and the daemon uses that backend (kind `In_Process`)
for `datapath udco`, and for `auto` after the kernel, when the config has no
`dco-socket`. With a `dco-socket` in the config the daemon uses the socket service.

Rules for such a backend:

- It gives the same return codes and events as the socket service
  (`docs/dco-interface.md`) for the calls that the daemon makes, and it
  sets `caps` as a service sets its HELLO reply.
- `fd` is valid from `make` on. The daemon calls `next_event` when it is readable.
- `log` is called only inside the calls of the backend, on the daemon's thread.
- `attach` is optional. The server calls it with its UDP socket before it drops
  root, so that the backend can bind its own sockets to the same port (a port
  below 1024 needs root). The first `new_peer` passes the same socket again.
- `key_install` is optional and needs `CAP_KEY_TABLE`. With it the daemon gives
  the key material, the cipher, the data format and the rekey policy in place of
  the wire `Key`. The backend applies the usage limits of the cipher and the
  format and sends `Key_Swap`; the time, byte and packet limits stay with the
  daemon.
- `epoch_keys`: `key_install` also takes the epoch data format. Then the client
  offers that format and the server pushes `aead-epoch`, as on the userspace data
  path. `epoch_stats` (optional) gives the epoch counters for the status. Without
  the flag every session on the backend uses the baseline format.

## The kernel backend

`kernel_connect` returns `ENO_OVPN` when the kernel has no `ovpn` family. Then the
daemon uses another backend. `kernel_backend` fills a `Backend` for a connected `Kernel`.

What it does:

- Makes the device by rtnetlink (`kernel_open_device`) and removes a stale device of
  the same name and kind `ovpn`.
- Sends the generic netlink commands for peers and keys, and keeps the extended-ack
  text of the last failure (`err_text`).
- Reads the `peers` notifications and turns them into events: `Peer_Del` with its
  reason, `Key_Swap`.
- Duplicates every socket it is given. The caller closes its own copy.
- Hands a TCP stream to the kernel, with the bytes read ahead (`new_peer_stream`).
  Control records of the stream arrive as `Ctrl_Rx` events. `ctrl_tx` frames and
  queues a control record.
- Detects a float by `PEER_GET` in `stats` and queues `Peer_Float`.
- Gives the daemon one descriptor (`Backend.fd`, an epoll descriptor) to watch.
  When it is readable the daemon calls `next_event` until it returns 0.

Limits:

- No key table: `CAP_KEY_TABLE` is not set, the daemon uses the two key slots.
- No `set_peer_id` and `set_peer_addr` (they return `ENOTSUP`). A peer is made once,
  with its final id and, in MP mode, its tunnel address.
- Keepalive only. The kernel has no `ping-exit`, `inactive` or epoch keys.
- `mssfix` is not applied (`mss_clamp` is false).
- A P2P device holds one peer.
- It does not bring the device up. The daemon sets address, MTU and up by interface
  index with `platform/sysnet`.
- It needs `CAP_NET_ADMIN`.

The tests that need no module are in `kernel_linux_test.odin` and
`kernel_proto_test.odin`. The rest is proven with `cmd/dcoktest` on two hosts.
