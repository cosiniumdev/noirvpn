# platform/dco

The data channel backends of the daemon.

| File | Backend |
|------|---------|
| `socket_linux.odin`, `proto.odin` | the DCO service on a Unix socket |
| `kernel_linux.odin`, `kernel_proto.odin` | the Linux `ovpn` driver (kernel 6.16 and later) |
| `backend.odin` (`in_process`) | a data channel in this process that a build may provide |
| `none.odin` | the stub of the other systems: each connect fails, so the daemon uses the userspace data path |

## The hook for a data channel in this process

`dco.in_process` holds three fields: `make`, `destroy` and `name`. 
An implementation can fill them in an `@(init)` procedure.
When `in_process_ready` is true, the daemon uses the in-process backend
with the configuration set to `datapath udco`, or for `auto` no `dco-socket`
is specified.

Rules for in-process backend:

- Implement the same return codes and events as the socket service (`docs/dco-interface.md`).
- `fd` is valid from `make()`. The daemon calls `next_event` when it is readable.
- `log` is called only inside the calls of the backend, on the daemon's thread.
- `attach` is optional. The server calls it with its UDP socket before it drops
  root, so that the backend can bind its own sockets to the same port (a port
  below 1024 needs root).
- `key_install` is optional and needs `CAP_KEY_TABLE`. With it the daemon will
  pass the key material, the cipher, the data format and the rekey policy.
  The backend is to apply the usage limits of the cipher and the
  format and send `Key_Swap`.
- `epoch_keys`: `key_install` also takes the epoch data format. Then the client
  offers that format and the server pushes `aead-epoch`, as on the userspace data
  path. `epoch_stats` (optional) gives the epoch counters for the status. Without
  the flag every session on the backend uses the baseline format.

## The kernel backend

`kernel_connect` returns `ENO_OVPN` when the kernel has no `ovpn` family. It implements
the calls into the Linux ovpn DCO driver for peer and key configuration.

Limits:

- No key table: `CAP_KEY_TABLE` is not set, the daemon uses the two key slots.
- No `set_peer_id` and `set_peer_addr` (they return `ENOTSUP`). A peer is initialized once,
  with its final id and, in MP mode, its tunnel address.
- Keepalive only. The kernel has no `ping-exit`, `inactive` or epoch keys.
- `mssfix` is not applied (`mss_clamp` is false).
- A P2P device holds one peer.
- The daemon sets address, MTU and up by interface index with `platform/sysnet`.
- It needs `CAP_NET_ADMIN`.

The tests that need no module are in `kernel_linux_test.odin` and
`kernel_proto_test.odin`. The rest is proven with `cmd/dcoktest` on two hosts.
