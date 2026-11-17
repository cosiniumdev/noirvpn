// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package dco

import "noir:proto/keys"
import "noir:proto/ossl"

// Backend data-channel interface for the daemon. Kinds:
//   socket_linux.odin - unix socket client
//   kernel_linux.odin - kernel `ovpn` driver
//   `in_process` below - data channel in this process (a build may add it)
// Argument types are wire structs of proto.odin; a non-socket backend reads
// the fields it needs. Every proc returns 0 or a negative errno.
// `user` is the backend's own pointer.
//
Backend_Kind :: enum {
	Service, // the userspace DCO service on a Unix socket
	Kernel, // the Linux `ovpn` driver
	In_Process, // a data channel in this process that a build may provide (`in_process`)
}

// Hook for a data channel in this process. A build may provide it.
// - Empty unless a package fills it in its `@(init)`.
// - Same results, return codes and events as the socket service.
//
//   make     new backend, no device yet; 0 or negative errno. `log` runs only
//            inside backend calls, on the daemon's thread
//   destroy  frees what `make` created (device, peers), like a closed connection
//   name     what the log and `--version` call it
//
// The daemon calls `make` and the backend on its main thread, which keeps the
// privileges left after start-up.
In_Process :: struct {
	make:    proc(log: Log_Proc, log_user: rawptr) -> (b: Backend, status: int),
	destroy: proc(b: ^Backend),
	name:    string,
}

in_process: In_Process

// Is there a data channel in this process?
in_process_ready :: proc "contextless" () -> bool {
	return in_process.make != nil && in_process.destroy != nil
}

// Data key from key material, for `Backend.key_install`.
// - The backend builds the key of `format` itself.
// - Epoch format needs the root keys of both chains; wire `Key` has no room.
// - `material` is valid during the call only; the caller wipes it.
Key_Install :: struct {
	peer_id:  u32,
	key_id:   u32, // 0..7
	cipher:   ossl.Aead_Cipher,
	format:   keys.Format,
	material: ^keys.Key_Material,
	// When the key is used up: the backend applies the cipher and format limits
	// (`limit_override` included) and sends `Key_Swap` when a rekey is due.
	// Time, byte and packet limits stay with the daemon.
	policy:   keys.Rekey_Policy,
}

// Epoch format of a peer (`Backend.epoch_stats`): moves of its send and
// receive epoch for all keys since the peer was created, plus the epochs of the
// key that sends now (0: none, or baseline format).
Epoch_Stats :: struct {
	tx_advances: u64,
	rx_advances: u64,
	tx_epoch:    u16,
	rx_epoch:    u16,
}

// The calls block until the backend has responded. Events and log lines that
// come in meanwhile are queued (events) or passed on (log lines), never lost.
Backend :: struct {
	user:       rawptr,
	kind:       Backend_Kind,
	// The descriptor that the daemon's event loop watches for "readable". When it is
	// readable the daemon calls `next_event` until that returns 0.
	fd:         i32,
	// Does `set_peer` apply `mss`? The kernel driver cannot: it returns 0 and does
	// nothing with it.
	mss_clamp:  bool,
	// The text the backend has for its last failed call (the extended ack of the
	// kernel), or "". Valid until the next call.
	err_text:   proc(user: rawptr) -> string,
	// `CAP_*` of the service, from its HELLO reply. With `CAP_KEY_TABLE` the keys go
	// by `key_add`, `key_tx` and `key_drop`; without it by the two slots.
	caps:       u32,
	// Creates the device `name` (it must not exist). The daemon never reads or
	// writes the device; it only configures it (address, MTU, routes) by index.
	open:       proc(user: rawptr, name: string, mode: Mode, flags: u32) -> (ifindex: u32, status: int),
	// Removes the device and every peer.
	close:      proc(user: rawptr) -> int,
	// `fd` is the bound UDP socket of the data channel, or -1: the first peer
	// after `open` or `detach` must pass it, later ones may omit it.
	new_peer:   proc(user: rawptr, p: ^New_Peer, fd: i32) -> int,
	// Optional (nil: absent). Takes the bound UDP socket `fd` before the first
	// peer. The server calls it before it drops root, so the backend can bind
	// its own sockets below port 1024. `fd` is valid only in the call. The first
	// `new_peer` passes the same socket again; the backend does nothing more.
	attach:     proc(user: rawptr, fd: i32) -> int,
	// TCP peer (`CAP_TCP`). `fd` is the connected stream; the backend owns it
	// from the call on, the caller closes its copy. `ahead`: bytes read, unused.
	new_peer_stream: proc(user: rawptr, p: ^New_Peer, fd: i32, ahead: []u8) -> int,
	// A control record for the stream of a TCP peer, without its length prefix.
	ctrl_tx:    proc(user: rawptr, peer_id: u32, rec: []u8) -> int,
	// The control record of the `Ctrl_Rx` event that `next_event` gave last.
	ctrl_record: proc(user: rawptr) -> []u8,
	// New peer id (`CAP_PEER_ID`). Keys, stream, counters, keepalive stay.
	// Messages queued earlier carry the old id and may arrive after the call,
	// so the caller accepts both ids for a while.
	// EEXIST: `new_id` is another peer's. EINVAL: above `PEER_ID_LIMIT`.
	set_peer_id: proc(user: rawptr, peer_id, new_id: u32) -> int,
	// VPN addresses of a peer (`CAP_PEER_ADDR`), set after it exists, like
	// `vpn4` and `vpn6` of `New_Peer`. Addresses not named by `a.flags` are
	// cleared. EEXIST: another peer has an address.
	set_peer_addr: proc(user: rawptr, a: ^Set_Peer_Addr) -> int,
	// Device packet filter (`CAP_BLOCK_IPV6`): `flags` (`FILTER_*`) are on from
	// now on. `out` gets device counters since `open`. ENOTSUP without the
	// capability.
	set_filter: proc(user: rawptr, flags: u32, out: ^Filter_Stats) -> int,
	// Optional (nil: absent; only in-process data channels have it). Device
	// `ifindex` is a second device of the same server (tun device of the `tls`
	// clients of a mixed server). With `OPT_NO_C2C` the backend also drops a
	// packet from a peer to a network routed through it.
	c2c_device: proc(user: rawptr, ifindex: u32) -> int,
	set_peer:   proc(user: rawptr, p: ^Set_Peer) -> int,
	del_peer:   proc(user: rawptr, peer_id: u32) -> int,
	// The service has two key slots per peer: primary (sends and receives) and
	// secondary (receives, and the next key of a rekey).
	new_key:    proc(user: rawptr, k: ^New_Key) -> int,
	swap_keys:  proc(user: rawptr, peer_id: u32) -> int,
	del_key:    proc(user: rawptr, peer_id: u32, slot: Key_Slot) -> int,
	// Key table (`CAP_KEY_TABLE`): up to 8 keys per peer, one per key id.
	// All keys receive; `key_tx` names the sealing one. `key_add` with an
	// existing id replaces that key. `key_drop` of the sealing key leaves the
	// peer without one until the next `key_tx`.
	key_add:    proc(user: rawptr, k: ^Key) -> int,
	key_tx:     proc(user: rawptr, peer_id, key_id: u32) -> int,
	key_drop:   proc(user: rawptr, peer_id, key_id: u32) -> int,
	// Optional (nil: absent; only with `CAP_KEY_TABLE`). `key_add` from key
	// material, with cipher, format and rekey policy. Same table and return codes.
	key_install: proc(user: rawptr, k: ^Key_Install) -> int,
	// The backend has keys of the epoch data format: `key_install` takes
	// `.Epoch`. Then a session on it may use that format.
	epoch_keys: bool,
	stats:      proc(user: rawptr, peer_id: u32, out: ^Peer_Stats) -> int,
	// Optional (nil: not there). The epoch counters of a peer (`epoch_keys`).
	epoch_stats: proc(user: rawptr, peer_id: u32, out: ^Epoch_Stats) -> int,
	// Lets go of the transport socket, so that the daemon can close and rebind
	// it. The next `new_peer` passes the fd again.
	detach:     proc(user: rawptr) -> int,
	// 1: `ev` holds the next event. 0: none now. Below 0: the backend is gone.
	next_event: proc(user: rawptr, ev: ^Event) -> int,
}
