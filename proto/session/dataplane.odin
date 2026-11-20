// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "base:intrinsics"
import "core:mem"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/wire"

// Data channel state of one peer, and the calls that change it. The control side
// (TLS, key derivation, timers) never touches it while packets flow: it sends
// commands (`Dp_Cmd`) and reads results (`Dp_Seal`, `Dp_Open`).
//
// Owner (one at a time):
// - Default: the thread that calls the session (`Session.dp`, commands apply at
//   once).
// - Daemon with crypto workers: one `Data_Plane` per peer goes to a worker, the
//   session gets a `Dp_Remote`. Commands and packets go to the worker in order;
//   results return to the session's thread.
// - Same code runs in both cases.
//
// Data plane owns:
// - data keys (AEAD contexts, send counters, epoch state, replay windows)
// - key slot table (picks the send key, tells which receive keys are valid)
// - packet counter that paces the rekey check
// Not owned (the control side needs them):
// - session packet counters and `last_tx` / `last_rx` (updated by the caller of
//   `dp_seal` and `dp_open` from the result)
// - the rekey itself
//
// The session keeps its own slot table copy (`Session.slots`) for timers (key
// expiry, rekey by age). Both copies get the same calls, `now` and order, so they
// agree.

// What a data plane publishes for other threads (status text, bus). Written by
// the owner, read with atomics.
Dp_Public :: struct {
	epoch_tx: u32,
	epoch_rx: u32,
	adv_tx:   u64,
	adv_rx:   u64,
}

Data_Plane :: struct {
	role:      Role,
	transport: Transport,
	format:    keys.Format,
	peer_id:   u32,
	policy:    keys.Rekey_Policy,
	slots:     keys.Key_Slots,
	dk:        [DATA_KEYS]crypt.Data_Key,
	dk_used:   [DATA_KEYS]bool,
	dk_of:     [keys.KEY_ID_COUNT]i8, // key id to index in `dk`, -1 none
	// Packets sealed and opened; every 256th asks the session to look at the
	// rekey triggers.
	ops:       u32,
	// Epoch moves of data keys that were freed (the live keys count for
	// themselves).
	gone_tx:   u64,
	gone_rx:   u64,
	pub:       Dp_Public,
}

dp_init :: proc(dp: ^Data_Plane, role: Role, transport: Transport, cfg: keys.Slots_Config) {
	dp^ = {}
	dp.role = role
	dp.transport = transport
	for i in 0 ..< len(dp.dk_of) {
		dp.dk_of[i] = -1
	}
	keys.slots_init(&dp.slots, cfg)
}

// Frees every key. The data plane can be used again after `dp_init`.
dp_destroy :: proc(dp: ^Data_Plane) {
	for i in 0 ..< DATA_KEYS {
		if dp.dk_used[i] {
			dp.gone_tx += dp.dk[i].tx.advances
			dp.gone_rx += dp.dk[i].rx.advances
			crypt.data_key_destroy(&dp.dk[i])
			dp.dk_used[i] = false
		}
	}
	for i in 0 ..< len(dp.dk_of) {
		dp.dk_of[i] = -1
	}
}

// ---------------------------------------------------------------- commands

Dp_Cmd_Kind :: enum u8 {
	// A new key: `key` (created by the caller, the data plane takes it over), the
	// settings that go with it, and the time.
	Install,
	// A soft reset began (`keys.slots_rekey_started`).
	Rekey_Started,
	// Keys whose time is over go (`keys.slots_expire`).
	Expire,
	// The session ends. The owner frees every key (and its own memory, when it
	// created the data plane for another thread).
	Destroy,
}

Dp_Cmd :: struct {
	kind:   Dp_Cmd_Kind,
	key_id: u8,
	now:    Time,
	// Install only. The key is copied by the data plane (or by the port that
	// takes it to another thread); the caller wipes its own.
	key:    ^crypt.Data_Key,
		// Install with `Config.ext_data` only: no `key` is created. The owner gets the
		// key material and the cipher and builds what it needs. Valid during the
		// call. The session wipes it afterwards.
	material: ^keys.Key_Material,
	cipher: ossl.Aead_Cipher,
	format: keys.Format,
	peer_id: u32,
	policy: keys.Rekey_Policy,
}

// Applies a command. False: Install found no free key (the session checks for
// that first, so it does not happen).
dp_apply :: proc(dp: ^Data_Plane, cmd: ^Dp_Cmd) -> bool {
	switch cmd.kind {
	case .Install:
		idx := -1
		for i in 0 ..< DATA_KEYS {
			if !dp.dk_used[i] {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false
		}
		dropped, serr := keys.slots_install(&dp.slots, cmd.key_id, cmd.now)
		if serr != .None {
			return false
		}
		dp.dk[idx] = cmd.key^
		dp.dk_used[idx] = true
		dp.dk_of[cmd.key_id] = i8(idx)
		dp.format = cmd.format
		dp.peer_id = cmd.peer_id
		dp.policy = cmd.policy
		dp_free_keys(dp, dropped)
	case .Rekey_Started:
		dp_free_keys(dp, keys.slots_rekey_started(&dp.slots, cmd.now))
	case .Expire:
		dp_free_keys(dp, keys.slots_expire(&dp.slots, cmd.now))
	case .Destroy:
		dp_destroy(dp)
	}
	dp_publish(dp)
	return true
}

@(private)
dp_free_keys :: proc(dp: ^Data_Plane, ids: keys.Key_Id_Set) {
	for i in 0 ..< keys.KEY_ID_COUNT {
		if i not_in ids {
			continue
		}
		idx := dp.dk_of[i]
		if idx < 0 {
			continue
		}
		// Keep what the key counted for the totals of the session.
		dp.gone_tx += dp.dk[idx].tx.advances
		dp.gone_rx += dp.dk[idx].rx.advances
		crypt.data_key_destroy(&dp.dk[idx])
		dp.dk_used[idx] = false
		dp.dk_of[i] = -1
	}
}

// The send and receive epoch of the newest key, and the epoch moves of all
// keys (live and freed). The epochs are 0 in the baseline format or without a
// key.
dp_epochs :: proc "contextless" (dp: ^Data_Plane) -> (tx, rx: u16) {
	id, _, ok := keys.slots_primary(&dp.slots)
	if !ok || dp.dk_of[id] < 0 {
		return 0, 0
	}
	dk := &dp.dk[dp.dk_of[id]]
	return crypt.tx_epoch(&dk.tx), crypt.rx_epoch(&dk.rx)
}

dp_advances :: proc "contextless" (dp: ^Data_Plane) -> (tx, rx: u64) {
	tx, rx = dp.gone_tx, dp.gone_rx
	for i in 0 ..< DATA_KEYS {
		if dp.dk_used[i] {
			tx += dp.dk[i].tx.advances
			rx += dp.dk[i].rx.advances
		}
	}
	return
}

// Exposes the epochs and the epoch moves for reading from another thread. The owner
// calls it after a command and at the end of a batch of packets.
dp_publish :: proc "contextless" (dp: ^Data_Plane) {
	etx, erx := dp_epochs(dp)
	atx, arx := dp_advances(dp)
	intrinsics.atomic_store_explicit(&dp.pub.epoch_tx, u32(etx), .Relaxed)
	intrinsics.atomic_store_explicit(&dp.pub.epoch_rx, u32(erx), .Relaxed)
	intrinsics.atomic_store_explicit(&dp.pub.adv_tx, atx, .Relaxed)
	intrinsics.atomic_store_explicit(&dp.pub.adv_rx, arx, .Relaxed)
}

// Reads what `dp_publish` wrote. Safe from any thread.
dp_read_public :: proc "contextless" (dp: ^Data_Plane) -> Dp_Public {
	return {
		epoch_tx = intrinsics.atomic_load_explicit(&dp.pub.epoch_tx, .Relaxed),
		epoch_rx = intrinsics.atomic_load_explicit(&dp.pub.epoch_rx, .Relaxed),
		adv_tx = intrinsics.atomic_load_explicit(&dp.pub.adv_tx, .Relaxed),
		adv_rx = intrinsics.atomic_load_explicit(&dp.pub.adv_rx, .Relaxed),
	}
}

// Is a renegotiation due by the usage of the newest key (or by its age)? The
// caller starts it. A key that is not there yet counts as not due. `id` is the
// key that was looked at.
dp_rekey_due :: proc "contextless" (dp: ^Data_Plane, now: Time) -> (due: bool, id: u8) {
	established: Time
	ok: bool
	id, established, ok = keys.slots_primary(&dp.slots)
	if !ok || dp.dk_of[id] < 0 {
		return false, id
	}
	usage := crypt.data_key_usage(&dp.dk[dp.dk_of[id]])
	return keys.rekey_check(&dp.policy, established, now, &usage) != .None, id
}

// ------------------------------------------------------------------- seal

Dp_Seal :: struct {
	err:       Error, // .None, .No_Key or .Crypto
	// The link packet is `buf[start:end]`.
	start:     int,
	end:       int,
	// A key ran out of packet ids and was set aside: the session starts a
	// rekey.
	exhausted: bool,
	// Time to look at the rekey triggers (every 256th packet).
	due:       bool,
	// The key that `exhausted` or `due` is about. With the data plane on another
	// thread the session may have a newer key when the result arrives.
	key:       u8,
}

// Seals the tunnel packet that sits at `buf[TUNNEL_HEADROOM:][:n]`, in place.
// `counted` means it is a tunnel packet (not a keepalive or an exit notice created
// by the session), so it counts for the rekey check.
dp_seal :: proc(dp: ^Data_Plane, buf: []u8, n: int, counted: bool, now: Time) -> (r: Dp_Seal) {
	for _ in 0 ..< 2 {
		key_id, ok := keys.slots_tx_key(&dp.slots, now)
		if !ok {
			r.err = .No_Key
			return
		}
		idx := dp.dk_of[key_id]
		if idx < 0 {
			r.err = .No_Key
			return
		}
		// The payload stays where the caller put it. The packet header goes right
		// in front of it, so it starts at `first`: 2 (the baseline format, 24
		// bytes of header) or 14 (the epoch format, 12 bytes).
		head, _ := format_room(dp.dk[idx].tx.format)
		first := TUNNEL_HEADROOM - head
		out := buf[first:]
		plain := buf[TUNNEL_HEADROOM:][:n]
		m, serr := crypt.data_key_seal(&dp.dk[idx], dp.peer_id, plain, out)
		#partial switch serr {
		case .None:
			r.err = .None
			r.start, r.end = first, first + m
			if dp.transport == .Tcp {
				buf[first - wire.FRAME_PREFIX_LEN] = u8(m >> 8)
				buf[first - wire.FRAME_PREFIX_LEN + 1] = u8(m)
				r.start = first - wire.FRAME_PREFIX_LEN
			}
			if counted {
				dp.ops += 1
				if dp.ops & 0xFF == 0 {
					r.due, r.key = dp_rekey_due(dp, now)
				}
			}
			return
		case .Packet_Id_Exhausted:
			// This key is used up: send on another one and start a rekey.
			keys.slots_block_tx(&dp.slots, key_id)
			r.exhausted = true
			r.key = key_id
			continue
		case:
			r.err = .Crypto
			return
		}
	}
	r.err = .No_Key
	return
}

// ------------------------------------------------------------------- open

// What a received data packet turned out to be. The first four authenticated;
// the others did not (the counter and the text are in `rx_drop_of`).
Dp_Open_Code :: enum u8 {
	Tunnel, // a tunnel packet: `buf[off:][:len]`
	Ping, // the keepalive
	Exit, // the exit notice
	Other, // authentic, but none of these
	Short, // shorter than the format allows
	Bad_Header,
	No_Key, // the key id is not valid now
	Peer_Id, // a server: another peer's id
	Replay,
	Tag, // failed authentication (or a key that refuses packets)
	Epoch, // epoch format: outside the receive window
	Payload, // any other error of the open
}

Dp_Open :: struct {
	code: Dp_Open_Code,
	// The plaintext is `pkt[off:][:len]` (the packet is opened in place).
	off:  int,
	len:  int,
	// Time to look at the rekey triggers (every 256th packet).
	due:  bool,
	// The key that `due` is about (see `Dp_Seal.key`).
	key:  u8,
}

// Checks and opens one data packet in place.
dp_open :: proc(dp: ^Data_Plane, pkt: []u8, now: Time) -> (r: Dp_Open) {
	if len(pkt) < wire.DATA_V2_MIN_PACKET {
		r.code = .Short
		return
	}
	hdr, _, herr := wire.data_v2_decode(pkt)
	if herr != .None {
		r.code = .Bad_Header
		return
	}
	if !keys.slots_rx_ok(&dp.slots, hdr.key_id, now) || dp.dk_of[hdr.key_id] < 0 {
		r.code = .No_Key
		return
	}
	// SPEC-GAP: a client does not compare the peer-id of a received packet with its
	// own. It is authenticated data, so only the real sender can set it, and a
	// stock server sends the id it pushed.
	// A server takes its own id, or "undefined" (the sender is then known by its
	// address, which the caller checked when it chose the session).
	if dp.role == .Server && hdr.peer_id != dp.peer_id && hdr.peer_id != wire.PEER_ID_UNDEFINED {
		r.code = .Peer_Id
		return
	}
	idx := dp.dk_of[hdr.key_id]
	head, tail := format_room(dp.dk[idx].rx.format)
	if len(pkt) < head + tail {
		r.code = .Short
		return
	}
	// Decrypt in place: the plaintext replaces the ciphertext.
	res, oerr := crypt.data_key_open(&dp.dk[idx], pkt, pkt[head:])
	#partial switch oerr {
	case .None:
	case .Replay:
		r.code = .Replay
		return
	case .Bad_Tag, .Key_Disabled:
		r.code = .Tag
		return
	case .Unknown_Epoch:
		r.code = .Epoch
		return
	case:
		r.code = .Payload
		return
	}
	dp.ops += 1
	if dp.ops & 0xFF == 0 {
		r.due, r.key = dp_rekey_due(dp, now)
	}
	r.off, r.len = head, res.n
	kind := crypt.classify_payload(pkt[head:][:res.n])
	switch {
	case crypt.payload_is_tunnel(kind):
		r.code = .Tunnel
	case kind == .Ping:
		r.code = .Ping
	case kind == .Occ_Exit:
		r.code = .Exit
	case:
		r.code = .Other
	}
	return
}

// The text of a dropped data packet, for the TCP failure.
@(private)
open_drop_text :: proc "contextless" (c: Dp_Open_Code) -> string {
	#partial switch c {
	case .Short:
		return "a data packet was too short"
	case .Bad_Header:
		return "a data packet had a header that is not valid"
	case .No_Key:
		return "a data packet had an unknown key id"
	case .Peer_Id:
		return "a data packet had another peer id"
	case .Replay:
		return "a data packet was a replay"
	case .Tag:
		return "a data packet failed authentication"
	case .Epoch:
		return "a data packet had an unknown epoch"
	}
	return "a data packet was not valid"
}

// -------------------------------------------------------------- the owner

// A data plane on another thread. The session calls these on its own thread; each
// call hands work to the owner in order. `user` goes to the first three, `host`
// (the daemon's pointer) to the last two.
//
//	submit   a command (key arrives, soft reset began, keys expire)
//	seal     one packet, wait for the result (session keepalives and exit notices;
//	         the daemon batches tunnel packets)
//	open     same for a received packet (no sink set)
//	take     a received data packet the daemon may keep for a batch: true if it did
//	         (no tunnel packet is returned; the daemon opens the batch and calls
//	         `session_rx_finish`)
//	barrier  something must follow the packets taken so far (a control packet):
//	         finish them first
Dp_Remote :: struct {
	user:    rawptr,
	host:    rawptr,
	submit:  proc(user: rawptr, dp: ^Data_Plane, cmd: ^Dp_Cmd),
	seal:    proc(user: rawptr, dp: ^Data_Plane, buf: []u8, n: int, counted: bool, now: Time) -> Dp_Seal,
	open:    proc(user: rawptr, dp: ^Data_Plane, pkt: []u8, now: Time) -> Dp_Open,
	take:    proc(host: rawptr, s: ^Session, pkt: []u8, now: Time) -> bool,
	barrier: proc(host: rawptr),
}

// Gives the session's data channel to another thread: returns a new data plane
// (allocated with the session's allocator) for the owner. Call it before the first key
// is installed. The session never touches the data plane again (except public
// numbers) and tells the owner when it ends (`session_destroy` sends `Destroy`);
// the owner then frees it.
session_set_remote :: proc(s: ^Session, remote: Dp_Remote) -> ^Data_Plane {
	dp := new(Data_Plane, s.allocator)
	if dp == nil {
		return nil
	}
	dp_init(dp, s.role, s.transport, dp_slots_config(&s.cfg))
	s.rdp = dp
	s.remote = remote
	return dp
}

// For `Config.ext_data`: the data channel belongs to something other than a
// `Data_Plane` (a DCO service that runs the keys, replay window and keepalive).
// - Commands (`Install` with key material, `Rekey_Started`, `Expire`, `Destroy`)
//   go to `remote.submit`.
// - No data packet is ever offered, sealed or opened here. One that reaches the
//   session anyway (before the owner has the peer) is dropped.
// - Call it before the first key is installed.
// - `remote.submit` must not free or use the `dp` it gets. The session passes its
//   own empty data plane, which only stands for "not on this thread".
session_set_external :: proc(s: ^Session, remote: Dp_Remote) {
	s.rdp = &s.dp
	s.remote = remote
	if s.remote.seal == nil {
		s.remote.seal = proc(user: rawptr, dp: ^Data_Plane, buf: []u8, n: int, counted: bool, now: Time) -> Dp_Seal {
			return Dp_Seal{err = .No_Key}
		}
	}
	if s.remote.open == nil {
		s.remote.open = proc(user: rawptr, dp: ^Data_Plane, pkt: []u8, now: Time) -> Dp_Open {
			return Dp_Open{code = .No_Key}
		}
	}
}

// True while the data channel is on another thread.
session_is_remote :: proc "contextless" (s: ^Session) -> bool {
	return s.rdp != nil
}

// The slot table settings of a session.
@(private)
dp_slots_config :: proc "contextless" (cfg: ^Config) -> keys.Slots_Config {
	return {tran_window = cfg.tran_window, tx_delay = cfg.rekey_tx_delay, lame_grace = keys.DEFAULT_LAME_GRACE}
}

// The slot table settings of a session, for an owner that keeps a table of its
// own (`Config.ext_data`). With the same settings and the same calls it agrees
// with the session's table.
session_slots_config :: proc "contextless" (s: ^Session) -> keys.Slots_Config {
	return dp_slots_config(&s.cfg)
}

// ------------------------------------------------------- session -> owner

// Sends a command to the owner of the data plane.
@(private)
dp_send :: proc(s: ^Session, cmd: ^Dp_Cmd) {
	if s.rdp != nil {
		s.remote.submit(s.remote.user, s.rdp, cmd)
		return
	}
	dp_apply(&s.dp, cmd)
}

@(private)
seal_now :: proc(s: ^Session, buf: []u8, n: int, counted: bool, now: Time) -> Dp_Seal {
	if s.rdp != nil {
		return s.remote.seal(s.remote.user, s.rdp, buf, n, counted, now)
	}
	return dp_seal(&s.dp, buf, n, counted, now)
}

@(private)
open_now :: proc(s: ^Session, pkt: []u8, now: Time) -> Dp_Open {
	if s.rdp != nil {
		return s.remote.open(s.remote.user, s.rdp, pkt, now)
	}
	return dp_open(&s.dp, pkt, now)
}

// The settings the rekey triggers use.
@(private)
session_policy :: proc(s: ^Session) -> keys.Rekey_Policy {
	return keys.Rekey_Policy {
		cipher = aead_of(s.cipher),
		format = s.format,
		reneg_sec = i64(max(s.reneg_eff, 0)),
		reneg_bytes = s.cfg.reneg_bytes,
		reneg_pkts = s.cfg.reneg_pkts,
		limit_override = s.cfg.limit_override,
	}
}

// Wipes a key that was copied to its owner.
@(private)
wipe_key :: proc(k: ^crypt.Data_Key) {
	mem.zero_explicit(k, size_of(crypt.Data_Key))
}
