// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:mem"
import "core:time"
import "noir:client"
import "noir:platform/dco"
import "noir:platform/event"
import net "noir:platform/net"
import "noir:platform/sysnet"
import "noir:proto/config"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/session"
import "noir:proto/wire"

// Data channel on a userspace DCO service (`datapath udco`, see
// platform/dco) or the Linux kernel `ovpn`
// driver (`datapath dco`). Both fill one `dco.Backend`: one code path.
// - Backend owns: tun device, data keys, replay window, keepalive.
// - This process keeps: control channel (TLS, key derivation, rekeys, push) and
//   device addresses and routes (by interface index, via sysnet).
//
// Kernel backend: no key table (2 slots), no `CAP_PEER_ID`/`CAP_PEER_ADDR` (TCP
// goes over late), no `mss_clamp`, no epoch keys; netcfg brings the device up.
// `key_install` backend: gets key material; with `epoch_keys`
// too, the session may use the epoch data format. `be.fd`: what the event loop
// watches. `be.next_event`: the events. Never use the service socket directly.
//
//	start      connect to the service (HELLO)
//	device     OPEN: the service creates the tun device, returns its index
//	peer       NEW_PEER (with the bound UDP socket), the session's keys, SET_PEER
//	           (keepalive, mss)
//	TCP        CAP_PEER_ID: the connection goes over when created. NEW_PEER carries
//	           the stream under a provisional id; control channel via CTRL_TX and
//	           CTRL_RX events; keys under the provisional id; SET_PEER_ID gives the
//	           real (pushed) id when known. No CAP_PEER_ID: late handover when UDP
//	           creates its peer; NEW_PEER carries the stream and unused read bytes
//	rekey      NEW_KEY in the secondary slot, SWAP_KEYS when the new key sends,
//	           DEL_KEY when the old key leaves the session's slot table
//	events     PEER_DEL (expired, transport), KEY_SWAP, PEER_FLOAT, CTRL_RX, log lines
//	stats      PEER_STATS feeds session counters and the status text
//	end        DEL_PEER; closing the connection removes the device
//
// A build may provide an in-process data channel (`dco.in_process`). With it and
// no `dco-socket` in the config, `datapath udco` (and `auto` after the kernel)
// uses it instead of a service, via the same `Backend`. A `dco-socket` keeps the
// service.
//
// If the backend fails, the client falls back to the in-process data path and
// says so on the bus (`client.state` `datapath`):
//
//	start      `udco`: wait up to DCO_WAIT_SECS for the service, then go on
//	           without it (warning). `dco`: ask the kernel once (no module:
//	           warning). `auto`: kernel, service (no wait), then none (`dco_pick`,
//	           one notice)
//	attempt    chosen before the session starts (`dco_for_attempt`): the backend
//	           if wanted, reachable (link remade if lost) and handling the
//	           transport; else this process. A changed choice is logged once
//	setup      a failure after the attempt went to the backend (OPEN, NEW_PEER,
//	           SET_PEER_ID, SET_PEER, TCP handover, refused command) ends it with
//	           `Datapath_Failed` (`udco_failed`/`dco_failed` on the bus). The next
//	           attempt follows at once in this process, no wait, no try used; later
//	           attempts try the backend again
//	running    a service that goes away under a running tunnel ends the
//	           connection; the next attempt is chosen as above
//
// This file: what both daemons use (link, per-peer owner with key slot mapping,
// stats, conversions) and the client part. Server part: server_dco.odin. Never
// reads or writes the tun device.

// The service's own error code for "not there": a key slot that is empty.
DCO_ENOENT :: dco.ENOENT
DCO_ECONNREFUSED :: -111
// "No such device": what the kernel driver returns when its device is gone.
DCO_ENODEV :: -19
// How long `datapath udco` waits for a service that is not there yet, and how
// often it asks.
DCO_WAIT_SECS :: 10
// A server that lost the service opens its own tun device. A name still taken
// (the service has not removed its device yet) is retried this often, this many
// times.
DCO_TUN_RETRY :: 100 * time.Millisecond
DCO_TUN_TRIES :: 50
// Provisional ids of TCP peers the service holds before their real id is known
// (SET_PEER_ID). They sit at the top of the 24-bit range (0xffffff: "no peer").
// Server-assigned ids count up from 0 (stock: below `max-clients`; ours: below
// `max-clients`, checked), so they never meet the top. A provisional id is not
// reused for a while: a message queued under it may arrive after its peer is
// gone.
DCO_PROV_TOP :: dco.PEER_ID_LIMIT - 1
// How many provisional ids the client rotates through (one per attempt).
DCO_PROV_CLIENT :: 256
// Seconds between PEER_STATS calls: when a `reneg-bytes` or `reneg-pkts` limit
// needs counters, and when nothing does (status text and bus want fresh numbers).
DCO_STATS_FAST :: 1
DCO_STATS_SLOW :: 10
// The same for a server on the kernel driver with UDP peers: a float is found only
// by this poll (before Linux 7.1), so it is faster.
DCO_STATS_KERNEL :: 2

// ------------------------------------------------------------------- the link

// One connection to a backend: the service's socket or the kernel driver. It
// controls one device. `be` is what the daemon calls; `c` and `k` are its state.
Dco_Link :: struct {
	c:       dco.Conn, // the service
	k:       dco.Kernel, // the kernel driver
	be:      dco.Backend,
	up:      bool, // connected
	dev:     bool, // the device exists (OPEN done)
	ifindex: u32,
	// The listener fd was passed with a NEW_PEER since the last OPEN or DETACH.
	fd_sent: bool,
	watched: bool, // `be.fd` is in the event loop
	// The IPv6 filter of the device is on (SET_FILTER), and the counters of its last
	// reply, for the deltas. Both start again with the device.
	filtered: bool,
	filter_last: dco.Filter_Stats,
}

dco_log :: proc(user: rawptr, level: dco.Log_Level, text: string) {
	logf(dco_log_level(level), "dco service: %s", text)
}

kernel_log :: proc(user: rawptr, level: dco.Log_Level, text: string) {
	logf(dco_log_level(level), "kernel ovpn: %s", text)
}

in_process_log :: proc(user: rawptr, level: dco.Log_Level, text: string) {
	logf(dco_log_level(level), "data channel: %s", text)
}

// "Operation not supported": a backend that this build does not have.
DCO_ENOTSUP :: -95

// True if the in-process data channel takes `datapath udco` (and `auto` after
// the kernel): the build has one and the config has no `dco-socket` (`path` is
// the default socket).
dco_in_process_on :: proc(path: string) -> bool {
	return dco.in_process_ready() && path == config.DCO_SOCKET_DEFAULT
}

// The name of the data channel in this process, for the log.
dco_in_process_name :: proc() -> string {
	return dco.in_process.name if dco.in_process.name != "" else "built in"
}

dco_log_level :: proc "contextless" (level: dco.Log_Level) -> Level {
	switch level {
	case .Error:
		return .Error
	case .Warn:
		return .Warn
	case .Info:
		return .Info
	case .Debug:
		return .Debug
	}
	return .Debug
}

// What the logs call the backend: the first when a sentence starts with it.
dco_who :: proc "contextless" (kind: dco.Backend_Kind) -> string {
	switch kind {
	case .Kernel:
		return "the kernel ovpn driver"
	case .In_Process:
		return "the data channel in this process"
	case .Service:
	}
	return "the DCO service"
}

// The same, shorter, for the reason of a session end.
dco_who_short :: proc "contextless" (kind: dco.Backend_Kind) -> string {
	switch kind {
	case .Kernel:
		return "the kernel"
	case .In_Process:
		return "the data channel in this process"
	case .Service:
	}
	return "the DCO service"
}

// The `datapath` word of the start line: the bus value, and a note when the data
// channel runs in this process.
dco_start_text :: proc "contextless" (kind: dco.Backend_Kind, on: bool) -> string {
	if !on {
		return "userspace"
	}
	if kind == .In_Process {
		return "udco (in this process)"
	}
	return dco_datapath_name(kind)
}

// How a link is created. A test replaces it (`dco_connect_hook`).
Dco_Connect :: proc(l: ^Dco_Link, kind: dco.Backend_Kind, path: string) -> int

@(thread_local)
dco_connect_hook: Dco_Connect

// One try. 0 or a negative errno (`dco.ENO_OVPN`: the kernel has no `ovpn` family).
dco_link_connect :: proc(l: ^Dco_Link, kind: dco.Backend_Kind, path: string) -> int {
	if dco_connect_hook != nil {
		return dco_connect_hook(l, kind, path)
	}
	l^ = {}
	switch kind {
	case .Service:
		if st := dco.connect(&l.c, path, dco_log); st != 0 {
			return st
		}
		l.be = dco.socket_backend(&l.c)
		if test_no_peer_id() {
			l.be.caps &= ~u32(dco.CAP_PEER_ID | dco.CAP_PEER_ADDR)
		}
	case .Kernel:
		if st := dco.kernel_connect(&l.k, kernel_log); st != 0 {
			return st
		}
		l.be = dco.kernel_backend(&l.k)
	case .In_Process:
		if !dco.in_process_ready() {
			return DCO_ENOTSUP
		}
		be, st := dco.in_process.make(in_process_log, nil)
		if st != 0 {
			return st
		}
		l.be = be
	}
	l.up = true
	return 0
}

// Connects; retries once a second for DCO_WAIT_SECS if the socket is missing or
// refuses. Other failures (service of another protocol version) are final.
dco_link_connect_wait :: proc(l: ^Dco_Link, path: string, secs: int) -> int {
	st := 0
	for i in 0 ..= secs {
		st = dco_link_connect(l, .Service, path)
		if st == 0 {
			return 0
		}
		if st != dco.ENOENT && st != DCO_ECONNREFUSED {
			return st
		}
		if i < secs {
			if i == 0 {
				logf(.Notice, "the DCO service at %s is not available yet, waiting up to %d s", path, secs)
			}
			time.sleep(time.Second)
		}
	}
	return st
}

dco_link_close :: proc(l: ^Dco_Link) {
	if l.up {
		switch l.be.kind {
		case .Service:
			dco.disconnect(&l.c)
		case .Kernel:
			dco.kernel_disconnect(&l.k)
		case .In_Process:
			if dco.in_process.destroy != nil {
				dco.in_process.destroy(&l.be)
			}
		}
	}
	l^ = {}
}

dco_status_text :: proc(st: int) -> string {
	return dco.status_text(st)
}

// The status of a failed call as text, with the words of the backend when it has
// some (the kernel's extended ack). Valid until the next call to the backend.
dco_why :: proc(l: ^Dco_Link, st: int) -> string {
	text := dco_status_text(st)
	if l.be.err_text != nil {
		if more := l.be.err_text(l.be.user); more != "" {
			return fmt.tprintf("%s (%s)", text, more)
		}
	}
	return text
}

// The module of the kernel is not there.
dco_no_module :: proc "contextless" (st: int) -> bool {
	return st == dco.ENO_OVPN
}

// The text for a connect that failed, for the log.
dco_connect_text :: proc(kind: dco.Backend_Kind, st: int) -> string {
	if kind == .Kernel && dco_no_module(st) {
		return "the kernel has no ovpn module"
	}
	return dco_status_text(st)
}

// OPEN flags of the NOIRVPN_NO_OFFLOAD words: what is switched off.
dco_open_flags :: proc(off: Off_Config) -> u32 {
	f := u32(0)
	if !off.tun {
		f |= dco.OPT_NO_TUN_OFFLOAD
	}
	if !off.gso {
		f |= dco.OPT_NO_GSO
	}
	if !off.gro {
		f |= dco.OPT_NO_GRO
	}
	return f
}

// Creates the device. Name is the `dev` name; a generic `dev tun` gets tun0.
// `text` says what went wrong if `ok` is false; nothing is logged. `extra`:
// more OPEN flags.
dco_try_open :: proc(l: ^Dco_Link, name: string, mode: dco.Mode, extra: u32 = 0) -> (ifindex: u32, ok: bool, text: string) {
	ifname := name if name != "" else "tun0"
	idx, st := l.be.open(l.be.user, ifname, mode, dco_open_flags(OFF) | extra)
	if st != 0 {
		return 0, false, dco_why(l, st)
	}
	l.dev = true
	l.filtered = false
	l.filter_last = {}
	if idx == 0 {
		return 0, false, "it gave no interface index"
	}
	l.ifindex = idx
	l.fd_sent = false
	return idx, true, ""
}

// As `dco_try_open`, and an error is logged.
dco_open_device :: proc(l: ^Dco_Link, name: string, mode: dco.Mode) -> (ifindex: u32, ok: bool) {
	idx, done, text := dco_try_open(l, name, mode)
	if !done {
		logf(.Error, "%s cannot create the device %s: %s", dco_who(l.be.kind), name if name != "" else "tun0", text)
		return 0, false
	}
	return idx, true
}

dco_close_device :: proc(l: ^Dco_Link) {
	if l.dev && l.up {
		if st := l.be.close(l.be.user); st != 0 && st != dco.ENOTCONN {
			logf(.Debug, "closing the DCO device: %s", dco_why(l, st))
		}
	}
	l.dev = false
	l.fd_sent = false
	l.filtered = false
	l.filter_last = {}
}

// Can the backend drop IPv6 packets (`block-ipv6`)? Only a service with `CAP_BLOCK_IPV6`
// can: the kernel driver has no filter.
dco_filter_ok :: proc "contextless" (l: ^Dco_Link) -> bool {
	return l.up && l.be.caps & dco.CAP_BLOCK_IPV6 != 0
}

// Turns the IPv6 filter of the device on or off, or reads its counters when `on`
// is the current state. Returns packets dropped since the last call (from the
// reply counters). `st` is 0 or a negative errno.
dco_filter_call :: proc(l: ^Dco_Link, on: bool) -> (rx, tx: u64, st: int) {
	fs: dco.Filter_Stats
	st = l.be.set_filter(l.be.user, u32(dco.FILTER_IPV6) if on else 0, &fs)
	if st != 0 {
		return 0, 0, st
	}
	l.filtered = on
	rx, tx = sub0(fs.rx_v6, l.filter_last.rx_v6), sub0(fs.tx_v6, l.filter_last.tx_v6)
	l.filter_last = fs
	return
}

// The IPv6 drops of the service since the last call, when the filter is on.
dco_filter_poll :: proc(l: ^Dco_Link) -> (rx, tx: u64) {
	if !l.up || !l.dev || !l.filtered {
		return 0, 0
	}
	r, t, st := dco_filter_call(l, true)
	if st != 0 {
		return 0, 0
	}
	return r, t
}

// ---------------------------------------------------------------- the owner

// Most commands that wait for the peer: the first key, and a few spare.
DCO_OPS :: 8

Dco_Op_Kind :: enum u8 {
	New_Key, // two slots: a key into `slot`
	Del_Key, // two slots: empty `slot`
	Swap_Keys, // two slots: the secondary key sends
	Key_Add, // key table: the key `key.key_id`
	Key_Tx, // key table: `key_id` sends
	Key_Drop, // key table: remove `key_id`
	Key_Install, // key table, `key_install`: the key `key_id` from `mat`
}

Dco_Op :: struct {
	kind:   Dco_Op_Kind,
	slot:   dco.Key_Slot,
	key_id: u32, // Key_Tx, Key_Drop
	key:    dco.New_Key, // New_Key, Key_Add: with secrets, wiped after it is sent
	// Key_Install: the material (wiped after it is sent) and what goes with it.
	mat:    keys.Key_Material,
	cipher: ossl.Aead_Cipher,
	format: keys.Format,
	policy: keys.Rekey_Policy,
}

// What the daemon wants of the service for one peer, in session order. The
// session's `Install`, `Rekey_Started`, `Expire`, `Destroy` arrive via
// `dco_submit`. The owner keeps its own slot table (same calls as the session's)
// and maps it to the two service slots:
//
//	primary    the key that sends (and receives)
//	secondary  receives; the next key during a rekey, the old key after it
//
// The session holds up to 3 keys (newest, lame, grace); the service 2, so the
// grace key leaves the service one step earlier. A service with the key table
// (`CAP_KEY_TABLE`) holds every key of the session table: one to one mapping:
//
//	Install                        KEY_ADD (the new key id)
//	the table's send key changes   KEY_TX (also for the first key)
//	a key leaves the table         KEY_DROP (a rekey start, an expiry, an install)
//
// Commands wait in `ops` until the peer exists, then go out in order.
Dco_Owner :: struct {
	link:    ^Dco_Link,
	slots:   keys.Key_Slots,
	// The service has the key table: `have` is the key ids it holds, `tx_id` the one
	// that sends (-1: none).
	table:   bool,
	// The backend builds the keys from their material (`key_install`).
	install: bool,
	have:    keys.Key_Id_Set,
	tx_id:   int,
	peer_id: u32,
	// SET_PEER_ID moved the peer from `old_id` to `peer_id`. Events and control
	// records queued earlier still carry `old_id` and may arrive after the reply.
	// Both ids are the peer's until it ends (`dco_owns_id`).
	old_id:  u32,
	has_old: bool,
	created: bool, // NEW_PEER done
	// TCP: the service owns the stream. The control records of this peer go out with
	// CTRL_TX and come in as CTRL_RX (`dco_ctrl_send`); the socket is closed here.
	stream:  bool,
	gone:    bool, // the service has dropped the peer, or we deleted it: no more calls
	// The key id in each service slot, -1: empty.
	held:    [2]int,
	ops:     [DCO_OPS]Dco_Op,
	n_ops:   int,
	// The first call that failed (a negative errno), and which one. `err_txt` is the
	// words of the backend for it (the kernel's extended ack), or empty.
	err:     int,
	err_op:  string,
	err_txt: [96]u8,
	err_txt_n: int,
	// SET_PEER values, sent once the peer exists.
	set:     dco.Set_Peer,
	set_ok:  bool,
	// The totals of the last PEER_STATS, for the deltas.
	last:    session.Ext_Totals,
}

dco_owner_init :: proc(o: ^Dco_Owner, l: ^Dco_Link, cfg: keys.Slots_Config) {
	o^ = {}
	o.link = l
	o.held = {-1, -1}
	o.tx_id = -1
	o.table = l.be.caps & dco.CAP_KEY_TABLE != 0
	o.install = o.table && l.be.key_install != nil
	keys.slots_init(&o.slots, cfg)
}

// Gives the data channel of a session to this owner. Call it after
// `session_init` and before `session_start`.
dco_attach :: proc(s: ^session.Session, o: ^Dco_Owner) {
	session.session_set_external(s, session.Dp_Remote{user = o, submit = dco_submit})
}

dco_fail :: proc(o: ^Dco_Owner, what: string, st: int) {
	if o.err == 0 {
		o.err = st
		o.err_op = what
		o.err_txt_n = 0
		if o.link != nil && o.link.be.err_text != nil {
			more := o.link.be.err_text(o.link.be.user)
			o.err_txt_n = min(len(more), len(o.err_txt))
			copy(o.err_txt[:], more[:o.err_txt_n])
		}
	}
}

// The status of the owner's first failure as text, with the backend's words.
dco_err_text :: proc(o: ^Dco_Owner) -> string {
	text := dco_status_text(o.err)
	if o.err_txt_n > 0 {
		return fmt.tprintf("%s (%s)", text, string(o.err_txt[:o.err_txt_n]))
	}
	return text
}

dco_op_wipe :: proc(op: ^Dco_Op) {
	mem.zero_explicit(&op.key, size_of(op.key))
	keys.material_wipe(&op.mat)
}

// The session's command. Runs inside a call into the session, so it only
// records failures (`o.err`); the daemon looks at them afterwards.
dco_submit :: proc(user: rawptr, dp: ^session.Data_Plane, cmd: ^session.Dp_Cmd) {
	o := (^Dco_Owner)(user)
	switch cmd.kind {
	case .Install:
		dco_install(o, cmd)
	case .Rekey_Started:
		dco_dropped(o, keys.slots_rekey_started(&o.slots, cmd.now))
	case .Expire:
		dco_dropped(o, keys.slots_expire(&o.slots, cmd.now))
		dco_sync_tx(o, cmd.now)
	case .Destroy:
		dco_peer_delete(o)
	}
}

dco_install :: proc(o: ^Dco_Owner, cmd: ^session.Dp_Cmd) {
	if o.gone {
		return
	}
	m := cmd.material
	what := "KEY_ADD" if o.table else "NEW_KEY"
	if m == nil || m.send.key_len != m.recv.key_len || m.send.key_len > 32 || (cmd.format != .Baseline && !o.install) {
		dco_fail(o, what, dco.EINVAL)
		return
	}
	dropped, serr := keys.slots_install(&o.slots, cmd.key_id, cmd.now)
	if serr != .None {
		dco_fail(o, what, dco.EINVAL)
		return
	}
	dco_dropped(o, dropped)
	if o.table {
		op := Dco_Op {
			kind   = .Key_Add,
			key_id = u32(cmd.key_id),
		}
		if o.install {
			op.kind = .Key_Install
			op.mat = m^
			op.cipher = cmd.cipher
			op.format = cmd.format
			op.policy = cmd.policy
		} else {
			dco_fill_key(&op.key, cmd, m)
		}
		dco_queue(o, op)
		dco_op_wipe(&op)
		o.have += {int(cmd.key_id)}
		dco_sync_tx(o, cmd.now)
		return
	}
	slot := dco.Key_Slot.Primary
	if o.held[0] >= 0 {
		// A rekey: the new key waits in the secondary slot. The service has room
		// for two keys, so the one that is there (the lame key) goes first.
		slot = .Secondary
		if o.held[1] >= 0 {
			dco_queue(o, Dco_Op{kind = .Del_Key, slot = .Secondary})
			o.held[1] = -1
		}
	}
	op := Dco_Op {
		kind = .New_Key,
		slot = slot,
	}
	dco_fill_key(&op.key, cmd, m)
	op.key.slot = u32(slot)
	dco_queue(o, op)
	dco_op_wipe(&op)
	o.held[int(slot)] = int(cmd.key_id)
	dco_sync_tx(o, cmd.now)
}

// The key of an `Install` in the format of the service's key message (the slot is
// left to the caller).
dco_fill_key :: proc(k: ^dco.New_Key, cmd: ^session.Dp_Cmd, m: ^keys.Key_Material) {
	k.key_id = u32(cmd.key_id)
	switch cmd.cipher {
	case .AES_128_GCM, .AES_256_GCM:
		k.cipher = u32(dco.Cipher.Aes_Gcm)
	case .CHACHA20_POLY1305:
		k.cipher = u32(dco.Cipher.Chacha20_Poly1305)
	}
	k.key_len = u32(m.send.key_len)
	copy(k.enc_key[:], m.send.key[:m.send.key_len])
	copy(k.enc_nonce[:], m.send.iv[:])
	copy(k.dec_key[:], m.recv.key[:m.recv.key_len])
	copy(k.dec_nonce[:], m.recv.iv[:])
}

// Keys that left the session's table: the service drops them too.
dco_dropped :: proc(o: ^Dco_Owner, dropped: keys.Key_Id_Set) {
	if o.table {
		for id in dropped & o.have {
			dco_queue(o, Dco_Op{kind = .Key_Drop, key_id = u32(id)})
			o.have -= {id}
			if o.tx_id == int(id) {
				o.tx_id = -1
			}
		}
		return
	}
	if o.held[1] >= 0 && o.held[1] in dropped {
		dco_queue(o, Dco_Op{kind = .Del_Key, slot = .Secondary})
		o.held[1] = -1
	}
	if o.held[0] >= 0 && o.held[0] in dropped {
		// The key that sends is gone from the table: the session is about to end.
		o.held[0] = -1
	}
}

// If the session now sends with the key in the secondary slot, the service must
// too.
dco_sync_tx :: proc(o: ^Dco_Owner, now: time.Duration) {
	id, ok := keys.slots_tx_key(&o.slots, now)
	if o.table {
		if ok && o.tx_id != int(id) && int(id) in o.have {
			dco_queue(o, Dco_Op{kind = .Key_Tx, key_id = u32(id)})
			o.tx_id = int(id)
		}
		return
	}
	if ok && o.held[1] == int(id) {
		dco_queue(o, Dco_Op{kind = .Swap_Keys})
		o.held[0], o.held[1] = o.held[1], o.held[0]
	}
}

dco_queue :: proc(o: ^Dco_Owner, op: Dco_Op) {
	if o.gone || o.err != 0 {
		return
	}
	if o.n_ops == DCO_OPS {
		dco_fail(o, "queue", -12)
		return
	}
	o.ops[o.n_ops] = op
	o.n_ops += 1
	if o.created {
		dco_flush(o)
	}
}

// Sends the waiting commands, in order. A command that fails stops the rest.
dco_flush :: proc(o: ^Dco_Owner) {
	be := &o.link.be
	for i in 0 ..< o.n_ops {
		op := &o.ops[i]
		if o.err == 0 {
			st := 0
			what := ""
			switch op.kind {
			case .New_Key:
				op.key.peer_id = o.peer_id
				st = be.new_key(be.user, &op.key)
				what = "NEW_KEY"
			case .Del_Key:
				st = be.del_key(be.user, o.peer_id, op.slot)
				what = "DEL_KEY"
				if st == DCO_ENOENT {
					st = 0 // nothing there: the same as gone
				}
			case .Swap_Keys:
				st = be.swap_keys(be.user, o.peer_id)
				what = "SWAP_KEYS"
			case .Key_Add:
				k := &op.key
				kk := dco.Key {
					peer_id   = o.peer_id,
					key_id    = k.key_id,
					cipher    = k.cipher,
					key_len   = k.key_len,
					enc_key   = k.enc_key,
					enc_nonce = k.enc_nonce,
					dec_key   = k.dec_key,
					dec_nonce = k.dec_nonce,
				}
				st = be.key_add(be.user, &kk)
				mem.zero_explicit(&kk, size_of(kk))
				what = "KEY_ADD"
			case .Key_Tx:
				st = be.key_tx(be.user, o.peer_id, op.key_id)
				what = "KEY_TX"
			case .Key_Drop:
				st = be.key_drop(be.user, o.peer_id, op.key_id)
				what = "KEY_DROP"
				if st == DCO_ENOENT {
					st = 0
				}
			case .Key_Install:
				ki := dco.Key_Install {
					peer_id  = o.peer_id,
					key_id   = op.key_id,
					cipher   = op.cipher,
					format   = op.format,
					material = &op.mat,
					policy   = op.policy,
				}
				st = be.key_install(be.user, &ki)
				what = "KEY_ADD"
			}
			if st != 0 {
				dco_fail(o, what, st)
			}
		}
		dco_op_wipe(op)
	}
	o.n_ops = 0
}

// Creates the peer in the service, then sends the waiting keys and SET_PEER
// values. `fd`: the bound UDP socket, -1 to leave it out (the service has one
// since the last OPEN or DETACH). Returns 0 or a negative errno.
dco_peer_create :: proc(o: ^Dco_Owner, p: ^dco.New_Peer, fd: i32) -> int {
	o.peer_id = p.peer_id
	be := &o.link.be
	st := be.new_peer(be.user, p, fd)
	if st != 0 {
		return st
	}
	if fd >= 0 {
		o.link.fd_sent = true
	}
	return dco_peer_made(o)
}

// Same for a TCP connection: `fd` is the connected stream, `ahead` the bytes
// read from it and not used. If the service took the stream (`o.stream`, also
// when a later step fails) the caller must close its copy of the socket and
// never use it again, whatever this returns.
dco_peer_create_stream :: proc(o: ^Dco_Owner, p: ^dco.New_Peer, fd: i32, ahead: []u8) -> int {
	o.peer_id = p.peer_id
	be := &o.link.be
	st := be.new_peer_stream(be.user, p, fd, ahead)
	if st != 0 {
		return st
	}
	o.stream = true
	return dco_peer_made(o)
}

// The peer takes its real id (`CAP_PEER_ID`); later commands use it. Returns 0
// or a negative errno (EEXIST: the id is another peer's). On error the peer
// keeps its id.
dco_peer_rename :: proc(o: ^Dco_Owner, new_id: u32) -> int {
	if !o.created || o.gone {
		return dco.ENOENT
	}
	if new_id == o.peer_id {
		return 0
	}
	be := &o.link.be
	if st := be.set_peer_id(be.user, o.peer_id, new_id); st != 0 {
		return st
	}
	o.old_id = o.peer_id
	o.has_old = true
	o.peer_id = new_id
	o.set.peer_id = new_id
	return 0
}

// The VPN addresses of the peer (`CAP_PEER_ADDR`), after the peer exists: the ones a
// NEW_PEER with `flags` (`PEER_VPN4`, `PEER_VPN6`) would have set. 0 or a negative errno.
dco_peer_set_addr :: proc(o: ^Dco_Owner, flags: u32, vpn4: [4]u8, vpn6: [16]u8) -> int {
	if !o.created || o.gone {
		return dco.ENOENT
	}
	a := dco.Set_Peer_Addr {
		peer_id = o.peer_id,
		flags   = flags & (dco.PEER_VPN4 | dco.PEER_VPN6),
		vpn4    = vpn4,
		vpn6    = vpn6,
	}
	be := &o.link.be
	return be.set_peer_addr(be.user, &a)
}

// Is `id` this peer's, now or before its rename?
dco_owns_id :: proc "contextless" (o: ^Dco_Owner, id: u32) -> bool {
	return id == o.peer_id || (o.has_old && id == o.old_id)
}

// After NEW_PEER: the keys that waited, and the keepalive values.
dco_peer_made :: proc(o: ^Dco_Owner) -> int {
	o.created = true
	dco_flush(o)
	if o.err != 0 {
		return o.err
	}
	if o.set_ok {
		return dco_peer_set(o, o.set.keepalive_interval, o.set.keepalive_timeout, o.set.mss)
	}
	return 0
}

// The keepalive and mss values: sent now when the peer exists, else with the
// peer. Seconds; 0 turns a timer off.
dco_peer_set :: proc(o: ^Dco_Owner, interval, timeout, mss: u32) -> int {
	o.set = dco.Set_Peer {
		peer_id            = o.peer_id,
		keepalive_interval = interval,
		keepalive_timeout  = timeout,
		mss                = mss,
	}
	o.set_ok = true
	if !o.created || o.gone {
		return 0
	}
	be := &o.link.be
	st := be.set_peer(be.user, &o.set)
	if st != 0 {
		dco_fail(o, "SET_PEER", st)
	}
	return st
}

// Removes the peer from the service (idempotent), and drops what waits.
dco_peer_delete :: proc(o: ^Dco_Owner) {
	for i in 0 ..< o.n_ops {
		dco_op_wipe(&o.ops[i])
	}
	o.n_ops = 0
	if o.created && !o.gone && o.link != nil && o.link.up {
		be := &o.link.be
		if st := be.del_peer(be.user, o.peer_id); st != 0 && st != DCO_ENOENT && st != dco.ENOTCONN {
			logf(.Debug, "DEL_PEER %d: %s", o.peer_id, dco_why(o.link, st))
		}
	}
	o.gone = true
}

// The service dropped the peer by itself (PEER_DEL): no DEL_PEER later.
dco_peer_dropped :: proc(o: ^Dco_Owner) {
	o.gone = true
}

// -------------------------------------------------- control records of a TCP peer

// The session's TCP output is framed (2-byte length, then the record). The
// service frames the stream itself, so only the record goes to CTRL_TX. This is
// the control channel sink when the service owns the stream; the source is
// CTRL_RX (`dco_ctrl_receive`). The session cannot tell the difference.
dco_ctrl_send :: proc(o: ^Dco_Owner, framed: []u8) {
	if !o.stream || !o.created || o.gone || len(framed) <= wire.FRAME_PREFIX_LEN {
		return
	}
	if int(framed[0]) << 8 | int(framed[1]) != len(framed) - wire.FRAME_PREFIX_LEN {
		dco_fail(o, "CTRL_TX", dco.EINVAL)
		return
	}
	be := &o.link.be
	st := be.ctrl_tx(be.user, o.peer_id, framed[wire.FRAME_PREFIX_LEN:])
	switch st {
	case 0:
	case dco.ENOENT, dco.ENOTCONN:
		// The stream is closed or the peer is gone: PEER_DEL says so, or already did.
		logf(.Debug, "CTRL_TX %d: %s", o.peer_id, dco_status_text(st))
	case:
		dco_fail(o, "CTRL_TX", st)
	}
}

// A control record that arrived on the stream (CTRL_RX event), to the session.
// The caller collects its output (acks, replies) and events. False: the session
// ended and cannot take more.
dco_ctrl_receive :: proc(l: ^Dco_Link, s: ^session.Session, now: time.Duration) -> bool {
	rec := l.be.ctrl_record(l.be.user)
	session.session_receive_record(s, rec, now)
	st := session.session_state(s)
	return st != .Failed && st != .Closed
}

// Asks for the counters, passes them to the session and returns what is new
// since the last call. False: no peer, or the call failed.
dco_stats :: proc(o: ^Dco_Owner, s: ^session.Session, now: time.Duration) -> (delta: session.Ext_Totals, ok: bool) {
	if !o.created || o.gone || !o.link.up {
		return {}, false
	}
	be := &o.link.be
	ps: dco.Peer_Stats
	if st := be.stats(be.user, o.peer_id, &ps); st != 0 {
		return {}, false
	}
	t := dco_totals(&ps)
	if be.epoch_stats != nil {
		es: dco.Epoch_Stats
		if be.epoch_stats(be.user, o.peer_id, &es) == 0 {
			t.epoch_adv_tx, t.epoch_adv_rx = es.tx_advances, es.rx_advances
			t.epoch_tx, t.epoch_rx = es.tx_epoch, es.rx_epoch
		}
	}
	d := &o.last
	delta = session.Ext_Totals {
		vpn_rx_bytes  = sub0(t.vpn_rx_bytes, d.vpn_rx_bytes),
		vpn_tx_bytes  = sub0(t.vpn_tx_bytes, d.vpn_tx_bytes),
		vpn_rx_pkts   = sub0(t.vpn_rx_pkts, d.vpn_rx_pkts),
		vpn_tx_pkts   = sub0(t.vpn_tx_pkts, d.vpn_tx_pkts),
		link_rx_bytes = sub0(t.link_rx_bytes, d.link_rx_bytes),
		link_tx_bytes = sub0(t.link_tx_bytes, d.link_tx_bytes),
		link_rx_pkts  = sub0(t.link_rx_pkts, d.link_rx_pkts),
		link_tx_pkts  = sub0(t.link_tx_pkts, d.link_tx_pkts),
		rx_drops      = sub0(t.rx_drops, d.rx_drops),
		tx_drops      = sub0(t.tx_drops, d.tx_drops),
		rx_no_key     = sub0(t.rx_no_key, d.rx_no_key),
		rx_replay     = sub0(t.rx_replay, d.rx_replay),
		rx_auth       = sub0(t.rx_auth, d.rx_auth),
		rx_bad        = sub0(t.rx_bad, d.rx_bad),
		tx_no_key     = sub0(t.tx_no_key, d.tx_no_key),
		rx_src        = sub0(t.rx_src, d.rx_src),
		epoch_adv_tx  = t.epoch_adv_tx,
		epoch_adv_rx  = t.epoch_adv_rx,
		epoch_tx      = t.epoch_tx,
		epoch_rx      = t.epoch_rx,
	}
	d^ = t
	if s != nil {
		session.session_ext_report(s, t, now)
	}
	return delta, true
}

sub0 :: proc "contextless" (a, b: u64) -> u64 {
	return a - b if a >= b else 0
}

dco_totals :: proc "contextless" (ps: ^dco.Peer_Stats) -> session.Ext_Totals {
	return session.Ext_Totals {
		vpn_rx_bytes = ps.vpn_rx_bytes,
		vpn_tx_bytes = ps.vpn_tx_bytes,
		vpn_rx_pkts = ps.vpn_rx_packets,
		vpn_tx_pkts = ps.vpn_tx_packets,
		link_rx_bytes = ps.link_rx_bytes,
		link_tx_bytes = ps.link_tx_bytes,
		link_rx_pkts = ps.link_rx_packets,
		link_tx_pkts = ps.link_tx_packets,
		rx_drops = ps.rx_drops,
		tx_drops = ps.tx_drops,
		rx_no_key = ps.rx_no_key,
		rx_replay = ps.rx_replay,
		rx_auth = ps.rx_auth,
		rx_bad = ps.rx_bad,
		tx_no_key = ps.tx_no_key,
		rx_src = ps.rx_src,
	}
}

// ------------------------------------------------------------ conversions

// A session peer address (family byte, IP, port) as a socket address.
dco_sockaddr :: proc(b: []u8) -> (ss: dco.Sockaddr_Storage, ok: bool) {
	switch {
	case len(b) == 7 && b[0] == 4:
		return dco.sockaddr_v4({b[1], b[2], b[3], b[4]}, u16(b[5]) << 8 | u16(b[6])), true
	case len(b) == 19 && b[0] == 6:
		ip: [16]u8
		copy(ip[:], b[1:17])
		return dco.sockaddr_v6(ip, u16(b[17]) << 8 | u16(b[18])), true
	}
	return {}, false
}

// A socket address of the service as a session peer address. An IPv4 address in
// IPv6 form (what a dual-stack socket sees) becomes IPv4.
dco_peer_addr :: proc(ss: ^dco.Sockaddr_Storage) -> (a: session.Peer_Addr, ok: bool) {
	fam, ip, port, pok := dco.sockaddr_parse(ss)
	if !pok {
		return {}, false
	}
	if fam == dco.AF_INET {
		return session.peer_addr_v4({ip[0], ip[1], ip[2], ip[3]}, port), true
	}
	mapped := true
	for i in 0 ..< 10 {
		if ip[i] != 0 {
			mapped = false
		}
	}
	if mapped && ip[10] == 0xff && ip[11] == 0xff {
		return session.peer_addr_v4({ip[12], ip[13], ip[14], ip[15]}, port), true
	}
	return session.peer_addr_v6(ip, port), true
}

// What the daemon does for an event of the backend.
Dco_Act :: enum u8 {
	None, // not ours, or nothing to do
	Expired, // the keepalive timeout ran out: ping-restart
	Link_Error, // the transport failed
	Key_Swap, // the send packet ids of a key are nearly used up: rekey
	Float, // the peer's address changed (server)
	Device_Gone, // the kernel removed the device and its peers (someone deleted it)
}

// A peer that the kernel ends with the reason "teardown" that we did not delete
// means the device is gone: the kernel sends it for every peer then.
dco_classify :: proc "contextless" (ev: ^dco.Event, kind: dco.Backend_Kind = .Service) -> Dco_Act {
	switch ev.kind {
	case .Ctrl_Rx:
		return .None // a control record: the daemon passes it to the session
	case .Peer_Del:
		#partial switch ev.reason {
		case .Expired:
			return .Expired
		case .Transport_Error, .Transport_Disconnect:
			return .Link_Error
		}
		if ev.reason == .Teardown && kind == .Kernel {
			return .Device_Gone
		}
		// Teardown and userspace: the daemon asked for it.
		return .None
	case .Peer_Float:
		return .Float
	case .Key_Swap:
		return .Key_Swap
	}
	return .None
}

// ================================================================== client

// Client state for the backend. `want`: this run uses it (`datapath udco` or
// `dco`, or `auto` and a backend responded). `kind`: which one. `active`: the
// current attempt uses it (UDP, or TCP with a backend that has `CAP_TCP`).
Dco_Client :: struct {
	link:       Dco_Link,
	o:          Dco_Owner,
	want:       bool,
	kind:       dco.Backend_Kind,
	active:     bool,
	dev:        bool, // the device is the backend's
	name:       string, // its name
	prov:       u32, // the next provisional peer id (`dco_prov_id`)
	t_stats:    Timer,
	// The next attempt runs in this process: the backend failed the setup of the last one.
	skip:       bool,
	// The backend did not respond at the last try, and the log says so: no more of these
	// lines until it responds again.
	lost:       bool,
	// The log said that the service lacks the TCP capability (until the link is created again).
	tcp_warned: bool,
	// The same for `block-ipv6` and the capability to drop IPv6.
	filter_warned: bool,
	// The last tunnel-up had a pushed `block-ipv6`. A backend that cannot drop IPv6 is not
	// used for the next attempt then (the config is known at the start, a push is not).
	pushed_block6: bool,
	// Where the last attempt runs (for the bus).
	path:       Dco_Path,
	// Creates the link and watches its socket; nil: `dco_dial`. A test replaces it.
	dial:       proc(d: ^Daemon) -> int,
}

// The data path of an attempt. `Udco` is also the data channel in this process.
Dco_Path :: enum u8 {
	None, // no attempt yet
	Userspace,
	Udco,
	Dco,
}

// The path of an attempt that runs on the backend `kind`.
dco_path_of :: proc "contextless" (kind: dco.Backend_Kind) -> Dco_Path {
	return .Dco if kind == .Kernel else .Udco
}

// The `datapath` value of the bus for a backend.
dco_datapath_name :: proc "contextless" (kind: dco.Backend_Kind) -> string {
	return "dco" if kind == .Kernel else "udco"
}

// What `dco_pick` found at the start.
Dco_Pick :: struct {
	found:         bool, // the link is up, on `kind`
	kind:          dco.Backend_Kind,
	tried_kernel:  bool,
	kernel_st:     int, // 0 when it was not tried
	tried_service: bool,
	service_st:    int,
}

// Connects the backend the mode asks for and keeps the link. `dco`: kernel.
// `udco`: service, waiting up to `wait_secs` for a missing socket. `auto`:
// kernel, then service (no wait). `userspace`: nothing. `no_kernel` skips the
// kernel (`block-ipv6`: the driver cannot drop IPv6).
dco_pick :: proc(l: ^Dco_Link, mode: config.Datapath, path: string, wait_secs: int, no_kernel := false) -> (p: Dco_Pick) {
	if (mode == .Dco || mode == .Auto) && !no_kernel {
		p.tried_kernel = true
		p.kernel_st = dco_link_connect(l, .Kernel, "")
		if p.kernel_st == 0 {
			p.found, p.kind = true, .Kernel
			return
		}
	}
	if (mode == .Udco || mode == .Auto) && dco_in_process_on(path) {
		p.tried_service = true
		p.service_st = dco_link_connect(l, .In_Process, "")
		if p.service_st == 0 {
			p.found, p.kind = true, .In_Process
		}
		return
	}
	if mode == .Udco || mode == .Auto {
		p.tried_service = true
		p.service_st = dco_link_connect_wait(l, path, wait_secs) if mode == .Udco else dco_link_connect(l, .Service, path)
		if p.service_st == 0 {
			p.found, p.kind = true, .Service
		}
	}
	return
}

// One line on what `dco_pick` decided: a warning if `dco` or `udco` is missing,
// a notice for `auto`, an info line if `dco` found the kernel driver. (The line
// for a service that was found is the caller's: it names the service.)
dco_pick_report :: proc(mode: config.Datapath, path: string, p: Dco_Pick) {
	switch mode {
	case .Userspace:
	case .Dco:
		switch {
		case p.found:
			logf(.Info, "datapath dco: using the kernel ovpn driver")
		case dco_no_module(p.kernel_st):
			logf(.Warn, "datapath dco: the kernel does not have the ovpn module (Linux 6.16 or later, modprobe ovpn), so the data path will run in this process")
		case:
			logf(.Warn, "datapath dco: cannot use the kernel ovpn driver: %s, so the data path will run in this process", dco_status_text(p.kernel_st))
		}
	case .Udco:
		switch {
		case p.found && p.kind == .In_Process:
			logf(.Info, "datapath udco: using the data channel in this process (%s)", dco_in_process_name())
		case !p.found && dco_in_process_on(path):
			logf(.Warn, "datapath udco: the data channel in this process cannot start: %s, so the data path will run in the daemon", dco_status_text(p.service_st))
		case !p.found:
			logf(.Warn, "datapath udco: cannot reach the DCO service at %s: %s, so the data path will run in this process", path, dco_status_text(p.service_st))
		}
	case .Auto:
		kernel := "no ovpn module in the kernel" if dco_no_module(p.kernel_st) else dco_status_text(p.kernel_st)
		switch {
		case p.found && p.kind == .Kernel:
			logf(.Notice, "datapath auto: using the kernel ovpn driver because the ovpn module is loaded")
		case p.found && p.kind == .In_Process:
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used (%s), so the data channel in this process (%s) will be used instead", kernel, dco_in_process_name())
		case !p.found && dco_in_process_on(path):
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used (%s) and the data channel in this process cannot start (%s), so the data path will run in the daemon", kernel, dco_status_text(p.service_st))
		case p.found:
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used (%s), so the DCO service at %s will be used instead", kernel, path)
		case:
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used (%s) and there is no DCO service at %s (%s), so the data path will run in this process", kernel, path, dco_status_text(p.service_st))
		}
	}
}

// At start: connects if the config asks. A missing backend does not stop the
// daemon: `datapath udco` and `dco` go on without it and retry at each attempt;
// `auto` leaves it out for the run. False: the daemon cannot start.
dco_client_init :: proc(d: ^Daemon) -> bool {
	mode := d.cfg.datapath
	if mode == .Userspace {
		return true
	}
	if len(d.cfg.allow_inbound) > 0 {
		logf(.Notice, "datapath %s: allow-inbound filters packets in this process, so the data path will run here", dco_mode_name(d))
		return true
	}
	when ODIN_OS != .Linux {
		if mode != .Auto {
			logf(
				.Warn,
				"datapath %s: %s has no DCO, so the data path will run in this process",
				"dco" if mode == .Dco else "udco",
				"Windows" if ODIN_OS == .Windows else "macOS",
			)
		}
		return true
	}
	c := &d.dco
	path := d.cfg.dco_socket
	block6 := d.cfg.block_ipv6
	if dco_only_tls(d) {
		logf(.Info, "datapath %s: every remote uses tls, which is always handled in this process", dco_mode_name(d))
		return true
	}
	if block6 && mode == .Dco {
		logf(.Warn, "datapath dco: the kernel ovpn driver cannot drop IPv6 traffic, which block-ipv6 requires, so the data path will run in this process")
		return true
	}
	wait_secs := DCO_WAIT_SECS
	if !dco_in_process_on(path) {
		path, wait_secs = dco_launch_start(dco.launcher, mode, d.inst_name, path, dco_launch_uid())
		d.cfg.dco_socket = path
	}
	pick := dco_pick(&c.link, mode, path, wait_secs, block6)
	if block6 && mode == .Auto {
		if !pick.found {
			logf(.Notice, "datapath auto: the kernel ovpn driver cannot be used because block-ipv6 is set, and there is no DCO service at %s (%s), so the data path will run in this process", path, dco_status_text(pick.service_st))
		}
	} else {
		dco_pick_report(mode, path, pick)
	}
	if !pick.found {
		if mode != .Auto {
			c.want = true
			c.kind = .Kernel if mode == .Dco else (.In_Process if dco_in_process_on(path) else .Service)
			c.lost = true
		}
		return true
	}
	c.want = true
	c.kind = pick.kind
	if pick.kind == .Service {
		if block6 && !dco_filter_ok(&c.link) {
			dco_filter_warn(d, false)
		}
		if !dco_tcp_ok(&c.link) && dco_wants_tcp(d) {
			if mode == .Auto {
				logf(.Notice, "datapath auto: the DCO service at %s does not support TCP (no TCP capability), so TCP remotes will be handled in this process", path)
			} else {
				logf(.Warn, "datapath udco: the DCO service at %s does not support TCP (its HELLO reply lacks the TCP capability), so TCP remotes will be handled in this process", path)
			}
			c.tcp_warned = true
		}
		logf(.Info, "DCO service at %s: %s", path, dco.daemon_name(&c.link.c))
	}
	if !dco_watch(d) {
		logf(.Error, "the data path will run in this process")
		dco_link_close(&c.link)
		c.lost = true
	}
	return true
}

// Puts the event descriptor of the link into the event loop.
dco_watch :: proc(d: ^Daemon) -> bool {
	l := &d.dco.link
	if err := event.add_fd(&d.loop, l.be.fd, {.Read}, on_dco, d); err != .None {
		logf(.Error, "cannot watch the descriptor of %s: %v", dco_who(l.be.kind), err)
		return false
	}
	l.watched = true
	return true
}

dco_client_destroy :: proc(d: ^Daemon) {
	if d.dco.link.up {
		if d.dco.link.watched {
			event.remove_fd(&d.loop, d.dco.link.be.fd)
		}
		dco_link_close(&d.dco.link)
	}
}

// The backend has keys of the epoch data format and takes them from their key material:
// a session on it may use that format (`Config.ext_epoch`).
dco_epoch_ok :: proc "contextless" (l: ^Dco_Link) -> bool {
	return l.up && l.be.epoch_keys && l.be.key_install != nil && l.be.caps & dco.CAP_KEY_TABLE != 0
}

// The service can carry TCP connections (`CAP_TCP`).
dco_tcp_ok :: proc(l: ^Dco_Link) -> bool {
	return l.up && l.be.caps & dco.CAP_TCP != 0
}

// A service that can rename a peer (`CAP_PEER_ID`) takes a TCP connection before
// its peer id is known: it goes over when created, and the handshake runs through
// CTRL_TX and CTRL_RX. Without it the handover is late (`dco_client_stream`).
dco_early_ok :: proc(l: ^Dco_Link) -> bool {
	return dco_tcp_ok(l) && l.be.caps & dco.CAP_PEER_ID != 0
}

// The server can do the same. It also needs the service to take the VPN
// addresses of the renamed peer (`CAP_PEER_ADDR`): the registry assigns them at
// login, and a multi-peer device finds the peer of an inner packet by them.
dco_server_early_ok :: proc(l: ^Dco_Link) -> bool {
	return dco_early_ok(l) && l.be.caps & dco.CAP_PEER_ADDR != 0
}

// Does a remote of the config use TCP?
dco_wants_tcp :: proc(d: ^Daemon) -> bool {
	for c in d.cfg.connections {
		if c.proto == .Tcp && !c.tls {
			return true
		}
	}
	return false
}

// Are all remotes of the config `tls`? Neither backend handles the outer TLS, so
// such a client does not need one.
dco_only_tls :: proc(d: ^Daemon) -> bool {
	if len(d.cfg.connections) == 0 {
		return false
	}
	for c in d.cfg.connections {
		if !c.tls {
			return false
		}
	}
	return true
}

// The mode as the config spells it, for the log.
dco_mode_name :: proc(d: ^Daemon) -> string {
	return config.datapath_name(d.cfg.datapath)
}

// Creates the link again (it went away since the last attempt, or the backend was not
// there) and watches its descriptor. 0 or a negative errno.
dco_dial :: proc(d: ^Daemon) -> int {
	c := &d.dco
	if c.kind == .Service {
		dco_launch_revive()
	}
	if st := dco_link_connect(&c.link, c.kind, d.cfg.dco_socket); st != 0 {
		return st
	}
	if !dco_watch(d) {
		dco_link_close(&c.link)
		return dco.EIO
	}
	return 0
}

// The backend is there for this attempt: the link is up, or created again now. A
// change (gone, back) is logged once.
dco_service_reach :: proc(d: ^Daemon) -> bool {
	c := &d.dco
	if c.link.up {
		return true
	}
	st := c.dial(d) if c.dial != nil else dco_dial(d)
	if st != 0 {
		if !c.lost {
			c.lost = true
			switch {
			case c.kind == .In_Process:
				logf(.Warn, "datapath %s: the data channel in this process cannot start: %s, so the data path will run in the daemon", dco_mode_name(d), dco_status_text(st))
			case c.kind == .Service:
				logf(.Warn, "datapath %s: cannot reach the DCO service at %s: %s, so the data path will run in this process", dco_mode_name(d), d.cfg.dco_socket, dco_status_text(st))
			case dco_no_module(st):
				logf(.Warn, "datapath %s: the kernel does not have the ovpn module (Linux 6.16 or later, modprobe ovpn), so the data path will run in this process", dco_mode_name(d))
			case:
				logf(.Warn, "datapath %s: cannot use the kernel ovpn driver: %s, so the data path will run in this process", dco_mode_name(d), dco_status_text(st))
			}
		}
		return false
	}
	// The old device went with the old connection; the capabilities may be other ones.
	c.dev = false
	c.tcp_warned = false
	c.filter_warned = false
	if c.lost {
		c.lost = false
		if c.kind == .Kernel {
			logf(.Notice, "datapath %s: the kernel ovpn module is available now, so the data path will run in the kernel", dco_mode_name(d))
		} else if c.kind == .In_Process {
			logf(.Notice, "datapath %s: the data channel in this process is available now", dco_mode_name(d))
		} else {
			logf(.Notice, "datapath %s: the DCO service at %s is back, so the data path will run on it again", dco_mode_name(d), d.cfg.dco_socket)
		}
	}
	return true
}

// True if this attempt's data channel is the service's: the run wants it, it is
// reachable now, and it handles the transport. Else the attempt runs in this
// process. Call before the session is created (`ext_data` depends on
// it). A TCP connection needs `CAP_TCP`. A `tls` remote always runs in this
// process (the service does not handle the outer TLS), and so does the attempt
// after a failed service setup.
dco_for_attempt :: proc(d: ^Daemon, proto: config.Proto, tls: bool) -> bool {
	c := &d.dco
	if !c.want {
		return false
	}
	if d.cfg.disable_dco {
		// A profile of the client service with `disable-dco` (service_install
		// logs it once).
		return false
	}
	if c.skip {
		c.skip = false
		return false
	}
	if len(d.cfg.allow_inbound) > 0 {
		// A service profile or a rule reload: the start check did not see these rules.
		logf(.Info, "allow-inbound filters packets in this process, so the data path of this connection will run here")
		return false
	}
	if tls {
		logf(.Info, "tls remote: the data path will run in this process because %s does not handle the outer TLS", dco_who(c.kind))
		return false
	}
	if !dco_service_reach(d) {
		return false
	}
	if proto == .Tcp && !dco_tcp_ok(&c.link) {
		if !c.tcp_warned {
			c.tcp_warned = true
			if c.kind == .In_Process {
				logf(.Notice, "datapath %s: the data channel in this process does not support TCP, so TCP connections will be handled by the daemon", dco_mode_name(d))
			} else if d.cfg.datapath == .Auto {
				logf(.Notice, "datapath auto: the DCO service does not support TCP (no TCP capability), so TCP connections will be handled in this process")
			} else {
				logf(.Warn, "datapath udco: the DCO service at %s does not support TCP (no TCP capability), so TCP connections will be handled in this process", d.cfg.dco_socket)
			}
		}
		return false
	}
	if (d.cfg.block_ipv6 || c.pushed_block6) && !dco_filter_ok(&c.link) {
		dco_filter_warn(d, !d.cfg.block_ipv6)
		return false
	}
	return true
}

// Says once that the backend cannot drop IPv6 and `block-ipv6` lets the data path run
// in this process. `pushed`: the server asked for it.
dco_filter_warn :: proc(d: ^Daemon, pushed: bool) {
	c := &d.dco
	if c.filter_warned {
		return
	}
	c.filter_warned = true
	why := "block-ipv6 (pushed by the server)" if pushed else "block-ipv6"
	switch {
	case c.kind == .Kernel:
		logf(.Warn, "datapath %s: the kernel ovpn driver cannot drop IPv6 traffic, which %s requires, so the data path will run in this process", dco_mode_name(d), why)
	case d.cfg.datapath == .Auto:
		logf(.Notice, "datapath auto: the DCO service at %s cannot drop IPv6 (no BLOCK_IPV6 capability), which %s requires, so the data path will run in this process", d.cfg.dco_socket, why)
	case:
		logf(.Warn, "datapath udco: the DCO service at %s cannot drop IPv6 (its HELLO reply lacks the BLOCK_IPV6 capability), which %s requires, so the data path will run in this process", d.cfg.dco_socket, why)
	}
}

// The attempt is chosen for the service (`dco_for_attempt`): gives its session the
// owner. Cannot fail: the link is up.
dco_attempt_begin :: proc(d: ^Daemon) {
	c := &d.dco
	dco_owner_init(&c.o, &c.link, session.session_slots_config(&d.s))
	dco_attach(&d.s, &c.o)
	c.active = true
}

// The attempt is over: after `Datapath_Failed` the next one runs in this process.
dco_attempt_ended :: proc(d: ^Daemon, outcome: client.Outcome) {
	d.dco.skip = d.dco.want && outcome == .Datapath_Failed
}

// A failure after the attempt went to the service: its data path setup cannot
// finish (the log has the service's status text). The attempt ends with
// `Datapath_Failed`; `dco_attempt_ended` lets the next one run in this
// process. A running session gets a goodbye first.
dco_setup_failed :: proc(d: ^Daemon) {
	logf(.Warn, "%s could not set up the data path, so reconnecting now with the data path in this process", dco_who(d.dco.link.be.kind) if d.dco.link.up else dco_who(d.dco.kind))
	if d.state == .Active {
		begin_close(d, .Datapath)
	} else {
		fail_connection(d, .Datapath_Failed, {})
	}
}

// Tunnel up on a backend that cannot drop IPv6, and the server pushed
// `block-ipv6`: the attempt ends and the next one runs in this process
// (`dco_filter_warn` logs the warning).
dco_filter_attempt_end :: proc(d: ^Daemon) {
	if d.state == .Active {
		begin_close(d, .Datapath)
	} else {
		fail_connection(d, .Datapath_Failed, {})
	}
}

// The service device, in place of the tun device. Created on the first tunnel-up
// of a run (and again after the service lost it), configured like the tun
// device through sysnet by index.
dco_client_device :: proc(d: ^Daemon) -> bool {
	c := &d.dco
	name := client_dev_name(d)
	idx, ok := dco_open_device(&c.link, name, .P2p)
	if !ok {
		return false
	}
	c.dev = true
	c.name = name if name != "" else "tun0"
	if d.cfg.block_ipv6 && !dco_client_filter(d, true) {
		return false
	}
	d.ifindex = idx
	if q := d.cfg.txqueuelen; q > 0 {
		if qerr := sysnet.link_set_txqlen(&d.sys, d.ifindex, u32(q)); qerr != .None {
			logf(.Warn, "cannot set txqueuelen %d on %s: %v", q, tun_name(d), qerr)
		}
	}
	client.netcfg_init(&d.nc, &d.sys, d.ifindex)
	d.nc_ok = true
	logf(.Info, "tun device %s (index %d) created by %s", tun_name(d), d.ifindex, dco_who(c.link.be.kind))
	return true
}

// Sets the IPv6 filter of the device as `block-ipv6` asks (`want`). False: the service
// refused (said in the log).
dco_client_filter :: proc(d: ^Daemon, want: bool) -> bool {
	l := &d.dco.link
	if !l.dev || l.filtered == want {
		return true
	}
	rx, tx, st := dco_filter_call(l, want)
	if st != 0 {
		logf(.Error, "%s refused the IPv6 filter: %s", dco_who(l.be.kind), dco_why(l, st))
		return false
	}
	d.stats.drop_block6_rx += rx
	d.stats.drop_block6_tx += tx
	if want {
		logf(.Info, "block-ipv6: %s will drop IPv6 packets", dco_who(l.be.kind))
	}
	return true
}

// The device must exist before a peer: created at tunnel-up or, for a TCP
// connection that goes to the service early, when the connection is created. An
// old userspace device of an earlier attempt goes first. False: failed (in the
// log).
dco_client_prepare :: proc(d: ^Daemon) -> bool {
	if d.tun_open {
		teardown_network(d, true) // a tun device of an attempt that ran here
	}
	return d.dco.dev || dco_client_device(d)
}

// In-process attempt (`tls` remote, service missing, or last setup failed) while
// the service still holds the device of an earlier attempt: the service closes
// it first, so this process can open its own tun device with the same name. The
// earlier addresses and routes go with it. No-op if the service holds no device.
dco_client_release_device :: proc(d: ^Daemon) {
	if !d.dco.dev {
		// A device that the service created but gave no index for: no addresses to take
		// away, but it must go.
		if d.dco.link.dev {
			dco_close_device(&d.dco.link)
		}
		return
	}
	name := d.dco.name
	teardown_network(d, true)
	logf(.Info, "tun device %s released by %s", name, dco_who(d.dco.link.be.kind) if d.dco.link.up else dco_who(d.dco.kind))
}

// Next provisional peer id of a TCP connection: one of the top DCO_PROV_CLIENT
// ids below 0xffffff, in turn, so a message queued for the last attempt's peer
// does not meet the next one.
dco_prov_id :: proc(c: ^Dco_Client) -> u32 {
	id := u32(DCO_PROV_TOP) - c.prov % DCO_PROV_CLIENT
	c.prov += 1
	return id
}

// TCP with `CAP_PEER_ID`: the connection goes to the service right after it is
// created, before the handshake, under a provisional id (`dco_client_peer_id`
// renames the peer when the pushed id is known).
// - No read ahead (except bytes behind an HTTP proxy reply: `ahead`).
// - The service owns the stream: session records go out with CTRL_TX, come in as
//   CTRL_RX events (`send_link`, `on_dco`); our socket is closed.
// - Session keys go in under the provisional id.
// False: failed, connection finished (in the log).
dco_client_handover :: proc(d: ^Daemon, ahead: []u8 = nil) -> bool {
	c := &d.dco
	if !dco_client_prepare(d) {
		dco_setup_failed(d)
		return false
	}
	ra := endpoint_peer_addr(d.endpoint)
	remote, rok := dco_sockaddr(session.peer_addr_bytes(&ra))
	if !rok {
		logf(.Error, "cannot use the server address for %s", dco_who(c.link.be.kind))
		fail_connection(d, .Connect_Failed, {})
		return false
	}
	p := dco.New_Peer {
		peer_id = dco_prov_id(c),
		flags   = dco.PEER_REMOTE,
		remote  = remote,
	}
	// Nothing was written to our socket since the connect (the proxy request, if
	// any, is out), so nothing to flush. Nothing was read, except bytes behind a
	// proxy reply: they go along.
	st := dco_peer_create_stream(&c.o, &p, d.sock.fd, ahead)
	if c.o.stream {
		// The service has its own copy of the socket, and reads and writes from now on.
		close_transport(d)
	}
	if st != 0 {
		logf(.Error, "%s refused the TCP peer: %s", dco_who(c.link.be.kind), dco_why(&c.link, st))
		dco_setup_failed(d)
		return false
	}
	c.o.last = {}
	logf(.Debug, "TCP connection handed to %s (provisional peer id %d)", dco_who(c.link.be.kind), p.peer_id)
	return true
}

// The tunnel is configured: create the peer in the service. False: failed (said in
// the log).
dco_client_peer :: proc(d: ^Daemon, po: ^push.Pushed_Options) -> bool {
	c := &d.dco
	id := session.session_peer_id(&d.s)
	if id >= u32(0xffffff) {
		logf(.Error, "the server did not push a peer-id, which %s requires", dco_who(c.link.be.kind))
		return false
	}
	ra := endpoint_peer_addr(d.endpoint)
	remote, rok := dco_sockaddr(session.peer_addr_bytes(&ra))
	if !rok {
		logf(.Error, "cannot use the server address for %s", dco_who(c.link.be.kind))
		return false
	}
	p := dco.New_Peer {
		peer_id = id,
		flags   = dco.PEER_REMOTE,
		remote  = remote,
	}
	if ifc, ok := po.ifconfig.?; ok {
		p.flags |= dco.PEER_VPN4
		p.vpn4 = ifc.a
	}
	if ifc6, ok := po.ifconfig6.?; ok {
		p.flags |= dco.PEER_VPN6
		p.vpn6 = ifc6.addr
	}
	interval, timeout := session.session_keepalive(&d.s)
	dco_peer_set(&c.o, u32(max(interval, 0)), u32(max(timeout, 0)), u32(d.mss4))
	if d.proto == .Tcp {
		return dco_client_stream(d, &p, id, interval, timeout)
	}
	// The client socket is passed again for every peer: a reconnect has a new one.
	if st := dco_peer_create(&c.o, &p, d.sock.fd); st != 0 {
		logf(.Error, "%s refused the peer: %s", dco_who(c.link.be.kind), dco_why(&c.link, st))
		return false
	}
	c.o.last = {}
	dco_client_stats_arm(d)
	logf(.Info, "DCO peer %d: keepalive %d/%d s", id, interval, timeout)
	return true
}

// Push reply read, connection already the service's (early handover): the peer
// takes the pushed id, then its keepalive values. Runs first at tunnel-up,
// before addresses and routes: the server sends data once it has our peer, and a
// packet with the new id is lost until the service knows it. Tunnel addresses
// are not needed (one peer on a point to point device).
dco_client_peer_id :: proc(d: ^Daemon) -> bool {
	c := &d.dco
	id := session.session_peer_id(&d.s)
	if id >= u32(0xffffff) {
		logf(.Error, "the server did not push a peer-id, which %s requires", dco_who(c.link.be.kind))
		return false
	}
	if st := dco_peer_rename(&c.o, id); st != 0 {
		logf(.Error, "%s refused the peer id %d: %s", dco_who(c.link.be.kind), id, dco_why(&c.link, st))
		return false
	}
	interval, timeout := session.session_keepalive(&d.s)
	if st := dco_peer_set(&c.o, u32(max(interval, 0)), u32(max(timeout, 0)), u32(d.mss4)); st != 0 {
		logf(.Error, "%s refused the keepalive values: %s", dco_who(c.link.be.kind), dco_why(&c.link, st))
		return false
	}
	dco_client_stats_arm(d)
	logf(.Info, "DCO peer %d (TCP, the service has owned the connection since it was created): keepalive %d/%d s", id, interval, timeout)
	return true
}

// TCP, late handover (service without `CAP_PEER_ID`): the connection goes to the
// service now, when UDP creates the peer. The peer id is the pushed one (data
// packets carry it), so it is not known earlier. Until here the handshake ran on
// our socket. Bytes the session read but did not use go along; a data frame
// right behind the push reply is lost (it reached the session before the service
// had the peer). Then control records use CTRL_TX and CTRL_RX (`send_link`,
// `on_dco`).
dco_client_stream :: proc(d: ^Daemon, p: ^dco.New_Peer, id: u32, interval, timeout: int) -> bool {
	c := &d.dco
	if net.tcp_pending(&d.tcp) > 0 {
		// What was queued must be on the wire before the service writes after it.
		if _, ok := stream_flush(d); !ok {
			return false
		}
		if net.tcp_pending(&d.tcp) > 0 {
			logf(.Error, "cannot hand the TCP connection to %s: there is still output waiting to be sent", dco_who(c.link.be.kind))
			return false
		}
	}
	ahead := session.session_stream_take(&d.s)
	st := dco_peer_create_stream(&c.o, p, d.sock.fd, ahead)
	if c.o.stream {
		// The service has its own copy of the socket, and reads and writes from now on.
		close_transport(d)
	}
	if st != 0 {
		logf(.Error, "%s refused the TCP peer: %s", dco_who(c.link.be.kind), dco_why(&c.link, st))
		return false
	}
	c.o.last = {}
	dco_client_stats_arm(d)
	logf(.Info, "DCO peer %d: TCP connection with %s, %d bytes read ahead, keepalive %d/%d s", id, "the kernel" if c.link.be.kind == .Kernel else "the service", len(ahead), interval, timeout)
	return true
}

// Counters from the service into the session and the daemon's own numbers (the
// ones that count tun traffic in the userspace path).
dco_client_refresh :: proc(d: ^Daemon) {
	c := &d.dco
	if !c.active || !d.s_ok {
		return
	}
	delta, ok := dco_stats(&c.o, &d.s, now_of(d))
	if !ok {
		return
	}
	s := &d.stats
	s.tun_read_pkts += delta.vpn_tx_pkts
	s.tun_read_bytes += delta.vpn_tx_bytes
	s.tun_write_pkts += delta.vpn_rx_pkts
	s.tun_write_bytes += delta.vpn_rx_bytes
	s.sent_pkts += delta.link_tx_pkts
	if c.o.stream {
		// TCP: the service drops a data packet while the stream is blocked, as our own
		// queue does (the oldest first); the sockets are not lossy, so these are all.
		s.drop_ring += sub0(delta.tx_drops, delta.tx_no_key)
	} else {
		s.drop_tun_write += sub0(delta.tx_drops, delta.tx_no_key)
	}
	s.drop_seal += delta.tx_no_key
	rx6, tx6 := dco_filter_poll(&c.link)
	s.drop_block6_rx += rx6
	s.drop_block6_tx += tx6
}

// Failures of the owner (a command the service refused). Before tunnel-up: a
// failed data path setup (the next attempt runs in this process). After: the
// connection ends, like a link error.
dco_client_check :: proc(d: ^Daemon) {
	c := &d.dco
	if !c.active || c.o.err == 0 || !d.s_ok {
		return
	}
	if d.close_reason == .Datapath {
		// The attempt is ending for this already; the goodbye may fail on the same service.
		c.o.err = 0
		return
	}
	text := dco_err_text(&c.o)
	logf(.Error, "%s failed %s: %s", dco_who(c.link.be.kind), c.o.err_op, text)
	c.o.err = 0
	if !d.up && d.close_reason == .None {
		dco_setup_failed(d)
		return
	}
	session.session_abort(&d.s, .Internal, "the DCO backend failed a command")
}

dco_client_stats_arm :: proc(d: ^Daemon) {
	c := &d.dco
	secs := DCO_STATS_SLOW
	if d.cfg.tls.reneg_bytes > 0 || d.cfg.tls.reneg_pkts > 0 {
		secs = DCO_STATS_FAST
	}
	timer_set(d, &c.t_stats, now_of(d) + time.Duration(secs) * time.Second, on_dco_stats_timer)
}

on_dco_stats_timer :: proc(loop: ^event.Loop, id: event.Timer_Id, user: rawptr) {
	d := (^Daemon)(user)
	d.dco.t_stats.on = false
	if !d.dco.active || !d.s_ok || d.state != .Active {
		return
	}
	dco_client_refresh(d)
	pump(d)
	flush_tx(d)
	dco_client_stats_arm(d)
}

// The attempt is over: the stats for the last time, the peer out of the service.
// Call it before `session_destroy`.
dco_client_end :: proc(d: ^Daemon) {
	c := &d.dco
	if !c.active {
		return
	}
	dco_client_refresh(d)
	timer_clear(d, &c.t_stats)
	c.active = false
}

// The device goes: with the tunnel (no persist-tun), or at the end.
dco_client_device_close :: proc(d: ^Daemon) {
	c := &d.dco
	if c.dev {
		dco_close_device(&c.link)
		c.dev = false
	}
}

// The descriptor of the backend is readable: events, or the end of the connection.
on_dco :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	d := (^Daemon)(user)
	c := &d.dco
	for _ in 0 ..< 256 {
		ev: dco.Event
		r := c.link.be.next_event(c.link.be.user, &ev)
		if r == 0 {
			break
		}
		if r < 0 {
			dco_client_lost(d)
			return
		}
		if ev.kind == .Ctrl_Rx {
			dco_client_ctrl(d, &ev)
		} else {
			dco_client_event(d, &ev)
		}
		if !c.link.up {
			return
		}
	}
	pump(d)
	flush_tx(d)
}

// A control record from the stream that the service owns: the session takes it as
// it would take a frame from its own socket.
dco_client_ctrl :: proc(d: ^Daemon, ev: ^dco.Event) {
	c := &d.dco
	if !c.active || !d.s_ok || !c.o.stream || !dco_owns_id(&c.o, ev.peer_id) || c.o.gone {
		return
	}
	dco_ctrl_receive(&c.link, &d.s, now_of(d))
}

dco_client_event :: proc(d: ^Daemon, ev: ^dco.Event) {
	c := &d.dco
	act := dco_classify(ev, c.link.be.kind)
	if !c.active || !d.s_ok || !c.o.created || !dco_owns_id(&c.o, ev.peer_id) {
		if act != .None {
			logf(.Debug, "DCO event for peer %d ignored (no such peer here)", ev.peer_id)
		}
		return
	}
	switch act {
	case .None, .Float:
	case .Device_Gone:
		dco_client_device_gone(d)
	case .Expired:
		dco_peer_dropped(&c.o)
		logf(.Notice, "%s: no packets were received from the server within the ping-restart time", dco_who(c.link.be.kind))
		session.session_abort(&d.s, .Ping_Timeout, fmt.tprintf("ping-restart (%s)", dco_who_short(c.link.be.kind)))
	case .Link_Error:
		dco_peer_dropped(&c.o)
		if c.o.stream {
			// What a read error or EOF on our own socket would be.
			logf(.Warn if d.close_reason == .None else .Debug, "the TCP connection ended (%s: %v)", dco_who(c.link.be.kind), ev.reason)
		} else {
			logf(.Warn, "%s lost the link to the server (%v)", dco_who(c.link.be.kind), ev.reason)
		}
		session.session_abort(&d.s, .Link_Error, "the DCO backend lost the link")
	case .Key_Swap:
		logf(.Debug, "%s: data key %d is nearly used up; renegotiating", dco_who(c.link.be.kind), ev.key_id)
		session.session_ext_key_swap(&d.s, now_of(d))
	}
}

// The service went away: its device is gone with it. The connection is treated
// as a link failure; the next attempt connects again.
dco_client_lost :: proc(d: ^Daemon) {
	c := &d.dco
	kind := c.link.be.kind
	logf(.Error, "the connection to %s was lost", dco_who(kind))
	if c.link.watched {
		event.remove_fd(&d.loop, c.link.be.fd)
	}
	dco_link_close(&c.link)
	c.o.gone = true
	timer_clear(d, &c.t_stats)
	// The device went with the connection; take what we set on it away.
	if c.dev {
		teardown_network(d, true)
	}
	if d.s_ok && d.state == .Active && c.active {
		session.session_abort(&d.s, .Link_Error, fmt.tprintf("%s is gone", dco_who(kind)))
		pump(d)
	}
}

// The kernel removed the device (someone deleted it) and the peer with it: the
// attempt ends as a link failure. The device is closed here too (the kernel
// forgets it, the daemon's state goes), so the next attempt creates a new one.
dco_client_device_gone :: proc(d: ^Daemon) {
	c := &d.dco
	if !c.active || !c.o.created || c.o.gone {
		return
	}
	logf(.Error, "the kernel removed the ovpn device %s, so the connection will end", c.name if c.name != "" else tun_name(d))
	dco_peer_dropped(&c.o)
	// The kernel's view of the device is gone; persist-tun cannot keep what is not there.
	dco_close_device(&c.link)
	d.persist = false
	if d.s_ok && d.state == .Active {
		session.session_abort(&d.s, .Link_Error, "the ovpn device was removed")
	}
}

// The address in the form the session wants (`session.peer_addr_v4`).
endpoint_peer_addr :: proc "contextless" (ep: net.Endpoint) -> (r: session.Peer_Addr) {
	switch a in ep.address {
	case net.IP4_Address:
		return session.peer_addr_v4(cast([4]u8)a, u16(ep.port))
	case net.IP6_Address:
		return session.peer_addr_v6(transmute([16]u8)a, u16(ep.port))
	}
	return
}

// `datapath` value of status and stats of a client: "dco" or "udco" if the
// backend carries the data channel, else "userspace". Shows where the last
// attempt ran (a fallback shows here); before the first attempt, where the run
// wants it.
daemon_datapath :: proc(d: ^Daemon) -> string {
	if name, ok := client_datapath(d); ok {
		return name
	}
	return dco_datapath_name(d.dco.kind) if d.dco.want && !d.dco.lost && !d.cfg.disable_dco else "userspace"
}

// The `datapath` of `client.state`: where the current attempt runs, or the last
// one while the client waits between attempts. `ok` is false before the first attempt.
client_datapath :: proc(d: ^Daemon) -> (name: string, ok: bool) {
	switch d.dco.path {
	case .None:
		return "", false
	case .Userspace:
		return "userspace", true
	case .Udco:
		return "udco", true
	case .Dco:
		return "dco", true
	}
	return "", false
}
