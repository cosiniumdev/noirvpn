// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/reliable"
import "noir:proto/wire"
import "noir:proto/wrap"

@(private)
aead_of :: proc "contextless" (c: push.Cipher) -> ossl.Aead_Cipher {
	switch c {
	case .Aes_128_Gcm:
		return .AES_128_GCM
	case .Aes_256_Gcm, .None:
		return .AES_256_GCM
	case .Chacha20_Poly1305:
		return .CHACHA20_POLY1305
	}
	return .AES_256_GCM
}

// The data packet format that the protocol flags select.
@(private)
format_of_flags :: proc "contextless" (f: push.Protocol_Flags) -> keys.Format {
	return .Epoch if .Aead_Epoch in f else .Baseline
}

// Bytes in front of the payload in a sealed packet, and behind it.
@(private)
format_room :: proc "contextless" (f: keys.Format) -> (head, tail: int) {
	if f == .Epoch {
		return crypt.EPOCH_HEADROOM, crypt.EPOCH_TAILROOM
	}
	return crypt.BASELINE_HEADROOM, 0
}

// Exports the keying material of the control key state and derives the data key
// (and, for key 0, the dynamic tls-crypt wrap) from it.
@(private)
install_keys :: proc(s: ^Session, now: Time) -> bool {
	ks := &s.ks
	role := wire.Role.Client if s.role == .Client else wire.Role.Server
	if ks.id == 0 && .Dyn_Tls_Crypt in s.flags {
		dexp: [wrap.DYNAMIC_EXPORT_LEN]u8
		ok := ossl.tls_export_keying_material(&ks.tls, wrap.DYNAMIC_TLS_CRYPT_LABEL, dexp[:])
		if !ok {
			zero_bytes(dexp[:])
			fail(s, .Key_Export, "the export of the dynamic tls-crypt key failed")
			return false
		}
		orig: ^wrap.Static_Key = &s.wrap.orig_key if s.wrap.have_key else nil
		derr := wrap.dynamic_tls_crypt_init(&s.wrap.dyn, dexp[:], orig, role)
		zero_bytes(dexp[:])
		if derr != .None {
			fail(s, .Internal, "dynamic tls-crypt")
			return false
		}
		s.wrap.have_dyn = true
	}
	export: [keys.EXPORT_LEN]u8
	if !ossl.tls_export_keying_material(&ks.tls, keys.EXPORT_LABEL, export[:]) {
		fail(s, .Key_Export, "the key export failed")
		return false
	}
	cipher := aead_of(s.cipher)
	m, merr := keys.derive_material(export[:], role, cipher)
	keys.export_wipe(export[:])
	if merr != .None {
		fail(s, .Key_Export, "the key material is not valid")
		return false
	}
	defer keys.material_wipe(&m)
	// At most three keys have crypto state at a time (the grace key goes when the
	// soft reset begins, before the new key arrives).
	if card(keys.slots_in_use(&s.slots)) >= DATA_KEYS {
		fail(s, .Internal, "there is no free slot for a data key")
		return false
	}
	opts := crypt.Key_Options {
		limit_override = s.cfg.limit_override,
	}
	// One format for every key of the session: `aead-epoch` is a property of
	// the connection. Each key id has its own chain, which
	// starts at epoch 1 (9.2).
	s.format = format_of_flags(s.flags)
	// The key is generated here and handed to the data plane. From the command on it
	// belongs to the data plane (the other thread, when there is one). With an
	// owner outside the process (`ext_data`) it gets the key material instead.
	dk: crypt.Data_Key
	defer wipe_key(&dk)
	ext := s.cfg.ext_data
	if ext {
		if s.format != .Baseline && !s.cfg.ext_epoch {
			fail(s, .Internal, "the epoch data format needs a data channel with epoch keys")
			return false
		}
	} else if crypt.data_key_init(&dk, s.format, cipher, ks.id, &m, opts) != .None {
		fail(s, .Internal, "data key")
		return false
	}
	if _, serr := keys.slots_install(&s.slots, ks.id, now); serr != .None {
		if !ext {
			crypt.data_key_destroy(&dk)
		}
		fail(s, .Protocol, "the key id is already in use")
		return false
	}
	cmd := Dp_Cmd {
		kind    = .Install,
		key_id  = ks.id,
		now     = now,
		key     = &dk if !ext else nil,
		format  = s.format,
		peer_id = s.peer_id,
		policy  = session_policy(s),
	}
	if ext {
		cmd.material = &m
		cmd.cipher = cipher
		// Bytes and packets for `reneg-bytes` and `reneg-pkts` count from here.
		s.ext_base = s.ext_seen
	}
	dp_send(s, &cmd)
	return true
}

// ------------------------------------------------------------------- send

// Bytes a sealed tunnel packet has over its IP packet: the AEAD header, packet
// id or epoch and counter, the tag, and on TCP the length prefix.
session_seal_overhead :: proc "contextless" (s: ^Session) -> int {
	n := crypt.packet_overhead(s.format)
	if s.transport == .Tcp {
		n += wire.FRAME_PREFIX_LEN
	}
	return n
}

// What a seal did, on the session's side: the counters, the clock, and the
// rekey that a used-up key or the packet count asks for. False if the packet
// was not sealed.
@(private)
seal_done :: proc(s: ^Session, r: Dp_Seal, now: Time) -> bool {
	if r.exhausted && !s.rekeying && !s.closing && s.state == .Up && is_primary(s, r.key) {
		begin_rekey(s, keys.key_id_next(s.ks.id), false, now)
	}
	if r.err != .None {
		return false
	}
	s.last_tx = now
	s.counters.data_tx += 1
	if r.due && is_primary(s, r.key) {
		start_rekey(s, now)
	}
	return true
}

// Is `id` the newest key of the session?
@(private)
is_primary :: proc(s: ^Session, id: u8) -> bool {
	cur, _, ok := keys.slots_primary(&s.slots)
	return ok && cur == id
}

// Checks that a tunnel packet of `n` bytes can be sealed now.
session_encap_check :: proc(s: ^Session, buf: []u8, n: int) -> Error {
	if s.state != .Up {
		return .Not_Up
	}
	_, tail := format_room(s.format)
	if n <= 0 || len(buf) < TUNNEL_HEADROOM + n + tail {
		return .Buffer_Too_Small
	}
	return .None
}

// The session's part after the data plane sealed a tunnel packet (`r` is the
// `dp_seal` result for `buf` and `n`): counters, rekey checks. Returns the link
// packet, a slice of `buf`.
// A daemon with a batch, in packet order:
// 1. `session_encap_check`
// 2. hand the packet to the data plane (`session_dp`)
// 3. call this with the result
session_encap_done :: proc(s: ^Session, buf: []u8, r: Dp_Seal, now: Time) -> (pkt: []u8, err: Error) {
	if !seal_done(s, r, now) {
		return nil, r.err
	}
	s.counters.tunnel_tx += 1
	return buf[r.start:r.end], .None
}

// Seals one tunnel packet. The IP packet must already be at
// `buf[TUNNEL_HEADROOM:][:n]` (read it from the tun device to there). Returns the
// link packet, a slice of `buf`, ready for the socket (with the length prefix
// for TCP). Valid until `buf` is reused.
session_encap :: proc(s: ^Session, buf: []u8, n: int, now: Time) -> (pkt: []u8, err: Error) {
	if cerr := session_encap_check(s, buf, n); cerr != .None {
		return nil, cerr
	}
	return session_encap_done(s, buf, seal_now(s, buf, n, true, now), now)
}

// The data plane of this session for a seal or an open that a daemon runs
// itself (on its worker): nil when the data channel is on this thread.
session_remote_dp :: proc "contextless" (s: ^Session) -> ^Data_Plane {
	return s.rdp
}

// A data packet created by the engine itself (keepalive, exit notice), written to
// the start of `out`.
@(private)
internal_data_packet :: proc(s: ^Session, out: []u8, plain: []u8, now: Time) -> int {
	copy(out[TUNNEL_HEADROOM:], plain)
	r := seal_now(s, out, len(plain), false, now)
	if !seal_done(s, r, now) {
		return 0
	}
	if r.start > 0 {
		copy(out, out[r.start:r.end])
	}
	n := r.end - r.start
	s.counters.link_tx_pkts += 1
	s.counters.link_tx_bytes += u64(n)
	return n
}

// Keepalive and exit notice. Called by `session_poll_tx` when no control
// packet is due.
@(private)
poll_data_tx :: proc(s: ^Session, out: []u8, now: Time) -> int {
	if s.state != .Up && s.state != .Closing {
		return 0
	}
	if s.state == .Closing {
		if !s.exit_cc && s.exit_left > 0 && now >= s.exit_next {
			buf: [crypt.OCC_PREFIX_LEN]u8
			plain, _ := crypt.build_occ_exit(buf[:])
			n := internal_data_packet(s, out, plain, now)
			s.exit_left -= 1
			s.exit_next = now + time.Second
			close_progress(s, now)
			return n
		}
		return 0
	}
	if s.ping > 0 && now - s.last_tx >= time.Duration(s.ping) * time.Second {
		buf: [crypt.PING_LEN]u8
		plain, _ := crypt.build_ping(buf[:])
		n := internal_data_packet(s, out, plain, now)
		if n > 0 {
			s.counters.ping_tx += 1
		}
		return n
	}
	return 0
}

// ---------------------------------------------------------------- receive

// A data packet. Opens it in place and returns the tunnel packet, if it is one.
// With a sink (a daemon with a batch) the packet may be kept for the batch
// instead. The daemon then calls `session_rx_finish` for it.
@(private)
process_data :: proc(s: ^Session, pkt: []u8, now: Time) -> []u8 {
	if s.state != .Up && s.state != .Closing {
		rx_drop(s, &s.counters.drop_tunnel_state, "a data packet arrived before the keys were ready")
		return nil
	}
	if s.rdp != nil && s.remote.take != nil && s.remote.take(s.remote.host, s, pkt, now) {
		return nil
	}
	return session_rx_finish(s, pkt, open_now(s, pkt, now), now, s.rx_from)
}

// The session's part after the data plane opened a data packet (`r` is the
// `dp_open` result for `pkt`): counters, clock, rekey check, keepalive and exit
// notices. Returns the tunnel packet, a slice of `pkt`. `from` is the datagram
// source (server, UDP) for the float check.
session_rx_finish :: proc(s: ^Session, pkt: []u8, r: Dp_Open, now: Time, from: []u8 = nil) -> []u8 {
	switch r.code {
	case .Short:
		rx_drop(s, &s.counters.drop_short, open_drop_text(r.code))
		return nil
	case .Bad_Header:
		rx_drop(s, &s.counters.drop_short, open_drop_text(r.code))
		return nil
	case .No_Key:
		rx_drop(s, &s.counters.drop_data_no_key, open_drop_text(r.code))
		return nil
	case .Peer_Id:
		rx_drop(s, &s.counters.drop_peer_id, open_drop_text(r.code))
		return nil
	case .Replay:
		// UDP loses and reorders; a replayed packet is just dropped. Stock TCP
		// peers never produce one.
		rx_drop(s, &s.counters.drop_data_replay, open_drop_text(r.code))
		return nil
	case .Tag:
		rx_drop(s, &s.counters.drop_data_tag, open_drop_text(r.code))
		return nil
	case .Epoch:
		// Epoch format: not the current, the retiring or one of the next four
		// epochs. A late packet of an old epoch, or noise.
		rx_drop(s, &s.counters.drop_data_epoch, open_drop_text(r.code))
		return nil
	case .Payload:
		rx_drop(s, &s.counters.drop_data_payload, open_drop_text(r.code))
		return nil
	case .Tunnel, .Ping, .Exit, .Other:
	}
	s.counters.data_rx += 1
	s.last_rx = now
	if s.role == .Server {
		saved := s.rx_from
		s.rx_from = from
		srv_float_check(s)
		s.rx_from = saved
	}
	plain := pkt[r.off:][:r.len]
	if r.due && is_primary(s, r.key) {
		start_rekey(s, now)
	}
	switch r.code {
	case .Tunnel:
		s.counters.tunnel_rx += 1
		return plain
	case .Ping:
		s.counters.ping_rx += 1
	case .Exit:
		if s.role == .Server {
			srv_peer_exit(s, now)
		} else {
			emit(s, Event{kind = .Remote_Exit})
			fail(s, .Server_Signal, "the server sent an exit notice")
		}
	case .Other, .Short, .Bad_Header, .No_Key, .Peer_Id, .Replay, .Tag, .Epoch, .Payload:
		s.counters.drop_data_payload += 1
	}
	return nil
}

// ------------------------------------------------------------------ rekey

// Starts a renegotiation if the session is in a state for it. The caller has
// found it due.
@(private)
start_rekey :: proc(s: ^Session, now: Time) {
	if s.state != .Up || s.rekeying || s.closing {
		return
	}
	id, _, ok := keys.slots_primary(&s.slots)
	if !ok {
		return
	}
	begin_rekey(s, keys.key_id_next(id), false, now)
}

// The timer's look at the rekey triggers. With the data channel on another
// thread the usage of the key is not known here: only the age is checked. The
// data plane reports the rest with the packets (`Dp_Seal.due`, `Dp_Open.due`).
@(private)
maybe_rekey :: proc(s: ^Session, now: Time) {
	if s.state != .Up || s.rekeying || s.closing {
		return
	}
	id, established, ok := keys.slots_primary(&s.slots)
	if !ok {
		return
	}
	usage: keys.Key_Usage
	if s.rdp == nil {
		if s.dp.dk_of[id] < 0 {
			return
		}
		usage = crypt.data_key_usage(&s.dp.dk[s.dp.dk_of[id]])
	}
	pol := session_policy(s)
	if keys.rekey_check(&pol, established, now, &usage) != .None {
		begin_rekey(s, keys.key_id_next(id), false, now)
	}
}

// ------------------------------------------------------------------ close

// Starts a clean exit. It tells the server by:
// - the EXIT command, if `cc-exit` was negotiated
// - else the data channel exit notice, if `explicit-exit-notify` is set (UDP
//   only)
// `Closed` is raised when done. Keep calling `session_poll_tx` and `session_tick`
// until it arrives. A session not up yet closes at once, sending nothing.
//
// Server: `kind` says how the peer ends (see `Close_Kind`). A client ignores it.
session_close :: proc(s: ^Session, now: Time, kind := Close_Kind.Exit) {
	if s.role == .Server {
		srv_close(s, now, kind)
		return
	}
	switch s.state {
	case .New, .Connecting, .Handshaking:
		s.state = .Closed
		emit(s, Event{kind = .Closed})
		return
	case .Closing, .Closed, .Failed:
		return
	case .Up:
	}
	s.closing = true
	s.state = .Closing
	ks := &s.ks
	if .Cc_Exit in s.flags && ks.state == .Generated_Keys && ks.tls_ok {
		buf: [16]u8
		n, ferr := push.cmd_frame(buf[:], "EXIT")
		if ferr == .None && ossl.tls_write_app(&ks.tls, buf[:n]) == .Ok {
			s.exit_cc = true
			s.exit_deadline = now + s.cfg.exit_timeout
			flush_tls(s, now)
			return
		}
	}
	if s.transport == .Udp && s.exit_notify > 0 && !s.cfg.ext_data {
		s.exit_left = s.exit_notify
		s.exit_next = now
		return
	}
	finish_close(s)
}

// Ends the close when the EXIT is acked (or its wait is over), or when the
// last exit notice is out.
@(private)
close_progress :: proc(s: ^Session, now: Time) {
	if s.state != .Closing {
		return
	}
	if s.exit_cc {
		// A server that was told to go lets the whole linger pass, to ack
		// retransmits of the last message.
		if s.srv.linger {
			if now >= s.exit_deadline {
				finish_close(s)
			}
		} else if reliable.all_acked(&s.ks.chan) || now >= s.exit_deadline {
			finish_close(s)
		}
	} else if s.exit_left == 0 {
		finish_close(s)
	}
}

@(private)
finish_close :: proc(s: ^Session) {
	if s.state == .Closing {
		s.state = .Closed
		emit(s, Event{kind = .Closed})
	}
}

// Plain base64 decode into `dst` (no allocation). Padding ends the input.
@(private)
b64_decode :: proc "contextless" (src: string, dst: []u8) -> (n: int, ok: bool) {
	val :: proc "contextless" (c: u8) -> int {
		switch {
		case c >= 'A' && c <= 'Z':
			return int(c - 'A')
		case c >= 'a' && c <= 'z':
			return int(c - 'a') + 26
		case c >= '0' && c <= '9':
			return int(c - '0') + 52
		case c == '+':
			return 62
		case c == '/':
			return 63
		}
		return -1
	}
	acc, bits := 0, 0
	for c in transmute([]u8)src {
		if c == '=' {
			break
		}
		v := val(c)
		if v < 0 {
			return 0, false
		}
		acc = acc << 6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			if n >= len(dst) {
				return 0, false
			}
			dst[n] = u8(acc >> uint(bits))
			n += 1
			acc &= (1 << uint(bits)) - 1
		}
	}
	return n, true
}

// ------------------------------------------------- a data channel of a service

// What the owner of the data channel counted for this peer (`Config.ext_data`),
// totals since the peer was created.
Ext_Totals :: struct {
	vpn_rx_bytes:    u64,
	vpn_tx_bytes:    u64,
	vpn_rx_pkts:     u64,
	vpn_tx_pkts:     u64,
	link_rx_bytes:   u64,
	link_tx_bytes:   u64,
	link_rx_pkts:    u64,
	link_tx_pkts:    u64,
	rx_drops:        u64, // all of them
	tx_drops:        u64,
	// `rx_drops` by reason, when the owner knows them (they stay 0 otherwise): they
	// go to the counters of the same name of the userspace path.
	rx_no_key:       u64, // no key for the key id
	rx_replay:       u64,
	rx_auth:         u64, // failed authentication
	rx_bad:          u64, // authentic but not an IP packet
	tx_no_key:       u64, // not sent for want of a key
	// A multi-peer owner: the inner source address is not the peer's. The session
	// has no counter for it (the userspace server counts the same packets as bad
	// source in its own totals). It is only in the total `rx_drops`.
	rx_src:          u64,
	// An owner with epoch keys (`Config.ext_epoch`): how often the send and the
	// receive epoch moved, and the epochs of the key that sends now. The status
	// shows them as they are (no deltas).
	epoch_adv_tx:    u64,
	epoch_adv_rx:    u64,
	epoch_tx:        u16,
	epoch_rx:        u16,
}

@(private)
ext_delta :: proc "contextless" (now, before: u64) -> u64 {
	return now - before if now >= before else 0
}

// The `ping` and `ping-restart` this session would have run, in seconds (0 is
// off), for the data channel owner to run (`Config.ext_data`). The session's own
// timers for them are off. Valid once the peer's options are known: a client
// after the PUSH_REPLY, a server after `session_server_accept`.
session_keepalive :: proc "contextless" (s: ^Session) -> (interval, timeout: int) {
	return s.ext_ping, s.ext_ping_restart
}

// The owner reports its totals. They feed the session counters (status text, bus)
// and the rekey triggers the owner does not know: `reneg-bytes` and `reneg-pkts`
// count traffic since the newest key was installed. A due rekey starts here.
session_ext_report :: proc(s: ^Session, t: Ext_Totals, now: Time) {
	c := &s.counters
	d := &s.ext_seen
	c.tunnel_rx += ext_delta(t.vpn_rx_pkts, d.vpn_rx_pkts)
	c.tunnel_tx += ext_delta(t.vpn_tx_pkts, d.vpn_tx_pkts)
	c.data_rx += ext_delta(t.link_rx_pkts, d.link_rx_pkts)
	c.data_tx += ext_delta(t.link_tx_pkts, d.link_tx_pkts)
	c.link_rx_pkts += ext_delta(t.link_rx_pkts, d.link_rx_pkts)
	c.link_tx_pkts += ext_delta(t.link_tx_pkts, d.link_tx_pkts)
	c.link_rx_bytes += ext_delta(t.link_rx_bytes, d.link_rx_bytes)
	c.link_tx_bytes += ext_delta(t.link_tx_bytes, d.link_tx_bytes)
	c.drop_data_no_key += ext_delta(t.rx_no_key, d.rx_no_key)
	c.drop_data_replay += ext_delta(t.rx_replay, d.rx_replay)
	c.drop_data_tag += ext_delta(t.rx_auth, d.rx_auth)
	c.drop_data_payload += ext_delta(t.rx_bad, d.rx_bad)
	c.drop_ext_rx += ext_delta(t.rx_drops, d.rx_drops)
	c.drop_ext_tx += ext_delta(t.tx_drops, d.tx_drops)
	d^ = t
	if s.state != .Up || s.rekeying || s.closing {
		return
	}
	id, established, ok := keys.slots_primary(&s.slots)
	if !ok {
		return
	}
	b := &s.ext_base
	usage := keys.Key_Usage {
		tx_pkts  = ext_delta(t.vpn_tx_pkts, b.vpn_tx_pkts),
		rx_pkts  = ext_delta(t.vpn_rx_pkts, b.vpn_rx_pkts),
		tx_bytes = ext_delta(t.vpn_tx_bytes, b.vpn_tx_bytes),
		rx_bytes = ext_delta(t.vpn_rx_bytes, b.vpn_rx_bytes),
	}
	pol := session_policy(s)
	if keys.rekey_check(&pol, established, now, &usage) != .None {
		begin_rekey(s, keys.key_id_next(id), false, now)
	}
}

// The owner says the send packet ids of the newest key are nearly used up: start
// a rekey, as a sealed packet that used up a key does.
session_ext_key_swap :: proc(s: ^Session, now: Time) {
	if s.state == .Up && !s.rekeying && !s.closing {
		begin_rekey(s, keys.key_id_next(s.ks.id), false, now)
	}
}

// Ends the session with a failure that the caller found (the owner of the data
// channel lost the peer): `.Ping_Timeout` for a keepalive timeout,
// `.Link_Error` for a transport error. The `Failed` event follows.
session_abort :: proc(s: ^Session, reason: Fail_Reason, text: string) {
	fail(s, reason, text)
}
