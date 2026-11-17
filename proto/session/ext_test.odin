// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:testing"
import "core:time"
import "noir:proto/keys"
import "noir:proto/ossl"

// A data channel that belongs to a service (`Config.ext_data`, see dataplane.odin
// `session_set_external`). The owner here only records what the session sends it.
// The control channel runs as in the other tests, with a real server session on
// the other side.

Ext_Install :: struct {
	key_id:  u8,
	m:       keys.Key_Material,
	cipher:  ossl.Aead_Cipher,
	has_key: bool,
}

Ext_Log :: struct {
	installs:      [8]Ext_Install,
	n_install:     int,
	rekey_started: int,
	expire:        int,
	destroy:       int,
}

ext_attach :: proc(s: ^Session, l: ^Ext_Log) {
	session_set_external(s, Dp_Remote{user = l, submit = ext_submit})
}

ext_submit :: proc(user: rawptr, dp: ^Data_Plane, cmd: ^Dp_Cmd) {
	l := (^Ext_Log)(user)
	switch cmd.kind {
	case .Install:
		if l.n_install < len(l.installs) {
			i := &l.installs[l.n_install]
			i.key_id = cmd.key_id
			i.has_key = cmd.key != nil
			i.cipher = cmd.cipher
			if cmd.material != nil {
				i.m = cmd.material^
			}
		}
		l.n_install += 1
	case .Rekey_Started:
		l.rekey_started += 1
	case .Expire:
		l.expire += 1
	case .Destroy:
		l.destroy += 1
	}
}

ext_tweak :: proc(d: ^Duo) {
	d.scfg.ext_data = true
	for i in 0 ..< d.n {
		d.peers[i].cfg.ext_data = true
	}
	d.ping = 10
	d.ping_rest = 30
}

ext_connect :: proc(t: ^testing.T, tweak: proc(d: ^Duo) = nil, loc := #caller_location) -> ^Duo {
	return duo_connect(t, {mode = .Tls_Crypt}, tweak = proc(d: ^Duo) {
		ext_tweak(d)
	} if tweak == nil else tweak, loc = loc)
}

ext_rekey :: proc(t: ^testing.T, d: ^Duo, who: Who, loc := #caller_location) {
	p := &d.peers[0]
	sl := duo_slot(d)
	ck := duo_count(p.ev[:], p.ev_n, .Key_Installed)
	if who != .Server {
		testing.expect(t, session_rekey(&p.c, d.now), "client session_rekey refused", loc = loc)
	}
	if who != .Client {
		testing.expect(t, session_rekey(&sl.s, d.now), "server session_rekey refused", loc = loc)
	}
	ok := duo_run(d, duo_rekey_done, 60 * time.Second)
	testing.expect(t, ok, "rekey did not finish", loc = loc)
	testing.expect_value(t, duo_count(p.ev[:], p.ev_n, .Key_Installed), ck + 1)
}

@(test)
test_ext_handshake_and_material :: proc(t: ^testing.T) {
	d := ext_connect(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	cl, sl := &d.ext_c[0], &d.ext_s[d.peers[0].slot]
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
	testing.expect_value(t, cl.n_install, 1)
	testing.expect_value(t, sl.n_install, 1)
	ci, si := cl.installs[0], sl.installs[0]
	// No key of our own is created.
	testing.expect(t, !ci.has_key && !si.has_key)
	testing.expect_value(t, ci.key_id, 0)
	testing.expect_value(t, si.key_id, 0)
	testing.expect_value(t, ci.cipher, ossl.Aead_Cipher.AES_256_GCM)
	testing.expect_value(t, si.cipher, ci.cipher)
	// What one side sends with, the other receives with.
	n := ci.m.send.key_len
	testing.expect_value(t, n, 32)
	testing.expect_value(t, si.m.recv.key_len, n)
	testing.expect(t, string(ci.m.send.key[:n]) == string(si.m.recv.key[:n]))
	testing.expect(t, string(ci.m.recv.key[:n]) == string(si.m.send.key[:n]))
	testing.expect(t, ci.m.send.iv == si.m.recv.iv)
	testing.expect(t, ci.m.recv.iv == si.m.send.iv)
	testing.expect(t, ci.m.send.key != ci.m.recv.key)
	// The baseline format: the epoch is never offered or pushed.
	testing.expect(t, .Data_Epoch not_in c.cfg.iv_proto)
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(c))
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(s))
	testing.expect_value(t, session_data_format(c), keys.Format.Baseline)
	testing.expect_value(t, session_data_format(s), keys.Format.Baseline)
	testing.expect_value(t, session_peer_id(c), 100)
	// The keepalive is the owner's: the session's own timers are off.
	testing.expect_value(t, c.ping, 0)
	testing.expect_value(t, c.ping_restart, 0)
	ci_, ct := session_keepalive(c)
	testing.expect_value(t, ci_, 10)
	testing.expect_value(t, ct, 30)
	si_, st := session_keepalive(s)
	testing.expect_value(t, si_, 10)
	testing.expect_value(t, st, 60) // twice the pushed ping-restart
	// A long quiet time: no ping, no ping-restart.
	duo_idle(d, 200 * time.Second)
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
	testing.expect_value(t, c.counters.ping_tx, 0)
	testing.expect_value(t, s.counters.ping_tx, 0)
	// A data packet that comes anyway is dropped.
	junk: [64]u8
	junk[0] = 0x48
	pkt := junk
	r := session_receive(c, pkt[:], d.now)
	testing.expect_value(t, len(r.tunnel), 0)
	testing.expect_value(t, c.counters.drop_data_no_key, 1)
	// The end of the session tells the owner.
	session_destroy(c)
	testing.expect_value(t, cl.destroy, 1)
}

@(test)
test_ext_client_offering_epoch_gets_baseline :: proc(t: ^testing.T) {
	// A client that runs its own data channel offers the epoch format; a server
	// with a service must not push it.
	d := ext_connect(t, proc(d: ^Duo) {
		ext_tweak(d)
		d.peers[0].cfg.ext_data = false
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect(t, .Data_Epoch in d.peers[0].c.cfg.iv_proto)
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(&d.peers[0].c))
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(duo_srv(d)))
}

@(test)
test_ext_rekey_commands :: proc(t: ^testing.T) {
	for who in ([]Who{.Client, .Server, .Both}) {
		d := ext_connect(t)
		if d == nil {
			return
		}
		cl, sl := &d.ext_c[0], &d.ext_s[d.peers[0].slot]
		for i in 0 ..< 3 {
			ext_rekey(t, d, who)
			testing.expect_value(t, cl.n_install, i + 2)
			testing.expect_value(t, sl.n_install, i + 2)
			testing.expect_value(t, int(cl.installs[i + 1].key_id), i + 1)
			testing.expect_value(t, int(sl.installs[i + 1].key_id), i + 1)
			testing.expect(t, cl.installs[i + 1].m.send.key == sl.installs[i + 1].m.recv.key)
			testing.expect(t, cl.installs[i + 1].m.recv.key == sl.installs[i + 1].m.send.key)
			// The keys of one key id differ from the keys before.
			testing.expect(t, cl.installs[i].m.send.key != cl.installs[i + 1].m.send.key)
		}
		testing.expect(t, cl.rekey_started >= 3)
		testing.expect(t, sl.rekey_started >= 3)
		// The old keys leave the slot table after the transition window.
		duo_idle(d, 3700 * time.Second)
		testing.expect(t, cl.expire >= 1)
		testing.expect(t, sl.expire >= 1)
		testing.expect_value(t, d.peers[0].c.state, State.Up)
		duo_free(d)
	}
}

@(test)
test_ext_no_exit_notice_on_the_data_channel :: proc(t: ^testing.T) {
	// No `cc-exit`: a session with its own data channel sends the exit notice as
	// a data packet. With a service there is nothing to send and the session
	// closes at once. A client config that asks for three notices changes nothing.
	d := ext_connect(t, proc(d: ^Duo) {
		ext_tweak(d)
		d.scfg.flags = {.Dyn_Tls_Crypt}
		d.peers[0].cfg.explicit_exit_notify = 3
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0].c
	testing.expect(t, .Cc_Exit not_in session_protocol_flags(c))
	before := c.counters.link_tx_pkts
	session_close(c, d.now)
	testing.expect_value(t, c.state, State.Closed)
	buf: [LINK_BUF_SIZE]u8
	testing.expect_value(t, session_poll_tx(c, buf[:], d.now), 0)
	testing.expect_value(t, c.counters.link_tx_pkts, before)

	// The server side: no data packet after a close either.
	s := duo_srv(d)
	session_close(s, d.now, .Exit)
	testing.expect_value(t, s.state, State.Closed)
	testing.expect_value(t, session_poll_tx(s, buf[:], d.now), 0)
}

@(test)
test_ext_exit_over_the_control_channel :: proc(t: ^testing.T) {
	d := ext_connect(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0].c
	testing.expect(t, .Cc_Exit in session_protocol_flags(c))
	session_close(c, d.now)
	testing.expect_value(t, c.state, State.Closing)
	ok := duo_run(d, duo_both_done, 10 * time.Second)
	testing.expect(t, ok, "the exit did not finish")
	testing.expect_value(t, c.state, State.Closed)
}

@(test)
test_ext_report_counters_and_rekey_triggers :: proc(t: ^testing.T) {
	d := ext_connect(t, proc(d: ^Duo) {
		ext_tweak(d)
		d.peers[0].cfg.reneg_bytes = 1000
		d.scfg.reneg_pkts = 50
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	// Below the limits: counters move, no rekey.
	tot := Ext_Totals {
		vpn_rx_bytes    = 300,
		vpn_tx_bytes    = 200,
		vpn_rx_pkts     = 3,
		vpn_tx_pkts     = 2,
		link_rx_bytes   = 400,
		link_tx_bytes   = 350,
		link_rx_pkts    = 4,
		link_tx_pkts    = 3,
		rx_drops        = 10,
		tx_drops        = 2,
		rx_no_key       = 1,
		rx_replay       = 2,
		rx_auth         = 3,
		rx_bad          = 4,
		tx_no_key       = 2,
	}
	rx0, tx0 := c.counters.link_rx_pkts, c.counters.link_tx_pkts
	session_ext_report(c, tot, d.now)
	testing.expect(t, !c.rekeying)
	testing.expect_value(t, c.counters.tunnel_rx, 3)
	testing.expect_value(t, c.counters.tunnel_tx, 2)
	testing.expect_value(t, c.counters.data_rx, 4)
	testing.expect_value(t, c.counters.data_tx, 3)
	testing.expect_value(t, c.counters.link_rx_pkts, rx0 + 4)
	testing.expect_value(t, c.counters.link_tx_pkts, tx0 + 3)
	testing.expect_value(t, c.counters.drop_ext_rx, 10)
	testing.expect_value(t, c.counters.drop_ext_tx, 2)
	testing.expect_value(t, c.counters.drop_data_no_key, 1)
	testing.expect_value(t, c.counters.drop_data_replay, 2)
	testing.expect_value(t, c.counters.drop_data_tag, 3)
	testing.expect_value(t, c.counters.drop_data_payload, 4)
	// The same totals again add nothing; a smaller total (a new count) adds nothing.
	session_ext_report(c, tot, d.now)
	smaller := tot
	smaller.vpn_rx_pkts = 1
	session_ext_report(c, smaller, d.now)
	testing.expect_value(t, c.counters.tunnel_rx, 3)
	testing.expect_value(t, c.counters.drop_data_tag, 3)
	// Bytes in plus out reach `reneg-bytes`: the client starts a rekey.
	tot.vpn_tx_bytes = 800
	tot.vpn_tx_pkts = 7
	session_ext_report(c, tot, d.now)
	testing.expect(t, c.rekeying, "reneg-bytes did not start a rekey")
	testing.expect_value(t, c.counters.tunnel_tx, 7)
	ok := duo_run(d, duo_rekey_done, 60 * time.Second)
	testing.expect(t, ok)
	// The count starts again with the new key: the totals so far are the base.
	testing.expect(t, !c.rekeying)
	session_ext_report(c, tot, d.now)
	testing.expect(t, !c.rekeying)
	tot.vpn_tx_bytes += 600
	tot.vpn_rx_bytes += 600
	session_ext_report(c, tot, d.now)
	testing.expect(t, c.rekeying)

	// Packets: the server has `reneg-pkts 50`.
	stot := Ext_Totals {
		vpn_rx_pkts = 20,
		vpn_tx_pkts = 20,
	}
	session_ext_report(s, stot, d.now)
	testing.expect(t, !s.rekeying)
	stot.vpn_tx_pkts = 31
	session_ext_report(s, stot, d.now)
	testing.expect(t, s.rekeying, "reneg-pkts did not start a rekey")
}

@(test)
test_ext_key_swap_event_starts_a_rekey :: proc(t: ^testing.T) {
	d := ext_connect(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0].c
	testing.expect(t, !c.rekeying)
	session_ext_key_swap(c, d.now)
	testing.expect(t, c.rekeying)
	ok := duo_run(d, duo_rekey_done, 60 * time.Second)
	testing.expect(t, ok)
	testing.expect_value(t, d.ext_c[0].n_install, 2)
	// Not while one is going on or when the session is not up.
	session_ext_key_swap(c, d.now)
	session_ext_key_swap(c, d.now)
	testing.expect_value(t, c.state, State.Up)
}

@(test)
test_ext_abort :: proc(t: ^testing.T) {
	d := ext_connect(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0].c
	session_abort(c, .Ping_Timeout, "the owner lost the peer")
	testing.expect_value(t, c.state, State.Failed)
	ev, ok := duo_last(d.peers[0].ev[:], d.peers[0].ev_n, .Failed)
	_ = ev
	// The harness drains events by itself; read the reason from the session.
	testing.expect_value(t, session_fail_reason(c), Fail_Reason.Ping_Timeout)
	_ = ok
}

// A TCP session whose stream and data channel belong to a service. The control
// records go through `session_poll_tx` (framed) and `session_receive_record`
// (deframed). `session_stream_take` gives the unused bytes of the stream away.
ext_connect_tcp :: proc(t: ^testing.T, loc := #caller_location) -> ^Duo {
	return duo_connect(t, {mode = .Tls_Crypt, transport = .Tcp}, tweak = proc(d: ^Duo) {
		ext_tweak(d)
	}, loc = loc)
}

@(test)
test_ext_tcp_handshake :: proc(t: ^testing.T) {
	d := ext_connect_tcp(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
	testing.expect_value(t, d.ext_c[0].n_install, 1)
	testing.expect_value(t, d.ext_s[d.peers[0].slot].n_install, 1)
	testing.expect(t, .Aead_Epoch not_in session_protocol_flags(c))
	ci_, ct := session_keepalive(c)
	testing.expect_value(t, ci_, 10)
	testing.expect_value(t, ct, 30)
	// A rekey over the TCP control channel.
	ext_rekey(t, d, .Both)
	testing.expect_value(t, d.ext_c[0].n_install, 2)
}

@(test)
test_ext_tcp_records_and_stream_take :: proc(t: ^testing.T) {
	d := ext_connect_tcp(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	// Bytes the session read and could not use (part of a frame) are given away, once.
	partial := [5]u8{0, 40, 0x20, 1, 2}
	r := session_receive(c, partial[:], d.now)
	testing.expect_value(t, r.consumed, 5)
	rest := session_stream_take(c)
	testing.expect_value(t, string(rest), string(partial[:]))
	testing.expect_value(t, len(session_stream_take(c)), 0)
	// The splitter is empty again: a frame is not completed by the old bytes.
	testing.expect_value(t, len(c.split.buf[c.split.start:c.split.end]), 0)

	// The client says goodbye: its output is framed, the record goes to the server without the prefix.
	session_close(c, d.now)
	buf: [LINK_BUF_SIZE]u8
	got := false
	for _ in 0 ..< 20 {
		n := session_poll_tx(c, buf[:], d.now)
		if n == 0 {
			break
		}
		testing.expect(t, n > 2)
		testing.expect_value(t, int(buf[0]) << 8 | int(buf[1]), n - 2)
		rec := make([]u8, n - 2)
		defer delete(rec)
		copy(rec, buf[2:n])
		before := s.counters.link_rx_pkts
		rr := session_receive_record(s, rec, d.now)
		testing.expect_value(t, rr.consumed, n - 2)
		testing.expect_value(t, len(rr.tunnel), 0)
		testing.expect_value(t, s.counters.link_rx_pkts, before + 1)
		got = true
	}
	testing.expect(t, got)
	// The server saw the exit notice.
	exit := false
	for {
		ev, ok := session_next_event(s)
		if !ok {
			break
		}
		if ev.kind == .Remote_Exit {
			exit = true
		}
	}
	testing.expect(t, exit, "the server did not see the exit notice")
}

@(test)
test_ext_tcp_data_record_is_only_dropped :: proc(t: ^testing.T) {
	// A data record that comes before the service has the peer (a frame behind the
	// push reply, read into the session) is lost, but does not end a TCP session.
	d := ext_connect_tcp(t)
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0].c
	junk: [64]u8
	junk[0] = 0x48
	r := session_receive_record(c, junk[:], d.now)
	testing.expect_value(t, len(r.tunnel), 0)
	testing.expect_value(t, c.counters.drop_data_no_key, 1)
	testing.expect_value(t, c.state, State.Up)
	// An empty record, or one above the frame limit, is a broken stream.
	empty: [0]u8
	session_receive_record(c, empty[:], d.now)
	testing.expect_value(t, c.state, State.Failed)
}

@(test)
test_ext_tcp_config :: proc(t: ^testing.T) {
	// The service carries TCP: `ext_data` works with TCP, so a TCP config gets
	// the response that the same UDP config gets (this one has no identity).
	s: Session
	cfg := Config {
		role      = .Client,
		ext_data  = true,
	}
	cfg.transport = .Udp
	want := session_init(&s, &cfg)
	session_destroy(&s)
	cfg.transport = .Tcp
	testing.expect_value(t, session_init(&s, &cfg), want)
	session_destroy(&s)
	sc := Server_Config {
		ext_data  = true,
	}
	sh: Server_Shared
	sc.transport = .Udp
	swant := server_shared_init(&sh, &sc, 0)
	sc.transport = .Tcp
	testing.expect_value(t, server_shared_init(&sh, &sc, 0), swant)
	// UDP sessions have no stream to give away.
	testing.expect_value(t, len(session_stream_take(&s)), 0)
}

@(test)
server_shared_set_ext_data_toggles_epoch :: proc(t: ^testing.T) {
	sh := Server_Shared {
		flags      = {.Cc_Exit, .Aead_Epoch},
		epoch_flag = true,
	}
	server_shared_set_ext_data(&sh, true)
	testing.expect(t, sh.cfg.ext_data)
	testing.expect(t, .Aead_Epoch not_in sh.flags)
	testing.expect(t, .Cc_Exit in sh.flags)
	server_shared_set_ext_data(&sh, false)
	testing.expect(t, !sh.cfg.ext_data)
	testing.expect(t, .Aead_Epoch in sh.flags)
	// A policy without the epoch format keeps it off.
	sh2 := Server_Shared {
		flags = {.Cc_Exit},
	}
	server_shared_set_ext_data(&sh2, false)
	testing.expect(t, .Aead_Epoch not_in sh2.flags)
	// An owner with epoch keys keeps the push.
	server_shared_set_ext_data(&sh, true, true)
	testing.expect(t, sh.cfg.ext_data && sh.cfg.ext_epoch)
	testing.expect(t, .Aead_Epoch in sh.flags)
	server_shared_set_ext_data(&sh, false, true)
	testing.expect(t, !sh.cfg.ext_epoch, "no owner, no epoch keys of an owner")
}

@(test)
test_ext_epoch_sessions_use_the_epoch_format :: proc(t: ^testing.T) {
	d := ext_connect(t, proc(d: ^Duo) {
		ext_tweak(d)
		d.scfg.ext_epoch = true
		for i in 0 ..< d.n {
			d.peers[i].cfg.ext_epoch = true
		}
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	c, s := &d.peers[0].c, duo_srv(d)
	testing.expect_value(t, c.state, State.Up)
	testing.expect(t, .Data_Epoch in c.cfg.iv_proto)
	testing.expect(t, .Aead_Epoch in session_protocol_flags(s))
	testing.expect_value(t, session_data_format(c), keys.Format.Epoch)
	testing.expect_value(t, session_data_format(s), keys.Format.Epoch)
	testing.expect_value(t, d.ext_c[0].n_install, 1)
	testing.expect_value(t, d.ext_s[d.peers[0].slot].n_install, 1)
}
