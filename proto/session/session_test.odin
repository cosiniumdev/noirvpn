// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/wire"

// ------------------------------------------------------------------- helpers

// Brings a session up against the fake server. Returns nil (and logs) if it
// does not come up.
connect :: proc(t: ^testing.T, o: Fake_Opts, chunk := 0, tweak: proc(m: ^Sim) = nil, loc := #caller_location) -> ^Sim {
	m := sim_new(o)
	if m == nil {
		testing.expect(t, false, "fake server setup failed", loc = loc)
		return nil
	}
	if chunk > 0 {
		m.chunk = chunk
	}
	if tweak != nil {
		tweak(m)
	}
	if err := sim_start(m); err != .None {
		testing.expectf(t, false, "session_start: %v", err, loc = loc)
		sim_free(m)
		return nil
	}
	if !sim_run(m, g_up, 60 * time.Second) {
		sim_dump(m)
		testing.expect(t, false, "session did not come up", loc = loc)
		sim_free(m)
		return nil
	}
	return m
}

expect_echo :: proc(t: ^testing.T, m: ^Sim, loc := #caller_location) {
	sizes := [?]int{0, 1, 64, 600, 1200}
	for size in sizes {
		got := sim_echo(m, 3, size)
		testing.expectf(t, got == 3, "echo of %d bytes: %d of 3 came back", size, got, loc = loc)
	}
}

// The checks every working connection must pass.
check_basic :: proc(t: ^testing.T, o: Fake_Opts, chunk := 0, loc := #caller_location) {
	m := connect(t, o, chunk, loc = loc)
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect(t, sim_has_event(m, .Link_Up), "no Link_Up", loc = loc)
	testing.expect_value(t, sim_count_event(m, .Up), 1)
	po := session_pushed(&m.s)
	testing.expect_value(t, po.ifconfig.? or_else {}, push.Ifconfig{a = {10, 8, 0, 2}, b = {255, 255, 255, 0}})
	testing.expect_value(t, po.route_gateway.? or_else {}, [4]u8{10, 8, 0, 1})
	want_cipher := o.cipher if o.cipher != .None else push.Cipher.Aes_256_Gcm
	testing.expect_value(t, session_cipher(&m.s), want_cipher)
	// The wrapping and the opcodes on the wire.
	if o.mode == .Tls_Crypt_V2 {
		testing.expect(t, m.f.seen_ops[int(wire.Opcode.Hard_Reset_Client_V3)] >= 1, "no opcode 10", loc = loc)
		testing.expect_value(t, m.f.seen_ops[int(wire.Opcode.Hard_Reset_Client_V2)], 0)
	} else {
		testing.expect(t, m.f.seen_ops[int(wire.Opcode.Hard_Reset_Client_V2)] >= 1, "no opcode 7", loc = loc)
	}
	// What the client told the server.
	opts := fake_text(m.f.client_opts[:], m.f.client_opts_n)
	testing.expect(t, strings.contains(opts, "key-method 2"), "no key-method 2", loc = loc)
	testing.expect(t, strings.contains(opts, "tls-client"), "no tls-client", loc = loc)
	pinfo := fake_text(m.f.peer_info[:], m.f.peer_info_n)
	testing.expect(t, strings.contains(pinfo, "IV_PROTO=1950\n"), "IV_PROTO is not 1950", loc = loc)
	testing.expect(t, strings.contains(pinfo, "IV_VER="), "no IV_VER", loc = loc)
	testing.expect(t, !strings.contains(pinfo, "IV_PROTO=8094"), "IV_PROTO has the update bit", loc = loc)
	// The format follows what the server pushed.
	want_format := keys.Format.Epoch if o.epoch else keys.Format.Baseline
	testing.expect_value(t, session_data_format(&m.s), want_format)
	testing.expect_value(t, (.Aead_Epoch in session_protocol_flags(&m.s)), o.epoch)
	testing.expect(t, !strings.contains(pinfo, "ID="), "ID= must not be sent", loc = loc)
	expect_echo(t, m, loc)
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, m.s.counters.drop_unwrap, 0)
	testing.expect_value(t, m.s.counters.drop_decode, 0)
}

// ---------------------------------------------------------- connect, by wrap

@(test)
test_udp_none :: proc(t: ^testing.T) {
	check_basic(t, {})
}

@(test)
test_udp_tls_auth_sha1 :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Auth, key_direction = .One})
}

@(test)
test_udp_tls_auth_sha256_bidir :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Auth, auth_digest = .SHA256, key_direction = .Bidirectional})
}

@(test)
test_udp_tls_auth_sha512 :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Auth, auth_digest = .SHA512, key_direction = .One})
}

@(test)
test_udp_tls_crypt :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt})
}

@(test)
test_udp_tls_crypt_dyn :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt, dyn = true, cc_exit = true})
}

@(test)
test_udp_tls_crypt_v2 :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt_V2})
}

@(test)
test_udp_tls_crypt_v2_dyn :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt_V2, dyn = true, cc_exit = true})
}

@(test)
test_tcp_none :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp})
}

@(test)
test_tcp_tls_auth :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Auth, key_direction = .One})
}

@(test)
test_tcp_tls_crypt :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Crypt, dyn = true})
}

@(test)
test_tcp_tls_crypt_v2 :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Crypt_V2})
}

@(test)
test_cipher_aes128 :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt, cipher = .Aes_128_Gcm})
}

@(test)
test_cipher_chacha :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt, cipher = .Chacha20_Poly1305})
}

@(test)
test_cipher_chacha_tcp :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Crypt_V2, cipher = .Chacha20_Poly1305})
}

// A server that sends no peer-id: the client uses 0xFFFFFF.
@(test)
test_no_peer_id :: proc(t: ^testing.T) {
	check_basic(t, {mode = .Tls_Crypt, no_peer_id = true})
	m := connect(t, {no_peer_id = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, session_peer_id(&m.s), u32(PEER_ID_NONE))
}

@(test)
test_peer_id_pushed :: proc(t: ^testing.T) {
	m := connect(t, {peer_id = 0x123456})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, session_peer_id(&m.s), u32(0x123456))
	expect_echo(t, m)
}

// ------------------------------------------------------------ TCP, odd reads

@(test)
test_tcp_chunk_1 :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Crypt}, chunk = 1)
}

@(test)
test_tcp_chunk_3 :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Auth, key_direction = .One}, chunk = 3)
}

@(test)
test_tcp_chunk_7_v2 :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp, mode = .Tls_Crypt_V2, dyn = true}, chunk = 7)
}

@(test)
test_tcp_chunk_1000 :: proc(t: ^testing.T) {
	check_basic(t, {transport = .Tcp}, chunk = 1000)
}

// ---------------------------------------------------------------- early WKc

@(test)
test_early_negotiation_wkc :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt_V2, early_neg = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	// Message id 1 (the ClientHello) came as opcode 11 with the WKc.
	testing.expect(t, m.f.op11_n >= 1, "no P_CONTROL_WKC_V1")
	testing.expect_value(t, m.f.op11_ids[0], u32(1))
	expect_echo(t, m)
}

// The resend flag is only for UDP: over TCP the flag is ignored.
@(test)
test_early_negotiation_ignored_on_tcp :: proc(t: ^testing.T) {
	m := connect(t, {transport = .Tcp, mode = .Tls_Crypt_V2, early_neg = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, m.f.op11_n, 0)
}

// The ClientHello is lost: the retransmission is still opcode 11.
@(test)
test_early_negotiation_retransmit_keeps_opcode :: proc(t: ^testing.T) {
	tweak :: proc(m: ^Sim) {
		m.cfg.tls_timeout = time.Second
	}
	m := sim_new({mode = .Tls_Crypt_V2, early_neg = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	tweak(m)
	testing.expect_value(t, sim_start(m), Error.None)
	// Let the reset exchange happen, then drop the first two packets of the
	// client that follow.
	for _ in 0 ..< 3 {
		sim_io(m)
	}
	m.kill_c2s = 0
	// Packets so far: reset, (ack with ClientHello). Drop what comes next.
	m.kill_c2s = 1
	ok := sim_run(m, g_up, 60 * time.Second)
	testing.expect(t, ok, "no connection")
	testing.expect(t, m.f.op11_n >= 1, "no opcode 11")
	for i in 0 ..< m.f.op11_n {
		testing.expect_value(t, m.f.op11_ids[i], u32(1))
	}
}

// --------------------------------------------------------------------- rekey

rekey_cycle :: proc(t: ^testing.T, m: ^Sim, by_client: bool, loc := #caller_location) {
	before_keys := sim_count_event(m, .Key_Installed)
	if by_client {
		testing.expect(t, session_rekey(&m.s, m.now), "session_rekey refused", loc = loc)
	} else {
		fake_rekey(&m.f, m.now)
	}
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.state == .Up && m.s.ks.state == .Generated_Keys && !m.s.rekeying && m.f.installed
	}, 60 * time.Second)
	if !ok {
		sim_dump(m)
	}
	testing.expect(t, ok, "rekey did not finish", loc = loc)
	testing.expect_value(t, sim_count_event(m, .Key_Installed), before_keys + 1)
	sim_idle(m, 10 * time.Millisecond)
	expect_echo(t, m, loc)
}

rekey_test :: proc(t: ^testing.T, o: Fake_Opts, by_client: bool, rounds := 3, chunk := 0, loc := #caller_location) {
	m := connect(t, o, chunk, loc = loc)
	if m == nil {
		return
	}
	defer sim_free(m)
	expect_echo(t, m, loc)
	for i in 0 ..< rounds {
		rekey_cycle(t, m, by_client, loc)
		testing.expect_value(t, int(m.s.ks.id), (i + 1) % 8 if (i + 1) < 8 else 1)
	}
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect_value(t, m.f.data_bad, 0)
	testing.expect_value(t, m.s.counters.drop_data_tag, 0)
	testing.expect_value(t, m.s.counters.drop_key_id, 0)
}

@(test)
test_rekey_by_client_udp_none :: proc(t: ^testing.T) {
	rekey_test(t, {}, true)
}

@(test)
test_rekey_by_server_udp_none :: proc(t: ^testing.T) {
	rekey_test(t, {}, false)
}

@(test)
test_rekey_by_client_tls_auth :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Auth, key_direction = .One}, true)
}

@(test)
test_rekey_by_server_tls_crypt_dyn :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, dyn = true}, false)
}

@(test)
test_rekey_by_client_tls_crypt_dyn :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, dyn = true}, true)
}

@(test)
test_rekey_by_client_v2_dyn :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt_V2, dyn = true, cc_exit = true}, true)
}

@(test)
test_rekey_by_server_v2_dyn :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt_V2, dyn = true}, false)
}

@(test)
test_rekey_by_client_tcp :: proc(t: ^testing.T) {
	rekey_test(t, {transport = .Tcp, mode = .Tls_Crypt_V2, dyn = true}, true, chunk = 5)
}

@(test)
test_rekey_by_server_tcp :: proc(t: ^testing.T) {
	rekey_test(t, {transport = .Tcp}, false, chunk = 700)
}

@(test)
test_rekey_chacha :: proc(t: ^testing.T) {
	rekey_test(t, {mode = .Tls_Crypt, cipher = .Chacha20_Poly1305}, true, rounds = 2)
}

// The key id wraps: 0, 1 .. 7, then 1 again.
@(test)
test_rekey_key_id_wraps :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	seen: [8]bool
	for i in 0 ..< 10 {
		rekey_cycle(t, m, i % 2 == 0)
		seen[m.s.ks.id] = true
		testing.expect(t, m.s.ks.id != 0, "key id 0 came back")
	}
	for id in 1 ..< 8 {
		testing.expectf(t, seen[id], "key id %d never used", id)
	}
}

// Both sides start the renegotiation in the same moment: the two soft resets
// are the same renegotiation.
@(test)
test_rekey_simultaneous :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect(t, session_rekey(&m.s, m.now), "session_rekey refused")
	fake_rekey(&m.f, m.now)
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.ks.state == .Generated_Keys && m.f.installed && m.s.ks.id == 1
	}, 30 * time.Second)
	if !ok {
		sim_dump(m)
	}
	testing.expect(t, ok, "simultaneous rekey did not finish")
	testing.expect_value(t, m.s.ks.id, u8(1))
	expect_echo(t, m)
}

// After the client switched to a new key the old key still decrypts what the
// server sent a moment before.
@(test)
test_old_key_still_receives :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	rekey_cycle(t, m, true)
	// The fake sends on key id 0 as a stock server does for a while.
	m.f.tx_kid = 0
	got := sim_echo(m, 4, 100)
	testing.expect_value(t, got, 4)
	testing.expect_value(t, m.s.counters.drop_data_no_key, 0)
}

// Keys older than the transition window are gone.
@(test)
test_old_key_expires :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.tran_window = 5 * time.Second
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	rekey_cycle(t, m, true)
	sim_idle(m, 8 * time.Second)
	m.f.tx_kid = 0
	got := sim_echo(m, 3, 50)
	testing.expect_value(t, got, 0)
	testing.expect(t, m.s.counters.drop_data_no_key >= 1, "old key was still accepted")
	// Still alive on the new key.
	m.f.tx_kid = 1
	testing.expect_value(t, sim_echo(m, 3, 50), 3)
}

// Time based rekey: reneg-sec 20 over 70 s causes three or more rekeys.
@(test)
test_rekey_by_timer :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, dyn = true, ping = 5, ping_restart = 40})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.reneg_sec = 20
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	for _ in 0 ..< 7 {
		sim_idle(m, 10 * time.Second)
		testing.expect_value(t, sim_echo(m, 2, 80), 2)
	}
	testing.expect(t, m.s.counters.rekeys >= 3, "fewer than 3 rekeys in 70 s")
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect_value(t, sim_count_event(m, .Failed), 0)
}

// reneg-sec -1: the client never starts a rekey itself.
@(test)
test_rekey_timer_off :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, ping = 5, ping_restart = 40})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.reneg_sec = -1
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	sim_idle(m, 7200 * time.Second)
	testing.expect_value(t, m.s.counters.rekeys, u64(0))
	testing.expect_value(t, m.s.state, State.Up)
}

@(test)
test_rekey_by_packet_count :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.reneg_pkts = 600
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	for _ in 0 ..< 20 {
		sim_echo(m, 20, 10)
		sim_idle(m, time.Second)
	}
	testing.expect(t, m.s.counters.rekeys >= 1, "no rekey after 800 packets")
	testing.expect_value(t, m.s.state, State.Up)
}

// ------------------------------------------------------ loss, reorder, duplicates

@(test)
test_udp_handshake_first_packets_lost :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.kill_c2s = 3
	m.kill_s2c = 2
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 120 * time.Second), "no connection after loss")
	expect_echo(t, m)
}

@(test)
test_udp_handshake_random_loss :: proc(t: ^testing.T) {
	modes := [?]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}
	for mode, i in modes {
		m := sim_new({mode = mode, key_direction = .One, dyn = mode == .Tls_Crypt || mode == .Tls_Crypt_V2})
		if m == nil {
			return
		}
		m.rng += u64(i) * 7919
		m.loss_c2s = 25
		m.loss_s2c = 25
		testing.expect_value(t, sim_start(m), Error.None)
		ok := sim_run(m, g_up, 600 * time.Second)
		if !ok {
			sim_dump(m)
		}
		testing.expectf(t, ok, "no connection with 25 percent loss (wrap %v)", mode)
		sim_free(m)
	}
}

@(test)
test_udp_handshake_duplicates :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt_V2, early_neg = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.dup_c2s, m.dup_s2c = true, true
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 60 * time.Second), "no connection with duplicates")
	testing.expect_value(t, sim_count_event(m, .Up), 1)
	testing.expect_value(t, sim_count_event(m, .Failed), 0)
	// Wrap replays and control duplicates were dropped.
	testing.expect(t, m.s.counters.drop_wrap_replay >= 1, "no replay was seen")
}

@(test)
test_udp_handshake_reordered :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Auth, key_direction = .One})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.swap_c2s, m.swap_s2c = true, true
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 120 * time.Second), "no connection with reordering")
	expect_echo(t, m)
}

// With tls-crypt a reordered wrap id is fine as long as it is inside the window.
@(test)
test_udp_reordered_tls_crypt :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.swap_c2s, m.swap_s2c = true, true
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 120 * time.Second), "no connection with reordering")
}

// A duplicated data packet is delivered once.
@(test)
test_udp_data_duplicates :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.dup_s2c = true
	got := sim_echo(m, 10, 100)
	testing.expect_value(t, got, 10)
	testing.expect_value(t, m.tunnel_n, 10)
	testing.expect_value(t, m.s.counters.drop_data_replay, u64(10))
}

// Data packets that arrive out of order are accepted (replay window).
@(test)
test_udp_data_reordered :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.swap_s2c = true
	m.tunnel_n = 0
	for i in 0 ..< 8 {
		testing.expect_value(t, sim_send_ip(m, 40, u16(i)), Error.None)
	}
	sim_settle(m)
	testing.expect_value(t, m.tunnel_n, 8)
	testing.expect_value(t, m.s.counters.drop_data_replay, u64(0))
}

// Rekey with a lost packet in the middle of it.
@(test)
test_rekey_with_loss :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.loss_c2s, m.loss_s2c = 30, 30
	testing.expect(t, session_rekey(&m.s, m.now), "rekey refused")
	ok := sim_run(m, proc(m: ^Sim) -> bool {
		return m.s.ks.state == .Generated_Keys && m.f.installed && m.s.ks.id == 1
	}, 600 * time.Second)
	testing.expect(t, ok, "rekey under loss did not finish")
	m.loss_c2s, m.loss_s2c = 0, 0
	expect_echo(t, m)
}

// ------------------------------------------------------------------ timeouts

@(test)
test_hand_window_no_server :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.hand_window = 10 * time.Second
	m.kill_s2c = 1000
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Hand_Window)
	testing.expect(t, m.now >= 11 * time.Second && m.now <= 13 * time.Second, "hand window was not 10 s")
	ev, ok := sim_last_event(m, .Failed)
	testing.expect(t, ok, "no Failed event")
	testing.expect_value(t, ev.reason, Fail_Reason.Hand_Window)
}

@(test)
test_hand_window_wrong_wrap_key :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.hand_window = 8 * time.Second
	// The client has another key than the server.
	other := m.f.skey
	for i := 3; i < len(other.bytes); i += 64 {
		other.bytes[i] ~= 0x55
	}
	m.cfg.wrap.static_key = &other
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Hand_Window)
	testing.expect(t, m.f.drop_wrap >= 1, "the server accepted the packet")
	testing.expect(t, !m.f.peer_set, "the server created a session")
}

@(test)
test_no_push_reply :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, silent_push = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.hand_window = 20 * time.Second
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 120 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.No_Push_Reply)
	// PUSH_REQUEST: once after one second, then every five seconds.
	testing.expect(t, m.f.cmds_n >= 3, "too few PUSH_REQUESTs")
	for i in 0 ..< m.f.cmds_n {
		testing.expect_value(t, string(m.f.cmds[i][:12]), "PUSH_REQUEST")
	}
	testing.expect(t, m.s.ks.state == .Error || m.s.state == .Failed, "state")
}

@(test)
test_auth_pending_extends_wait :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, pending = 20})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.hand_window = 5 * time.Second
	testing.expect_value(t, sim_start(m), Error.None)
	// Without AUTH_PENDING the session would fail at 5 s. The server asks for
	// 20 s and responds after 12 s.
	testing.expect(t, sim_run(m, proc(m: ^Sim) -> bool {
		return sim_has_event(m, .Auth_Pending) || m.s.state == .Failed
	}, 30 * time.Second), "no AUTH_PENDING")
	ev, _ := sim_last_event(m, .Auth_Pending)
	testing.expect_value(t, ev.timeout, 20)
	sim_idle(m, 10 * time.Second)
	testing.expect_value(t, m.s.state, State.Handshaking)
	fake_release(&m.f, m.now)
	testing.expect(t, sim_run(m, g_up, 10 * time.Second), "no connection after the reply")
}

@(test)
test_auth_pending_expires :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, pending = 20})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.hand_window = 5 * time.Second
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.No_Push_Reply)
	testing.expect(t, m.now >= 20 * time.Second, "gave up before the pending timeout")
}

// ping-restart: no packet from the server for that long ends the session.
@(test)
test_ping_restart :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, ping = 5, ping_restart = 30})
	if m == nil {
		return
	}
	defer sim_free(m)
	sim_idle(m, 20 * time.Second)
	testing.expect_value(t, m.s.state, State.Up)
	m.f.silent = true
	m.kill_s2c = 1000000
	start := m.now
	testing.expect(t, sim_run(m, g_failed, 120 * time.Second), "no ping-restart")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Ping_Timeout)
	testing.expect(t, m.now - start >= 29 * time.Second && m.now - start <= 36 * time.Second, "wrong ping-restart time")
}

@(test)
test_keepalive_ping_sent :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, ping = 10, ping_restart = 60})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.f.silent = true // the fake sends no pings of its own
	sim_idle(m, 35 * time.Second)
	// The fake is silent, so ping-restart (60 s) is not due yet.
	testing.expect_value(t, m.s.state, State.Up)
	testing.expect(t, m.f.pings >= 3 && m.f.pings <= 4, "client keepalive count is wrong")
	testing.expect_value(t, m.s.counters.ping_tx, u64(m.f.pings))
}

@(test)
test_config_ping_overrides_push :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, ping = 10, ping_restart = 60})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.ping = 2
	m.cfg.ping_restart = -1
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	m.f.silent = true
	sim_idle(m, 21 * time.Second)
	testing.expect(t, m.f.pings >= 9, "ping 2 was not used")
	m.kill_s2c = 100000
	sim_idle(m, 500 * time.Second)
	testing.expect_value(t, m.s.state, State.Up)
}

// ------------------------------------------------------------ login and token

@(test)
test_login_ok :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, login = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, string(m.f.user[:m.f.user_n]), FAKE_USER)
	testing.expect_value(t, string(m.f.pass[:m.f.pass_n]), FAKE_PASS)
	_, _, have := session_auth_token(&m.s)
	testing.expect(t, !have, "a token appeared from nowhere")
}

@(test)
test_login_wrong_password :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, login = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.password = "wrong"
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Auth_Failed)
	ev, ok := sim_last_event(m, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed event")
	testing.expect_value(t, ev.auth_kind, push.Auth_Failed_Kind.Plain)
	testing.expect(t, !ev.token_dropped, "no token to drop")
}

auth_failed_case :: proc(t: ^testing.T, text: string, kind: push.Auth_Failed_Kind, loc := #caller_location) -> ^Sim {
	m := sim_new({mode = .Tls_Crypt, reject = text})
	if m == nil {
		return nil
	}
	testing.expect_value(t, sim_start(m), Error.None, loc = loc)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure", loc = loc)
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Auth_Failed, loc = loc)
	ev, ok := sim_last_event(m, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed event", loc = loc)
	testing.expect_value(t, ev.auth_kind, kind, loc = loc)
	return m
}

@(test)
test_auth_failed_with_reason :: proc(t: ^testing.T) {
	m := auth_failed_case(t, "AUTH_FAILED,Account locked", .Reason)
	defer sim_free(m)
	ev, _ := sim_last_event(m, .Auth_Failed)
	testing.expect_value(t, event_text(&ev), "Account locked")
}

@(test)
test_auth_failed_temp :: proc(t: ^testing.T) {
	m := auth_failed_case(t, "AUTH_FAILED,TEMP[backoff 30,advance addr]:try later", .Temp)
	defer sim_free(m)
	ev, _ := sim_last_event(m, .Auth_Failed)
	testing.expect_value(t, ev.backoff, 30)
	testing.expect_value(t, event_text(&ev), "try later")
}

@(test)
test_auth_failed_session :: proc(t: ^testing.T) {
	m := auth_failed_case(t, "AUTH_FAILED,SESSION", .Session)
	sim_free(m)
}

@(test)
test_auth_failed_crv1 :: proc(t: ^testing.T) {
	m := auth_failed_case(t, "AUTH_FAILED,CRV1:R,E:state:dXNlcg==:Enter the code", .Crv1)
	sim_free(m)
}

@(test)
test_auth_failed_plain :: proc(t: ^testing.T) {
	m := auth_failed_case(t, "AUTH_FAILED", .Plain)
	sim_free(m)
}

@(test)
test_token_stored_and_used_on_rekey :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, dyn = true, login = true, token = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	user, token, have := session_auth_token(&m.s)
	testing.expect(t, have, "no token stored")
	testing.expect_value(t, token, FAKE_TOKEN)
	_ = user
	rekey_cycle(t, m, true)
	// On the rekey the token went as the password.
	testing.expect_value(t, string(m.f.pass[:m.f.pass_n]), FAKE_TOKEN)
	rekey_cycle(t, m, false)
	testing.expect_value(t, string(m.f.pass[:m.f.pass_n]), FAKE_TOKEN)
}

// ----------------------------------------------------------- push handling

@(test)
test_push_continuation :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, routes = 69})
	if m == nil {
		return
	}
	defer sim_free(m)
	po := session_pushed(&m.s)
	testing.expect_value(t, len(po.routes), 69)
	expect_echo(t, m)
}

@(test)
test_push_cipher_not_ours :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, cipher = .Aes_256_Gcm})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.ciphers = []push.Cipher{.Aes_128_Gcm}
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Push)
	testing.expect_value(t, sim_count_event(m, .Up), 0)
}

// A server must not push `aead-epoch` to a client that did not offer bit 10.
@(test)
test_push_epoch_not_offered_refused :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, epoch = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.iv_proto = DEFAULT_IV_PROTO - {.Data_Epoch}
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Push)
}

// A server that pushes no `aead-epoch` gets the baseline format, though the
// client offered the epoch bit (the fallback for 2.6 servers).
@(test)
test_push_without_epoch_is_baseline :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, session_data_format(&m.s), keys.Format.Baseline)
	tx, rx := session_epochs(&m.s)
	testing.expect_value(t, tx, 0)
	testing.expect_value(t, rx, 0)
	pinfo := fake_text(m.f.peer_info[:], m.f.peer_info_n)
	testing.expect(t, strings.contains(pinfo, "IV_PROTO=1950\n"), "bit 10 not offered")
}

@(test)
test_push_garbage_option :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, extra = []string{"route 10.0.0.0 not-a-mask"}})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	// A bad option must not bring the session up with half a config.
	sim_run(m, g_done, 90 * time.Second)
	testing.expect(t, m.s.state != .Up || sim_has_event(m, .Up), "inconsistent")
}

@(test)
test_mtu_above_iv_mtu :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, mtu = 9000})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Push)
}

// --------------------------------------------------------- server commands

@(test)
test_server_restart :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, cc_exit = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "RESTART,server is going down", m.now)
	testing.expect(t, sim_run(m, g_failed, 10 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Server_Signal)
	ev, ok := sim_last_event(m, .Restart)
	testing.expect(t, ok, "no Restart event")
	testing.expect_value(t, event_text(&ev), "server is going down")
}

@(test)
test_server_restart_next_remote :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "RESTART,[N]bye", m.now)
	testing.expect(t, sim_run(m, g_failed, 10 * time.Second), "no failure")
	ev, ok := sim_last_event(m, .Restart)
	testing.expect(t, ok, "no Restart event")
	testing.expect(t, ev.next_remote, "next-remote flag lost")
}

@(test)
test_server_halt :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "HALT,gone", m.now)
	testing.expect(t, sim_run(m, g_failed, 10 * time.Second), "no failure")
	testing.expect(t, sim_has_event(m, .Halt), "no Halt event")
}

@(test)
test_server_exit_command :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, cc_exit = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "EXIT", m.now)
	testing.expect(t, sim_run(m, g_failed, 10 * time.Second), "no failure")
	testing.expect(t, sim_has_event(m, .Remote_Exit), "no Remote_Exit event")
}

@(test)
test_server_exit_notice_on_data_channel :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	buf: [32]u8
	plain, _ := crypt.build_occ_exit(buf[:])
	fake_data_tx(&m.f, plain, m.now)
	sim_settle(m)
	testing.expect(t, sim_has_event(m, .Remote_Exit), "no Remote_Exit event")
}

@(test)
test_info_message :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "INFO,WEB_AUTH::https://example.com/login", m.now)
	sim_settle(m)
	ev, ok := sim_last_event(m, .Info)
	testing.expect(t, ok, "no Info event")
	testing.expect(t, strings.contains(event_text(&ev), "example.com"), "text lost")
	testing.expect_value(t, m.s.state, State.Up)
}

// INFO_PRE keeps its whole text in the session, out of the event.
@(test)
test_info_pre_message :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	url := strings.concatenate({"WEB_AUTH::https://login.example.com/", strings.repeat("a", 600, context.temp_allocator)}, context.temp_allocator)
	fake_text_out(&m.f, strings.concatenate({"INFO_PRE,", url}, context.temp_allocator), m.now)
	sim_settle(m)
	ev, ok := sim_last_event(m, .Info_Pre)
	testing.expect(t, ok, "no Info_Pre event")
	testing.expect_value(t, event_text(&ev), "")
	text, cut := session_info_pre(&m.s)
	testing.expect_value(t, text, url)
	testing.expect(t, !cut, "cut")
	testing.expect_value(t, m.s.state, State.Up)
}

// IV_SSO goes to the server only when the config names a method.
@(test)
test_iv_sso_peer_info :: proc(t: ^testing.T) {
	tweak :: proc(m: ^Sim) {
		m.cfg.sso = "webauth"
	}
	m := connect(t, {mode = .Tls_Crypt}, tweak = tweak)
	if m == nil {
		return
	}
	pinfo := fake_text(m.f.peer_info[:], m.f.peer_info_n)
	testing.expect(t, strings.contains(pinfo, "\nIV_SSO=webauth\n"), "no IV_SSO=webauth")
	sim_free(m)
	m = connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	pinfo = fake_text(m.f.peer_info[:], m.f.peer_info_n)
	testing.expect(t, !strings.contains(pinfo, "IV_SSO"), "IV_SSO without a method")
}

// The token of the first PUSH_REPLY is announced, so a reconnect can use it.
@(test)
test_first_reply_token_event :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, login = true, token = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect(t, sim_has_event(m, .Token_Updated), "no Token_Updated for the first reply")
	_, token, have := session_auth_token(&m.s)
	testing.expect(t, have && token == FAKE_TOKEN, "token not kept")
}

// An unknown command and one for the other direction are ignored.
@(test)
test_unknown_commands_ignored :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	fake_text_out(&m.f, "NOT_A_COMMAND,whatever", m.now)
	fake_text_out(&m.f, "PUSH_REQUEST", m.now)
	sim_settle(m)
	testing.expect_value(t, m.s.state, State.Up)
	expect_echo(t, m)
}

// ---------------------------------------------------------------------- close

@(test)
test_close_with_cc_exit :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, cc_exit = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	start := m.now
	session_close(&m.s, m.now)
	testing.expect(t, sim_run(m, g_closed, 10 * time.Second), "close did not finish")
	testing.expect(t, m.f.got_exit, "the server did not see EXIT")
	testing.expect_value(t, m.f.occ_exits, 0)
	// Closed as soon as the ack came.
	testing.expect(t, m.now - start < 500 * time.Millisecond, "the close waited for the timeout")
	testing.expect(t, sim_has_event(m, .Closed), "no Closed event")
}

@(test)
test_close_with_cc_exit_tcp :: proc(t: ^testing.T) {
	m := connect(t, {transport = .Tcp, mode = .Tls_Crypt, cc_exit = true}, chunk = 3)
	if m == nil {
		return
	}
	defer sim_free(m)
	session_close(&m.s, m.now)
	testing.expect(t, sim_run(m, g_closed, 10 * time.Second), "close did not finish")
	testing.expect(t, m.f.got_exit, "the server did not see EXIT")
}

// The EXIT is lost: the close ends at the timeout.
@(test)
test_close_exit_lost :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, cc_exit = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.kill_s2c = 100
	start := m.now
	session_close(&m.s, m.now)
	testing.expect(t, sim_run(m, g_closed, 10 * time.Second), "close did not finish")
	testing.expect(t, m.now - start >= time.Second, "closed before the exit timeout")
}

@(test)
test_close_with_occ_exit :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.explicit_exit_notify = 3
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	start := m.now
	session_close(&m.s, m.now)
	testing.expect(t, sim_run(m, g_closed, 20 * time.Second), "close did not finish")
	testing.expect_value(t, m.f.occ_exits, 3)
	testing.expect(t, m.now - start >= 2 * time.Second, "exit notices not spaced by a second")
	testing.expect(t, !m.f.got_exit, "EXIT without cc-exit")
}

@(test)
test_close_pushed_exit_notify :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, extra = []string{"explicit-exit-notify 2"}})
	if m == nil {
		return
	}
	defer sim_free(m)
	session_close(&m.s, m.now)
	testing.expect(t, sim_run(m, g_closed, 20 * time.Second), "close did not finish")
	testing.expect_value(t, m.f.occ_exits, 2)
}

@(test)
test_close_without_notice :: proc(t: ^testing.T) {
	m := connect(t, {transport = .Tcp, mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	session_close(&m.s, m.now)
	sim_settle(m)
	testing.expect_value(t, m.s.state, State.Closed)
	testing.expect(t, sim_has_event(m, .Closed), "no Closed event")
	// No more tunnel traffic after the close.
	_, err := session_encap(&m.s, make([]u8, 200, context.temp_allocator), 40, m.now)
	testing.expect_value(t, err, Error.Not_Up)
}

@(test)
test_close_before_up :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	session_close(&m.s, m.now)
	sim_settle(m)
	testing.expect_value(t, m.s.state, State.Closed)
}

// ---------------------------------------------------------------------- TLS

@(test)
test_tls_untrusted_server :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.ca_pem = OTHER_CA_PEM
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Tls)
	testing.expect_value(t, sim_count_event(m, .Up), 0)
}

@(test)
test_pinned_server_key :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, p256 = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	expect_echo(t, m)
}

@(test)
test_pinned_server_cert :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, p256 = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.pin_spki = nil
	m.cfg.pin_cert = m.f.pin[1:2]
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
}

@(test)
test_pinned_wrong_pin :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, p256 = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.f.pin[0][5] ~= 1
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Tls)
	testing.expect_value(t, sim_count_event(m, .Up), 0)
	// The client never wrote the key-method message.
	testing.expect(t, !m.s.ks.km_sent, "key-method sent to an unpinned server")
}

@(test)
test_pinned_other_key_pinned :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, p256 = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	// The pin of the client's own key is not the server's.
	other := ossl.sha256(P256_CLIENT_SPKI)
	pins := [1][32]u8{other}
	m.cfg.pin_spki = pins[:]
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Tls)
}

// ------------------------------------------------------------- bad packets

@(test)
test_garbage_before_and_after_up :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	rng: u64 = 99
	garbage :: proc(m: ^Sim, rng: ^u64, count: int) {
		for _ in 0 ..< count {
			buf: [1500]u8
			rng^ = rng^ * 6364136223846793005 + 1442695040888963407
			n := int((rng^ >> 33) % 1400)
			for i in 0 ..< n {
				rng^ = rng^ * 6364136223846793005 + 1442695040888963407
				buf[i] = u8(rng^ >> 56)
			}
			if n > 0 && (rng^ >> 20) & 3 != 0 {
				// A plausible first byte: a control or data opcode.
				ops := [?]u8{0x20, 0x28, 0x38, 0x40, 0x48, 0x58, 0x60, 0x68, 0x5a, 0x4f, 0x30}
				buf[0] = ops[int((rng^ >> 40) % len(ops))] | u8((rng^ >> 10) & 7)
			}
			session_receive(&m.s, buf[:n], m.now)
		}
	}
	garbage(m, &rng, 300)
	testing.expect(t, sim_run(m, g_up, 60 * time.Second), "no connection after garbage")
	garbage(m, &rng, 1000)
	sim_settle(m)
	testing.expect_value(t, m.s.state, State.Up)
	expect_echo(t, m)
	total := m.s.counters.drop_opcode + m.s.counters.drop_short + m.s.counters.drop_sid + m.s.counters.drop_unwrap + m.s.counters.drop_decode + m.s.counters.drop_key_id + m.s.counters.drop_data_no_key + m.s.counters.drop_data_tag + m.s.counters.drop_data_payload + m.s.counters.drop_tunnel_state
	testing.expect(t, total >= 1000, "garbage was not counted")
}

// A replayed or corrupted data packet is dropped and the session lives on.
@(test)
test_corrupt_data_packet :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], 100, 1)
	// Seal it with the fake (as the server would) and flip a bit.
	fake_data_tx(&m.f, buf[TUNNEL_HEADROOM:][:n], m.now)
	out: [LINK_BUF_SIZE]u8
	pn := fake_poll(&m.f, out[:], m.now)
	testing.expect(t, pn > 0, "no packet")
	pkt := make([]u8, pn, context.temp_allocator)
	copy(pkt, out[:pn])
	pkt[pn - 1] ~= 1
	r := session_receive(&m.s, pkt, m.now)
	testing.expect_value(t, len(r.tunnel), 0)
	testing.expect_value(t, m.s.counters.drop_data_tag, u64(1))
	testing.expect_value(t, m.s.state, State.Up)
}

// Over TCP a bad data tag ends the connection.
@(test)
test_tcp_bad_data_tag_is_fatal :: proc(t: ^testing.T) {
	m := connect(t, {transport = .Tcp, mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], 100, 1)
	fake_data_tx(&m.f, buf[TUNNEL_HEADROOM:][:n], m.now)
	out: [LINK_BUF_SIZE]u8
	pn := fake_poll(&m.f, out[:], m.now)
	framed := make([]u8, pn + 2, context.temp_allocator)
	framed[0], framed[1] = u8(pn >> 8), u8(pn)
	copy(framed[2:], out[:pn])
	framed[pn + 1] ~= 1
	session_receive(&m.s, framed, m.now)
	testing.expect_value(t, m.s.state, State.Failed)
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Link_Error)
}

@(test)
test_tcp_zero_length_frame :: proc(t: ^testing.T) {
	m := connect(t, {transport = .Tcp})
	if m == nil {
		return
	}
	defer sim_free(m)
	session_receive(&m.s, []u8{0, 0}, m.now)
	testing.expect_value(t, m.s.state, State.Failed)
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Link_Error)
}

// Two server resets with different session ids: the second is ignored.
@(test)
test_second_server_reset_ignored :: proc(t: ^testing.T) {
	m := sim_new({})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	sim_io(m)
	// A forged reset with another sid, built by hand (wrapping none).
	cp := wire.Control_Packet {
		opcode         = .Hard_Reset_Server_V2,
		session_id     = {9, 9, 9, 9, 9, 9, 9, 9},
		ack_count      = 1,
		ack_remote_sid = m.s.local_sid,
		packet_id      = 0,
	}
	buf: [64]u8
	n, _ := wire.control_encode(buf[:], &cp)
	session_receive(&m.s, buf[:n], m.now)
	testing.expect_value(t, m.s.peer_sid, m.f.sid)
	testing.expect(t, m.s.counters.drop_sid >= 1, "forged reset not counted")
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
}

// A server reset that acks another session of ours is ignored.
@(test)
test_reset_with_wrong_ack_ignored :: proc(t: ^testing.T) {
	m := sim_new({})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	cp := wire.Control_Packet {
		opcode         = .Hard_Reset_Server_V2,
		session_id     = {9, 9, 9, 9, 9, 9, 9, 9},
		ack_count      = 1,
		ack_remote_sid = {1, 2, 3, 4, 5, 6, 7, 8},
		packet_id      = 0,
	}
	buf: [64]u8
	n, _ := wire.control_encode(buf[:], &cp)
	session_receive(&m.s, buf[:n], m.now)
	testing.expect(t, !m.s.peer_sid_set, "peer sid taken from a bad reset")
	testing.expect_value(t, m.s.state, State.Connecting)
}

// ---------------------------------------------------------- config and misc

@(test)
test_server_role_not_implemented :: proc(t: ^testing.T) {
	s: Session
	cfg := Config {
		role = .Server,
	}
	testing.expect_value(t, session_init(&s, &cfg), Error.Not_Implemented)
	session_destroy(&s)
}

@(test)
test_bad_config :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	s: Session
	// A refused IV_PROTO bit.
	cfg := m.cfg
	cfg.iv_proto = DEFAULT_IV_PROTO + {.Push_Update}
	testing.expect_value(t, session_init(&s, &cfg), Error.Bad_Config)
	// No key for tls-crypt.
	cfg = m.cfg
	cfg.wrap.static_key = nil
	testing.expect_value(t, session_init(&s, &cfg), Error.Bad_Config)
	// A long password.
	cfg = m.cfg
	long: [200]u8
	for &c in long {
		c = 'x'
	}
	cfg.password = string(long[:])
	testing.expect_value(t, session_init(&s, &cfg), Error.Credentials_Too_Long)
	// Pinned without pins.
	cfg = m.cfg
	cfg.verify = .Pinned
	cfg.pin_spki, cfg.pin_cert = nil, nil
	testing.expect_value(t, session_init(&s, &cfg), Error.Bad_Config)
	// A bad certificate.
	cfg = m.cfg
	cfg.cert_pem = []u8{'x'}
	testing.expect_value(t, session_init(&s, &cfg), Error.Bad_Key)
	// The cipher list may not be empty of real ciphers.
	cfg = m.cfg
	cfg.ciphers = []push.Cipher{.None}
	testing.expect_value(t, session_init(&s, &cfg), Error.Bad_Config)
}

@(test)
test_state_misuse :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, session_init(&m.s, &m.cfg), Error.None)
	m.started = true
	buf: [LINK_BUF_SIZE]u8
	_, err := session_encap(&m.s, buf[:], 40, m.now)
	testing.expect_value(t, err, Error.Not_Up)
	testing.expect_value(t, session_poll_tx(&m.s, buf[:], m.now), 0)
	testing.expect(t, !session_rekey(&m.s, m.now), "rekey before start")
	_, wake := session_next_wakeup(&m.s, m.now)
	testing.expect(t, !wake, "a wake-up before start")
	testing.expect_value(t, session_start(&m.s, m.now, FAKE_WALL_BASE), Error.None)
	testing.expect_value(t, session_start(&m.s, m.now, FAKE_WALL_BASE), Error.Bad_State)
	// Short output buffer: nothing is written.
	small: [100]u8
	testing.expect_value(t, session_poll_tx(&m.s, small[:], m.now), 0)
}

// The wall clock the engine passes to the wrapping moves with `now`.
@(test)
test_wall_clock_follows_now :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect_value(t, wall_now(&m.s, m.now), FAKE_WALL_BASE + 1)
	testing.expect_value(t, wall_now(&m.s, m.now + 100 * time.Second), FAKE_WALL_BASE + 101)
}

@(test)
test_memory_size :: proc(t: ^testing.T) {
	testing.expectf(t, size_of(Session) < 100 * 1024, "Session is %d bytes", size_of(Session))
	testing.expectf(t, size_of(Event) <= 288, "Event is %d bytes", size_of(Event))
}

@(test)
test_event_ring_drops_oldest :: proc(t: ^testing.T) {
	s: Session
	for i in 0 ..< EVENT_RING + 5 {
		emit(&s, Event{kind = .Info, key_id = u8(i)})
	}
	testing.expect_value(t, s.counters.events_dropped, u64(5))
	ev, ok := session_next_event(&s)
	testing.expect(t, ok, "no event")
	testing.expect_value(t, ev.key_id, u8(5))
}

// ----------------------------------------------------------- more cases

@(test)
test_auth_failed_drops_token :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, login = true, token = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	_, _, have := session_auth_token(&m.s)
	testing.expect(t, have, "no token")
	fake_text_out(&m.f, "AUTH_FAILED", m.now)
	testing.expect(t, sim_run(m, g_failed, 10 * time.Second), "no failure")
	ev, ok := sim_last_event(m, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed event")
	testing.expect(t, ev.token_dropped, "the token was not dropped")
	_, _, have = session_auth_token(&m.s)
	testing.expect(t, !have, "the token is still there")
}

// Tunnel packets keep flowing on the old key while a rekey runs.
@(test)
test_data_during_rekey :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect(t, session_rekey(&m.s, m.now), "rekey refused")
	m.tunnel_n = 0
	for i in 0 ..< 5 {
		testing.expect_value(t, sim_send_ip(m, 100, u16(i)), Error.None)
	}
	sim_settle(m)
	testing.expect_value(t, m.tunnel_n, 5)
	testing.expect_value(t, m.s.ks.state, Ks_State.Generated_Keys)
	testing.expect_value(t, m.s.ks.id, u8(1))
}

// A tiny max-packet-size: the TLS flights are cut into many small packets and
// are longer than the send window.
@(test)
test_small_control_packets :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, dyn = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.max_packet_size = 300
	testing.expect_value(t, sim_start(m), Error.None)
	ok := sim_run(m, g_up, 120 * time.Second)
	if !ok {
		sim_dump(m)
	}
	testing.expect(t, ok, "no connection with small packets")
	expect_echo(t, m)
	rekey_cycle(t, m, true)
}

@(test)
test_small_control_packets_wkc :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt_V2, early_neg = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.max_packet_size = 300
	testing.expect_value(t, sim_start(m), Error.None)
	ok := sim_run(m, g_up, 120 * time.Second)
	if !ok {
		sim_dump(m)
	}
	testing.expect(t, ok, "no connection with small packets")
	testing.expect(t, m.f.op11_n >= 1, "no WKc on message 1")
}

// The ML-DSA-65 certificates produce a TLS flight of several kilobytes.
@(test)
test_big_certificate_flight :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt, mldsa = true})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect(t, m.s2c_pkts >= 6, "the flight was not big")
	expect_echo(t, m)
}

// Credentials may be empty (certificate login): the key-method has none.
@(test)
test_no_credentials :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	testing.expect_value(t, m.f.user_n, 0)
	testing.expect_value(t, m.f.pass_n, 0)
}

// `session_encap` refuses a buffer without headroom or too small.
@(test)
test_encap_buffer_checks :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	small := make([]u8, TUNNEL_HEADROOM + 10, context.temp_allocator)
	_, err := session_encap(&m.s, small, 40, m.now)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
	_, err = session_encap(&m.s, small, 0, m.now)
	testing.expect_value(t, err, Error.Buffer_Too_Small)
}

// The session id of a client is random and never zero, and every start picks
// a new one.
@(test)
test_session_ids_differ :: proc(t: ^testing.T) {
	a := sim_new({})
	b := sim_new({})
	if a == nil || b == nil {
		return
	}
	defer sim_free(a)
	defer sim_free(b)
	b.rng = 42
	testing.expect_value(t, sim_start(a), Error.None)
	testing.expect_value(t, sim_start(b), Error.None)
	testing.expect(t, a.s.local_sid != b.s.local_sid, "same session id")
	testing.expect(t, a.s.local_sid != ([8]u8{}), "zero session id")
}

// A random source that fails stops the start.
@(test)
test_random_failure :: proc(t: ^testing.T) {
	m := sim_new({})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.random = proc(user: rawptr, buf: []u8) -> bool {
		return false
	}
	testing.expect_value(t, session_init(&m.s, &m.cfg), Error.None)
	m.started = true
	testing.expect_value(t, session_start(&m.s, m.now, FAKE_WALL_BASE), Error.Random)
}

// An IPv6 tunnel packet goes through both ways.
@(test)
test_ipv6_tunnel_packet :: proc(t: ^testing.T) {
	m := connect(t, {mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	buf: [LINK_BUF_SIZE]u8
	ip := buf[TUNNEL_HEADROOM:][:60]
	ip[0] = 0x60
	ip[4], ip[5] = 0, 20
	ip[6] = 58
	ip[7] = 64
	for i in 8 ..< 60 {
		ip[i] = u8(i)
	}
	pkt, err := session_encap(&m.s, buf[:], 60, m.now)
	testing.expect_value(t, err, Error.None)
	m.tunnel_n = 0
	impair_push(m, &m.c2s, pkt, &m.kill_c2s, 0, false, false)
	sim_settle(m)
	testing.expect_value(t, m.tunnel_n, 1)
	testing.expect_value(t, m.tunnel[0].n, 60)
}

// `session_seal_overhead` is what a sealed packet adds to its IP packet, with
// and without the TCP length prefix.
@(test)
test_seal_overhead :: proc(t: ^testing.T) {
	for transport in ([2]Transport{.Udp, .Tcp}) {
		m := connect(t, {mode = .Tls_Crypt, transport = transport})
		if m == nil {
			return
		}
		defer sim_free(m)
		buf: [LINK_BUF_SIZE]u8
		ip := buf[TUNNEL_HEADROOM:][:100]
		ip[0] = 0x45
		pkt, err := session_encap(&m.s, buf[:], 100, m.now)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(pkt), 100 + session_seal_overhead(&m.s))
		testing.expect_value(t, session_seal_overhead(&m.s), 24 + (2 if transport == .Tcp else 0))
	}
}

// A soft reset with a key id that is not the next one is dropped (UDP) or ends
// the connection (TCP).
@(test)
test_soft_reset_wrong_key_id :: proc(t: ^testing.T) {
	for transport in ([2]Transport{.Udp, .Tcp}) {
		m := connect(t, {mode = .Tls_Crypt, transport = transport})
		if m == nil {
			return
		}
		fake_new_state(&m.f, 3, m.now)
		sim_settle(m)
		if transport == .Udp {
			testing.expect_value(t, m.s.state, State.Up)
			testing.expect(t, m.s.counters.drop_key_id >= 1, "not counted")
			testing.expect_value(t, m.s.ks.id, u8(0))
		} else {
			testing.expect_value(t, m.s.state, State.Failed)
		}
		sim_free(m)
	}
}

// A refused handshake sends its alert: the server sees the failure too.
@(test)
test_tls_alert_reaches_server :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.ca_pem = OTHER_CA_PEM
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	sim_settle(m)
	testing.expect(t, m.f.tls_failed, "the server never saw the alert")
}

// ------------------------------------------------------------- push filter

Filter_Test :: struct {
	drop:   string, // options that start with this are left out
	reject: string, // a reply with such an option is refused
	calls:  int,
}

filter_test_proc :: proc(user: rawptr, options: string, out: []u8) -> (n: int, reject: string, ok: bool) {
	ft := (^Filter_Test)(user)
	ft.calls += 1
	rest := options
	for len(rest) > 0 {
		item, _ := push.next_item(&rest, ',')
		if len(ft.reject) > 0 && strings.has_prefix(item, ft.reject) {
			return 0, item, false
		}
		if len(ft.drop) > 0 && strings.has_prefix(item, ft.drop) {
			continue
		}
		if n > 0 {
			out[n] = ','
			n += 1
		}
		n += copy(out[n:], item)
	}
	return n, "", true
}

// An option dropped by the filter is not parsed, so a default can take its place.
@(test)
test_push_filter_ignore :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, ping = 10, ping_restart = 60})
	if m == nil {
		return
	}
	defer sim_free(m)
	ft := Filter_Test {
		drop = "ping ",
	}
	m.cfg.push_filter = filter_test_proc
	m.cfg.push_filter_user = &ft
	m.cfg.ping_default = 3
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	testing.expect(t, ft.calls >= 1, "the filter was not called")
	po := session_pushed(&m.s)
	testing.expect(t, po.ping == nil, "the dropped `ping` was parsed")
	testing.expect_value(t, po.ifconfig.? or_else {}, push.Ifconfig{a = {10, 8, 0, 2}, b = {255, 255, 255, 0}})
	testing.expect_value(t, m.s.ping, 3)
	testing.expect_value(t, m.s.ping_restart, 60)
	m.f.silent = true
	sim_idle(m, 10 * time.Second)
	testing.expect(t, m.f.pings >= 2, "ping_default was not used")
}

@(test)
test_push_filter_reject :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt})
	if m == nil {
		return
	}
	defer sim_free(m)
	ft := Filter_Test {
		reject = "ifconfig",
	}
	m.cfg.push_filter = filter_test_proc
	m.cfg.push_filter_user = &ft
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_failed, 60 * time.Second), "no failure")
	testing.expect_value(t, session_fail_reason(&m.s), Fail_Reason.Push)
	ev, ok := sim_last_event(m, .Failed)
	testing.expect(t, ok, "no Failed event")
	testing.expect(t, strings.contains(event_text(&ev), "ifconfig"), "the refused option is not in the event text")
	testing.expect(t, session_pushed(&m.s) == nil, "options of a refused reply were kept")
}

// The ping defaults apply only when the server pushes nothing.
@(test)
test_ping_default_loses_to_push :: proc(t: ^testing.T) {
	m := sim_new({mode = .Tls_Crypt, ping = 10, ping_restart = 60})
	if m == nil {
		return
	}
	defer sim_free(m)
	m.cfg.ping_default = 3
	m.cfg.ping_restart_default = 7
	testing.expect_value(t, sim_start(m), Error.None)
	testing.expect(t, sim_run(m, g_up, 30 * time.Second), "no connection")
	testing.expect_value(t, m.s.ping, 10)
	testing.expect_value(t, m.s.ping_restart, 60)
}
