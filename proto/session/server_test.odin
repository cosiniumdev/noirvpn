// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/ossl"
import "noir:proto/push"

P256_CLIENT_DER := #load("../ossl/testdata/p256_client.crt.der")

// ------------------------------------------------------------------- helpers

// Brings every client up against the server sessions. Returns nil (and logs)
// if they do not come up.
duo_connect :: proc(t: ^testing.T, o: Duo_Opts, tweak: proc(d: ^Duo) = nil, loc := #caller_location) -> ^Duo {
	d := duo_new(o)
	if d == nil {
		testing.expect(t, false, "bench setup failed", loc = loc)
		return nil
	}
	if tweak != nil {
		tweak(d)
	}
	if err := duo_start(d); err != .None {
		testing.expectf(t, false, "duo_start: %v", err, loc = loc)
		duo_free(d)
		return nil
	}
	if !duo_run(d, duo_all_up, 60 * time.Second) {
		duo_dump(d)
		testing.expect(t, false, "sessions did not come up", loc = loc)
		duo_free(d)
		return nil
	}
	return d
}

duo_expect_echo :: proc(t: ^testing.T, d: ^Duo, peer := 0, loc := #caller_location) {
	sizes := [?]int{0, 1, 64, 600, 1200}
	for size in sizes {
		got := duo_echo(d, peer, 3, size)
		testing.expectf(t, got == 3, "echo of %d bytes: %d of 3 came back", size, got, loc = loc)
	}
}

// The checks every working connection must pass.
check_duo :: proc(t: ^testing.T, o: Duo_Opts, loc := #caller_location) {
	d := duo_connect(t, o, loc = loc)
	if d == nil {
		return
	}
	defer duo_free(d)
	for i in 0 ..< d.n {
		p := &d.peers[i]
		sl := duo_slot(d, i)
		testing.expect_value(t, p.c.state, State.Up)
		testing.expect_value(t, sl.s.state, State.Up)
		testing.expect_value(t, duo_count(p.ev[:], p.ev_n, .Up), 1)
		testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Up), 1)
		testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Request), 1)
		po := session_pushed(&p.c)
		testing.expect_value(t, po.ifconfig.? or_else {}, push.Ifconfig{a = {10, 8, 0, u8(2 + i)}, b = {255, 255, 255, 0}})
		testing.expect_value(t, po.route_gateway.? or_else {}, [4]u8{10, 8, 0, 1})
		testing.expect_value(t, session_peer_id(&p.c), u32(100 + i))
		testing.expect_value(t, session_peer_id(&sl.s), u32(100 + i))
		want_cipher := o.cipher if o.cipher != .None else push.Cipher.Aes_256_Gcm
		testing.expect_value(t, session_cipher(&p.c), want_cipher)
		testing.expect_value(t, session_cipher(&sl.s), want_cipher)
		testing.expect_value(t, session_protocol_flags(&p.c), session_protocol_flags(&sl.s))
		testing.expect(t, .Tls_Ekm in session_protocol_flags(&sl.s), "no tls-ekm", loc = loc)
		if o.transport == .Udp {
			testing.expect_value(t, string(sl.seen.remote[:sl.seen.remote_n]), string(peer_addr_bytes(&p.addr)))
		} else {
			testing.expect_value(t, sl.seen.remote_n, 0)
		}
		testing.expect(t, .Data_V2 in sl.seen.proto, "no data v2 in IV_PROTO", loc = loc)
	}
	for i in 0 ..< d.n {
		duo_expect_echo(t, d, i, loc)
	}
}

// ----------------------------------------------------------------- basics

@(test)
duo_udp_plain :: proc(t: ^testing.T) {
	check_duo(t, {mode = .None})
}

@(test)
duo_udp_tls_auth :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Auth})
	check_duo(t, {mode = .Tls_Auth, auth_digest = .SHA256})
}

@(test)
duo_udp_tls_crypt :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt})
}

@(test)
duo_udp_tls_crypt_v2 :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt_V2})
	check_duo(t, {mode = .Tls_Crypt_V2, force_cookie = true})
}

@(test)
duo_tcp_plain :: proc(t: ^testing.T) {
	check_duo(t, {mode = .None, transport = .Tcp})
}

@(test)
duo_tcp_tls_auth :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Auth, transport = .Tcp})
}

@(test)
duo_tcp_tls_crypt :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt, transport = .Tcp})
}

@(test)
duo_tcp_tls_crypt_v2 :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt_V2, transport = .Tcp})
}

// --------------------------------------------------------------------- rekey

duo_rekey_done :: proc(d: ^Duo) -> bool {
	for i in 0 ..< d.n {
		c := &d.peers[i].c
		s := duo_srv(d, i)
		if c.state != .Up || s.state != .Up || c.rekeying || s.rekeying {
			return false
		}
		if c.ks.state != .Generated_Keys || s.ks.state != .Generated_Keys {
			return false
		}
	}
	return true
}

Who :: enum u8 {
	Client,
	Server,
	Both,
}

duo_rekey_cycle :: proc(t: ^testing.T, d: ^Duo, who: Who, loc := #caller_location) {
	p := &d.peers[0]
	sl := duo_slot(d)
	ck := duo_count(p.ev[:], p.ev_n, .Key_Installed)
	sk := duo_count(sl.ev[:], sl.ev_n, .Key_Installed)
	if who != .Server {
		testing.expect(t, session_rekey(&p.c, d.now), "client session_rekey refused", loc = loc)
	}
	if who != .Client {
		testing.expect(t, session_rekey(&sl.s, d.now), "server session_rekey refused", loc = loc)
	}
	// Let the soft resets cross.
	ok := duo_run(d, duo_rekey_done, 60 * time.Second)
	if !ok {
		duo_dump(d)
	}
	testing.expect(t, ok, "rekey did not finish", loc = loc)
	testing.expect_value(t, duo_count(p.ev[:], p.ev_n, .Key_Installed), ck + 1)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Key_Installed), sk + 1)
	duo_idle(d, 10 * time.Millisecond)
	duo_expect_echo(t, d, 0, loc)
}

rekey_duo :: proc(t: ^testing.T, o: Duo_Opts, who: Who, rounds := 3, loc := #caller_location) {
	d := duo_connect(t, o, loc = loc)
	if d == nil {
		return
	}
	defer duo_free(d)
	duo_expect_echo(t, d, 0, loc)
	for i in 0 ..< rounds {
		duo_rekey_cycle(t, d, who, loc)
		testing.expect_value(t, int(d.peers[0].c.ks.id), i % 7 + 1)
		testing.expect_value(t, d.peers[0].c.ks.id, duo_srv(d).ks.id)
	}
	c, s := &d.peers[0].c, duo_srv(d)
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
	testing.expect_value(t, c.counters.drop_data_tag, 0)
	testing.expect_value(t, s.counters.drop_data_tag, 0)
	testing.expect_value(t, s.counters.drop_key_id, 0)
	testing.expect_value(t, c.counters.drop_key_id, 0)
	testing.expect_value(t, s.counters.drop_data_no_key, 0)
}

@(test)
duo_rekey_by_client_udp :: proc(t: ^testing.T) {
	rekey_duo(t, {mode = .None}, .Client)
	rekey_duo(t, {mode = .Tls_Auth}, .Client)
	rekey_duo(t, {mode = .Tls_Crypt}, .Client)
	rekey_duo(t, {mode = .Tls_Crypt_V2}, .Client)
}

@(test)
duo_rekey_by_server_udp :: proc(t: ^testing.T) {
	rekey_duo(t, {mode = .None}, .Server)
	rekey_duo(t, {mode = .Tls_Auth}, .Server)
	rekey_duo(t, {mode = .Tls_Crypt}, .Server)
	rekey_duo(t, {mode = .Tls_Crypt_V2}, .Server)
}

@(test)
duo_rekey_by_both_udp :: proc(t: ^testing.T) {
	rekey_duo(t, {mode = .Tls_Crypt}, .Both)
	rekey_duo(t, {mode = .None}, .Both)
}

@(test)
duo_rekey_tcp :: proc(t: ^testing.T) {
	rekey_duo(t, {mode = .Tls_Crypt, transport = .Tcp}, .Client)
	rekey_duo(t, {mode = .Tls_Crypt, transport = .Tcp}, .Server)
	rekey_duo(t, {mode = .None, transport = .Tcp}, .Both)
}

@(test)
duo_rekey_key_id_wraps :: proc(t: ^testing.T) {
	rekey_duo(t, {mode = .Tls_Crypt}, .Server, rounds = 9)
	rekey_duo(t, {mode = .Tls_Crypt}, .Client, rounds = 9)
}

// ------------------------------------------------------------------ ciphers

@(test)
duo_ciphers :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt, cipher = .Aes_128_Gcm})
	check_duo(t, {mode = .Tls_Crypt, cipher = .Chacha20_Poly1305})
	check_duo(t, {mode = .Tls_Auth, cipher = .Chacha20_Poly1305, transport = .Tcp})
	check_duo(t, {mode = .None, cipher = .Aes_128_Gcm, transport = .Tcp})
	check_duo(t, {mode = .Tls_Crypt_V2, cipher = .Aes_256_Gcm})
}

CHACHA_FIRST := [2]push.Cipher{.Chacha20_Poly1305, .Aes_128_Gcm}
CHACHA_ONLY := [1]push.Cipher{.Chacha20_Poly1305}

@(test)
duo_server_cipher_order :: proc(t: ^testing.T) {
	// The client offers all three; the first one of the server wins.
	d := duo_connect(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.ciphers = CHACHA_FIRST[:]
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, session_cipher(&d.peers[0].c), push.Cipher.Chacha20_Poly1305)
	testing.expect_value(t, session_cipher(duo_srv(d)), push.Cipher.Chacha20_Poly1305)
	duo_expect_echo(t, d)
}

@(test)
duo_no_common_cipher :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, cipher = .Aes_128_Gcm})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.ciphers = CHACHA_ONLY[:]
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	c, sl := &d.peers[0], duo_slot(d)
	// The caller was not asked.
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Request), 0)
	sev, ok := duo_last(sl.ev[:], sl.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed on the server")
	testing.expect_value(t, event_text(&sev), push.NCP_FAIL_NO_SHARED_CIPHER)
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Closed), "no Closed on the server")
	cev, ok2 := duo_last(c.ev[:], c.ev_n, .Auth_Failed)
	testing.expect(t, ok2, "no Auth_Failed on the client")
	testing.expect_value(t, event_text(&cev), push.NCP_FAIL_NO_SHARED_CIPHER)
	testing.expect_value(t, session_fail_reason(&c.c), Fail_Reason.Auth_Failed)
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
}

// ------------------------------------------------------------------- login

@(test)
duo_login_ok :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, string(sl.seen.user[:sl.seen.user_n]), FAKE_USER)
	testing.expect(t, sl.seen.pass_ok, "the server did not get the password")
	// The reply wiped it: no second look.
	req: Auth_Request
	testing.expect(t, !session_auth_request(&sl.s, &req), "request still readable after the reply")
	// No event or text carries the password.
	for i in 0 ..< sl.ev_n {
		testing.expect(t, !strings.contains(event_text(&sl.ev[i]), FAKE_PASS), "password in an event")
	}
}

wrong_password :: proc(d: ^Duo) {
	d.peers[0].cfg.password = "wrong"
}

@(test)
duo_login_wrong_password :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	wrong_password(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	c, sl := &d.peers[0], duo_slot(d)
	cev, ok := duo_last(c.ev[:], c.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed on the client")
	testing.expect_value(t, cev.auth_kind, push.Auth_Failed_Kind.Reason)
	testing.expect_value(t, event_text(&cev), "no entry")
	testing.expect_value(t, session_fail_reason(&c.c), Fail_Reason.Auth_Failed)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Failed), 1)
	testing.expect_value(t, sl.s.state, State.Closed)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Up), 0)
}

reject_case :: proc(t: ^testing.T, policy: Policy, kind: push.Auth_Failed_Kind, text: string, loc := #caller_location) {
	d := duo_new({mode = .Tls_Crypt, policy = policy})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end", loc = loc)
	testing.expect(t, d.now < 5 * time.Second, "the server waited for the linger", loc = loc)
	c, sl := &d.peers[0], duo_slot(d)
	cev, ok := duo_last(c.ev[:], c.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed on the client", loc = loc)
	testing.expect_value(t, cev.auth_kind, kind)
	testing.expect_value(t, event_text(&cev), text)
	if kind == .Temp {
		testing.expect_value(t, cev.backoff, 7)
		testing.expect_value(t, cev.advance, push.Temp_Advance.Remote)
	}
	sev, ok2 := duo_last(sl.ev[:], sl.ev_n, .Auth_Failed)
	testing.expect(t, ok2, "no Auth_Failed on the server", loc = loc)
	testing.expect_value(t, sev.auth_kind, kind)
	// The server closes after the ack.
	testing.expect_value(t, sl.s.state, State.Closed)
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Closed), "no Closed", loc = loc)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Up), 0)
	testing.expect_value(t, duo_count(c.ev[:], c.ev_n, .Up), 0)
}

@(test)
duo_reject_plain :: proc(t: ^testing.T) {
	reject_case(t, .Reject_Plain, .Reason, "no entry")
}

@(test)
duo_reject_temp :: proc(t: ^testing.T) {
	reject_case(t, .Reject_Temp, .Temp, "come back later")
}

@(test)
duo_reject_session :: proc(t: ^testing.T) {
	reject_case(t, .Reject_Session, .Session, "")
}

@(test)
duo_reject_temp_needs_the_iv_proto_bit :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, policy = .Reject_Temp})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.iv_proto = push.Iv_Proto{.Data_V2, .Request_Push, .Tls_Key_Export, .Cc_Exit_Notify, .Dyn_Tls_Crypt}
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	c := &d.peers[0]
	cev, ok := duo_last(c.ev[:], c.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed on the client")
	// A client without the bit gets the plain form with the reason.
	testing.expect_value(t, cev.auth_kind, push.Auth_Failed_Kind.Reason)
	testing.expect_value(t, event_text(&cev), "come back later")
}

short_hand_window :: proc(d: ^Duo) {
	d.scfg.hand_window = 10 * time.Second
}

@(test)
duo_auth_never_answered :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, policy = .Silent})
	if d == nil {
		return
	}
	defer duo_free(d)
	short_hand_window(d)
	testing.expect_value(t, duo_start(d), Error.None)
	start := d.now
	testing.expect(t, duo_run(d, duo_s0_done, 60 * time.Second), "the server never gave up")
	sl := duo_slot(d)
	testing.expect_value(t, sl.s.state, State.Failed)
	testing.expect_value(t, session_fail_reason(&sl.s), Fail_Reason.Hand_Window)
	testing.expect(t, d.now - start >= 10 * time.Second && d.now - start <= 12 * time.Second, "wrong auth deadline")
}

@(test)
duo_auth_pending :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, policy = .Pending})
	if d == nil {
		return
	}
	defer duo_free(d)
	c := &d.peers[0]
	ev, ok := duo_last(c.ev[:], c.ev_n, .Auth_Pending)
	testing.expect(t, ok, "no Auth_Pending on the client")
	testing.expect_value(t, ev.timeout, 20)
	duo_expect_echo(t, d)
}

@(test)
duo_auth_pending_expires :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, policy = .Pending})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	// The harness responds after 3 s; hold it back past the 20 s of AUTH_PENDING.
	duo_run(d, proc(d: ^Duo) -> bool {
		sl := duo_slot(d)
		if sl != nil && sl.pend_sent {
			sl.pend_at = d.now + 600 * time.Second
			return true
		}
		return false
	}, 30 * time.Second)
	testing.expect(t, duo_run(d, duo_s0_done, 60 * time.Second), "the server never gave up")
	testing.expect_value(t, session_fail_reason(duo_srv(d)), Fail_Reason.Hand_Window)
}

// -------------------------------------------------------- pinned and CA mode

@(test)
duo_pinned_accept :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt, pinned = true})
	check_duo(t, {mode = .None, pinned = true, transport = .Tcp})
	check_duo(t, {mode = .Tls_Crypt_V2, pinned = true})
}

// What the server saw of the client key is the one that was pinned.
@(test)
duo_pinned_identity :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, pinned = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.key.spki_sha256, ossl.sha256(P256_CLIENT_SPKI))
	testing.expect_value(t, sl.seen.key.cert_sha256, ossl.sha256(P256_CLIENT_DER))
	key, ok := session_server_peer_key(&sl.s)
	testing.expect(t, ok, "no peer key")
	testing.expect_value(t, key, sl.seen.key)
	_, _, has_cert := session_server_chain_cert(&sl.s)
	testing.expect(t, !has_cert, "a pinned key is not a chain proof")
}

// The client session keeps the key of the server's certificate (the daemon
// compares it with the key of the outer TLS of the `tls` transport).
@(test)
duo_client_peer_key :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, pinned = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	key, ok := session_peer_key(&d.peers[0].c)
	testing.expect(t, ok, "no peer key")
	testing.expect_value(t, key.spki_sha256, ossl.sha256(P256_SERVER_SPKI))
	testing.expect_value(t, key.cert_sha256, ossl.sha256(P256_SERVER_DER))
}

other_pin :: proc(d: ^Duo) {
	d.pin_client[0][0] ~= 0x55
}

// The server refuses a key that is not pinned. In TLS 1.3 the client's
// handshake is already done at that point: the server must not ask the caller,
// and the client must fail on the alert.
@(test)
duo_pinned_refuse :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, pinned = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	other_pin(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	sl := duo_slot(d)
	testing.expect_value(t, sl.s.state, State.Failed)
	testing.expect_value(t, session_fail_reason(&sl.s), Fail_Reason.Tls)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Request), 0)
	testing.expect(t, !sl.s.ks.km_sent, "the server sent its key-method message to a refused client")
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
	testing.expect_value(t, duo_count(d.peers[0].ev[:], d.peers[0].ev_n, .Up), 0)
}

Pin_Switch :: struct {
	allow: bool,
	asked: int,
}

pin_switch_check :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> bool {
	sw := (^Pin_Switch)(user)
	sw.asked += 1
	return sw.allow
}

// A peers file that can switch a key off: the callback sees the key and says
// no for a disabled one.
@(test)
duo_pinned_callback_disabled :: proc(t: ^testing.T) {
	sw := Pin_Switch {
		allow = true,
	}
	tweak :: proc(d: ^Duo) {
		d.scfg.pin_spki = nil
		d.scfg.pin_check = pin_switch_check
	}
	{
		d := duo_new({mode = .Tls_Crypt, pinned = true})
		if d == nil {
			return
		}
		defer duo_free(d)
		tweak(d)
		d.scfg.pin_user = &sw
		testing.expect_value(t, duo_start(d), Error.None)
		testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection while enabled")
		testing.expect(t, sw.asked >= 1, "the callback was not called")
	}
	sw.allow = false
	{
		d := duo_new({mode = .Tls_Crypt, pinned = true})
		if d == nil {
			return
		}
		defer duo_free(d)
		tweak(d)
		d.scfg.pin_user = &sw
		testing.expect_value(t, duo_start(d), Error.None)
		testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end while disabled")
		testing.expect_value(t, session_fail_reason(duo_srv(d)), Fail_Reason.Tls)
		testing.expect_value(t, duo_count(duo_slot(d).ev[:], duo_slot(d).ev_n, .Auth_Request), 0)
	}
}

// The client refuses the server by its pin (a different server key).
@(test)
duo_pinned_client_refuses :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, pinned = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].pin[0][0] ~= 0x55
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
	testing.expect_value(t, duo_count(duo_slot(d).ev[:], duo_slot(d).ev_n, .Auth_Request), 0)
}

@(test)
duo_ca_chain_ok :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	// The CN of the leaf, for a label.
	testing.expect(t, sl.seen.cn_n > 0, "no common name in CA mode")
	// The certificate selector (peer.kick `serial`) sees the CN and a serial.
	cn, serial, ok := session_server_chain_cert(&sl.s)
	testing.expect(t, ok)
	testing.expect_value(t, cn, string(sl.seen.cn[:sl.seen.cn_n]))
	testing.expect(t, len(serial) > 0 && len(serial) <= ossl.SERIAL_BYTES_MAX && serial[0] != 0, "serial has no leading zero")
}

@(test)
duo_ca_wrong_ca_on_the_server :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.ca_pem = OTHER_CA_PEM
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	sl := duo_slot(d)
	testing.expect_value(t, session_fail_reason(&sl.s), Fail_Reason.Tls)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Request), 0)
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
}

@(test)
duo_ca_wrong_ca_on_the_client :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.ca_pem = OTHER_CA_PEM
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
	sl := duo_slot(d)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Auth_Request), 0)
}

// ------------------------------------------------------------------- closing

g_client_ended :: proc(d: ^Duo) -> bool {
	return duo_c0_done(d)
}

NO_CC_EXIT := push.Protocol_Flags{.Dyn_Tls_Crypt}

@(test)
duo_server_exit_cc :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	start := d.now
	session_close(&sl.s, d.now, .Exit)
	testing.expect(t, duo_run(d, duo_both_done, 10 * time.Second), "close did not finish")
	testing.expect(t, duo_has(d.peers[0].ev[:], d.peers[0].ev_n, .Remote_Exit), "the client saw no exit")
	testing.expect_value(t, session_fail_reason(&d.peers[0].c), Fail_Reason.Server_Signal)
	testing.expect_value(t, sl.s.state, State.Closed)
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Closed), "no Closed on the server")
	testing.expect(t, d.now - start < 500 * time.Millisecond, "the close waited for the timeout")
}

@(test)
duo_server_exit_cc_tcp :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	session_close(duo_srv(d), d.now, .Exit)
	testing.expect(t, duo_run(d, duo_both_done, 10 * time.Second), "close did not finish")
	testing.expect(t, duo_has(d.peers[0].ev[:], d.peers[0].ev_n, .Remote_Exit), "the client saw no exit")
}

@(test)
duo_server_exit_occ :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.flags = NO_CC_EXIT
	d.scfg.exit_notify = 2
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect(t, .Cc_Exit not_in session_protocol_flags(duo_srv(d)), "cc-exit negotiated")
	start := d.now
	session_close(duo_srv(d), d.now, .Exit)
	testing.expect(t, duo_run(d, duo_both_done, 20 * time.Second), "close did not finish")
	testing.expect(t, duo_has(d.peers[0].ev[:], d.peers[0].ev_n, .Remote_Exit), "the client saw no exit")
	testing.expect(t, d.now - start >= time.Second, "exit notices not spaced by a second")
	testing.expect_value(t, duo_slot(d).s.state, State.Closed)
}

@(test)
duo_server_restart :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	session_close(duo_srv(d), d.now, .Restart)
	testing.expect(t, duo_run(d, duo_both_done, 10 * time.Second), "close did not finish")
	ev, ok := duo_last(d.peers[0].ev[:], d.peers[0].ev_n, .Restart)
	testing.expect(t, ok, "the client saw no RESTART")
	testing.expect(t, !ev.next_remote, "next remote on a plain RESTART")
}

@(test)
duo_server_restart_next :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Auth})
	if d == nil {
		return
	}
	defer duo_free(d)
	session_close(duo_srv(d), d.now, .Restart_Next)
	testing.expect(t, duo_run(d, duo_both_done, 10 * time.Second), "close did not finish")
	ev, ok := duo_last(d.peers[0].ev[:], d.peers[0].ev_n, .Restart)
	testing.expect(t, ok, "the client saw no RESTART")
	testing.expect(t, ev.next_remote, "no next remote")
}

// TCP: a restart notice has no point (the connection ends), so the server
// just closes.
@(test)
duo_server_restart_tcp :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	session_close(duo_srv(d), d.now, .Restart)
	duo_settle(d)
	testing.expect_value(t, duo_slot(d).s.state, State.Closed)
	testing.expect(t, !duo_has(d.peers[0].ev[:], d.peers[0].ev_n, .Restart), "RESTART over TCP")
}

@(test)
duo_server_halt :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	session_close(duo_srv(d), d.now, .Halt)
	testing.expect(t, duo_run(d, duo_both_done, 10 * time.Second), "close did not finish")
	testing.expect(t, duo_has(d.peers[0].ev[:], d.peers[0].ev_n, .Halt), "the client saw no HALT")
}

@(test)
duo_server_close_before_up :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	session_close(duo_srv(d), d.now)
	duo_settle(d)
	testing.expect_value(t, duo_slot(d).s.state, State.Closed)
}

// The client says EXIT: the server raises Remote_Exit, keeps the session for
// five seconds (retransmits of the last message still get acked), then closes.
@(test)
duo_client_exit_cc :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	start := d.now
	session_close(&d.peers[0].c, d.now)
	testing.expect(t, duo_run(d, g_client_ended, 10 * time.Second), "the client did not close")
	duo_settle(d)
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Remote_Exit), "the server saw no exit")
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Closed), 0)
	testing.expect(t, sl.s.state == .Closing, "the server did not linger")
	testing.expect(t, duo_run(d, duo_s0_done, 10 * time.Second), "the server never closed")
	testing.expect_value(t, sl.s.state, State.Closed)
	testing.expect(t, d.now - start >= 5 * time.Second && d.now - start < 7 * time.Second, "the linger is not five seconds")
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Closed), 1)
}

@(test)
duo_client_exit_cc_tcp :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt_V2, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	session_close(&d.peers[0].c, d.now)
	testing.expect(t, duo_run(d, duo_s0_done, 20 * time.Second), "the server never closed")
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Remote_Exit), "the server saw no exit")
}

@(test)
duo_client_exit_occ :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.flags = NO_CC_EXIT
	d.peers[0].cfg.explicit_exit_notify = 2
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	session_close(&d.peers[0].c, d.now)
	testing.expect(t, duo_run(d, duo_s0_done, 30 * time.Second), "the server never closed")
	sl := duo_slot(d)
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Remote_Exit), 1)
	testing.expect_value(t, sl.s.state, State.Closed)
}

// ---------------------------------------------------------------- keepalive

@(test)
duo_keepalive_both_ways :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.ping, d.ping_rest = 10, 60
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	duo_idle(d, 35 * time.Second)
	c, s := &d.peers[0].c, duo_srv(d)
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, s.state, State.Up)
	testing.expect(t, c.counters.ping_tx >= 3 && c.counters.ping_tx <= 4, "client ping count is wrong")
	testing.expect(t, s.counters.ping_tx >= 3 && s.counters.ping_tx <= 4, "server ping count is wrong")
	testing.expect_value(t, s.ping, 10)
	// The client is told 60; the server waits twice as long (as `keepalive 10 60`).
	testing.expect_value(t, c_pushed_restart(&d.peers[0].c), 60)
	testing.expect_value(t, s.ping_restart, 120)
}

c_pushed_restart :: proc(c: ^Session) -> int {
	po := session_pushed(c)
	return (po.ping_restart.? or_else 0) if po != nil else -1
}

@(test)
duo_ping_restart_on_the_server :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.ping, d.ping_rest = 5, 30
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	duo_idle(d, 20 * time.Second)
	testing.expect_value(t, duo_srv(d).state, State.Up)
	d.peers[0].kill_c2s = 1000000
	start := d.now
	testing.expect(t, duo_run(d, duo_s0_done, 120 * time.Second), "no ping-restart")
	sl := duo_slot(d)
	testing.expect_value(t, session_fail_reason(&sl.s), Fail_Reason.Ping_Timeout)
	// Pushed 30: the server gives up after twice that.
	testing.expect(t, d.now - start >= 59 * time.Second && d.now - start <= 66 * time.Second, "wrong ping-restart time")
	testing.expect(t, duo_has(sl.ev[:], sl.ev_n, .Failed), "no Failed event")
}

own_restart_45 :: proc(d: ^Duo, slot: int, cp: ^Client_Params) {
	cp.ping_restart_own = 45
}

// `Client_Params.ping_restart_own` replaces the "twice the pushed value" rule.
@(test)
duo_ping_restart_own_value :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.ping, d.ping_rest = 5, 30
	d.params = own_restart_45
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, duo_srv(d).ping_restart, 45)
	testing.expect_value(t, c_pushed_restart(&d.peers[0].c), 30)
	duo_idle(d, 20 * time.Second)
	testing.expect_value(t, duo_srv(d).state, State.Up)
	d.peers[0].kill_c2s = 1000000
	start := d.now
	testing.expect(t, duo_run(d, duo_s0_done, 120 * time.Second), "no ping-restart")
	testing.expect_value(t, session_fail_reason(&duo_slot(d).s), Fail_Reason.Ping_Timeout)
	testing.expect(t, d.now - start >= 44 * time.Second && d.now - start <= 51 * time.Second, "wrong ping-restart time")
}

// No pushed ping-restart and no own value: the server runs no timeout.
@(test)
duo_ping_restart_none :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, duo_srv(d).ping_restart, 0)
}

@(test)
duo_traffic_keeps_the_peer_alive :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.ping, d.ping_rest = 5, 20
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	for _ in 0 ..< 10 {
		duo_idle(d, 10 * time.Second)
		testing.expect_value(t, duo_echo(d, 0, 2, 100), 2)
	}
	testing.expect_value(t, duo_srv(d).state, State.Up)
	testing.expect_value(t, d.peers[0].c.state, State.Up)
}

// ---------------------------------------------------------------- rekey timers

// The server starts rekeys at reneg-sec (with the jitter of 10 percent at
// most), once per session.
@(test)
duo_server_rekey_by_timer :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.reneg_sec = 20
	d.peers[0].cfg.reneg_sec = -1
	d.ping, d.ping_rest = 5, 60
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	s := duo_srv(d)
	testing.expect(t, s.reneg_eff >= 18 && s.reneg_eff <= 20, "jitter out of range")
	for _ in 0 ..< 7 {
		duo_idle(d, 10 * time.Second)
		testing.expect_value(t, duo_echo(d, 0, 2, 80), 2)
	}
	testing.expect(t, s.counters.rekeys >= 3, "fewer than 3 rekeys in 70 s")
	testing.expect_value(t, s.state, State.Up)
	testing.expect_value(t, d.peers[0].c.state, State.Up)
	testing.expect_value(t, duo_count(duo_slot(d).ev[:], duo_slot(d).ev_n, .Failed), 0)
}

@(test)
duo_jitter_differs_between_sessions :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, n = 6})
	if d == nil {
		return
	}
	defer duo_free(d)
	seen: [DUO_MAX]int
	same := 0
	for i in 0 ..< d.n {
		seen[i] = duo_srv(d, i).reneg_eff
		testing.expect(t, seen[i] >= 3240 && seen[i] <= 3600, "jitter out of range")
		if i > 0 && seen[i] == seen[0] {
			same += 1
		}
	}
	testing.expect(t, same < d.n - 1, "all sessions got the same reneg-sec")
}

@(test)
duo_server_rekey_by_packet_count :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.reneg_pkts = 20
	d.peers[0].cfg.reneg_sec = -1
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	for _ in 0 ..< 6 {
		duo_echo(d, 0, 10, 50)
		duo_idle(d, time.Second)
	}
	testing.expect(t, duo_srv(d).counters.rekeys >= 2, "no rekey by packet count")
	testing.expect_value(t, duo_srv(d).state, State.Up)
	testing.expect_value(t, duo_echo(d, 0, 3, 50), 3)
}

// --------------------------------------------------------------- impairments

impaired :: proc(t: ^testing.T, o: Duo_Opts, tweak: proc(p: ^Duo_Peer), loc := #caller_location) {
	d := duo_new(o)
	if d == nil {
		return
	}
	defer duo_free(d)
	tweak(&d.peers[0])
	testing.expect_value(t, duo_start(d), Error.None)
	ok := duo_run(d, duo_all_up, 120 * time.Second)
	if !ok {
		duo_dump(d)
	}
	testing.expect(t, ok, "no connection under impairment", loc = loc)
	if !ok {
		return
	}
	// Clean link again: data flows, and a rekey from each side works.
	p := &d.peers[0]
	p.loss_c2s, p.loss_s2c = 0, 0
	p.dup_c2s, p.dup_s2c, p.swap_c2s, p.swap_s2c = false, false, false, false
	duo_expect_echo(t, d, 0, loc)
}

@(test)
duo_handshake_first_packets_lost :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Crypt, .Tls_Crypt_V2}) {
		impaired(t, {mode = m}, proc(p: ^Duo_Peer) {
			p.kill_c2s = 2
			p.kill_s2c = 2
		})
	}
}

@(test)
duo_handshake_random_loss :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		impaired(t, {mode = m}, proc(p: ^Duo_Peer) {
			p.loss_c2s, p.loss_s2c = 25, 25
		})
	}
}

@(test)
duo_handshake_duplicates :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		impaired(t, {mode = m}, proc(p: ^Duo_Peer) {
			p.dup_c2s, p.dup_s2c = true, true
		})
	}
}

@(test)
duo_handshake_reordered :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		impaired(t, {mode = m}, proc(p: ^Duo_Peer) {
			p.swap_c2s, p.swap_s2c = true, true
		})
	}
}

// The first packet of the client is lost many times: the client resends its
// reset, and each resend gets a reply (same cookie inside one bucket).
@(test)
duo_reset_resent :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].kill_s2c = 3 // three replies get lost
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 120 * time.Second), "no connection")
	testing.expect(t, d.replies >= 3, "the stateless replies were not repeated")
}

@(test)
duo_data_duplicates_and_reorder :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	p := &d.peers[0]
	p.dup_c2s, p.dup_s2c = true, true
	// A replay is dropped by the receiver: one echo per packet.
	testing.expect_value(t, duo_echo(d, 0, 5, 100), 5)
	testing.expect(t, duo_srv(d).counters.drop_data_replay >= 5 || duo_srv(d).counters.drop_data_tag >= 0, "replays not counted")
	p.dup_c2s, p.dup_s2c = false, false
	p.swap_c2s, p.swap_s2c = true, true
	testing.expect(t, duo_echo(d, 0, 6, 100) >= 6, "reordered data lost")
}

@(test)
duo_rekey_with_loss :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	p := &d.peers[0]
	p.loss_c2s, p.loss_s2c = 30, 30
	testing.expect(t, session_rekey(duo_srv(d), d.now), "server session_rekey refused")
	ok := duo_run(d, duo_rekey_done, 120 * time.Second)
	if !ok {
		duo_dump(d)
	}
	testing.expect(t, ok, "rekey did not finish")
	p.loss_c2s, p.loss_s2c = 0, 0
	duo_expect_echo(t, d)
}

// --------------------------------------------------------------- TCP framing

@(test)
duo_tcp_partial_reads :: proc(t: ^testing.T) {
	for chunk in ([]int{1, 3, 7, 1000}) {
		d := duo_new({mode = .Tls_Crypt_V2, transport = .Tcp})
		if d == nil {
			return
		}
		d.chunk = chunk
		testing.expect_value(t, duo_start(d), Error.None)
		ok := duo_run(d, duo_all_up, 60 * time.Second)
		if !ok {
			duo_dump(d)
		}
		testing.expectf(t, ok, "no connection with chunk %d", chunk)
		if ok {
			duo_expect_echo(t, d)
			testing.expect(t, session_rekey(duo_srv(d), d.now), "rekey refused")
			testing.expect(t, duo_run(d, duo_rekey_done, 30 * time.Second), "rekey did not finish")
		}
		duo_free(d)
	}
}

// A TCP connection that does not start with a reset is not a peer.
@(test)
duo_tcp_first_packet_must_be_a_reset :: proc(t: ^testing.T) {
	d := duo_new({mode = .None, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	s := duo_srv(d)
	// The reset of the server is held back until the client spoke.
	testing.expect_value(t, session_poll_tx(s, d.tx_buf[:], d.now), 0)
	// An ack frame with a fake session id.
	frame: [24]u8
	frame[1] = 22
	frame[2] = 0x28
	for i in 0 ..< 8 {
		frame[3 + i] = u8(i + 1)
		frame[16 + i] = u8(i + 9)
	}
	frame[11] = 1
	r := session_receive(s, frame[:], d.now)
	testing.expect_value(t, r.consumed, len(frame))
	testing.expect_value(t, s.counters.drop_opcode, u64(1))
	testing.expect_value(t, s.state, State.Failed)
	testing.expect_value(t, session_fail_reason(s), Fail_Reason.Link_Error)
}

// ---------------------------------------------------------------- many peers

@(test)
duo_many_peers :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		check_duo(t, {mode = m, n = DUO_MAX})
	}
	check_duo(t, {mode = .Tls_Crypt, transport = .Tcp, n = 4})
}

@(test)
duo_many_peers_login :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt_V2, n = 5, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	// The WKc metadata tells the clients apart.
	for i in 0 ..< d.n {
		sl := duo_slot(d, i)
		testing.expect_value(t, sl.seen.meta_n, 9)
		testing.expect_value(t, sl.seen.meta[0], u8(1))
		testing.expect_value(t, sl.seen.meta[8], u8(i))
		testing.expect_value(t, string(session_server_metadata(&sl.s)), string(sl.seen.meta[:sl.seen.meta_n]))
	}
}

// A rekey of one peer does not touch the others.
@(test)
duo_peers_are_independent :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, n = 3})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect(t, session_rekey(duo_srv(d, 1), d.now), "rekey refused")
	testing.expect(t, duo_run(d, duo_rekey_done_all, 30 * time.Second), "rekey did not finish")
	testing.expect_value(t, duo_srv(d, 0).counters.rekeys, u64(0))
	testing.expect_value(t, duo_srv(d, 1).counters.rekeys, u64(1))
	testing.expect_value(t, duo_srv(d, 2).counters.rekeys, u64(0))
	// One peer leaves; the others go on.
	session_close(duo_srv(d, 0), d.now, .Exit)
	duo_settle(d)
	testing.expect_value(t, duo_echo(d, 1, 3, 90), 3)
	testing.expect_value(t, duo_echo(d, 2, 3, 90), 3)
}

duo_rekey_done_all :: proc(d: ^Duo) -> bool {
	return duo_rekey_done(d)
}

// Mixed wrapping on one server: plain tls-crypt clients and tls-crypt-v2
// clients.
@(test)
duo_mixed_wrapping :: proc(t: ^testing.T) {
	check_duo(t, {mode = .Tls_Crypt, both_v2 = true})
	check_duo(t, {mode = .Tls_Crypt, client_v2 = true})
	check_duo(t, {mode = .Tls_Auth, client_v2 = true, n = 2})
	check_duo(t, {mode = .Tls_Crypt, client_v2 = true, transport = .Tcp})
}

// A tls-crypt-v2 only server does not respond to a plain client, and the other
// way round.
@(test)
duo_wrong_wrapping_gets_nothing :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt_V2})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.wrap.mode = .Tls_Crypt
	d.peers[0].cfg.wrap.static_key = &d.skey
	d.peers[0].cfg.hand_window = 20 * time.Second
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_c0_done, 60 * time.Second), "the client never gave up")
	testing.expect_value(t, d.peers[0].slot, -1)
	testing.expect_value(t, d.replies, 0)
	testing.expect(t, d.drops[.Wrap_Mode] >= 1, "the first packets were not refused for their wrapping")
}

@(test)
duo_wrong_key_gets_nothing :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.wrap.static_key = &d.other
	d.peers[0].cfg.hand_window = 20 * time.Second
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_c0_done, 60 * time.Second), "the client never gave up")
	testing.expect_value(t, d.peers[0].slot, -1)
	testing.expect_value(t, d.replies, 0)
	testing.expect(t, d.drops[.Unwrap] >= 1, "the first packets were not refused")
}

// ------------------------------------------------------------------- float

@(test)
duo_float :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	p := &d.peers[0]
	sl := duo_slot(d)
	old := p.addr
	// The client moves to another address.
	p.addr = peer_addr_v4({198, 51, 100, 7}, 5555)
	testing.expect_value(t, duo_echo(d, 0, 2, 100), 2)
	testing.expect_value(t, sl.floats, 1)
	fev, ok := duo_last(sl.ev[:], sl.ev_n, .Float_Candidate)
	testing.expect(t, ok, "no Float_Candidate")
	testing.expect_value(t, string(event_addr(&fev)), string(peer_addr_bytes(&p.addr)))
	// The server still talks to the old address until the caller moves it.
	testing.expect_value(t, string(session_server_remote(&sl.s)), string(peer_addr_bytes(&old)))
	// A control packet from the new address is not accepted by the session.
	testing.expect(t, session_rekey(&p.c, d.now), "rekey refused")
	pkt: [LINK_BUF_SIZE]u8
	n := session_poll_tx(&p.c, pkt[:], d.now)
	testing.expect(t, n > 0, "no soft reset")
	_ = session_receive(&sl.s, pkt[:n], d.now, peer_addr_bytes(&p.addr))
	testing.expect_value(t, sl.s.counters.drop_addr, u64(1))
	testing.expect(t, !sl.s.rekeying, "the soft reset from the new address was taken")
	// The caller moves the session; the handshake then goes on.
	testing.expect(t, session_server_set_remote(&sl.s, peer_addr_bytes(&p.addr)), "set_remote refused")
	testing.expect(t, duo_run(d, duo_rekey_done, 60 * time.Second), "rekey did not finish after the move")
	testing.expect_value(t, duo_echo(d, 0, 3, 100), 3)
	testing.expect_value(t, sl.floats, 1)
}

// A forged data packet from another address does not float anything.
@(test)
duo_float_needs_authentic_data :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	junk: [64]u8
	junk[0] = 0x48 // opcode 9, key id 0
	id := session_peer_id(&sl.s)
	junk[1], junk[2], junk[3] = u8(id >> 16), u8(id >> 8), u8(id)
	from := peer_addr_v4({203, 0, 113, 9}, 1234)
	for _ in 0 ..< 5 {
		_ = session_receive(&sl.s, junk[:], d.now, peer_addr_bytes(&from))
	}
	testing.expect_value(t, sl.floats, 0)
	for sl.s.ev_count > 0 {
		ev, _ := session_next_event(&sl.s)
		testing.expect(t, ev.kind != .Float_Candidate, "forged packet raised a float")
	}
	testing.expect_value(t, duo_echo(d, 0, 2, 100), 2)
}

// ---------------------------------------------------------------- peer id

// A data packet with another peer id than the one pushed is dropped before any
// decryption. The id "undefined" is taken (the caller found the peer by its
// address).
@(test)
duo_peer_id_checked :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	p := &d.peers[0]
	sl := duo_slot(d)
	from := peer_addr_bytes(&p.addr)

	buf: [LINK_BUF_SIZE]u8
	n := make_ip_packet(buf[TUNNEL_HEADROOM:], 50, 1)
	pkt, err := session_encap(&p.c, buf[:], n, d.now)
	testing.expect_value(t, err, Error.None)
	wrong := session_peer_id(&sl.s) + 1
	pkt[1], pkt[2], pkt[3] = u8(wrong >> 16), u8(wrong >> 8), u8(wrong)
	r := session_receive(&sl.s, pkt, d.now, from)
	testing.expect_value(t, len(r.tunnel), 0)
	testing.expect_value(t, sl.s.counters.drop_peer_id, u64(1))
	testing.expect_value(t, sl.s.counters.drop_data_tag, u64(0))

	// The id 0xFFFFFF: sealed by a client that has no id.
	p.c.peer_id = PEER_ID_NONE
	n = make_ip_packet(buf[TUNNEL_HEADROOM:], 50, 2)
	pkt, err = session_encap(&p.c, buf[:], n, d.now)
	testing.expect_value(t, err, Error.None)
	r = session_receive(&sl.s, pkt, d.now, from)
	testing.expect_value(t, len(r.tunnel), n)
	testing.expect_value(t, sl.s.counters.drop_peer_id, u64(1))
}

// ------------------------------------------------------------------ renegotiation login

@(test)
duo_rekey_does_not_ask_again :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	duo_rekey_cycle(t, d, .Client)
	duo_rekey_cycle(t, d, .Server)
	// The peer key is the same, so the caller is not asked again.
	testing.expect_value(t, duo_slot(d).seen.count, 1)
}

@(test)
duo_rekey_asks_again_with_reauth :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.reauth = true
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	duo_rekey_cycle(t, d, .Client)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.count, 2)
	testing.expect_value(t, sl.seen.key_id, u8(1))
	testing.expect_value(t, string(sl.seen.user[:sl.seen.user_n]), FAKE_USER)
}

// The caller can ask for the login again for one session only.
@(test)
duo_rekey_asks_again_when_the_session_says_so :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.count, 1)
	session_server_set_reauth(&sl.s, true)
	duo_rekey_cycle(t, d, .Client)
	testing.expect_value(t, sl.seen.count, 2)
	testing.expect_value(t, sl.seen.key_id, u8(1))
	testing.expect(t, sl.seen.pass_ok)
	session_server_set_reauth(&sl.s, false)
	duo_rekey_cycle(t, d, .Client)
	testing.expect_value(t, sl.seen.count, 2)
}

// A wrong password at a renegotiation: the caller refuses, the session ends.
@(test)
duo_rekey_with_a_wrong_password_ends_the_session :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	session_server_set_reauth(&sl.s, true)
	pc := &d.peers[0].c
	pc.pass_n = copy(pc.pass[:], "wrong")
	testing.expect(t, session_rekey(pc, d.now), "rekey refused")
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	testing.expect_value(t, sl.seen.count, 2)
	_, ok := duo_last(sl.ev[:], sl.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed")
	// The new key never went live.
	testing.expect_value(t, duo_count(sl.ev[:], sl.ev_n, .Key_Installed), 0)
}

// A password that the login did not have is put to the caller at a rekey.
@(test)
duo_rekey_with_a_new_password_asks :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.count, 1)
	// No password and no ask at a rekey.
	duo_rekey_cycle(t, d, .Client)
	testing.expect_value(t, sl.seen.count, 1)
	pc := &d.peers[0].c
	pc.user_n = copy(pc.user[:], FAKE_USER)
	pc.pass_n = copy(pc.pass[:], FAKE_PASS)
	duo_rekey_cycle(t, d, .Client)
	testing.expect_value(t, sl.seen.count, 2)
	testing.expect(t, sl.seen.pass_ok)
	testing.expect_value(t, sl.seen.key_id, u8(2))
}

// A renegotiation by another TLS peer key is refused without asking.
@(test)
duo_rekey_by_another_key_refused :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	sl.s.srv.peer_key.spki_sha256[0] ~= 1
	testing.expect(t, session_rekey(&d.peers[0].c, d.now), "rekey refused")
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	ev, ok := duo_last(sl.ev[:], sl.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed")
	testing.expect_value(t, event_text(&ev), "peer key changed on renegotiation")
	testing.expect_value(t, sl.seen.count, 1)
}

// ------------------------------------------------------------------- no client certificate

// The client has no certificate; the server may let it go on.
no_cert_client :: proc(d: ^Duo) {
	d.scfg.client_cert_optional = true
	d.peers[0].cfg.cert_pem, d.peers[0].cfg.key_pem = nil, nil
}

@(test)
duo_optional_certificate_takes_a_client_without_one :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true}, no_cert_client)
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.count, 1)
	testing.expect_value(t, sl.seen.proof, ossl.Peer_Proof.None)
	testing.expect_value(t, sl.seen.cn_n, 0)
	testing.expect_value(t, sl.seen.key, ossl.Peer_Key{})
	_, has := session_server_peer_key(&sl.s)
	testing.expect(t, !has, "a client with no certificate has no key")
	_, _, has_cert := session_server_chain_cert(&sl.s)
	testing.expect(t, !has_cert, "a client with no certificate never matches")
	// The user name and the password reach the caller as always.
	testing.expect_value(t, string(sl.seen.user[:sl.seen.user_n]), FAKE_USER)
	testing.expect(t, sl.seen.pass_ok)
}

@(test)
duo_optional_certificate_still_checks_a_certificate_that_is_sent :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.client_cert_optional = true
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.proof, ossl.Peer_Proof.Chain)
	testing.expect(t, sl.seen.cn_n > 0)
	_, has := session_server_peer_key(&sl.s)
	testing.expect(t, has)
	// A certificate of another CA ends the handshake: the caller is not asked.
	d2 := duo_new({mode = .Tls_Crypt})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	d2.scfg.client_cert_optional = true
	d2.scfg.ca_pem = OTHER_CA_PEM
	testing.expect_value(t, duo_start(d2), Error.None)
	testing.expect(t, duo_run(d2, duo_both_done, 30 * time.Second), "no end")
	testing.expect_value(t, duo_count(duo_slot(d2).ev[:], duo_slot(d2).ev_n, .Auth_Request), 0)
	testing.expect_value(t, d2.peers[0].c.state, State.Failed)
}

@(test)
duo_no_certificate_is_refused_unless_optional :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.cert_pem, d.peers[0].cfg.key_pem = nil, nil
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	testing.expect_value(t, d.peers[0].c.state, State.Failed)
	testing.expect_value(t, duo_count(duo_slot(d).ev[:], duo_slot(d).ev_n, .Auth_Request), 0)
}

// A renegotiation must have the certificate state of the first key: a client
// that had none cannot come back with one, and the other way round.
@(test)
duo_rekey_certificate_state_must_not_change :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.client_cert_optional = true
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	// The server thinks the first key had no certificate.
	sl.s.srv.have_peer_key = false
	testing.expect(t, session_rekey(&d.peers[0].c, d.now), "rekey refused")
	testing.expect(t, duo_run(d, duo_both_done, 30 * time.Second), "no end")
	ev, ok := duo_last(sl.ev[:], sl.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed")
	testing.expect_value(t, event_text(&ev), "peer key changed on renegotiation")

	d2 := duo_connect(t, {mode = .Tls_Crypt, login = true}, no_cert_client)
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	// A client with no certificate renegotiates with none: the caller is not asked again.
	duo_rekey_cycle(t, d2, .Client)
	testing.expect_value(t, duo_slot(d2).seen.count, 1)
	// The server thinks the first key had a certificate.
	sl2 := duo_slot(d2)
	sl2.s.srv.have_peer_key = true
	testing.expect(t, session_rekey(&d2.peers[0].c, d2.now), "rekey refused")
	testing.expect(t, duo_run(d2, duo_both_done, 30 * time.Second), "no end")
	ev, ok = duo_last(sl2.ev[:], sl2.ev_n, .Auth_Failed)
	testing.expect(t, ok, "no Auth_Failed")
	testing.expect_value(t, event_text(&ev), "peer key changed on renegotiation")
}

// ------------------------------------------------------------------- push

@(test)
duo_push_content :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.params = proc(d: ^Duo, slot: int, cp: ^Client_Params) {
		@(static) routes := [?]push.Route{{net = {192, 168, 5, 0}, mask = {255, 255, 255, 0}}, {net = {172, 16, 0, 0}, mask = {255, 240, 0, 0}}}
		@(static) dns := [?]push.Ip_Addr{{bytes = {0 = 10, 1 = 8, 2 = 0, 3 = 1}}}
		@(static) extra := [?]string{"sndbuf 393216", "persist-tun"}
		cp.options.routes = routes[:]
		cp.options.dhcp_dns = dns[:]
		cp.options.redirect_gateway = {
			set   = true,
			flags = {.Def1},
		}
		cp.options.extra = extra[:]
		cp.options.ifconfig6 = push.Ifconfig6 {
			addr    = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			bits    = 64,
			gateway = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		}
	}
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	po := session_pushed(&d.peers[0].c)
	testing.expect_value(t, len(po.routes), 2)
	testing.expect_value(t, po.routes[0].net, [4]u8{192, 168, 5, 0})
	testing.expect_value(t, po.routes[1].mask, [4]u8{255, 240, 0, 0})
	testing.expect_value(t, len(po.dhcp_dns), 1)
	testing.expect(t, po.redirect_gateway.set && .Def1 in po.redirect_gateway.flags, "redirect-gateway def1 missing")
	testing.expect_value(t, po.sndbuf.? or_else 0, 393216)
	testing.expect(t, po.persist_tun, "persist-tun missing")
	i6, ok := po.ifconfig6.?
	testing.expect(t, ok, "no ifconfig-ipv6")
	testing.expect_value(t, i6.bits, u8(64))
	testing.expect_value(t, po.topology, push.Topology.Subnet)
	testing.expect_value(t, po.peer_id.? or_else 0, u32(100))
	// The negotiated values are pushed too.
	testing.expect_value(t, po.cipher, "AES-256-GCM")
	testing.expect_value(t, po.protocol_flags, session_protocol_flags(duo_srv(d)))
}

// A reply that does not fit one message is cut with push-continuation, and the
// client puts it together.
@(test)
duo_push_continuation :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.params = proc(d: ^Duo, slot: int, cp: ^Client_Params) {
		@(static) routes: [200]push.Route
		for i in 0 ..< len(routes) {
			routes[i] = push.Route {
				net  = {10, u8(i / 256 + 20), u8(i), 0},
				mask = {255, 255, 255, 0},
			}
		}
		cp.options.routes = routes[:]
	}
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, len(session_pushed(&d.peers[0].c).routes), 200)
	duo_expect_echo(t, d)
}

@(test)
duo_push_mtu :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.scfg.push_tun_mtu = 1400
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, session_pushed(&d.peers[0].c).tun_mtu.? or_else 0, 1400)
	// Never above what the client takes (IV_MTU).
	d2 := duo_new({mode = .Tls_Crypt})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	d2.scfg.push_tun_mtu = 1500
	d2.peers[0].cfg.iv_mtu = 1300
	testing.expect_value(t, duo_start(d2), Error.None)
	testing.expect(t, duo_run(d2, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, session_pushed(&d2.peers[0].c).tun_mtu.? or_else 0, 1300)
}

// A client that does not say REQUEST_PUSH in its IV_PROTO has to ask; the
// server responds to the PUSH_REQUEST. One that does gets the reply at once.
@(test)
duo_push_on_request :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.iv_proto = push.Iv_Proto{.Data_V2, .Tls_Key_Export, .Auth_Pending_Kw, .Cc_Exit_Notify, .Auth_Fail_Temp, .Dyn_Tls_Crypt}
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect(t, .Request_Push not_in duo_slot(d).seen.proto, "the client said REQUEST_PUSH")
	duo_expect_echo(t, d)

	// A second PUSH_REQUEST is ignored: no second reply.
	c := &d.peers[0].c
	req := "PUSH_REQUEST\x00"
	testing.expect_value(t, int(ossl.tls_write_app(&c.ks.tls, transmute([]u8)req)), int(ossl.Io_Status.Ok))
	flush_tls(c, d.now)
	duo_settle(d)
	testing.expect_value(t, c.state, State.Up)
	testing.expect_value(t, duo_srv(d).state, State.Up)
	testing.expect_value(t, duo_count(d.peers[0].ev[:], d.peers[0].ev_n, .Up), 1)
	duo_expect_echo(t, d)
}

@(test)
duo_push_at_once_with_request_push_bit :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect(t, .Request_Push in duo_slot(d).seen.proto, "no REQUEST_PUSH in IV_PROTO")
	testing.expect(t, duo_srv(d).srv.push_sent, "no PUSH_REPLY sent")
}

// A client without the bit that announces cc-exit (bit 7) is told by
// protocol-flags. One without it gets `key-derivation tls-ekm` and no cc-exit
// or dynamic tls-crypt.
@(test)
duo_old_client_flags :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.iv_proto = push.Iv_Proto{.Data_V2, .Request_Push, .Tls_Key_Export}
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, session_protocol_flags(duo_srv(d)), push.Protocol_Flags{.Tls_Ekm})
	testing.expect(t, session_pushed(&d.peers[0].c).key_derivation_ekm, "no key-derivation tls-ekm")
	duo_expect_echo(t, d)
	duo_rekey_cycle(t, d, .Server)
}

@(test)
duo_dynamic_tls_crypt :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect(t, .Dyn_Tls_Crypt in session_protocol_flags(duo_srv(d)), "dyn-tls-crypt not negotiated")
	testing.expect(t, duo_srv(d).wrap.have_dyn, "no dynamic wrap on the server")
	// A server without the flag keeps the static wrap for all key ids.
	d2 := duo_new({mode = .Tls_Crypt})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	d2.scfg.flags = push.Protocol_Flags{.Cc_Exit}
	testing.expect_value(t, duo_start(d2), Error.None)
	testing.expect(t, duo_run(d2, duo_all_up, 30 * time.Second), "no connection")
	testing.expect(t, !duo_srv(d2).wrap.have_dyn, "dynamic wrap without the flag")
	duo_rekey_cycle(t, d2, .Client)
}

// ---------------------------------------------------------------- no cookie

// A v2 client that does not signal early negotiation (an old one): the server
// creates the session at its first packet and sends its own reset.
@(test)
duo_v2_without_early_negotiation :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt_V2})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	d.peers[0].c.wrap.crypt.counter.id = 0
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection")
	testing.expect_value(t, d.replies, 0)
	testing.expect(t, !duo_srv(d).srv.cookie_start, "cookie where there is none")
	duo_expect_echo(t, d)
	duo_rekey_cycle(t, d, .Server)
}

@(test)
duo_v2_without_early_negotiation_force_cookie :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt_V2, force_cookie = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	d.peers[0].cfg.hand_window = 15 * time.Second
	testing.expect_value(t, duo_start(d), Error.None)
	d.peers[0].c.wrap.crypt.counter.id = 0
	testing.expect(t, duo_run(d, duo_c0_done, 60 * time.Second), "the client never gave up")
	testing.expect_value(t, d.peers[0].slot, -1)
	testing.expect(t, d.drops[.Force_Cookie] >= 1, "no force-cookie refusal")
}

// ------------------------------------------------------------------- misuse

@(test)
duo_server_api_misuse :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	s := duo_srv(d)
	cp := Client_Params {
		peer_id = 5,
	}
	// No request is waiting.
	testing.expect_value(t, session_server_accept(s, &cp, d.now), Error.Bad_State)
	testing.expect_value(t, session_server_reject(s, d.now, "x"), Error.Bad_State)
	testing.expect_value(t, session_server_auth_pending(s, d.now, 5), Error.Bad_State)
	req: Auth_Request
	testing.expect(t, !session_auth_request(s, &req), "request without a waiting login")
	// A client session is not a server.
	c := &d.peers[0].c
	testing.expect_value(t, session_server_accept(c, &cp, d.now), Error.Bad_State)
	testing.expect(t, !session_auth_request(c, &req), "request on a client")
	// session_close twice is harmless.
	session_close(s, d.now)
	session_close(s, d.now)
	duo_settle(d)
}

@(test)
duo_server_bad_peer_id :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, policy = .Silent})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, proc(d: ^Duo) -> bool {
		sl := duo_slot(d)
		return sl != nil && sl.s.ks.auth == .Requested
	}, 30 * time.Second), "no request")
	s := duo_srv(d)
	bad := Client_Params {
		peer_id = PEER_ID_NONE,
	}
	testing.expect_value(t, session_server_accept(s, &bad, d.now), Error.Bad_Config)
	testing.expect_value(t, session_server_accept(s, nil, d.now), Error.Bad_Config)
	// Still waiting; a good reply works.
	good := duo_client_params(d, d.peers[0].slot)
	testing.expect_value(t, session_server_accept(s, &good, d.now), Error.None)
	testing.expect(t, duo_run(d, duo_all_up, 30 * time.Second), "no connection after the good reply")
	// A second reply is refused.
	testing.expect_value(t, session_server_accept(s, &good, d.now), Error.Bad_State)
}

@(test)
duo_memory_size :: proc(t: ^testing.T) {
	// Run with -define:ODIN_TEST_LOG_SIZES=true to see the numbers.
	testing.expectf(t, size_of(Session) < 64 * 1024, "Session is %d bytes", size_of(Session))
	testing.expectf(t, size_of(Srv_State) < 1088, "Srv_State is %d bytes", size_of(Srv_State))
	testing.expectf(t, size_of(Server_Shared) < 16 * 1024, "Server_Shared is %d bytes", size_of(Server_Shared))
}

// ------------------------------------------------------------ stalled handshakes

@(test)
duo_tcp_silent_client_times_out :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	short_hand_window(d)
	testing.expect_value(t, duo_start(d), Error.None)
	d.peers[0].started = false // the client never sends a byte
	start := d.now
	testing.expect(t, duo_run(d, duo_s0_done, 60 * time.Second), "the server never gave up")
	testing.expect_value(t, session_fail_reason(duo_srv(d)), Fail_Reason.Hand_Window)
	testing.expect(t, d.now - start >= 10 * time.Second && d.now - start <= 12 * time.Second, "wrong hand window")
	d.peers[0].started = true
}

@(test)
duo_udp_client_goes_quiet :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	short_hand_window(d)
	// The session exists after the cookie packet (the second one); then nothing
	// more arrives.
	d.peers[0].after_c2s = 2
	testing.expect_value(t, duo_start(d), Error.None)
	start := d.now
	testing.expect(t, duo_run(d, duo_s0_done, 60 * time.Second), "the server never gave up")
	testing.expect_value(t, session_fail_reason(duo_srv(d)), Fail_Reason.Hand_Window)
	testing.expect(t, d.now - start <= 12 * time.Second, "the server waited too long")
}

@(test)
duo_server_wipe_password_while_parked :: proc(t: ^testing.T) {
	d := duo_new({mode = .Tls_Crypt, policy = .Silent, login = true})
	if d == nil {
		return
	}
	defer duo_free(d)
	testing.expect_value(t, duo_start(d), Error.None)
	testing.expect(t, duo_run(d, proc(d: ^Duo) -> bool {
		sl := duo_slot(d)
		return sl != nil && sl.s.ks.auth == .Requested
	}, 30 * time.Second), "no request")
	s := duo_srv(d)
	req: Auth_Request
	testing.expect(t, session_auth_request(s, &req))
	testing.expect_value(t, req.username, FAKE_USER)
	testing.expect_value(t, req.password, FAKE_PASS)
	// The raw peer-info lines are there for the bus event; no password in them.
	testing.expect(t, strings.contains(req.peer_info_text, "IV_VER="), "no IV_VER in the peer-info text")
	testing.expect(t, !strings.contains(req.peer_info_text, FAKE_PASS))
	// Where the password sits in the session's copy of the message.
	pw_at := raw_data(req.password)
	testing.expect(t, session_server_wipe_password(s))
	for i in 0 ..< len(FAKE_PASS) {
		testing.expect_value(t, pw_at[i], u8(0))
	}
	// The user name stays; the password is gone from the view.
	req2: Auth_Request
	testing.expect(t, session_auth_request(s, &req2))
	testing.expect_value(t, req2.username, FAKE_USER)
	testing.expect_value(t, req2.password, "")
	// Still waiting: a decision is possible, and then no request is left.
	testing.expect_value(t, session_server_reject(s, d.now, "denied"), Error.None)
	testing.expect(t, !session_server_wipe_password(s))
	testing.expect(t, !session_auth_request(s, &req2))
}

// A server that checks no certificate (`verify = .None`, for password logins
// only) asks for none. A client that has one still logs in. The caller sees no
// key, no pin and no certificate name, only the user name and password.
@(test)
duo_no_verifier_server_ignores_a_client_certificate :: proc(t: ^testing.T) {
	d := duo_connect(t, {mode = .Tls_Crypt, login = true}, proc(d: ^Duo) {
		d.scfg.client_cert_optional = true
		d.scfg.verify = .None
		d.scfg.ca_pem = nil
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	sl := duo_slot(d)
	testing.expect_value(t, sl.seen.count, 1)
	testing.expect_value(t, sl.seen.proof, ossl.Peer_Proof.None)
	testing.expect_value(t, sl.seen.cn_n, 0)
	testing.expect_value(t, sl.seen.key, ossl.Peer_Key{})
	_, has := session_server_peer_key(&sl.s)
	testing.expect(t, !has, "the server asked for no certificate, so it has no key")
	testing.expect_value(t, string(sl.seen.user[:sl.seen.user_n]), FAKE_USER)
	testing.expect(t, sl.seen.pass_ok)
	// It also renegotiates: the state of the first key holds.
	duo_rekey_cycle(t, d, .Client)
	_, has = session_server_peer_key(&sl.s)
	testing.expect(t, !has)
}
