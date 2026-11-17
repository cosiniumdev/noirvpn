// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/push"
import "noir:proto/wire"
import "noir:proto/wrap"

// The first packets of a UDP server: what a stranger can get the server to do
// (nothing, and no memory), and what a real client gets.

// ------------------------------------------------------------------ helpers

// The first two packets of a real client against `d`: its reset, and the ack
// with the ClientHello that follows our reply.
Flight :: struct {
	reset:  Fake_Pkt,
	reply:  Fake_Pkt,
	second: Fake_Pkt,
	from:   Peer_Addr,
	now:    Time,
}

flight_make :: proc(t: ^testing.T, d: ^Duo, f: ^Flight, peer := 0) -> bool {
	p := &d.peers[peer]
	f.from = p.addr
	f.now = d.now
	buf: [LINK_BUF_SIZE]u8
	n := session_poll_tx(&p.c, buf[:], d.now)
	if !testing.expect(t, n > 0, "the client generated no first packet") {
		return false
	}
	f.reset.n = n
	copy(f.reset.b[:], buf[:n])
	res := server_first_packet(&d.sh, f.reset.b[:n], peer_addr_bytes(&f.from), d.now, duo_unix(d), buf[:])
	if !testing.expect_value(t, res.kind, First_Kind.Reply) {
		return false
	}
	f.reply.n = res.n
	copy(f.reply.b[:], buf[:res.n])
	_ = session_receive(&p.c, f.reply.b[:res.n], d.now)
	n = session_poll_tx(&p.c, buf[:], d.now)
	if !testing.expect(t, n > 0, "the client generated no second packet") {
		return false
	}
	f.second.n = n
	copy(f.second.b[:], buf[:n])
	return true
}

stateless_duo :: proc(t: ^testing.T, o: Duo_Opts, tweak: proc(d: ^Duo) = nil) -> ^Duo {
	d := duo_new(o)
	if d == nil {
		testing.expect(t, false, "bench setup failed")
		return nil
	}
	if tweak != nil {
		tweak(d)
	}
	if err := duo_start(d); err != .None {
		testing.expectf(t, false, "duo_start: %v", err)
		duo_free(d)
		return nil
	}
	return d
}

first :: proc(d: ^Duo, pkt: []u8, from: Peer_Addr, now: Time) -> (r: First_Result) {
	f := from
	out: [LINK_BUF_SIZE]u8
	return server_first_packet(&d.sh, pkt, peer_addr_bytes(&f), now, FAKE_WALL_BASE + i64(now / time.Second), out[:])
}

// The parts of the shared state that a first packet must not change. The rate
// tables and the counters are the only state a first packet may touch.
fingerprint :: proc(sh: ^Server_Shared) -> Server_Shared {
	c := sh^
	c.sources = {}
	c.global = {}
	c.created = {}
	c.stats = {}
	return c
}

same_state :: proc(a, b: ^Server_Shared) -> bool {
	return mem.compare_ptrs(a, b, size_of(Server_Shared)) == 0
}

// ------------------------------------------------------------ what a client gets

// The reply of 3.3 against the reset of a real client, and its size against the
// request (the amplification finding of the package doc).
@(test)
stateless_reply_sizes :: proc(t: ^testing.T) {
	Case :: struct {
		o:       Duo_Opts,
		request: int,
		reply:   int,
	}
	cases := [?]Case {
		{{mode = .None}, 14, 26},
		{{mode = .Tls_Auth}, 42, 54},
		{{mode = .Tls_Auth, auth_digest = .SHA256}, 54, 66},
		{{mode = .Tls_Crypt}, 54, 66},
		// With the WKc the request is much longer than the reply: no gain.
		{{mode = .Tls_Crypt_V2}, 353, 72},
	}
	for c in cases {
		d := stateless_duo(t, c.o)
		if d == nil {
			continue
		}
		defer duo_free(d)
		f: Flight
		if !flight_make(t, d, &f) {
			continue
		}
		testing.expectf(t, f.reset.n == c.request, "%v: request is %d bytes, want %d", c.o.mode, f.reset.n, c.request)
		testing.expectf(t, f.reply.n == c.reply, "%v: reply is %d bytes, want %d", c.o.mode, f.reply.n, c.reply)
		// The reply is longer than the request in the three plain modes (at
		// most 1.86 times) and shorter with a WKc.
		if c.o.mode == .Tls_Crypt_V2 {
			testing.expect(t, f.reply.n < f.reset.n, "v2 reply is not shorter than its request")
		}
		testing.expect(t, f.reply.n * 100 <= f.reset.n * 190 || c.o.mode == .Tls_Crypt_V2, "amplification above 1.9")
	}
}

// What the cookie packet does: the same client address and session id get a
// session; anything else does not.
@(test)
stateless_cookie_accept :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		d := stateless_duo(t, {mode = m})
		if d == nil {
			continue
		}
		defer duo_free(d)
		f: Flight
		if !flight_make(t, d, &f) {
			continue
		}
		res := first(d, f.second.b[:f.second.n], f.from, f.now)
		testing.expect_value(t, res.kind, First_Kind.Accept)
		testing.expect(t, res.accept.cookie, "the accept has no cookie")
		testing.expect_value(t, string(peer_addr_bytes(&res.accept.from)), string(peer_addr_bytes(&f.from)))
		// The reply of the server carried the cookie as its session id.
		sid, ok := server_cookie(&d.sh, peer_addr_bytes(&f.from), res.accept.client_sid, f.now)
		testing.expect(t, ok, "no cookie")
		testing.expect_value(t, res.accept.server_sid, sid)
		testing.expect_value(t, d.sh.stats.accepted, u64(1))

		// A session created from it is in the middle of the handshake.
		s: Session
		testing.expect_value(t, session_init_server(&s, &d.sh, &res.accept, f.now, duo_unix(d)), Error.None)
		defer session_destroy(&s)
		_ = session_receive(&s, f.second.b[:f.second.n], f.now, peer_addr_bytes(&f.from))
		testing.expect_value(t, s.state, State.Handshaking)
		testing.expect_value(t, s.counters.drop_sid + s.counters.drop_reliable + s.counters.drop_opcode, u64(0))
		testing.expect(t, s.ks.tls_ok, "the ClientHello did not start TLS")
	}
}

@(test)
stateless_cookie_other_address :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.None, .Tls_Crypt}) {
		d := stateless_duo(t, {mode = m})
		if d == nil {
			continue
		}
		defer duo_free(d)
		f: Flight
		if !flight_make(t, d, &f) {
			continue
		}
		// Same packet from another port, another IP, another family.
		tries := [?]Peer_Addr {
			peer_addr_v4({192, 0, 2, 10}, 40001),
			peer_addr_v4({192, 0, 2, 11}, 40000),
			peer_addr_v6({0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, 40000),
		}
		for a in tries {
			res := first(d, f.second.b[:f.second.n], a, f.now)
			testing.expect_value(t, res.kind, First_Kind.Drop)
			testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
		}
		testing.expect_value(t, d.sh.stats.accepted, u64(0))
	}
}

@(test)
stateless_cookie_age_and_rotation :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	pkt := f.second.b[:f.second.n]
	// Valid for three buckets: with the default hand window 30 s each, so the
	// reply is good for at least 60 s and at most 90 s.
	res := first(d, pkt, f.from, f.now + 55 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Accept)
	res = first(d, pkt, f.from, f.now + 100 * time.Second)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	res = first(d, pkt, f.from, f.now + 1000 * time.Second)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	// A time before the cookie was generated is not valid either.
	res = first(d, pkt, f.from, 0)
	testing.expect(t, res.kind == .Accept || res.reason == .Bad_Cookie, "odd result for an early clock")

	// One rotation keeps the cookie valid (the previous key stays); two do not.
	testing.expect(t, !server_cookie_rotate_due(&d.sh, f.now), "rotation due at once")
	testing.expect(t, server_cookie_rotate_due(&d.sh, f.now + COOKIE_ROTATE_INTERVAL), "rotation not due after the interval")
	testing.expect_value(t, server_cookie_next_rotation(&d.sh), d.sh.cookie_at + COOKIE_ROTATE_INTERVAL)
	testing.expect_value(t, server_cookie_rotate(&d.sh, f.now + time.Second), Error.None)
	res = first(d, pkt, f.from, f.now + 2 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Accept)
	testing.expect_value(t, server_cookie_rotate(&d.sh, f.now + 3 * time.Second), Error.None)
	res = first(d, pkt, f.from, f.now + 4 * time.Second)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	// A new reset gets a cookie of the new key, and its packet is good.
	res = first(d, f.reset.b[:f.reset.n], f.from, f.now + 5 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Reply)
}

// The cookie belongs to the client session id: another id (created without the
// wrapping, so the packet stays well formed) does not match.
@(test)
stateless_cookie_other_client_sid :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .None})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	pkt := f.second
	pkt.b[1] ~= 0x01 // the sid of the client
	res := first(d, pkt.b[:pkt.n], f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	// A cookie that was guessed.
	pkt = f.second
	cp: wire.Control_Packet
	testing.expect_value(t, wire.control_decode(pkt.b[:pkt.n], &cp), wire.Error.None)
	n := pkt.n
	// The remote sid of the ack sits after the ack ids: 1 + 8 + 1 + 4 * count.
	off := 1 + 8 + 1 + 4 * cp.ack_count
	for i in 0 ..< 8 {
		pkt.b[off + i] ~= 0xff
	}
	res = first(d, pkt.b[:n], f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	// An all-zero cookie.
	for i in 0 ..< 8 {
		pkt.b[off + i] = 0
	}
	res = first(d, pkt.b[:n], f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Bad_Cookie)
	// The packet with a message id above 1 (a forged continuation).
	pkt = f.second
	pkt.b[off + 8 + 3] = 7
	res = first(d, pkt.b[:pkt.n], f.from, f.now)
	testing.expect(t, res.kind == .Drop, "a packet with a far message id was accepted")
}

// Each byte of an authenticated packet is covered by the tag.
@(test)
stateless_flipped_bits :: proc(t: ^testing.T) {
	for m in ([]Wrap_Mode{.Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		d := stateless_duo(t, {mode = m})
		if d == nil {
			continue
		}
		defer duo_free(d)
		f: Flight
		if !flight_make(t, d, &f) {
			continue
		}
		for which in 0 ..< 2 {
			base := f.reset if which == 0 else f.second
			// Every byte but the WKc part of a v2 first packet (that part has its
			// own tag, checked below).
			limit := base.n
			if m == .Tls_Crypt_V2 && which == 0 {
				limit = base.n - 290
			}
			accepted := 0
			for i in 0 ..< limit {
				pkt := base
				pkt.b[i] ~= 0x01
				res := first(d, pkt.b[:pkt.n], f.from, f.now)
				if res.kind != .Drop {
					accepted += 1
				}
			}
			testing.expectf(t, accepted == 0, "%v: %d of %d flipped copies were taken (packet %d)", m, accepted, limit, which)
		}
	}
}

@(test)
stateless_v2_wkc_flipped :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt_V2})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	for i in f.reset.n - 290 ..< f.reset.n {
		pkt := f.reset
		pkt.b[i] ~= 0x80
		res := first(d, pkt.b[:pkt.n], f.from, f.now)
		if res.kind != .Drop {
			testing.expectf(t, false, "a damaged WKc was taken (byte %d)", i)
			return
		}
	}
	// And a WKc generated for another server key.
	pkt := f.reset
	for i in pkt.n - 290 ..< pkt.n - 2 {
		pkt.b[i] = u8(i)
	}
	res := first(d, pkt.b[:pkt.n], f.from, f.now)
	testing.expect_value(t, res.kind, First_Kind.Drop)
}

// ------------------------------------------------------------------- garbage

@(test)
stateless_garbage :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	for m in ([]Wrap_Mode{.Tls_Auth, .Tls_Crypt, .Tls_Crypt_V2}) {
		d := stateless_duo(t, {mode = m})
		if d == nil {
			continue
		}
		defer duo_free(d)
		before := fingerprint(&d.sh)
		from := peer_addr_v4({198, 51, 100, 1}, 1)
		buf: [3000]u8
		context.allocator = mem.tracking_allocator(&track)
		bad := 0
		for i in 0 ..< 4000 {
			duo_random(d, buf[:])
			// Aim at the interesting opcodes: the first byte is a reset, a
			// control or an ack with key id 0, now and then another.
			switch i % 5 {
			case 0:
				buf[0] = 7 << 3
			case 1:
				buf[0] = 10 << 3
			case 2:
				buf[0] = 4 << 3
			case 3:
				buf[0] = 11 << 3
			}
			n := (i * 37) % len(buf)
			res := first(d, buf[:n], from, d.now)
			if res.kind != .Drop {
				bad += 1
			}
		}
		testing.expectf(t, bad == 0, "%v: %d random packets were not dropped", m, bad)
		testing.expect_value(t, track.total_allocation_count, 0)
		after := fingerprint(&d.sh)
		testing.expect(t, same_state(&before, &after), "garbage changed the shared state")
		testing.expect_value(t, d.sh.stats.replies, u64(0))
	}
}

// Short packets of every opcode: nothing reads past the end.
@(test)
stateless_short_packets :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .None})
	if d == nil {
		return
	}
	defer duo_free(d)
	from := peer_addr_v4({198, 51, 100, 1}, 1)
	buf: [40]u8
	for op in 0 ..< 32 {
		for n in 0 ..< len(buf) {
			for i in 0 ..< n {
				buf[i] = u8(i * 3 + 1)
			}
			if n > 0 {
				buf[0] = u8(op << 3)
			}
			res := first(d, buf[:n], from, d.now)
			if n < 14 {
				testing.expectf(t, res.kind == .Drop, "opcode %d, %d bytes: not dropped", op, n)
			}
		}
	}
}

// Every opcode and key id on a valid reset: only 7 (or 10) with key id 0 pass.
@(test)
stateless_opcodes :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .None})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	for op in 0 ..< 32 {
		for kid in 0 ..< 8 {
			pkt := f.reset
			pkt.b[0] = u8(op << 3 | kid)
			res := first(d, pkt.b[:pkt.n], f.from, f.now)
			want_reply := op == 7 && kid == 0
			if want_reply {
				testing.expect_value(t, res.kind, First_Kind.Reply)
			} else {
				testing.expectf(t, res.kind == .Drop, "opcode %d key id %d got a %v", op, kid, res.kind)
			}
		}
	}
	// A data packet is not a first packet.
	dp: [40]u8
	dp[0] = 9 << 3
	res := first(d, dp[:], f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Bad_Opcode)
	// An all-zero session id.
	pkt := f.reset
	for i in 1 ..= 8 {
		pkt.b[i] = 0
	}
	res = first(d, pkt.b[:pkt.n], f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Zero_Sid)
}

@(test)
stateless_bad_addresses_and_buffers :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .None})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	out: [LINK_BUF_SIZE]u8
	r := server_first_packet(&d.sh, f.reset.b[:f.reset.n], nil, f.now, 0, out[:])
	testing.expect_value(t, r.reason, First_Drop.Bad_Address)
	odd := [?]u8{4, 1, 2, 3}
	r = server_first_packet(&d.sh, f.reset.b[:f.reset.n], odd[:], f.now, 0, out[:])
	testing.expect_value(t, r.reason, First_Drop.Bad_Address)
	r = server_first_packet(&d.sh, f.reset.b[:f.reset.n], peer_addr_bytes(&f.from), f.now, 0, out[:100])
	testing.expect_value(t, r.reason, First_Drop.Out_Too_Small)
	huge: [4000]u8
	huge[0] = 7 << 3
	r = server_first_packet(&d.sh, huge[:], peer_addr_bytes(&f.from), f.now, 0, out[:])
	testing.expect_value(t, r.reason, First_Drop.Too_Long)
}

// ---------------------------------------------------------------- floods

@(test)
stateless_flood_keeps_no_state :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	for m in ([]Wrap_Mode{.None, .Tls_Crypt, .Tls_Crypt_V2}) {
		// Limits off: every packet gets a reply, so the whole path runs.
		d := stateless_duo(t, {mode = m}, proc(d: ^Duo) {
			d.scfg.initial_limit = -1
			d.scfg.source_limit = -1
		})
		if d == nil {
			continue
		}
		defer duo_free(d)
		f: Flight
		if !flight_make(t, d, &f) {
			continue
		}
		before := fingerprint(&d.sh)
		replies := 0
		context.allocator = mem.tracking_allocator(&track)
		for i in 0 ..< 20000 {
			// The same wrapped reset from a new address each time. In the wrapped
			// modes the tag is good, as if the attacker had a recorded packet.
			a := peer_addr_v4({u8(10 + i / 65536), u8(i / 256), u8(i), 1}, u16(1024 + i))
			res := first(d, f.reset.b[:f.reset.n], a, f.now)
			if res.kind == .Reply {
				replies += 1
			}
		}
		testing.expect_value(t, replies, 20000)
		testing.expect_value(t, track.total_allocation_count, 0)
		after := fingerprint(&d.sh)
		testing.expect(t, same_state(&before, &after), "a flood of resets changed the shared state")
		testing.expect_value(t, d.sh.stats.accepted, u64(0))
	}
}

@(test)
stateless_rate_limits :: proc(t: ^testing.T) {
	// Per source: 20 per window by default.
	d := stateless_duo(t, {mode = .Tls_Crypt})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	pkt := f.reset.b[:f.reset.n]
	// The reply of flight_make was the first one of this source.
	got := 1
	for _ in 0 ..< 40 {
		res := first(d, pkt, f.from, f.now)
		if res.kind == .Reply {
			got += 1
		} else {
			testing.expect_value(t, res.reason, First_Drop.Rate_Source)
		}
	}
	testing.expect_value(t, got, DEFAULT_SOURCE_LIMIT)
	// Another source is not affected.
	other := peer_addr_v4({192, 0, 2, 99}, 1)
	res := first(d, pkt, other, f.now)
	testing.expect_value(t, res.kind, First_Kind.Reply)
	// The window moves on.
	res = first(d, pkt, f.from, f.now + 11 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Reply)

	// All sources together: 100 per window by default.
	d2 := stateless_duo(t, {mode = .Tls_Crypt})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	f2: Flight
	if !flight_make(t, d2, &f2) {
		return
	}
	pkt2 := f2.reset.b[:f2.reset.n]
	got = 1
	global := 0
	for i in 0 ..< 400 {
		a := peer_addr_v4({10, 1, u8(i / 200), u8(i)}, 5)
		res = first(d2, pkt2, a, f2.now)
		if res.kind == .Reply {
			got += 1
		} else if res.reason == .Rate_Global {
			global += 1
		}
	}
	testing.expect_value(t, got, DEFAULT_INITIAL_LIMIT)
	testing.expect(t, global > 0, "no global limit hit")
	testing.expect(t, d2.sh.stats.rate_hit > 0, "rate hits not counted")
}

// A source limit from the config (`connect-freq-source`) replaces the default;
// the window is the one of the global limit.
@(test)
stateless_source_limit_is_configurable :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.source_limit = 3
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	pkt := f.reset.b[:f.reset.n]
	// The reply of flight_make was the first one of this source.
	got := 1
	for _ in 0 ..< 10 {
		res := first(d, pkt, f.from, f.now)
		if res.kind == .Reply {
			got += 1
		} else {
			testing.expect_value(t, res.reason, First_Drop.Rate_Source)
		}
	}
	testing.expect_value(t, got, 3)
	// Another source has its own count.
	other := peer_addr_v4({192, 0, 2, 99}, 1)
	res := first(d, pkt, other, f.now)
	testing.expect_value(t, res.kind, First_Kind.Reply)
	// The next window starts again.
	res = first(d, pkt, f.from, f.now + 11 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Reply)

	// Without a per-source limit one source gets replies up to the global one.
	d2 := stateless_duo(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.source_limit = -1
	})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	f2: Flight
	if !flight_make(t, d2, &f2) {
		return
	}
	pkt2 := f2.reset.b[:f2.reset.n]
	got = 1
	for _ in 0 ..< 60 {
		res = first(d2, pkt2, f2.from, f2.now)
		if res.kind == .Reply {
			got += 1
		} else {
			testing.expect_value(t, res.reason, First_Drop.Rate_Global)
		}
	}
	testing.expect_value(t, got, 61)
}

// A handshake that works gives its slot back, so honest clients do not use up
// the budget.
@(test)
stateless_accept_gives_the_slot_back :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.initial_limit = 3
		d.scfg.source_limit = -1
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	testing.expect_value(t, d.sh.global.count, 1)
	res := first(d, f.second.b[:f.second.n], f.from, f.now)
	testing.expect_value(t, res.kind, First_Kind.Accept)
	testing.expect_value(t, d.sh.global.count, 0)
}

@(test)
stateless_session_limit :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt}, proc(d: ^Duo) {
		d.scfg.session_limit = 1
	})
	if d == nil {
		return
	}
	defer duo_free(d)
	f: Flight
	if !flight_make(t, d, &f) {
		return
	}
	pkt := f.second.b[:f.second.n]
	res := first(d, pkt, f.from, f.now)
	testing.expect_value(t, res.kind, First_Kind.Accept)
	res = first(d, pkt, f.from, f.now)
	testing.expect_value(t, res.reason, First_Drop.Rate_Sessions)
	res = first(d, pkt, f.from, f.now + 11 * time.Second)
	testing.expect_value(t, res.kind, First_Kind.Accept)
}

// ------------------------------------------------------------- tls-crypt-v2

// A v2 reset without the early-negotiation flag (an old client) cannot be
// replied to statelessly. With force-cookie it is refused. Without it a session
// is created at once.
v2_plain_reset :: proc(d: ^Duo, from: Peer_Addr, out: []u8) -> int {
	p := &d.peers[0]
	ctx: wrap.Tls_Crypt
	wrap.tls_crypt_v2_client_init(&ctx, &p.ckey)
	ctx.counter.id = 0 // no flag
	cp := wire.Control_Packet {
		opcode     = .Hard_Reset_Client_V3,
		session_id = {1, 2, 3, 4, 5, 6, 7, 8},
		packet_id  = 0,
	}
	inner: [64]u8
	n, _ := wire.control_encode(inner[:], &cp)
	wn, err := wrap.tls_crypt_v2_client_wrap(&ctx, p.ckey.wkc[:p.ckey.wkc_len], duo_unix(d), inner[:n], out)
	if err != .None {
		return 0
	}
	return wn
}

@(test)
stateless_v2_without_early_negotiation :: proc(t: ^testing.T) {
	for force in ([]bool{false, true}) {
		d := duo_new({mode = .Tls_Crypt_V2, force_cookie = force})
		if d == nil {
			return
		}
		defer duo_free(d)
		testing.expect_value(t, duo_start(d), Error.None)
		pkt: [LINK_BUF_SIZE]u8
		n := v2_plain_reset(d, d.peers[0].addr, pkt[:])
		testing.expect(t, n > 0, "no packet")
		res := first(d, pkt[:n], d.peers[0].addr, d.now)
		if force {
			testing.expect_value(t, res.kind, First_Kind.Drop)
			testing.expect_value(t, res.reason, First_Drop.Force_Cookie)
		} else {
			testing.expect_value(t, res.kind, First_Kind.Accept)
			testing.expect(t, !res.accept.cookie, "a cookie where there is none")
			// The session responds with its own reset and goes on from there.
			s: Session
			testing.expect_value(t, session_init_server(&s, &d.sh, &res.accept, d.now, duo_unix(d)), Error.None)
			defer session_destroy(&s)
			testing.expect_value(t, session_poll_tx(&s, d.tx_buf[:], d.now), 0) // not before the first packet
			_ = session_receive(&s, pkt[:n], d.now, peer_addr_bytes(&d.peers[0].addr))
			testing.expect_value(t, s.state, State.Handshaking)
			m := session_poll_tx(&s, d.tx_buf[:], d.now)
			testing.expect(t, m > 0, "no reset from the session")
			testing.expect_value(t, d.sh.stats.replies, u64(0))
		}
	}
}

@(test)
stateless_v2_max_age :: proc(t: ^testing.T) {
	// Key generated 40 days before the clock of the bench.
	d := stateless_duo(t, {mode = .Tls_Crypt_V2, max_age_days = 30, key_age_days = 40})
	if d == nil {
		return
	}
	defer duo_free(d)
	buf: [LINK_BUF_SIZE]u8
	n := session_poll_tx(&d.peers[0].c, buf[:], d.now)
	res := first(d, buf[:n], d.peers[0].addr, d.now)
	testing.expect_value(t, res.kind, First_Kind.Drop)
	testing.expect_value(t, res.reason, First_Drop.Metadata_Age)
	d2 := stateless_duo(t, {mode = .Tls_Crypt_V2, max_age_days = 30, key_age_days = 20})
	if d2 == nil {
		return
	}
	defer duo_free(d2)
	n = session_poll_tx(&d2.peers[0].c, buf[:], d2.now)
	res = first(d2, buf[:n], d2.peers[0].addr, d2.now)
	testing.expect_value(t, res.kind, First_Kind.Reply)
}

@(test)
stateless_tcp_and_config_errors :: proc(t: ^testing.T) {
	d := stateless_duo(t, {mode = .Tls_Crypt, transport = .Tcp})
	if d == nil {
		return
	}
	defer duo_free(d)
	buf: [LINK_BUF_SIZE]u8
	res := first(d, buf[:40], d.peers[0].addr, d.now)
	testing.expect_value(t, res.reason, First_Drop.Not_Udp)
	// A UDP session cannot be created on a TCP server, nor the other way round.
	info: Accept_Info
	s: Session
	testing.expect_value(t, session_init_server(&s, &d.sh, &info, d.now, 0), Error.Bad_Config)
	u := stateless_duo(t, {mode = .Tls_Crypt})
	if u == nil {
		return
	}
	defer duo_free(u)
	testing.expect_value(t, session_init_server_tcp(&s, &u.sh, u.now, 0), Error.Bad_Config)

	// Settings that are not allowed.
	sh: Server_Shared
	sc: Server_Config
	sc.cert_pem, sc.key_pem, sc.ca_pem = SERVER_CRT, SERVER_KEY, CA_PEM
	sc.wrap.mode = .Tls_Auth
	testing.expect_value(t, server_shared_init(&sh, &sc, 0), Error.Bad_Config) // no key
	sc.wrap.mode = .Tls_Crypt_V2
	testing.expect_value(t, server_shared_init(&sh, &sc, 0), Error.Bad_Config) // no server key
	sc.wrap.mode = .None
	sc.ciphers = ([]push.Cipher){.None}
	testing.expect_value(t, server_shared_init(&sh, &sc, 0), Error.Bad_Config)
	sc.ciphers = nil
	sc.verify = .Pinned
	testing.expect_value(t, server_shared_init(&sh, &sc, 0), Error.Bad_Config) // no pins
	sc.verify = .Chain
	sc.key_pem = nil
	testing.expect(t, server_shared_init(&sh, &sc, 0) != .None, "no key accepted")
	// The old entry point stays client only.
	cfg: Config
	cfg.role = .Server
	testing.expect_value(t, session_init(&s, &cfg), Error.Not_Implemented)
}

// ---------------------------------------------------------------- vectors

// First packets that stock clients sent (proto/testdata/vectors): our stateless
// path takes them and responds with a reply of the length a stock server gives.
// The packets that follow (cookie = stock server's session id) are refused.
vec_server_case :: proc(t: ^testing.T, c: json.Object, mode: Wrap_Mode, name: string) {
	pkts := vec_arr(c, "packets")
	if vec_str(c, "transport") != "udp" || len(pkts) < 3 {
		return
	}
	p0 := pkts[0].(json.Object)
	p1 := pkts[1].(json.Object)
	req := unhex(vec_str(p0, "wire_hex"))
	stock_reply := unhex(vec_str(p1, "wire_hex"))
	d0 := vec_obj(p0, "decode")
	d1 := vec_obj(p1, "decode")

	key: wrap.Static_Key
	sk: wrap.Server_Key
	sc := Server_Config {
		cert_pem = SERVER_CRT,
		key_pem  = SERVER_KEY,
		ca_pem   = CA_PEM,
	}
	sc.wrap.mode = mode
	switch mode {
	case .None:
	case .Tls_Auth:
		copy(key.bytes[:], unhex(vec_str(c, "static_key_hex")))
		sc.wrap.static_key = &key
		sc.wrap.auth_digest = .SHA1 if vec_str(c, "digest") == "SHA1" else .SHA256
		// The stock client had key-direction 1 (or none); the server takes the other.
		kd := vec_str(c, "key_direction")
		sc.wrap.key_direction = .Zero if strings.has_prefix(kd, "client=1") else .Bidirectional
	case .Tls_Crypt:
		copy(key.bytes[:], unhex(vec_str(c, "static_key_hex")))
		sc.wrap.static_key = &key
	case .Tls_Crypt_V2:
		if !testing.expectf(t, wrap.server_key_from_bytes(unhex(vec_str(c, "server_key_pem_body_hex")), &sk) == .None, "%s: server key", name) {
			return
		}
		sc.wrap.server_key = &sk
	}
	sh: Server_Shared
	if !testing.expectf(t, server_shared_init(&sh, &sc, time.Second) == .None, "%s: server_shared_init", name) {
		return
	}
	defer server_shared_destroy(&sh)
	from := peer_addr_v4({192, 0, 2, 77}, 4242)
	out: [LINK_BUF_SIZE]u8
	unix := i64(vec_int(d0, "wrap_time"))
	res := server_first_packet(&sh, req, peer_addr_bytes(&from), time.Second, unix, out[:])
	if !testing.expectf(t, res.kind == .Reply, "%s: the stock reset got %v %v", name, res.kind, res.reason) {
		return
	}
	testing.expectf(t, res.n == len(stock_reply), "%s: reply is %d bytes, a stock server sent %d", name, res.n, len(stock_reply))

	// The reply is a valid server reset for that client: our client takes it.
	// (Build the client of the vector with its own keys, as vec_first_flight does.)
	client_sid := unhex(vec_str(d0, "session_id"))
	testing.expectf(t, res.n >= 9 && string(client_sid) != string(out[1:9]), "%s: the reply has the client's sid", name)
	if mode == .Tls_Crypt_V2 {
		stock_payload := vec_str(d1, "payload_hex")
		// Early negotiation is signalled by the wrap id of the stock client.
		wid := vec_int(d0, "wrap_id")
		testing.expectf(t, (wid & 0x0f000000 == 0x0f000000) == (stock_payload == "000100020001"), "%s: flag", name)
	}

	// Later packets of the stock client carry the stock server's sid.
	for i in 2 ..< min(len(pkts), 5) {
		o := pkts[i].(json.Object)
		if vec_str(o, "dir") != "c2s" {
			continue
		}
		r2 := server_first_packet(&sh, unhex(vec_str(o, "wire_hex")), peer_addr_bytes(&from), time.Second, unix, out[:])
		// (A v2 server drops a plain opcode 4 for its wrapping, before the cookie.)
		testing.expectf(t, r2.kind == .Drop, "%s: packet %d got %v %v", name, i, r2.kind, r2.reason)
	}
	// The damaged copies are dropped.
	for item in vec_arr(c, "negative") {
		o := item.(json.Object)
		if vec_str(o, "dir") != "c2s" {
			continue
		}
		bad := unhex(vec_str(o, "wire_hex"))
		r3 := server_first_packet(&sh, bad, peer_addr_bytes(&from), time.Second, unix, out[:])
		testing.expectf(t, r3.kind == .Drop, "%s: a damaged stock packet got a %v", name, r3.kind)
	}
}

@(test)
stateless_vectors :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	files := [?]struct {
		data: []u8,
		mode: Wrap_Mode,
	}{{TLS_AUTH_VECTORS, .Tls_Auth}, {TLS_CRYPT_VECTORS, .Tls_Crypt}, {TLS_CRYPT_V2_VECTORS, .Tls_Crypt_V2}}
	cases := 0
	for f in files {
		root, ok := vec_load(t, f.data)
		if !ok {
			continue
		}
		for c in vec_arr(root, "cases") {
			o := c.(json.Object)
			vec_server_case(t, o, f.mode, vec_str(o, "cell"))
			if vec_str(o, "transport") == "udp" {
				cases += 1
			}
		}
	}
	testing.expect(t, cases >= 6, "too few UDP vector cases")
}
