// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package session

import "core:fmt"
import "core:time"
import "noir:proto/ossl"
import "noir:proto/push"
import "noir:proto/wrap"

// Test bench for the server role: real clients against real server sessions. One
// `Server_Shared`, up to DUO_MAX clients, and a small server driver that acts as
// a daemon would: find the session of a datagram, call `server_first_packet` for
// the rest, reply to `Auth_Request` by a policy, echo tunnel packets. The clock
// jumps from wake-up to wake-up; nothing sleeps.

DUO_MAX :: 8
DUO_EVENTS :: 128

Policy :: enum u8 {
	Accept,
	Reject_Plain,
	Reject_Temp,
	Reject_Session,
	// Never reply (the auth deadline ends the session).
	Silent,
	// AUTH_PENDING first, the decision a little later.
	Pending,
}

Duo_Peer :: struct {
	c:        Session,
	cfg:      Config,
	started:  bool,
	addr:     Peer_Addr,
	ckey:     wrap.Client_Key,
	pin:      [2][32]u8,
	cipher1:  [1]push.Cipher,
	c2s:      Link_Q,
	s2c:      Link_Q,
	// TCP: bytes of the two directions.
	up:       [32768]u8,
	up_n:     int,
	down:     [32768]u8,
	down_n:   int,
	// Impairments, as in the client bench.
	kill_c2s: int,
	kill_s2c: int,
	dup_c2s:  bool,
	dup_s2c:  bool,
	swap_c2s: bool,
	swap_s2c: bool,
	loss_c2s: int,
	loss_s2c: int,
	// Drop every packet of the client after the first n (0: off).
	after_c2s: int,
	// What the client reported.
	ev:       [DUO_EVENTS]Event,
	ev_n:     int,
	tunnel:   [32]Fake_Pkt,
	tunnel_n: int,
	slot:     int,
	c2s_pkts: int,
	s2c_pkts: int,
}

// What the server driver saw of the login (copied; the session wipes it).
Seen_Login :: struct {
	key_id:    u8,
	user:      [128]u8,
	user_n:    int,
	pass_ok:   bool,
	cn:        [64]u8,
	cn_n:      int,
	key:       ossl.Peer_Key,
	proof:     ossl.Peer_Proof,
	proto:     push.Iv_Proto,
	remote:    [ADDR_MAX]u8,
	remote_n:  int,
	meta:      [16]u8,
	meta_n:    int,
	has_plat:  bool,
	count:     int,
}

Duo_Slot :: struct {
	s:         Session,
	used:      bool,
	peer:      int,
	ev:        [DUO_EVENTS]Event,
	ev_n:      int,
	tunnel:    [32]Fake_Pkt,
	tunnel_n:  int,
	seen:      Seen_Login,
	asked:     bool, // the Auth_Request got a reply
	pend_sent: bool,
	pend_at:   Time,
	floats:    int,
}

Duo :: struct {
	sh:        Server_Shared,
	scfg:      Server_Config,
	sh_ok:     bool,
	remote:    bool,
	// The sessions with `ext_data` get a recording owner (ext_test.odin).
	ext_c:     [DUO_MAX]Ext_Log,
	ext_s:     [DUO_MAX * 2]Ext_Log,
	now:       Time,
	rng:       u64,
	n:         int,
	peers:     [DUO_MAX]Duo_Peer,
	slots:     [DUO_MAX * 2]Duo_Slot,
	policy:    Policy,
	// Server side: check the user name and password.
	login:     bool,
	echo:      bool,
	// What `Client_Params` the harness gives.
	ping:      int,
	ping_rest: int,
	// Stock-like data for the wrap modes.
	skey:      wrap.Static_Key,
	sk:        wrap.Server_Key,
	mode:      Wrap_Mode,
	transport: Transport,
	chunk:     int,
	tx_buf:    [LINK_BUF_SIZE]u8,
	reply:     [LINK_BUF_SIZE]u8,
	// First-packet results, for the tests.
	replies:   int,
	reply_len: int,
	drops:     [First_Drop]int,
	// Datagrams the driver refused (no session and no accept).
	stray:     int,
	// Changes the `Client_Params` of the harness.
	params:    proc(d: ^Duo, slot: int, cp: ^Client_Params),
	pin_client: [1][32]u8,
	other:     wrap.Static_Key,
}

Duo_Opts :: struct {
	n:           int, // clients, default 1
	mode:        Wrap_Mode,
	transport:   Transport,
	auth_digest: ossl.Hmac_Alg,
	// The data cipher of the client (its only one); default: its own list.
	cipher:      push.Cipher,
	// Pinned certificates (P-256) both ways.
	pinned:      bool,
	login:       bool,
	policy:      Policy,
	force_cookie: bool,
	max_age_days: int,
	// tls-crypt-v2 client keys with a timestamp of this many days ago.
	key_age_days: int,
	// The server has the v2 key on top of a plain mode.
	both_v2:     bool,
	// The clients use tls-crypt-v2 whatever the server's main mode is.
	client_v2:   bool,
	// Every session's data channel runs behind a loopback owner (remote_test.odin).
	remote:      bool,
}

duo_random :: proc(user: rawptr, buf: []u8) -> bool {
	d := (^Duo)(user)
	for i in 0 ..< len(buf) {
		d.rng ~= d.rng >> 12
		d.rng ~= d.rng << 25
		d.rng ~= d.rng >> 27
		buf[i] = u8((d.rng * 0x2545F4914F6CDD1D) >> 56)
	}
	return true
}

duo_pct :: proc(d: ^Duo) -> int {
	d.rng ~= d.rng >> 12
	d.rng ~= d.rng << 25
	d.rng ~= d.rng >> 27
	return int(((d.rng * 0x2545F4914F6CDD1D) >> 33) % 100)
}

duo_new :: proc(o: Duo_Opts) -> ^Duo {
	d := new(Duo)
	d.rng = 0x1234_5678_9abc_def1
	d.n = max(o.n, 1)
	d.mode = o.mode
	d.transport = o.transport
	d.remote = o.remote
	d.policy = o.policy
	d.login = o.login
	d.echo = true
	d.chunk = 1 << 20
	d.now = time.Second
	fake_fill(1, d.skey.bytes[:])
	fake_fill(2, d.other.bytes[:])
	if o.mode == .Tls_Crypt_V2 || o.both_v2 || o.client_v2 {
		sk: [wrap.SERVER_KEY_LEN]u8
		fake_fill(5, sk[:])
		if wrap.server_key_from_bytes(sk[:], &d.sk) != .None {
			free(d)
			return nil
		}
	}

	sc := &d.scfg
	sc.transport = o.transport
	sc.wrap.mode = o.mode
	sc.wrap.static_key = &d.skey
	sc.wrap.auth_digest = o.auth_digest if o.auth_digest != nil else ossl.Hmac_Alg.SHA1
	sc.wrap.key_direction = .Zero
	sc.wrap.force_cookie = o.force_cookie
	sc.wrap.max_age_days = o.max_age_days
	if o.mode == .Tls_Crypt_V2 || o.both_v2 || o.client_v2 {
		sc.wrap.server_key = &d.sk
	}
	sc.cert_pem, sc.key_pem = SERVER_CRT, SERVER_KEY
	sc.ca_pem = CA_PEM
	sc.verify = .Chain
	sc.random = duo_random
	sc.random_user = d
	sc.ciphers = nil

	for i in 0 ..< d.n {
		p := &d.peers[i]
		p.slot = -1
		p.addr = peer_addr_v4({192, 0, 2, u8(10 + i)}, u16(40000 + i))
		c := &p.cfg
		c.transport = o.transport
		c.wrap.mode = .Tls_Crypt_V2 if o.client_v2 else o.mode
		c.wrap.auth_digest = o.auth_digest if o.auth_digest != nil else ossl.Hmac_Alg.SHA1
		c.wrap.key_direction = .One
		c.wrap.static_key = &d.skey
		c.wrap.client_key = &p.ckey
		c.cert_pem, c.key_pem = CLIENT_CRT, CLIENT_KEY
		c.ca_pem = CA_PEM
		c.verify = .Chain
		c.ipv4_peer = true
		c.random = duo_random
		c.random_user = d
		if o.cipher != .None {
			p.cipher1[0] = o.cipher
			c.ciphers = p.cipher1[:]
		}
		if o.login {
			c.username = FAKE_USER
			c.password = FAKE_PASS
		}
		if o.pinned {
			c.cert_pem, c.key_pem = P256_CLIENT_CRT, P256_CLIENT_KEY
			p.pin[0] = ossl.sha256(P256_SERVER_SPKI)
			c.verify = .Pinned
			c.pin_spki = p.pin[0:1]
		}
		if o.mode == .Tls_Crypt_V2 || o.client_v2 {
			kc: wrap.Static_Key
			fake_fill(u64(9 + i), kc.bytes[:])
			meta: wrap.Metadata
			wrap.metadata_make_timestamp(&meta, FAKE_WALL_BASE - i64(o.key_age_days) * 86400)
			meta.data[8] = u8(i) // the last byte tells the clients apart
			n, werr := wrap.tls_crypt_v2_wkc_build(&d.sk, &kc, wrap.metadata_bytes(&meta), p.ckey.wkc[:])
			if werr != .None {
				free(d)
				return nil
			}
			p.ckey.wkc_len = n
			p.ckey.kc = kc
		}
	}
	if o.pinned {
		sc.cert_pem, sc.key_pem = P256_SERVER_CRT, P256_SERVER_KEY
		sc.verify = .Pinned
		d.pin_client[0] = ossl.sha256(P256_CLIENT_SPKI)
		sc.pin_spki = d.pin_client[:]
	}
	return d
}

// Starts the server and every client. Change `d.scfg` and the client configs
// before this.
duo_start :: proc(d: ^Duo) -> Error {
	if err := server_shared_init(&d.sh, &d.scfg, d.now); err != .None {
		return err
	}
	d.sh_ok = true
	for i in 0 ..< d.n {
		if err := duo_start_peer(d, i); err != .None {
			return err
		}
	}
	return .None
}

duo_start_peer :: proc(d: ^Duo, i: int) -> Error {
	p := &d.peers[i]
	if err := session_init(&p.c, &p.cfg); err != .None {
		return err
	}
	p.started = true
	if d.remote {
		loop_attach(&p.c)
	} else if p.cfg.ext_data {
		d.ext_c[i] = {}
		ext_attach(&p.c, &d.ext_c[i])
	}
	if d.transport == .Tcp {
		// The accept of a TCP server: a session per connection.
		slot := duo_slot_new(d, i)
		if slot < 0 {
			return .Alloc
		}
		sl := &d.slots[slot]
		if err := session_init_server_tcp(&sl.s, &d.sh, d.now, FAKE_WALL_BASE + i64(d.now / time.Second)); err != .None {
			sl.used = false
			return err
		}
		if d.remote {
			loop_attach(&sl.s)
		} else if d.scfg.ext_data {
			d.ext_s[slot] = {}
			ext_attach(&sl.s, &d.ext_s[slot])
		}
	}
	return session_start(&p.c, d.now, FAKE_WALL_BASE + i64(d.now / time.Second))
}

duo_slot_new :: proc(d: ^Duo, peer: int) -> int {
	for i in 0 ..< len(d.slots) {
		sl := &d.slots[i]
		if !sl.used {
			sl^ = {}
			sl.used = true
			sl.peer = peer
			d.peers[peer].slot = i
			return i
		}
	}
	return -1
}

duo_free :: proc(d: ^Duo) {
	for i in 0 ..< len(d.slots) {
		if d.slots[i].used {
			session_destroy(&d.slots[i].s)
		}
	}
	for i in 0 ..< d.n {
		if d.peers[i].started {
			session_destroy(&d.peers[i].c)
		}
	}
	if d.sh_ok {
		server_shared_destroy(&d.sh)
	}
	free(d)
}

// --------------------------------------------------------------- the driver

duo_unix :: proc(d: ^Duo) -> i64 {
	return FAKE_WALL_BASE + i64(d.now / time.Second)
}

duo_find_addr :: proc(d: ^Duo, from: []u8) -> int {
	for i in 0 ..< len(d.slots) {
		sl := &d.slots[i]
		if sl.used && sl.s.state != .Closed && sl.s.state != .Failed && string(session_server_remote(&sl.s)) == string(from) {
			return i
		}
	}
	return -1
}

duo_find_id :: proc(d: ^Duo, id: u32) -> int {
	for i in 0 ..< len(d.slots) {
		sl := &d.slots[i]
		if sl.used && sl.s.state == .Up && session_peer_id(&sl.s) == id {
			return i
		}
	}
	return -1
}

// One datagram that reached the server.
duo_input_udp :: proc(d: ^Duo, peer: int, pkt: []u8) {
	p := &d.peers[peer]
	from := peer_addr_bytes(&p.addr)
	slot := -1
	if id, ok := server_peer_id(pkt); ok {
		slot = duo_find_id(d, id) if id != PEER_ID_NONE else duo_find_addr(d, from)
	} else if _, ok2 := server_client_sid(pkt); ok2 {
		slot = duo_find_addr(d, from)
	} else {
		d.stray += 1
		return
	}
	if slot >= 0 {
		sl := &d.slots[slot]
		r := session_receive(&sl.s, pkt, d.now, from)
		duo_server_tunnel(d, slot, r.tunnel)
		return
	}
	if _, isdata := server_peer_id(pkt); isdata {
		d.stray += 1
		return
	}
	res := server_first_packet(&d.sh, pkt, from, d.now, duo_unix(d), d.reply[:])
	switch res.kind {
	case .Drop:
		d.drops[res.reason] += 1
	case .Reply:
		d.replies += 1
		d.reply_len = res.n
		duo_push_s2c(d, peer, d.reply[:res.n])
	case .Accept:
		ns := duo_slot_new(d, peer)
		if ns < 0 {
			d.stray += 1
			return
		}
		sl := &d.slots[ns]
		if err := session_init_server(&sl.s, &d.sh, &res.accept, d.now, duo_unix(d)); err != .None {
			sl.used = false
			p.slot = -1
			return
		}
		if d.remote {
			loop_attach(&sl.s)
		} else if d.scfg.ext_data {
			d.ext_s[ns] = {}
			ext_attach(&sl.s, &d.ext_s[ns])
		}
		r := session_receive(&sl.s, pkt, d.now, from)
		duo_server_tunnel(d, ns, r.tunnel)
	}
}

// The server got a tunnel packet from a client: keep it, and send it back.
duo_server_tunnel :: proc(d: ^Duo, slot: int, pkt: []u8) {
	if len(pkt) == 0 {
		return
	}
	sl := &d.slots[slot]
	if sl.tunnel_n < len(sl.tunnel) {
		x := &sl.tunnel[sl.tunnel_n]
		x.n = len(pkt)
		copy(x.b[:], pkt)
		sl.tunnel_n += 1
	}
	if !d.echo || sl.s.state != .Up {
		return
	}
	buf: [LINK_BUF_SIZE]u8
	copy(buf[TUNNEL_HEADROOM:], pkt)
	out, err := session_encap(&sl.s, buf[:], len(pkt), d.now)
	if err != .None {
		return
	}
	p := &d.peers[sl.peer]
	if d.transport == .Tcp {
		duo_stream_add(p.down[:], &p.down_n, out)
	} else {
		duo_push_s2c(d, sl.peer, out)
	}
}

duo_stream_add :: proc(buf: []u8, n: ^int, data: []u8) {
	if n^ + len(data) <= len(buf) {
		copy(buf[n^:], data)
		n^ += len(data)
	}
}

duo_push_s2c :: proc(d: ^Duo, peer: int, pkt: []u8) {
	p := &d.peers[peer]
	p.s2c_pkts += 1
	duo_impair(d, &p.s2c, pkt, &p.kill_s2c, p.loss_s2c, p.dup_s2c, p.swap_s2c)
}

duo_impair :: proc(d: ^Duo, q: ^Link_Q, pkt: []u8, kill: ^int, loss: int, dup, swap: bool) {
	if kill^ > 0 {
		kill^ -= 1
		return
	}
	if loss > 0 && duo_pct(d) < loss {
		return
	}
	q_push(q, pkt)
	if dup {
		q_push(q, pkt)
	}
	if swap && q.n >= 2 && q.n % 2 == 0 {
		a := (q.head + q.n - 1) % LINK_Q
		b := (q.head + q.n - 2) % LINK_Q
		q.pk[a], q.pk[b] = q.pk[b], q.pk[a]
	}
}

duo_take_tunnel :: proc(p: ^Duo_Peer, pkt: []u8) {
	if len(pkt) == 0 || p.tunnel_n >= len(p.tunnel) {
		return
	}
	x := &p.tunnel[p.tunnel_n]
	x.n = len(pkt)
	copy(x.b[:], pkt)
	p.tunnel_n += 1
}

// The default reply to a login.
duo_client_params :: proc(d: ^Duo, slot: int) -> Client_Params {
	i := d.slots[slot].peer
	cp := Client_Params {
		peer_id = u32(100 + i),
	}
	cp.options.ifconfig = push.Ifconfig {
		a = {10, 8, 0, u8(2 + i)},
		b = {255, 255, 255, 0},
	}
	cp.options.route_gateway = [4]u8{10, 8, 0, 1}
	cp.options.topology = .Subnet
	if d.ping > 0 {
		cp.options.ping = d.ping
	}
	if d.ping_rest > 0 {
		cp.options.ping_restart = d.ping_rest
	}
	if d.params != nil {
		d.params(d, slot, &cp)
	}
	return cp
}

// The caller's side of an `Auth_Request`.
duo_answer :: proc(d: ^Duo, slot: int) {
	sl := &d.slots[slot]
	req: Auth_Request
	if !session_auth_request(&sl.s, &req) {
		return
	}
	sl.seen.count += 1
	sl.seen.key_id = req.key_id
	sl.seen.user_n = copy(sl.seen.user[:], req.username)
	sl.seen.pass_ok = req.password == FAKE_PASS
	sl.seen.cn_n = copy(sl.seen.cn[:], req.common_name)
	sl.seen.key = req.peer_key
	sl.seen.proof = req.proof
	sl.seen.proto = req.peer_info.proto
	sl.seen.remote_n = copy(sl.seen.remote[:], req.remote)
	sl.seen.meta_n = copy(sl.seen.meta[:], req.metadata)
	login_ok := !d.login || (req.username == FAKE_USER && req.password == FAKE_PASS)
	if d.login && d.policy != .Silent {
		// The daemon wipes the password as soon as it has read it.
		_ = session_server_wipe_password(&sl.s)
	}
	sl.asked = true
	policy := d.policy
	if !login_ok {
		policy = .Reject_Plain
	}
	switch policy {
	case .Accept:
		cp := duo_client_params(d, slot)
		if req.key_id > 0 {
			cp = {}
		}
		_ = session_server_accept(&sl.s, &cp, d.now)
	case .Reject_Plain:
		_ = session_server_reject(&sl.s, d.now, "no entry")
	case .Reject_Temp:
		_ = session_server_reject(&sl.s, d.now, "come back later", .Temp, 7, .Remote)
	case .Reject_Session:
		_ = session_server_reject(&sl.s, d.now, "", .Session)
	case .Silent:
		sl.asked = false
	case .Pending:
		_ = session_server_auth_pending(&sl.s, d.now, 20)
		sl.pend_sent = true
		sl.pend_at = d.now + 3 * time.Second
		sl.asked = false
	}
}

duo_drain_events :: proc(d: ^Duo) -> (any: bool) {
	for i in 0 ..< d.n {
		p := &d.peers[i]
		if !p.started {
			continue
		}
		for {
			ev, ok := session_next_event(&p.c)
			if !ok {
				break
			}
			any = true
			if p.ev_n < len(p.ev) {
				p.ev[p.ev_n] = ev
				p.ev_n += 1
			}
		}
	}
	for i in 0 ..< len(d.slots) {
		sl := &d.slots[i]
		if !sl.used {
			continue
		}
		for {
			ev, ok := session_next_event(&sl.s)
			if !ok {
				break
			}
			any = true
			if sl.ev_n < len(sl.ev) {
				sl.ev[sl.ev_n] = ev
				sl.ev_n += 1
			}
			#partial switch ev.kind {
			case .Auth_Request:
				duo_answer(d, i)
			case .Float_Candidate:
				sl.floats += 1
			}
		}
		if sl.pend_sent && !sl.asked && d.now >= sl.pend_at && sl.s.ks.auth == .Requested {
			sl.asked = true
			cp := duo_client_params(d, i)
			_ = session_server_accept(&sl.s, &cp, d.now)
			any = true
		}
	}
	return
}

// One round of I/O. Returns true if anything moved.
duo_io :: proc(d: ^Duo) -> bool {
	moved := false
	tcp := d.transport == .Tcp
	// Clients to the link.
	for i in 0 ..< d.n {
		p := &d.peers[i]
		if !p.started {
			continue
		}
		for {
			n := session_poll_tx(&p.c, d.tx_buf[:], d.now)
			if n == 0 {
				break
			}
			moved = true
			p.c2s_pkts += 1
			pkt := d.tx_buf[:n]
			if p.after_c2s > 0 && p.c2s_pkts > p.after_c2s {
				continue
			}
			if tcp {
				duo_stream_add(p.up[:], &p.up_n, pkt)
			} else {
				duo_impair(d, &p.c2s, pkt, &p.kill_c2s, p.loss_c2s, p.dup_c2s, p.swap_c2s)
			}
		}
	}
	// Link to the server.
	for i in 0 ..< d.n {
		p := &d.peers[i]
		p_pkt: Fake_Pkt
		for q_pop(&p.c2s, &p_pkt) {
			moved = true
			duo_input_udp(d, i, p_pkt.b[:p_pkt.n])
		}
		for p.up_n > 0 && p.slot >= 0 {
			moved = true
			sl := &d.slots[p.slot]
			take := min(p.up_n, d.chunk)
			r := session_receive(&sl.s, p.up[:take], d.now)
			duo_server_tunnel(d, p.slot, r.tunnel)
			copy(p.up[:], p.up[r.consumed:p.up_n])
			p.up_n -= r.consumed
			more := r.more
			for more {
				r2 := session_receive(&sl.s, nil, d.now)
				duo_server_tunnel(d, p.slot, r2.tunnel)
				more = r2.more
			}
			if r.consumed == 0 {
				break
			}
		}
	}
	// Server to the link.
	for k in 0 ..< len(d.slots) {
		sl := &d.slots[k]
		if !sl.used {
			continue
		}
		p := &d.peers[sl.peer]
		for {
			n := session_poll_tx(&sl.s, d.tx_buf[:], d.now)
			if n == 0 {
				break
			}
			moved = true
			if tcp {
				duo_stream_add(p.down[:], &p.down_n, d.tx_buf[:n])
				p.s2c_pkts += 1
			} else {
				duo_push_s2c(d, sl.peer, d.tx_buf[:n])
			}
		}
	}
	// Link to the clients.
	for i in 0 ..< d.n {
		p := &d.peers[i]
		if !p.started {
			continue
		}
		pkt: Fake_Pkt
		for q_pop(&p.s2c, &pkt) {
			moved = true
			r := session_receive(&p.c, pkt.b[:pkt.n], d.now)
			duo_take_tunnel(p, r.tunnel)
		}
		for p.down_n > 0 {
			moved = true
			take := min(p.down_n, d.chunk)
			r := session_receive(&p.c, p.down[:take], d.now)
			duo_take_tunnel(p, r.tunnel)
			copy(p.down[:], p.down[r.consumed:p.down_n])
			p.down_n -= r.consumed
			more := r.more
			for more {
				r2 := session_receive(&p.c, nil, d.now)
				duo_take_tunnel(p, r2.tunnel)
				more = r2.more
			}
			if r.consumed == 0 {
				break
			}
		}
	}
	if duo_drain_events(d) {
		moved = true
	}
	return moved
}

duo_settle :: proc(d: ^Duo) {
	for _ in 0 ..< 4000 {
		if !duo_io(d) {
			return
		}
	}
	panic("the link never went quiet")
}

duo_wake :: proc(d: ^Duo) -> (at: Time, ok: bool) {
	for i in 0 ..< d.n {
		p := &d.peers[i]
		if !p.started {
			continue
		}
		if t, k := session_next_wakeup(&p.c, d.now); k && (!ok || t < at) {
			at, ok = t, true
		}
	}
	for i in 0 ..< len(d.slots) {
		sl := &d.slots[i]
		if !sl.used {
			continue
		}
		if t, k := session_next_wakeup(&sl.s, d.now); k && (!ok || t < at) {
			at, ok = t, true
		}
		if sl.pend_sent && !sl.asked && (!ok || sl.pend_at < at) {
			at, ok = sl.pend_at, true
		}
	}
	return
}

duo_tick_all :: proc(d: ^Duo) {
	for i in 0 ..< d.n {
		if d.peers[i].started {
			session_tick(&d.peers[i].c, d.now)
		}
	}
	for i in 0 ..< len(d.slots) {
		if d.slots[i].used {
			session_tick(&d.slots[i].s, d.now)
		}
	}
}

duo_advance :: proc(d: ^Duo, limit: Time) -> bool {
	at, ok := duo_wake(d)
	if !ok || at > limit {
		return false
	}
	d.now = max(at, d.now)
	duo_tick_all(d)
	return true
}

Duo_Goal :: #type proc(d: ^Duo) -> bool

duo_run :: proc(d: ^Duo, goal: Duo_Goal, span: Time) -> bool {
	limit := d.now + span
	steps := 0
	for {
		duo_settle(d)
		if goal(d) {
			return true
		}
		steps += 1
		if steps > 200000 {
			panic("the clock does not move")
		}
		before := d.now
		if !duo_advance(d, limit) {
			duo_settle(d)
			return goal(d)
		}
		if d.now == before {
			d.now += time.Millisecond
		}
	}
}

duo_idle :: proc(d: ^Duo, span: Time) {
	end := d.now + span
	for {
		duo_settle(d)
		before := d.now
		if !duo_advance(d, end) {
			break
		}
		if d.now == before {
			d.now += time.Millisecond
		}
	}
	d.now = max(d.now, end)
	duo_tick_all(d)
	duo_settle(d)
}

// ----------------------------------------------------------------- goals

duo_all_up :: proc(d: ^Duo) -> bool {
	for i in 0 ..< d.n {
		if d.peers[i].c.state != .Up {
			return false
		}
		sl := d.peers[i].slot
		if sl < 0 || d.slots[sl].s.state != .Up {
			return false
		}
	}
	return true
}

duo_c0_done :: proc(d: ^Duo) -> bool {
	return d.peers[0].c.state == .Failed || d.peers[0].c.state == .Closed
}

duo_s0_done :: proc(d: ^Duo) -> bool {
	sl := d.peers[0].slot
	return sl >= 0 && (d.slots[sl].s.state == .Failed || d.slots[sl].s.state == .Closed)
}

duo_both_done :: proc(d: ^Duo) -> bool {
	return duo_c0_done(d) && duo_s0_done(d)
}

duo_srv :: proc(d: ^Duo, peer := 0) -> ^Session {
	sl := d.peers[peer].slot
	if sl < 0 {
		return nil
	}
	return &d.slots[sl].s
}

duo_slot :: proc(d: ^Duo, peer := 0) -> ^Duo_Slot {
	sl := d.peers[peer].slot
	if sl < 0 {
		return nil
	}
	return &d.slots[sl]
}

duo_has :: proc(evs: []Event, n: int, kind: Event_Kind) -> bool {
	for i in 0 ..< n {
		if evs[i].kind == kind {
			return true
		}
	}
	return false
}

duo_count :: proc(evs: []Event, n: int, kind: Event_Kind) -> (c: int) {
	for i in 0 ..< n {
		if evs[i].kind == kind {
			c += 1
		}
	}
	return
}

duo_last :: proc(evs: []Event, n: int, kind: Event_Kind) -> (ev: Event, ok: bool) {
	for i := n - 1; i >= 0; i -= 1 {
		if evs[i].kind == kind {
			return evs[i], true
		}
	}
	return
}

// ------------------------------------------------------------------ traffic

// Sends `count` tunnel packets from client `peer` and checks that the echoes
// of the server come back unchanged. Returns how many matched.
duo_echo :: proc(d: ^Duo, peer: int, count: int, payload: int) -> int {
	p := &d.peers[peer]
	p.tunnel_n = 0
	for i in 0 ..< count {
		buf: [LINK_BUF_SIZE]u8
		n := make_ip_packet(buf[TUNNEL_HEADROOM:], payload, u16(i))
		pkt, err := session_encap(&p.c, buf[:], n, d.now)
		if err != .None {
			break
		}
		if d.transport == .Tcp {
			duo_stream_add(p.up[:], &p.up_n, pkt)
		} else {
			p.c2s_pkts += 1
			duo_impair(d, &p.c2s, pkt, &p.kill_c2s, p.loss_c2s, p.dup_c2s, p.swap_c2s)
		}
		duo_settle(d)
	}
	duo_settle(d)
	ok := 0
	for i in 0 ..< p.tunnel_n {
		want: [LINK_BUF_SIZE]u8
		n := make_ip_packet(want[:], payload, u16(i))
		got := p.tunnel[i]
		if got.n == n && string(got.b[:n]) == string(want[:n]) {
			ok += 1
		}
	}
	return ok
}

duo_dump :: proc(d: ^Duo) {
	fmt.eprintfln("now=%v replies=%d drops=%v stray=%d", d.now, d.replies, d.drops, d.stray)
	for i in 0 ..< d.n {
		p := &d.peers[i]
		fmt.eprintfln(
			"client %d: state=%v ks=%v id=%d fail=%v km_sent=%v km_got=%v push_done=%v c2s=%d s2c=%d",
			i,
			p.c.state,
			p.c.ks.state,
			p.c.ks.id,
			p.c.fail_reason,
			p.c.ks.km_sent,
			p.c.ks.km_got,
			p.c.ks.push_done,
			p.c2s_pkts,
			p.s2c_pkts,
		)
		fmt.eprintfln("  counters=%v", p.c.counters)
		for k in 0 ..< p.ev_n {
			e := &p.ev[k]
			fmt.eprintfln("  event %v reason=%v key=%d text=%q", e.kind, e.reason, e.key_id, event_text(e))
		}
		sl := p.slot
		if sl < 0 {
			fmt.eprintfln("  no server session")
			continue
		}
		s := &d.slots[sl]
		fmt.eprintfln(
			"server %d: state=%v ks=%v id=%d auth=%v fail=%v km_sent=%v km_got=%v tls_ok=%v push_sent=%v",
			i,
			s.s.state,
			s.s.ks.state,
			s.s.ks.id,
			s.s.ks.auth,
			s.s.fail_reason,
			s.s.ks.km_sent,
			s.s.ks.km_got,
			s.s.ks.tls_ok,
			s.s.srv.push_sent,
		)
		fmt.eprintfln("  counters=%v", s.s.counters)
		for k in 0 ..< s.ev_n {
			e := &s.ev[k]
			fmt.eprintfln("  event %v reason=%v key=%d text=%q", e.kind, e.reason, e.key_id, event_text(e))
		}
	}
}
