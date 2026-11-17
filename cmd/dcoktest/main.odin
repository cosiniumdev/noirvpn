// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// dcoktest: an internal test tool for the kernel `ovpn` backend (platform/dco).
// It runs on two hosts without the daemon: both get the same secret, create the
// device and a peer, install mirrored keys; the operator pings and runs iperf3
// across.
//
// The two ends also talk on the transport, with control records that the kernel
// passes up (opcode 4): echo, and the steps of a rekey and of a float. A TCP run
// connects, exchanges records, hands the connection over with read-ahead bytes,
// then sends control records both ways while data flows.
//
// `--userspace` runs a peer without a device: it seals and opens data packets
// with the daemon's data channel code (proto/crypt), so the kernel on the other
// host proves the packet and key layout.
package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/linux"
import "core:time"
import "noir:platform/dco"
import "noir:platform/netlink"
import "noir:platform/sysnet"

Cfg :: struct {
	client:     bool,
	mp:         bool,
	dev:        string,
	tcp:        bool,
	local:      [4]u8,
	lport:      u16,
	remote:     [4]u8,
	rport:      u16,
	vpn:        [4]u8,
	vpn_plen:   u8,
	peer_vpn:   [4]u8,
	vpn6:       Maybe([16]u8),
	peer_vpn6:  Maybe([16]u8),
	cipher:     dco.Cipher,
	key_len:    int,
	secret:     string,
	peer_id:    u32,
	ka_int:     u32,
	ka_to:      u32,
	duration:   int,
	stats_secs: int,
	rekey_secs: int,
	float_after: int,
	echo_secs:  int,
	userspace:  bool,
	ping_count: int,
	udp_gro:    bool,
	tcp_ahead:  bool,
	probe:      bool,
	second:     bool,
	errors:     bool,
	burst:      int,
	bad_swap:   int,
}

start: time.Tick

// Has the time `t` come?
due :: proc(now, t: time.Tick) -> bool {
	return time.tick_diff(t, now) >= 0
}

say :: proc(format: string, args: ..any) {
	ms := time.duration_milliseconds(time.tick_since(start))
	fmt.printf("[%7.3f] ", ms / 1000)
	fmt.printfln(format, ..args)
}

die :: proc(format: string, args: ..any) -> ! {
	fmt.eprintf("dcoktest: ")
	fmt.eprintfln(format, ..args)
	os.exit(2)
}

usage :: proc() {
	fmt.eprintln(`usage: dcoktest --role client|server --local IP:PORT --remote IP:PORT --vpn IP/LEN --peer-vpn IP --secret TEXT [options]
  --mode p2p|mp          device mode (default: client p2p, server mp)
  --dev NAME             device name (default nvk0)
  --transport udp|tcp    (tcp: the server listens on --local, the client connects)
  --cipher aes128|aes192|aes256|chacha   (default aes256)
  --peer-id N            (default 5)
  --keepalive INT,TO     seconds, 0,0 off (default 5,20)
  --vpn6 ADDR/LEN --peer-vpn6 ADDR   also an IPv6 tunnel address
  --duration SECS        stop after this long (default: until a signal)
  --stats SECS           print the peer counters every SECS
  --echo SECS            send an echo control record every SECS
  --rekey SECS           (client) rekey every SECS: KEY_NEW secondary, SWAP, DEL
  --float-after SECS     (udp) rebind to local port + 1 after SECS
  --udp-gro              turn UDP_GRO on for the data socket before PEER_NEW
  --no-ahead             tcp: hand over with nothing read ahead
  --second-peer          (udp) a second peer: id + 1, remote port + 2, tunnel address + 1, no fd passed
  --probe-errors         (udp) after the setup, send requests the kernel refuses and print its error texts
  --burst N              (client) after 3 s send N echo records of 1400 bytes at once
  --bad-swap SECS        after SECS, KEY_SWAP with an empty secondary slot (shows what the kernel does)
  --probe-tcp            tcp: the server reads the stream itself and prints what the kernel gives
  --userspace            a peer with no device (interop with the kernel on the other host)
  --ping-count N         userspace: ICMP echo requests to send to --peer-vpn`)
	os.exit(2)
}

parse_hostport :: proc(s: string) -> (ip: [4]u8, port: u16, ok: bool) {
	i := strings.last_index_byte(s, ':')
	if i < 0 {
		return
	}
	p, pok := strconv.parse_int(s[i + 1:], 10)
	if !pok || p < 0 || p > 65535 {
		return
	}
	ip, ok = parse_ip4(s[:i])
	return ip, u16(p), ok
}

parse_ip4 :: proc(s: string) -> (ip: [4]u8, ok: bool) {
	parts := strings.split(s, ".", context.temp_allocator)
	if len(parts) != 4 {
		return
	}
	for p, i in parts {
		v, vok := strconv.parse_int(p, 10)
		if !vok || v < 0 || v > 255 {
			return
		}
		ip[i] = u8(v)
	}
	return ip, true
}

parse_ip6 :: proc(s: string) -> (ip: [16]u8, ok: bool) {
	// Only the forms this tool needs: eight groups, or one "::" in the middle.
	halves := strings.split(s, "::", context.temp_allocator)
	if len(halves) > 2 {
		return
	}
	groups :: proc(t: string, out: ^[dynamic]u16) -> bool {
		if t == "" {
			return true
		}
		for g in strings.split(t, ":", context.temp_allocator) {
			v, vok := strconv.parse_int(g, 16)
			if !vok || v < 0 || v > 0xffff {
				return false
			}
			append(out, u16(v))
		}
		return true
	}
	head, tail: [dynamic]u16
	head.allocator = context.temp_allocator
	tail.allocator = context.temp_allocator
	if !groups(halves[0], &head) {
		return
	}
	if len(halves) == 2 && !groups(halves[1], &tail) {
		return
	}
	if (len(halves) == 1 && len(head) != 8) || len(head) + len(tail) > 8 {
		return
	}
	all: [8]u16
	for g, i in head {
		all[i] = g
	}
	for g, i in tail {
		all[8 - len(tail) + i] = g
	}
	for g, i in all {
		ip[2 * i] = u8(g >> 8)
		ip[2 * i + 1] = u8(g)
	}
	return ip, true
}

parse_cfg :: proc(args: []string) -> (c: Cfg) {
	c.dev = "nvk0"
	c.cipher = .Aes_Gcm
	c.key_len = 32
	c.peer_id = 5
	c.ka_int = 5
	c.ka_to = 20
	c.vpn_plen = 24
	role_set, mode_set := false, false
	local_set, remote_set, vpn_set, peer_set := false, false, false, false
	i := 0
	next :: proc(args: []string, i: ^int) -> string {
		i^ += 1
		if i^ >= len(args) {
			usage()
		}
		return args[i^]
	}
	for i < len(args) {
		a := args[i]
		switch a {
		case "--role":
			v := next(args, &i)
			c.client = v == "client"
			if v != "client" && v != "server" {
				usage()
			}
			role_set = true
		case "--mode":
			v := next(args, &i)
			c.mp = v == "mp"
			if v != "mp" && v != "p2p" {
				usage()
			}
			mode_set = true
		case "--dev":
			c.dev = next(args, &i)
		case "--transport":
			v := next(args, &i)
			c.tcp = v == "tcp"
			if v != "tcp" && v != "udp" {
				usage()
			}
		case "--local":
			ok: bool
			c.local, c.lport, ok = parse_hostport(next(args, &i))
			if !ok {
				die("bad --local")
			}
			local_set = true
		case "--remote":
			ok: bool
			c.remote, c.rport, ok = parse_hostport(next(args, &i))
			if !ok {
				die("bad --remote")
			}
			remote_set = true
		case "--vpn":
			v := next(args, &i)
			s := strings.split(v, "/", context.temp_allocator)
			ok: bool
			c.vpn, ok = parse_ip4(s[0])
			if !ok || len(s) != 2 {
				die("bad --vpn")
			}
			p, pok := strconv.parse_int(s[1], 10)
			if !pok || p < 1 || p > 32 {
				die("bad --vpn length")
			}
			c.vpn_plen = u8(p)
			vpn_set = true
		case "--peer-vpn":
			ok: bool
			c.peer_vpn, ok = parse_ip4(next(args, &i))
			if !ok {
				die("bad --peer-vpn")
			}
			peer_set = true
		case "--vpn6":
			v := next(args, &i)
			s := strings.split(v, "/", context.temp_allocator)
			ip, ok := parse_ip6(s[0])
			if !ok || len(s) != 2 {
				die("bad --vpn6")
			}
			c.vpn6 = ip
		case "--peer-vpn6":
			ip, ok := parse_ip6(next(args, &i))
			if !ok {
				die("bad --peer-vpn6")
			}
			c.peer_vpn6 = ip
		case "--cipher":
			switch next(args, &i) {
			case "aes128":
				c.cipher, c.key_len = .Aes_Gcm, 16
			case "aes192":
				c.cipher, c.key_len = .Aes_Gcm, 24
			case "aes256":
				c.cipher, c.key_len = .Aes_Gcm, 32
			case "chacha":
				c.cipher, c.key_len = .Chacha20_Poly1305, 32
			case:
				usage()
			}
		case "--secret":
			c.secret = next(args, &i)
		case "--peer-id":
			v, ok := strconv.parse_int(next(args, &i), 10)
			if !ok || v < 0 || v > dco.PEER_ID_LIMIT {
				die("bad --peer-id")
			}
			c.peer_id = u32(v)
		case "--keepalive":
			s := strings.split(next(args, &i), ",", context.temp_allocator)
			if len(s) != 2 {
				usage()
			}
			x, xok := strconv.parse_int(s[0], 10)
			y, yok := strconv.parse_int(s[1], 10)
			if !xok || !yok {
				usage()
			}
			c.ka_int, c.ka_to = u32(x), u32(y)
		case "--duration":
			c.duration, _ = strconv.parse_int(next(args, &i), 10)
		case "--stats":
			c.stats_secs, _ = strconv.parse_int(next(args, &i), 10)
		case "--rekey":
			c.rekey_secs, _ = strconv.parse_int(next(args, &i), 10)
		case "--float-after":
			c.float_after, _ = strconv.parse_int(next(args, &i), 10)
		case "--echo":
			c.echo_secs, _ = strconv.parse_int(next(args, &i), 10)
		case "--ping-count":
			c.ping_count, _ = strconv.parse_int(next(args, &i), 10)
		case "--udp-gro":
			c.udp_gro = true
		case "--no-ahead":
			c.tcp_ahead = true
		case "--second-peer":
			c.second = true
		case "--bad-swap":
			c.bad_swap, _ = strconv.parse_int(next(args, &i), 10)
		case "--burst":
			c.burst, _ = strconv.parse_int(next(args, &i), 10)
		case "--probe-errors":
			c.errors = true
		case "--probe-tcp":
			c.probe = true
		case "--userspace":
			c.userspace = true
		case:
			usage()
		}
		i += 1
	}
	if !role_set || !local_set || !remote_set || !peer_set || c.secret == "" || (!vpn_set && !c.userspace) {
		usage()
	}
	if !mode_set {
		c.mp = !c.client
	}
	return
}

main :: proc() {
	start = time.tick_now()
	cfg := parse_cfg(os.args[1:])
	if cfg.userspace {
		os.exit(run_userspace(&cfg))
	}
	os.exit(run_kernel(&cfg))
}

// ------------------------------------------------------------------- keys

// The key of key id `kid` for this end: the client sends with the "cs" half.
// Both ends derive the same bytes from the secret.
derive_key :: proc(c: ^Cfg, kid: u32, slot: dco.Key_Slot) -> (k: dco.New_Key) {
	k.peer_id = c.peer_id
	k.slot = u32(slot)
	k.key_id = kid
	k.cipher = u32(c.cipher)
	k.key_len = u32(c.key_len)
	cs := hash4(c.secret, "cs", kid, c.cipher)
	sc := hash4(c.secret, "sc", kid, c.cipher)
	ncs := hash4(c.secret, "ncs", kid, c.cipher)
	nsc := hash4(c.secret, "nsc", kid, c.cipher)
	enc, dec := cs, sc
	nenc, ndec := ncs, nsc
	if !c.client {
		enc, dec = sc, cs
		nenc, ndec = nsc, ncs
	}
	copy(k.enc_key[:c.key_len], enc[:c.key_len])
	copy(k.dec_key[:c.key_len], dec[:c.key_len])
	copy(k.enc_nonce[:], nenc[:8])
	copy(k.dec_nonce[:], ndec[:8])
	return
}

// ------------------------------------------------------------ the transport

// The control records of the tool: the first byte is a control opcode (4), so the
// kernel hands them to user space.
CTRL_OP :: 0x20

Kind :: enum u8 {
	Echo        = 'E',
	Echo_Reply  = 'e',
	Key         = 'K', // install key as secondary
	Key_Ok      = 'k',
	Swap        = 'S',
	Swap_Ok     = 's',
	Del         = 'D', // delete the secondary slot
	Float       = 'F', // the sender rebinds: install this key as secondary, the old one stays
	Float_Ok    = 'f',
	Pre         = 'P',
	Ahead_Ctrl  = 'A',
	Ahead_Big   = 'B',
	Go          = 'G',
}

App :: struct {
	cfg:      ^Cfg,
	k:        dco.Kernel,
	be:       dco.Backend,
	ifindex:  u32,
	udp:      linux.Fd, // the data socket (udp), -1
	probe_fd: linux.Fd, // tcp --probe-tcp: our own copy of the stream, -1
	tcp:      linux.Fd, // the stream before the handover, -1
	dst:      [4]u8, // where control records go (udp)
	dport:    u16,
	cur_kid:  u32,
	sig:      linux.Fd,
	stop:     bool,
	// echo
	echo_seq:   u32,
	echo_sent:  int,
	echo_back:  int,
	echo_got:   int,
	// rekey (initiator)
	rekey_kid:  u32,
	rekey_step: int, // 0 idle, 1 waiting for Key_Ok, 2 waiting for Swap_Ok, 3 waiting to delete
	rekey_at:   time.Tick,
	rekeys:     int,
	// float
	float_kid:  u32, // responder: the key that the floating peer will send with (valid when float_wait)
	float_old:  u32,
	float_wait: bool,
	floats:     int,
	prev:       dco.Peer_Stats,
	ctrl_rx:    int,
	ctrl_bad:   int,
}

// Sends one control record (the kind and a number) on the transport.
send_ctrl :: proc(a: ^App, kind: Kind, n: u32, extra: []u8 = nil) -> int {
	rec := make([dynamic]u8, 0, 16 + len(extra), context.temp_allocator)
	append(&rec, CTRL_OP, u8(kind), u8(n >> 24), u8(n >> 16), u8(n >> 8), u8(n))
	append(&rec, ..extra)
	if a.cfg.tcp {
		return a.be.ctrl_tx(a.be.user, a.cfg.peer_id, rec[:])
	}
	addr := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(a.dport),
		sin_addr   = a.dst,
	}
	_, e := linux.sendto(a.udp, rec[:], {}, &addr)
	return -int(e)
}

open_signals :: proc() -> linux.Fd {
	mask: u64
	for sig in ([]int{2, 15}) {
		mask |= u64(1) << u64(sig - 1)
	}
	linux.syscall(linux.SYS_rt_sigprocmask, int(0), &mask, rawptr(nil), 8)
	r := linux.syscall(linux.SYS_signalfd4, int(-1), &mask, 8, int(0o4000 | 0o2000000))
	if r < 0 {
		return -1
	}
	return linux.Fd(r)
}

// ----------------------------------------------------------------- kernel run

run_kernel :: proc(c: ^Cfg) -> int {
	a := new(App)
	a.cfg = c
	a.udp = -1
	a.tcp = -1
	a.probe_fd = -1
	a.dst = c.remote
	a.dport = c.rport
	a.sig = open_signals()

	st := dco.kernel_connect(&a.k, proc(user: rawptr, level: dco.Log_Level, text: string) {
			say("dco log (%v): %s", level, text)
		})
	if st == dco.ENO_OVPN {
		say("the kernel has no ovpn family (module not loaded)")
		return 1
	}
	if st != 0 {
		say("kernel_connect: %s", dco.status_text(st))
		return 1
	}
	a.be = dco.kernel_backend(&a.k)
	defer {
		a.be.close(a.be.user)
		dco.kernel_disconnect(&a.k)
	}

	mode := dco.Mode.Mp if c.mp else dco.Mode.P2p
	idx, ost := a.be.open(a.be.user, c.dev, mode, 0)
	if ost != 0 {
		say("open %s: %s (%s)", c.dev, dco.status_text(ost), a.be.err_text(a.be.user))
		return 1
	}
	a.ifindex = idx
	say("device %s ifindex %d mode %v", c.dev, idx, mode)

	np := dco.New_Peer {
		peer_id = c.peer_id,
		flags   = dco.PEER_REMOTE | dco.PEER_LOCAL | dco.PEER_VPN4,
		remote  = dco.sockaddr_v4(c.remote, c.rport),
		local   = dco.sockaddr_v4(c.local, c.lport),
		vpn4    = c.peer_vpn,
	}
	if v, ok := c.peer_vpn6.?; ok {
		np.flags |= dco.PEER_VPN6
		np.vpn6 = v
	}

	if c.tcp {
		if !tcp_start(a, &np) {
			return 1
		}
	} else {
		fd := udp_bind(c.local, c.lport, c.udp_gro)
		if fd < 0 {
			return 1
		}
		a.udp = fd
		st = a.be.new_peer(a.be.user, &np, i32(fd))
		if st != 0 {
			say("new_peer: %s (%s)", dco.status_text(st), a.be.err_text(a.be.user))
			return 1
		}
		say("peer %d: remote %v:%d", c.peer_id, c.remote, c.rport)
	}

	k0 := derive_key(c, 0, .Primary)
	if st = a.be.new_key(a.be.user, &k0); st != 0 {
		say("new_key: %s (%s)", dco.status_text(st), a.be.err_text(a.be.user))
		return 1
	}
	if c.second && !c.tcp {
		np2 := np
		np2.peer_id = c.peer_id + 1
		np2.remote = dco.sockaddr_v4(c.remote, c.rport + 2)
		np2.vpn4[3] += 1
		st = a.be.new_peer(a.be.user, &np2, -1)
		say("second peer %d (no fd passed, remote port %d): %s (%s)", np2.peer_id, c.rport + 2, dco.status_text(st), a.be.err_text(a.be.user))
		if st != 0 {
			return 1
		}
		k2 := derive_key(c, 0, .Primary)
		k2.peer_id = np2.peer_id
		st = a.be.new_key(a.be.user, &k2)
		say("second peer new_key: %s", dco.status_text(st))
		sp2 := dco.Set_Peer{peer_id = np2.peer_id, keepalive_interval = 0, keepalive_timeout = 0}
		a.be.set_peer(a.be.user, &sp2)
	}
	sp := dco.Set_Peer {
		peer_id            = c.peer_id,
		keepalive_interval = c.ka_int,
		keepalive_timeout  = c.ka_to,
		mss                = 1300,
	}
	if st = a.be.set_peer(a.be.user, &sp); st != 0 {
		say("set_peer: %s (%s)", dco.status_text(st), a.be.err_text(a.be.user))
		return 1
	}
	say("keys installed (%v, %d byte key), keepalive %d/%d s, mss clamp applied: %v", c.cipher, c.key_len, c.ka_int, c.ka_to, a.be.mss_clamp)

	if !configure_link(a) {
		return 1
	}
	say("ready: vpn %v/%d peer %v. Waiting.", c.vpn, c.vpn_plen, c.peer_vpn)
	if c.probe && c.tcp {
		probe_tcp(a)
	}
	if c.errors && !c.tcp {
		probe_errors(a)
		return 0
	}
	loop(a)
	final_report(a)
	return 0
}

udp_bind :: proc(ip: [4]u8, port: u16, gro: bool) -> linux.Fd {
	fd, e := linux.socket(.INET, .DGRAM, {.CLOEXEC}, .UDP)
	if e != .NONE {
		say("socket: %v", e)
		return -1
	}
	one: i32 = 1
	linux.setsockopt_base(fd, 1, 2, &one) // SO_REUSEADDR
	if gro {
		if ge := linux.setsockopt_base(fd, 17, 104, &one); ge != .NONE { // SOL_UDP, UDP_GRO
			say("UDP_GRO: %v", ge)
		} else {
			say("UDP_GRO is on for the data socket")
		}
	}
	addr := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(port),
		sin_addr   = ip,
	}
	if be := linux.bind(fd, &addr); be != .NONE {
		say("bind %v:%d: %v", ip, port, be)
		linux.close(fd)
		return -1
	}
	return fd
}

configure_link :: proc(a: ^App) -> bool {
	c := a.cfg
	sc, serr := sysnet.open()
	if serr != .None {
		say("sysnet.open: %v", serr)
		return false
	}
	defer sysnet.close(&sc)
	if err := sysnet.addr_add(&sc, a.ifindex, sysnet.IP4_Address(c.vpn), c.vpn_plen); err != .None {
		say("addr_add: %v %s", err, sysnet.last_error_text(&sc))
		return false
	}
	if v, ok := c.vpn6.?; ok {
		if err := sysnet.addr_add(&sc, a.ifindex, sysnet.IP6_Address(transmute([8]u16be)v), 64); err != .None {
			say("addr_add v6: %v %s", err, sysnet.last_error_text(&sc))
			return false
		}
	}
	if err := sysnet.link_set_up(&sc, a.ifindex); err != .None {
		say("link_set_up: %v", err)
		return false
	}
	return true
}

// -------------------------------------------------------------------- loop

loop :: proc(a: ^App) {
	c := a.cfg
	now := time.tick_now()
	end := time.tick_add(now, time.Duration(c.duration) * time.Second) if c.duration > 0 else time.Tick{}
	next_stats := time.tick_add(now, time.Duration(max(c.stats_secs, 1)) * time.Second)
	next_echo := time.tick_add(now, time.Duration(max(c.echo_secs, 1)) * time.Second)
	next_rekey := time.tick_add(now, time.Duration(max(c.rekey_secs, 1)) * time.Second)
	float_at := time.tick_add(now, time.Duration(max(c.float_after, 1)) * time.Second)
	floated := false
	a.prev = {}
	// The stats of a peer that may float are read once a second: that is how a float is seen.
	next_poll := time.tick_add(now, time.Second)
	burst_at := time.tick_add(now, 3 * time.Second)
	burst_done := c.burst == 0
	swap_at := time.tick_add(now, time.Duration(max(c.bad_swap, 1)) * time.Second)
	swapped := c.bad_swap == 0

	for !a.stop {
		pfds: [3]linux.Poll_Fd
		n := 0
		pfds[n] = {fd = a.sig, events = {.IN}}
		n += 1
		pfds[n] = {fd = linux.Fd(a.be.fd), events = {.IN}}
		n += 1
		if a.udp >= 0 {
			pfds[n] = {fd = a.udp, events = {.IN}}
			n += 1
		}
		linux.poll(pfds[:n], 100)
		if .IN in pfds[0].revents {
			say("signal: stopping")
			break
		}
		if a.udp >= 0 && .IN in pfds[2].revents {
			udp_ctrl(a)
		}
		drain_events(a)

		now = time.tick_now()
		if c.duration > 0 && due(now, end) {
			say("duration over")
			break
		}
		if due(now, next_poll) {
			next_poll = time.tick_add(now, time.Second)
			if !c.tcp {
				var: dco.Peer_Stats
				if st := a.be.stats(a.be.user, c.peer_id, &var); st != 0 && st != dco.ENOENT {
					say("stats: %s", dco.status_text(st))
				}
				drain_events(a)
			}
		}
		if !swapped && due(now, swap_at) {
			swapped = true
			st := a.be.swap_keys(a.be.user, c.peer_id)
			say("bad swap: KEY_SWAP with an empty secondary slot: %s", dco.status_text(st))
			k := dco.Key_Slot.Primary
			ki, kst := dco.kernel_key_slot_info(&a.k, c.peer_id, k)
			say("bad swap: KEY_GET primary: key id %d, cipher %d, %s", ki.key_id, ki.cipher, dco.status_text(kst))
			ki, kst = dco.kernel_key_slot_info(&a.k, c.peer_id, .Secondary)
			say("bad swap: KEY_GET secondary: key id %d, cipher %d, %s", ki.key_id, ki.cipher, dco.status_text(kst))
		}
		if !burst_done && due(now, burst_at) {
			burst_done = true
			fails := 0
			pad := make([]u8, 1400)
			defer delete(pad)
			for _ in 0 ..< c.burst {
				a.echo_seq += 1
				if st := send_ctrl(a, .Echo, a.echo_seq, pad); st != 0 {
					fails += 1
					if fails == 1 {
						say("burst: send failed: %s", dco.status_text(st))
					}
				} else {
					a.echo_sent += 1
				}
			}
			say("burst: %d records sent, %d failed; control records that waited for the socket: %d", c.burst, fails, a.k.tx_waits)
		}
		if c.stats_secs > 0 && due(now, next_stats) {
			next_stats = time.tick_add(now, time.Duration(c.stats_secs) * time.Second)
			print_stats(a, false)
		}
		if c.echo_secs > 0 && due(now, next_echo) {
			next_echo = time.tick_add(now, time.Duration(c.echo_secs) * time.Second)
			a.echo_seq += 1
			if st := send_ctrl(a, .Echo, a.echo_seq); st != 0 {
				say("echo send: %s", dco.status_text(st))
			} else {
				a.echo_sent += 1
			}
		}
		if c.client && c.rekey_secs > 0 && a.rekey_step == 0 && due(now, next_rekey) {
			next_rekey = time.tick_add(now, time.Duration(c.rekey_secs) * time.Second)
			rekey_start(a)
		}
		if a.rekey_step == 3 && due(now, a.rekey_at) {
			rekey_finish(a)
		}
		if c.float_after > 0 && !floated && !c.tcp && due(now, float_at) {
			floated = true
			do_float(a)
		}
	}
}

drain_events :: proc(a: ^App) {
	for _ in 0 ..< 256 {
		ev: dco.Event
		r := a.be.next_event(a.be.user, &ev)
		if r == 0 {
			return
		}
		if r < 0 {
			say("next_event: %s", dco.status_text(r))
			a.stop = true
			return
		}
		switch ev.kind {
		case .Ctrl_Rx:
			on_ctrl(a, a.be.ctrl_record(a.be.user))
		case .Peer_Del:
			say("EVENT Peer_Del peer %d reason %v", ev.peer_id, ev.reason)
			a.stop = true
		case .Peer_Float:
			fam, ip, port, _ := dco.sockaddr_parse(&ev.addr)
			say("EVENT Peer_Float peer %d now at family %d %v:%d", ev.peer_id, fam, ip[:4], port)
			a.floats += 1
			a.dst = {ip[0], ip[1], ip[2], ip[3]}
			a.dport = port
			if a.float_wait {
				float_swap(a)
			}
		case .Key_Swap:
			say("EVENT Key_Swap peer %d key %d", ev.peer_id, ev.key_id)
		}
	}
}

udp_ctrl :: proc(a: ^App) {
	buf: [2048]u8
	for _ in 0 ..< 32 {
		src: linux.Sock_Addr_In
		n, e := linux.recvfrom(a.udp, buf[:], {.DONTWAIT}, &src)
		if e != .NONE || n <= 0 {
			return
		}
		a.dst = src.sin_addr
		a.dport = u16(src.sin_port)
		on_ctrl(a, buf[:n])
	}
}

// ------------------------------------------------------- the control records

on_ctrl :: proc(a: ^App, rec: []u8) {
	if len(rec) < 6 || rec[0] != CTRL_OP {
		a.ctrl_bad += 1
		say("unexpected control record, %d bytes, first byte %#x", len(rec), rec[0] if len(rec) > 0 else 0)
		return
	}
	a.ctrl_rx += 1
	kind := Kind(rec[1])
	n := u32(rec[2]) << 24 | u32(rec[3]) << 16 | u32(rec[4]) << 8 | u32(rec[5])
	c := a.cfg
	switch kind {
	case .Echo:
		a.echo_got += 1
		send_ctrl(a, .Echo_Reply, n)
	case .Echo_Reply:
		a.echo_back += 1
	case .Key:
		k := derive_key(c, n, .Secondary)
		st := a.be.new_key(a.be.user, &k)
		say("rekey: KEY_NEW secondary key %d: %s", n, dco.status_text(st))
		send_ctrl(a, .Key_Ok, n)
	case .Key_Ok:
		if a.rekey_step == 1 && n == a.rekey_kid {
			st := a.be.swap_keys(a.be.user, c.peer_id)
			say("rekey: KEY_SWAP (sending with key %d): %s", n, dco.status_text(st))
			a.cur_kid = n
			a.rekey_step = 2
			send_ctrl(a, .Swap, n)
		}
	case .Swap:
		st := a.be.swap_keys(a.be.user, c.peer_id)
		say("rekey: KEY_SWAP on request (sending with key %d): %s", n, dco.status_text(st))
		a.cur_kid = n
		send_ctrl(a, .Swap_Ok, n)
	case .Swap_Ok:
		if a.rekey_step == 2 {
			// A second of grace: packets of the old key may still be on the way.
			a.rekey_step = 3
			a.rekey_at = time.tick_add(time.tick_now(), time.Second)
		}
	case .Del:
		st := a.be.del_key(a.be.user, c.peer_id, .Secondary)
		say("rekey: KEY_DEL secondary on request: %s", dco.status_text(st))
	case .Float:
		// The sender rebinds and sends with key `n`; its old key is `rec[6]`.
		a.float_kid = n
		a.float_old = u32(rec[6]) if len(rec) > 6 else 0
		k := derive_key(c, n, .Secondary)
		st := a.be.new_key(a.be.user, &k)
		say("float: the peer rebinds; KEY_NEW secondary key %d: %s", n, dco.status_text(st))
		a.float_wait = true
		send_ctrl(a, .Float_Ok, n)
	case .Float_Ok:
		say("float: the peer has key %d", n)
	case .Pre, .Ahead_Ctrl, .Ahead_Big, .Go:
		say("control record %c in the stream", rune(rec[1]))
	}
}

rekey_start :: proc(a: ^App) {
	a.rekey_kid = (a.cur_kid + 1) & 7
	k := derive_key(a.cfg, a.rekey_kid, .Secondary)
	st := a.be.new_key(a.be.user, &k)
	say("rekey: KEY_NEW secondary key %d: %s", a.rekey_kid, dco.status_text(st))
	if st != 0 {
		return
	}
	a.rekey_step = 1
	send_ctrl(a, .Key, a.rekey_kid)
}

rekey_finish :: proc(a: ^App) {
	st := a.be.del_key(a.be.user, a.cfg.peer_id, .Secondary)
	say("rekey: KEY_DEL secondary: %s", dco.status_text(st))
	send_ctrl(a, .Del, 0)
	a.rekey_step = 0
	a.rekeys += 1
}

// The responder of a float: the peer's data arrived with the new key and from a new
// address. The new key sends from now on, the old one is dropped.
float_swap :: proc(a: ^App) {
	st := a.be.swap_keys(a.be.user, a.cfg.peer_id)
	say("float: KEY_SWAP (sending with key %d): %s", a.float_kid, dco.status_text(st))
	a.cur_kid = a.float_kid
	st = a.be.del_key(a.be.user, a.cfg.peer_id, .Secondary)
	say("float: KEY_DEL secondary: %s", dco.status_text(st))
	a.float_wait = false
}

// This end rebinds: a new socket on the next port, the peer created again on it, the new key
// as primary and the old one as secondary, then the other end is told.
do_float :: proc(a: ^App) {
	c := a.cfg
	nport := c.lport + 1
	say("float: rebinding to %v:%d", c.local, nport)
	fd := udp_bind(c.local, nport, false)
	if fd < 0 {
		return
	}
	if st := a.be.del_peer(a.be.user, c.peer_id); st != 0 {
		say("float: del_peer: %s", dco.status_text(st))
	}
	a.be.detach(a.be.user)
	linux.close(a.udp)
	a.udp = fd
	np := dco.New_Peer {
		peer_id = c.peer_id,
		flags   = dco.PEER_REMOTE | dco.PEER_LOCAL | dco.PEER_VPN4,
		remote  = dco.sockaddr_v4(c.remote, c.rport),
		local   = dco.sockaddr_v4(c.local, nport),
		vpn4    = c.peer_vpn,
	}
	if st := a.be.new_peer(a.be.user, &np, i32(fd)); st != 0 {
		say("float: new_peer: %s (%s)", dco.status_text(st), a.be.err_text(a.be.user))
		a.stop = true
		return
	}
	nk := (a.cur_kid + 1) & 7
	k := derive_key(c, nk, .Primary)
	st := a.be.new_key(a.be.user, &k)
	say("float: KEY_NEW primary key %d: %s", nk, dco.status_text(st))
	k = derive_key(c, a.cur_kid, .Secondary)
	st = a.be.new_key(a.be.user, &k)
	say("float: KEY_NEW secondary (old) key %d: %s", a.cur_kid, dco.status_text(st))
	sp := dco.Set_Peer {
		peer_id            = c.peer_id,
		keepalive_interval = c.ka_int,
		keepalive_timeout  = c.ka_to,
	}
	a.be.set_peer(a.be.user, &sp)
	old := a.cur_kid
	a.cur_kid = nk
	send_ctrl(a, .Float, nk, []u8{u8(old)})
}

// ------------------------------------------------------------------- reports

print_stats :: proc(a: ^App, total: bool) {
	ps: dco.Peer_Stats
	st := a.be.stats(a.be.user, a.cfg.peer_id, &ps)
	if st != 0 {
		say("stats: %s", dco.status_text(st))
		return
	}
	d := ps
	if !total {
		d.vpn_rx_bytes -= a.prev.vpn_rx_bytes
		d.vpn_tx_bytes -= a.prev.vpn_tx_bytes
		d.vpn_rx_packets -= a.prev.vpn_rx_packets
		d.vpn_tx_packets -= a.prev.vpn_tx_packets
		d.link_rx_bytes -= a.prev.link_rx_bytes
		d.link_tx_bytes -= a.prev.link_tx_bytes
		d.link_rx_packets -= a.prev.link_rx_packets
		d.link_tx_packets -= a.prev.link_tx_packets
	}
	say(
		"stats%s: vpn rx %d B %d pkt, tx %d B %d pkt; link rx %d B %d pkt, tx %d B %d pkt",
		"" if !total else " (total)",
		d.vpn_rx_bytes, d.vpn_rx_packets, d.vpn_tx_bytes, d.vpn_tx_packets,
		d.link_rx_bytes, d.link_rx_packets, d.link_tx_bytes, d.link_tx_packets,
	)
	a.prev = ps
}

final_report :: proc(a: ^App) {
	print_stats(a, true)
	say("summary: echo sent %d, replies %d, echo requests replied to %d, control records in %d (bad %d), rekeys %d, floats seen %d", a.echo_sent, a.echo_back, a.echo_got, a.ctrl_rx, a.ctrl_bad, a.rekeys, a.floats)
	if a.cfg.tcp {
		say("summary: data records dropped from the read-ahead bytes: %d, control records that waited for the socket: %d", a.k.ahead_data, a.k.tx_waits)
	}
}

// Requests that the kernel refuses, with the text it gives.
probe_errors :: proc(a: ^App) {
	c := a.cfg
	k := &a.k
	run :: proc(a: ^App, what: string, msg: []u8, err: netlink.Error) {
		if err != .None {
			say("probe: %s: could not build the message: %v", what, err)
			return
		}
		k := &a.k
		e := netlink.request(&k.gen, msg, k.rx)
		say("probe: %-52s -> %v errno %v text %q", what, e, k.gen.errno if e != .None else linux.Errno(0), netlink.ext_message(&k.gen))
	}
	buf: [512]u8
	seq :: proc(k: ^dco.Kernel) -> u32 {
		return netlink.next_seq(&k.gen)
	}
	good := dco.Peer_New_Args {
		id     = c.peer_id,
		sock   = i32(a.udp),
		mp     = c.mp,
		remote = dco.endpoint_v4(c.remote, c.rport),
		vpn4   = c.peer_vpn,
	}
	msg, err := dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, good)
	run(a, "PEER_NEW again, same id", msg, err)
	other := good
	other.id = 77
	other.remote = dco.endpoint_v4(c.remote, c.rport + 5)
	other.vpn4 = [4]u8{10, 209, 0, 99}
	other.mp = !c.mp
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, other)
	run(a, "PEER_NEW with the VPN address rule of the other mode", msg, err)
	other.mp = c.mp
	other.vpn4 = nil
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, other)
	run(a, "PEER_NEW with no VPN address", msg, err)
	other.vpn4 = [4]u8{10, 209, 0, 99}
	other.remote = {}
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, other)
	run(a, "PEER_NEW UDP with no remote", msg, err)
	other.remote = dco.endpoint_v4(c.remote, c.rport + 5)
	other.id = 0x1000000
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, other)
	run(a, "PEER_NEW with an id above 24 bits", msg, err)
	other.id = 78
	other.sock = 9999
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), a.ifindex, other)
	run(a, "PEER_NEW with a descriptor that is not open", msg, err)
	msg, err = dco.build_peer_id(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_PEER_GET, 4242)
	run(a, "PEER_GET of an unknown peer", msg, err)
	msg, err = dco.build_peer_id(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_PEER_DEL, 4242)
	run(a, "PEER_DEL of an unknown peer", msg, err)
	msg, err = dco.build_peer_set(buf[:], k.family, seq(k), a.ifindex, 4242, 5, 20)
	run(a, "PEER_SET of an unknown peer", msg, err)
	kk := derive_key(c, 3, .Secondary)
	kk.peer_id = 4242
	msg, err = dco.build_key_new(buf[:], k.family, seq(k), a.ifindex, &kk)
	run(a, "KEY_NEW for an unknown peer", msg, err)
	kk.peer_id = c.peer_id
	kk.key_id = 9
	msg, err = dco.build_key_new(buf[:], k.family, seq(k), a.ifindex, &kk)
	run(a, "KEY_NEW with key id 9", msg, err)
	kk.key_id = 3
	kk.key_len = 20
	msg, err = dco.build_key_new(buf[:], k.family, seq(k), a.ifindex, &kk)
	run(a, "KEY_NEW AES-GCM with a 20 byte key", msg, err)
	kk.key_len = 32
	kk.cipher = 7
	msg, err = dco.build_key_new(buf[:], k.family, seq(k), a.ifindex, &kk)
	run(a, "KEY_NEW with cipher 7", msg, err)
	kk.cipher = u32(dco.Cipher.None)
	msg, err = dco.build_key_new(buf[:], k.family, seq(k), a.ifindex, &kk)
	run(a, "KEY_NEW with cipher none", msg, err)
	msg, err = dco.build_key_slot(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_KEY_DEL, c.peer_id, .Secondary)
	run(a, "KEY_DEL of an empty secondary slot", msg, err)
	msg, err = dco.build_key_slot(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_KEY_SWAP, c.peer_id, .Primary)
	run(a, "KEY_SWAP with an empty secondary slot", msg, err)
	msg, err = dco.build_key_slot(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_KEY_DEL, c.peer_id, .Primary)
	run(a, "KEY_DEL of the primary slot", msg, err)
	msg, err = dco.build_key_slot(buf[:], k.family, seq(k), a.ifindex, dco.OVPN_CMD_KEY_DEL, c.peer_id, .Primary)
	run(a, "KEY_DEL of the primary slot again", msg, err)
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), 999999, good)
	run(a, "PEER_NEW on an interface that does not exist", msg, err)
	msg, err = dco.build_peer_new(buf[:], k.family, seq(k), 1, good)
	run(a, "PEER_NEW on the loopback device (not ovpn)", msg, err)
}
