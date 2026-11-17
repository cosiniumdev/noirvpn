// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:crypto/sha2"
import "core:sys/linux"
import "core:time"
import "noir:platform/dco"

// A key or nonce: SHA-256 over the secret, a label, the key id and the cipher.
hash4 :: proc(secret, label: string, kid: u32, cipher: dco.Cipher) -> [32]u8 {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]u8)secret)
	sha2.update(&ctx, []u8{0})
	sha2.update(&ctx, transmute([]u8)label)
	sha2.update(&ctx, []u8{0, u8(kid), u8(cipher)})
	out: [32]u8
	sha2.final(&ctx, out[:])
	return out
}

// A framed control record: 2-byte length, the control opcode, the kind, a number,
// and `extra`.
frame :: proc(kind: Kind, n: u32, extra: []u8) -> []u8 {
	body := 6 + len(extra)
	b := make([dynamic]u8, 0, 2 + body, context.temp_allocator)
	append(&b, u8(body >> 8), u8(body), CTRL_OP, u8(kind), u8(n >> 24), u8(n >> 16), u8(n >> 8), u8(n))
	append(&b, ..extra)
	return b[:]
}

send_all :: proc(fd: linux.Fd, b: []u8) -> bool {
	off := 0
	for off < len(b) {
		n, e := linux.send(fd, b[off:], {.NOSIGNAL})
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			say("send: %v", e)
			return false
		}
		off += n
	}
	return true
}

recv_exact :: proc(fd: linux.Fd, buf: []u8, timeout_ms: int) -> bool {
	got := 0
	deadline := time.tick_add(time.tick_now(), time.Duration(timeout_ms) * time.Millisecond)
	for got < len(buf) {
		left := time.tick_diff(time.tick_now(), deadline)
		if left <= 0 {
			return false
		}
		pfd := [1]linux.Poll_Fd{{fd = fd, events = {.IN}}}
		linux.poll(pfd[:], i32(left / time.Millisecond))
		n, e := linux.recv(fd, buf[got:], {.DONTWAIT})
		if e == .EAGAIN || e == .EINTR {
			continue
		}
		if e != .NONE || n == 0 {
			return false
		}
		got += n
	}
	return true
}

// One framed record from the stream, without its prefix.
read_frame :: proc(fd: linux.Fd) -> (rec: []u8, ok: bool) {
	hdr: [2]u8
	if !recv_exact(fd, hdr[:], 10000) {
		return nil, false
	}
	n := int(hdr[0]) << 8 | int(hdr[1])
	rec = make([]u8, n, context.temp_allocator)
	if !recv_exact(fd, rec, 10000) {
		return nil, false
	}
	return rec, true
}

// The bytes that the server sends for the read-ahead test: a complete control
// record, a data record, and the start of a second control record. `rest` is the
// end of the second record.
ahead_bytes :: proc() -> (first: []u8, rest: []u8) {
	big := make([]u8, 294, context.temp_allocator)
	for i in 0 ..< len(big) {
		big[i] = u8(i % 251)
	}
	a := frame(.Ahead_Ctrl, 1, transmute([]u8)string("hello-ahead"))
	d := make([]u8, 2 + 30, context.temp_allocator)
	d[1] = 30
	d[2] = 9 << 3 // a data packet: the kernel handles these
	b := frame(.Ahead_Big, 2, big)
	f := make([dynamic]u8, 0, len(a) + len(d) + 5, context.temp_allocator)
	append(&f, ..a)
	append(&f, ..d)
	append(&f, ..b[:5])
	return f[:], b[5:]
}

// Creates the stream, exchanges records, and hands it to the backend. True when the peer exists.
tcp_start :: proc(a: ^App, np: ^dco.New_Peer) -> bool {
	c := a.cfg
	fd: linux.Fd
	e: linux.Errno
	fd, e = linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
	if e != .NONE {
		say("socket: %v", e)
		return false
	}
	defer linux.close(fd)
	one: i32 = 1
	linux.setsockopt_base(fd, 1, 2, &one) // SO_REUSEADDR
	laddr := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(c.lport),
		sin_addr   = c.local,
	}
	conn := fd
	if c.client {
		if be := linux.bind(fd, &laddr); be != .NONE {
			say("bind: %v", be)
			return false
		}
		raddr := linux.Sock_Addr_In {
			sin_family = .INET,
			sin_port   = u16be(c.rport),
			sin_addr   = c.remote,
		}
		ok := false
		for _ in 0 ..< 60 {
			if ce := linux.connect(fd, &raddr); ce == .NONE {
				ok = true
				break
			}
			time.sleep(500 * time.Millisecond)
			// A failed connect leaves the socket unusable: start again.
			linux.close(fd)
			nfd, ne := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
			if ne != .NONE {
				return false
			}
			fd = nfd
			linux.setsockopt_base(fd, 1, 2, &one)
			linux.bind(fd, &laddr)
		}
		if !ok {
			say("connect to %v:%d failed", c.remote, c.rport)
			return false
		}
		conn = fd
		say("connected to %v:%d", c.remote, c.rport)
	} else {
		if be := linux.bind(fd, &laddr); be != .NONE {
			say("bind: %v", be)
			return false
		}
		linux.listen(fd, 1)
		say("listening on %v:%d", c.local, c.lport)
		pfd := [1]linux.Poll_Fd{{fd = fd, events = {.IN}}}
		if n, _ := linux.poll(pfd[:], 60000); n <= 0 {
			say("no client within 60 s")
			return false
		}
		src: linux.Sock_Addr_In
		cfd, ae := linux.accept(fd, &src, {.CLOEXEC})
		if ae != .NONE {
			say("accept: %v", ae)
			return false
		}
		conn = cfd
		say("accepted a connection from %v:%d", src.sin_addr, u16(src.sin_port))
	}
	defer if conn != fd {
		linux.close(conn)
	}
	linux.setsockopt_base(conn, 6, 1, &one) // TCP_NODELAY
	a.tcp = conn

	// Control records before the handover, read by this process.
	for i in u32(1) ..= 2 {
		if !send_all(conn, frame(.Pre, i, transmute([]u8)string("before the handover"))) {
			return false
		}
	}
	for _ in 0 ..< 2 {
		rec, ok := read_frame(conn)
		if !ok {
			say("no pre-handover record from the peer")
			return false
		}
		say("pre-handover record from the peer: %d bytes, kind %c", len(rec), rune(rec[1]))
	}

	ahead: []u8
	if !c.tcp_ahead {
		if c.client {
			// The server sends: a control record, a data record, half of a control record.
			time.sleep(400 * time.Millisecond)
			buf := make([]u8, 4096, context.temp_allocator)
			n, re := linux.recv(conn, buf, {.DONTWAIT})
			if re != .NONE || n <= 0 {
				say("nothing to read ahead: %v", re)
				return false
			}
			ahead = buf[:n]
			say("read ahead %d bytes (a control record, a data record, half of a control record)", n)
			if !send_all(conn, frame(.Go, 0, nil)) {
				return false
			}
		} else {
			first, rest := ahead_bytes()
			if !send_all(conn, first) {
				return false
			}
			say("sent %d bytes: a control record, a data record, 5 bytes of a second control record", len(first))
			rec, ok := read_frame(conn)
			if !ok || len(rec) < 2 || Kind(rec[1]) != .Go {
				say("no go record from the client")
				return false
			}
			if !send_all(conn, rest) {
				return false
			}
			say("sent the %d bytes that complete the second control record", len(rest))
		}
	}

	st := a.be.new_peer_stream(a.be.user, np, i32(conn), ahead)
	if st != 0 {
		say("new_peer_stream: %s (%s)", dco.status_text(st), a.be.err_text(a.be.user))
		return false
	}
	if c.probe {
		a.probe_fd, _ = linux.fcntl_dupfd_cloexec(conn, linux.F_DUPFD_CLOEXEC, 0)
	}
	say("peer %d on the stream (the kernel owns it now); dropped data records from the read-ahead: %d", c.peer_id, a.k.ahead_data)
	return true
}

// What the kernel does with the stream of a peer, seen from user space. The client
// sends control records by `ctrl_tx`; the server reads its own copy of the socket.
probe_tcp :: proc(a: ^App) {
	if a.cfg.client {
		time.sleep(1500 * time.Millisecond)
		for n in ([]int{100, 150, 3000}) {
			rec := make([]u8, n, context.temp_allocator)
			rec[0] = CTRL_OP
			rec[1] = 'X'
			st := a.be.ctrl_tx(a.be.user, a.cfg.peer_id, rec)
			say("probe: sent a record of %d bytes: %s", n, dco.status_text(st))
			time.sleep(1000 * time.Millisecond)
		}
		return
	}
	fd := a.probe_fd
	poll_now :: proc(fd: linux.Fd, ms: i32, what: string) {
		pfd := [1]linux.Poll_Fd{{fd = fd, events = {.IN}}}
		n, _ := linux.poll(pfd[:], ms)
		out := [1]linux.Poll_Fd{{fd = fd, events = {.OUT}}}
		linux.poll(out[:], 0)
		say("probe: poll (%s): %d ready, readable %v, error %v, hangup %v; writable %v", what, n, .IN in pfd[0].revents, .ERR in pfd[0].revents, .HUP in pfd[0].revents, .OUT in out[0].revents)
	}
	read_small :: proc(fd: linux.Fd, size: int, flags: linux.Socket_Msg) {
		buf := make([]u8, size, context.temp_allocator)
		iov := [1]linux.IO_Vec{{base = raw_data(buf), len = uint(size)}}
		hdr := linux.Msg_Hdr {
			iov = iov[:],
		}
		n, e := linux.recvmsg(fd, &hdr, flags)
		say("probe: recvmsg with a %d byte buffer, flags %v: returned %d (%v), msg_flags has TRUNC: %v, first bytes %02x", size, flags, n, e, .TRUNC in hdr.flags, buf[:min(n, 4) if n > 0 else 0])
	}
	poll_now(fd, 0, "before any record")
	read_small(fd, 4096, {.DONTWAIT})
	poll_now(fd, 3000, "waiting for the first record (100 bytes)")
	read_small(fd, 10, {.DONTWAIT})
	poll_now(fd, 0, "after a short read")
	read_small(fd, 4096, {.DONTWAIT})
	poll_now(fd, 3000, "waiting for the second record (150 bytes)")
	read_small(fd, 10, {.TRUNC, .DONTWAIT})
	poll_now(fd, 3000, "waiting for the third record (3000 bytes)")
	read_small(fd, 4096, {.DONTWAIT})
	poll_now(fd, 0, "at the end")
}
