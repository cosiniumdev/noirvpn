// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import cnet "core:net"
import "core:time"
import "noir:platform/event"
import "noir:platform/net"

// The UDP side of `forward`. One listener socket for each tunnel address and
// port. One session for each peer address and port: a UDP socket connected to
// the target. Datagrams from the target leave through the listener socket.
//
//	listener readable -> fwd_on_udp_in -> session found?  -> send to the target
//	                                      else fwd_udp_new -> target known? fwd_udp_open
//	                                                          else the datagram waits for the lookup
//	target socket readable -> fwd_on_udp_target -> send_to the peer from the listener
//	tick -> a session with no traffic for `udp_idle` closes

FWD_UDP_BURST :: 64
// Datagrams (and bytes) that wait for the lookup of the target, for each session.
FWD_UDP_QUEUE :: 16
FWD_UDP_QUEUE_BYTES :: 64 * 1024
FWD_UDP_RX :: 64 * 1024

Fwd_Udp_Key :: struct {
	addr: [16]u8,
	port: u16,
	lst:  u16,
}

Fwd_Udp :: struct {
	fw:      ^Fwd,
	lst:     ^Fwd_Listener,
	line:    int,
	idx:     int,
	key:     Fwd_Udp_Key,
	peer:    cnet.Endpoint,
	target:  cnet.Endpoint,
	sock:    net.Socket,
	reg:     bool,
	open:    bool, // the socket to the target exists
	last:    time.Duration,
	queue:   [dynamic][]u8,
	q_bytes: int,
	bytes_in:  u64,
	bytes_out: u64,
}

@(private = "file")
fwd_udp_key :: proc(l: ^Fwd_Listener, ep: cnet.Endpoint) -> (k: Fwd_Udp_Key) {
	k.lst = l.id
	k.port = u16(ep.port)
	switch a in ep.address {
	case cnet.IP4_Address:
		k.addr[10], k.addr[11] = 0xff, 0xff
		k.addr[12], k.addr[13], k.addr[14], k.addr[15] = a[0], a[1], a[2], a[3]
	case cnet.IP6_Address:
		k.addr = transmute([16]u8)a
	}
	return
}

// A datagram from a tunnel peer.
fwd_on_udp_in :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	l := (^Fwd_Listener)(user)
	fw := l.fw
	if fw.rx == nil {
		fw.rx = make([]u8, FWD_UDP_RX)
	}
	now := now_of(fw.d)
	for _ in 0 ..< FWD_UDP_BURST {
		n, from, err := net.recv_from(l.sock, fw.rx)
		#partial switch err {
		case .None:
		case .Connection_Reset:
			continue
		case:
			return
		}
		s, found := fw.udp_map[fwd_udp_key(l, from)]
		if !found {
			s = fwd_udp_new(fw, l, from)
			if s == nil {
				continue
			}
		}
		s.last = now
		if s.open {
			fwd_udp_send(s, fw.rx[:n])
		} else if len(s.queue) < FWD_UDP_QUEUE && s.q_bytes + n <= FWD_UDP_QUEUE_BYTES {
			append(&s.queue, clone_bytes(fw.rx[:n]))
			s.q_bytes += n
		}
	}
}

@(private = "file")
clone_bytes :: proc(b: []u8) -> []u8 {
	c := make([]u8, len(b))
	copy(c, b)
	return c
}

@(private = "file")
fwd_udp_send :: proc(s: ^Fwd_Udp, data: []u8) {
	if net.send(s.sock, data) == .None {
		s.bytes_in += u64(len(data))
		s.fw.stats.bytes_in += u64(len(data))
	}
}

// A session for a peer that sent a datagram. When the pool is full, the session
// with the longest idle time goes. nil: the session cannot be made.
@(private = "file")
fwd_udp_new :: proc(fw: ^Fwd, l: ^Fwd_Listener, from: cnet.Endpoint) -> ^Fwd_Udp {
	if len(fw.udp) >= fw.max {
		oldest := fw.udp[0]
		for s in fw.udp {
			if s.last < oldest.last {
				oldest = s
			}
		}
		fwd_udp_close(oldest, .Replaced)
	}
	s := new(Fwd_Udp)
	s.fw, s.lst, s.line, s.peer = fw, l, l.line, from
	s.key = fwd_udp_key(l, from)
	s.sock = net.INVALID_SOCKET
	s.last = now_of(fw.d)
	s.idx = len(fw.udp)
	append(&fw.udp, s)
	fw.udp_map[s.key] = s
	fw.stats.udp_sessions = u64(len(fw.udp))
	fwd_arm_tick(fw)
	line := &fw.lines[s.line]
	if fwd_line_ready(fw, line) {
		if !fwd_udp_open(s) {
			return nil
		}
	} else {
		fwd_resolve(fw, s.line)
	}
	return s
}

// Opens the socket to the target and sends the datagrams that waited. False:
// the session failed and is gone.
fwd_udp_open :: proc(s: ^Fwd_Udp) -> bool {
	fw := s.fw
	d := fw.d
	line := &fw.lines[s.line]
	for i in 0 ..< line.n {
		ep := cnet.Endpoint {
			address = line.addrs[i],
			port    = int(line.f.host_port),
		}
		sock, err := net.udp_open(net.family_of(ep))
		if err != .None {
			continue
		}
		if net.connect(sock, ep) != .None {
			net.close(sock)
			continue
		}
		if event.add_fd(&d.loop, sock.fd, {.Read}, fwd_on_udp_target, s) != .None {
			net.close(sock)
			fwd_warn(fw, .Register, "forward: the event loop cannot watch more sockets, so a session is refused")
			fwd_udp_close(s, .Refused)
			return false
		}
		s.sock, s.reg, s.target, s.open = sock, true, ep, true
		fw.stats.opened += 1
		fwd_event(fw, "open", true, s.lst.ep.port, s.peer, ep, 0, 0, .Eof)
		logf(.Debug, "forward: udp %s -> %s open", fwd_ep_text(s.peer), fwd_ep_text(ep))
		for dg in s.queue {
			fwd_udp_send(s, dg)
			delete(dg)
		}
		clear(&s.queue)
		s.q_bytes = 0
		return true
	}
	fwd_udp_close(s, .Connect_Failed)
	return false
}

// A datagram from the target: back to the peer, from the listener socket.
@(private = "file")
fwd_on_udp_target :: proc(loop: ^event.Loop, fd: i32, ready: event.Ready, user: rawptr) {
	s := (^Fwd_Udp)(user)
	fw := s.fw
	if fw.rx == nil {
		fw.rx = make([]u8, FWD_UDP_RX)
	}
	for _ in 0 ..< FWD_UDP_BURST {
		n, err := net.recv(s.sock, fw.rx)
		#partial switch err {
		case .None:
		case .Would_Block, .Connection_Refused, .Connection_Reset:
			return
		case:
			fwd_udp_close(s, .Target_Reset)
			return
		}
		if net.send_to(s.lst.sock, fw.rx[:n], s.peer) == .None {
			s.bytes_out += u64(n)
			fw.stats.bytes_out += u64(n)
		}
		s.last = now_of(fw.d)
	}
}

// Closes the session and takes it out of the pool.
fwd_udp_close :: proc(s: ^Fwd_Udp, reason: Fwd_Reason) {
	fw := s.fw
	d := fw.d
	if s.reg {
		event.remove_fd(&d.loop, s.sock.fd)
	}
	if net.is_valid(s.sock) {
		net.close(s.sock)
	}
	#partial switch reason {
	case .Connect_Failed, .Lookup_Failed:
		fw.stats.failed += 1
	case .Refused:
		fw.stats.refused += 1
	}
	if s.open || reason != .Refused {
		fwd_event(fw, "close", true, s.lst.ep.port, s.peer, s.target, s.bytes_in, s.bytes_out, reason, fw.lines[s.line].text)
		logf(
			.Debug,
			"forward: udp %s -> %s closed (%s), %d bytes in, %d bytes out",
			fwd_ep_text(s.peer),
			fw.lines[s.line].text,
			FWD_REASON_TEXT[reason],
			s.bytes_in,
			s.bytes_out,
		)
	}
	delete_key(&fw.udp_map, s.key)
	last := pop(&fw.udp)
	if s.idx < len(fw.udp) {
		fw.udp[s.idx] = last
		last.idx = s.idx
	}
	fw.stats.udp_sessions = u64(len(fw.udp))
	for dg in s.queue {
		delete(dg)
	}
	delete(s.queue)
	free(s)
}
