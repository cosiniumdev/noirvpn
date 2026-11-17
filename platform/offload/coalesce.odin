// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

// Joining decrypted TCP segments into one packet for one write to the tun.
//
//	offload.coal_reset(&c)                      // once
//	// for each received batch:
//	for each decrypted IP packet `pkt` (a slice of the receive buffer):
//		offload.coal_push(&c, pkt)
//		for o in offload.coal_pop(&c) { writev(tun, o.pieces[:o.n]) }
//	offload.coal_flush(&c)
//	for o in offload.coal_pop(&c) { writev(tun, o.pieces[:o.n]) }
//
// (`coal_pop` returns two values; the loop above is a sketch.)
//
// An output packet is a list of pieces for `writev`:
//
//	pieces[0]   the virtio header
//	pieces[1]   the first packet in full (its header is fixed for the whole run)
//	pieces[2..] the TCP payload of each packet that was joined
//
// Packets stay in the caller's memory. Do not change it until the
// last `coal_pop` after `coal_flush` and the writes are done. The header of
// the first packet of a run is changed in place.
//
// A packet joins an open run if it is the next segment of the same TCP flow
// and differs in nothing the receiver could see:
//
//	- same addresses and ports; next sequence number; same ACK number
//	- IPv4: same TOS, TTL, DF; id = last id + 1 (not checked if DF set); no
//	  IP options, no fragment
//	- IPv6: same version, traffic class, flow label, hop limit; no extension
//	  headers
//	- same TCP header length, options, window, urgent pointer; same flags
//	  except PSH (ACK and ECE must be equal); no SYN, FIN, RST, URG; CWR only
//	  on the first
//	- payload not above the first packet's; less (or PSH) ends the run
//	- at most GRO_MAX_SEGS packets and 65535 bytes
//
// The joined packet has the first header (lengths fixed).
//
// Checksums:
// - Before joining, the IPv4 header and TCP checksums of each candidate are
//   checked, like the kernel does. A bad packet is never joined. It comes out
//   as it is (after the open run of its flow), so the kernel drops it.
// - Joined packet: partial checksum, F_NEEDS_CSUM, pseudo-header sum in the
//   checksum field. The kernel completes it.
// - Packets not joined come out as they are, with an all-zero virtio header.
//
// `Coalescer.authenticated`: no TCP checksum check, so a packet is not read in
// full before it joins. Packets not joined get F_DATA_VALID. The IPv4 header
// checksum is still checked (20 bytes), because a joined packet gets a new one.
//
// Order: one flow keeps input order. Different flows may swap. A packet that
// is not a plain TCP data segment (UDP, ICMP, ACK only, SYN, FIN, garbage) is
// never dropped. It comes out as it is, after the open run of its flow.

// Most packets in one joined packet.
GRO_MAX_SEGS :: 64
// Runs (flows) that can be open at the same time. A new flow on a full table
// ends the oldest run.
GRO_FLOWS :: 8
// Packets that wait for `coal_pop`. `coal_push` needs room for two.
GRO_OUT_CAP :: 16

// Bytes of a flow key: source and destination address (16 each), two ports.
@(private)
KEY_LEN :: 36

Out_Packet :: struct {
	// The virtio header. `pieces[0]` is a slice of this array.
	hdr:    [VNET_HDR_LEN]u8,
	pieces: [GRO_MAX_SEGS + 2][]u8,
	// Pieces in use.
	n:      int,
	// Packets joined into this one. 1 means a plain packet, and `hdr` is zero
	// (F_DATA_VALID with `Coalescer.authenticated`).
	segs:   int,
	// Bytes of the IP packet (all pieces but the first).
	bytes:  int,
}

@(private)
Entry :: struct {
	used:     bool,
	v6:       bool,
	last_psh: bool, // the last packet joined had PSH
	key:      [KEY_LEN]u8,
	age:      u64,
	pkt:      []u8, // the first packet
	iphl:     int,
	tcphl:    int,
	mss:      int, // payload of the first packet
	segs:     int,
	bytes:    int, // IP bytes of the joined packet
	next_seq: u32,
	ack:      u32,
	flags:    u8, // TCP flags of the first packet
	last_id:  u16, // IPv4 id of the last packet
	pieces:   [GRO_MAX_SEGS - 1][]u8, // payload of packet 2, 3, ...
}

// Create one and call `coal_reset` before use. It is large (tens of KiB): keep
// it in a global, not on the stack.
Coalescer :: struct {
	// No TCP checksum check (see the top of this file). Set it only when an
	// authenticated channel (an AEAD tag) proved every byte of each packet
	// since the sender computed its checksum. Else a packet damaged earlier is
	// joined and the stack takes it as good. The Linux tun driver ignores
	// F_DATA_VALID on a write (6.12) and still checks a packet not joined.
	// `coal_reset` keeps this field.
	authenticated: bool,
	entries: [GRO_FLOWS]Entry,
	n_open:  int,
	age:     u64,
	q:       [GRO_OUT_CAP]Out_Packet,
	q_head:  int,
	q_n:     int,
}

// Forgets everything: open runs and waiting packets.
coal_reset :: proc "contextless" (c: ^Coalescer) {
	auth := c.authenticated
	c^ = {}
	c.authenticated = auth
}

// True while a run is open or a packet waits for `coal_pop`.
coal_pending :: proc "contextless" (c: ^Coalescer) -> bool {
	return c.n_open > 0 || c.q_n > 0
}

@(private)
Pkt_Kind :: enum u8 {
	Other, // not TCP, or the flow cannot be told
	Flow, // a TCP packet of a flow, that cannot be joined
	Cand, // a TCP data segment that can be joined
}

@(private)
Tcp_Info :: struct {
	v6:     bool,
	iphl:   int,
	tcphl:  int,
	paylen: int,
	seq:    u32,
	ack:    u32,
	flags:  u8,
	key:    [KEY_LEN]u8,
}

// Reads what is needed to find the flow, and, for a packet that may be
// joined, the rest. Checks all lengths.
@(private)
tcp_parse :: proc "contextless" (pkt: []u8, p: ^Tcp_Info, authenticated: bool) -> Pkt_Kind {
	n := len(pkt)
	if n < 24 {
		return .Other
	}
	p^ = {}
	cand := false
	switch pkt[0] >> 4 {
	case 4:
		iphl := int(pkt[0] & 0x0f) * 4
		if iphl < 20 || iphl + 4 > n || pkt[9] != PROTO_TCP {
			return .Other
		}
		// More fragments or not the first one: no ports to read.
		if be16(pkt[6:]) & 0x3fff != 0 {
			return .Other
		}
		p.iphl = iphl
		copy(p.key[0:4], pkt[12:16])
		copy(p.key[16:20], pkt[16:20])
		cand = iphl == 20 && int(be16(pkt[2:])) == n
	case 6:
		if n < 44 || pkt[6] != PROTO_TCP {
			return .Other
		}
		p.v6 = true
		p.iphl = 40
		copy(p.key[0:16], pkt[8:24])
		copy(p.key[16:32], pkt[24:40])
		cand = int(be16(pkt[4:])) == n - 40
	case:
		return .Other
	}
	copy(p.key[32:36], pkt[p.iphl:][:4])
	if !cand || n < p.iphl + 20 {
		return .Flow
	}
	tp := pkt[p.iphl:]
	tcphl := int(tp[12] >> 4) * 4
	// The low 4 bits of byte 12 are the NS flag and reserved bits.
	if tp[12] & 0x0f != 0 || tcphl < 20 || tcphl > 60 || p.iphl + tcphl >= n {
		return .Flow
	}
	flags := tp[13]
	if flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_URG) != 0 || flags & TCP_ACK == 0 {
		return .Flow
	}
	if !checksums_ok(pkt, p.v6, p.iphl, authenticated) {
		return .Flow
	}
	p.tcphl = tcphl
	p.paylen = n - p.iphl - tcphl
	p.seq = be32(tp[4:])
	p.ack = be32(tp[8:])
	p.flags = flags
	return .Cand
}

// Are the IPv4 header checksum (IPv6 has none) and the TCP checksum right?
// The packet is already whole (IP length = slice length). With
// `authenticated` only the IPv4 header is checked.
@(private)
checksums_ok :: proc "contextless" (pkt: []u8, v6: bool, iphl: int, authenticated: bool) -> bool {
	if !v6 && csum_sum(pkt[:iphl]) != 0xffff {
		return false
	}
	if authenticated {
		return true
	}
	tlen := len(pkt) - iphl
	return csum_add(pseudo_sum(pkt, v6, PROTO_TCP, tlen), csum_sum(pkt[iphl:])) == 0xffff
}

@(private)
find_entry :: proc "contextless" (c: ^Coalescer, p: ^Tcp_Info) -> int {
	if c.n_open == 0 {
		return -1
	}
	for i in 0 ..< GRO_FLOWS {
		e := &c.entries[i]
		if e.used && e.v6 == p.v6 && e.key == p.key {
			return i
		}
	}
	return -1
}

@(private)
same_bytes :: proc "contextless" (a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Can the packet (a candidate of the flow of `e`) join the run?
@(private)
can_append :: proc "contextless" (e: ^Entry, p: ^Tcp_Info, pkt: []u8) -> bool {
	if p.seq != e.next_seq || p.ack != e.ack || p.tcphl != e.tcphl {
		return false
	}
	if p.flags & TCP_CWR != 0 || (p.flags ~ e.flags) & ~u8(TCP_CWR | TCP_PSH) != 0 {
		return false
	}
	if e.segs >= GRO_MAX_SEGS || p.paylen > e.mss || e.bytes + p.paylen > 65535 {
		return false
	}
	first := e.pkt
	if e.v6 {
		if pkt[0] != first[0] || pkt[1] != first[1] || pkt[2] != first[2] || pkt[3] != first[3] || pkt[7] != first[7] {
			return false
		}
	} else {
		// TOS, TTL, and the DF bit.
		if pkt[1] != first[1] || pkt[8] != first[8] || (pkt[6] ~ first[6]) & 0x40 != 0 {
			return false
		}
		if pkt[6] & 0x40 == 0 && be16(pkt[4:]) != e.last_id + 1 {
			return false
		}
	}
	// The window (bytes 14 and 15) and the urgent pointer (18 and 19).
	t, f := pkt[p.iphl:], first[e.iphl:]
	if t[14] != f[14] || t[15] != f[15] || t[18] != f[18] || t[19] != f[19] {
		return false
	}
	return same_bytes(t[20:p.tcphl], f[20:e.tcphl])
}

@(private)
q_tail :: #force_inline proc "contextless" (c: ^Coalescer) -> ^Out_Packet {
	return &c.q[(c.q_head + c.q_n) % GRO_OUT_CAP]
}

// Puts a packet that is not joined in the output queue.
@(private)
emit_plain :: proc "contextless" (c: ^Coalescer, pkt: []u8) {
	o := q_tail(c)
	o.hdr = {}
	if c.authenticated {
		o.hdr[0] = F_DATA_VALID
	}
	o.pieces[1] = pkt
	o.n = 2
	o.segs = 1
	o.bytes = len(pkt)
	c.q_n += 1
}

// Ends a run: fixes the header of its first packet and puts it in the output
// queue. The caller has checked that there is room.
@(private)
emit_entry :: proc "contextless" (c: ^Coalescer, idx: int) {
	e := &c.entries[idx]
	if e.segs == 1 {
		emit_plain(c, e.pkt)
	} else {
		o := q_tail(c)
		pkt := e.pkt
		iphl := e.iphl
		tcp := pkt[iphl:]
		if e.v6 {
			put_be16(pkt[4:], u16(e.bytes - 40))
		} else {
			put_be16(pkt[2:], u16(e.bytes))
			put_be16(pkt[10:], ip4_checksum(pkt, 20))
		}
		if e.last_psh {
			tcp[13] |= TCP_PSH
		}
		// Not inverted: the checksum is partial, see `Vnet_Hdr`.
		put_be16(tcp[16:], pseudo_sum(pkt, e.v6, PROTO_TCP, e.bytes - iphl))
		h := Vnet_Hdr {
			flags       = F_NEEDS_CSUM,
			gso_type    = GSO_TCPV6 if e.v6 else GSO_TCPV4,
			hdr_len     = u16(iphl + e.tcphl),
			gso_size    = u16(e.mss),
			csum_start  = u16(iphl),
			csum_offset = 16,
		}
		if e.flags & TCP_CWR != 0 {
			h.gso_type |= GSO_ECN
		}
		vnet_encode(o.hdr[:], h)
		o.pieces[1] = pkt
		for i in 0 ..< e.segs - 1 {
			o.pieces[2 + i] = e.pieces[i]
		}
		o.n = e.segs + 1
		o.segs = e.segs
		o.bytes = e.bytes
		c.q_n += 1
	}
	e.used = false
	e.pkt = nil
	c.n_open -= 1
}

// A free entry. If all are in use, the oldest run is ended (it needs one place
// in the output queue) and its entry is given.
@(private)
free_entry :: proc "contextless" (c: ^Coalescer) -> int {
	oldest := -1
	for i in 0 ..< GRO_FLOWS {
		e := &c.entries[i]
		if !e.used {
			return i
		}
		if oldest < 0 || e.age < c.entries[oldest].age {
			oldest = i
		}
	}
	emit_entry(c, oldest)
	return oldest
}

@(private)
start_entry :: proc "contextless" (c: ^Coalescer, idx: int, pkt: []u8, p: ^Tcp_Info) {
	e := &c.entries[idx]
	c.age += 1
	e.used = true
	e.v6 = p.v6
	e.last_psh = false
	e.key = p.key
	e.age = c.age
	e.pkt = pkt
	e.iphl = p.iphl
	e.tcphl = p.tcphl
	e.mss = p.paylen
	e.segs = 1
	e.bytes = len(pkt)
	e.next_seq = p.seq + u32(p.paylen)
	e.ack = p.ack
	e.flags = p.flags
	e.last_id = 0 if p.v6 else be16(pkt[4:])
	c.n_open += 1
}

// Takes the next received IP packet. `pkt` must stay valid and unchanged (but
// for changes done here) until it left `coal_pop` and was written. Returns
// false and does nothing if the output queue has no room for two packets: call
// `coal_pop` until empty, push again. A packet that cannot join, or ends a
// run, comes out at once.
coal_push :: proc "contextless" (c: ^Coalescer, pkt: []u8) -> bool {
	if GRO_OUT_CAP - c.q_n < 2 {
		return false
	}
	p: Tcp_Info
	kind := tcp_parse(pkt, &p, c.authenticated)
	if kind == .Other {
		emit_plain(c, pkt)
		return true
	}
	idx := find_entry(c, &p)
	if kind == .Flow {
		if idx >= 0 {
			emit_entry(c, idx)
		}
		emit_plain(c, pkt)
		return true
	}
	if idx >= 0 {
		e := &c.entries[idx]
		if can_append(e, &p, pkt) {
			e.pieces[e.segs - 1] = pkt[p.iphl + p.tcphl:]
			e.segs += 1
			e.bytes += p.paylen
			e.next_seq += u32(p.paylen)
			if !p.v6 {
				e.last_id = be16(pkt[4:])
			}
			psh := p.flags & TCP_PSH != 0
			e.last_psh = psh
			if psh || p.paylen < e.mss {
				emit_entry(c, idx)
			}
			return true
		}
		emit_entry(c, idx)
	}
	if p.flags & TCP_PSH != 0 {
		// A run that starts with PSH cannot take more packets.
		emit_plain(c, pkt)
		return true
	}
	start_entry(c, free_entry(c), pkt, &p)
	return true
}

// Ends all open runs, oldest first, and puts them in the output queue. Call it
// at the end of a batch, then `coal_pop` until empty. If the output queue is
// full, some runs stay open: pop, then call again (see `coal_pending`).
coal_flush :: proc "contextless" (c: ^Coalescer) {
	for c.n_open > 0 && c.q_n < GRO_OUT_CAP {
		oldest := -1
		for i in 0 ..< GRO_FLOWS {
			e := &c.entries[i]
			if e.used && (oldest < 0 || e.age < c.entries[oldest].age) {
				oldest = i
			}
		}
		emit_entry(c, oldest)
	}
}

// The next packet to write, or false. The packet and its pieces are valid
// until the next `coal_push` or `coal_reset`.
coal_pop :: proc "contextless" (c: ^Coalescer) -> (o: ^Out_Packet, ok: bool) {
	if c.q_n == 0 {
		return nil, false
	}
	o = &c.q[c.q_head]
	c.q_head = (c.q_head + 1) % GRO_OUT_CAP
	c.q_n -= 1
	o.pieces[0] = o.hdr[:]
	return o, true
}
