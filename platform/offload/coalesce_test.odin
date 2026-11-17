// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

import "core:fmt"
import "core:testing"
import "core:time"

// What came out of the coalescer, copied (the pieces are only valid until the
// next push).
Result :: struct {
	h:     Vnet_Hdr,
	raw:   [VNET_HDR_LEN]u8,
	segs:  int,
	bytes: int,
	n:     int,
	flat:  []u8,
}

new_coalescer :: proc() -> ^Coalescer {
	c := new(Coalescer, context.temp_allocator)
	coal_reset(c)
	return c
}

drain :: proc(c: ^Coalescer, res: ^[dynamic]Result) {
	for {
		o, ok := coal_pop(c)
		if !ok {
			return
		}
		r := Result {
			segs  = o.segs,
			bytes = o.bytes,
			n     = o.n,
			flat  = flatten(o),
			raw   = o.hdr,
		}
		r.h, _ = vnet_decode(o.pieces[0])
		append(res, r)
	}
}

// Pushes all packets, popping after each, then flushes.
run_coal :: proc(c: ^Coalescer, pkts: [][]u8) -> [dynamic]Result {
	res := make([dynamic]Result, context.temp_allocator)
	for p in pkts {
		ok := coal_push(c, p)
		if !ok {
			panic("coal_push refused")
		}
		drain(c, &res)
	}
	coal_flush(c)
	drain(c, &res)
	return res
}

// A run of `n` segments of a flow (sequence number and id follow each other).
// `edit` may change segment `k` (and `sticky` also changes the later ones).
Edit :: struct {
	at:     int,
	sticky: bool,
	f:      proc(sp: ^Spec),
}

make_run :: proc(base: Spec, n, mss: int, edit: Edit = {at = -1}) -> [][]u8 {
	out := make([][]u8, n, context.temp_allocator)
	seq := base.seq
	id := base.id
	pay := fill_payload(mss * n + 100)
	for k in 0 ..< n {
		sp := base
		sp.seq = seq
		sp.id = id
		sp.payload = pay[k * mss:][:mss]
		if edit.f != nil && (k == edit.at || (edit.sticky && k > edit.at)) {
			edit.f(&sp)
		}
		buf := make([]u8, mss + 400, context.temp_allocator)
		out[k] = build(&sp, buf)
		seq = sp.seq + u32(len(sp.payload))
		id = sp.id + 1
	}
	return out
}

segs_of :: proc(res: [dynamic]Result) -> []int {
	s := make([]int, len(res), context.temp_allocator)
	for r, i in res {
		s[i] = r.segs
	}
	return s
}

same_ints :: proc(a, b: []int) -> bool {
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

// For a joined packet: completes the checksum the way the kernel does it, then
// checks the whole packet.
check_joined :: proc(t: ^testing.T, r: Result, label: string) -> bool {
	p := make([]u8, len(r.flat), context.temp_allocator)
	copy(p, r.flat)
	iphl := 20 if p[0] >> 4 == 4 else 40
	// The IPv4 header checksum and the lengths are final.
	if iphl == 20 {
		testing.expectf(t, naive_fold(naive_sum(p[:20])) == 0xffff, "%s: bad ip header checksum", label)
		testing.expectf(t, int(be16(p[2:])) == len(p), "%s: bad total length", label)
	} else {
		testing.expectf(t, int(be16(p[4:])) == len(p) - 40, "%s: bad payload length", label)
	}
	// The checksum field holds the pseudo-header sum, not inverted.
	ps := naive_fold(naive_pseudo(p, iphl, iphl == 40, PROTO_TCP))
	testing.expectf(t, be16(p[iphl + 16:]) == ps, "%s: the checksum field is not the pseudo-header sum", label)
	// Completing it as the kernel does gives a right checksum.
	put_be16(p[iphl + 16:], ~naive_fold(naive_sum(p[iphl:])))
	v, why := verify(p)
	testing.expectf(t, v, "%s: completed packet: %s", label, why)
	// The virtio header.
	tcphl := int(p[iphl + 12] >> 4) * 4
	want := Vnet_Hdr {
		flags       = F_NEEDS_CSUM,
		gso_type    = GSO_TCPV6 if iphl == 40 else GSO_TCPV4,
		hdr_len     = u16(iphl + tcphl),
		gso_size    = r.h.gso_size,
		csum_start  = u16(iphl),
		csum_offset = 16,
	}
	if p[iphl + 13] & TCP_CWR != 0 {
		want.gso_type |= GSO_ECN
	}
	testing.expectf(t, r.h == want, "%s: virtio header %v, want %v", label, r.h, want)
	testing.expectf(t, r.h.gso_size > 0 && int(r.h.gso_size) <= len(p) - iphl - tcphl, "%s: gso_size %d", label, r.h.gso_size)
	return true
}

base_ts :: proc(v6: bool, ts: ^[12]u8) -> Spec {
	sp := default_spec(v6)
	ts^ = ts_options(1000, 2000)
	sp.topts = ts[:]
	return sp
}

// Copies of packets.
copy_all :: proc(pkts: [][]u8) -> [][]u8 {
	out := make([][]u8, len(pkts), context.temp_allocator)
	for p, i in pkts {
		out[i] = make([]u8, len(p), context.temp_allocator)
		copy(out[i], p)
	}
	return out
}

// A flat packet is the same bytes as another.
same_bytes_test :: proc(a, b: []u8) -> bool {
	return string(a) == string(b)
}

@(test)
coal_run :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		ts: [12]u8
		sp := base_ts(v6, &ts)
		mss := 1348
		segs := make_run(sp, 45, mss)
		c := new_coalescer()
		res := run_coal(c, segs)
		label := fmt.tprintf("v6=%v", v6)
		if !testing.expectf(t, len(res) == 1, "%s: %d outputs", label, len(res)) {
			continue
		}
		r := res[0]
		testing.expect_value(t, r.segs, 45)
		testing.expect_value(t, r.n, 46)
		testing.expect_value(t, r.bytes, len(r.flat))
		testing.expect_value(t, r.h.gso_size, u16(mss))
		check_joined(t, r, label)
	}
}

// The packet the coalescer creates is the one a tun would hand over for the same
// data: same bytes, same virtio header.
@(test)
coal_equals_super_packet :: proc(t: ^testing.T) {
	for v6 in ([2]bool{false, true}) {
		for ecn in ([2]bool{false, true}) {
			ts: [12]u8
			sp := base_ts(v6, &ts)
			mss := 1000
			n := 30
			sp.payload = fill_payload(mss * n)
			if ecn {
				sp.flags |= TCP_CWR
			}
			// The last packet has PSH: it ends the run and sets PSH on the whole.
			sp.flags |= TCP_PSH
			buf := make([]u8, len(sp.payload) + 300, context.temp_allocator)
			h, super := make_super(&sp, mss, buf)
			segs := expected_segments(&sp, mss)
			orig := copy_all(segs) // the coalescer changes the first packet in place
			c := new_coalescer()
			res := run_coal(c, segs)
			label := fmt.tprintf("v6=%v ecn=%v", v6, ecn)
			if !testing.expectf(t, len(res) == 1, "%s: %d outputs: %v", label, len(res), segs_of(res)) {
				continue
			}
			testing.expectf(t, same_bytes_test(res[0].flat, super), "%s: packet differs from the tun's super-packet", label)
			testing.expectf(t, res[0].h == h, "%s: header %v, want %v", label, res[0].h, h)
			// And back: cutting it gives the packets that went in.
			back, err := split_all(res[0].h, res[0].flat, MAX_OUT)
			testing.expect_value(t, err, Error.None)
			if testing.expectf(t, len(back) == len(orig), "%s: %d packets back", label, len(back)) {
				for i in 0 ..< len(back) {
					testing.expectf(t, same_bytes_test(back[i], orig[i]), "%s: packet %d differs after the round trip", label, i)
				}
			}
		}
	}
}

// Order: it stays inside a flow. `flat` of the outputs of a flow, joined, has
// the payload of the inputs in the same order.
payload_of :: proc(p: []u8) -> []u8 {
	iphl := 20 if p[0] >> 4 == 4 else 40
	tcphl := int(p[iphl + 12] >> 4) * 4
	return p[iphl + tcphl:]
}

flow_port :: proc(p: []u8) -> u16 {
	iphl := 20 if p[0] >> 4 == 4 else 40
	return be16(p[iphl:])
}

// Every input comes out exactly once, in order inside its flow. TCP only.
check_conservation :: proc(t: ^testing.T, inputs: [][]u8, res: [dynamic]Result, label: string) {
	total_in := 0
	for r in res {
		total_in += r.segs
	}
	testing.expectf(t, total_in == len(inputs), "%s: %d packets in, %d out", label, len(inputs), total_in)
	ports := make(map[u16]bool, context.temp_allocator)
	for p in inputs {
		ports[flow_port(p)] = true
	}
	for port in ports {
		want := make([dynamic]u8, context.temp_allocator)
		for p in inputs {
			if flow_port(p) == port {
				append(&want, ..payload_of(p))
			}
		}
		got := make([dynamic]u8, context.temp_allocator)
		for r in res {
			if flow_port(r.flat) == port {
				append(&got, ..payload_of(r.flat))
			}
		}
		testing.expectf(t, string(want[:]) == string(got[:]), "%s: payload of port %d differs", label, port)
	}
}

// ---- reasons for a run to end ----

Case :: struct {
	name:   string,
	v6:     bool,
	edit:   Edit,
	df:     bool, // the base spec's DF bit (IPv4)
	ip_opt: bool,
	want:   []int,
}

edit_seq_gap :: proc(sp: ^Spec) {
	sp.seq += 5
}
edit_ack :: proc(sp: ^Spec) {
	sp.ack += 1
}
edit_opts :: proc(sp: ^Spec) {
	sp.topts = ts_opts_alt[:]
}
edit_no_opts :: proc(sp: ^Spec) {
	sp.topts = nil
}
edit_syn :: proc(sp: ^Spec) {
	sp.flags |= TCP_SYN
}
edit_fin :: proc(sp: ^Spec) {
	sp.flags |= TCP_FIN
}
edit_rst :: proc(sp: ^Spec) {
	sp.flags |= TCP_RST
}
edit_urg :: proc(sp: ^Spec) {
	sp.flags |= TCP_URG
	sp.urg_ptr = 3
}
edit_cwr :: proc(sp: ^Spec) {
	sp.flags |= TCP_CWR
}
edit_ece :: proc(sp: ^Spec) {
	sp.flags |= TCP_ECE
}
edit_psh :: proc(sp: ^Spec) {
	sp.flags |= TCP_PSH
}
edit_big :: proc(sp: ^Spec) {
	sp.payload = fill_payload(1200)
}
edit_small :: proc(sp: ^Spec) {
	sp.payload = sp.payload[:700]
}
edit_no_payload :: proc(sp: ^Spec) {
	sp.payload = nil
}
edit_id_jump :: proc(sp: ^Spec) {
	sp.id += 7
}
edit_id_same :: proc(sp: ^Spec) {
	sp.id = 5
}
edit_ttl :: proc(sp: ^Spec) {
	sp.ttl = 63
}
edit_tos :: proc(sp: ^Spec) {
	sp.tos = 0x28
}
edit_flow_label :: proc(sp: ^Spec) {
	sp.flow = 0x12345
}
edit_port :: proc(sp: ^Spec) {
	sp.sport += 1
}
edit_window :: proc(sp: ^Spec) {
	sp.window += 100
}
edit_urg_ptr :: proc(sp: ^Spec) {
	sp.urg_ptr = 3 // without the URG flag
}
edit_bad_csum :: proc(sp: ^Spec) {
	sp.bad_csum = true
}
edit_bad_ip_csum :: proc(sp: ^Spec) {
	sp.bad_ip_csum = true
}
edit_trailing :: proc(sp: ^Spec) {
	sp.trailing = 4
}
edit_df_off :: proc(sp: ^Spec) {
	sp.df = false
}
ts_opts_alt: [12]u8

@(test)
coal_stop_reasons :: proc(t: ^testing.T) {
	ts_opts_alt = ts_options(1001, 2000) // another timestamp
	cases := []Case {
		{name = "none", edit = {at = -1}, df = true, want = {4}},
		{name = "seq gap", edit = {at = 2, f = edit_seq_gap}, df = true, want = {2, 2}},
		{name = "ack differs", edit = {at = 2, f = edit_ack}, df = true, want = {2, 1, 1}},
		{name = "ack differs from here on", edit = {at = 2, f = edit_ack, sticky = true}, df = true, want = {2, 2}},
		{name = "options differ", edit = {at = 2, f = edit_opts}, df = true, want = {2, 1, 1}},
		{name = "options differ from here on", edit = {at = 2, f = edit_opts, sticky = true}, df = true, want = {2, 2}},
		{name = "no options", edit = {at = 2, f = edit_no_opts}, df = true, want = {2, 1, 1}},
		{name = "SYN", edit = {at = 2, f = edit_syn}, df = true, want = {2, 1, 1}},
		{name = "FIN", edit = {at = 2, f = edit_fin}, df = true, want = {2, 1, 1}},
		{name = "RST", edit = {at = 2, f = edit_rst}, df = true, want = {2, 1, 1}},
		{name = "URG", edit = {at = 2, f = edit_urg}, df = true, want = {2, 1, 1}},
		{name = "CWR on the first", edit = {at = 0, f = edit_cwr}, df = true, want = {4}},
		{name = "CWR on the second", edit = {at = 1, f = edit_cwr}, df = true, want = {1, 3}},
		{name = "ECE differs", edit = {at = 2, f = edit_ece}, df = true, want = {2, 1, 1}},
		{name = "ECE on all", edit = {at = 0, f = edit_ece, sticky = true}, df = true, want = {4}},
		{name = "PSH on the second", edit = {at = 1, f = edit_psh}, df = true, want = {2, 2}},
		{name = "PSH on the first", edit = {at = 0, f = edit_psh}, df = true, want = {1, 3}},
		{name = "PSH on the last", edit = {at = 3, f = edit_psh}, df = true, want = {4}},
		{name = "bigger payload", edit = {at = 2, f = edit_big}, df = true, want = {2, 2}},
		{name = "smaller payload", edit = {at = 1, f = edit_small}, df = true, want = {2, 2}},
		{name = "smaller payload last", edit = {at = 3, f = edit_small}, df = true, want = {4}},
		{name = "no payload", edit = {at = 2, f = edit_no_payload}, df = true, want = {2, 1, 1}},
		{name = "id jumps, DF set", edit = {at = 2, f = edit_id_jump}, df = true, want = {4}},
		{name = "id repeats, DF set", edit = {at = 1, f = edit_id_same, sticky = true}, df = true, want = {4}},
		{name = "id jumps, DF clear", edit = {at = 2, f = edit_id_jump}, df = false, want = {2, 2}},
		{name = "id repeats, DF clear", edit = {at = 1, f = edit_id_same, sticky = true}, df = false, want = {1, 1, 1, 1}},
		{name = "DF changes", edit = {at = 2, f = edit_df_off}, df = true, want = {2, 1, 1}},
		{name = "TTL differs", edit = {at = 2, f = edit_ttl}, df = true, want = {2, 1, 1}},
		{name = "TOS differs", edit = {at = 2, f = edit_tos}, df = true, want = {2, 1, 1}},
		{name = "other port", edit = {at = 2, f = edit_port}, df = true, want = {2, 1, 1}},
		{name = "window differs", edit = {at = 2, f = edit_window}, df = true, want = {2, 1, 1}},
		{name = "window differs from here on", edit = {at = 2, f = edit_window, sticky = true}, df = true, want = {2, 2}},
		{name = "window differs on the second", edit = {at = 1, f = edit_window}, df = true, want = {1, 1, 2}},
		{name = "urgent pointer differs", edit = {at = 2, f = edit_urg_ptr}, df = true, want = {2, 1, 1}},
		{name = "bad TCP checksum, first", edit = {at = 0, f = edit_bad_csum}, df = true, want = {1, 3}},
		{name = "bad TCP checksum, middle", edit = {at = 2, f = edit_bad_csum}, df = true, want = {2, 1, 1}},
		{name = "bad TCP checksum, last", edit = {at = 3, f = edit_bad_csum}, df = true, want = {3, 1}},
		{name = "bad TCP checksum, all", edit = {at = 0, f = edit_bad_csum, sticky = true}, df = true, want = {1, 1, 1, 1}},
		{name = "bad IPv4 header checksum, first", edit = {at = 0, f = edit_bad_ip_csum}, df = true, want = {1, 3}},
		{name = "bad IPv4 header checksum, middle", edit = {at = 2, f = edit_bad_ip_csum}, df = true, want = {2, 1, 1}},
		{name = "bad IPv4 header checksum, last", edit = {at = 3, f = edit_bad_ip_csum}, df = true, want = {3, 1}},
		{name = "bad IPv4 header checksum, DF clear", edit = {at = 2, f = edit_bad_ip_csum}, df = false, want = {2, 1, 1}},
		{name = "trailing bytes", edit = {at = 2, f = edit_trailing}, df = true, want = {2, 1, 1}},
		{name = "IPv4 options", edit = {at = -1}, df = true, ip_opt = true, want = {1, 1, 1, 1}},
		// IPv6
		{name = "v6 none", v6 = true, edit = {at = -1}, df = true, want = {4}},
		{name = "v6 hop limit", v6 = true, edit = {at = 2, f = edit_ttl}, df = true, want = {2, 1, 1}},
		{name = "v6 traffic class", v6 = true, edit = {at = 2, f = edit_tos}, df = true, want = {2, 1, 1}},
		{name = "v6 flow label", v6 = true, edit = {at = 2, f = edit_flow_label}, df = true, want = {2, 1, 1}},
		{name = "v6 seq gap", v6 = true, edit = {at = 2, f = edit_seq_gap}, df = true, want = {2, 2}},
		{name = "v6 CWR on the second", v6 = true, edit = {at = 1, f = edit_cwr}, df = true, want = {1, 3}},
		{name = "v6 trailing bytes", v6 = true, edit = {at = 2, f = edit_trailing}, df = true, want = {2, 1, 1}},
		{name = "v6 window differs", v6 = true, edit = {at = 2, f = edit_window}, df = true, want = {2, 1, 1}},
		{name = "v6 urgent pointer differs", v6 = true, edit = {at = 2, f = edit_urg_ptr}, df = true, want = {2, 1, 1}},
		{name = "v6 bad TCP checksum, first", v6 = true, edit = {at = 0, f = edit_bad_csum}, df = true, want = {1, 3}},
		{name = "v6 bad TCP checksum, middle", v6 = true, edit = {at = 2, f = edit_bad_csum}, df = true, want = {2, 1, 1}},
		{name = "v6 bad TCP checksum, last", v6 = true, edit = {at = 3, f = edit_bad_csum}, df = true, want = {3, 1}},
	}
	for cs in cases {
		ts: [12]u8
		sp := base_ts(cs.v6, &ts)
		sp.df = cs.df
		if cs.ip_opt {
			sp.ip_opts = {1, 1, 1, 0}
		}
		segs := make_run(sp, 4, 1000, cs.edit)
		c := new_coalescer()
		res := run_coal(c, segs)
		got := segs_of(res)
		if !testing.expectf(t, same_ints(got, cs.want), "%s: outputs %v, want %v", cs.name, got, cs.want) {
			continue
		}
		check_conservation(t, segs, res, cs.name)
		for r in res {
			if r.segs > 1 {
				check_joined(t, r, cs.name)
			} else {
				testing.expectf(t, r.raw == {}, "%s: a plain packet has a header", cs.name)
				testing.expectf(t, r.n == 2, "%s: a plain packet has %d pieces", cs.name, r.n)
			}
		}
	}
}

// With `authenticated` a bad TCP checksum does not stop a run, a bad IPv4
// header checksum still does, and packets that are not joined have F_DATA_VALID.
@(test)
coal_authenticated :: proc(t: ^testing.T) {
	cases := []Case {
		{name = "none", edit = {at = -1}, df = true, want = {4}},
		{name = "bad TCP checksum, first", edit = {at = 0, f = edit_bad_csum}, df = true, want = {4}},
		{name = "bad TCP checksum, middle", edit = {at = 2, f = edit_bad_csum}, df = true, want = {4}},
		{name = "bad TCP checksum, all", edit = {at = 0, f = edit_bad_csum, sticky = true}, df = true, want = {4}},
		{name = "bad IPv4 header checksum, middle", edit = {at = 2, f = edit_bad_ip_csum}, df = true, want = {2, 1, 1}},
		{name = "SYN", edit = {at = 2, f = edit_syn}, df = true, want = {2, 1, 1}},
		{name = "IPv4 options", edit = {at = -1}, df = true, ip_opt = true, want = {1, 1, 1, 1}},
		{name = "v6 bad TCP checksum, middle", v6 = true, edit = {at = 2, f = edit_bad_csum}, df = true, want = {4}},
		{name = "v6 bad TCP checksum, all", v6 = true, edit = {at = 0, f = edit_bad_csum, sticky = true}, df = true, want = {4}},
	}
	valid := [VNET_HDR_LEN]u8{0 = F_DATA_VALID}
	for cs in cases {
		ts: [12]u8
		sp := base_ts(cs.v6, &ts)
		sp.df = cs.df
		if cs.ip_opt {
			sp.ip_opts = {1, 1, 1, 0}
		}
		segs := make_run(sp, 4, 1000, cs.edit)
		c := new(Coalescer, context.temp_allocator)
		c.authenticated = true
		coal_reset(c)
		testing.expectf(t, c.authenticated, "%s: coal_reset cleared the option", cs.name)
		res := run_coal(c, segs)
		got := segs_of(res)
		if !testing.expectf(t, same_ints(got, cs.want), "%s: outputs %v, want %v", cs.name, got, cs.want) {
			continue
		}
		check_conservation(t, segs, res, cs.name)
		for r in res {
			if r.segs > 1 {
				check_joined(t, r, cs.name)
			} else {
				testing.expectf(t, r.raw == valid, "%s: plain header %v", cs.name, r.raw)
				testing.expectf(t, r.n == 2, "%s: a plain packet has %d pieces", cs.name, r.n)
			}
		}
	}
	// Anything else also goes out as it is, with F_DATA_VALID.
	c := new(Coalescer, context.temp_allocator)
	c.authenticated = true
	sp := default_spec(false)
	sp.udp = true
	sp.payload = fill_payload(300)
	sp.bad_csum = true
	udp := build(&sp, make([]u8, 400, context.temp_allocator))
	res := run_coal(c, {udp})
	if testing.expect_value(t, len(res), 1) {
		testing.expect(t, res[0].raw == valid && string(res[0].flat) == string(udp), "UDP packet")
	}
}

// PSH on the last packet of a run: the joined packet has PSH, and an ordinary
// packet in the middle does not.
@(test)
coal_psh_and_flags :: proc(t: ^testing.T) {
	ts: [12]u8
	sp := base_ts(false, &ts)
	segs := make_run(sp, 4, 1000, {at = 3, f = edit_psh})
	c := new_coalescer()
	res := run_coal(c, segs)
	if testing.expect_value(t, len(res), 1) {
		testing.expect(t, res[0].flat[20 + 13] == TCP_ACK | TCP_PSH, "flags of the joined packet")
	}
	// CWR on the first: kept, and the ECN type flag is set.
	segs = make_run(sp, 3, 1000, {at = 0, f = edit_cwr})
	c = new_coalescer()
	res = run_coal(c, segs)
	if testing.expect_value(t, len(res), 1) {
		testing.expect(t, res[0].flat[20 + 13] == TCP_ACK | TCP_CWR, "CWR is kept")
		testing.expect(t, res[0].h.gso_type == GSO_TCPV4 | GSO_ECN, "ECN flag")
	}
}

@(test)
coal_limits :: proc(t: ^testing.T) {
	ts: [12]u8
	for v6 in ([2]bool{false, true}) {
		sp := base_ts(v6, &ts)
		// 64 packets at most.
		segs := make_run(sp, 70, 500)
		c := new_coalescer()
		res := run_coal(c, segs)
		testing.expectf(t, same_ints(segs_of(res), {64, 6}), "v6=%v: 70 small packets: %v", v6, segs_of(res))
		check_conservation(t, segs, res, "64 limit")
		// 65535 bytes at most: 46 * 1400 + 52 fits, 47 do not.
		segs = make_run(sp, 100, 1400)
		c = new_coalescer()
		res = run_coal(c, segs)
		testing.expectf(t, same_ints(segs_of(res), {46, 46, 8}), "v6=%v: 100 big packets: %v", v6, segs_of(res))
		for r in res {
			testing.expect(t, len(r.flat) <= 65535, "joined packet too long")
		}
		check_conservation(t, segs, res, "65535 limit")
		for r in res {
			if r.segs > 1 {
				check_joined(t, r, "limit")
			}
		}
	}
}

@(test)
coal_interleaved_flows :: proc(t: ^testing.T) {
	ts: [12]u8
	a := base_ts(false, &ts)
	b := a
	b.sport = 40001
	b.seq = 5_000_000
	ra := make_run(a, 10, 1000)
	rb := make_run(b, 10, 1000)
	mixed := make([][]u8, 20, context.temp_allocator)
	for i in 0 ..< 10 {
		mixed[2 * i] = ra[i]
		mixed[2 * i + 1] = rb[i]
	}
	c := new_coalescer()
	res := run_coal(c, mixed)
	testing.expectf(t, same_ints(segs_of(res), {10, 10}), "outputs %v", segs_of(res))
	// The flow that started first comes out first.
	if len(res) == 2 {
		testing.expect_value(t, flow_port(res[0].flat), u16(40000))
		testing.expect_value(t, flow_port(res[1].flat), u16(40001))
	}
	check_conservation(t, mixed, res, "interleaved")
	// With a reverse flow: data A, pure ACKs of the reverse flow B in between.
	ra = make_run(a, 10, 1000) // the first run was changed in place
	rev := default_spec(false)
	rev.src, rev.dst = a.dst, a.src
	rev.sport, rev.dport = a.dport, a.sport
	ackbuf := make([]u8, 200, context.temp_allocator)
	ack := build(&rev, ackbuf)
	mixed2 := make([dynamic][]u8, context.temp_allocator)
	for i in 0 ..< 10 {
		append(&mixed2, ra[i])
		append(&mixed2, ack)
	}
	c = new_coalescer()
	res = run_coal(c, mixed2[:])
	// The ACKs are a flow of their own: they come out at once and never end the
	// data run, which comes out last.
	testing.expectf(t, same_ints(segs_of(res), {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10}), "outputs %v", segs_of(res))
	total := 0
	for r in res {
		total += r.segs
	}
	testing.expect_value(t, total, 20)
}

// A packet of the same flow that cannot be joined ends the run before it is
// written, so the order inside the flow is kept.
@(test)
coal_order_in_flow :: proc(t: ^testing.T) {
	ts: [12]u8
	sp := base_ts(false, &ts)
	segs := make_run(sp, 5, 1000)
	// A pure ACK of the same flow between segment 1 and segment 2.
	ack := default_spec(false)
	ack.sport, ack.dport = sp.sport, sp.dport
	ack.seq = segs_seq(segs[1]) + 1000
	ack.flags = TCP_ACK
	abuf := make([]u8, 200, context.temp_allocator)
	ackp := build(&ack, abuf)
	in_order := [][]u8{segs[0], segs[1], ackp, segs[2], segs[3], segs[4]}
	c := new_coalescer()
	res := run_coal(c, in_order)
	if testing.expectf(t, same_ints(segs_of(res), {2, 1, 3}), "outputs %v", segs_of(res)) {
		testing.expect(t, len(payload_of(res[1].flat)) == 0, "the ACK comes second")
	}
	// A UDP packet and an ICMP packet of another flow come out at once, before
	// the open run.
	udp := default_spec(false)
	udp.udp = true
	udp.payload = fill_payload(100)
	ubuf := make([]u8, 300, context.temp_allocator)
	up := build(&udp, ubuf)
	segs = make_run(sp, 5, 1000) // the first run was changed in place
	in2 := [][]u8{segs[0], up, segs[1]}
	c = new_coalescer()
	res = run_coal(c, in2)
	testing.expectf(t, same_ints(segs_of(res), {1, 2}), "outputs %v", segs_of(res))
	if len(res) == 2 {
		testing.expect(t, res[0].flat[9] == PROTO_UDP, "the UDP packet does not wait")
	}
}

segs_seq :: proc(p: []u8) -> u32 {
	iphl := 20 if p[0] >> 4 == 4 else 40
	return be32(p[iphl + 4:])
}

@(test)
coal_table_overflow :: proc(t: ^testing.T) {
	ts: [12]u8
	base := base_ts(false, &ts)
	flows := 12
	runs := make([][][]u8, flows, context.temp_allocator)
	for f in 0 ..< flows {
		sp := base
		sp.sport = u16(41000 + f)
		sp.seq = u32(f * 1_000_000)
		runs[f] = make_run(sp, 3, 800)
	}
	// Segment 0 of every flow, then 1, then 2: more flows than entries.
	all := make([dynamic][]u8, context.temp_allocator)
	for k in 0 ..< 3 {
		for f in 0 ..< flows {
			append(&all, runs[f][k])
		}
	}
	c := new_coalescer()
	res := run_coal(c, all[:])
	check_conservation(t, all[:], res, "table overflow")
	// Exactly 8 flows fit: the 9th push ends the oldest run.
	for f in 0 ..< flows {
		sp := base
		sp.sport = u16(41000 + f)
		sp.seq = u32(f * 1_000_000)
		runs[f] = make_run(sp, 3, 800)
	}
	c = new_coalescer()
	got := make([dynamic]Result, context.temp_allocator)
	for f in 0 ..< 9 {
		testing.expect(t, coal_push(c, runs[f][0]), "push")
		drain(c, &got)
		if f < GRO_FLOWS {
			testing.expectf(t, len(got) == 0, "flow %d: output before the table is full", f)
		}
	}
	if testing.expect_value(t, len(got), 1) {
		testing.expect_value(t, flow_port(got[0].flat), u16(41000)) // the oldest
	}
	testing.expect(t, coal_pending(c), "pending")
	coal_flush(c)
	drain(c, &got)
	testing.expect_value(t, len(got), 9)
	testing.expect(t, !coal_pending(c), "not pending after the flush")
}

@(test)
coal_queue_full :: proc(t: ^testing.T) {
	udp := default_spec(false)
	udp.udp = true
	udp.payload = fill_payload(50)
	ubuf := make([]u8, 300, context.temp_allocator)
	up := build(&udp, ubuf)
	c := new_coalescer()
	pushed := 0
	for coal_push(c, up) {
		pushed += 1
		if pushed > 100 {
			break
		}
	}
	// The queue holds 16, a push needs room for two.
	testing.expect_value(t, pushed, GRO_OUT_CAP - 1)
	res := make([dynamic]Result, context.temp_allocator)
	drain(c, &res)
	testing.expect_value(t, len(res), GRO_OUT_CAP - 1)
	testing.expect(t, coal_push(c, up), "push after draining")

	// The flush with a full queue leaves runs open until there is room.
	ts: [12]u8
	base := base_ts(false, &ts)
	c = new_coalescer()
	res = make([dynamic]Result, context.temp_allocator)
	for f in 0 ..< GRO_FLOWS {
		sp := base
		sp.sport = u16(42000 + f)
		testing.expect(t, coal_push(c, make_run(sp, 1, 500)[0]), "open a run")
	}
	for _ in 0 ..< GRO_OUT_CAP - 1 {
		testing.expect(t, coal_push(c, up), "plain")
	}
	coal_flush(c)
	testing.expect(t, coal_pending(c), "runs still open")
	drain(c, &res)
	testing.expect_value(t, len(res), GRO_OUT_CAP)
	coal_flush(c)
	drain(c, &res)
	testing.expect_value(t, len(res), GRO_OUT_CAP + GRO_FLOWS - 1)
	testing.expect(t, !coal_pending(c), "nothing pending")
}

// Packets that are not TCP data, and garbage, are passed on as they are.
@(test)
coal_passthrough :: proc(t: ^testing.T) {
	c := new_coalescer()
	res := make([dynamic]Result, context.temp_allocator)
	junk := make([dynamic][]u8, context.temp_allocator)
	append(&junk, []u8{})
	for n in 1 ..< 70 {
		p := make([]u8, n, context.temp_allocator)
		for i in 0 ..< n {
			p[i] = u8(i * 31 + n)
		}
		append(&junk, p)
		q := make([]u8, n, context.temp_allocator)
		copy(q, p)
		q[0] = 0x45 // looks like IPv4
		if n > 9 {
			q[9] = PROTO_TCP
		}
		append(&junk, q)
		w := make([]u8, n, context.temp_allocator)
		copy(w, q)
		w[0] = 0x60
		if n > 6 {
			w[6] = PROTO_TCP
		}
		append(&junk, w)
	}
	for p in junk {
		testing.expect(t, coal_push(c, p), "push")
		drain(c, &res)
	}
	coal_flush(c)
	drain(c, &res)
	testing.expect_value(t, len(res), len(junk))
	for r, i in res {
		testing.expect(t, r.segs == 1 && r.raw == {}, "plain")
		testing.expect(t, string(r.flat) == string(junk[i]), "bytes changed")
	}
}

// Random sequences of mutated TCP packets of a few flows. Every packet comes
// out once. The splitter accepts every joined packet and gives right packets.
@(test)
coal_fuzz :: proc(t: ^testing.T) {
	r := Rng {
		s = 0xfeed,
	}
	ts: [12]u8
	for round in 0 ..< 400 {
		v6 := rng_n(&r, 2) == 0
		sp0 := base_ts(v6, &ts)
		sp0.df = rng_n(&r, 3) != 0
		flows := 1 + rng_n(&r, 4)
		seqs: [4]u32
		ids: [4]u16
		pkts := make([dynamic][]u8, context.temp_allocator)
		wrong_idx := make([dynamic]int, context.temp_allocator)
		n := 5 + rng_n(&r, 60)
		for _ in 0 ..< n {
			f := rng_n(&r, flows)
			sp := sp0
			sp.sport = u16(40000 + f)
			sp.seq = seqs[f]
			sp.id = ids[f]
			size := 1000 if rng_n(&r, 8) != 0 else rng_n(&r, 1200)
			sp.payload = fill_payload(size, round)
			// Mutations: now and then.
			switch rng_n(&r, 20) {
			case 0:
				sp.flags |= TCP_PSH
			case 1:
				sp.flags |= u8(1 << u32(rng_n(&r, 8)))
			case 2:
				sp.seq += u32(rng_n(&r, 100))
			case 3:
				sp.ttl = u8(rng_n(&r, 4))
			case 4:
				sp.topts = nil
			case 5:
				sp.id += u16(rng_n(&r, 3))
			case 6:
				sp.ack += 1
			case 7:
				sp.bad_csum = true
			case 8:
				sp.bad_ip_csum = true
			case 9:
				sp.window += 1
			}
			buf := make([]u8, size + 400, context.temp_allocator)
			p := build(&sp, buf)
			// A packet with one wrong checksum and nothing else done to it.
			wrong := (sp.bad_csum || sp.bad_ip_csum && !sp.v6) && size > 0
			// And now and then a damaged header.
			if rng_n(&r, 12) == 0 {
				p[rng_n(&r, min(len(p), 70))] = u8(rng_next(&r))
				wrong = false
			}
			if rng_n(&r, 40) == 0 {
				p = p[:rng_n(&r, len(p) + 1)]
				wrong = false
			}
			if wrong {
				append(&wrong_idx, len(pkts))
			}
			append(&pkts, p)
			seqs[f] = sp.seq + u32(size)
			ids[f] = sp.id + 1
		}
		// Copies, because the coalescer changes headers in place.
		orig := make([][]u8, len(pkts), context.temp_allocator)
		for p, i in pkts {
			orig[i] = make([]u8, len(p), context.temp_allocator)
			copy(orig[i], p)
		}
		c := new_coalescer()
		res := run_coal(c, pkts[:])
		total := 0
		bytes_out := 0
		for rs in res {
			total += rs.segs
			bytes_out += len(rs.flat)
			testing.expect_value(t, rs.bytes, len(rs.flat))
			if rs.segs > 1 {
				back, err := split_all(rs.h, rs.flat, 70000)
				testing.expectf(t, err == .None, "round %d: a joined packet is refused by the splitter: %v", round, err)
				testing.expectf(t, len(back) == rs.segs, "round %d: %d packets back, want %d", round, len(back), rs.segs)
				for b in back {
					v, why := verify(b)
					testing.expectf(t, v, "round %d: %s", round, why)
				}
			}
		}
		testing.expect_value(t, total, len(orig))
		// A packet with a wrong checksum is never joined: it comes out as it was.
		for i in wrong_idx {
			found := false
			for rs in res {
				if rs.segs == 1 && same_bytes_test(rs.flat, orig[i]) {
					found = true
					break
				}
			}
			testing.expectf(t, found, "round %d: packet %d has a wrong checksum and was joined or changed", round, i)
		}
		// Payload bytes are conserved (headers of joined packets go away).
		in_pay := 0
		out_pay := 0
		for p in orig {
			in_pay += len(p)
		}
		for rs in res {
			out_pay += len(rs.flat)
		}
		testing.expect(t, out_pay <= in_pay, "output has more bytes than the input")
		free_all(context.temp_allocator)
	}
}

// How fast is it? Only prints; no assertion.
@(test)
coal_speed :: proc(t: ^testing.T) {
	ts: [12]u8
	sp := base_ts(false, &ts)
	mss := 1348
	segs := make_run(sp, 45, mss)
	// The first packet is changed in place: keep its headers to put back.
	saved: [52]u8
	copy(saved[:], segs[0][:52])
	for auth in ([2]bool{false, true}) {
		c := new_coalescer()
		c.authenticated = auth
		rounds := 3000
		start := time.tick_now()
		out := 0
		for _ in 0 ..< rounds {
			copy(segs[0][:52], saved[:])
			for p in segs {
				coal_push(c, p)
				for {
					_, ok := coal_pop(c)
					if !ok {
						break
					}
					out += 1
				}
			}
			coal_flush(c)
			for {
				_, ok := coal_pop(c)
				if !ok {
					break
				}
				out += 1
			}
		}
		d := time.tick_since(start)
		fmt.printfln("coalesce (authenticated %v): %.1f ns per packet (%d packets in %d runs)", auth, f64(d) / f64(rounds * 45), rounds * 45, out)
	}
}
