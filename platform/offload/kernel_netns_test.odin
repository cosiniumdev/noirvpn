// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package offload

import "core:fmt"
import "core:os"
import "core:sys/linux"
import "core:testing"
import "core:time"
import "noir:platform/sysnet"
import "noir:platform/tun"

// Tests of this package against a real kernel. They create tun devices and
// change sysctls. So they build only with -define:NOIR_NETNS_TESTS=true and
// run only in a private network namespace (platform/run-netns-tests.sh, which
// does `unshare -rn`).
//
//	read side   the kernel gives plain packets with partial checksums, USO
//	            packets and TSO packets of a real TCP stream. Each goes
//	            through `split_*` and is checked byte by byte.
//	write side  a joined packet from the coalescer goes to the kernel. The
//	            kernel forwards it to a device without offloads, which cuts it
//	            into segments again. The segments are checked.
NETNS :: #config(NOIR_NETNS_TESTS, false)

// True when this process is in a user namespace that is not the initial one
// (see platform/tun). The initial namespace maps the whole uid range.
in_private_userns :: proc() -> bool {
	fd, e := linux.open("/proc/self/uid_map", {.CLOEXEC})
	if e != .NONE {
		return false
	}
	defer linux.close(fd)
	buf: [128]u8
	n, re := linux.read(fd, buf[:])
	if re != .NONE || n <= 0 {
		return false
	}
	text := string(buf[:n])
	for i in 0 ..< len(text) - 9 {
		if text[i:i + 10] == "4294967295" {
			return false
		}
	}
	return true
}

log_note :: proc(format: string, args: ..any) {
	fmt.printfln(format, ..args)
}

// Two tun devices in the private namespace: `ktun0` with the offloads (we
// play the VPN client on it) and `ktun1` without (the kernel forwards to it).
Lab :: struct {
	d0:   tun.Device,
	d1:   tun.Device,
	fd0:  linux.Fd,
	fd1:  linux.Fd,
	conn: sysnet.Conn,
}

lab_close :: proc(l: ^Lab) {
	tun.close(&l.d0)
	tun.close(&l.d1)
	sysnet.close(&l.conn)
}

sysctl :: proc(path, value: string) -> bool {
	return os.write_entire_file(path, transmute([]u8)value) == nil
}

lab_setup :: proc(t: ^testing.T, l: ^Lab) -> bool {
	err: tun.Error
	l.d0, err = tun.open({name = "ktun0", offload = true})
	if !testing.expect_value(t, err, tun.Error.None) {
		return false
	}
	l.d1, err = tun.open({name = "ktun1"})
	if !testing.expect_value(t, err, tun.Error.None) {
		tun.close(&l.d0)
		return false
	}
	if !l.d0.vnet || .Tso4 not_in l.d0.offloads {
		testing.expect(t, false, "this kernel does not take the virtio header on a tun device")
		tun.close(&l.d0)
		tun.close(&l.d1)
		return false
	}
	l.fd0, l.fd1 = linux.Fd(l.d0.fd), linux.Fd(l.d1.fd)
	serr: sysnet.Error
	l.conn, serr = sysnet.open()
	if !testing.expect_value(t, serr, sysnet.Error.None) {
		tun.close(&l.d0)
		tun.close(&l.d1)
		return false
	}
	c := &l.conn
	ok := true
	for spec in ([2]struct {
			name: string,
			a4:   sysnet.IP4_Address,
			a6:   sysnet.IP6_Address,
		}{{"ktun0", {10, 8, 0, 1}, {0xfd08, 0, 0, 0, 0, 0, 0, 1}}, {"ktun1", {10, 9, 0, 1}, {0xfd09, 0, 0, 0, 0, 0, 0, 1}}}) {
		li, lerr := sysnet.link_get(c, spec.name)
		ok &&= testing.expect_value(t, lerr, sysnet.Error.None)
		ok &&= testing.expect_value(t, sysnet.link_set_mtu(c, li.index, 1400), sysnet.Error.None)
		ok &&= testing.expect_value(t, sysnet.link_set_up(c, li.index), sysnet.Error.None)
		ok &&= testing.expect_value(t, sysnet.addr_add(c, li.index, spec.a4, 24), sysnet.Error.None)
		ok &&= testing.expect_value(t, sysnet.addr_add(c, li.index, spec.a6, 64), sysnet.Error.None)
	}
	ok &&= sysctl("/proc/sys/net/ipv4/ip_forward", "1")
	ok &&= sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	for dev in ([]string{"all", "default", "ktun0", "ktun1"}) {
		sysctl(fmt.tprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", dev), "0")
	}
	if !ok {
		lab_close(l)
	}
	return ok
}

// Reads one packet (with the virtio header if `vnet`). Waits up to `ms`.
read_pkt :: proc(fd: linux.Fd, buf: []u8, ms: i32) -> (n: int, ok: bool) {
	fds := [1]linux.Poll_Fd{{fd = fd, events = {.IN}}}
	r, _ := linux.poll(fds[:], ms)
	if r <= 0 {
		return 0, false
	}
	got, e := linux.read(fd, buf)
	if e != .NONE {
		return 0, false
	}
	return got, true
}

drain_fd :: proc(fd: linux.Fd) {
	buf: [70000]u8
	for {
		if _, ok := read_pkt(fd, buf[:], 20); !ok {
			return
		}
	}
}

// Reads until a packet of `proto` and destination port `port` comes.
read_flow :: proc(fd: linux.Fd, buf: []u8, proto: u8, v6: bool, port: u16, ms: i32) -> (n: int, ok: bool) {
	for _ in 0 ..< 50 {
		got, rok := read_pkt(fd, buf, ms)
		if !rok {
			return 0, false
		}
		p := buf[VNET_HDR_LEN:got]
		if len(p) < 48 || (p[0] >> 4 == 6) != v6 {
			continue
		}
		pr := p[6] if v6 else p[9]
		ip := pkt_iphl(p)
		if pr == proto && be16(p[ip + 2:]) == port {
			return got, true
		}
	}
	return 0, false
}

write_pkt :: proc(fd: linux.Fd, hdr: Vnet_Hdr, pkt: []u8, vnet: bool) -> bool {
	buf := make([]u8, len(pkt) + VNET_HDR_LEN, context.temp_allocator)
	off := 0
	if vnet {
		vnet_encode(buf, hdr)
		off = VNET_HDR_LEN
	}
	copy(buf[off:], pkt)
	n, e := linux.write(fd, buf[:off + len(pkt)])
	if e != .NONE || n != off + len(pkt) {
		log_note("write: %v, %d of %d", e, n, off + len(pkt))
		return false
	}
	return true
}

pkt_iphl :: proc(p: []u8) -> int {
	return 40 if p[0] >> 4 == 6 else int(p[0] & 0xf) * 4
}

peer_spec :: proc(v6: bool, dst_net: int) -> Spec {
	sp := default_spec(v6)
	if v6 {
		sp.src = {0xfd, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		sp.dst = {0xfd, u8(dst_net), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		if dst_net == 8 {
			sp.dst[15] = 1
		}
	} else {
		sp.src = {0 = 10, 1 = 8, 2 = 0, 3 = 2}
		sp.dst = {0 = 10, 1 = u8(dst_net), 2 = 0, 3 = 1 if dst_net == 8 else 2}
	}
	return sp
}

// Kernel -> us: plain packets with partial checksums, USO, and TSO of a real
// TCP stream. Everything goes through `split_*` and is checked.
read_side :: proc(t: ^testing.T, fd0: linux.Fd, v6: bool) {
	label := "v6" if v6 else "v4"
	buf := make([]u8, 70000, context.temp_allocator)

	// --- a UDP packet with a partial checksum
	af: linux.Address_Family = .INET6 if v6 else .INET
	us, _ := linux.socket(af, .DGRAM, {.NONBLOCK}, .UDP)
	dst4 := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(9),
		sin_addr   = {10, 8, 0, 2},
	}
	dst6 := linux.Sock_Addr_In6 {
		sin6_family = .INET6,
		sin6_port   = u16be(9),
		sin6_addr   = {0xfd, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	data := fill_payload(5200)
	send_to :: proc(us: linux.Fd, v6: bool, d4: ^linux.Sock_Addr_In, d6: ^linux.Sock_Addr_In6, b: []u8) {
		if v6 {
			linux.sendto(us, b, {}, d6)
		} else {
			linux.sendto(us, b, {}, d4)
		}
	}
	drain_fd(fd0)
	send_to(us, v6, &dst4, &dst6, data[:100])
	n, ok := read_flow(fd0, buf, PROTO_UDP, v6, 9, 1000)
	if !testing.expectf(t, ok, "%s: no UDP packet", label) {
		return
	}
	h, _ := vnet_decode(buf)
	pkt := buf[VNET_HDR_LEN:n]
	log_note("%s udp: hdr %v len %d", label, h, len(pkt))
	got, err := split_all(h, pkt, 2000)
	testing.expect_value(t, err, Error.None)
	if len(got) == 1 {
		v, why := verify(got[0])
		testing.expectf(t, v, "%s: plain UDP completed: %s", label, why)
	}

	// --- USO
	one: i32 = 1000
	linux.setsockopt_base(us, 17, 103, &one)
	send_to(us, v6, &dst4, &dst6, data)
	n, ok = read_flow(fd0, buf, PROTO_UDP, v6, 9, 1000)
	if !testing.expectf(t, ok, "%s: no USO packet", label) {
		return
	}
	h, _ = vnet_decode(buf)
	pkt = buf[VNET_HDR_LEN:n]
	log_note("%s uso: hdr %v len %d", label, h, len(pkt))
	got, err = split_all(h, pkt, 2000)
	testing.expect_value(t, err, Error.None)
	if h.gso_type == GSO_UDP_L4 {
		testing.expect_value(t, len(got), 6)
	} else {
		log_note("%s: the kernel did not hand over a USO packet (gso_type %d)", label, h.gso_type)
	}
	all := make([dynamic]u8, context.temp_allocator)
	for g in got {
		v, why := verify(g)
		testing.expectf(t, v, "%s: USO segment: %s", label, why)
		iphl := pkt_iphl(g)
		append(&all, ..g[iphl + 8:])
	}
	testing.expectf(t, string(all[:]) == string(data), "%s: USO payload differs (%d bytes)", label, len(all))
	linux.close(us)
	drain_fd(fd0)

	// --- a TCP stream
	app, _ := linux.socket(af, .STREAM, {.NONBLOCK}, .TCP)
	c4 := dst4
	c4.sin_port = u16be(5201)
	c6 := dst6
	c6.sin6_port = u16be(5201)
	if v6 {
		linux.connect(app, &c6)
	} else {
		linux.connect(app, &c4)
	}
	var_syn: []u8
	for _ in 0 ..< 10 {
		n, ok = read_flow(fd0, buf, PROTO_TCP, v6, 5201, 1000)
		if !ok {
			break
		}
		p := buf[VNET_HDR_LEN:n]
		iphl := pkt_iphl(p)
		if p[iphl + 13] & TCP_SYN != 0 {
			var_syn = make([]u8, len(p), context.temp_allocator)
			copy(var_syn, p)
			break
		}
	}
	if !testing.expectf(t, var_syn != nil, "%s: no SYN", label) {
		return
	}
	iphl := pkt_iphl(var_syn)
	cport := be16(var_syn[iphl:])
	sport := be16(var_syn[iphl + 2:])
	cseq := be32(var_syn[iphl + 4:])
	sp := peer_spec(v6, 8)
	sp.sport, sp.dport = sport, cport
	sp.seq = 7000
	sp.ack = cseq + 1
	sp.flags = TCP_SYN | TCP_ACK
	sp.window = 65535
	mssopt := [4]u8{2, 4, 0x05, 0x50}
	sp.topts = mssopt[:]
	synack := build(&sp, make([]u8, 200, context.temp_allocator))
	testing.expect(t, write_pkt(fd0, {}, synack, true), "write SYN-ACK")

	total := 400000
	data = fill_payload(total, 5)
	sent := 0
	expect_seq := cseq + 1
	rx := make([dynamic]u8, context.temp_allocator)
	gso_reads, plain_reads := 0, 0
	conv_ok, conv_bad := 0, 0
	start := time.tick_now()
	for len(rx) < total && time.tick_since(start) < 6 * time.Second {
		if sent < total {
			k, e := linux.send(app, data[sent:], {.DONTWAIT})
			if e == .NONE {
				sent += k
			}
		}
		n, ok = read_flow(fd0, buf, PROTO_TCP, v6, 5201, 50)
		if !ok {
			continue
		}
		hh, _ := vnet_decode(buf)
		p := buf[VNET_HDR_LEN:n]
		ip := pkt_iphl(p)
		if len(p) <= ip + 20 || p[ip + 13] & TCP_SYN != 0 {
			continue
		}
		tcphl := int(p[ip + 12] >> 4) * 4
		if len(p) <= ip + tcphl {
			continue
		}
		if hh.gso_type != GSO_NONE {
			gso_reads += 1
			// The convention for the field in a TSO packet: the pseudo-header sum
			// with the length of the whole packet, not inverted.
			ps := naive_fold(naive_pseudo(p, ip, v6, PROTO_TCP))
			if be16(p[ip + 16:]) == ps {
				conv_ok += 1
			} else {
				conv_bad += 1
			}
		} else {
			plain_reads += 1
		}
		segs, serr := split_all(hh, p, 2000)
		if !testing.expectf(t, serr == .None, "%s: TCP packet refused: %v hdr %v", label, serr, hh) {
			return
		}
		for g in segs {
			v, why := verify(g)
			testing.expectf(t, v, "%s: TCP segment: %s", label, why)
			gi := pkt_iphl(g)
			gt := int(g[gi + 12] >> 4) * 4
			testing.expectf(t, be32(g[gi + 4:]) == expect_seq, "%s: seq %d, want %d", label, be32(g[gi + 4:]), expect_seq)
			append(&rx, ..g[gi + gt:])
			expect_seq += u32(len(g) - gi - gt)
		}
		// Acknowledge.
		ack := peer_spec(v6, 8)
		ack.sport, ack.dport = sport, cport
		ack.seq = 7001
		ack.ack = expect_seq
		ack.flags = TCP_ACK
		ack.window = 65535
		ab := build(&ack, make([]u8, 200, context.temp_allocator))
		write_pkt(fd0, {}, ab, true)
	}
	log_note("%s tcp: received %d of %d bytes; %d TSO reads, %d plain reads; field convention ok %d bad %d", label, len(rx), total, gso_reads, plain_reads, conv_ok, conv_bad)
	testing.expectf(t, len(rx) == total && string(rx[:]) == string(data), "%s: stream differs", label)
	testing.expect(t, gso_reads > 0, "no TSO packet seen")
	testing.expect_value(t, conv_bad, 0)
	linux.close(app)
	drain_fd(fd0)
}

// Us -> kernel: a joined packet with a partial checksum goes to the kernel,
// which forwards it to a device without offloads and so cuts it up.
write_side :: proc(t: ^testing.T, fd0, fd1: linux.Fd, v6: bool, cwr: bool) {
	label := fmt.tprintf("%s cwr=%v", "v6" if v6 else "v4", cwr)
	mss := 1300
	n := 20
	sp := peer_spec(v6, 9)
	sp.sport, sp.dport = 40000, 5201
	sp.seq = 0xfffff000 // the sequence number wraps in the middle
	sp.flags = TCP_ACK
	ts := ts_options(111, 222)
	sp.topts = ts[:]
	segs := make([][]u8, n, context.temp_allocator)
	pay := fill_payload(mss * n, 9)
	for k in 0 ..< n {
		s := sp
		s.seq = sp.seq + u32(k * mss)
		s.id = sp.id + u16(k)
		s.payload = pay[k * mss:][:mss]
		if k == 0 && cwr {
			s.flags |= TCP_CWR
		}
		if k == n - 1 {
			s.flags |= TCP_PSH
		}
		segs[k] = build(&s, make([]u8, 2000, context.temp_allocator))
	}
	c := new_coalescer()
	var_res := run_coal(c, segs)
	if !testing.expectf(t, len(var_res) == 1, "%s: %d outputs", label, len(var_res)) {
		return
	}
	r := var_res[0]
	drain_fd(fd1)
	testing.expect(t, write_pkt(fd0, r.h, r.flat, true), "write the joined packet")
	buf := make([]u8, 3000, context.temp_allocator)
	got := make([dynamic]u8, context.temp_allocator)
	cnt := 0
	expect_seq := sp.seq
	for cnt < n {
		m, ok := read_pkt(fd1, buf, 1000)
		if !ok {
			break
		}
		p := buf[:m]
		if len(p) < 60 || (p[6] if v6 else p[9]) != PROTO_TCP {
			log_note("%s: skipped a %d byte packet", label, len(p))
			continue
		}
		v, why := verify(p)
		testing.expectf(t, v, "%s: forwarded segment %d: %s", label, cnt, why)
		ip := pkt_iphl(p)
		tcphl := int(p[ip + 12] >> 4) * 4
		testing.expectf(t, be32(p[ip + 4:]) == expect_seq, "%s: seq %d", label, cnt)
		fl := p[ip + 13]
		testing.expectf(t, (fl & TCP_CWR != 0) == (cwr && cnt == 0), "%s: CWR on segment %d", label, cnt)
		testing.expectf(t, (fl & TCP_PSH != 0) == (cnt == n - 1), "%s: PSH on segment %d", label, cnt)
		append(&got, ..p[ip + tcphl:])
		expect_seq += u32(m - ip - tcphl)
		cnt += 1
	}
	testing.expectf(t, cnt == n, "%s: %d segments came out, want %d", label, cnt, n)
	testing.expectf(t, string(got[:]) == string(pay), "%s: payload differs", label)
	log_note("%s: joined packet of %d bytes was accepted and cut into %d segments, all checksums right", label, len(r.flat), cnt)
}

when NETNS {

	@(test)
	netns_kernel_offload_round_trip :: proc(t: ^testing.T) {
		if !in_private_userns() {
			testing.expect(t, false, "not in a private user namespace: run platform/run-netns-tests.sh")
			return
		}
		lab: Lab
		if !lab_setup(t, &lab) {
			return
		}
		defer lab_close(&lab)
		for v6 in ([2]bool{false, true}) {
			read_side(t, lab.fd0, v6)
			for cwr in ([2]bool{false, true}) {
				write_side(t, lab.fd0, lab.fd1, v6, cwr)
			}
		}
	}

}
