// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:os"
import "core:strings"
import net "noir:platform/net"
import "noir:platform/offload"
import "noir:platform/tun"

// Kernel offloads of the data path (client and server).
//
//	UDP GSO   many sealed datagrams in one sendmmsg entry (platform/net)
//	UDP GRO   one recvmmsg message holding many datagrams (platform/net)
//	tun       IFF_VNET_HDR: large TSO/USO packets are read from the tun and cut
//	          into ordinary packets before sealing (`offload.split_*`); received
//	          TCP segments are joined into large packets for one tun write
//	          (`offload.coal_*`). Link packets stay the same as without offloads.
//
// All on when the kernel has them. If it refuses one, the daemon uses the plain
// path for that part and logs it once (no error).
//
// Escape hatch (tests, fault finding): env NOIRVPN_NO_OFFLOAD, comma list of what
// to switch off: `gso`, `gro`, `tun`, `all`.

Off_Config :: struct {
	tun: bool,
	gso: bool,
	gro: bool,
}

// What is allowed. `off_load_config` sets it once at start.
OFF := Off_Config {
	tun = true,
	gso = true,
	gro = true,
}

// Reads NOIRVPN_NO_OFFLOAD. Unknown words are ignored.
off_load_config :: proc() {
	when ODIN_OS != .Linux {
		// wintun and Winsock, utun and the BSD sockets have none of them.
		OFF = {}
		return
	}
	buf: [128]u8
	text := os.get_env_buf(buf[:], "NOIRVPN_NO_OFFLOAD")
	OFF = off_parse_config(text)
}

off_parse_config :: proc(text: string) -> Off_Config {
	c := Off_Config {
		tun = true,
		gso = true,
		gro = true,
	}
	rest := text
	for len(rest) > 0 {
		word: string
		if i := strings.index_byte(rest, ','); i >= 0 {
			word, rest = rest[:i], rest[i + 1:]
		} else {
			word, rest = rest, ""
		}
		switch strings.trim_space(word) {
		case "all":
			c = {}
		case "tun":
			c.tun = false
		case "gso":
			c.gso = false
		case "gro":
			c.gro = false
		}
	}
	return c
}

// Offload counters, in `stats.get` (every u64 field is a counter there) and the
// status text. The first group shows what is on (1) or off (0); the rest count
// events.
Offload_Stats :: struct {
	// State.
	tun_vnet:           u64, // the tun device has the virtio header
	tun_tso:            u64, // and the kernel hands over TCP segmentation offload packets
	tun_uso:            u64, // and UDP ones
	udp_gso:            u64, // UDP sockets that send with GSO (the server: how many listeners)
	udp_gro:            u64, // UDP sockets that receive with GRO
	// tun -> link. A tun read gives one packet, or a large one that is cut.
	tun_reads:          u64, // reads that returned a packet
	tun_gso_reads:      u64, // of them: large packets
	tun_gso_segs:       u64, // packets they were cut into
	tun_split_errors:   u64, // large packets that could not be cut (dropped)
	// link -> tun.
	tun_writes:         u64, // write calls
	tun_coalesced:      u64, // of them: packets built from several
	tun_coalesced_segs: u64, // packets inside them
	tun_write_errors:   u64, // write calls the kernel refused
	// UDP send: datagrams, sendmmsg entries and calls.
	udp_tx_calls:       u64,
	udp_tx_entries:     u64,
	udp_tx_dgrams:      u64,
	udp_gso_entries:    u64, // entries with several datagrams
	udp_gso_dgrams:     u64, // datagrams in them
	udp_gso_fallbacks:  u64, // times the kernel refused GSO and sends went plain
	// UDP receive.
	udp_rx_calls:       u64,
	udp_rx_msgs:        u64, // messages recvmmsg returned
	udp_rx_dgrams:      u64, // datagrams in them
	udp_gro_msgs:       u64, // messages that held more than one
}

// The tun side of the data path as the callers see it.
Tun_Tx :: struct {
	coal: offload.Coalescer,
	// Joining is on. It goes off by itself if the kernel refuses a joined packet.
	on:   bool,
	// Room for copies of packets that are not in stable memory (see
	// `tun_tx_push`). Empty: such packets are written at once.
	arena:      []u8,
	arena_used: int,
	// Packets written / dropped by the last call, for the caller's own counters.
	wrote_pkts:  u64,
	wrote_bytes: u64,
	dropped:     u64,
}

// Bytes of the copy area of `Tun_Tx`: a round of a TCP stream read.
TUN_TX_ARENA :: 128 * 1024

// The largest read from a device with the virtio header: the header, and an IP
// packet of up to 65536 bytes.
TUN_BUF_SIZE :: tun.VNET_HDR_LEN + 65536 + 64

// Notes what the tun device came with.
off_note_tun :: proc(st: ^Offload_Stats, dev: ^tun.Device) {
	st.tun_vnet = u64(dev.vnet)
	st.tun_tso = u64(.Tso4 in dev.offloads || .Tso6 in dev.offloads)
	st.tun_uso = u64(.Uso4 in dev.offloads || .Uso6 in dev.offloads)
}

// Applies `OFF` to a UDP socket that `udp_open` created with `offload = true`.
off_sock :: proc(s: net.Socket) -> net.Socket {
	r := s
	if !OFF.gso {
		r.gso = false
	}
	if r.gro && !OFF.gro {
		r = net.udp_gro_disable(r)
	}
	return r
}

// The size of one message of the receive buffer when UDP GRO may be on: the
// kernel can give up to 64 KiB (many datagrams) in one message.
UDP_GRO_SLOT :: 65536
// Messages one `recvmmsg` takes when GRO may be on. A message can hold many
// datagrams, and then `rx_vlen` asks for few. On a link device that does not
// join datagrams each message holds one, and a read needs this many to give
// the tun write a full run of segments.
RX_MSGS_GRO :: 64

// The layout of the receive buffer: messages per call and bytes per message.
off_rx_layout :: proc() -> (msgs, slot: int) {
	if OFF.gro {
		return RX_MSGS_GRO, UDP_GRO_SLOT
	}
	return RX_BATCH, RX_SLOT
}

// The most datagrams one message of a receive buffer with `slot` bytes per
// message can hold: the kernel joins at most 64 with GRO.
rx_max_per_msg :: proc(slot: int) -> int {
	return 64 if slot >= UDP_GRO_SLOT else 1
}

// Messages of a read that the crypto workers have room for (`room` packets):
// each message may hold `rx_max_per_msg` datagrams. 0: do not read now.
rx_msgs_for_room :: proc(room, slot: int) -> int {
	return room / rx_max_per_msg(slot)
}

// How many messages to ask `recv_batch` for when `left` datagrams may still be
// taken this round. A GRO socket may give many datagrams per message, so the
// average of the last call (`per_msg`, at least 1) decides.
rx_vlen :: proc(cap, left, per_msg: int) -> int {
	per := max(per_msg, 1)
	return clamp((left + per - 1) / per, 1, cap)
}

// Pushes one packet for the tun. Written or dropped counts are added to
// `Tun_Tx.wrote_pkts` and the other counters; the caller takes and clears them.
// Needs a device with `vnet`.
//
// The coalescer keeps a slice of the packet until the run is written, so the
// packet must stay unchanged until `tun_tx_flush`. Memory inside `stable` (the
// receive buffer; the next read overwrites it only after the flush) is safe. A
// packet outside it (a reassembled TCP frame, memory the session reuses) is
// copied to the arena first.
tun_tx_push :: proc(dev: ^tun.Device, t: ^Tun_Tx, st: ^Offload_Stats, pkt: []u8, stable: []u8) {
	p := pkt
	if !inside(pkt, stable) {
		if len(t.arena) == 0 || len(pkt) > len(t.arena) {
			// No copy area: write it at once, with all open runs.
			tun_tx_push_one(dev, t, st, pkt)
			tun_tx_flush(dev, t, st)
			return
		}
		if t.arena_used + len(pkt) > len(t.arena) {
			tun_tx_flush(dev, t, st)
		}
		p = t.arena[t.arena_used:][:len(pkt)]
		copy(p, pkt)
		t.arena_used += len(pkt)
	}
	tun_tx_push_one(dev, t, st, p)
}

@(private)
tun_tx_push_one :: proc(dev: ^tun.Device, t: ^Tun_Tx, st: ^Offload_Stats, pkt: []u8) {
	if !offload.coal_push(&t.coal, pkt) {
		tun_tx_drain(dev, t, st)
		if !offload.coal_push(&t.coal, pkt) {
			t.dropped += 1
			return
		}
	}
	tun_tx_drain(dev, t, st)
}

// Is all of `p` in memory of `region`?
inside :: proc(p, region: []u8) -> bool {
	if len(p) == 0 {
		return true
	}
	a, b := uintptr(raw_data(p)), uintptr(raw_data(region))
	return a >= b && a + uintptr(len(p)) <= b + uintptr(len(region))
}

// The end of a batch: writes the open runs too. Call it before the memory of the
// packets is reused.
tun_tx_flush :: proc(dev: ^tun.Device, t: ^Tun_Tx, st: ^Offload_Stats) {
	for {
		offload.coal_flush(&t.coal)
		tun_tx_drain(dev, t, st)
		if !offload.coal_pending(&t.coal) {
			// Everything is written: the copies are free again.
			t.arena_used = 0
			return
		}
	}
}

// Writes the packets that are ready.
@(private)
tun_tx_drain :: proc(dev: ^tun.Device, t: ^Tun_Tx, st: ^Offload_Stats) {
	for {
		o, ok := offload.coal_pop(&t.coal)
		if !ok {
			return
		}
		err := tun.write_v(dev, o.pieces[:o.n])
		if err != .None {
			// The tun queue is full, or the interface is down: the packet is lost.
			t.dropped += u64(o.segs)
			st.tun_write_errors += 1
			if o.segs > 1 && (err == .Invalid || err == .Message_Too_Long) {
				// The kernel does not take our joined packets: stop building them.
				t.on = false
				logf(.Warn, "the tun device refused a joined packet (%v), so joined writes are now off", err)
			}
			continue
		}
		st.tun_writes += 1
		if o.segs > 1 {
			st.tun_coalesced += 1
			st.tun_coalesced_segs += u64(o.segs)
		}
		t.wrote_pkts += u64(o.segs)
		t.wrote_bytes += u64(o.bytes)
	}
}

// Copies the counters of the UDP batches into the stats. Call it with the
// receive batch and the send batches of the daemon before the stats are read.
off_sync_batches :: proc(st: ^Offload_Stats, rx: ^net.Batch, txs: []^net.Batch) {
	st.udp_rx_calls = rx.rx_calls
	st.udp_rx_msgs = rx.rx_msgs
	st.udp_rx_dgrams = rx.rx_dgrams
	st.udp_gro_msgs = rx.rx_gro_msgs
	st.udp_tx_calls, st.udp_tx_entries, st.udp_tx_dgrams = 0, 0, 0
	st.udp_gso_entries, st.udp_gso_dgrams = 0, 0
	for b in txs {
		st.udp_tx_calls += b.tx_calls
		st.udp_tx_entries += b.tx_msgs
		st.udp_tx_dgrams += b.tx_dgrams
		st.udp_gso_entries += b.gso_msgs
		st.udp_gso_dgrams += b.gso_dgrams
	}
}

// One line for the status text.
off_status_line :: proc(level: Level, st: ^Offload_Stats, what: string) {
	logf(
		level,
		"%s: offload tun-vnet=%d tso=%d uso=%d udp-gso=%d udp-gro=%d; tun-reads=%d large=%d cut-into=%d split-errors=%d; tun-writes=%d joined=%d of=%d errors=%d; udp-tx calls=%d entries=%d datagrams=%d gso-entries=%d in=%d fallbacks=%d; udp-rx calls=%d messages=%d datagrams=%d coalesced=%d",
		what, st.tun_vnet, st.tun_tso, st.tun_uso, st.udp_gso, st.udp_gro,
		st.tun_reads, st.tun_gso_reads, st.tun_gso_segs, st.tun_split_errors,
		st.tun_writes, st.tun_coalesced, st.tun_coalesced_segs, st.tun_write_errors,
		st.udp_tx_calls, st.udp_tx_entries, st.udp_tx_dgrams, st.udp_gso_entries, st.udp_gso_dgrams, st.udp_gso_fallbacks,
		st.udp_rx_calls, st.udp_rx_msgs, st.udp_rx_dgrams, st.udp_gro_msgs,
	) // fmt: skip
}
