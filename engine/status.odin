// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import cnet "core:net"
import "noir:proto/push"
import "noir:proto/session"

// The resident memory of the process in kilobytes, from /proc/self/statm.
// 0 if it cannot be read.
rss_kb :: proc() -> int {
	data, err := os.read_entire_file("/proc/self/statm", context.temp_allocator)
	if err != nil {
		return 0
	}
	fields := strings.fields(string(data), context.temp_allocator)
	if len(fields) < 2 {
		return 0
	}
	pages, _ := strconv.parse_int(fields[1])
	return pages * 4
}

state_text :: proc(d: ^Daemon) -> string {
	switch d.state {
	case .Idle:
		return "waiting" if !d.exit else "stopped"
	case .Tcp_Connecting, .Proxy_Connecting, .Tls_Handshaking, .Ws_Upgrading:
		return "connecting"
	case .Active:
		if !d.s_ok {
			return "ending"
		}
		#partial switch session.session_state(&d.s) {
		case .Up:
			return "up"
		case .Closing:
			return "closing"
		case .Connecting, .Handshaking:
			return "handshake"
		}
		return "ending"
	}
	return "?"
}

// One status block (what SIGUSR2 prints, and the last thing at exit).
log_status :: proc(d: ^Daemon, level: Level, what: string) {
	if !log_enabled(level) {
		return
	}
	dco_client_refresh(d)
	remote := ""
	if d.state != .Idle || d.s_ok {
		remote = cnet.endpoint_to_string(d.endpoint, context.temp_allocator)
	}
	cipher := "-"
	format := "-"
	peer := u32(0)
	etx, erx := u16(0), u16(0)
	if d.s_ok && d.up {
		cipher = push.cipher_name(session.session_cipher(&d.s))
		format = session.session_data_format_name(&d.s)
		peer = session.session_peer_id(&d.s)
		etx, erx = session.session_epochs(&d.s)
	}
	up_secs := 0
	if d.up {
		up_secs = int((event_now(d) - d.up_at) / time.Second)
	}
	logf(
		level,
		"%s: state=%s remote=%s proto=%s%s%s%s cipher=%s peer-id=%d format=%s epoch=%d/%d tun=%s up=%ds rekeys=%d%s rss=%dkB",
		what, state_text(d), remote if len(remote) > 0 else "-", proto_name(d.proto, d.tls),
		fmt.tprintf(" outer=%s", outer_text(d.outer)) if d.tls else "", proxy_status(d), ws_status(d), cipher, peer, format, int(etx), int(erx), tun_label(d), up_secs, d.rekey_count, fmt.tprintf(" outer-rekeys=%d", outer_rekeys(d)) if d.tls else "", rss_kb(),
	) // fmt: skip
	s := &d.stats
	logf(
		level,
		"%s: daemon attempts=%d connects=%d tun-read=%d pkts/%d bytes tun-write=%d pkts/%d bytes sent=%d pkts",
		what, s.attempts, s.connects, s.tun_read_pkts, s.tun_read_bytes, s.tun_write_pkts, s.tun_write_bytes, s.sent_pkts,
	) // fmt: skip
	logf(
		level,
		"%s: daemon drops ring=%d seal=%d not-up=%d tun-write=%d oversize=%d rx-no-tun=%d source=%d block-ipv6-tx=%d block-ipv6-rx=%d acl=%d; errors tun-read=%d send=%d recv=%d; send-blocked=%d; waiting=%d",
		what, s.drop_ring, s.drop_seal, s.drop_not_up, s.drop_tun_write, s.drop_oversize, s.drop_rx_not_up, s.drop_source, s.drop_block6_tx, s.drop_block6_rx, s.drop_acl,
		s.tun_read_errors, s.sock_send_errors, s.sock_recv_errors, s.sock_blocked, d.ring.count,
	) // fmt: skip
	off_sync_batches(&d.off, &d.rx_batch, {&d.tx_batch})
	off_status_line(level, &d.off, what)
	if d.wk != nil {
		logf(level, "%s: %s", what, pool_text(d.wk))
	}
	if d.s_ok {
		c := session.session_counters(&d.s)
		log_counters(level, &c)
	}
}

tun_label :: proc(d: ^Daemon) -> string {
	if !d.tun_open && !d.dco.dev {
		return "-"
	}
	return tun_name(d)
}

event_now :: proc(d: ^Daemon) -> time.Duration {
	return now_of(d)
}

// The counters of a session, in two lines.
log_counters :: proc(level: Level, c: ^session.Counters) {
	if !log_enabled(level) {
		return
	}
	logf(
		level,
		"session: link rx=%d pkts/%d bytes tx=%d pkts/%d bytes; control rx=%d tx=%d; data rx=%d tx=%d; tunnel rx=%d tx=%d; ping rx=%d tx=%d; rekeys=%d; epoch-adv-tx=%d epoch-adv-rx=%d",
		c.link_rx_pkts, c.link_rx_bytes, c.link_tx_pkts, c.link_tx_bytes, c.control_rx, c.control_tx,
		c.data_rx, c.data_tx, c.tunnel_rx, c.tunnel_tx, c.ping_rx, c.ping_tx, c.rekeys, c.epoch_adv_tx, c.epoch_adv_rx,
	) // fmt: skip
	logf(
		level,
		"session: drops opcode=%d short=%d sid=%d addr=%d peer-id=%d unwrap=%d wrap-replay=%d decode=%d key-id=%d reliable=%d no-key=%d data-epoch=%d data-tag=%d data-replay=%d data-payload=%d not-up=%d; events-lost=%d",
		c.drop_opcode, c.drop_short, c.drop_sid, c.drop_addr, c.drop_peer_id, c.drop_unwrap, c.drop_wrap_replay, c.drop_decode, c.drop_key_id,
		c.drop_reliable, c.drop_data_no_key, c.drop_data_epoch, c.drop_data_tag, c.drop_data_replay, c.drop_data_payload,
		c.drop_tunnel_state, c.events_dropped,
	) // fmt: skip
}
