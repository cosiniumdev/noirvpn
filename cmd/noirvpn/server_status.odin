// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:fmt"
import "core:sync"
import "core:time"
import net "noir:platform/net"
import "noir:proto/push"
import "noir:proto/session"
import "noir:server"

// What SIGUSR2 prints (and the last thing at exit): the totals, the drop
// counters, then one line for each client.

srv_log_status :: proc(d: ^Srv, level: Level, what: string) {
	if !log_enabled(level) {
		return
	}
	srv_dco_refresh_all(d)
	now := now_srv(d)
	up_secs := int((now - d.started) / time.Second)
	state := "running"
	if d.finished {
		state = "stopped"
	} else if d.stopping {
		state = "stopping"
	}
	logf(
		level,
		"%s: server state=%s up=%ds clients=%d/%d sessions=%d connects=%d disconnects=%d refused=%d handshake-failed=%d outer-tls-failed=%d kicks=%d tun=%s%s%s rss=%dkB",
		what, state, up_secs, srv_clients_up(d), d.n_conns, d.stats.sessions, d.stats.connects, d.stats.disconnects,
		d.stats.refused, d.stats.hs_failed, d.stats.outer_failed, d.stats.kicks, srv_tun_name(d),
		" tls-tun=" if d.dco.mixed else "", srv_tls_tun_name(d), rss_kb(),
	) // fmt: skip
	s := &d.stats
	logf(
		level,
		"%s: daemon tun-read=%d pkts/%d bytes tun-write=%d pkts/%d bytes to-clients=%d client-to-client=%d sent=%d pkts",
		what, s.tun_read_pkts, s.tun_read_bytes, s.tun_write_pkts, s.tun_write_bytes, s.from_tun_pkts, s.c2c_pkts, s.sent_pkts,
	) // fmt: skip
	logf(
		level,
		"%s: daemon drops no-session=%d conn-state=%d bad-opcode=%d oversize=%d stopping=%d conn-limit=%d preauth=%d seal=%d tx-busy=%d tcp-backlog=%d tun-write=%d block-ipv6-tx=%d block-ipv6-rx=%d; tcp-slow-closed=%d; errors tun-read=%d send=%d recv=%d; send-blocked=%d tun-paused=%d",
		what, s.drop_no_session, s.drop_conn_state, s.drop_bad_opcode, s.drop_oversize, s.drop_stopping, s.drop_conn_limit,
		s.drop_preauth, s.drop_seal, s.drop_tx_busy, s.drop_tcp_backlog, s.drop_tun_write, s.drop_block6_tx, s.drop_block6_rx, s.tcp_slow_closed,
		s.tun_read_errors, s.sock_send_errors, s.sock_recv_errors, s.sock_blocked, s.tun_paused,
	) // fmt: skip
	srv_sync_off(d)
	off_status_line(level, &d.off, what)
	if d.wk != nil {
		logf(level, "%s: %s", what, pool_text(d.wk))
	}
	if d.srv_ok {
		rc := &d.srv.reg.counters
		bad_src := "n/a"
		if srv_bad_source_known(d) {
			bad_src = fmt.tprintf("%d", rc[.Drop_Bad_Source])
		}
		logf(
			level,
			"%s: routing to-tun=%d to-peer=%d bad-packet=%d bad-source=%s no-route=%d loop=%d c2c=%d",
			what, rc[.To_Tun], rc[.To_Peer], rc[.Drop_Bad_Packet], bad_src, rc[.Drop_No_Route], rc[.Drop_Loop], rc[.Drop_C2C],
		) // fmt: skip
		pl := &d.srv.pools
		logf(
			level,
			"%s: pools v4-used=%d v4-remembered=%d v6-used=%d v6-remembered=%d peers=%d",
			what, server.pool_used(&pl.v4), server.pool_remembered(&pl.v4), server.pool_used(&pl.v6), server.pool_remembered(&pl.v6), d.srv.reg.peers.count,
		) // fmt: skip
		ps := &d.srv.pins
		logf(
			level,
			"%s: pins accepted=%d refused-unknown=%d refused-disabled=%d",
			what, sync.atomic_load(&ps.accepted), sync.atomic_load(&ps.refused_unknown), sync.atomic_load(&ps.refused_disabled),
		) // fmt: skip
	}
	// The counters of the sessions that ended, plus the ones that run.
	total := d.agg
	for c in d.conns {
		if c != nil && c.s_ok {
			counters_add(&total, session.session_counters(&c.s))
		}
	}
	log_counters(level, &total)
	for c in d.conns {
		if c != nil && c.up {
			srv_log_client(d, level, what, c, now)
		}
	}
}

// Brings the offload counters up to date from the UDP batches.
srv_sync_off :: proc(d: ^Srv) {
	txs: [MAX_LISTEN]^net.Batch
	n := 0
	for i in 0 ..< d.n_listen {
		if d.listeners[i].proto == .Udp {
			txs[n] = &d.listeners[i].tx_batch
			n += 1
		}
	}
	off_sync_batches(&d.off, &d.rx_batch, txs[:n])
}

srv_clients_up :: proc(d: ^Srv) -> (n: int) {
	for c in d.conns {
		if c != nil && c.up && !c.closing {
			n += 1
		}
	}
	return
}

srv_log_client :: proc(d: ^Srv, level: Level, what: string, c: ^Conn, now: time.Duration) {
	addrs4, addrs6 := "-", "-"
	if p := server.peers_get(&d.srv.reg.peers, c.h); p != nil {
		if p.has4 {
			addrs4 = ip4_text(p.vpn4)
		}
		if p.has6 {
			addrs6 = ip6_text(p.vpn6)
		}
	}
	etx, erx := session.session_epochs(&c.s)
	logf(
		level,
		"%s: client %s real=%s %s vpn=%s,%s cipher=%s peer-id=%d format=%s epoch=%d/%d in=%d pkts/%d bytes out=%d pkts/%d bytes drops=%d rekeys=%d connected=%ds ago",
		what, server.identity_str(&c.name), endpoint_text(c.ep), conn_proto(c), addrs4, addrs6,
		push.cipher_name(c.cipher), session.session_peer_id(&c.s), c.data_format, int(etx), int(erx),
		c.in_pkts, c.in_bytes, c.out_pkts, c.out_bytes,
		c.drops, c.rekeys, int((now - c.up_at) / time.Second),
	) // fmt: skip
}
