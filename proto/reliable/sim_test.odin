// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package reliable

// Deterministic simulation: two channels joined by a fake lossy link and a manual
// clock. No real clock, no thread, so a seed always gives the same run.
//
// Each side plays the TLS layer too: it sends a byte stream and checks that the
// other side's stream arrives complete, in order, with no byte wrong. Both sides
// open with a reset packet (id 0, tag 7 or 8), like a real session.

import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"

// Build with -define:RELIABLE_SIM_REPORT=true to print one line per scenario.
SIM_REPORT :: #config(RELIABLE_SIM_REPORT, false)

@(private = "file")
SEC :: time.Second
@(private = "file")
MS :: time.Millisecond
@(private = "file")
TAG_DATA :: 4
@(private = "file")
TAG_RESET_C :: 7
@(private = "file")
TAG_RESET_S :: 8

@(private = "file")
Prng :: struct {
	state: u64,
}

// SplitMix64.
@(private = "file")
prng_next :: proc(p: ^Prng) -> u64 {
	p.state += 0x9E3779B97F4A7C15
	z := p.state
	z = (z ~ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ~ (z >> 27)) * 0x94D049BB133111EB
	return z ~ (z >> 31)
}

@(private = "file")
prng_below :: proc(p: ^Prng, n: u64) -> u64 {
	return prng_next(p) % n
}

// True with chance `per_mille` in 1000.
@(private = "file")
prng_chance :: proc(p: ^Prng, per_mille: int) -> bool {
	return int(prng_below(p, 1000)) < per_mille
}

@(private = "file")
Link :: struct {
	loss:       int, // chance in 1/1000 that a packet is lost
	dup:        int, // chance in 1/1000 that a packet is sent twice
	delay:      time.Duration, // fixed one-way delay
	jitter:     time.Duration, // extra random delay, 0..jitter (this reorders packets)
	reorder:    int, // chance in 1/1000 of a large extra delay
	reorder_by: time.Duration,
}

@(private = "file")
Scenario :: struct {
	seed:        u64,
	link:        Link,
	bytes_a:     int, // TLS stream A to B
	bytes_b:     int, // TLS stream B to A
	budget:      int, // payload bytes per packet
	timeout:     time.Duration, // 0 = default
	first_id:    u32, // first message id in both directions; not 0 means no reset opening (a reset has id 0)
	hand_window: time.Duration, // 0 = none
	max_time:    time.Duration, // give up the run at this clock value
}

@(private = "file")
Result :: struct {
	completed:          bool, // both streams delivered and every packet acked
	failure:            [2]Failure,
	data_done_at:       time.Duration, // both streams fully delivered
	quiet_at:           time.Duration, // and everything acked
	stats:              [2]Stats,
	link_sent:          int,
	link_lost:          int,
	link_duplicated:    int,
	backoff_violations: int, // non-fast retransmits sent earlier than the backoff allows
	stream_errors:      int, // delivered bytes or ids that are wrong
	max_attempt:        int,
	stalled:            bool, // nothing left to do but not finished
}

@(private = "file")
Sim_Pkt :: struct {
	to:   int,
	at:   time.Duration,
	seq:  int,
	kind: Tx_Kind,
	id:   u32,
	tag:  u8,
	acks: Ack_List,
	len:  int,
	data: [DEFAULT_MAX_PAYLOAD]u8,
}

@(private = "file")
End :: struct {
	ch:        Channel,
	out:       []u8,
	out_off:   int,
	in_off:    int,
	delivered: int, // messages delivered so far
	expect:    []u8, // what the peer sends
	last_at:   [dynamic]time.Duration, // last send time per id
}

@(private = "file")
Sim :: struct {
	sc:       Scenario,
	now:      time.Duration,
	rng:      Prng,
	ends:     [2]End,
	inflight: [dynamic]Sim_Pkt,
	seq:      int,
	res:      Result,
	timeout:  time.Duration,
}

@(private = "file")
make_stream :: proc(n: int, seed: u64) -> []u8 {
	rng := Prng{seed}
	b := make([]u8, n)
	for &x in b {
		x = u8(prng_next(&rng))
	}
	return b
}

// Hands every due packet of one end to the link.
@(private = "file")
sim_pump :: proc(s: ^Sim, e: int) {
	end := &s.ends[e]
	for end.out_off < len(end.out) && send_room(&end.ch) > 0 {
		n := send(&end.ch, end.out[end.out_off:], s.sc.budget, TAG_DATA, s.now)
		if n == 0 {
			break
		}
		end.out_off += n
	}
	for {
		tx, ok := poll(&end.ch, s.now)
		if !ok {
			break
		}
		sim_transmit(s, e, tx)
	}
}

@(private = "file")
sim_transmit :: proc(s: ^Sim, e: int, tx: Tx) {
	end := &s.ends[e]
	if tx.kind == .Control {
		idx := int(tx.id - s.sc.first_id)
		for len(end.last_at) <= idx {
			append(&end.last_at, -1)
		}
		s.res.max_attempt = max(s.res.max_attempt, tx.attempt)
		if tx.attempt > 1 && !tx.fast {
			// The wait after send k-1 is timeout * 2^(k-2), up to 64 times timeout.
			want := s.timeout
			for _ in 0 ..< tx.attempt - 2 {
				want = min(want * 2, s.timeout * BACKOFF_CAP_FACTOR)
			}
			if s.now - end.last_at[idx] < want {
				s.res.backoff_violations += 1
			}
		}
		end.last_at[idx] = s.now
	}
	link := s.sc.link
	copies := 1
	if prng_chance(&s.rng, link.dup) {
		copies = 2
		s.res.link_duplicated += 1
	}
	for _ in 0 ..< copies {
		s.res.link_sent += 1
		if prng_chance(&s.rng, link.loss) {
			s.res.link_lost += 1
			continue
		}
		delay := link.delay
		if link.jitter > 0 {
			delay += time.Duration(prng_below(&s.rng, u64(link.jitter)))
		}
		if prng_chance(&s.rng, link.reorder) {
			delay += link.reorder_by
		}
		s.seq += 1
		pkt := Sim_Pkt {
			to   = 1 - e,
			at   = s.now + delay,
			seq  = s.seq,
			kind = tx.kind,
			id   = tx.id,
			tag  = tx.tag,
			acks = tx.acks,
			len  = len(tx.payload),
		}
		copy(pkt.data[:], tx.payload)
		append(&s.inflight, pkt)
	}
}

// Gives one packet to its receiver and checks what comes out of the window.
@(private = "file")
sim_deliver :: proc(s: ^Sim, pkt: ^Sim_Pkt) {
	end := &s.ends[pkt.to]
	rx := Rx {
		acks       = pkt.acks,
		has_msg    = pkt.kind == .Control,
		id         = pkt.id,
		tag        = pkt.tag,
		hard_reset = pkt.tag == TAG_RESET_C || pkt.tag == TAG_RESET_S,
		payload    = pkt.data[:pkt.len],
	}
	receive(&end.ch, rx, s.now)
	for {
		d, ok := pop(&end.ch)
		if !ok {
			break
		}
		if d.id != s.sc.first_id + u32(end.delivered) {
			s.res.stream_errors += 1
		}
		end.delivered += 1
		if d.tag != TAG_DATA {
			continue // a reset: TLV data, not part of the TLS stream
		}
		room := len(end.expect) - end.in_off
		if len(d.payload) > room || mem.compare(d.payload, end.expect[end.in_off:][:len(d.payload)]) != 0 {
			s.res.stream_errors += 1
		}
		end.in_off += len(d.payload)
	}
	sim_pump(s, pkt.to)
}

@(private = "file")
simulate :: proc(t: ^testing.T, sc: Scenario) -> Result {
	s: Sim
	s.sc = sc
	s.rng = Prng{sc.seed}
	s.timeout = sc.timeout if sc.timeout != 0 else DEFAULT_TIMEOUT
	s.inflight.allocator = context.allocator
	defer delete(s.inflight)

	sid_a := Sid{1, 2, 3, 4, 5, 6, 7, 8}
	sid_b := Sid{9, 9, 9, 9, 9, 9, 9, 9}
	cfg := Config {
		timeout       = sc.timeout,
		hand_window   = sc.hand_window,
		send_first_id = sc.first_id,
		recv_first_id = sc.first_id,
	}
	cfg_a, cfg_b := cfg, cfg
	cfg_a.local_sid, cfg_a.peer_sid = sid_a, sid_b
	cfg_b.local_sid, cfg_b.peer_sid = sid_b, sid_a
	testing.expect_value(t, init(&s.ends[0].ch, cfg_a, 0), Init_Error.None)
	testing.expect_value(t, init(&s.ends[1].ch, cfg_b, 0), Init_Error.None)
	s.ends[0].out = make_stream(sc.bytes_a, sc.seed * 2 + 1)
	s.ends[1].out = make_stream(sc.bytes_b, sc.seed * 2 + 2)
	s.ends[0].expect = s.ends[1].out
	s.ends[1].expect = s.ends[0].out
	defer for &end in s.ends {
		destroy(&end.ch)
		delete(end.out)
		delete(end.last_at)
	}

	// Both sides open with a reset (only when ids start at 0).
	if sc.first_id == 0 {
		send_packet(&s.ends[0].ch, TAG_RESET_C, nil, 0)
		send_packet(&s.ends[1].ch, TAG_RESET_S, nil, 0)
	}

	limit := sc.max_time if sc.max_time != 0 else 3600 * SEC
	data_done := false
	for {
		sim_pump(&s, 0)
		sim_pump(&s, 1)

		a, b := &s.ends[0], &s.ends[1]
		streams_in := a.in_off == len(b.out) && b.in_off == len(a.out)
		if streams_in && !data_done {
			data_done = true
			s.res.data_done_at = s.now
		}
		if streams_in && a.out_off == len(a.out) && b.out_off == len(b.out) && all_acked(&a.ch) && all_acked(&b.ch) {
			s.res.completed = true
			s.res.quiet_at = s.now
			break
		}
		if error(&a.ch) != .None || error(&b.ch) != .None {
			break
		}

		// Advance to the next event: a packet arriving or a timer.
		next: time.Duration
		have := false
		for pkt in s.inflight {
			if !have || pkt.at < next {
				next, have = pkt.at, true
			}
		}
		for &end in s.ends {
			if at, ok := next_wakeup(&end.ch, s.now); ok && (!have || at < next) {
				next, have = at, true
			}
		}
		if !have {
			s.res.stalled = true
			break
		}
		if next > limit {
			break
		}
		s.now = max(s.now, next)

		// Deliver what has arrived, earliest first.
		for {
			best := -1
			for pkt, i in s.inflight {
				if pkt.at > s.now {
					continue
				}
				if best < 0 || pkt.at < s.inflight[best].at || (pkt.at == s.inflight[best].at && pkt.seq < s.inflight[best].seq) {
					best = i
				}
			}
			if best < 0 {
				break
			}
			pkt := s.inflight[best]
			unordered_remove(&s.inflight, best)
			sim_deliver(&s, &pkt)
		}
	}
	for &end, e in s.ends {
		s.res.stats[e] = end.ch.stats
		s.res.failure[e] = error(&end.ch)
	}
	return s.res
}

@(private = "file")
report :: proc(name: string, r: Result) {
	if SIM_REPORT {
		fmt.printfln(
			"%-34s data %8.2fs quiet %8.2fs | A: tx %3d ack %3d rexmit %3d fast %2d | B: tx %3d ack %3d rexmit %3d fast %2d | link sent %4d lost %4d dup %3d | max attempt %d",
			name,
			time.duration_seconds(r.data_done_at),
			time.duration_seconds(r.quiet_at),
			r.stats[0].tx_control,
			r.stats[0].tx_ack,
			r.stats[0].retransmits,
			r.stats[0].fast_retransmits,
			r.stats[1].tx_control,
			r.stats[1].tx_ack,
			r.stats[1].retransmits,
			r.stats[1].fast_retransmits,
			r.link_sent,
			r.link_lost,
			r.link_duplicated,
			r.max_attempt,
		)
	}
}

// 64 KiB each way: about the size of an ML-DSA handshake.
@(private = "file")
STREAM :: 64 * 1024

@(private = "file")
check_run :: proc(t: ^testing.T, r: Result, what: string, loc := #caller_location) {
	testing.expectf(t, r.completed, "%s: did not complete (failure %v, stalled %v)", what, r.failure, r.stalled, loc = loc)
	testing.expectf(t, r.stream_errors == 0, "%s: %d stream errors", what, r.stream_errors, loc = loc)
	testing.expectf(t, r.backoff_violations == 0, "%s: %d retransmits earlier than the backoff", what, r.backoff_violations, loc = loc)
	testing.expectf(t, r.failure == {.None, .None}, "%s: failure %v", what, r.failure, loc = loc)
}

// The base link: 20 ms each way, 30 ms of jitter (which reorders).
@(private = "file")
base_link :: proc(loss, dup: int) -> Link {
	return Link{loss = loss, dup = dup, delay = 20 * MS, jitter = 30 * MS}
}

@(test)
sim_lossless :: proc(t: ^testing.T) {
	// A plain delay, no jitter: packets arrive in the order they were sent.
	link := Link {
		delay = 20 * MS,
	}
	r := simulate(t, Scenario{seed = 1, link = link, bytes_a = STREAM, bytes_b = STREAM, budget = 1184})
	report("lossless", r)
	check_run(t, r, "lossless")
	// No loss: nothing is ever sent twice, and it all takes a few round trips.
	testing.expect_value(t, r.stats[0].retransmits, 0)
	testing.expect_value(t, r.stats[1].retransmits, 0)
	testing.expect_value(t, r.max_attempt, 1)
	testing.expect(t, r.quiet_at < 2 * SEC, "lossless transfer should take well under one timeout")
	// 65536 / 1184 = 56 data packets plus the reset.
	testing.expect_value(t, r.stats[0].tx_control, 57)
	testing.expect_value(t, r.stats[1].tx_control, 57)
}

@(private = "file")
Agg :: struct {
	runs:          int,
	retransmits:   [2]int,
	fast:          [2]int,
	tx:            [2]int,
	worst_time:    time.Duration,
	worst_ratio:   f64, // retransmits per first transmission, worst side of worst run
	worst_attempt: int,
}

// What a sweep must stay under.
@(private = "file")
Bounds :: struct {
	time:    time.Duration, // finish time of the slowest run
	ratio:   f64, // retransmits per first transmission, worst side of the worst run
	attempt: int, // sends of one packet
}

// Runs one scenario over `seeds` seeds and checks every run.
@(private = "file")
sweep :: proc(t: ^testing.T, name: string, sc: Scenario, seeds: int, bounds: Bounds, loc := #caller_location) -> Agg {
	agg: Agg
	for seed in 1 ..= seeds {
		sc := sc
		sc.seed = u64(seed)
		r := simulate(t, sc)
		check_run(t, r, name, loc)
		if seed == 1 {
			report(name, r)
		}
		agg.runs += 1
		for e in 0 ..< 2 {
			agg.retransmits[e] += r.stats[e].retransmits
			agg.fast[e] += r.stats[e].fast_retransmits
			agg.tx[e] += r.stats[e].tx_control
			first := r.stats[e].tx_control - r.stats[e].retransmits
			agg.worst_ratio = max(agg.worst_ratio, f64(r.stats[e].retransmits) / f64(max(first, 1)))
		}
		agg.worst_time = max(agg.worst_time, r.quiet_at)
		agg.worst_attempt = max(agg.worst_attempt, r.max_attempt)
	}
	if SIM_REPORT {
		fmt.printfln(
			"  %s over %d seeds: retransmits per run A %.1f B %.1f, worst finish %.1fs, worst rexmit ratio %.2f, worst attempt %d",
			name,
			seeds,
			f64(agg.retransmits[0]) / f64(seeds),
			f64(agg.retransmits[1]) / f64(seeds),
			time.duration_seconds(agg.worst_time),
			agg.worst_ratio,
			agg.worst_attempt,
		)
	}
	testing.expectf(t, agg.worst_time <= bounds.time, "%s: slowest run %v, bound %v", name, agg.worst_time, bounds.time, loc = loc)
	testing.expectf(t, agg.worst_ratio <= bounds.ratio, "%s: retransmit ratio %.2f, bound %.2f", name, agg.worst_ratio, bounds.ratio, loc = loc)
	testing.expectf(t, agg.worst_attempt <= bounds.attempt, "%s: %d sends of one packet, bound %d", name, agg.worst_attempt, bounds.attempt, loc = loc)
	return agg
}

@(test)
sim_loss_10_percent :: proc(t: ^testing.T) {
	sc := Scenario {
		link    = base_link(100, 0),
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 1184,
	}
	sweep(t, "loss 10%", sc, 20, Bounds{time = 120 * SEC, ratio = 1, attempt = 8})
}

@(test)
sim_loss_30_percent :: proc(t: ^testing.T) {
	sc := Scenario {
		link    = base_link(300, 0),
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 1184,
	}
	// The tail is long on purpose: a packet lost 8 times in a row waits
	// 2 + 4 + ... + 128 s. Nothing here is a hang.
	sweep(t, "loss 30%", sc, 20, Bounds{time = 1800 * SEC, ratio = 2, attempt = 25})
}

@(test)
sim_reorder_and_duplicates :: proc(t: ^testing.T) {
	// 5% loss, 20% of packets doubled, 10% delayed by 0.6 s on top of the jitter.
	link := Link {
		loss       = 50,
		dup        = 200,
		delay      = 20 * MS,
		jitter     = 200 * MS,
		reorder    = 100,
		reorder_by = 600 * MS,
	}
	sc := Scenario {
		link    = link,
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 1184,
	}
	sweep(t, "loss 5% dup 20% reorder", sc, 20, Bounds{time = 60 * SEC, ratio = 1, attempt = 8})
}

@(test)
sim_duplicates_and_reordering_only :: proc(t: ^testing.T) {
	link := Link {
		dup        = 500,
		delay      = 20 * MS,
		jitter     = 400 * MS,
		reorder    = 200,
		reorder_by = SEC,
	}
	sc := Scenario {
		link    = link,
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 1184,
	}
	// No packet is lost, but late packets cause some spurious fast retransmits.
	sweep(t, "dup 50% reorder only", sc, 20, Bounds{time = 30 * SEC, ratio = 0.5, attempt = 4})
}

@(test)
sim_id_wraparound_under_loss :: proc(t: ^testing.T) {
	sc := Scenario {
		link     = base_link(200, 100),
		bytes_a  = STREAM,
		bytes_b  = STREAM,
		budget   = 1184,
		first_id = 0xFFFFFFF0, // the ids wrap after 16 packets
	}
	sweep(t, "wraparound, loss 20% dup 10%", sc, 20, Bounds{time = 600 * SEC, ratio = 2, attempt = 20})
}

@(test)
sim_tls_crypt_ipv6_budget :: proc(t: ^testing.T) {
	sc := Scenario {
		link    = base_link(300, 50),
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = payload_budget(1250, WRAP_OVERHEAD_TLS_CRYPT, IP_UDP_OVERHEAD_V6),
	}
	testing.expect_value(t, sc.budget, 1108)
	sweep(t, "tls-crypt IPv6 budget, loss 30%", sc, 10, Bounds{time = 1800 * SEC, ratio = 2, attempt = 25})
}

@(test)
sim_many_small_packets :: proc(t: ^testing.T) {
	// A small budget generates 330 packets each way: the 6-wide window and the
	// "oldest unacked" distance rule are the limit.
	sc := Scenario {
		link    = base_link(100, 0),
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 200,
	}
	sweep(t, "budget 200, loss 10%", sc, 5, Bounds{time = 300 * SEC, ratio = 1, attempt = 8})
}

@(test)
sim_one_direction_only :: proc(t: ^testing.T) {
	// B has nothing to say after its reset; its acks are bare P_ACK packets.
	sc := Scenario {
		link    = base_link(150, 0),
		bytes_a = STREAM,
		bytes_b = 0,
		budget  = 1184,
	}
	sweep(t, "one direction, loss 15%", sc, 10, Bounds{time = 300 * SEC, ratio = 2, attempt = 12})
}

@(test)
sim_short_timeout :: proc(t: ^testing.T) {
	// tls-timeout 1: the schedule is checked against 1, 2, 4, ... 64 s.
	sc := Scenario {
		link    = base_link(300, 0),
		bytes_a = STREAM,
		bytes_b = STREAM,
		budget  = 1184,
		timeout = SEC,
	}
	sweep(t, "tls-timeout 1s, loss 30%", sc, 10, Bounds{time = 900 * SEC, ratio = 2, attempt = 25})
}

@(test)
sim_black_hole_gives_up :: proc(t: ^testing.T) {
	// Everything is lost. With a 60 s hand window each of the 6 packets in
	// flight is sent 5 times (at 0, 2, 6, 14, 30 s; the sixth would be at 62 s).
	sc := Scenario {
		seed        = 1,
		link        = Link{loss = 1000, delay = 20 * MS},
		bytes_a     = STREAM,
		bytes_b     = STREAM,
		budget      = 1184,
		hand_window = 60 * SEC,
	}
	r := simulate(t, sc)
	report("black hole, hand window 60s", r)
	testing.expect(t, !r.completed)
	testing.expect_value(t, r.failure[0], Failure.Hand_Window)
	testing.expect_value(t, r.failure[1], Failure.Hand_Window)
	testing.expect_value(t, r.stats[0].tx_control, 30)
	testing.expect_value(t, r.stats[1].tx_control, 30)
	testing.expect_value(t, r.max_attempt, 5)
	testing.expect_value(t, r.backoff_violations, 0)
	testing.expect_value(t, r.stats[0].tx_ack, 0)
}

@(test)
sim_black_hole_without_deadline_keeps_backing_off :: proc(t: ^testing.T) {
	// No hand window, no limit: after an hour each packet has been sent at
	// 0, 2, 6, 14, 30, 62, 126, 254, then every 128 s: 8 + (3600 - 254) / 128 = 34.
	sc := Scenario {
		seed     = 1,
		link     = Link{loss = 1000, delay = 20 * MS},
		bytes_a  = 2000,
		bytes_b  = 0,
		budget   = 1184,
		max_time = 3600 * SEC,
	}
	r := simulate(t, sc)
	testing.expect(t, !r.completed)
	testing.expect_value(t, r.failure[0], Failure.None)
	testing.expect_value(t, r.backoff_violations, 0)
	// A sends reset + 2 data packets; B sends its reset.
	testing.expect_value(t, r.stats[0].tx_control, 3 * 34)
	testing.expect_value(t, r.stats[1].tx_control, 34)
}
