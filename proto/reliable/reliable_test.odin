// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package reliable

import "core:mem"
import "core:testing"
import "core:time"

@(private = "file")
SID_A :: Sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
@(private = "file")
SID_B :: Sid{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
@(private = "file")
SEC :: time.Second

// Opcode stand-ins for the opaque tag.
@(private = "file")
TAG_DATA :: 4
@(private = "file")
TAG_RESET_C :: 7
@(private = "file")
TAG_RESET_S :: 8

// Two channels that know each other's sids. A is the client side.
@(private = "file")
Pair :: struct {
	a, b: Channel,
}

@(private = "file")
pair_init :: proc(t: ^testing.T, p: ^Pair, cfg: Config = {}) {
	ca, cb := cfg, cfg
	ca.local_sid, ca.peer_sid = SID_A, SID_B
	cb.local_sid, cb.peer_sid = SID_B, SID_A
	testing.expect_value(t, init(&p.a, ca, 0), Init_Error.None)
	testing.expect_value(t, init(&p.b, cb, 0), Init_Error.None)
}

@(private = "file")
pair_destroy :: proc(p: ^Pair) {
	destroy(&p.a)
	destroy(&p.b)
}

// What the receiver of a lossless wire would be handed for this Tx.
@(private = "file")
rx_of :: proc(tx: Tx) -> Rx {
	return Rx{acks = tx.acks, has_msg = tx.kind == .Control, id = tx.id, tag = tx.tag, payload = tx.payload}
}

// Polls until the channel has nothing more. Payloads stay valid (poll does not
// touch the buffers).
@(private = "file")
drain :: proc(c: ^Channel, now: time.Duration) -> []Tx {
	out := make([dynamic]Tx, context.temp_allocator)
	for {
		tx, ok := poll(c, now)
		if !ok {
			break
		}
		append(&out, tx)
	}
	return out[:]
}

@(private = "file")
msg :: proc(id: u32, tag: u8 = TAG_DATA, payload: []u8 = nil, hard_reset := false) -> Rx {
	return Rx{has_msg = true, id = id, tag = tag, payload = payload, hard_reset = hard_reset}
}

// A bare ack packet for the channel whose own sid is `sid`.
@(private = "file")
ack_pkt :: proc(sid: Sid, ids: ..u32) -> Rx {
	rx: Rx
	rx.acks.sid = sid
	rx.acks.count = u8(len(ids))
	for id, i in ids {
		if i < ACK_LIST_MAX {
			rx.acks.ids[i] = id
		}
	}
	return rx
}

// Takes every deliverable message; returns how many.
@(private = "file")
pop_all :: proc(c: ^Channel) -> int {
	n := 0
	for _, ok := pop(c); ok; _, ok = pop(c) {
		n += 1
	}
	return n
}

@(private = "file")
expect_ids :: proc(t: ^testing.T, got: []u32, want: []u32, loc := #caller_location) {
	ok := len(got) == len(want)
	for i in 0 ..< min(len(got), len(want)) {
		ok &&= got[i] == want[i]
	}
	testing.expectf(t, ok, "ids: got %v, want %v", got, want, loc = loc)
}

@(private = "file")
expect_bytes :: proc(t: ^testing.T, got: []u8, want: []u8, loc := #caller_location) {
	ok := len(got) == len(want)
	for i in 0 ..< min(len(got), len(want)) {
		ok &&= got[i] == want[i]
	}
	testing.expectf(t, ok, "bytes: got %v, want %v", got, want, loc = loc)
}

// Queues n one-byte packets (payload = index) on c.
@(private = "file")
queue_n :: proc(t: ^testing.T, c: ^Channel, n: int, now: time.Duration = 0) {
	for i in 0 ..< n {
		_, ok := send_packet(c, TAG_DATA, []u8{u8(i)}, now)
		testing.expectf(t, ok, "send_packet %d refused", i)
	}
}

@(test)
backoff_default_timeout :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A, peer_sid = SID_B}, 0), Init_Error.None)
	defer destroy(&c)
	_, ok := send_packet(&c, TAG_DATA, nil, 0)
	testing.expect(t, ok)

	// The spec's schedule for tls-timeout 2: 0, 2, 6, 14, 30, 62, 126, 254,
	// then every 128 s.
	want := [?]int{0, 2, 6, 14, 30, 62, 126, 254, 382, 510}
	now := time.Duration(0)
	for w, i in want {
		at, have := next_wakeup(&c, now)
		testing.expect(t, have)
		testing.expect_value(t, at, time.Duration(w) * SEC)
		if i > 0 {
			_, early := poll(&c, at - 1) // one nanosecond early: nothing
			testing.expect(t, !early, "retransmitted early")
		}
		now = at
		tx, got := poll(&c, now)
		testing.expect(t, got)
		testing.expect_value(t, tx.attempt, i + 1)
		testing.expect(t, !tx.fast)
		testing.expect_value(t, tx.id, 0)
		_, again := poll(&c, now)
		testing.expect(t, !again, "one packet per poll, and no second send at the same time")
	}
	testing.expect_value(t, c.stats.retransmits, len(want) - 1)
}

@(test)
backoff_custom_timeout :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {timeout = SEC}, 0), Init_Error.None)
	defer destroy(&c)
	send_packet(&c, TAG_DATA, nil, 0)
	// Doubles up to 64 s, then stays there.
	want := [?]int{0, 1, 3, 7, 15, 31, 63, 127, 191, 255}
	for w in want {
		at, have := next_wakeup(&c, 0)
		testing.expect(t, have)
		testing.expect_value(t, at, time.Duration(w) * SEC)
		_, got := poll(&c, at)
		testing.expect(t, got)
	}
}

@(test)
retransmit_keeps_id_tag_and_payload :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {}, 0), Init_Error.None)
	defer destroy(&c)
	TAG_WKC :: 11
	send_packet(&c, TAG_WKC, []u8{1, 2, 3}, 0)
	send_packet(&c, TAG_DATA, []u8{4, 5}, 0)
	first := drain(&c, 0)
	testing.expect_value(t, len(first), 2)
	// Both are due at 2 s: the lower id goes first, one per poll.
	second := drain(&c, 2 * SEC)
	testing.expect_value(t, len(second), 2)
	for i in 0 ..< 2 {
		testing.expect_value(t, second[i].id, first[i].id)
		testing.expect_value(t, second[i].tag, first[i].tag)
		testing.expect_value(t, second[i].attempt, 2)
		expect_bytes(t, second[i].payload, first[i].payload)
	}
	testing.expect_value(t, second[0].tag, TAG_WKC)
	expect_bytes(t, second[0].payload, []u8{1, 2, 3})
}

@(test)
late_poll_still_waits_full_timeout :: proc(t: ^testing.T) {
	// The caller polls late. The next gap counts from the late send.
	c: Channel
	testing.expect_value(t, init(&c, {}, 0), Init_Error.None)
	defer destroy(&c)
	send_packet(&c, TAG_DATA, nil, 0)
	poll(&c, 0)
	poll(&c, 5 * SEC) // due at 2 s, polled at 5 s
	at, _ := next_wakeup(&c, 5 * SEC)
	testing.expect_value(t, at, 9 * SEC) // 5 + 4
}

@(test)
lost_packet_retransmits_after_timeout :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	queue_n(t, &p.a, 6)
	flight := drain(&p.a, 0)
	testing.expect_value(t, len(flight), 6)
	for tx, i in flight {
		testing.expect_value(t, tx.id, u32(i))
	}
	// Lose id 4. Only id 5 is acked after it: one later ack, not enough for
	// a fast retransmit.
	for tx in flight {
		if tx.id != 4 {
			testing.expect_value(t, receive(&p.b, rx_of(tx), 50 * time.Millisecond), Rx_Status.Stored)
		}
	}
	acks := drain(&p.b, 50 * time.Millisecond)
	testing.expect_value(t, len(acks), 1)
	testing.expect_value(t, acks[0].kind, Tx_Kind.Ack)
	testing.expect_value(t, acks[0].acks.count, 5)
	testing.expect_value(t, receive(&p.a, rx_of(acks[0]), 100 * time.Millisecond), Rx_Status.Ack_Only)
	testing.expect_value(t, outstanding(&p.a), 1)

	_, early := poll(&p.a, 1900 * time.Millisecond)
	testing.expect(t, !early, "nothing is due before the timeout")
	tx, ok := poll(&p.a, 2 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, tx.id, 4)
	testing.expect_value(t, tx.attempt, 2)
	testing.expect(t, !tx.fast)

	// B gets it, and now delivers all six in order.
	testing.expect_value(t, receive(&p.b, rx_of(tx), 2 * SEC), Rx_Status.Stored)
	n := 0
	for d, got := pop(&p.b); got; d, got = pop(&p.b) {
		testing.expect_value(t, d.id, u32(n))
		testing.expect_value(t, len(d.payload), 1)
		testing.expect_value(t, d.payload[0], u8(n))
		n += 1
	}
	testing.expect_value(t, n, 6)
}

@(test)
two_later_acks_are_not_enough :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	queue_n(t, &p.a, 6)
	flight := drain(&p.a, 0)
	for tx in flight {
		if tx.id != 3 {
			receive(&p.b, rx_of(tx), 50 * time.Millisecond)
		}
	}
	acks := drain(&p.b, 50 * time.Millisecond)
	receive(&p.a, rx_of(acks[0]), 100 * time.Millisecond) // acks 4 and 5 are later than 3
	_, early := poll(&p.a, SEC)
	testing.expect(t, !early, "two later acks do not cause id 3 to be due")
	tx, ok := poll(&p.a, 2 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, tx.id, 3)
	testing.expect(t, !tx.fast)
}

@(test)
lost_packet_fast_retransmit_after_three_later_acks :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	queue_n(t, &p.a, 6)
	flight := drain(&p.a, 0)
	for tx in flight {
		if tx.id != 2 {
			receive(&p.b, rx_of(tx), 50 * time.Millisecond)
		}
	}
	// B acks 0, 1, 3, 4, 5 in one packet: id 2 gets three later acks.
	acks := drain(&p.b, 50 * time.Millisecond)
	receive(&p.a, rx_of(acks[0]), 100 * time.Millisecond)

	at, ok := next_wakeup(&p.a, 100 * time.Millisecond)
	testing.expect(t, ok)
	testing.expect_value(t, at, 100 * time.Millisecond) // due now, long before 2 s
	tx, got := poll(&p.a, 100 * time.Millisecond)
	testing.expect(t, got)
	testing.expect_value(t, tx.id, 2)
	testing.expect(t, tx.fast)
	testing.expect_value(t, tx.attempt, 2)
	testing.expect_value(t, p.a.stats.fast_retransmits, 1)
	// The send followed the normal timer rules. The first send already
	// doubled the timeout, so the next try is 4 s later.
	at, _ = next_wakeup(&p.a, 100 * time.Millisecond)
	testing.expect_value(t, at, 100 * time.Millisecond + 4 * SEC)
}

@(test)
repeated_acks_do_not_trigger_fast_retransmit :: proc(t: ^testing.T) {
	// A stock peer repeats old ids in every ack array. Only an ack that
	// removes a packet counts as an ack of a later packet.
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	queue_n(t, &c, 3)
	drain(&c, 0)
	for _ in 0 ..< 6 {
		testing.expect_value(t, receive(&c, ack_pkt(SID_A, 1), 10 * time.Millisecond), Rx_Status.Ack_Only)
	}
	_, ok := poll(&c, 10 * time.Millisecond)
	testing.expect(t, !ok)
	testing.expect_value(t, c.stats.acks_applied, 1)
	testing.expect_value(t, c.stats.acks_ignored, 5)
}

@(test)
reordering_delivers_in_order :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	queue_n(t, &p.a, 6)
	flight := drain(&p.a, 0)
	order := [?]int{5, 3, 4, 1, 2, 0}
	for k, i in order {
		testing.expect_value(t, receive(&p.b, rx_of(flight[k]), 10 * time.Millisecond), Rx_Status.Stored)
		_, got := pop(&p.b)
		testing.expect_value(t, got, i == len(order) - 1) // nothing until id 0 is there
		if got {
			break
		}
	}
	// The first pop above took id 0; the rest follow in order.
	n := 1
	for d, got := pop(&p.b); got; d, got = pop(&p.b) {
		testing.expect_value(t, d.id, u32(n))
		n += 1
	}
	testing.expect_value(t, n, 6)
	// One bare ack covers the burst, ids in arrival order.
	acks := drain(&p.b, 10 * time.Millisecond)
	testing.expect_value(t, len(acks), 1)
	testing.expect_value(t, acks[0].acks.count, 6)
	expect_ids(t, acks[0].acks.ids[:6], []u32{5, 3, 4, 1, 2, 0})
	testing.expect_value(t, acks[0].acks.sid, SID_A)
}

@(test)
receive_window_edges :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_B, peer_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	// next expected id is 0: ids 0..11 are inside the window, 12 is not.
	testing.expect_value(t, receive(&c, msg(11), 0), Rx_Status.Stored)
	testing.expect_value(t, pending_acks(&c), 1)
	testing.expect_value(t, receive(&c, msg(12), 0), Rx_Status.Ahead)
	testing.expect_value(t, receive(&c, msg(1000), 0), Rx_Status.Ahead)
	testing.expect_value(t, pending_acks(&c), 1) // 12 and 1000 were not queued for an ack
	_, got := pop(&c)
	testing.expect(t, !got, "id 0 is missing")

	// Deliver id 0: the window moves by one and 12 now fits.
	testing.expect_value(t, receive(&c, msg(0), 0), Rx_Status.Stored)
	d, ok := pop(&c)
	testing.expect(t, ok)
	testing.expect_value(t, d.id, 0)
	testing.expect_value(t, receive(&c, msg(12), 0), Rx_Status.Stored)
	testing.expect_value(t, receive(&c, msg(13), 0), Rx_Status.Ahead)
}

@(test)
receive_window_full_refuses :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_B, peer_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	// Fill all 12 slots without popping.
	for i in 0 ..< u32(RECV_WINDOW) {
		testing.expect_value(t, receive(&c, msg(i), 0), Rx_Status.Stored)
	}
	// Every slot is in use: no store, no ack. The acks inside are still used.
	testing.expect_value(t, receive(&c, msg(12), 0), Rx_Status.Window_Full)
	testing.expect_value(t, receive(&c, msg(3), 0), Rx_Status.Window_Full)
	testing.expect_value(t, c.stats.rx_window_full, 2)
	d, ok := pop(&c)
	testing.expect(t, ok)
	testing.expect_value(t, d.id, 0)
	testing.expect_value(t, receive(&c, msg(12), 0), Rx_Status.Stored)
}

@(test)
duplicate_is_acked_not_redelivered :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	data := []u8{9, 9, 9}
	testing.expect_value(t, receive(&p.b, msg(0, payload = data), 0), Rx_Status.Stored)
	d, ok := pop(&p.b)
	testing.expect(t, ok)
	expect_bytes(t, d.payload, data)
	first := drain(&p.b, 0)
	testing.expect_value(t, len(first), 1)
	testing.expect_value(t, first[0].acks.ids[0], 0)

	// The ack is lost; the sender repeats the packet. Consumed id: acked.
	testing.expect_value(t, receive(&p.b, msg(0, payload = data), SEC), Rx_Status.Duplicate)
	_, again := pop(&p.b)
	testing.expect(t, !again, "a duplicate must not be delivered twice")
	second := drain(&p.b, SEC)
	testing.expect_value(t, len(second), 1)
	testing.expect_value(t, second[0].kind, Tx_Kind.Ack)
	testing.expect_value(t, second[0].acks.count, 1)
	testing.expect_value(t, second[0].acks.ids[0], 0)

	// Stored but not yet consumed: also a duplicate.
	testing.expect_value(t, receive(&p.b, msg(2), SEC), Rx_Status.Stored)
	testing.expect_value(t, receive(&p.b, msg(2), SEC), Rx_Status.Duplicate)

	// A flood of the same id costs one entry.
	for _ in 0 ..< 100 {
		receive(&p.b, msg(0), SEC)
	}
	testing.expect_value(t, pending_acks(&p.b), 2) // ids 2 and 0
}

@(test)
lost_bare_ack_is_answered_again :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	queue_n(t, &p.a, 1)
	tx, _ := poll(&p.a, 0)
	receive(&p.b, rx_of(tx), 0)
	lost := drain(&p.b, 0) // this ack never arrives
	testing.expect_value(t, len(lost), 1)

	retry, ok := poll(&p.a, 2 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, retry.attempt, 2)
	testing.expect_value(t, receive(&p.b, rx_of(retry), 2 * SEC), Rx_Status.Duplicate)
	fresh := drain(&p.b, 2 * SEC)
	testing.expect_value(t, len(fresh), 1)
	testing.expect_value(t, fresh[0].acks.count, 1)
	testing.expect_value(t, receive(&p.a, rx_of(fresh[0]), 2 * SEC), Rx_Status.Ack_Only)
	testing.expect(t, all_acked(&p.a))
	_, more := poll(&p.a, 100 * SEC)
	testing.expect(t, !more, "an acked packet is never sent again")
}

@(test)
send_window_is_a_distance :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	testing.expect_value(t, send_room(&c), 6)
	queue_n(t, &c, 6)
	testing.expect_value(t, send_room(&c), 0)
	_, ok := send_packet(&c, TAG_DATA, nil, 0)
	testing.expect(t, !ok, "seventh packet refused")

	// Ids 1..5 acked, id 0 stuck: five slots are free but the distance of the
	// next id (6) from the oldest unacked (0) is 6, so no room.
	testing.expect_value(t, receive(&c, ack_pkt(SID_A, 1, 2, 3, 4, 5), 0), Rx_Status.Ack_Only)
	testing.expect_value(t, outstanding(&c), 1)
	testing.expect_value(t, send_room(&c), 0)
	testing.expect_value(t, send(&c, []u8{1, 2, 3}, 100, TAG_DATA, 0), 0)

	// When id 0 is acked everything is open again.
	receive(&c, ack_pkt(SID_A, 0), 0)
	testing.expect_value(t, send_room(&c), 6)

	// Partial: send 6 more (ids 6..11), ack all but id 8: oldest is 8, next 12.
	queue_n(t, &c, 6)
	receive(&c, ack_pkt(SID_A, 6, 7, 9, 10, 11), 0)
	testing.expect_value(t, outstanding(&c), 1)
	testing.expect_value(t, send_room(&c), 2) // 6 - (12 - 8)
}

@(test)
send_cuts_pieces :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	data := make([]u8, 3000, context.temp_allocator)
	for &b, i in data {
		b = u8(i * 7)
	}
	testing.expect_value(t, send(&c, data, 1184, TAG_DATA, 0), 3000)
	flight := drain(&c, 0)
	testing.expect_value(t, len(flight), 3)
	testing.expect_value(t, len(flight[0].payload), 1184)
	testing.expect_value(t, len(flight[1].payload), 1184)
	testing.expect_value(t, len(flight[2].payload), 632)
	pos := 0
	for tx in flight {
		for b in tx.payload {
			testing.expect_value(t, b, data[pos])
			pos += 1
		}
	}
}

@(test)
send_takes_only_what_the_window_admits :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	data := make([]u8, 20000, context.temp_allocator)
	testing.expect_value(t, send(&c, data, 1184, TAG_DATA, 0), 6 * 1184)
	testing.expect_value(t, send(&c, data, 1184, TAG_DATA, 0), 0)
	testing.expect_value(t, outstanding(&c), 6)
}

@(test)
send_budget_floor_and_ceiling :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {max_payload = 100}, 0), Init_Error.None)
	defer destroy(&c)
	// A budget under 16 still gives 16-byte pieces.
	testing.expect_value(t, send(&c, make([]u8, 40, context.temp_allocator), 3, TAG_DATA, 0), 40)
	flight := drain(&c, 0)
	testing.expect_value(t, len(flight), 3)
	testing.expect_value(t, len(flight[0].payload), 16)
	testing.expect_value(t, len(flight[1].payload), 16)
	testing.expect_value(t, len(flight[2].payload), 8)
	// A budget over max_payload is lowered to it.
	reset(&c, 0)
	testing.expect_value(t, send(&c, make([]u8, 250, context.temp_allocator), 1184, TAG_DATA, 0), 250)
	flight = drain(&c, 0)
	testing.expect_value(t, len(flight), 3)
	testing.expect_value(t, len(flight[0].payload), 100)
	testing.expect_value(t, len(flight[2].payload), 50)
	// A single packet can never exceed max_payload.
	_, ok := send_packet(&c, TAG_DATA, make([]u8, 101, context.temp_allocator), 0)
	testing.expect(t, !ok)
}

@(test)
payload_budget_matches_spec_examples :: proc(t: ^testing.T) {
	// Default tls_mtu 1250, IPv4, 4 ack ids.
	testing.expect_value(t, payload_budget(1250, 0, IP_UDP_OVERHEAD_V4), 1184)
	testing.expect_value(t, payload_budget(1250, 28, IP_UDP_OVERHEAD_V4), 1156) // tls-auth SHA1
	testing.expect_value(t, payload_budget(1250, WRAP_OVERHEAD_TLS_CRYPT, IP_UDP_OVERHEAD_V4), 1128)
	testing.expect_value(t, payload_budget(1250, WRAP_OVERHEAD_TLS_CRYPT, IP_UDP_OVERHEAD_V6), 1108)
	// Empty ack array: 1 byte instead of 25.
	testing.expect_value(t, payload_budget(1250, 0, IP_UDP_OVERHEAD_V4, 0), 1208)
	// Clamps: mtu 100 is treated as 154, 5000 as 2048. Never negative.
	testing.expect_value(t, payload_budget(100, 0, 28), 154 - 38 - 28)
	testing.expect_value(t, payload_budget(5000, 0, 28), 2048 - 38 - 28)
	testing.expect_value(t, payload_budget(154, WRAP_OVERHEAD_TLS_CRYPT, IP_UDP_OVERHEAD_V6), 12)
	testing.expect_value(t, payload_budget(154, 200, 48), 0)
}

@(test)
ack_array_validation :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A, peer_sid = SID_B}, 0), Init_Error.None)
	defer destroy(&c)
	queue_n(t, &c, 1)
	drain(&c, 0)

	// Count 9 is refused whole.
	bad := ack_pkt(SID_A, 0)
	bad.acks.count = 9
	bad.has_msg = true
	bad.id = 0
	testing.expect_value(t, receive(&c, bad, 0), Rx_Status.Bad_Ack_List)
	// Wrong remote sid: refused whole, nothing applied, message not stored.
	wrong := ack_pkt(SID_B, 0)
	wrong.has_msg = true
	wrong.id = 0
	testing.expect_value(t, receive(&c, wrong, 0), Rx_Status.Bad_Sid)
	testing.expect_value(t, outstanding(&c), 1)
	testing.expect_value(t, c.recv_used, 0)
	testing.expect_value(t, pending_acks(&c), 0)
	testing.expect_value(t, c.stats.rx_bad_acks, 2)

	// An empty array has no sid on the wire; whatever is in the field is not checked.
	empty := msg(0)
	empty.acks.sid = SID_B
	testing.expect_value(t, receive(&c, empty, 0), Rx_Status.Stored)

	// A good one works.
	testing.expect_value(t, receive(&c, ack_pkt(SID_A, 0), 0), Rx_Status.Ack_Only)
	testing.expect_value(t, outstanding(&c), 0)

	// A bare ack with an empty array is ignored without complaint.
	testing.expect_value(t, receive(&c, ack_pkt(SID_A), 0), Rx_Status.Ack_Only)
}

@(test)
acks_outside_the_window_are_ignored :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A, send_first_id = 100}, 0), Init_Error.None)
	defer destroy(&c)
	queue_n(t, &c, 1) // id 100, next id 101
	// 101 is the future, 50 is far below, 0 and 0xffffffff are far off or never sent.
	st := receive(&c, ack_pkt(SID_A, 101, 50, 88, 7, 102), 0)
	testing.expect_value(t, st, Rx_Status.Ack_Only)
	testing.expect_value(t, outstanding(&c), 1)
	testing.expect_value(t, c.stats.acks_ignored, 5)
	// 89 is the oldest id inside the 12-wide window (101 - 12), but nothing
	// was sent with it. 88 is outside. Both are ignored.
	receive(&c, ack_pkt(SID_A, 89, 88), 0)
	testing.expect_value(t, c.stats.acks_ignored, 7)
	testing.expect_value(t, outstanding(&c), 1)
	receive(&c, ack_pkt(SID_A, 100), 0)
	testing.expect_value(t, outstanding(&c), 0)
}

@(test)
ack_limits_four_with_data_eight_bare :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	for i in 0 ..< u32(8) {
		receive(&p.b, msg(i), 0)
	}
	// Nothing to send: one bare ack with all 8, in arrival order.
	acks := drain(&p.b, 0)
	testing.expect_value(t, len(acks), 1)
	testing.expect_value(t, acks[0].kind, Tx_Kind.Ack)
	testing.expect_value(t, acks[0].acks.count, 8)
	expect_ids(t, acks[0].acks.ids[:8], []u32{0, 1, 2, 3, 4, 5, 6, 7})
	testing.expect_value(t, pending_acks(&p.b), 0)

	// With a packet to send: 4 ride on it, the rest go on a bare ack.
	pair_destroy(&p)
	pair_init(t, &p)
	for i in 0 ..< u32(8) {
		receive(&p.b, msg(i), 0)
	}
	queue_n(t, &p.b, 1)
	out := drain(&p.b, 0)
	testing.expect_value(t, len(out), 2)
	testing.expect_value(t, out[0].kind, Tx_Kind.Control)
	testing.expect_value(t, out[0].acks.count, 4)
	expect_ids(t, out[0].acks.ids[:4], []u32{0, 1, 2, 3})
	testing.expect_value(t, out[1].kind, Tx_Kind.Ack)
	// Pending 4..7 first, then the recent ids to fill up to 8.
	testing.expect_value(t, out[1].acks.count, 8)
	expect_ids(t, out[1].acks.ids[:8], []u32{4, 5, 6, 7, 3, 2, 1, 0})
	testing.expect_value(t, out[1].acks.sid, SID_A)
}

@(test)
ack_limit_never_above_eight_or_four :: proc(t: ^testing.T) {
	// Whatever the state, no array is longer than its limit.
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	for i in 0 ..< u32(12) {
		receive(&p.b, msg(i), 0)
	}
	// Only 8 fit in the pending list; the other 4 were never queued.
	testing.expect_value(t, pending_acks(&p.b), 8)
	testing.expect_value(t, p.b.stats.pending_full, 4)
	queue_n(t, &p.b, 3)
	for tx in drain(&p.b, 0) {
		limit := tx.kind == .Control ? ACK_PIGGY_MAX : ACK_LIST_MAX
		testing.expect(t, int(tx.acks.count) <= limit, "ack array above its limit")
	}
	// Retransmits carry recent ids too, still at most 4.
	tx, ok := poll(&p.b, 2 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, tx.acks.count, 4)
}

@(test)
recent_acks_are_repeated :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	receive(&p.b, msg(0), 0)
	receive(&p.b, msg(1), 0)
	first := drain(&p.b, 0)
	expect_ids(t, first[0].acks.ids[:2], []u32{0, 1})
	testing.expect_value(t, first[0].acks.count, 2)

	// New id first, then the earlier ones, newest first.
	receive(&p.b, msg(2), 0)
	second := drain(&p.b, 0)
	testing.expect_value(t, second[0].acks.count, 3)
	expect_ids(t, second[0].acks.ids[:3], []u32{2, 1, 0})

	// A data packet with nothing pending still carries up to 4 recent ids.
	receive(&p.b, msg(3), 0)
	queue_n(t, &p.b, 1)
	third := drain(&p.b, 0)
	testing.expect_value(t, len(third), 1)
	testing.expect_value(t, third[0].acks.count, 4)
	expect_ids(t, third[0].acks.ids[:4], []u32{3, 2, 1, 0})
	// No bare ack is sent for ids that are not new.
	_, bare := poll(&p.b, 0)
	testing.expect(t, !bare)

	// The list holds at most 8: after ids 4..11 the oldest are gone.
	pop_all(&p.b)
	for i in 4 ..< u32(12) {
		receive(&p.b, msg(i), 0)
		pop_all(&p.b)
		drain(&p.b, 0)
	}
	receive(&p.b, msg(12), 0)
	last := drain(&p.b, 0)
	testing.expect_value(t, last[0].acks.count, 8)
	expect_ids(t, last[0].acks.ids[:8], []u32{12, 11, 10, 9, 8, 7, 6, 5})
}

@(test)
empty_packet_uses_an_id_and_is_acked :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	id, ok := send_packet(&p.a, TAG_DATA, nil, 0)
	testing.expect(t, ok)
	testing.expect_value(t, id, 0)
	tx, _ := poll(&p.a, 0)
	testing.expect_value(t, len(tx.payload), 0)
	testing.expect_value(t, receive(&p.b, rx_of(tx), 0), Rx_Status.Stored)
	d, got := pop(&p.b)
	testing.expect(t, got)
	testing.expect_value(t, len(d.payload), 0)
	testing.expect_value(t, p.b.next_recv, 1)
	ack := drain(&p.b, 0)
	testing.expect_value(t, ack[0].acks.ids[0], 0)
	id2, _ := send_packet(&p.a, TAG_DATA, []u8{1}, 0)
	testing.expect_value(t, id2, 1)
}

@(test)
hard_reset_needs_id_zero :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	testing.expect_value(t, receive(&p.b, msg(5, TAG_RESET_C, hard_reset = true), 0), Rx_Status.Bad_Reset_Id)
	testing.expect_value(t, pending_acks(&p.b), 0)
	testing.expect_value(t, p.b.recv_used, 0)
	// The same id on an ordinary packet is just inside the window.
	testing.expect_value(t, receive(&p.b, msg(5), 0), Rx_Status.Stored)

	// A reset with id 0 is delivered with its tag, and acked.
	pair_destroy(&p)
	pair_init(t, &p)
	tlv := []u8{0, 1, 0, 2, 0, 1}
	testing.expect_value(t, receive(&p.b, msg(0, TAG_RESET_C, tlv, true), 0), Rx_Status.Stored)
	d, ok := pop(&p.b)
	testing.expect(t, ok)
	testing.expect_value(t, d.tag, TAG_RESET_C)
	expect_bytes(t, d.payload, tlv)
	// A copy of the reset after delivery is acked again.
	testing.expect_value(t, receive(&p.b, msg(0, TAG_RESET_C, tlv, true), 0), Rx_Status.Duplicate)
}

@(test)
opening_exchange_stateful :: proc(t: ^testing.T) {
	// TCP-like opening: reset, reset reply, ClientHello, ServerHello.
	p: Pair
	pair_init(t, &p)
	defer pair_destroy(&p)
	set_hold(&p.b, true) // TCP server: silent until the client speaks

	rid, _ := send_packet(&p.a, TAG_RESET_C, nil, 0)
	testing.expect_value(t, rid, 0)
	c1, _ := poll(&p.a, 0)
	testing.expect_value(t, c1.acks.count, 0)
	rx := rx_of(c1)
	rx.hard_reset = true // the codec knows the opcode
	testing.expect_value(t, receive(&p.b, rx, 0), Rx_Status.Stored)
	_, got := pop(&p.b)
	testing.expect(t, got)

	// The server queued its reset earlier; the first client packet releases it.
	send_packet(&p.b, TAG_RESET_S, nil, 0)
	testing.expect_value(t, len(drain(&p.b, 0)), 0)
	set_hold(&p.b, false)
	s1, _ := poll(&p.b, 0)
	testing.expect_value(t, s1.id, 0)
	testing.expect_value(t, s1.acks.count, 1)
	testing.expect_value(t, s1.acks.ids[0], 0)
	testing.expect_value(t, s1.acks.sid, SID_A) // the client's sid, echoed

	// Client: the server's reset acks ours.
	rx = rx_of(s1)
	rx.hard_reset = true
	testing.expect_value(t, receive(&p.a, rx, 0), Rx_Status.Stored)
	testing.expect(t, all_acked(&p.a))
	d, ok := pop(&p.a)
	testing.expect(t, ok)
	testing.expect_value(t, d.tag, TAG_RESET_S)
	// ClientHello goes out as id 1 and carries the ack of the server's reset.
	testing.expect_value(t, send(&p.a, []u8{0x16, 3, 1}, 1184, TAG_DATA, 0), 3)
	ch, _ := poll(&p.a, 0)
	testing.expect_value(t, ch.id, 1)
	testing.expect_value(t, ch.acks.count, 1)
	testing.expect_value(t, ch.acks.ids[0], 0)
	testing.expect_value(t, ch.acks.sid, SID_B)
	_, bare := poll(&p.a, 0)
	testing.expect(t, !bare, "the ack rode on the data packet")

	testing.expect_value(t, receive(&p.b, rx_of(ch), 0), Rx_Status.Stored)
	testing.expect(t, all_acked(&p.b))
}

@(test)
opening_exchange_from_cookie :: proc(t: ^testing.T) {
	// a server created from the client's third packet starts
	// with both ids at 1. The reset reply (id 0) was sent without state.
	cookie := Sid{0xc0, 0x0c, 0x1e, 0, 0, 0, 0, 1}
	client: Channel
	testing.expect_value(t, init(&client, {local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&client)
	server: Channel
	testing.expect_value(t, init(&server, {local_sid = cookie, peer_sid = SID_A, send_first_id = 1, recv_first_id = 1}, 0), Init_Error.None)
	defer destroy(&server)

	send_packet(&client, TAG_RESET_C, nil, 0)
	poll(&client, 0)
	// The stateless reply: server sid = cookie, acks id 0, carries id 0.
	set_peer_sid(&client, cookie)
	reply := Rx {
		acks       = {ids = {0, 0, 0, 0, 0, 0, 0, 0}, count = 1, sid = SID_A},
		has_msg    = true,
		id         = 0,
		tag        = TAG_RESET_S,
		hard_reset = true,
	}
	testing.expect_value(t, receive(&client, reply, 10 * time.Millisecond), Rx_Status.Stored)
	testing.expect(t, all_acked(&client))
	_, got := pop(&client)
	testing.expect(t, got)

	send(&client, []u8{1, 2, 3}, 1000, TAG_DATA, 10 * time.Millisecond)
	hello, _ := poll(&client, 10 * time.Millisecond)
	testing.expect_value(t, hello.id, 1)
	testing.expect_value(t, hello.acks.ids[0], 0)

	// The server sees it as a new session. Its ack of id 0 matches nothing
	// outstanding and is ignored.
	testing.expect_value(t, receive(&server, rx_of(hello), 10 * time.Millisecond), Rx_Status.Stored)
	d, ok := pop(&server)
	testing.expect(t, ok)
	testing.expect_value(t, d.id, 1)
	// A retransmitted client reset (id 0) is "older": acked.
	testing.expect_value(t, receive(&server, msg(0, TAG_RESET_C, hard_reset = true), 20 * time.Millisecond), Rx_Status.Duplicate)
	_, again := pop(&server)
	testing.expect(t, !again)

	send(&server, []u8{9}, 1000, TAG_DATA, 20 * time.Millisecond)
	sh, _ := poll(&server, 20 * time.Millisecond)
	testing.expect_value(t, sh.id, 1)
	testing.expect_value(t, sh.acks.count, 2) // pending [1, 0]... newest first
	testing.expect_value(t, sh.acks.sid, SID_A)
	testing.expect_value(t, receive(&client, rx_of(sh), 20 * time.Millisecond), Rx_Status.Stored)
}

@(test)
id_wraparound :: proc(t: ^testing.T) {
	first := u32(0xFFFFFFFD)
	p: Pair
	pair_init(t, &p, Config{send_first_id = first, recv_first_id = first})
	defer pair_destroy(&p)
	queue_n(t, &p.a, 6) // ids fffffffd, fe, ff, 0, 1, 2
	flight := drain(&p.a, 0)
	testing.expect_value(t, flight[0].id, 0xFFFFFFFD)
	testing.expect_value(t, flight[3].id, 0)
	testing.expect_value(t, flight[5].id, 2)

	order := [?]int{4, 0, 5, 3, 2, 1}
	for k in order {
		testing.expect_value(t, receive(&p.b, rx_of(flight[k]), 0), Rx_Status.Stored)
	}
	for i in 0 ..< 6 {
		d, ok := pop(&p.b)
		testing.expect(t, ok)
		testing.expect_value(t, d.payload[0], u8(i))
	}
	_, more := pop(&p.b)
	testing.expect(t, !more)
	testing.expect_value(t, p.b.next_recv, 3)

	// Old and ahead are judged across the wrap.
	testing.expect_value(t, receive(&p.b, msg(0xFFFFFFF0), 0), Rx_Status.Duplicate)
	testing.expect_value(t, receive(&p.b, msg(0xFFFFFFFE), 0), Rx_Status.Duplicate)
	testing.expect_value(t, receive(&p.b, msg(15), 0), Rx_Status.Ahead) // 3 + 12
	testing.expect_value(t, receive(&p.b, msg(14), 0), Rx_Status.Stored) // 3 + 11

	// Acks across the wrap free the window.
	acks := drain(&p.b, 0)
	testing.expect_value(t, receive(&p.a, rx_of(acks[0]), 0), Rx_Status.Ack_Only)
	testing.expect(t, all_acked(&p.a))
	testing.expect_value(t, send_room(&p.a), 6)
	id, ok := send_packet(&p.a, TAG_DATA, nil, 0)
	testing.expect(t, ok)
	testing.expect_value(t, id, 3)
}

@(test)
hand_window_expiry :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {hand_window = 60 * SEC, local_sid = SID_A}, 10 * SEC), Init_Error.None)
	defer destroy(&c)
	send_packet(&c, TAG_DATA, nil, 10 * SEC)

	// Follow the wake-ups. They follow the retransmit timer (sends at 10, 12,
	// 16, 24, 40 s); the deadline at 70 s comes before the one at 72 s.
	now := 10 * SEC
	seen: [dynamic]time.Duration
	seen.allocator = context.temp_allocator
	for {
		poll(&c, now)
		at, ok := next_wakeup(&c, now)
		if !ok {
			break
		}
		append(&seen, at)
		testing.expect_value(t, error(&c), Failure.None)
		now = at
		if len(seen) > 20 {
			break
		}
	}
	testing.expect_value(t, error(&c), Failure.Hand_Window)
	testing.expect_value(t, now, 70 * SEC)
	want := [?]time.Duration{12 * SEC, 16 * SEC, 24 * SEC, 40 * SEC, 70 * SEC}
	testing.expect_value(t, len(seen), len(want))
	for w, i in want {
		testing.expect_value(t, seen[i], w)
	}

	// Everything is inert now.
	_, wake := next_wakeup(&c, 71 * SEC)
	testing.expect(t, !wake)
	testing.expect_value(t, receive(&c, msg(0), 71 * SEC), Rx_Status.Failed)
	testing.expect_value(t, send_room(&c), 0)
	_, pops := pop(&c)
	testing.expect(t, !pops)
	_, sent := send_packet(&c, TAG_DATA, nil, 71 * SEC)
	testing.expect(t, !sent)
	_, polled := poll(&c, 71 * SEC)
	testing.expect(t, !polled)

	// reset clears it and arms the deadline again from the new time.
	reset(&c, 100 * SEC)
	testing.expect_value(t, error(&c), Failure.None)
	testing.expect_value(t, outstanding(&c), 0)
	at, ok := next_wakeup(&c, 100 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, at, 160 * SEC)
}

@(test)
hand_window_one_nanosecond_before :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {hand_window = 60 * SEC}, 0), Init_Error.None)
	defer destroy(&c)
	poll(&c, 60 * SEC - 1)
	testing.expect_value(t, error(&c), Failure.None)
	poll(&c, 60 * SEC)
	testing.expect_value(t, error(&c), Failure.Hand_Window)
}

@(test)
hand_window_can_be_cleared_and_extended :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {hand_window = 60 * SEC}, 0), Init_Error.None)
	defer destroy(&c)
	set_deadline(&c, 90 * SEC) // pending authentication: wait longer
	_, ok := poll(&c, 80 * SEC)
	testing.expect(t, !ok)
	testing.expect_value(t, error(&c), Failure.None)
	clear_deadline(&c) // ACTIVE
	poll(&c, 1000 * SEC)
	testing.expect_value(t, error(&c), Failure.None)
	_, wake := next_wakeup(&c, 1000 * SEC)
	testing.expect(t, !wake, "no deadline, nothing outstanding: nothing scheduled")
}

@(test)
retransmit_limit :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {timeout = SEC, max_retransmits = 3}, 0), Init_Error.None)
	defer destroy(&c)
	send_packet(&c, TAG_DATA, nil, 0)
	// Sends at 0, 1, 3, 7 (first plus three retransmits); then it waits one more timeout.
	for at in ([?]int{0, 1, 3, 7}) {
		tx, ok := poll(&c, time.Duration(at) * SEC)
		testing.expect(t, ok)
		testing.expect_value(t, tx.id, 0)
	}
	w, ok := next_wakeup(&c, 7 * SEC)
	testing.expect(t, ok)
	testing.expect_value(t, w, 15 * SEC)
	_, sent := poll(&c, 15 * SEC - 1)
	testing.expect(t, !sent)
	testing.expect_value(t, error(&c), Failure.None)
	_, sent = poll(&c, 15 * SEC)
	testing.expect(t, !sent)
	testing.expect_value(t, error(&c), Failure.Retransmit_Limit)
}

@(test)
ack_stops_the_failure_clock :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {timeout = SEC, max_retransmits = 2, local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	send_packet(&c, TAG_DATA, nil, 0)
	poll(&c, 0)
	poll(&c, SEC)
	poll(&c, 3 * SEC)
	receive(&c, ack_pkt(SID_A, 0), 3 * SEC + 1)
	poll(&c, 100 * SEC)
	testing.expect_value(t, error(&c), Failure.None)
}

@(test)
hold_and_burst :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {}, 0), Init_Error.None)
	defer destroy(&c)
	set_hold(&c, true)
	send_packet(&c, TAG_RESET_S, nil, 0)
	_, ok := poll(&c, 0)
	testing.expect(t, !ok, "held: nothing is sent")
	_, wake := next_wakeup(&c, 0)
	testing.expect(t, !wake)
	set_hold(&c, false)
	_, ok = poll(&c, 0)
	testing.expect(t, ok)

	// Timeout is 4 s now (next try at 2 s). A burst sets it due at once and
	// goes back to the first timeout.
	burst(&c, SEC)
	at, _ := next_wakeup(&c, SEC)
	testing.expect_value(t, at, SEC)
	tx, ok2 := poll(&c, SEC)
	testing.expect(t, ok2)
	testing.expect_value(t, tx.attempt, 2)
	at, _ = next_wakeup(&c, SEC)
	testing.expect_value(t, at, 3 * SEC) // 1 s + the first timeout of 2 s
}

@(test)
oversize_is_refused :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {max_payload = 64, local_sid = SID_A}, 0), Init_Error.None)
	defer destroy(&c)
	queue_n(t, &c, 1)
	big := ack_pkt(SID_A, 0)
	big.has_msg = true
	big.payload = make([]u8, 65, context.temp_allocator)
	testing.expect_value(t, receive(&c, big, 0), Rx_Status.Oversize)
	testing.expect_value(t, outstanding(&c), 1) // whole packet dropped, ack not applied
	big.payload = big.payload[:64]
	testing.expect_value(t, receive(&c, big, 0), Rx_Status.Stored)
	testing.expect_value(t, outstanding(&c), 0)
}

@(test)
reset_starts_over :: proc(t: ^testing.T) {
	p: Pair
	pair_init(t, &p, Config{send_first_id = 7, recv_first_id = 9})
	defer pair_destroy(&p)
	queue_n(t, &p.a, 3)
	receive(&p.a, msg(9), 0)
	set_peer_sid(&p.a, Sid{9, 9, 9, 9, 9, 9, 9, 9})
	poll(&p.a, 0)
	reset(&p.a, 5 * SEC)
	testing.expect_value(t, outstanding(&p.a), 0)
	testing.expect_value(t, pending_acks(&p.a), 0)
	testing.expect_value(t, p.a.next_id, 7)
	testing.expect_value(t, p.a.next_recv, 9)
	testing.expect_value(t, p.a.stats, Stats{})
	testing.expect_value(t, p.a.last_rx, 5 * SEC)
	_, got := pop(&p.a)
	testing.expect(t, !got)
	_, tx := poll(&p.a, 100 * SEC)
	testing.expect(t, !tx)
	// The peer sid set after init survives a reset.
	testing.expect_value(t, p.a.cfg.peer_sid, Sid{9, 9, 9, 9, 9, 9, 9, 9})
}

@(test)
last_rx_follows_valid_packets :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {local_sid = SID_A}, SEC), Init_Error.None)
	defer destroy(&c)
	testing.expect_value(t, c.last_rx, SEC)
	receive(&c, msg(0), 3 * SEC)
	testing.expect_value(t, c.last_rx, 3 * SEC)
	receive(&c, msg(500), 4 * SEC) // too far ahead: not counted
	testing.expect_value(t, c.last_rx, 3 * SEC)
	receive(&c, ack_pkt(SID_B), 5 * SEC) // wrong sid with an id... count 0 here, so fine
	testing.expect_value(t, c.last_rx, 5 * SEC)
	bad := ack_pkt(SID_B, 1)
	receive(&c, bad, 6 * SEC)
	testing.expect_value(t, c.last_rx, 5 * SEC)
}

@(test)
bad_config_is_refused :: proc(t: ^testing.T) {
	c: Channel
	testing.expect_value(t, init(&c, {timeout = -1}, 0), Init_Error.Bad_Config)
	testing.expect_value(t, init(&c, {max_payload = 8}, 0), Init_Error.Bad_Config)
	testing.expect_value(t, init(&c, {timeout = 70000 * SEC}, 0), Init_Error.Bad_Config)
	testing.expect_value(t, init(&c, {max_retransmits = -1}, 0), Init_Error.Bad_Config)
}

@(test)
no_allocation_after_init :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	alloc := mem.tracking_allocator(&track)

	p: Pair
	ca := Config{local_sid = SID_A, peer_sid = SID_B}
	cb := Config{local_sid = SID_B, peer_sid = SID_A}
	testing.expect_value(t, init(&p.a, ca, 0, alloc), Init_Error.None)
	testing.expect_value(t, init(&p.b, cb, 0, alloc), Init_Error.None)
	testing.expect_value(t, track.total_allocation_count, 2)

	// Move 2 MB through the pair over a lossless link.
	data := make([]u8, 1 << 16, context.temp_allocator)
	now := time.Duration(0)
	for _ in 0 ..< 32 {
		off := 0
		for off < len(data) || !all_acked(&p.a) {
			off += send(&p.a, data[off:], 1184, TAG_DATA, now)
			for tx in drain(&p.a, now) {
				receive(&p.b, rx_of(tx), now)
			}
			for _, ok := pop(&p.b); ok; _, ok = pop(&p.b) {}
			for tx in drain(&p.b, now) {
				receive(&p.a, rx_of(tx), now)
			}
			now += 10 * time.Millisecond
		}
	}
	testing.expect_value(t, track.total_allocation_count, 2)
	destroy(&p.a)
	destroy(&p.b)
	testing.expect_value(t, len(track.allocation_map), 0)
}
