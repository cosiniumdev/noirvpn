// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wrap

// Wrap packet id ("replay id"), long form: u32 id (never 0) and u32 time
//.

// Number of ids the receive window remembers.
REPLAY_WINDOW :: 64

// Sender side: counter and time of one wrap context.
Send_Counter :: struct {
	id:       u32,
	time:     u32,
	time_set: bool,
}

// `first_id` is the counter value before the first packet. The first wire id
// is `first_id + 1`. Use 0 normally; a tls-crypt-v2 client uses EARLY_NEG_START.
send_counter_init :: proc "contextless" (c: ^Send_Counter, first_id: u32 = 0) {
	c^ = {
		id = first_id,
	}
}

// Next (id, time) to put on a packet. The time is fixed at the first call and
// changes only at a roll-over. A roll-over (id 0xFFFFFFFF) needs `now` to be
// strictly later than the stored time, else `.Counter_Exhausted`.
send_counter_next :: proc "contextless" (c: ^Send_Counter, now: i64) -> (id: u32, time: u32, err: Error) {
	t := wrap_time(now)
	if !c.time_set {
		c.time = t
		c.time_set = true
	}
	if c.id == max(u32) {
		if t <= c.time {
			return 0, 0, .Counter_Exhausted
		}
		c.time = t
		c.id = 0
	}
	c.id += 1
	return c.id, c.time, .None
}

// Receiver side: sliding window over the ids seen at the newest time.
// A zero value is a fresh window. The caller owns it, one per wrap context.
//
// SPEC-GAP: the spec does not give the state of a fresh window. This one starts
// with max_time 0 and max_id 0, so any id above 0 is fresh. The optional
// 15-second expiry of old ids ("noirvpn MAY ignore") is not
// implemented.
//
// `replay_check` may run before authentication. `replay_commit` only after the
// packet authenticated (`replay_accept` does both, call it after authentication).
Replay_Window :: struct {
	max_time: u32,
	max_id:   u32,
	seen:     u64, // bit k set: id (max_id - k) was seen at max_time
}

replay_reset :: proc "contextless" (r: ^Replay_Window) {
	r^ = {}
}

// Would this (id, time) be accepted? Does not change the window.
replay_check :: proc "contextless" (r: ^Replay_Window, id, time: u32) -> bool {
	if id == 0 || time < r.max_time {
		return false
	}
	if time > r.max_time || id > r.max_id {
		return true
	}
	age := r.max_id - id // id <= max_id here
	if age >= REPLAY_WINDOW {
		return false
	}
	return r.seen & (u64(1) << age) == 0
}

// Records (id, time). Call only for an authenticated packet that passed
// `replay_check`. Ignores values the check would refuse.
replay_commit :: proc "contextless" (r: ^Replay_Window, id, time: u32) {
	if !replay_check(r, id, time) {
		return
	}
	if time > r.max_time {
		r.max_time = time
		r.max_id = id
		r.seen = 1
		return
	}
	if id > r.max_id {
		shift := id - r.max_id
		if shift >= REPLAY_WINDOW {
			r.seen = 1
		} else {
			r.seen = r.seen << shift | 1
		}
		r.max_id = id
		return
	}
	r.seen |= u64(1) << (r.max_id - id)
}

// Check and commit in one step. True if the packet is fresh.
replay_accept :: proc "contextless" (r: ^Replay_Window, id, time: u32) -> bool {
	if !replay_check(r, id, time) {
		return false
	}
	replay_commit(r, id, time)
	return true
}
