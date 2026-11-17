// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

// Replay window for data packets.
//
// Sliding window by packet id, a ring of bits. Ids are u64: one type serves the
// 32-bit baseline id and the 48-bit epoch counter.
//
// Rule for id `p`, highest accepted `h`, window size `w`:
//
//   p == 0           drop
//   p > h            accept; the window moves up
//   h - p >= w       drop (too old)
//   otherwise        accept once; a second time it is a duplicate
//
// Ids may arrive out of order inside the window. Check and commit are separate on
// purpose: `replay_check` any time, `replay_commit` only after the tag verified,
// so a forged packet cannot move the window.
//
// SPEC-GAP: the optional time rule of stock peers (15 s) is
// not implemented (not needed for interoperability). Window size: power of two up
// to REPLAY_MAX_BITS. Stock allows up to 65536 (`replay-window`), so the session
// layer should clamp larger requests to REPLAY_MAX_BITS.

// Window sizes are powers of two from 64 up to this many bits (256 bytes of
// state). Stock allows up to 65536. A larger window only helps against very
// deep reordering.
REPLAY_MAX_BITS :: 2048
// The stock default, and ours.
REPLAY_DEFAULT_BITS :: 64
@(private)
REPLAY_WORDS :: REPLAY_MAX_BITS / 64

// A zero value is not ready: call `replay_init`.
Replay_Window :: struct {
	top:  u64, // highest id accepted so far; 0 = none
	mask: u64, // size - 1
	bits: [REPLAY_WORDS]u64, // ring: bit (id & mask) is set if that id was seen
}

// Sets an empty window of at least `size` bits. The size is rounded up to a
// power of two and kept between 64 and REPLAY_MAX_BITS.
replay_init :: proc "contextless" (r: ^Replay_Window, size: int = REPLAY_DEFAULT_BITS) {
	n := 64
	for n < size && n < REPLAY_MAX_BITS {
		n <<= 1
	}
	r^ = {}
	r.mask = u64(n - 1)
}

// Window size in bits (0 if not initialised).
replay_size :: proc "contextless" (r: ^Replay_Window) -> int {
	if r.mask == 0 {
		return 0
	}
	return int(r.mask) + 1
}

// Forgets everything; keeps the size.
replay_reset :: proc "contextless" (r: ^Replay_Window) {
	mask := r.mask
	r^ = {}
	r.mask = mask
}

// Would this id be accepted? Does not change the window.
replay_check :: #force_inline proc "contextless" (r: ^Replay_Window, id: u64) -> bool {
	if id == 0 || r.mask == 0 {
		return false
	}
	if id > r.top {
		return true
	}
	if r.top - id > r.mask { 	// age >= size
		return false
	}
	pos := id & r.mask
	return r.bits[pos >> 6] & (u64(1) << (pos & 63)) == 0
}

// Records an id. Call only for an authenticated packet that passed
// `replay_check`; an id that the check would refuse is ignored.
replay_commit :: #force_inline proc "contextless" (r: ^Replay_Window, id: u64) {
	if replay_check(r, id) {
		replay_set(r, id)
	}
}

// Marks an id that `replay_check` has accepted.
@(private)
replay_set :: #force_inline proc "contextless" (r: ^Replay_Window, id: u64) {
	if id > r.top {
		gap := id - r.top
		if gap > r.mask {
			// Further than the window: everything old is out.
			r.bits = {}
		} else {
			// Clear the ring slots of the ids that were skipped, then the
			// slot that the new top reuses.
			for i := r.top + 1; i <= id; i += 1 {
				pos := i & r.mask
				r.bits[pos >> 6] &~= u64(1) << (pos & 63)
			}
		}
		r.top = id
	}
	pos := id & r.mask
	r.bits[pos >> 6] |= u64(1) << (pos & 63)
}

// Check and commit in one step. True if the id was fresh.
replay_accept :: #force_inline proc "contextless" (r: ^Replay_Window, id: u64) -> bool {
	if !replay_check(r, id) {
		return false
	}
	replay_set(r, id)
	return true
}
