// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:proto/session"

// Packets read from the tun wait here until sealed and sent. Fixed size. If full,
// the oldest packet is dropped (a new packet matters more than a stale one, and
// TCP inside the tunnel treats it as loss). Nothing allocates after `ring_init`.
//
// One slot more than the capacity: a spare that `ring_next` hands out, so a read
// that finds nothing never damages a waiting packet.

RING_SLOTS :: 256 // packets that can wait
// Room for the headroom, the largest IP packet we take, and the AEAD tag.
SLOT_SIZE :: 2304
MAX_TUN_PACKET :: SLOT_SIZE - session.TUNNEL_HEADROOM - 32

Slot :: struct {
	buf:    [SLOT_SIZE]u8,
	// Length of the IP packet at `buf[TUNNEL_HEADROOM:]`.
	n:      int,
	// The sealed link packet is `buf[off:][:len]` once `sealed` is true.
	off:    int,
	len:    int,
	sealed: bool,
	// Sealing failed: the slot is skipped.
	bad:    bool,
}

Ring :: struct {
	slots:   []Slot,
	head:    int,
	count:   int,
	dropped: u64, // packets overwritten because the ring was full
}

ring_init :: proc(r: ^Ring, capacity: int, allocator := context.allocator) -> bool {
	s, err := make([]Slot, capacity + 1, allocator)
	if err != nil {
		return false
	}
	r^ = {
		slots = s,
	}
	return true
}

ring_destroy :: proc(r: ^Ring, allocator := context.allocator) {
	delete(r.slots, allocator)
	r^ = {}
}

// The slot the next packet goes into (free until `ring_commit`).
ring_next :: proc(r: ^Ring) -> ^Slot {
	s := &r.slots[(r.head + r.count) % len(r.slots)]
	s.n, s.off, s.len = 0, 0, 0
	s.sealed, s.bad = false, false
	return s
}

// The slot from `ring_next` now holds a packet.
ring_commit :: proc(r: ^Ring) {
	if r.count == len(r.slots) - 1 {
		r.head = (r.head + 1) % len(r.slots)
		r.dropped += 1
	} else {
		r.count += 1
	}
}

// The k-th oldest packet (0 is the oldest).
ring_at :: proc(r: ^Ring, k: int) -> ^Slot {
	return &r.slots[(r.head + k) % len(r.slots)]
}

// Removes the `n` oldest packets.
ring_pop :: proc(r: ^Ring, n: int) {
	r.head = (r.head + n) % len(r.slots)
	r.count -= n
}

ring_clear :: proc(r: ^Ring) {
	r.head, r.count = 0, 0
}

ring_is_empty :: proc(r: ^Ring) -> bool {
	return r.count == 0
}
