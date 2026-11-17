// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package reliable

// Is `id` among the first `n` entries of `ids`?
@(private)
has_id :: proc(ids: []u32, id: u32) -> bool {
	for x in ids {
		if x == id {
			return true
		}
	}
	return false
}

// Queues `id` to be acknowledged, unless it is already queued or the pending
// list is full. A full list means no ack for this
// id now. The sender retransmits it and gets an ack then.
@(private)
add_pending :: proc(c: ^Channel, id: u32) {
	if has_id(c.pending[:c.pending_n], id) {
		return
	}
	if c.pending_n >= ACK_LIST_MAX {
		c.stats.pending_full += 1
		return
	}
	c.pending[c.pending_n] = id
	c.pending_n += 1
}

// Builds an ack array of at most `limit` ids.
// - Ids that must be acked now come first, in arrival order.
// - Spare room: ids acked lately, most recent first (the next packet repairs
//   one lost ack).
// - Ids put in the array leave the pending list and become the newest entries of
//   the recent list. Ids that do not fit stay pending.
//
// SPEC-GAP: the spec does not say when an id enters the recent list or whether a
// repeat moves it to the front. Here an id enters when written as a "must ack
// now" id; a repeat does not move it.
@(private)
take_acks :: proc(c: ^Channel, max_ids: int) -> (out: Ack_List) {
	limit := min(max_ids, ACK_LIST_MAX)
	n := min(c.pending_n, limit)
	for i in 0 ..< n {
		out.ids[i] = c.pending[i]
	}
	copy(c.pending[:], c.pending[n:c.pending_n])
	c.pending_n -= n

	// New recent list: what was just acked (newest first), then the old one.
	fresh: [ACK_LIST_MAX]u32
	m := 0
	for i := n - 1; i >= 0; i -= 1 {
		fresh[m] = out.ids[i]
		m += 1
	}
	// Repeat old ids to fill the array.
	total := n
	for i in 0 ..< c.recent_n {
		if total >= limit {
			break
		}
		if !has_id(out.ids[:total], c.recent[i]) {
			out.ids[total] = c.recent[i]
			total += 1
		}
	}
	for i in 0 ..< c.recent_n {
		if m >= ACK_LIST_MAX {
			break
		}
		if !has_id(fresh[:m], c.recent[i]) {
			fresh[m] = c.recent[i]
			m += 1
		}
	}
	c.recent = fresh
	c.recent_n = m

	out.count = u8(total)
	if total > 0 {
		out.sid = c.cfg.peer_sid
	}
	return out
}
