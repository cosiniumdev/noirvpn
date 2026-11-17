// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Apply a state-changing request once per request id.
// nng REQ resends a request after a reconnect or timer, so the daemon can see
// it twice. The cache keeps the reply of each state-changing request for a
// window. A repeat of the same id gets the stored reply; the handler does not
// run again.
//   - Key: sender uid + id (users cannot collide).
//   - A repeat must have the same hash. Same id, other content: `conflict`.
//   - No locking, no clock: the caller holds a lock and passes the time (ns,
//     any steady clock).
//   - Bounded: at most `max_entries`; oldest finished entries go first.

import "core:mem"
import "core:slice"

Dedupe_Key :: struct {
	uid:    u32,
	id_len: u8,
	id:     [MAX_ID_LEN]u8,
}

dedupe_key :: proc(uid: u32, id: string) -> (k: Dedupe_Key) {
	k.uid = uid
	k.id_len = u8(min(len(id), MAX_ID_LEN))
	copy(k.id[:], id)
	return
}

Dedupe_State :: enum u8 {
	// The first request is still being handled.
	Pending,
	Done,
}

Dedupe_Entry :: struct {
	hash:    u64,
	state:   Dedupe_State,
	reply:   []byte,
	// Done entries expire at this time.
	expires: i64,
	// Insertion number, to match entries to their place in the order queue.
	serial:  u64,
}

Dedupe :: struct {
	entries:     map[Dedupe_Key]Dedupe_Entry,
	order:       [dynamic]Order_Item,
	window:      i64,
	max_entries: int,
	serial:      u64,
	allocator:   mem.Allocator,
}

@(private)
Order_Item :: struct {
	key:    Dedupe_Key,
	serial: u64,
}

Dedupe_Result :: enum u8 {
	// First time: the caller must handle it and then call `dedupe_finish` (or
	// `dedupe_forget` if it did not run).
	New,
	// Same request, first one still running: wait, then ask again.
	Pending,
	// Same request, already replied to: `reply` is the stored reply.
	Done,
	// The id was used before for a different request.
	Conflict,
}

dedupe_init :: proc(d: ^Dedupe, window_ns: i64, max_entries: int, allocator := context.allocator) {
	d^ = {
		window      = window_ns,
		max_entries = max_entries,
		allocator   = allocator,
	}
	d.entries.allocator = allocator
	d.order.allocator = allocator
}

dedupe_destroy :: proc(d: ^Dedupe) {
	for _, e in d.entries {
		delete(e.reply, d.allocator)
	}
	delete(d.entries)
	delete(d.order)
	d^ = {}
}

dedupe_len :: proc(d: ^Dedupe) -> int {
	return len(d.entries)
}

// Look a request up. On `.New` an entry in state Pending is stored. The reply
// returned with `.Done` belongs to the cache: copy it before unlocking.
dedupe_check :: proc(d: ^Dedupe, key: Dedupe_Key, hash: u64, now: i64) -> (res: Dedupe_Result, reply: []byte) {
	dedupe_expire(d, now)
	if e, found := d.entries[key]; found {
		if e.hash != hash {
			return .Conflict, nil
		}
		if e.state == .Pending {
			return .Pending, nil
		}
		return .Done, e.reply
	}
	d.serial += 1
	d.entries[key] = Dedupe_Entry {
		hash   = hash,
		state  = .Pending,
		serial = d.serial,
	}
	append(&d.order, Order_Item{key, d.serial})
	dedupe_trim(d)
	return .New, nil
}

// Store the reply of a request that ran. Copies `reply`.
dedupe_finish :: proc(d: ^Dedupe, key: Dedupe_Key, reply: []byte, now: i64) {
	e, found := d.entries[key]
	if !found {
		return
	}
	delete(e.reply, d.allocator)
	e.reply = slice.clone(reply, d.allocator)
	e.state = .Done
	e.expires = now + d.window
	d.entries[key] = e
}

// Drop an entry whose request did not run (or whose result must not be kept).
dedupe_forget :: proc(d: ^Dedupe, key: Dedupe_Key) {
	if e, found := d.entries[key]; found {
		delete(e.reply, d.allocator)
		delete_key(&d.entries, key)
	}
}

// Remove finished entries that are past their time.
dedupe_expire :: proc(d: ^Dedupe, now: i64) {
	for len(d.order) > 0 {
		item := d.order[0]
		e, found := d.entries[item.key]
		if !found || e.serial != item.serial {
			ordered_remove(&d.order, 0)
			continue
		}
		if e.state == .Done && e.expires <= now {
			delete(e.reply, d.allocator)
			delete_key(&d.entries, item.key)
			ordered_remove(&d.order, 0)
			continue
		}
		break
	}
}

// Keep the cache below its size limit by dropping the oldest finished entries.
@(private)
dedupe_trim :: proc(d: ^Dedupe) {
	i := 0
	for len(d.entries) > d.max_entries && i < len(d.order) {
		item := d.order[i]
		e, found := d.entries[item.key]
		if !found || e.serial != item.serial {
			ordered_remove(&d.order, i)
			continue
		}
		if e.state == .Done {
			delete(e.reply, d.allocator)
			delete_key(&d.entries, item.key)
			ordered_remove(&d.order, i)
			continue
		}
		i += 1
	}
}
