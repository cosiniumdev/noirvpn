// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:mem"
import "noir:proto/ossl"

// Epoch key schedule. Each direction has a chain of
// 32-byte epoch keys E1, E2, ... E1 comes from the exporter. From E(i):
//
//   data key   K(i)   = ExpandLabel(E(i), "data_key", key_len)
//   data IV    IV(i)  = ExpandLabel(E(i), "data_iv", 12)
//   next       E(i+1) = ExpandLabel(E(i), "datakey upd", 32)
//
// A used E is wiped when the next one is generated, so a later memory leak cannot
// reveal older traffic.

EPOCH_IV_LEN :: 12
// Largest epoch number. 0 is never valid.
EPOCH_MAX :: 65535
// Keys precomputed ahead of the current receive epoch.
EPOCH_FUTURE :: 4
// Highest epoch a receiver accepts as a "future" epoch.
EPOCH_FUTURE_MAX :: EPOCH_MAX - EPOCH_FUTURE - 1
// A sender should ask for a renegotiation when its epoch gets here (6.4).
EPOCH_REKEY_AT :: 0xF000
// Receive slots: current, retiring, and the future keys.
EPOCH_SLOTS :: EPOCH_FUTURE + 2

// HKDF-Expand with the `ovpn ` info prefix. `secret` is
// 32 bytes, `label` 1 to 250, `context` up to 255. Fills all of `out`.
expand_label :: proc "contextless" (secret: []u8, label: string, context_bytes: []u8, out: []u8) -> bool {
	if len(secret) != EPOCH_KEY_LEN || len(label) < 1 || len(label) > 250 || len(context_bytes) > 255 || len(out) == 0 {
		return false
	}
	info: [2 + 1 + 5 + 250 + 1 + 255]u8
	n := expand_label_info(info[:], label, context_bytes, len(out))
	return ossl.hkdf_expand(.SHA256, secret, info[:n], out)
}

// Writes the ExpandLabel info block, returns its length:
//   out_len (u16 BE), 5 + len(label), "ovpn ", label, len(context), context
// `buf` needs 2 + 1 + 5 + len(label) + 1 + len(context) bytes.
expand_label_info :: proc "contextless" (buf: []u8, label: string, context_bytes: []u8, out_len: int) -> int {
	buf[0] = u8(out_len >> 8)
	buf[1] = u8(out_len)
	buf[2] = u8(5 + len(label))
	prefix := "ovpn "
	n := 3
	n += copy(buf[n:], prefix)
	n += copy(buf[n:], label)
	buf[n] = u8(len(context_bytes))
	n += 1
	n += copy(buf[n:], context_bytes)
	return n
}

// One epoch of one direction: the chain key and what comes out of it.
Epoch_Key :: struct {
	epoch:   u16, // 0: the slot is unused
	key_len: u8,
	e:       [EPOCH_KEY_LEN]u8, // E(epoch); wiped once the next epoch exists
	key:     [MAX_KEY_LEN]u8, // K(epoch); the first key_len bytes
	iv:      [EPOCH_IV_LEN]u8, // IV(epoch)
}

epoch_key_wipe :: proc "contextless" (k: ^Epoch_Key) {
	mem.zero_explicit(k, size_of(Epoch_Key))
}

// Sets `k` to `epoch` with chain key `e`, and derives its key and IV.
epoch_key_set :: proc "contextless" (k: ^Epoch_Key, epoch: u16, e: []u8, key_len: int) -> Error {
	if epoch == 0 || len(e) != EPOCH_KEY_LEN || (key_len != 16 && key_len != 32) {
		return .Bad_Argument
	}
	k^ = {}
	k.epoch = epoch
	k.key_len = u8(key_len)
	copy(k.e[:], e)
	if !expand_label(k.e[:], "data_key", nil, k.key[:key_len]) || !expand_label(k.e[:], "data_iv", nil, k.iv[:]) {
		epoch_key_wipe(k)
		return .Crypto
	}
	return .None
}

// Generates epoch `from.epoch + 1` in `to` and wipes the chain key of `from` (its
// key and IV stay: it may still be needed to open late packets).
epoch_key_step :: proc "contextless" (from, to: ^Epoch_Key) -> Error {
	if from.epoch == EPOCH_MAX {
		return .Epoch_Exhausted
	}
	next: [EPOCH_KEY_LEN]u8
	defer mem.zero_explicit(&next, size_of(next))
	if !expand_label(from.e[:], "datakey upd", nil, next[:]) {
		return .Crypto
	}
	key_len := int(from.key_len)
	epoch := from.epoch + 1
	mem.zero_explicit(&from.e, size_of(from.e))
	return epoch_key_set(to, epoch, next[:], key_len)
}

// --- Send side ---

// Starts the send chain at epoch 1 from E1.
epoch_send_init :: proc "contextless" (k: ^Epoch_Key, e1: []u8, key_len: int) -> Error {
	return epoch_key_set(k, 1, e1, key_len)
}

// Moves the send chain to epoch `to` (one step per epoch, in place). `to` must
// be above the current epoch. On error the key is wiped: stop using the sender.
epoch_send_advance :: proc "contextless" (k: ^Epoch_Key, to: u16) -> Error {
	if to <= k.epoch {
		return .Bad_Epoch
	}
	for k.epoch < to {
		if err := epoch_key_step(k, k); err != .None {
			epoch_key_wipe(k)
			return err
		}
	}
	return .None
}

// --- Receive side ---

// What a received epoch number means.
Epoch_Class :: enum {
	Drop, // 0, or unknown
	Current,
	Retiring, // the previous epoch, kept for late packets
	Future, // one of the precomputed keys
}

// Receive keys of one key id: current epoch, retiring one, up to 4 future ones.
// The fixed array lets package crypt keep AEAD contexts at the same indices.
// A slot with epoch 0 is empty.
Epoch_Recv :: struct {
	slots:   [EPOCH_SLOTS]Epoch_Key,
	current: int, // slot index
	retiring: int, // slot index, or -1
}

// Which slots changed, so the caller can keep its own per-slot state in step.
Epoch_Change :: struct {
	freed:  bit_set[0 ..< EPOCH_SLOTS; u8], // key wiped: destroy what you built from it
	filled: bit_set[0 ..< EPOCH_SLOTS; u8], // new key: build contexts for it, empty replay state
}

// Starts the receive chain: epoch 1 is current, 2 to 5 are future keys.
// Returns the filled slots (all five).
epoch_recv_init :: proc "contextless" (r: ^Epoch_Recv, e1: []u8, key_len: int) -> (change: Epoch_Change, err: Error) {
	r^ = {}
	r.retiring = -1
	if err = epoch_send_init(&r.slots[0], e1, key_len); err != .None {
		return {}, err
	}
	r.current = 0
	change.filled += {0}
	err = epoch_recv_fill(r, &change)
	if err != .None {
		epoch_recv_wipe(r)
		return {}, err
	}
	return change, .None
}

epoch_recv_wipe :: proc "contextless" (r: ^Epoch_Recv) {
	mem.zero_explicit(r, size_of(Epoch_Recv))
	r.retiring = -1
}

// Finds the slot for epoch `e`. Changes nothing.
//
//   0                                          -> Drop
//   current epoch                              -> Current
//   retiring epoch                             -> Retiring
//   current < e <= current + 4 and e <= 65530  -> Future
//   anything else                              -> Drop
epoch_recv_lookup :: proc "contextless" (r: ^Epoch_Recv, e: u16) -> (slot: int, class: Epoch_Class) {
	cur := r.slots[r.current].epoch
	if e == 0 || cur == 0 {
		return -1, .Drop // epoch 0 is never valid; cur == 0 means a wiped receiver
	}
	if e == cur {
		return r.current, .Current
	}
	if r.retiring >= 0 && e == r.slots[r.retiring].epoch {
		return r.retiring, .Retiring
	}
	if e <= cur || e > EPOCH_FUTURE_MAX || e - cur > EPOCH_FUTURE {
		return -1, .Drop
	}
	for i in 0 ..< EPOCH_SLOTS {
		if r.slots[i].epoch == e {
			return i, .Future
		}
	}
	return -1, .Drop
}

// A packet of a future epoch passed its tag check (steps 1 to 4):
// 1. The slot for `e` becomes current.
// 2. The old current becomes retiring (the old retiring key is wiped).
// 3. Skipped epochs are wiped.
// 4. The future window is refilled to e + 4.
// `e` must be a `.Future` epoch.
// On error the receiver is wiped and unusable.
epoch_recv_promote :: proc "contextless" (r: ^Epoch_Recv, e: u16) -> (change: Epoch_Change, err: Error) {
	slot, class := epoch_recv_lookup(r, e)
	if class != .Future {
		return {}, .Bad_Epoch
	}
	old_cur := r.slots[r.current].epoch
	if r.retiring >= 0 {
		epoch_key_wipe(&r.slots[r.retiring])
		change.freed += {r.retiring}
	}
	r.retiring = r.current
	r.current = slot
	// Epochs between the old and the new current are skipped for good.
	for i in 0 ..< EPOCH_SLOTS {
		ep := r.slots[i].epoch
		if ep > old_cur && ep < e {
			epoch_key_wipe(&r.slots[i])
			change.freed += {i}
		}
	}
	if err = epoch_recv_fill(r, &change); err != .None {
		epoch_recv_wipe(r)
		return {}, err
	}
	return change, .None
}

// Derives future keys until the window reaches current + 4 (at most epoch
// 65535). Starts from the slot with the highest epoch (it still has its
// chain key).
@(private)
epoch_recv_fill :: proc "contextless" (r: ^Epoch_Recv, change: ^Epoch_Change) -> Error {
	target := min(u32(r.slots[r.current].epoch) + EPOCH_FUTURE, EPOCH_MAX)
	for {
		lead := 0
		for i in 1 ..< EPOCH_SLOTS {
			if r.slots[i].epoch > r.slots[lead].epoch {
				lead = i
			}
		}
		if u32(r.slots[lead].epoch) >= target {
			return .None
		}
		empty := -1
		for i in 0 ..< EPOCH_SLOTS {
			if r.slots[i].epoch == 0 {
				empty = i
				break
			}
		}
		if empty < 0 {
			return .Bad_Argument // cannot happen: the window always fits in 6 slots
		}
		if err := epoch_key_step(&r.slots[lead], &r.slots[empty]); err != .None {
			return err
		}
		change.filled += {empty}
	}
}
