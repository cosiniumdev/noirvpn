// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:testing"

SEC :: i64(1_000_000_000)

@(test)
dedupe_new_pending_done :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 10 * SEC, 8)
	defer dedupe_destroy(&d)
	k := dedupe_key(1000, "req-1")

	r, _ := dedupe_check(&d, k, 111, 0)
	testing.expect_value(t, r, Dedupe_Result.New)
	// A repeat while the first runs.
	r, _ = dedupe_check(&d, k, 111, 1)
	testing.expect_value(t, r, Dedupe_Result.Pending)

	reply := transmute([]byte)string(`{"ok":true}`)
	dedupe_finish(&d, k, reply, 2)
	cached: []byte
	r, cached = dedupe_check(&d, k, 111, 3)
	testing.expect_value(t, r, Dedupe_Result.Done)
	testing.expect_value(t, string(cached), `{"ok":true}`)
	// The cache holds its own copy.
	testing.expect(t, raw_data(cached) != raw_data(reply))
}

@(test)
dedupe_conflict_and_scope :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 10 * SEC, 8)
	defer dedupe_destroy(&d)
	k := dedupe_key(1000, "same")
	r, _ := dedupe_check(&d, k, 1, 0)
	testing.expect_value(t, r, Dedupe_Result.New)
	dedupe_finish(&d, k, transmute([]byte)string("x"), 0)

	// Same id and uid, different content.
	r, _ = dedupe_check(&d, k, 2, 1)
	testing.expect_value(t, r, Dedupe_Result.Conflict)
	// Same id, another user: its own entry.
	r, _ = dedupe_check(&d, dedupe_key(1001, "same"), 2, 1)
	testing.expect_value(t, r, Dedupe_Result.New)
	// The original is still intact.
	r, _ = dedupe_check(&d, k, 1, 2)
	testing.expect_value(t, r, Dedupe_Result.Done)
}

@(test)
dedupe_window_expires :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 10 * SEC, 8)
	defer dedupe_destroy(&d)
	k := dedupe_key(1, "a")
	dedupe_check(&d, k, 5, 0)
	dedupe_finish(&d, k, transmute([]byte)string("r"), 100 * SEC)
	// Inside the window.
	r, _ := dedupe_check(&d, k, 5, 109 * SEC)
	testing.expect_value(t, r, Dedupe_Result.Done)
	// Past it: forgotten, so the same id runs again.
	r, _ = dedupe_check(&d, k, 5, 110 * SEC)
	testing.expect_value(t, r, Dedupe_Result.New)
	testing.expect_value(t, dedupe_len(&d), 1)
}

@(test)
dedupe_pending_never_expires_but_forget_removes :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 1 * SEC, 8)
	defer dedupe_destroy(&d)
	k := dedupe_key(1, "p")
	dedupe_check(&d, k, 5, 0)
	r, _ := dedupe_check(&d, k, 5, 1000 * SEC)
	testing.expect_value(t, r, Dedupe_Result.Pending)
	dedupe_forget(&d, k)
	r, _ = dedupe_check(&d, k, 5, 1000 * SEC)
	testing.expect_value(t, r, Dedupe_Result.New)
}

@(test)
dedupe_is_bounded :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 1000 * SEC, 4)
	defer dedupe_destroy(&d)
	ids := [?]string{"a", "b", "c", "d", "e", "f", "g"}
	for id, i in ids {
		k := dedupe_key(1, id)
		dedupe_check(&d, k, 1, i64(i))
		dedupe_finish(&d, k, transmute([]byte)id, i64(i))
	}
	testing.expect(t, dedupe_len(&d) <= 4)
	// The newest are kept, the oldest are gone.
	r, _ := dedupe_check(&d, dedupe_key(1, "g"), 1, 10)
	testing.expect_value(t, r, Dedupe_Result.Done)
	r, _ = dedupe_check(&d, dedupe_key(1, "a"), 1, 10)
	testing.expect_value(t, r, Dedupe_Result.New)
}

@(test)
dedupe_pending_entries_are_not_trimmed :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 1000 * SEC, 2)
	defer dedupe_destroy(&d)
	for id in ([?]string{"a", "b", "c"}) {
		r, _ := dedupe_check(&d, dedupe_key(1, id), 1, 0)
		testing.expect_value(t, r, Dedupe_Result.New)
	}
	// All three still pending: nothing may be dropped.
	for id in ([?]string{"a", "b", "c"}) {
		r, _ := dedupe_check(&d, dedupe_key(1, id), 1, 0)
		testing.expect_value(t, r, Dedupe_Result.Pending)
	}
}

@(test)
dedupe_forget_then_reuse_order_is_consistent :: proc(t: ^testing.T) {
	d: Dedupe
	dedupe_init(&d, 5 * SEC, 4)
	defer dedupe_destroy(&d)
	k := dedupe_key(1, "x")
	for round in 0 ..< 20 {
		now := i64(round) * SEC
		r, _ := dedupe_check(&d, k, 1, now)
		testing.expect_value(t, r, Dedupe_Result.New)
		if round % 2 == 0 {
			dedupe_forget(&d, k)
		} else {
			dedupe_finish(&d, k, transmute([]byte)string("r"), now)
			dedupe_forget(&d, k)
		}
	}
	dedupe_expire(&d, 1000 * SEC)
	testing.expect_value(t, dedupe_len(&d), 0)
	testing.expect_value(t, len(d.order), 0)
}

@(test)
dedupe_key_uses_full_id :: proc(t: ^testing.T) {
	a := dedupe_key(1, "abc")
	b := dedupe_key(1, "abd")
	testing.expect(t, a != b)
	long := "0123456789012345678901234567890123456789012345678901234567890123"
	testing.expect_value(t, len(long), MAX_ID_LEN)
	k := dedupe_key(1, long)
	testing.expect_value(t, int(k.id_len), MAX_ID_LEN)
}

@(test)
hash_differs_for_different_bodies :: proc(t: ^testing.T) {
	a := hash_bytes(transmute([]byte)string(`{"v":1,"id":"1","op":"status"}`))
	b := hash_bytes(transmute([]byte)string(`{"v":1,"id":"1","op":"peers.list"}`))
	testing.expect(t, a != b)
	testing.expect_value(t, a, hash_bytes(transmute([]byte)string(`{"v":1,"id":"1","op":"status"}`)))
}
