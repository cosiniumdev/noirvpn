// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:testing"
import "core:time"

// A manual clock: tests pass `now` as plain seconds.
@(private = "file")
sec :: proc(n: int) -> time.Duration {
	return time.Duration(n) * time.Second
}

@(private = "file")
set_of :: proc(ids: ..u8) -> (s: Key_Id_Set) {
	for i in ids {
		s += {int(i)}
	}
	return
}

@(test)
key_id_sequence :: proc(t: ^testing.T) {
	// 0, 1, ... 7, then 7 wraps to 1.
	id := u8(0)
	want := [?]u8{1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 5, 6, 7, 1}
	for w in want {
		id = key_id_next(id)
		testing.expect_value(t, id, w)
	}
	testing.expect_value(t, key_id_next(200), 1)
}

@(test)
slots_first_key :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	testing.expect_value(t, slots_next_key_id(&s), 0)
	_, _, ok := slots_primary(&s)
	testing.expect(t, !ok, "no primary yet")
	_, ok = slots_tx_key(&s, 0)
	testing.expect(t, !ok, "nothing to send with")
	testing.expect(t, !slots_rx_ok(&s, 0, 0), "key 0 not installed")

	dropped, err := slots_install(&s, 0, sec(5))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect_value(t, slots_next_key_id(&s), 1)
	id, est, pok := slots_primary(&s)
	testing.expect(t, pok, "primary")
	testing.expect_value(t, id, 0)
	testing.expect_value(t, est, sec(5))
	testing.expect(t, slots_rx_ok(&s, 0, sec(5)), "rx 0")
	testing.expect(t, !slots_rx_ok(&s, 1, sec(5)), "rx 1")
	testing.expect(t, !slots_rx_ok(&s, 8, sec(5)), "rx 8")
	k, tok := slots_tx_key(&s, sec(5))
	testing.expect(t, tok, "tx")
	testing.expect_value(t, k, 0)

	_, err = slots_install(&s, 0, sec(6))
	testing.expect_value(t, err, Error.Key_Id_In_Use)
	_, err = slots_install(&s, 9, sec(6))
	testing.expect_value(t, err, Error.Bad_Key_Id)
	// `established` can be earlier than the install time.
	s2: Key_Slots
	slots_init(&s2)
	_, _ = slots_install(&s2, 0, sec(100), sec(40))
	_, est, _ = slots_primary(&s2)
	testing.expect_value(t, est, sec(40))
}

@(test)
slots_rekey_transition :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s) // 3600 s transition window, no send delay
	_, _ = slots_install(&s, 0, sec(0))

	// Key 1 arrives at t = 3600: accepted at once, and used for sending at once.
	dropped, err := slots_install(&s, 1, sec(3600))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect(t, slots_rx_ok(&s, 1, sec(3600)), "new key at once")
	testing.expect(t, slots_rx_ok(&s, 0, sec(3600)), "old key kept")
	k, _ := slots_tx_key(&s, sec(3600))
	testing.expect_value(t, k, 1)

	// The old key receives for the whole transition window: 3600 s.
	testing.expect(t, slots_rx_ok(&s, 0, sec(3600 + 3599)), "old key, 1 s before its end")
	testing.expect(t, !slots_rx_ok(&s, 0, sec(3600 + 3600)), "old key at the end")
	at, ok := slots_next_expiry(&s)
	testing.expect(t, ok, "expiry known")
	testing.expect_value(t, at, sec(7200))

	// It is gone for good after expire().
	testing.expect_value(t, slots_expire(&s, sec(7199)), Key_Id_Set{})
	testing.expect_value(t, slots_expire(&s, sec(7200)), set_of(0))
	testing.expect(t, !slots_rx_ok(&s, 0, sec(7200)), "old key dropped")
	testing.expect(t, slots_rx_ok(&s, 1, sec(99999)), "primary never expires on its own")
	_, ok = slots_next_expiry(&s)
	testing.expect(t, !ok, "nothing left to expire")
	testing.expect_value(t, slots_expire(&s, sec(99999)), Key_Id_Set{})
}

@(test)
slots_next_rekey_replaces_lame :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	_, _ = slots_install(&s, 0, sec(0))
	_, _ = slots_install(&s, 1, sec(100))
	// A further renegotiation 200 s later replaces the lame key 0 at once.
	dropped, err := slots_install(&s, 2, sec(300))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, set_of(0))
	testing.expect(t, !slots_rx_ok(&s, 0, sec(300)), "key 0 gone")
	testing.expect(t, slots_rx_ok(&s, 1, sec(300)), "key 1 lame")
	testing.expect(t, slots_rx_ok(&s, 2, sec(300)), "key 2 primary")
	// The lame key's window counts from its replacement (t = 300).
	at, _ := slots_next_expiry(&s)
	testing.expect_value(t, at, sec(300 + 3600))
	testing.expect_value(t, slots_in_use(&s), set_of(1, 2))
	// Key 0 may be used again by a later session (id wrap), not while it is held.
	_, err = slots_install(&s, 1, sec(400))
	testing.expect_value(t, err, Error.Key_Id_In_Use)
}

// With a grace time:
// - the lame key is dropped when the new key is installed (not when the next
//   soft reset begins), and it still receives for the grace time
// - the key before it goes when a soft reset begins
@(test)
slots_grace_key :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s, {tran_window = sec(3600), lame_grace = sec(60)})
	_, _ = slots_install(&s, 0, sec(0))
	slots_rekey_started(&s, sec(100))
	dropped, err := slots_install(&s, 1, sec(100))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect_value(t, slots_in_use(&s), set_of(0, 1))

	// A second soft reset 10 s later: key 0 is the lame key and stays through the handshake.
	dropped = slots_rekey_started(&s, sec(110))
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect(t, slots_rx_ok(&s, 0, sec(111)), "lame key during the handshake")
	// The new key arrives: 0 becomes the grace key, 1 the lame key.
	dropped, err = slots_install(&s, 2, sec(112))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect_value(t, slots_in_use(&s), set_of(0, 1, 2))
	testing.expect(t, slots_rx_ok(&s, 0, sec(171)), "grace key receives")
	testing.expect(t, !slots_rx_ok(&s, 0, sec(172)), "grace over")
	// It never sends: the primary does, or the lame key if the primary cannot.
	k, ok := slots_tx_key(&s, sec(120))
	testing.expect(t, ok, "sends")
	testing.expect_value(t, k, 2)
	slots_block_tx(&s, 2)
	k, ok = slots_tx_key(&s, sec(120))
	testing.expect(t, ok, "lame key sends")
	testing.expect_value(t, k, 1)
	slots_block_tx(&s, 1)
	_, ok = slots_tx_key(&s, sec(120))
	testing.expect(t, !ok, "the grace key does not send")
	// The timer sees it: expiry at 112 + 60.
	at, aok := slots_next_expiry(&s)
	testing.expect(t, aok, "expiry")
	testing.expect_value(t, at, sec(172))
	dropped = slots_expire(&s, sec(172))
	testing.expect_value(t, dropped, set_of(0))
	testing.expect_value(t, slots_in_use(&s), set_of(1, 2))

	// Another soft reset before the grace time ends drops the grace key at once, the lame key stays.
	s2: Key_Slots
	slots_init(&s2, {tran_window = sec(3600), lame_grace = sec(60)})
	_, _ = slots_install(&s2, 0, sec(0))
	slots_rekey_started(&s2, sec(10))
	_, _ = slots_install(&s2, 1, sec(10))
	slots_rekey_started(&s2, sec(20))
	_, _ = slots_install(&s2, 2, sec(20)) // 0 is the grace key now (until 80)
	dropped = slots_rekey_started(&s2, sec(30))
	testing.expect_value(t, dropped, set_of(0))
	testing.expect_value(t, slots_in_use(&s2), set_of(1, 2))
	dropped, err = slots_install(&s2, 3, sec(31))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, Key_Id_Set{})
	testing.expect_value(t, slots_in_use(&s2), set_of(1, 2, 3)) // 1 grace, 2 lame, 3 primary
	// An install without `slots_rekey_started` first drops the grace key.
	dropped, err = slots_install(&s2, 4, sec(32))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dropped, set_of(1))
	testing.expect_value(t, slots_in_use(&s2), set_of(2, 3, 4))

	// The transition window caps the grace: a short window ends it sooner.
	s3: Key_Slots
	slots_init(&s3, {tran_window = sec(20), lame_grace = sec(60)})
	_, _ = slots_install(&s3, 0, sec(0))
	slots_rekey_started(&s3, sec(100))
	_, _ = slots_install(&s3, 1, sec(100))
	slots_rekey_started(&s3, sec(105))
	_, _ = slots_install(&s3, 2, sec(105))
	at, _ = slots_next_expiry(&s3)
	testing.expect_value(t, at, sec(120)) // key 0: soft reset 100 + window 20, not 105 + 60

	// Without a grace time the table is as the spec says.
	s4: Key_Slots
	slots_init(&s4)
	_, _ = slots_install(&s4, 0, sec(0))
	slots_rekey_started(&s4, sec(100))
	_, _ = slots_install(&s4, 1, sec(100))
	dropped = slots_rekey_started(&s4, sec(110))
	testing.expect_value(t, dropped, set_of(0))
	slots_clear(&s4)
	testing.expect_value(t, slots_in_use(&s4), Key_Id_Set{})
}

@(test)
slots_id_wrap_seven_to_one :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	now := sec(0)
	for i in 0 ..< 10 {
		id := slots_next_key_id(&s)
		_, err := slots_install(&s, id, now)
		testing.expectf(t, err == .None, "install %d (key id %d): %v", i, id, err)
		now += sec(60)
	}
	// 0, 1..7, then 1, 2: the primary is key id 2.
	id, _, _ := slots_primary(&s)
	testing.expect_value(t, id, 2)
	testing.expect_value(t, slots_next_key_id(&s), 3)
	testing.expect_value(t, slots_in_use(&s), set_of(1, 2))
}

// A stock peer waits before it sends on a new key. With a send delay the old
// key stays the send key until the new one is ready, and both receive.
@(test)
slots_send_delay :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s, {tran_window = sec(3600), tx_delay = sec(60)})
	_, _ = slots_install(&s, 0, sec(0))
	k, _ := slots_tx_key(&s, sec(1000))
	testing.expect_value(t, k, 0)

	_, _ = slots_install(&s, 1, sec(3000))
	testing.expect(t, slots_rx_ok(&s, 1, sec(3000)), "rx on the new key at once")
	k, _ = slots_tx_key(&s, sec(3000))
	testing.expect_value(t, k, 0)
	k, _ = slots_tx_key(&s, sec(3059))
	testing.expect_value(t, k, 0)
	k, _ = slots_tx_key(&s, sec(3060))
	testing.expect_value(t, k, 1)
	// If the old key were gone, the primary is used even before it is ready.
	s3: Key_Slots
	slots_init(&s3, {tran_window = sec(10), tx_delay = sec(60)})
	_, _ = slots_install(&s3, 0, sec(0))
	_, _ = slots_install(&s3, 1, sec(100))
	ok: bool
	k, ok = slots_tx_key(&s3, sec(105))
	testing.expect(t, ok, "old key still there")
	testing.expect_value(t, k, 0)
	k, ok = slots_tx_key(&s3, sec(111)) // lame expired at 110, primary ready at 160
	testing.expect(t, ok, "primary used before it is ready")
	testing.expect_value(t, k, 1)
}

@(test)
slots_blocked_send_key :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	_, _ = slots_install(&s, 0, sec(0))
	slots_block_tx(&s, 0) // packet ids used up
	_, ok := slots_tx_key(&s, sec(1))
	testing.expect(t, !ok, "cannot send until a new key exists")
	// Receiving is not affected.
	testing.expect(t, slots_rx_ok(&s, 0, sec(1)), "still receives")

	_, _ = slots_install(&s, 1, sec(2))
	k, ok2 := slots_tx_key(&s, sec(2))
	testing.expect(t, ok2, "new key sends")
	testing.expect_value(t, k, 1)
	// The primary blocked, the old key still sending is not a thing: 0 is blocked too.
	slots_block_tx(&s, 1)
	_, ok = slots_tx_key(&s, sec(3))
	testing.expect(t, !ok, "both blocked")
	// Unblocked lame key keeps sending when the primary is blocked.
	s2: Key_Slots
	slots_init(&s2)
	_, _ = slots_install(&s2, 0, sec(0))
	_, _ = slots_install(&s2, 1, sec(1))
	slots_block_tx(&s2, 1)
	k, ok = slots_tx_key(&s2, sec(2))
	testing.expect(t, ok, "lame key sends")
	testing.expect_value(t, k, 0)
	slots_block_tx(&s2, 77) // out of range: ignored
}

@(test)
slots_remove_and_clear :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	_, _ = slots_install(&s, 0, sec(0))
	_, _ = slots_install(&s, 1, sec(10))
	testing.expect(t, !slots_remove(&s, 5), "unused id")
	testing.expect(t, !slots_remove(&s, 9), "bad id")
	testing.expect(t, slots_remove(&s, 1), "remove primary")
	testing.expect(t, !slots_rx_ok(&s, 1, sec(11)), "removed key does not receive")
	// The lame key remains and still works for both directions until it expires.
	k, ok := slots_tx_key(&s, sec(11))
	testing.expect(t, ok, "lame key sends")
	testing.expect_value(t, k, 0)
	testing.expect_value(t, slots_next_key_id(&s), 0) // no primary: a new session

	_, _ = slots_install(&s, 2, sec(20))
	testing.expect_value(t, slots_in_use(&s), set_of(2)) // the old lame key was dropped
	testing.expect_value(t, slots_clear(&s), set_of(2))
	testing.expect_value(t, slots_in_use(&s), Key_Id_Set{})
	testing.expect_value(t, slots_next_key_id(&s), 0)
	// The config survives a clear.
	_, _ = slots_install(&s, 0, sec(0))
	_, _ = slots_install(&s, 1, sec(1))
	at, _ := slots_next_expiry(&s)
	testing.expect_value(t, at, sec(1) + DEFAULT_TRAN_WINDOW)
}

// Walks one session over several rekeys with a manual clock, using the rekey
// trigger, as the session layer would.
@(test)
slots_with_rekey_policy :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	p := Rekey_Policy {
		cipher    = .AES_256_GCM,
		format    = .Baseline,
		reneg_sec = 600,
	}
	_, _ = slots_install(&s, 0, sec(0))
	rekeys := 0
	for now := sec(0); now <= sec(3600); now += sec(10) {
		slots_expire(&s, now)
		_, est, _ := slots_primary(&s)
		u: Key_Usage
		if rekey_check(&p, est, now, &u) == .Age {
			_, err := slots_install(&s, slots_next_key_id(&s), now)
			testing.expect_value(t, err, Error.None)
			rekeys += 1
		}
	}
	testing.expect_value(t, rekeys, 6)
	id, _, _ := slots_primary(&s)
	testing.expect_value(t, id, 6)
}

// the transition window counts from the soft reset, and the
// older lame key goes at that moment.
@(test)
slots_window_counts_from_the_soft_reset :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	_, _ = slots_install(&s, 0, sec(0))
	_, _ = slots_install(&s, 1, sec(1000)) // key 0 is lame until 4600

	// Soft reset at t = 3600: key 0 goes now; key 1 has a window until 7200.
	dropped := slots_rekey_started(&s, sec(3600))
	testing.expect_value(t, dropped, set_of(0))
	testing.expect(t, !slots_rx_ok(&s, 0, sec(3600)), "key 0 is gone")
	testing.expect(t, slots_rx_ok(&s, 1, sec(3600)), "key 1 still works")
	k, ok := slots_tx_key(&s, sec(3601))
	testing.expect(t, ok, "key 1 still sends")
	testing.expect_value(t, k, 1)
	at, _ := slots_next_expiry(&s)
	testing.expect_value(t, at, sec(7200))
	// A second call changes nothing.
	testing.expect_value(t, slots_rekey_started(&s, sec(3700)), Key_Id_Set{})
	at, _ = slots_next_expiry(&s)
	testing.expect_value(t, at, sec(7200))

	// The new key arrives after 30 s: the window of key 1 still ends at 7200.
	_, err := slots_install(&s, 2, sec(3630))
	testing.expect_value(t, err, Error.None)
	testing.expect(t, slots_rx_ok(&s, 1, sec(7199)), "key 1 until the end of its window")
	testing.expect(t, !slots_rx_ok(&s, 1, sec(7200)), "key 1 at the end")
	at, _ = slots_next_expiry(&s)
	testing.expect_value(t, at, sec(7200))
	testing.expect_value(t, slots_expire(&s, sec(7200)), set_of(1))
	testing.expect(t, slots_rx_ok(&s, 2, sec(10000)), "key 2 is the primary")
	// The primary key of the new session part has no deadline.
	_, ok = slots_next_expiry(&s)
	testing.expect(t, !ok, "no expiry for the primary")
}

// A renegotiation that never finishes: the old key works until its window
// ends, then the session has no key at all.
@(test)
slots_failed_renegotiation :: proc(t: ^testing.T) {
	s: Key_Slots
	slots_init(&s)
	_, _ = slots_install(&s, 0, sec(0))
	testing.expect_value(t, slots_rekey_started(&s, sec(100)), Key_Id_Set{})
	for now in ([?]int{101, 1000, 3699}) {
		testing.expect(t, slots_rx_ok(&s, 0, sec(now)), "rx")
		_, ok := slots_tx_key(&s, sec(now))
		testing.expect(t, ok, "tx")
	}
	testing.expect_value(t, slots_expire(&s, sec(3699)), Key_Id_Set{})
	testing.expect(t, !slots_rx_ok(&s, 0, sec(3700)), "rx at the end")
	_, ok := slots_tx_key(&s, sec(3700))
	testing.expect(t, !ok, "tx at the end")
	testing.expect_value(t, slots_expire(&s, sec(3700)), set_of(0))
	testing.expect_value(t, slots_in_use(&s), Key_Id_Set{})
	testing.expect_value(t, slots_next_key_id(&s), 0) // start over with a hard reset
	// With no primary, a soft reset is not possible and the call is harmless.
	testing.expect_value(t, slots_rekey_started(&s, sec(4000)), Key_Id_Set{})
}
