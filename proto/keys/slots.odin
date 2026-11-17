// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:time"

// The key ids of one peer.
//
// At most three usable keys:
//   primary   - newest
//   lame duck - the one before, kept so late packets still open
//   grace     - the one before that, receive only, for `lame_grace`
// A key still being negotiated is not here: `slots_install` adds it after key
// exchange and login (state GENERATED_KEYS). So there are at
// most four key ids, but never more than three keys with crypto state (the
// grace key goes when the next soft reset begins, before the new key installs).
//
// Rules:
//   - Receive: the primary key; the lame key until `must_die` or until the next
//     key is installed (first one wins); then the grace key until `lame_grace`
//     passes or the next soft reset begins. A new key id is accepted at once.
//   - `must_die` = soft reset time + transition window (default 3600 s).
//     Call `slots_rekey_started` when a soft reset begins.
//     Without it the window counts from the install, later by at most the
//     handshake time.
//   - Send: the newest key that is ready (`tx_delay` after install, default
//     none) and not blocked. Use the old key until the new one is ready. A stock
//     peer waits min(hand-window, reneg-sec / 2) (60 s by default) before it
//     sends on a new key. noirvpn may send at once.
//   - Install: old primary becomes lame; old lame becomes grace (dropped at
//     once if `lame_grace` is 0).
//   - SPEC-GAP: the spec drops the lame key when a soft reset begins.
//     A stock peer keeps sending on its old key for up to
//     min(hand-window, reneg-sec / 2) after a rekey, so a second soft reset in
//     that time loses its packets on the dropped key. We keep the lame key
//     through the handshake and, after the new key installs, for `lame_grace`
//     more. Only the key before it goes at the soft reset. With `lame_grace` 0
//     the table follows the spec.
//   - A failed renegotiation needs no call: the old key works until `must_die`.
//     Then the session layer starts a new session, and `slots_clear` drops
//     everything when it authenticates.
//
// The table holds only timing and state. The caller keeps crypto state in an
// array indexed by key id and destroys the entries named in `Key_Id_Set`
// results (`slots_install`, `slots_expire`, `slots_clear`).

DEFAULT_TRAN_WINDOW :: 3600 * time.Second
// How long the key before the lame key still receives. A stock peer sends on an
// old key for at most min(hand-window, reneg-sec / 2) after a rekey (60 s default).
DEFAULT_LAME_GRACE :: 60 * time.Second

Slot_State :: enum u8 {
	Free,
	Primary,
	Lame,
	Grace, // receive only; the key before the lame key
}

Slot :: struct {
	state:       Slot_State,
	established: time.Duration, // when the key state became active; reneg-sec counts from here
	must_die:    time.Duration, // valid when `dying`: the key stops working at this time
	dying:       bool, // lame, or a primary whose replacement is being negotiated
	tx_ready:    time.Duration, // earliest time we may send with it
	tx_blocked:  bool, // the send side cannot go on (packet ids used up)
}

Slots_Config :: struct {
	tran_window: time.Duration, // how long a replaced key keeps receiving
	tx_delay:    time.Duration, // wait before sending on a new key; 0 sends at once
	lame_grace:  time.Duration, // how long the key before the lame key still receives; 0: none
}

Key_Slots :: struct {
	cfg:     Slots_Config,
	slot:    [KEY_ID_COUNT]Slot, // index = key id
	primary: int, // key id, or -1
	lame:    int, // key id, or -1
	grace:   int, // key id, or -1
}

slots_init :: proc "contextless" (s: ^Key_Slots, cfg := Slots_Config{tran_window = DEFAULT_TRAN_WINDOW}) {
	s^ = {}
	s.cfg = cfg
	s.primary = -1
	s.lame = -1
	s.grace = -1
}

// The key id for the next soft reset: 0 for the first key of a session, else
// the one after the primary (7 wraps to 1).
slots_next_key_id :: proc "contextless" (s: ^Key_Slots) -> u8 {
	if s.primary < 0 {
		return 0
	}
	return key_id_next(u8(s.primary))
}

// A soft reset begins (sent or received):
// - The transition window of the current key starts now.
// - Keys of earlier renegotiations drop (steps 1 and 2): the
//   grace key, and the lame key if `lame_grace` is 0 (else it stays until the
//   new key installs; see the SPEC-GAP in the header).
// - The current key keeps working until the new key installs or the window ends.
// Returns the dropped key ids. Does nothing without a primary key or if already
// called for it.
slots_rekey_started :: proc "contextless" (s: ^Key_Slots, now: time.Duration) -> (dropped: Key_Id_Set) {
	if s.primary < 0 || s.slot[s.primary].dying {
		return
	}
	if s.grace >= 0 {
		s.slot[s.grace] = {}
		dropped += {s.grace}
		s.grace = -1
	}
	if s.lame >= 0 && s.cfg.lame_grace <= 0 {
		s.slot[s.lame] = {}
		dropped += {s.lame}
		s.lame = -1
	}
	s.slot[s.primary].dying = true
	s.slot[s.primary].must_die = now + s.cfg.tran_window
	return
}

// A key id finished key exchange and login: it becomes primary. `established`
// is when the key state went active (use `now` if unknown). Returns the dropped
// key ids (the old lame key if no grace time, and any grace key).
slots_install :: proc "contextless" (
	s: ^Key_Slots,
	key_id: u8,
	now: time.Duration,
	established: Maybe(time.Duration) = nil,
) -> (
	dropped: Key_Id_Set,
	err: Error,
) {
	if key_id >= KEY_ID_COUNT {
		return {}, .Bad_Key_Id
	}
	if s.slot[key_id].state != .Free {
		return {}, .Key_Id_In_Use
	}
	if s.grace >= 0 {
		s.slot[s.grace] = {}
		dropped += {s.grace}
		s.grace = -1
	}
	if s.lame >= 0 {
		if s.cfg.lame_grace > 0 {
			sl := &s.slot[s.lame]
			sl.state = .Grace
			sl.dying = true
			sl.must_die = min(sl.must_die, now + s.cfg.lame_grace)
			s.grace = s.lame
		} else {
			s.slot[s.lame] = {}
			dropped += {s.lame}
		}
		s.lame = -1
	}
	tx_ready := now
	if s.primary >= 0 {
		old := &s.slot[s.primary]
		old.state = .Lame
		if !old.dying {
			old.dying = true
			old.must_die = now + s.cfg.tran_window
		}
		s.lame = s.primary
		tx_ready = now + s.cfg.tx_delay
	}
	s.slot[key_id] = {
		state       = .Primary,
		established = established.? or_else now,
		tx_ready    = tx_ready,
	}
	s.primary = int(key_id)
	return dropped, .None
}

// May a packet with this key id be opened now?
slots_rx_ok :: proc "contextless" (s: ^Key_Slots, key_id: u8, now: time.Duration) -> bool {
	if key_id >= KEY_ID_COUNT {
		return false
	}
	sl := &s.slot[key_id]
	if sl.state == .Free {
		return false
	}
	return !sl.dying || now < sl.must_die
}

// Drops a lame or grace key whose time has ended. Call it from a timer
// (`slots_next_expiry` says when) or before a lookup. Returns the dropped ids.
slots_expire :: proc "contextless" (s: ^Key_Slots, now: time.Duration) -> (dropped: Key_Id_Set) {
	if s.grace >= 0 && now >= s.slot[s.grace].must_die {
		s.slot[s.grace] = {}
		dropped += {s.grace}
		s.grace = -1
	}
	if s.lame >= 0 && now >= s.slot[s.lame].must_die {
		s.slot[s.lame] = {}
		dropped += {s.lame}
		s.lame = -1
	}
	// A primary whose renegotiation never finished runs out too.
	if s.primary >= 0 && s.slot[s.primary].dying && now >= s.slot[s.primary].must_die {
		s.slot[s.primary] = {}
		dropped += {s.primary}
		s.primary = -1
	}
	return
}

// When the next key will expire, for timer scheduling.
slots_next_expiry :: proc "contextless" (s: ^Key_Slots) -> (at: time.Duration, ok: bool) {
	if s.lame >= 0 {
		at, ok = s.slot[s.lame].must_die, true
	}
	if s.grace >= 0 {
		if m := s.slot[s.grace].must_die; !ok || m < at {
			at, ok = m, true
		}
	}
	if s.primary >= 0 && s.slot[s.primary].dying {
		if m := s.slot[s.primary].must_die; !ok || m < at {
			at, ok = m, true
		}
	}
	return
}

// The key id to send with now: the first of primary, then lame, that is ready
// and not blocked. If none is ready but the primary is not blocked, use the
// primary (as stock does).
slots_tx_key :: proc "contextless" (s: ^Key_Slots, now: time.Duration) -> (key_id: u8, ok: bool) {
	if s.primary >= 0 {
		sl := &s.slot[s.primary]
		if !sl.tx_blocked && now >= sl.tx_ready && slots_rx_ok(s, u8(s.primary), now) {
			return u8(s.primary), true
		}
	}
	if s.lame >= 0 {
		sl := &s.slot[s.lame]
		if !sl.tx_blocked && slots_rx_ok(s, u8(s.lame), now) {
			return u8(s.lame), true
		}
	}
	if s.primary >= 0 && !s.slot[s.primary].tx_blocked && slots_rx_ok(s, u8(s.primary), now) {
		return u8(s.primary), true
	}
	return 0, false
}

// The send side of this key cannot go on (packet ids used up). Sending moves
// to another key if there is one.
slots_block_tx :: proc "contextless" (s: ^Key_Slots, key_id: u8) {
	if key_id < KEY_ID_COUNT {
		s.slot[key_id].tx_blocked = true
	}
}

// The primary key and the time it became active, for `rekey_check`.
slots_primary :: proc "contextless" (s: ^Key_Slots) -> (key_id: u8, established: time.Duration, ok: bool) {
	if s.primary < 0 {
		return 0, 0, false
	}
	return u8(s.primary), s.slot[s.primary].established, true
}

// Drops one key now (for example its login was revoked). Returns true if the
// key id was in use.
slots_remove :: proc "contextless" (s: ^Key_Slots, key_id: u8) -> bool {
	if key_id >= KEY_ID_COUNT || s.slot[key_id].state == .Free {
		return false
	}
	s.slot[key_id] = {}
	if s.primary == int(key_id) {
		s.primary = -1
	}
	if s.lame == int(key_id) {
		s.lame = -1
	}
	if s.grace == int(key_id) {
		s.grace = -1
	}
	return true
}

// Drops every key (a new session replaced this one, or the peer is closed).
// Returns the key ids that were in use.
slots_clear :: proc "contextless" (s: ^Key_Slots) -> (dropped: Key_Id_Set) {
	for i in 0 ..< KEY_ID_COUNT {
		if s.slot[i].state != .Free {
			dropped += {i}
		}
	}
	// A copy: a parameter that is bigger than a few words is passed by reference, and
	// `slots_init` clears `s` before it reads `cfg`.
	cfg := s.cfg
	slots_init(s, cfg)
	return
}

// The key ids that are in use.
slots_in_use :: proc "contextless" (s: ^Key_Slots) -> (used: Key_Id_Set) {
	for i in 0 ..< KEY_ID_COUNT {
		if s.slot[i].state != .Free {
			used += {i}
		}
	}
	return
}
