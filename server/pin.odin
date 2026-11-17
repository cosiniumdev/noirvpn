// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "base:intrinsics"
import "core:mem"
import "core:sync"
import "noir:proto/config"
import "noir:proto/ossl"

// Pin table: the peers file as a lookup from a key's SHA-256 to its entry.
// - A pin is the SHA-256 of the peer's SubjectPublicKeyInfo
//   (`ossl.Peer_Key.spki_sha256`). Both pin kinds (`sha256:`, `mldsa65-sha256:`)
//   are that digest, which covers the algorithm identifier, so an ML-DSA-65 key
//   and an Ed25519 key never share one. The table is keyed by the digest alone.
//   It cannot check the kind against the key algorithm (`Peer_Key` lacks it;
//   SPEC-GAP, harmless).
// - A table is built once and never changes. Reload builds a new one and swaps a
//   pointer in the `Pin_Store`. The TLS check (`pin_check`) reads that pointer,
//   looks up and returns, with no allocation and no lock: safe in the TLS
//   callback.
// Freeing the old table after a swap:
//   - One thread: the swap runs on the TLS callback thread, so destroy at once.
//   - Several handshake threads: wait until each holds no table pointer.
// Fail-closed: an unknown key, a disabled entry, or no table refuses the
// handshake.

Pin_Table :: struct {
	// The parsed peers file. The table owns it.
	peers:     config.Peers,
	cells:     []u32,
	mask:      u32,
	// Entries that share a digest with an earlier entry of another kind.
	shadowed:  int,
	disabled:  int,
	allocator: mem.Allocator,
}

// Builds the index. Takes ownership of `peers` (`pin_table_destroy` frees it),
// even if `peers` had errors: the parser already left out lines with errors.
// A daemon refuses to reload a file that has errors (see `pin_table_load`).
pin_table_make :: proc(peers: config.Peers, allocator := context.allocator) -> ^Pin_Table {
	t := new(Pin_Table, allocator)
	t.peers = peers
	t.allocator = allocator
	n := len(peers.entries)
	size := 16
	for size < n * 2 {
		size <<= 1
	}
	t.cells = make([]u32, size, allocator)
	t.mask = u32(size - 1)
	for i in 0 ..< n {
		e := &t.peers.entries[i]
		if e.disabled {
			t.disabled += 1
		}
		if _, dup := find_digest(t, &e.pin.digest); dup {
			t.shadowed += 1
			continue
		}
		slot := digest_home(&e.pin.digest) & t.mask
		for t.cells[slot] != 0 {
			slot = (slot + 1) & t.mask
		}
		t.cells[slot] = u32(i + 1)
	}
	return t
}

// Reads and parses a peers file and builds the table. If the file cannot be
// read or any line has an error, it returns a nil table and the error text, so
// the daemon keeps its old table. The text uses `allocator`; the caller frees it
// with `delete`. On success it is empty.
pin_table_load :: proc(
	path: string,
	opts := config.Parse_Options{},
	allocator := context.allocator,
) -> (
	t: ^Pin_Table,
	errors: string,
) {
	peers := config.peers_parse_file(path, opts, allocator)
	if !config.peers_ok(&peers) {
		text := config.format_diagnostics(peers.diags, allocator)
		config.peers_destroy(&peers)
		return nil, text
	}
	return pin_table_make(peers, allocator), ""
}

pin_table_destroy :: proc(t: ^Pin_Table) {
	if t == nil {
		return
	}
	a := t.allocator
	delete(t.cells, a)
	config.peers_destroy(&t.peers)
	free(t, a)
}

pin_table_len :: proc "contextless" (t: ^Pin_Table) -> int {
	return len(t.peers.entries)
}

@(private)
digest_home :: #force_inline proc "contextless" (d: ^[config.PIN_LEN]u8) -> u32 {
	return intrinsics.unaligned_load((^u32)(&d[0]))
}

@(private)
find_digest :: proc "contextless" (t: ^Pin_Table, d: ^[config.PIN_LEN]u8) -> (e: ^config.Peer_Entry, found: bool) {
	slot := digest_home(d) & t.mask
	for {
		c := t.cells[slot]
		if c == 0 {
			return nil, false
		}
		ent := &t.peers.entries[c - 1]
		if ent.pin.digest == d^ {
			return ent, true
		}
		slot = (slot + 1) & t.mask
	}
}

// The entry for a key digest, or nil. A disabled entry is returned too; the
// caller refuses it.
pin_table_find :: proc "contextless" (t: ^Pin_Table, spki_sha256: [config.PIN_LEN]u8) -> ^config.Peer_Entry {
	d := spki_sha256
	e, _ := find_digest(t, &d)
	return e
}

// ---------------------------------------------------------------------------
// The store: what the TLS callback reads

Pin_Store :: struct {
	// The current table. Read and written only with atomic operations.
	table:            ^Pin_Table,
	// Counters, atomic.
	accepted:         u64,
	refused_unknown:  u64,
	refused_disabled: u64,
	// The last refusal, for the `auth.fail` event of the daemon. `refusal_seq`
	// counts refusals. The kind and the key are those of the latest one. Only
	// the thread that runs handshakes reads and writes these.
	refusal_seq:      u64,
	refusal_kind:     Pin_Refusal,
	refusal_spki:     [config.PIN_LEN]u8,
}

Pin_Refusal :: enum u8 {
	None,
	// The key is not in the peers file (or there is no table).
	Unknown,
	Disabled,
}

// Puts a table in. For the first table of a new store.
pin_store_init :: proc(s: ^Pin_Store, t: ^Pin_Table) {
	s^ = {}
	sync.atomic_store_explicit(&s.table, t, .Release)
}

pin_store_current :: #force_inline proc "contextless" (s: ^Pin_Store) -> ^Pin_Table {
	return sync.atomic_load_explicit(&s.table, .Acquire)
}

// Swaps in a new table and returns the old one. The caller destroys the old one
// when it is safe (see the top of this file).
pin_store_swap :: proc "contextless" (s: ^Pin_Store, t: ^Pin_Table) -> (old: ^Pin_Table) {
	return sync.atomic_exchange_explicit(&s.table, t, .Acq_Rel)
}

// The `ossl.Pin_Check` for `Tls_Config.pin_check`; pass the `^Pin_Store` as
// `pin_user`. Accepts a key only if it has an entry that is not disabled.
pin_check :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> bool {
	s := (^Pin_Store)(user)
	if s == nil {
		return false
	}
	t := pin_store_current(s)
	if t == nil {
		sync.atomic_add_explicit(&s.refused_unknown, 1, .Relaxed)
		note_refusal(s, .Unknown, peer.spki_sha256)
		return false
	}
	e := pin_table_find(t, peer.spki_sha256)
	switch {
	case e == nil:
		sync.atomic_add_explicit(&s.refused_unknown, 1, .Relaxed)
		note_refusal(s, .Unknown, peer.spki_sha256)
		return false
	case e.disabled || e.client.disable:
		sync.atomic_add_explicit(&s.refused_disabled, 1, .Relaxed)
		note_refusal(s, .Disabled, peer.spki_sha256)
		return false
	}
	sync.atomic_add_explicit(&s.accepted, 1, .Relaxed)
	return true
}

// The `ossl.Pin_Lookup` of `peer-keys-mode either`: a key that is not in the
// table is left to the chain check, so it counts as no refusal here.
pin_lookup :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> ossl.Pin_Verdict {
	s := (^Pin_Store)(user)
	if s == nil {
		return .Unknown
	}
	t := pin_store_current(s)
	if t == nil {
		return .Unknown
	}
	e := pin_table_find(t, peer.spki_sha256)
	switch {
	case e == nil:
		return .Unknown
	case e.disabled || e.client.disable:
		sync.atomic_add_explicit(&s.refused_disabled, 1, .Relaxed)
		note_refusal(s, .Disabled, peer.spki_sha256)
		return .Refused
	}
	sync.atomic_add_explicit(&s.accepted, 1, .Relaxed)
	return .Accepted
}

@(private)
note_refusal :: proc "contextless" (s: ^Pin_Store, kind: Pin_Refusal, spki: [config.PIN_LEN]u8) {
	s.refusal_seq += 1
	s.refusal_kind = kind
	s.refusal_spki = spki
}

// ---------------------------------------------------------------------------
// Reload: who must be disconnected, and what changed

// A live session, as the daemon knows it.
Live_Key :: struct {
	handle:   Peer_Handle,
	// The identity the session was admitted under.
	identity: string,
	// Its key.
	spki:     [config.PIN_LEN]u8,
	// Either mode: the chain let it in; the key was not pinned.
	by_chain: bool,
}

Kick_Reason :: enum u8 {
	// The key is no longer in the file.
	Key_Removed,
	// The key is still there but `disabled`.
	Key_Disabled,
	// The key now belongs to another username.
	Identity_Changed,
}

Reload_Kick :: struct {
	handle: Peer_Handle,
	reason: Kick_Reason,
}

// Which live sessions the new table no longer allows. Call it with the new
// table before or after the swap; it only reads. Free the result with `delete`.
pin_kicks :: proc(
	new_table: ^Pin_Table,
	live: []Live_Key,
	allocator := context.allocator,
) -> (
	kicks: [dynamic]Reload_Kick,
) {
	kicks = make([dynamic]Reload_Kick, allocator)
	for l in live {
		e := pin_table_find(new_table, l.spki)
		switch {
		case e == nil && l.by_chain:
		case e == nil:
			append(&kicks, Reload_Kick{l.handle, .Key_Removed})
		case e.disabled || e.client.disable:
			append(&kicks, Reload_Kick{l.handle, .Key_Disabled})
		case !name_equal(e.user, l.identity):
			append(&kicks, Reload_Kick{l.handle, .Identity_Changed})
		}
	}
	return
}

Pin_Change_Kind :: enum u8 {
	Added,
	Removed,
	Disabled,
	Enabled,
	// Same key, another username.
	User_Changed,
	// Same key and user, other options (address, iroutes).
	Options_Changed,
}

// One line of the reload report, for the log and the bus.
Pin_Change :: struct {
	kind:     Pin_Change_Kind,
	// Username in the new file (the old file for `.Removed`).
	user:     string,
	// Username in the old file, for `.User_Changed`.
	old_user: string,
	digest:   [config.PIN_LEN]u8,
}

// What differs between two tables: first the entries of the new file in its
// order, then the removed keys in the order of the old file. The strings point
// into the two tables.
pin_diff :: proc(old, new_table: ^Pin_Table, allocator := context.allocator) -> (changes: [dynamic]Pin_Change) {
	changes = make([dynamic]Pin_Change, allocator)
	for &n in new_table.peers.entries {
		o := pin_table_find(old, n.pin.digest)
		switch {
		case o == nil:
			append(&changes, Pin_Change{.Added, n.user, "", n.pin.digest})
		case !name_equal(o.user, n.user):
			append(&changes, Pin_Change{.User_Changed, n.user, o.user, n.pin.digest})
		case !o.disabled && n.disabled:
			append(&changes, Pin_Change{.Disabled, n.user, "", n.pin.digest})
		case o.disabled && !n.disabled:
			append(&changes, Pin_Change{.Enabled, n.user, "", n.pin.digest})
		case !client_specific_equal(&o.client, &n.client):
			append(&changes, Pin_Change{.Options_Changed, n.user, "", n.pin.digest})
		}
	}
	for &o in old.peers.entries {
		if pin_table_find(new_table, o.pin.digest) == nil {
			append(&changes, Pin_Change{.Removed, o.user, "", o.pin.digest})
		}
	}
	return
}

@(private)
client_specific_equal :: proc(a, b: ^config.Client_Specific) -> bool {
	if a.ifconfig_push != b.ifconfig_push || a.ifconfig_ipv6_push != b.ifconfig_ipv6_push {
		return false
	}
	if len(a.iroutes) != len(b.iroutes) || len(a.iroutes6) != len(b.iroutes6) {
		return false
	}
	for i in 0 ..< len(a.iroutes) {
		if a.iroutes[i] != b.iroutes[i] {
			return false
		}
	}
	for i in 0 ..< len(a.iroutes6) {
		if a.iroutes6[i] != b.iroutes6[i] {
			return false
		}
	}
	return a.disable == b.disable
}
