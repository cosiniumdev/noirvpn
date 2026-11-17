// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "noir:proto/config"
import "noir:proto/ossl"

peers_text :: proc(lines: ..string) -> string {
	return strings.join(lines, "\n", context.temp_allocator)
}

@(test)
test_pin_table_lookup :: proc(t: ^testing.T) {
	text := peers_text(
		strings.concatenate({"alice ", pin_text(1), " ifconfig-push=10.8.0.10"}, context.temp_allocator),
		strings.concatenate({"alice ", pin_text(2), " # second device"}, context.temp_allocator),
		strings.concatenate({"bob ", pin_text(3, "mldsa65-sha256"), " iroute=192.168.10.0/24"}, context.temp_allocator),
		strings.concatenate({"carol ", pin_text(4), " disabled"}, context.temp_allocator),
	)
	tab := make_pins(t, text)
	defer pin_table_destroy(tab)
	testing.expect_value(t, pin_table_len(tab), 4)
	testing.expect_value(t, tab.disabled, 1)

	e := pin_table_find(tab, digest_of(1))
	testing.expect(t, e != nil && e.user == "alice" && !e.disabled)
	if e != nil {
		ip, ok := e.client.ifconfig_push.?
		testing.expect(t, ok && ip.local_ip == [4]u8{10, 8, 0, 10})
	}
	e = pin_table_find(tab, digest_of(2))
	testing.expect(t, e != nil && e.user == "alice")
	// The mldsa65 pin is matched by the same digest.
	e = pin_table_find(tab, digest_of(3))
	testing.expect(t, e != nil && e.user == "bob" && e.pin.kind == .Mldsa65_Sha256)
	e = pin_table_find(tab, digest_of(4))
	testing.expect(t, e != nil && e.disabled)
	// Not in the file.
	testing.expect(t, pin_table_find(tab, digest_of(5)) == nil)
	testing.expect(t, pin_table_find(tab, [32]u8{}) == nil)
}

@(test)
test_pin_table_many :: proc(t: ^testing.T) {
	sb := strings.builder_make(context.temp_allocator)
	for i in 0 ..< 5000 {
		strings.write_string(&sb, "user")
		strings.write_int(&sb, i)
		strings.write_byte(&sb, ' ')
		strings.write_string(&sb, pin_text(u64(i)))
		strings.write_byte(&sb, '\n')
	}
	tab := make_pins(t, strings.to_string(sb))
	defer pin_table_destroy(tab)
	testing.expect_value(t, pin_table_len(tab), 5000)
	for i in 0 ..< 5000 {
		e := pin_table_find(tab, digest_of(u64(i)))
		if e == nil {
			testing.expectf(t, false, "pin %d not found", i)
			return
		}
	}
	for i in 5000 ..< 5200 {
		testing.expect(t, pin_table_find(tab, digest_of(u64(i))) == nil)
	}
}

@(test)
test_pin_table_empty :: proc(t: ^testing.T) {
	tab := make_pins(t, "# nothing here\n")
	defer pin_table_destroy(tab)
	testing.expect_value(t, pin_table_len(tab), 0)
	testing.expect(t, pin_table_find(tab, digest_of(1)) == nil)
}

@(test)
test_pin_check_fail_closed :: proc(t: ^testing.T) {
	text := peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator),
		strings.concatenate({"carol ", pin_text(4), " disabled"}, context.temp_allocator),
	)
	tab := make_pins(t, text)
	store: Pin_Store
	pin_store_init(&store, tab)
	defer pin_table_destroy(pin_store_current(&store))

	// It has the type the TLS layer wants.
	check: ossl.Pin_Check = pin_check
	testing.expect(t, check(peer_key(1), &store))
	testing.expect(t, !check(peer_key(4), &store)) // disabled
	testing.expect(t, !check(peer_key(9), &store)) // unknown
	testing.expect_value(t, store.accepted, u64(1))
	testing.expect_value(t, store.refused_disabled, u64(1))
	testing.expect_value(t, store.refused_unknown, u64(1))
	// The last refusal is remembered for the bus event.
	testing.expect_value(t, store.refusal_seq, u64(2))
	testing.expect_value(t, store.refusal_kind, Pin_Refusal.Unknown)
	testing.expect_value(t, store.refusal_spki, digest_of(9))
	testing.expect(t, !check(peer_key(4), &store))
	testing.expect_value(t, store.refusal_seq, u64(3))
	testing.expect_value(t, store.refusal_kind, Pin_Refusal.Disabled)
	// The certificate hash does not matter, only the key's.
	k := peer_key(1)
	k.cert_sha256 = digest_of(777)
	testing.expect(t, check(k, &store))
	// No store, or a store without a table, refuses everything.
	testing.expect(t, !check(peer_key(1), nil))
	empty: Pin_Store
	testing.expect(t, !check(peer_key(1), &empty))
}

@(test)
test_pin_check_ccd_style_disable_in_entry :: proc(t: ^testing.T) {
	// `disabled` sets both flags; either one refuses.
	tab := make_pins(t, strings.concatenate({"x ", pin_text(1), " disabled"}, context.temp_allocator))
	e := pin_table_find(tab, digest_of(1))
	testing.expect(t, e != nil && e.disabled && e.client.disable)
	store: Pin_Store
	pin_store_init(&store, tab)
	defer pin_table_destroy(pin_store_current(&store))
	testing.expect(t, !pin_check(peer_key(1), &store))
	e.disabled = false // only the other flag left
	testing.expect(t, !pin_check(peer_key(1), &store))
}

@(test)
test_pin_load_errors_keep_old_table :: proc(t: ^testing.T) {
	files := make(Mem_Files, context.temp_allocator)
	files["/etc/peers"] = strings.concatenate(
		{"alice ", pin_text(1), "\nbad line with no pin\nbob sha256:short\n"},
		context.temp_allocator,
	)
	files["/etc/good"] = strings.concatenate({"alice ", pin_text(1), "\n"}, context.temp_allocator)
	tab, errs := pin_table_load("/etc/peers", config.Parse_Options{loader = mem_loader, loader_data = &files})
	testing.expect(t, tab == nil)
	testing.expect(t, strings.contains(errs, "peers"))
	delete(errs)
	tab, errs = pin_table_load("/etc/missing", config.Parse_Options{loader = mem_loader, loader_data = &files})
	testing.expect(t, tab == nil)
	testing.expect(t, strings.contains(errs, "cannot read"))
	delete(errs)
	tab, errs = pin_table_load("/etc/good", config.Parse_Options{loader = mem_loader, loader_data = &files})
	testing.expect(t, tab != nil)
	testing.expect_value(t, errs, "")
	testing.expect(t, pin_table_find(tab, digest_of(1)) != nil)
	pin_table_destroy(tab)
}

@(test)
test_pin_shadowed_digest :: proc(t: ^testing.T) {
	// The same digest under both kinds: the first line wins, the second is
	// counted, and the table does not loop.
	text := peers_text(
		strings.concatenate({"alice ", pin_text(1), ""}, context.temp_allocator),
		strings.concatenate({"mallory ", pin_text(1, "mldsa65-sha256")}, context.temp_allocator),
	)
	tab := make_pins(t, text)
	defer pin_table_destroy(tab)
	testing.expect_value(t, tab.shadowed, 1)
	e := pin_table_find(tab, digest_of(1))
	testing.expect(t, e != nil && e.user == "alice")
}

@(test)
test_pin_reload_kicks :: proc(t: ^testing.T) {
	old_text := peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator),
		strings.concatenate({"bob ", pin_text(2)}, context.temp_allocator),
		strings.concatenate({"carol ", pin_text(3)}, context.temp_allocator),
		strings.concatenate({"dave ", pin_text(4)}, context.temp_allocator),
		strings.concatenate({"erin ", pin_text(5), " ifconfig-push=10.8.0.5"}, context.temp_allocator),
	)
	new_text := peers_text(
		strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator), // unchanged
		// bob's key is gone
		strings.concatenate({"carol ", pin_text(3), " disabled"}, context.temp_allocator), // disabled
		strings.concatenate({"davina ", pin_text(4)}, context.temp_allocator), // renamed
		strings.concatenate({"erin ", pin_text(5), " ifconfig-push=10.8.0.99"}, context.temp_allocator), // option change
		strings.concatenate({"frank ", pin_text(6)}, context.temp_allocator), // new
	)
	old_t := make_pins(t, old_text)
	new_t := make_pins(t, new_text)
	defer pin_table_destroy(old_t)
	defer pin_table_destroy(new_t)

	live := []Live_Key {
		{Peer_Handle{0, 1}, "alice", digest_of(1), false},
		{Peer_Handle{1, 1}, "bob", digest_of(2), false},
		{Peer_Handle{2, 1}, "carol", digest_of(3), false},
		{Peer_Handle{3, 1}, "dave", digest_of(4), false},
		{Peer_Handle{4, 1}, "erin", digest_of(5), false},
		// A second device of alice is not affected either.
		{Peer_Handle{5, 1}, "alice", digest_of(1), false},
	}
	kicks := pin_kicks(new_t, live)
	defer delete(kicks)
	testing.expect_value(t, len(kicks), 3)
	find :: proc(kicks: [dynamic]Reload_Kick, idx: u32) -> (Kick_Reason, bool) {
		for k in kicks {
			if k.handle.index == idx {
				return k.reason, true
			}
		}
		return {}, false
	}
	r, ok := find(kicks, 1)
	testing.expect(t, ok && r == .Key_Removed)
	r, ok = find(kicks, 2)
	testing.expect(t, ok && r == .Key_Disabled)
	r, ok = find(kicks, 3)
	testing.expect(t, ok && r == .Identity_Changed)
	_, ok = find(kicks, 0)
	testing.expect(t, !ok)
	_, ok = find(kicks, 4) // only its options changed: stays connected
	testing.expect(t, !ok)

	changes := pin_diff(old_t, new_t)
	defer delete(changes)
	count := [Pin_Change_Kind]int{}
	for c in changes {
		count[c.kind] += 1
	}
	testing.expect_value(t, count[.Added], 1)
	testing.expect_value(t, count[.Removed], 1)
	testing.expect_value(t, count[.Disabled], 1)
	testing.expect_value(t, count[.User_Changed], 1)
	testing.expect_value(t, count[.Options_Changed], 1)
	testing.expect_value(t, count[.Enabled], 0)
	for c in changes {
		if c.kind == .User_Changed {
			testing.expect_value(t, c.user, "davina")
			testing.expect_value(t, c.old_user, "dave")
		}
		if c.kind == .Removed {
			testing.expect_value(t, c.user, "bob")
		}
	}
	// The other direction.
	back := pin_diff(new_t, old_t)
	defer delete(back)
	n_enabled := 0
	for c in back {
		if c.kind == .Enabled {
			n_enabled += 1
		}
	}
	testing.expect_value(t, n_enabled, 1)
}

@(test)
test_pin_store_swap :: proc(t: ^testing.T) {
	a := make_pins(t, strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator))
	b := make_pins(t, strings.concatenate({"bob ", pin_text(2)}, context.temp_allocator))
	store: Pin_Store
	pin_store_init(&store, a)
	testing.expect(t, pin_check(peer_key(1), &store))
	testing.expect(t, !pin_check(peer_key(2), &store))
	old := pin_store_swap(&store, b)
	testing.expect(t, old == a)
	testing.expect(t, !pin_check(peer_key(1), &store))
	testing.expect(t, pin_check(peer_key(2), &store))
	pin_table_destroy(old)
	pin_table_destroy(pin_store_current(&store))
}

Swap_Ctx :: struct {
	store: ^Pin_Store,
	stop:  bool,
	bad:   int,
	calls: int,
}

swap_reader :: proc(th: ^thread.Thread) {
	c := (^Swap_Ctx)(th.data)
	for !sync.atomic_load_explicit(&c.stop, .Acquire) {
		// Key 1 is in both tables: it must always be accepted. Key 99 is in
		// neither: always refused.
		if !pin_check(peer_key(1), c.store) {
			c.bad += 1
		}
		if pin_check(peer_key(99), c.store) {
			c.bad += 1
		}
		sync.atomic_add_explicit(&c.calls, 1, .Relaxed)
	}
}

// Another thread calls the check all the time while tables are swapped.
@(test)
test_pin_check_during_swaps :: proc(t: ^testing.T) {
	line1 := strings.concatenate({"alice ", pin_text(1), "\n"}, context.temp_allocator)
	line2 := strings.concatenate({"bob ", pin_text(2), "\n"}, context.temp_allocator)
	tables: [2]^Pin_Table
	tables[0] = make_pins(t, line1)
	tables[1] = make_pins(t, strings.concatenate({line1, line2}, context.temp_allocator))
	store: Pin_Store
	pin_store_init(&store, tables[0])
	ctx := Swap_Ctx {
		store = &store,
	}
	th := thread.create(swap_reader)
	th.data = &ctx
	thread.start(th)
	// Swap while the reader runs: wait for it to start, and go on until it has
	// performed many calls during the swaps (or 5 s have passed).
	deadline := time.tick_now()
	for sync.atomic_load_explicit(&ctx.calls, .Relaxed) == 0 && time.duration_seconds(time.tick_since(deadline)) < 5 {
		thread.yield()
	}
	start_calls := sync.atomic_load_explicit(&ctx.calls, .Relaxed)
	swaps := 0
	for {
		pin_store_swap(&store, tables[(swaps + 1) % 2])
		swaps += 1
		done := swaps >= 20000 && sync.atomic_load_explicit(&ctx.calls, .Relaxed) - start_calls >= 2000
		if done || time.duration_seconds(time.tick_since(deadline)) > 5 {
			break
		}
	}
	sync.atomic_store_explicit(&ctx.stop, true, .Release)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, ctx.bad, 0)
	testing.expect(t, ctx.calls > 0)
	// Both tables are still ours to free: we never freed one under the reader.
	pin_table_destroy(tables[0])
	pin_table_destroy(tables[1])
}

// A session that the chain let in (either mode) ends only when the new file
// lists its key as disabled or under another name.
@(test)
test_pin_kicks_by_chain :: proc(t: ^testing.T) {
	new_t := make_pins(
		t,
		peers_text(
			strings.concatenate({"bob ", pin_text(2), " disabled"}, context.temp_allocator),
			strings.concatenate({"carol ", pin_text(3)}, context.temp_allocator),
			strings.concatenate({"dave ", pin_text(4)}, context.temp_allocator),
		),
	)
	defer pin_table_destroy(new_t)
	live := []Live_Key {
		{Peer_Handle{0, 1}, "alice", digest_of(1), true}, // not in the file: stays
		{Peer_Handle{1, 1}, "bob", digest_of(2), true}, // disabled: ends
		{Peer_Handle{2, 1}, "erin", digest_of(3), true}, // pinned to carol: ends
		{Peer_Handle{3, 1}, "dave", digest_of(4), true}, // pinned to dave: stays
	}
	kicks := pin_kicks(new_t, live)
	defer delete(kicks)
	if !testing.expect_value(t, len(kicks), 2) {
		return
	}
	testing.expect_value(t, kicks[0], Reload_Kick{Peer_Handle{1, 1}, .Key_Disabled})
	testing.expect_value(t, kicks[1], Reload_Kick{Peer_Handle{2, 1}, .Identity_Changed})
}

@(test)
test_pin_user_case_change_is_no_change :: proc(t: ^testing.T) {
	old_t := make_pins(t, strings.concatenate({"alice ", pin_text(1)}, context.temp_allocator))
	new_t := make_pins(t, strings.concatenate({"Alice ", pin_text(1)}, context.temp_allocator))
	defer pin_table_destroy(old_t)
	defer pin_table_destroy(new_t)
	live := []Live_Key{{Peer_Handle{0, 1}, "alice", digest_of(1), false}}
	kicks := pin_kicks(new_t, live)
	defer delete(kicks)
	testing.expect_value(t, len(kicks), 0)
	changes := pin_diff(old_t, new_t)
	defer delete(changes)
	testing.expect_value(t, len(changes), 0)
	// Another user is a change.
	other := make_pins(t, strings.concatenate({"alicia ", pin_text(1)}, context.temp_allocator))
	defer pin_table_destroy(other)
	kicks2 := pin_kicks(other, live)
	defer delete(kicks2)
	testing.expect_value(t, len(kicks2), 1)
}
