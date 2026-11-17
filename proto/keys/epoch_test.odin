// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package keys

import "core:encoding/json"
import "core:testing"
import "noir:proto/ossl"

// E1 of the table below: bytes 00 01 02 ... 1f.
@(private = "file")
e1_pattern :: proc() -> (e: [32]u8) {
	for i in 0 ..< 32 {
		e[i] = u8(i)
	}
	return
}

// Epoch keys for E1 = 00..1f, generated with Python hmac + hashlib,
// an independent implementation of the spec's formulas.
@(private = "file")
Chain_Vector :: struct {
	epoch: u16,
	e:     string,
	k16:   string,
	k32:   string,
	iv:    string,
}

@(private = "file")
CHAIN := [?]Chain_Vector {
	{
		1,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"c0b015350de890ee8e1849d2c29a1b94",
		"ebbbf838a8658beb56f2324d691351bd4c8c230fb271ada8f67de830b7ee3192",
		"568de14f8f744bfb0b721f66",
	},
	{
		2,
		"e35bffa31e2723bf09e8d394fa9171ca4e534553bffa1d3482de4c9b3bc639d7",
		"2586116e6e44094e7e8659d311948333",
		"4010426e3e169cd80289883d7f38d7eee445ead5fa21812fabebe155a4408ee5",
		"9caaa619cb6277bbb0e90c48",
	},
	{
		3,
		"f42019f62ea8cd6a2dc9e3e0778903253a1320d2c87f27e15e0494b796665101",
		"4254f2a6c4ab003f3857ab2e4c25bf53",
		"97262f79e388a314377b63881143f2490755d3396aa5c4fe98ab8384318cc859",
		"cd8fc5d76f8d9e1d521e6401",
	},
	{
		4,
		"3593b3d8bd83ed6063b4226f77854a737132b4a4f95dfd892d8cb88a5e89b8a7",
		"075f9f777c86b1a20a8b736cdd703e8c",
		"4143f33e41979afca15daa9e88dec238e26867817e32d8a83a949c0dc4f5a09e",
		"e2c0b50224e8f4775e9ba94c",
	},
	{
		5,
		"a9bc65b1ec21f6a04a8b23d0dcfa5998d7a3286e80bcfcc5ea3a443182098f77",
		"1928a46d966efe66d139940ab72274ca",
		"462d81a688f0d4065816d16c5c0e26f5ab0c5cfb1e9ee13e66f21d21e721bbf7",
		"380d48fd40f4436496f72f13",
	},
}

// The info blocks of the spec.
@(test)
expand_label_info_blocks :: proc(t: ^testing.T) {
	buf: [64]u8
	n := expand_label_info(buf[:], "data_key", nil, 16)
	expect_bytes(t, buf[:n], unhex("00100d6f76706e20646174615f6b657900"), "data_key 16")
	n = expand_label_info(buf[:], "data_key", nil, 32)
	expect_bytes(t, buf[:n], unhex("00200d6f76706e20646174615f6b657900"), "data_key 32")
	n = expand_label_info(buf[:], "data_iv", nil, 12)
	expect_bytes(t, buf[:n], unhex("000c0c6f76706e20646174615f697600"), "data_iv 12")
	n = expand_label_info(buf[:], "datakey upd", nil, 32)
	expect_bytes(t, buf[:n], unhex("0020106f76706e20646174616b65792075706400"), "datakey upd 32")
	// A context is appended after its length byte.
	n = expand_label_info(buf[:], "x", []u8{1, 2, 3}, 4)
	expect_bytes(t, buf[:n], unhex("00040 66f76706e2078 03010203"), "context")
}

@(test)
expand_label_rejects_bad_input :: proc(t: ^testing.T) {
	e := e1_pattern()
	out: [32]u8
	testing.expect(t, expand_label(e[:], "data_key", nil, out[:]), "good call")
	testing.expect(t, !expand_label(e[:31], "data_key", nil, out[:]), "31-byte secret")
	testing.expect(t, !expand_label(e[:], "", nil, out[:]), "empty label")
	long: [251]u8
	for &b in long {
		b = 'a'
	}
	testing.expect(t, !expand_label(e[:], string(long[:]), nil, out[:]), "251-byte label")
	testing.expect(t, expand_label(e[:], string(long[:250]), nil, out[:]), "250-byte label")
	testing.expect(t, !expand_label(e[:], "data_key", nil, nil), "no output")
	ctx: [256]u8
	testing.expect(t, !expand_label(e[:], "data_key", ctx[:], out[:]), "256-byte context")
	testing.expect(t, expand_label(e[:], "data_key", ctx[:255], out[:]), "255-byte context")
}

@(test)
epoch_chain_vectors :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	k32, k16: Epoch_Key
	testing.expect_value(t, epoch_send_init(&k32, e1[:], 32), Error.None)
	testing.expect_value(t, epoch_send_init(&k16, e1[:], 16), Error.None)
	for v in CHAIN {
		testing.expect_value(t, k32.epoch, v.epoch)
		expect_bytes(t, k32.e[:], unhex(v.e), "E")
		expect_bytes(t, k32.key[:], unhex(v.k32), "K 32")
		expect_bytes(t, k32.iv[:], unhex(v.iv), "IV")
		testing.expect_value(t, k16.epoch, v.epoch)
		expect_bytes(t, k16.key[:16], unhex(v.k16), "K 16")
		testing.expect_value(t, k16.key[16], 0)
		expect_bytes(t, k16.iv[:], unhex(v.iv), "IV (16-byte cipher)")
		if v.epoch < 5 {
			testing.expect_value(t, epoch_send_advance(&k32, v.epoch + 1), Error.None)
			testing.expect_value(t, epoch_send_advance(&k16, v.epoch + 1), Error.None)
		}
	}
	// Advancing by several epochs at once gives the same keys as one by one.
	jump: Epoch_Key
	testing.expect_value(t, epoch_send_init(&jump, e1[:], 32), Error.None)
	testing.expect_value(t, epoch_send_advance(&jump, 5), Error.None)
	expect_bytes(t, jump.key[:], unhex(CHAIN[4].k32), "K(5) by one jump")
	expect_bytes(t, jump.iv[:], unhex(CHAIN[4].iv), "IV(5) by one jump")
	// Never backwards, never the same epoch.
	testing.expect_value(t, epoch_send_advance(&jump, 5), Error.Bad_Epoch)
	testing.expect_value(t, epoch_send_advance(&jump, 3), Error.Bad_Epoch)
}

// The captured E1 of the 2.7.7 peers gives the same K(1) and IV(1) as the
// verifier found. The first packets in the capture open with them (see the
// crypt package tests).
@(test)
epoch_one_from_captures :: proc(t: ^testing.T) {
	root := load_json(t, DATA_CHANNEL_JSON)
	seen := 0
	for c in json_cases(t, root) {
		cs := c.(json.Object)
		derived := jobj(cs, "derived")
		for dir in ([?]string{"c2s", "s2c"}) {
			d := jobj(derived, dir)
			if "epoch_1_base_key_e1" not_in d {
				continue
			}
			cipher, _ := cipher_from_name(jstr(cs, "cipher"))
			k: Epoch_Key
			testing.expect_value(t, epoch_send_init(&k, jhex(d, "epoch_1_base_key_e1"), ossl.aead_key_len(cipher)), Error.None)
			expect_bytes(t, k.key[:k.key_len], jhex(d, "epoch_1_key"), jstr(cs, "cell"))
			expect_bytes(t, k.iv[:], jhex(d, "epoch_1_iv"), jstr(cs, "cell"))
			seen += 1
		}
	}
	testing.expect_value(t, seen, 6) // 3 epoch cells, 2 directions
}

@(test)
epoch_key_bad_arguments :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	k: Epoch_Key
	testing.expect_value(t, epoch_key_set(&k, 0, e1[:], 32), Error.Bad_Argument)
	testing.expect_value(t, epoch_key_set(&k, 1, e1[:31], 32), Error.Bad_Argument)
	testing.expect_value(t, epoch_key_set(&k, 1, e1[:], 24), Error.Bad_Argument)
	// The chain stops at 65535.
	testing.expect_value(t, epoch_key_set(&k, EPOCH_MAX, e1[:], 32), Error.None)
	to: Epoch_Key
	testing.expect_value(t, epoch_key_step(&k, &to), Error.Epoch_Exhausted)
	epoch_key_wipe(&k)
	zero: Epoch_Key
	testing.expect(t, k == zero, "wipe")
}

// Epochs held by the receiver, sorted, for easy comparison.
@(private = "file")
held :: proc(r: ^Epoch_Recv) -> (epochs: [EPOCH_SLOTS]u16) {
	for i in 0 ..< EPOCH_SLOTS {
		epochs[i] = r.slots[i].epoch
	}
	// Small insertion sort.
	for i in 1 ..< EPOCH_SLOTS {
		for j := i; j > 0 && epochs[j - 1] > epochs[j]; j -= 1 {
			epochs[j - 1], epochs[j] = epochs[j], epochs[j - 1]
		}
	}
	return
}

@(test)
epoch_recv_start :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	r: Epoch_Recv
	change, err := epoch_recv_init(&r, e1[:], 32)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, change.filled, bit_set[0 ..< EPOCH_SLOTS; u8]{0, 1, 2, 3, 4})
	testing.expect_value(t, change.freed, bit_set[0 ..< EPOCH_SLOTS; u8]{})
	testing.expect_value(t, held(&r), [EPOCH_SLOTS]u16{0, 1, 2, 3, 4, 5})

	// Every held key is the chain key of its epoch.
	for v in CHAIN {
		slot, class := epoch_recv_lookup(&r, v.epoch)
		testing.expect_value(t, class, v.epoch == 1 ? Epoch_Class.Current : Epoch_Class.Future)
		if class != .Drop {
			expect_bytes(t, r.slots[slot].key[:], unhex(v.k32), "K")
			expect_bytes(t, r.slots[slot].iv[:], unhex(v.iv), "IV")
		}
	}
	// Epoch 0, 6 (one too far) and a far one are dropped.
	for e in ([?]u16{0, 6, 100, 65535}) {
		_, class := epoch_recv_lookup(&r, e)
		testing.expectf(t, class == .Drop, "epoch %d: %v", e, class)
	}
	// No retiring key yet.
	testing.expect_value(t, r.retiring, -1)
	epoch_recv_wipe(&r)
	zero: Epoch_Recv
	zero.retiring = -1
	testing.expect(t, r == zero, "wipe")
}

@(test)
epoch_recv_promote_next :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	r: Epoch_Recv
	_, _ = epoch_recv_init(&r, e1[:], 32)
	// A packet of epoch 2 authenticated.
	change, err := epoch_recv_promote(&r, 2)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, held(&r), [EPOCH_SLOTS]u16{1, 2, 3, 4, 5, 6})
	testing.expect_value(t, r.slots[r.current].epoch, 2)
	testing.expect_value(t, r.slots[r.retiring].epoch, 1)
	// One new key was created (epoch 6) and no slot was freed except the one it reuses.
	testing.expect_value(t, card(change.filled), 1)
	testing.expect_value(t, card(change.freed), 0)
	_, cls := epoch_recv_lookup(&r, 1)
	testing.expect_value(t, cls, Epoch_Class.Retiring)
	_, cls = epoch_recv_lookup(&r, 2)
	testing.expect_value(t, cls, Epoch_Class.Current)
	_, cls = epoch_recv_lookup(&r, 6)
	testing.expect_value(t, cls, Epoch_Class.Future)
	_, cls = epoch_recv_lookup(&r, 7)
	testing.expect_value(t, cls, Epoch_Class.Drop)

	// Next promotion drops epoch 1 (retiring) and keeps 2 as retiring.
	change, err = epoch_recv_promote(&r, 3)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, held(&r), [EPOCH_SLOTS]u16{2, 3, 4, 5, 6, 7})
	testing.expect_value(t, card(change.freed), 1)
	testing.expect_value(t, card(change.filled), 1)
	_, cls = epoch_recv_lookup(&r, 1)
	testing.expect_value(t, cls, Epoch_Class.Drop)
	slot, _ := epoch_recv_lookup(&r, 7)
	expect_bytes(t, r.slots[slot].key[:], keys_of_chain(7), "K(7)")

	// Only a future epoch can be promoted.
	_, err = epoch_recv_promote(&r, 3)
	testing.expect_value(t, err, Error.Bad_Epoch)
	_, err = epoch_recv_promote(&r, 2)
	testing.expect_value(t, err, Error.Bad_Epoch)
	_, err = epoch_recv_promote(&r, 8)
	testing.expect_value(t, err, Error.Bad_Epoch)
	_, err = epoch_recv_promote(&r, 0)
	testing.expect_value(t, err, Error.Bad_Epoch)
}

@(private = "file")
card :: proc(s: bit_set[0 ..< EPOCH_SLOTS; u8]) -> (n: int) {
	for i in 0 ..< EPOCH_SLOTS {
		if i in s {
			n += 1
		}
	}
	return
}

// K(epoch) for the E1 = 00..1f chain, 32-byte key, by plain stepping.
@(private = "file")
keys_of_chain :: proc(epoch: u16) -> []u8 {
	e1 := e1_pattern()
	k: Epoch_Key
	_ = epoch_send_init(&k, e1[:], 32)
	if epoch > 1 {
		_ = epoch_send_advance(&k, epoch)
	}
	out := make([]u8, 32, context.temp_allocator)
	copy(out, k.key[:])
	return out
}

@(test)
epoch_recv_promote_skips :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	r: Epoch_Recv
	_, _ = epoch_recv_init(&r, e1[:], 32)
	// The peer jumped to epoch 4 (its epochs 2 and 3 never arrived).
	change, err := epoch_recv_promote(&r, 4)
	testing.expect_value(t, err, Error.None)
	// Current 4, retiring 1 (the old current), futures 5 to 8. 2 and 3 are gone.
	testing.expect_value(t, held(&r), [EPOCH_SLOTS]u16{1, 4, 5, 6, 7, 8})
	testing.expect_value(t, card(change.freed), 2)
	testing.expect_value(t, card(change.filled), 3)
	for e in ([?]u16{2, 3}) {
		_, cls := epoch_recv_lookup(&r, e)
		testing.expectf(t, cls == .Drop, "epoch %d: %v", e, cls)
	}
	for e in 4 ..= 8 {
		slot, cls := epoch_recv_lookup(&r, u16(e))
		testing.expectf(t, cls != .Drop, "epoch %d: %v", e, cls)
		expect_bytes(t, r.slots[slot].key[:], keys_of_chain(u16(e)), "K")
	}
	// Retiring is the old current, epoch 1.
	slot, cls := epoch_recv_lookup(&r, 1)
	testing.expect_value(t, cls, Epoch_Class.Retiring)
	expect_bytes(t, r.slots[slot].key[:], keys_of_chain(1), "K(1)")
	// The chain keys of used epochs are wiped; only the newest keeps its E.
	for i in 0 ..< EPOCH_SLOTS {
		sl := &r.slots[i]
		zero_e: [EPOCH_KEY_LEN]u8
		if sl.epoch == 8 {
			testing.expect(t, sl.e != zero_e, "newest key lost its chain key")
		} else {
			testing.expectf(t, sl.e == zero_e, "epoch %d kept its chain key", sl.epoch)
		}
	}

	// Jump the full window: 4 ahead.
	_, err = epoch_recv_promote(&r, 8)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, held(&r), [EPOCH_SLOTS]u16{4, 8, 9, 10, 11, 12})
}

// Many promotions: the receiver stays in step with a sender chain, and it stops
// at the top of the epoch range.
@(test)
epoch_recv_near_the_top :: proc(t: ^testing.T) {
	e1 := e1_pattern()
	r: Epoch_Recv
	_, _ = epoch_recv_init(&r, e1[:], 16)
	send: Epoch_Key
	_ = epoch_send_init(&send, e1[:], 16)
	cur := u16(1)
	for cur + EPOCH_FUTURE <= EPOCH_FUTURE_MAX {
		cur += EPOCH_FUTURE
		_, err := epoch_recv_promote(&r, cur)
		if !testing.expect_value(t, err, Error.None) {
			return
		}
	}
	// One more step of up to 4 reaches 65530 at most.
	for cur < EPOCH_FUTURE_MAX {
		cur += 1
		_, err := epoch_recv_promote(&r, cur)
		testing.expect_value(t, err, Error.None)
	}
	testing.expect_value(t, cur, EPOCH_FUTURE_MAX)
	_ = epoch_send_advance(&send, cur)
	testing.expect_value(t, r.slots[r.current].epoch, cur)
	expect_bytes(t, r.slots[r.current].key[:16], send.key[:16], "key at 65530")
	expect_bytes(t, r.slots[r.current].iv[:], send.iv[:], "iv at 65530")

	// The window is capped at 65535, and above 65530 nothing is accepted as a future epoch.
	testing.expect_value(t, held(&r)[EPOCH_SLOTS - 1], EPOCH_MAX - 1)
	for e in EPOCH_FUTURE_MAX + 1 ..= EPOCH_MAX {
		_, cls := epoch_recv_lookup(&r, u16(e))
		testing.expectf(t, cls == .Drop, "epoch %d: %v", e, cls)
	}
}
