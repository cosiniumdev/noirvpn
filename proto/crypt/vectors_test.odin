// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "core:encoding/json"
import "core:testing"
import "noir:proto/keys"
import "noir:proto/ossl"
import "noir:proto/wire"

// Real packets of proto/testdata/vectors/data-channel.json and
// data-channel-rekey.json, captured from stock 2.6.23 (baseline format) and
// 2.7.7 (epoch format) peers. Each packet is opened with keys our code derived
// from the exporter output, and sealed again (where the vector has the packet
// id) to reproduce the wire bytes.

// How many captured packets the tests below opened. Printed at the end.
@(private = "file")
Counts :: struct {
	opened:   int,
	resealed: int,
}

@(private = "file")
kind_from_name :: proc(name: string) -> (k: Payload_Kind, ok: bool) {
	switch name {
	case "ipv4-icmp":
		return .Ipv4, true
	case "ipv6":
		return .Ipv6, true
	case "ping":
		return .Ping, true
	case "occ-exit":
		return .Occ_Exit, true
	}
	return {}, false
}

@(private = "file")
format_from_name :: proc(name: string) -> keys.Format {
	// "baseline" or "epoch (aead-epoch)".
	if len(name) >= 5 && name[:5] == "epoch" {
		return .Epoch
	}
	return .Baseline
}

// Opens and re-seals every packet of one captured case.
@(private = "file")
check_case :: proc(t: ^testing.T, cs: json.Object, counts: ^Counts) {
	cell := jstr(cs, "cell")
	format := format_from_name(jstr(cs, "format"))
	cipher, cipher_ok := cipher_from_name(jstr(cs, "cipher"))
	testing.expectf(t, cipher_ok, "%s: unknown cipher", cell)
	export := unhex(jstr(jobj(cs, "exporter"), "output_hex"))

	cm, cerr := keys.derive_material(export, .Client, cipher)
	sm, serr := keys.derive_material(export, .Server, cipher)
	testing.expect_value(t, cerr, keys.Error.None)
	testing.expect_value(t, serr, keys.Error.None)

	// Pass 1: open into a separate buffer, seal again with the vector's packet id,
	// compare with the wire bytes.
	// Pass 2: fresh pair, open in place.
	// Pass 3: fresh pair, seal with the counting `Tx_Key` in capture order.
	for pass in 1 ..= 3 {
		client, server: Data_Key
		if !testing.expect_value(t, data_key_init(&client, format, cipher, 0, &cm), Error.None) ||
		   !testing.expect_value(t, data_key_init(&server, format, cipher, 0, &sm), Error.None) {
			return
		}
		defer data_key_destroy(&client)
		defer data_key_destroy(&server)

		for pv in jarr(cs, "packets") {
			p := pv.(json.Object)
			dir := jstr(p, "dir")
			what := jstr(p, "kind")
			// The client opens what the server sent, and the other way round.
			rx: ^Rx_Key = &server.rx if dir == "c2s" else &client.rx
			sender: ^Data_Key = &client if dir == "c2s" else &server
			wire_bytes := unhex(jstr(p, "wire_hex"))
			want_plain := unhex(jstr(p, "plaintext_hex"))
			want_kind, kind_ok := kind_from_name(what)
			testing.expectf(t, kind_ok, "%s: unknown kind %s", cell, what)

			id: u64
			epoch: u16
			if format == .Epoch {
				epoch = u16(jint(p, "epoch"))
				id = u64(jint(p, "packet_counter"))
			} else {
				id = u64(jint(p, "packet_id"))
			}
			peer_id := u32(jint(p, "peer_id"))

			switch pass {
			case 1:
				out := make([]u8, len(wire_bytes), context.temp_allocator)
				res, err := rx_open(rx, wire_bytes, out)
				if !testing.expectf(t, err == .None, "%s %s #%d: open failed: %v", cell, dir, id, err) {
					continue
				}
				counts.opened += 1
				expect_bytes(t, out[:res.n], want_plain, cell)
				testing.expect_value(t, res.id, id)
				testing.expect_value(t, res.peer_id, peer_id)
				testing.expect_value(t, res.epoch, epoch)
				testing.expect_value(t, classify_payload(out[:res.n]), want_kind)
				// The same packet a second time is a replay.
				_, err = rx_open(rx, wire_bytes, out)
				testing.expect_value(t, err, Error.Replay)

				// Seal again from the vector's packet id: same bytes.
				kc := &sender.tx.ctx
				again := make([]u8, len(wire_bytes), context.temp_allocator)
				n: int
				serr2: Error
				if format == .Epoch {
					// The send context of a fresh pair is at epoch 1, as in the vector.
					testing.expect_value(t, epoch, 1)
					n, serr2 = epoch_seal(kc, 0, peer_id, epoch, id, want_plain, again)
				} else {
					n, serr2 = baseline_seal(kc, 0, peer_id, u32(id), want_plain, again)
				}
				testing.expect_value(t, serr2, Error.None)
				if expect_bytes(t, again[:n], wire_bytes, cell) {
					counts.resealed += 1
				}
				// The pieces the vector lists: AD, nonce, tag.
				if format == .Epoch {
					expect_bytes(t, wire_bytes[:EPOCH_AD_LEN], unhex(jstr(p, "ad_hex")), "AD")
					nonce := epoch_nonce(kc, epoch_word(epoch, id))
					expect_bytes(t, nonce[:], unhex(jstr(p, "nonce_hex")), "nonce")
					expect_bytes(t, wire_bytes[len(wire_bytes) - TAG_LEN:], unhex(jstr(p, "tag_hex")), "tag")
				} else {
					expect_bytes(t, wire_bytes[:BASELINE_AD_LEN], unhex(jstr(p, "ad_hex")), "AD")
					nonce := baseline_nonce(kc, u32(id))
					expect_bytes(t, nonce[:], unhex(jstr(p, "nonce_hex")), "nonce")
					expect_bytes(t, wire_bytes[8:24], unhex(jstr(p, "tag_hex")), "tag")
				}
				hdr, _, herr := wire.data_v2_decode(wire_bytes)
				testing.expect_value(t, herr, wire.Error.None)
				testing.expect_value(t, hdr.peer_id, peer_id)
				testing.expect_value(t, hdr.key_id, 0)

			case 2:
				buf := make([]u8, len(wire_bytes), context.temp_allocator)
				copy(buf, wire_bytes)
				headroom := EPOCH_HEADROOM if format == .Epoch else BASELINE_HEADROOM
				res, err := rx_open(rx, buf, buf[headroom:])
				if !testing.expectf(t, err == .None, "%s %s #%d: in-place open failed: %v", cell, dir, id, err) {
					continue
				}
				expect_bytes(t, buf[headroom:][:res.n], want_plain, cell)

			case 3:
				// Packet ids in a capture are consecutive from 1 per direction,
				// so the counting sender must give the same bytes.
				out := make([]u8, len(wire_bytes), context.temp_allocator)
				n, err := data_key_seal(sender, peer_id, want_plain, out)
				testing.expect_value(t, err, Error.None)
				expect_bytes(t, out[:n], wire_bytes, cell)
				testing.expect_value(t, sender.tx.st.last_id, id)
			}
		}
	}
	keys.material_wipe(&cm)
	keys.material_wipe(&sm)
}

@(test)
decrypt_captured_data_channel :: proc(t: ^testing.T) {
	root := load_json(t, DATA_CHANNEL_JSON)
	counts: Counts
	baseline_cases, epoch_cases: int
	ciphers: [ossl.Aead_Cipher]bool
	for c in jarr(root, "cases") {
		cs := c.(json.Object)
		check_case(t, cs, &counts)
		if format_from_name(jstr(cs, "format")) == .Epoch {
			epoch_cases += 1
		} else {
			baseline_cases += 1
		}
		cipher, _ := cipher_from_name(jstr(cs, "cipher"))
		ciphers[cipher] = true
	}
	// 6 cases (3 baseline from 2.6.23, 3 epoch from 2.7.7), 6 packets each.
	testing.expect_value(t, baseline_cases, 3)
	testing.expect_value(t, epoch_cases, 3)
	testing.expect_value(t, counts.opened, 36)
	testing.expect_value(t, counts.resealed, 36)
	for c in ossl.Aead_Cipher {
		testing.expectf(t, ciphers[c], "no captured case for %v", c)
	}
}

// First packets of every key id after soft resets (data-channel-rekey.json).
// Each key id has its own exporter output and keys. Packets are opened through
// a Key_Slots table with a manual clock, as the session layer does. Keys of
// other ids must not open them.
@(test)
decrypt_captured_rekey :: proc(t: ^testing.T) {
	root := load_json(t, DATA_CHANNEL_REKEY_JSON)
	opened := 0
	cases := 0
	for c in jarr(root, "cases") {
		cs := c.(json.Object)
		cell := jstr(cs, "cell")
		format := format_from_name(jstr(cs, "format"))
		cipher, _ := cipher_from_name(jstr(cs, "cipher"))
		ids := jarr(cs, "key_ids_seen")
		testing.expectf(t, len(ids) == 3, "%s: expected 3 key ids", cell)

		server_keys: [keys.KEY_ID_COUNT]Data_Key
		client_keys: [keys.KEY_ID_COUNT]Data_Key
		slots: keys.Key_Slots
		keys.slots_init(&slots)
		now := keys.DEFAULT_TRAN_WINDOW * 0 // manual clock

		// The session layer installs each key when its key exchange is done and
		// then receives with whatever the slot table allows.
		prev, prev2: Maybe(u8)
		for idv in ids {
			kid := u8(idv.(json.Integer))
			entry := jobj(jobj(cs, "keys"), key_name(kid))
			export := unhex(jstr(entry, "exporter_output_hex"))
			cm, _ := keys.derive_material(export, .Client, cipher)
			sm, _ := keys.derive_material(export, .Server, cipher)
			testing.expect_value(t, data_key_init(&client_keys[kid], format, cipher, kid, &cm), Error.None)
			testing.expect_value(t, data_key_init(&server_keys[kid], format, cipher, kid, &sm), Error.None)
			keys.material_wipe(&cm)
			keys.material_wipe(&sm)
			now += 60e9 // one minute later (time.Duration is nanoseconds)
			dropped, ierr := keys.slots_install(&slots, kid, now)
			testing.expect_value(t, ierr, keys.Error.None)
			// The caller destroys the crypto state of dropped key ids.
			for d in 0 ..< keys.KEY_ID_COUNT {
				if d in dropped {
					data_key_destroy(&server_keys[d])
					data_key_destroy(&client_keys[d])
				}
			}
			if p1, ok := prev.?; ok {
				testing.expect(t, keys.slots_rx_ok(&slots, p1, now), "the previous key still receives")
			}
			if p2, ok := prev2.?; ok {
				testing.expect(t, !keys.slots_rx_ok(&slots, p2, now), "the key before it is gone")
			}
			prev2, prev = prev, kid

			for pv in jarr(entry, "first_packets") {
				p := pv.(json.Object)
				wire_bytes := unhex(jstr(p, "wire_hex"))
				want := unhex(jstr(p, "plaintext_hex"))
				// The key id in the packet picks the key, if the table allows it.
				hdr, _, herr := wire.data_v2_decode(wire_bytes)
				testing.expect_value(t, herr, wire.Error.None)
				testing.expect_value(t, hdr.key_id, kid)
				testing.expect(t, keys.slots_rx_ok(&slots, hdr.key_id, now), "slot table refuses a captured key id")

				rx := &server_keys[kid].rx if jstr(p, "dir") == "c2s" else &client_keys[kid].rx
				out := make([]u8, len(wire_bytes), context.temp_allocator)
				res, err := rx_open(rx, wire_bytes, out)
				if testing.expectf(t, err == .None, "%s key %d %s: %v", cell, kid, jstr(p, "dir"), err) {
					opened += 1
					expect_bytes(t, out[:res.n], want, cell)
					testing.expect_value(t, classify_payload(out[:res.n]), Payload_Kind.Ipv6 if want[0] >> 4 == 6 else .Ipv4)
				}
				// The key before this one cannot open it: the packet's key id
				// is checked first, and with the header patched to that id the
				// tag check fails (the keys of two key ids are unrelated).
				if p1, ok := prev2.?; ok && keys.slots_rx_ok(&slots, p1, now) {
					orx := &server_keys[p1].rx if jstr(p, "dir") == "c2s" else &client_keys[p1].rx
					_, err = rx_open(orx, wire_bytes, out)
					testing.expect_value(t, err, Error.Wrong_Key_Id)
					patched := make([]u8, len(wire_bytes), context.temp_allocator)
					copy(patched, wire_bytes)
					patched[0] = 0x48 | p1
					_, err = rx_open(orx, patched, out)
					testing.expect_value(t, err, Error.Bad_Tag)
				}
			}
		}
		for kid in 0 ..< keys.KEY_ID_COUNT {
			data_key_destroy(&server_keys[kid])
			data_key_destroy(&client_keys[kid])
		}
		cases += 1
	}
	testing.expect_value(t, cases, 2)
	testing.expect_value(t, opened, 12) // 2 cases x 3 key ids x 2 directions
}

@(private = "file")
key_name :: proc(id: u8) -> string {
	names := [keys.KEY_ID_COUNT]string{"0", "1", "2", "3", "4", "5", "6", "7"}
	return names[id]
}
