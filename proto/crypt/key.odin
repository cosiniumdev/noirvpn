// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package crypt

import "base:runtime"
import "core:mem"
import "noir:proto/keys"
import "noir:proto/ossl"

// Keys of one key id with their counters and rules:
//
//   Tx_Key     send direction: key, packet id counter, usage, epoch chain
//   Rx_Key     receive direction: key(s), replay window(s), usage
//   Data_Key   both, and the rules that tie the two epochs together
//
// Thread sharing: see the package comment. `tx_seal` and `rx_open` are the
// packet procs; they do not allocate.

// What a worker owns for the send direction of one key (or one epoch key).
Tx_State :: struct {
	last_id: u64, // packet id (baseline) or counter (epoch) of the last packet sent; 0 = none yet
	usage:   keys.Usage, // blocks and highest id of the current key
}

// What a worker owns for the receive direction of one key (or one epoch key).
Rx_State :: struct {
	replay: Replay_Window,
	usage:  keys.Usage, // blocks, highest id, failed tag checks
}

// The usage limit in force: the spec's limit, or a lower override. A spec
// limit of 0 means none (ChaCha20-Poly1305), so any override is lower.
@(private)
effective_limit :: #force_inline proc "contextless" (override, spec: u64) -> u64 {
	if override != 0 && (spec == 0 || override < spec) {
		return override
	}
	return spec
}

Key_Options :: struct {
	// Lowers the AEAD usage limit (0: the spec's value). For tests: the stock
	// binary has a hidden option for the same purpose. A value above the spec's
	// limit is ignored, so the override can never weaken a key.
	limit_override: u64,
	// Replay window size in bits (0: 64). See `replay_init`.
	replay_bits:    int,
}

// --- Send direction ---

Tx_Key :: struct {
	format:      keys.Format,
	cipher:      ossl.Aead_Cipher,
	key_id:      u8,
	usable:      bool, // set by init; cleared by destroy or by a library failure
	limit:       u64, // AEAD usage limit (0: none)
	ctx:         Key_Ctx, // baseline: the key; epoch: the key of the current send epoch
	st:          Tx_State,
	pkts, bytes: u64, // everything sent with this key id, all epochs
	advances:    u64, // epoch format: how often the send epoch moved (by limit, by the peer, or by `tx_follow_epoch`)
	chain:       keys.Epoch_Key, // epoch format: the send chain, at the current send epoch
}

// Sets up the send side of key `key_id` from `m` (`Key_Material.send`).
tx_init :: proc(tx: ^Tx_Key, format: keys.Format, cipher: ossl.Aead_Cipher, key_id: u8, m: ^keys.Dir_Material, opts: Key_Options = {}) -> Error {
	tx^ = {}
	tx.format = format
	tx.cipher = cipher
	tx.key_id = key_id
	tx.limit = effective_limit(opts.limit_override, keys.usage_limit(cipher, format))
	err: Error
	switch format {
	case .Baseline:
		err = key_ctx_init_baseline(&tx.ctx, cipher, m.key[:m.key_len], m.iv[:], .Seal)
	case .Epoch:
		if kerr := keys.epoch_send_init(&tx.chain, m.e1[:], m.key_len); kerr != .None {
			return key_error(kerr)
		}
		err = tx_epoch_ctx(tx)
	}
	tx.usable = err == .None
	return err
}

// Frees the AEAD context and wipes the key bytes.
tx_destroy :: proc "contextless" (tx: ^Tx_Key) {
	key_ctx_destroy(&tx.ctx)
	keys.epoch_key_wipe(&tx.chain)
	tx^ = {}
}

// (Re)builds the context of the current send epoch from the chain.
@(private)
tx_epoch_ctx :: proc "contextless" (tx: ^Tx_Key) -> Error {
	// Setting up a context calls the C library; it needs no Odin context, but
	// the binding is a normal proc.
	context = runtime.default_context()
	key_ctx_destroy(&tx.ctx)
	c := &tx.chain
	err := key_ctx_init_epoch(&tx.ctx, tx.cipher, c.key[:c.key_len], c.iv[:], .Seal)
	// The context has the key now; the chain needs only E.
	mem.zero_explicit(&c.key, size_of(c.key))
	return err
}

@(private)
key_error :: proc "contextless" (e: keys.Error) -> Error {
	#partial switch e {
	case .None:
		return .None
	case .Bad_Argument:
		return .Bad_Argument
	}
	return .Crypto
}

// Moves the send side to epoch `to` (above the current one), with a fresh
// counter and usage. Epoch format only.
@(private)
tx_set_epoch :: proc "contextless" (tx: ^Tx_Key, to: u16) -> Error {
	if kerr := keys.epoch_send_advance(&tx.chain, to); kerr != .None {
		tx.usable = false
		return key_error(kerr)
	}
	tx.st = {}
	tx.advances += 1
	if err := tx_epoch_ctx(tx); err != .None {
		tx.usable = false
		return err
	}
	return .None
}

// The send epoch (0 in the baseline format).
tx_epoch :: proc "contextless" (tx: ^Tx_Key) -> u16 {
	if tx.format == .Epoch {
		return tx.chain.epoch
	}
	return 0
}

// The receive side saw a packet of epoch `e` authenticate and moved to it. The
// send epoch is never lower than the receive epoch.
// No-op if the send epoch is already `e` or higher.
tx_follow_epoch :: proc "contextless" (tx: ^Tx_Key, e: u16) -> Error {
	if tx.format != .Epoch || e <= tx.chain.epoch {
		return .None
	}
	return tx_set_epoch(tx, e)
}

// Moves the send side to the next epoch now. Normally
// `tx_seal` does this by itself. `Data_Key` calls it for rule 2. No-op at
// epoch 65535.
tx_next_epoch :: proc "contextless" (tx: ^Tx_Key) -> Error {
	if tx.format != .Epoch || tx.chain.epoch == keys.EPOCH_MAX {
		return .None
	}
	return tx_set_epoch(tx, tx.chain.epoch + 1)
}

// Seals `plain` into `out` and returns the packet length. `plain` may be
// `out[headroom:]` (see the package comment). Takes the next packet id; a
// failed call (buffer errors) takes none.
// `.Packet_Id_Exhausted`: this key cannot send any more. Start a rekey and use
// another key; do not retry with this one.
tx_seal :: proc "contextless" (tx: ^Tx_Key, peer_id: u32, plain: []u8, out: []u8) -> (n: int, err: Error) {
	if !tx.usable {
		return 0, .Crypto
	}
	if len(plain) == 0 {
		return 0, .Bad_Argument // a sender never sends an empty payload
	}
	id: u64
	switch tx.format {
	case .Baseline:
		id = tx.st.last_id + 1
		if id > BASELINE_PID_MAX {
			return 0, .Packet_Id_Exhausted
		}
		n, err = baseline_seal(&tx.ctx, tx.key_id, peer_id, u32(id), plain, out)
	case .Epoch:
		// Move to the next epoch when the counter or the usage limit is reached
		// (6.5, rules 1 and 3). At the last epoch there is nowhere to go.
		if tx.chain.epoch < keys.EPOCH_MAX &&
		   (tx.st.last_id >= EPOCH_COUNTER_MAX || keys.usage_reached(tx.limit, tx.st.usage)) {
			if err = tx_set_epoch(tx, tx.chain.epoch + 1); err != .None {
				return 0, err
			}
		}
		id = tx.st.last_id + 1
		if id > EPOCH_COUNTER_MAX {
			return 0, .Packet_Id_Exhausted
		}
		n, err = epoch_seal(&tx.ctx, tx.key_id, peer_id, tx.chain.epoch, id, plain, out)
	}
	if err != .None {
		return 0, err
	}
	tx.st.last_id = id
	keys.usage_count(&tx.st.usage, id, len(plain))
	tx.pkts += 1
	tx.bytes += u64(len(plain))
	return n, .None
}

// --- Receive direction ---

Baseline_Rx :: struct {
	ctx: Key_Ctx,
	st:  Rx_State,
}

// One epoch key of the receive window, with what keeps its state. The slot
// numbers are those of `keys.Epoch_Recv`.
Epoch_Rx_Slot :: struct {
	ctx: Key_Ctx,
	st:  Rx_State,
}

Epoch_Rx :: struct {
	chain: keys.Epoch_Recv,
	slot:  [keys.EPOCH_SLOTS]Epoch_Rx_Slot,
}

Rx_Key :: struct {
	format:      keys.Format,
	cipher:      ossl.Aead_Cipher,
	key_id:      u8,
	usable:      bool,
	limit:       u64,
	replay_bits: int,
	pkts, bytes: u64, // everything accepted with this key id, all epochs
	advances:    u64, // epoch format: how often a future epoch authenticated and became current
	body:        union {
		Baseline_Rx,
		Epoch_Rx,
	},
}

// What `rx_open` found.
Open_Result :: struct {
	n:              int, // plaintext length; the plaintext is in the `out` given
	peer_id:        u32, // from the header (the tag covers it); the caller looks the peer up before it opens
	id:             u64, // packet id (baseline) or counter (epoch)
	epoch:          u16, // epoch format: epoch of the packet
	epoch_advanced: bool, // epoch format: a future epoch authenticated and became current; see `tx_follow_epoch`
}

// Sets up the receive side of key `key_id` from `m` (`Key_Material.recv`).
rx_init :: proc(rx: ^Rx_Key, format: keys.Format, cipher: ossl.Aead_Cipher, key_id: u8, m: ^keys.Dir_Material, opts: Key_Options = {}) -> Error {
	rx^ = {}
	rx.format = format
	rx.cipher = cipher
	rx.key_id = key_id
	rx.limit = effective_limit(opts.limit_override, keys.usage_limit(cipher, format))
	rx.replay_bits = opts.replay_bits if opts.replay_bits != 0 else REPLAY_DEFAULT_BITS
	switch format {
	case .Baseline:
		b := Baseline_Rx{}
		if err := key_ctx_init_baseline(&b.ctx, cipher, m.key[:m.key_len], m.iv[:], .Open); err != .None {
			return err
		}
		replay_init(&b.st.replay, rx.replay_bits)
		rx.body = b
		rx.usable = true
		return .None
	case .Epoch:
		rx.body = Epoch_Rx{}
		er := &rx.body.(Epoch_Rx)
		change, kerr := keys.epoch_recv_init(&er.chain, m.e1[:], m.key_len)
		if kerr != .None {
			return key_error(kerr)
		}
		if err := rx_epoch_apply(rx, er, change); err != .None {
			rx_destroy(rx)
			return err
		}
		rx.usable = true
		return .None
	}
	return .Bad_Argument
}

rx_destroy :: proc "contextless" (rx: ^Rx_Key) {
	switch &b in rx.body {
	case Baseline_Rx:
		key_ctx_destroy(&b.ctx)
	case Epoch_Rx:
		for i in 0 ..< keys.EPOCH_SLOTS {
			key_ctx_destroy(&b.slot[i].ctx)
		}
		keys.epoch_recv_wipe(&b.chain)
	}
	rx^ = {}
}

// Brings the per-slot state in step with a change of the epoch window. Drops
// what belonged to freed slots. Builds contexts and empty replay windows for
// new ones.
@(private)
rx_epoch_apply :: proc "contextless" (rx: ^Rx_Key, er: ^Epoch_Rx, change: keys.Epoch_Change) -> Error {
	context = runtime.default_context()
	for i in 0 ..< keys.EPOCH_SLOTS {
		if i in change.freed {
			key_ctx_destroy(&er.slot[i].ctx)
			er.slot[i] = {}
		}
	}
	for i in 0 ..< keys.EPOCH_SLOTS {
		if i not_in change.filled {
			continue
		}
		k := &er.chain.slots[i]
		sl := &er.slot[i]
		sl.st = {}
		replay_init(&sl.st.replay, rx.replay_bits)
		err := key_ctx_init_epoch(&sl.ctx, rx.cipher, k.key[:k.key_len], k.iv[:], .Open)
		mem.zero_explicit(&k.key, size_of(k.key)) // the context has it now
		if err != .None {
			return err
		}
	}
	return .None
}

// Checks, decrypts and accepts one packet.
//
// SPEC-GAP: the spec says the shortest packet is 24 (baseline) or 28
// (epoch) bytes "plus the payload", and a sender never sends an empty payload.
// A packet of exactly the minimum length is not "shorter", so an authentic one
// is accepted with `n == 0` (`classify_payload` says `.Empty`; the caller drops
// it). `tx_seal` refuses an empty payload.
//
// Order: length, opcode and key id -> epoch window ->
// tag -> replay window -> counters. Only an authentic, fresh packet changes
// anything.
// `out` gets the plaintext (may be the ciphertext's own place, see the package
// comment). On error `out` is garbage.
//
// `.Bad_Tag` counts a failed check against the key. A future-epoch packet that
// authenticates moves the receive window (`epoch_advanced`); the send side must
// follow (`tx_follow_epoch`; `data_key_open` does it).
rx_open :: proc "contextless" (rx: ^Rx_Key, pkt, out: []u8) -> (res: Open_Result, err: Error) {
	if !rx.usable {
		return {}, .Crypto
	}
	switch &b in rx.body {
	case Baseline_Rx:
		if len(pkt) < BASELINE_HEADROOM {
			return {}, .Too_Short
		}
		hdr := get_header(pkt) or_return
		if hdr.key_id != rx.key_id {
			return {}, .Wrong_Key_Id
		}
		if b.st.usage.tag_fail > keys.TAG_FAIL_REFUSE {
			return {}, .Key_Disabled
		}
		pid, n, oerr := baseline_open(&b.ctx, pkt, out)
		if oerr != .None {
			if oerr == .Bad_Tag {
				b.st.usage.tag_fail += 1
			}
			return {}, oerr
		}
		if !replay_accept(&b.st.replay, u64(pid)) {
			return {}, .Replay
		}
		keys.usage_count(&b.st.usage, u64(pid), n)
		rx.pkts += 1
		rx.bytes += u64(n)
		return {n = n, peer_id = hdr.peer_id, id = u64(pid)}, .None

	case Epoch_Rx:
		if len(pkt) < EPOCH_HEADROOM + EPOCH_TAILROOM {
			return {}, .Too_Short
		}
		hdr := get_header(pkt) or_return
		if hdr.key_id != rx.key_id {
			return {}, .Wrong_Key_Id
		}
		epoch, counter, _ := epoch_peek(pkt)
		// The packet of the current epoch is the usual case: it takes the current
		// slot at once.
		idx, class := b.chain.current, keys.Epoch_Class.Current
		if epoch == 0 || epoch != b.chain.slots[idx].epoch {
			idx, class = keys.epoch_recv_lookup(&b.chain, epoch)
			if class == .Drop {
				return {}, .Unknown_Epoch
			}
		}
		sl := &b.slot[idx]
		if sl.st.usage.tag_fail > keys.TAG_FAIL_REFUSE {
			return {}, .Key_Disabled
		}
		if counter == 0 {
			return {}, .Bad_Packet_Id // the epoch is not 0: the lookup above refused that
		}
		n, oerr := epoch_open_checked(&sl.ctx, pkt, out)
		if oerr != .None {
			if oerr == .Bad_Tag {
				sl.st.usage.tag_fail += 1
			}
			return {}, oerr
		}
		if !replay_accept(&sl.st.replay, counter) {
			return {}, .Replay
		}
		res = {
			n       = n,
			peer_id = hdr.peer_id,
			id      = counter,
			epoch   = epoch,
		}
		if class == .Future {
			// Authenticated: this epoch is current now. Contexts of the slots
			// that changed are built here (the C library may allocate).
			change, kerr := keys.epoch_recv_promote(&b.chain, epoch)
			if kerr != .None {
				rx.usable = false
				return {}, key_error(kerr)
			}
			if aerr := rx_epoch_apply(rx, &b, change); aerr != .None {
				rx.usable = false
				return {}, aerr
			}
			res.epoch_advanced = true
			rx.advances += 1
		}
		keys.usage_count(&sl.st.usage, counter, n)
		rx.pkts += 1
		rx.bytes += u64(n)
		return res, .None
	}
	return {}, .Bad_Argument
}

// The receive epoch (0 in the baseline format).
rx_epoch :: proc "contextless" (rx: ^Rx_Key) -> u16 {
	if er, ok := &rx.body.(Epoch_Rx); ok {
		return er.chain.slots[er.chain.current].epoch
	}
	return 0
}

// Usage of the current receive key (the current epoch key in the epoch format).
rx_usage :: proc "contextless" (rx: ^Rx_Key) -> keys.Usage {
	switch &b in rx.body {
	case Baseline_Rx:
		return b.st.usage
	case Epoch_Rx:
		return b.slot[b.chain.current].st.usage
	}
	return {}
}

// --- Both directions ---

Data_Key :: struct {
	tx: Tx_Key,
	rx: Rx_Key,
}

// Sets up both directions of key `key_id` from the exporter split of
// `keys.derive_material`. The caller wipes `m` afterwards (`keys.material_wipe`).
data_key_init :: proc(dk: ^Data_Key, format: keys.Format, cipher: ossl.Aead_Cipher, key_id: u8, m: ^keys.Key_Material, opts: Key_Options = {}) -> Error {
	if err := tx_init(&dk.tx, format, cipher, key_id, &m.send, opts); err != .None {
		return err
	}
	if err := rx_init(&dk.rx, format, cipher, key_id, &m.recv, opts); err != .None {
		tx_destroy(&dk.tx)
		return err
	}
	return .None
}

data_key_destroy :: proc "contextless" (dk: ^Data_Key) {
	tx_destroy(&dk.tx)
	rx_destroy(&dk.rx)
}

// Seals with the send key. Epoch format, rule 2: if send
// and receive epochs are equal and the receive key is at its usage limit (or had
// too many failed tag checks), move to the next epoch. The peer moves too.
data_key_seal :: proc "contextless" (dk: ^Data_Key, peer_id: u32, plain: []u8, out: []u8) -> (n: int, err: Error) {
	if dk.tx.format == .Epoch && dk.tx.usable && dk.rx.usable {
		if tx_epoch(&dk.tx) == rx_epoch(&dk.rx) {
			u := rx_usage(&dk.rx)
			if keys.usage_reached(dk.rx.limit, u) || u.tag_fail > keys.TAG_FAIL_REKEY {
				if err = tx_next_epoch(&dk.tx); err != .None {
					return 0, err
				}
			}
		}
	}
	return tx_seal(&dk.tx, peer_id, plain, out)
}

// Opens with the receive key and, in the epoch format, moves the send epoch
// follow a receive epoch that moved ahead (6.6 step 3).
data_key_open :: proc "contextless" (dk: ^Data_Key, pkt, out: []u8) -> (res: Open_Result, err: Error) {
	res, err = rx_open(&dk.rx, pkt, out)
	if err == .None && res.epoch_advanced {
		if ferr := tx_follow_epoch(&dk.tx, res.epoch); ferr != .None {
			return {}, ferr
		}
	}
	return
}

// Counters for `keys.rekey_check` (copy them out of the workers that own the
// two directions if those differ).
data_key_usage :: proc "contextless" (dk: ^Data_Key) -> keys.Key_Usage {
	return {
		tx = dk.tx.st.usage,
		rx = rx_usage(&dk.rx),
		tx_pkts = dk.tx.pkts,
		rx_pkts = dk.rx.pkts,
		tx_bytes = dk.tx.bytes,
		rx_bytes = dk.rx.bytes,
		tx_epoch = tx_epoch(&dk.tx),
	}
}
