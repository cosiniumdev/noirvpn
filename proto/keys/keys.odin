// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package keys turns the TLS exporter output into data-channel keys and decides
// which keys are in use and when to replace them.
//
// Pure state: no I/O, no clock (the caller passes `now` as a `time.Duration` on
// any monotonic scale), no crypto contexts (package crypt creates AEAD contexts
// from the key bytes generated here and seals and opens packets).
//
//	material.odin   256 exporter bytes -> send and receive key bytes
//	epoch.odin      epoch key schedule (OVPN expand-label, future-key window)
//	usage.odin      AEAD usage limits and rekey triggers, as data
//	slots.odin      the 8 key ids of a peer: primary, lame duck, transition window
//
// Key bytes are secret. Every type that holds them has a wipe proc.
// Call it when the key is dropped.
package keys

// Which of the two data packet formats a connection uses. It is fixed for the
// whole connection by the `aead-epoch` protocol flag.
Format :: enum u8 {
	Baseline, // packet id (u32) and tag before the ciphertext
	Epoch, // epoch and counter, tag after the ciphertext
}

// The name of a format, for logs and the control bus.
format_name :: proc "contextless" (f: Format) -> string {
	switch f {
	case .Baseline:
		return "baseline"
	case .Epoch:
		return "epoch"
	}
	return "?"
}

Error :: enum {
	None,
	// The exporter output is not 256 bytes.
	Bad_Export_Length,
	// The first 16 bytes of one of the four 64-byte parts are all zero: the
	// export most likely failed and left an empty buffer.
	Zero_Material,
	// An argument has a wrong size or value (key size, label length, ...).
	Bad_Argument,
	// The crypto library failed (HKDF). Not a property of the input.
	Crypto,
	// The epoch chain cannot go past epoch 65535.
	Epoch_Exhausted,
	// Epoch not in the window (receiver) or not ahead of the current one (sender).
	Bad_Epoch,
	// Key id above 7.
	Bad_Key_Id,
	// The slot of this key id is already in use.
	Key_Id_In_Use,
}

// A key id has 3 bits.
KEY_ID_COUNT :: 8
Key_Id_Set :: bit_set[0 ..< KEY_ID_COUNT; u8]

// The key id that follows `id`: 0 is
// the first key only, then 1, 2, ... 7, and 7 wraps to 1.
key_id_next :: proc "contextless" (id: u8) -> u8 {
	if id >= KEY_ID_COUNT - 1 {
		return 1
	}
	return id + 1
}
