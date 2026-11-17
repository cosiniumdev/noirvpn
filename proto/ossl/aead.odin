// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

// Data-channel AEAD: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305.
// - 12-byte nonce, 16-byte tag (a separate buffer: the caller picks its place).
// - An `Aead` is set up once per key and direction (`aead_init`); then only the
//   nonce changes per packet.
// - `aead_seal` and `aead_open` do not allocate: the caller gives the output buffers.
// - In place is allowed: `ciphertext` may be the same slice as `plaintext`, but
//   must not overlap it any other way.
//
// Thread rule (OpenSSL backend): an `Aead` has mutable state. Use one per key
// direction per worker, never from two threads at once. AWS-LC lifts this (its
// context is immutable after init, so threads may share one `Aead`), but code
// for both backends keeps the OpenSSL rule. `aead_destroy` must never run while
// another thread uses the same `Aead`.
//
// This file: API, argument checks, and the AEAD override (below). The library
// calls are in `aead_<backend>.odin`.

AEAD_NONCE_LEN :: 12
AEAD_TAG_LEN :: 16

Aead_Cipher :: enum {
	AES_128_GCM,
	AES_256_GCM,
	CHACHA20_POLY1305,
}

Aead_Dir :: enum {
	Seal,
	Open,
}

// One key and direction. Exactly one of `lib` and `ovr` is set after a
// successful `aead_init`.
Aead :: struct {
	lib: Aead_Lib, // the context of the crypto library
	ovr: rawptr, // a key of the AEAD override
	dir: Aead_Dir,
}

// Key size in bytes.
aead_key_len :: proc "contextless" (cipher: Aead_Cipher) -> int {
	switch cipher {
	case .AES_128_GCM:
		return 16
	case .AES_256_GCM, .CHACHA20_POLY1305:
		return 32
	}
	return 0
}

// Name of the cipher as OpenVPN writes it in `data-ciphers`.
aead_cipher_name :: proc "contextless" (cipher: Aead_Cipher) -> string {
	switch cipher {
	case .AES_128_GCM:
		return "AES-128-GCM"
	case .AES_256_GCM:
		return "AES-256-GCM"
	case .CHACHA20_POLY1305:
		return "CHACHA20-POLY1305"
	}
	return ""
}

// Sets up `a` for one key and direction. `key` must be aead_key_len(cipher)
// bytes. Call `aead_destroy` when done. AES-128-GCM and AES-256-GCM go to the
// AEAD override if it runs and accepts the key. All else uses the crypto library.
aead_init :: proc(a: ^Aead, cipher: Aead_Cipher, key: []u8, dir: Aead_Dir) -> Error {
	a^ = {}
	if len(key) != aead_key_len(cipher) {
		return .Bad_Argument
	}
	if aead_ovr_on && cipher != .CHACHA20_POLY1305 {
		if k := aead_ovr.key_new(cipher, key); k != nil {
			a.ovr = k
			a.dir = dir
			return .None
		}
	}
	return aead_init_library(a, cipher, key, dir)
}

// The same as `aead_init`, but always with the crypto library. For the
// self-test of an override, and for benchmarks.
aead_init_library :: proc(a: ^Aead, cipher: Aead_Cipher, key: []u8, dir: Aead_Dir) -> Error {
	a^ = {}
	if len(key) != aead_key_len(cipher) {
		return .Bad_Argument
	}
	lib, err := lib_aead_new(cipher, key, dir)
	if err != .None {
		return err
	}
	a.lib = lib
	a.dir = dir
	return .None
}

aead_destroy :: proc "contextless" (a: ^Aead) {
	if a.ovr != nil {
		aead_ovr.key_free(a.ovr) // also wipes the key schedule
	}
	if a.lib != nil {
		lib_aead_free(a.lib) // also wipes the key schedule
	}
	a^ = {}
}

// True when `a` uses the AEAD override.
aead_uses_override :: proc "contextless" (a: ^Aead) -> bool {
	return a.ovr != nil
}

// Encrypts `plaintext` into `ciphertext` (same length or longer), writes the
// 16-byte tag to `tag`. `aad` is authenticated, not encrypted. `nonce` is 12
// bytes and must never repeat for one key. False on a size error or library failure.
aead_seal :: proc "contextless" (a: ^Aead, nonce, aad, plaintext, ciphertext, tag: []u8) -> bool {
	if a.dir != .Seal ||
	   len(nonce) != AEAD_NONCE_LEN ||
	   len(tag) != AEAD_TAG_LEN ||
	   len(ciphertext) < len(plaintext) ||
	   len(plaintext) > 1 << 30 ||
	   len(aad) > 1 << 30 {
		return false
	}
	if a.ovr != nil {
		return aead_ovr.seal(a.ovr, nonce, aad, plaintext, ciphertext, tag)
	}
	return a.lib != nil && lib_aead_seal(a.lib, nonce, aad, plaintext, ciphertext, tag)
}

// Checks `tag` over `aad` and `ciphertext`, decrypts into `plaintext` (same
// length or longer). False if not authentic: then do not use `plaintext`.
aead_open :: proc "contextless" (a: ^Aead, nonce, aad, ciphertext, tag, plaintext: []u8) -> bool {
	if a.dir != .Open ||
	   len(nonce) != AEAD_NONCE_LEN ||
	   len(tag) != AEAD_TAG_LEN ||
	   len(plaintext) < len(ciphertext) ||
	   len(ciphertext) > 1 << 30 ||
	   len(aad) > 1 << 30 {
		return false
	}
	if a.ovr != nil {
		return aead_ovr.open(a.ovr, nonce, aad, ciphertext, tag, plaintext)
	}
	return a.lib != nil && lib_aead_open(a.lib, nonce, aad, ciphertext, tag, plaintext)
}

// --- AEAD override ---
//
// An override a build may provide: another AES-128-GCM and AES-256-GCM
// implementation, used instead of the crypto library. The hook is empty unless a
// package sets `aead_override_starter` (in `@(init)`). No package here does.
//
//	@(init) of the package   aead_override_starter = <its start proc>
//	daemon, once at start    aead_override_start()  -> the starter runs once
//	                           ok: the table is installed and aead_init uses it
//	                           not ok: nothing changes
//
// Rules for an override:
//   - `aead_init` calls `key_new` only for AES-128-GCM and AES-256-GCM, with a
//     key of the right length. A nil key means "refused": the crypto library
//     creates the key.
//   - `seal` and `open` get arguments that passed the `aead_seal` / `aead_open`
//     checks. No allocation. Same results as the crypto library, byte for byte.
//   - A failed `open` must leave no plaintext in the output buffer.
//   - `key_free` wipes the key memory.
//   - A key is read-only after `key_new`: threads may share it. Code for both
//     backends still keeps the thread rule above.
//
// `aead_override_start` must run before any thread creates an `Aead`. After it the
// table is never written.

Aead_Override :: struct {
	// A short name for logs.
	name:     string,
	key_new:  proc(cipher: Aead_Cipher, key: []u8) -> rawptr,
	key_free: proc "contextless" (key: rawptr),
	seal:     proc "contextless" (key: rawptr, nonce, aad, plaintext, ciphertext, tag: []u8) -> bool,
	open:     proc "contextless" (key: rawptr, nonce, aad, ciphertext, tag, plaintext: []u8) -> bool,
}

// What the starter of an override found.
Aead_Override_Start :: struct {
	// Set when the override can run.
	table:  Aead_Override,
	// No override runs: why, for logs ("" when there is nothing to say).
	note:   string,
	// The override was there and failed its self-test.
	failed: bool,
}

// Set by the package that provides the override. It loads the
// implementation and tests it. It runs at most once.
aead_override_starter: proc() -> Aead_Override_Start

@(private)
aead_ovr: Aead_Override
@(private)
aead_ovr_on: bool
@(private)
aead_ovr_tried: bool
@(private)
aead_ovr_result: Aead_Override_Start

// Starts the override, once. Returns what the starter found: `table.name` is
// set when the override runs. A second call returns the first result.
aead_override_start :: proc() -> Aead_Override_Start {
	if aead_ovr_tried {
		return aead_ovr_result
	}
	aead_ovr_tried = true
	if aead_override_starter == nil {
		return {}
	}
	r := aead_override_starter()
	t := r.table
	if t.name == "" || t.key_new == nil || t.key_free == nil || t.seal == nil || t.open == nil {
		r.table = {}
	} else {
		aead_ovr = t
		aead_ovr_on = true
	}
	aead_ovr_result = r
	return r
}

// The name of the override that runs, or "".
aead_override_name :: proc "contextless" () -> string {
	return aead_ovr.name if aead_ovr_on else ""
}
