// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:mem"
import "core:strings"

// Encrypted private keys (the passphrase of `askpass`).
//
//	key_pem_encrypted(key_pem) -> bool                       true for an encrypted PEM key
//	key_pem_decrypt(key_pem, pass) -> (plain, Error)          the key as unencrypted PKCS#8 PEM
//
// Two PEM forms are encrypted:
//
//	-----BEGIN ENCRYPTED PRIVATE KEY-----        PKCS#8 (PBES2, or PBES1 on OpenSSL)
//	Proc-Type: 4,ENCRYPTED  + DEK-Info           the legacy form of RSA and EC keys
//
// A caller decrypts a key once and then uses the result like an unencrypted key,
// so the passphrase is needed only for this one call.

// The longest passphrase. Both libraries give the callback a buffer of 1024 bytes.
KEY_PASS_MAX :: 1023

// True when the PEM text has an encrypted private key in one of the two forms.
key_pem_encrypted :: proc(key_pem: []u8) -> bool {
	text := string(key_pem)
	return strings.contains(text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") || strings.contains(text, "Proc-Type: 4,ENCRYPTED")
}

// Reads the private key of `key_pem` with `pass` and returns it as unencrypted
// PKCS#8 PEM from `allocator`. Free it with `key_pem_wipe_free`. An unencrypted
// key is read the same way; `pass` is unused. Errors:
//
//	.Key_Encrypted    encrypted key, `pass` empty
//	.Bad_Passphrase   encrypted key, `pass` does not open it
//	.Bad_Key          no private key readable (also an encryption the library
//	                  does not support: it never asks for the passphrase)
//	.Bad_Argument     `pass` longer than KEY_PASS_MAX
key_pem_decrypt :: proc(key_pem: []u8, pass: []u8, allocator := context.allocator) -> (plain: []u8, err: Error) {
	if len(pass) > KEY_PASS_MAX {
		return nil, .Bad_Argument
	}
	bio := pem_bio(key_pem)
	if bio == nil {
		ERR_clear_error()
		return nil, .Bad_Key
	}
	defer BIO_free(bio)
	req := Pass_Request {
		pass = pass,
	}
	pkey := PEM_read_bio_PrivateKey(bio, nil, give_password, &req)
	if pkey == nil {
		ERR_clear_error()
		switch {
		case !key_pem_encrypted(key_pem):
			return nil, .Bad_Key
		case len(pass) == 0:
			return nil, .Key_Encrypted
		case req.asked:
			return nil, .Bad_Passphrase
		}
		return nil, .Bad_Key
	}
	defer EVP_PKEY_free(pkey)

	out := BIO_new(BIO_s_mem())
	if out == nil {
		ERR_clear_error()
		return nil, .Alloc
	}
	// The memory BIO wipes its buffer when it is freed (both libraries).
	defer BIO_free(out)
	if PEM_write_bio_PrivateKey(out, pkey, nil, nil, 0, nil, nil) != 1 {
		ERR_clear_error()
		return nil, .Lib
	}
	n := bio_pending(out)
	if n <= 0 {
		ERR_clear_error()
		return nil, .Lib
	}
	buf := make([]u8, n, allocator)
	if BIO_read(out, raw_data(buf), cint(n)) != cint(n) {
		ERR_clear_error()
		key_pem_wipe_free(buf, allocator)
		return nil, .Lib
	}
	return buf, .None
}

// Wipes and frees a key text of `key_pem_decrypt`.
key_pem_wipe_free :: proc(key_pem: []u8, allocator := context.allocator) {
	if len(key_pem) > 0 {
		mem.zero_explicit(raw_data(key_pem), len(key_pem))
	}
	delete(key_pem, allocator)
}

@(private = "file")
Pass_Request :: struct {
	pass:  []u8,
	asked: bool, // the library called the callback: the key is in a form it can decrypt
}

// Copies the passphrase into the buffer of the library. Without a callback
// OpenSSL would ask at the terminal.
@(private = "file")
give_password :: proc "c" (buf: [^]u8, size: cint, rwflag: cint, userdata: rawptr) -> cint {
	req := (^Pass_Request)(userdata)
	req.asked = true
	n := len(req.pass)
	if n == 0 || n > int(size) {
		return 0
	}
	mem.copy_non_overlapping(buf, raw_data(req.pass), n)
	return cint(n)
}
