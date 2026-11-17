// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:testing"

// The encrypted keys of testdata/README.md ("keypass_*"), with the certificate
// of the unencrypted key each one is a copy of.
@(private = "file")
Locked :: struct {
	name: string,
	key:  []u8,
	cert: []u8,
}

@(private = "file")
LOCKED := [?]Locked {
	{"pkcs8 ed25519", #load("testdata/keypass_pkcs8_ed25519.key.pem"), #load("testdata/ed25519_server.crt.pem")},
	{"pkcs8 p256", #load("testdata/keypass_pkcs8_p256.key.pem"), #load("testdata/p256_server.crt.pem")},
	{"pkcs8 rsa", #load("testdata/keypass_pkcs8_rsa.key.pem"), #load("testdata/rsa_server.crt.pem")},
	{"legacy rsa", #load("testdata/keypass_legacy_rsa.key.pem"), #load("testdata/rsa_server.crt.pem")},
	{"legacy p256", #load("testdata/keypass_legacy_p256.key.pem"), #load("testdata/p256_server.crt.pem")},
	{"legacy des3 rsa", #load("testdata/keypass_des3_rsa.key.pem"), #load("testdata/rsa_server.crt.pem")},
}

@(private = "file")
PLAIN_KEY := #load("testdata/p256_server.key.pem")
@(private = "file")
PLAIN_CERT := #load("testdata/p256_server.crt.pem")

@(private = "file")
PASS := "noir-test-pass"

// True when a server context takes the certificate and the key (the key
// belongs to the certificate).
@(private = "file")
key_fits :: proc(cert, key: []u8) -> Error {
	ctx, err := tls_ctx_create({role = .Server, verify = .None, cert_pem = cert, key_pem = key})
	if err == .None {
		tls_ctx_destroy(&ctx)
	}
	return err
}

@(test)
keypass_right_passphrase :: proc(t: ^testing.T) {
	for l in LOCKED {
		testing.expectf(t, key_pem_encrypted(l.key), "%s: seen as encrypted", l.name)
		plain, err := key_pem_decrypt(l.key, transmute([]u8)PASS)
		testing.expectf(t, err == .None, "%s: decrypt: %v", l.name, err)
		if err != .None {
			continue
		}
		testing.expectf(t, !key_pem_encrypted(plain), "%s: the result is not encrypted", l.name)
		testing.expectf(t, key_fits(l.cert, plain) == .None, "%s: the result belongs to the certificate", l.name)
		key_pem_wipe_free(plain)
	}
}

@(test)
keypass_wrong_passphrase :: proc(t: ^testing.T) {
	for l in LOCKED {
		plain, err := key_pem_decrypt(l.key, transmute([]u8)string("not-the-pass"))
		testing.expectf(t, err == .Bad_Passphrase, "%s: wrong passphrase: %v", l.name, err)
		testing.expect(t, plain == nil)
	}
}

@(test)
keypass_no_passphrase :: proc(t: ^testing.T) {
	for l in LOCKED {
		_, err := key_pem_decrypt(l.key, nil)
		testing.expectf(t, err == .Key_Encrypted, "%s: no passphrase: %v", l.name, err)
		// The TLS context never asks: it reports the key as encrypted.
		testing.expectf(t, key_fits(l.cert, l.key) == .Key_Encrypted, "%s: context with the encrypted key", l.name)
	}
}

@(test)
keypass_plain_key_with_passphrase :: proc(t: ^testing.T) {
	testing.expect(t, !key_pem_encrypted(PLAIN_KEY))
	plain, err := key_pem_decrypt(PLAIN_KEY, transmute([]u8)PASS)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, key_fits(PLAIN_CERT, plain), Error.None)
	key_pem_wipe_free(plain)
}

@(test)
keypass_bad_input :: proc(t: ^testing.T) {
	_, err := key_pem_decrypt(transmute([]u8)string("this is not PEM"), transmute([]u8)PASS)
	testing.expect_value(t, err, Error.Bad_Key)
	_, err = key_pem_decrypt(nil, transmute([]u8)PASS)
	testing.expect_value(t, err, Error.Bad_Key)
	long: [KEY_PASS_MAX + 1]u8
	for &b in long {
		b = 'a'
	}
	_, err = key_pem_decrypt(LOCKED[0].key, long[:])
	testing.expect_value(t, err, Error.Bad_Argument)
	// The longest passphrase is accepted (and is wrong).
	_, err = key_pem_decrypt(LOCKED[0].key, long[:KEY_PASS_MAX])
	testing.expect_value(t, err, Error.Bad_Passphrase)
}
