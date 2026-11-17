// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:log"
import "core:testing"
import "core:thread"

// McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)", test cases 4 and 16.
@(private = "file")
GCM_P :: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
@(private = "file")
GCM_A :: "feedfacedeadbeeffeedfacedeadbeefabaddad2"
@(private = "file")
GCM_IV :: "cafebabefacedbaddecaf888"

// Seals and opens one packet and checks it against a published vector.
@(private = "file")
check_vector :: proc(t: ^testing.T, cipher: Aead_Cipher, key, nonce, aad, pt, ct, tag: []u8) {
	seal, open: Aead
	testing.expect_value(t, aead_init(&seal, cipher, key, .Seal), Error.None)
	testing.expect_value(t, aead_init(&open, cipher, key, .Open), Error.None)
	defer aead_destroy(&seal)
	defer aead_destroy(&open)

	got_ct := make([]u8, len(pt), context.temp_allocator)
	got_tag: [AEAD_TAG_LEN]u8
	testing.expect(t, aead_seal(&seal, nonce, aad, pt, got_ct, got_tag[:]), "seal failed")
	expect_bytes(t, got_ct, ct, "ciphertext")
	expect_bytes(t, got_tag[:], tag, "tag")

	got_pt := make([]u8, len(ct), context.temp_allocator)
	testing.expect(t, aead_open(&open, nonce, aad, ct, tag, got_pt), "open failed")
	expect_bytes(t, got_pt, pt, "plaintext")
}

@(test)
aes128_gcm_vector :: proc(t: ^testing.T) {
	check_vector(
		t,
		.AES_128_GCM,
		unhex("feffe9928665731c6d6a8f9467308308"),
		unhex(GCM_IV),
		unhex(GCM_A),
		unhex(GCM_P),
		unhex(
			"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		),
		unhex("5bc94fbc3221a5db94fae95ae7121a47"),
	)
}

@(test)
aes256_gcm_vector :: proc(t: ^testing.T) {
	check_vector(
		t,
		.AES_256_GCM,
		unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
		unhex(GCM_IV),
		unhex(GCM_A),
		unhex(GCM_P),
		unhex(
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		),
		unhex("76fc6ece0f4e1768cddf8853bb2d551b"),
	)
}

// RFC 8439 section 2.8.2.
@(test)
chacha20_poly1305_vector :: proc(t: ^testing.T) {
	pt := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	check_vector(
		t,
		.CHACHA20_POLY1305,
		unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
		unhex("070000004041424344454647"),
		unhex("50515253c0c1c2c3c4c5c6c7"),
		transmute([]u8)pt,
		unhex(
			"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
		),
		unhex("1ae10b594f09e26a7e902ecbd0600691"),
	)
}

// A packet that was changed anywhere, or opened with other AAD or nonce, must
// be refused. The same `Aead` must keep working afterwards.
@(test)
tamper_is_detected :: proc(t: ^testing.T) {
	for cipher in Aead_Cipher {
		key := make([]u8, aead_key_len(cipher), context.temp_allocator)
		for &b, i in key {
			b = u8(i * 7 + 1)
		}
		seal, open: Aead
		testing.expect_value(t, aead_init(&seal, cipher, key, .Seal), Error.None)
		testing.expect_value(t, aead_init(&open, cipher, key, .Open), Error.None)
		defer aead_destroy(&seal)
		defer aead_destroy(&open)

		nonce := [AEAD_NONCE_LEN]u8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		aad := [?]u8{0x48, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07}
		pt := transmute([]u8)string("the quick brown fox jumps over the lazy dog")
		ct := make([]u8, len(pt), context.temp_allocator)
		out := make([]u8, len(pt), context.temp_allocator)
		tag: [AEAD_TAG_LEN]u8
		testing.expect(t, aead_seal(&seal, nonce[:], aad[:], pt, ct, tag[:]))

		name := aead_cipher_name(cipher)
		testing.expectf(t, aead_open(&open, nonce[:], aad[:], ct, tag[:], out), "%s: good packet refused", name)
		expect_bytes(t, out, pt, name)

		// Flip one bit of the ciphertext.
		ct[5] ~= 0x01
		testing.expectf(t, !aead_open(&open, nonce[:], aad[:], ct, tag[:], out), "%s: bad ciphertext accepted", name)
		ct[5] ~= 0x01

		// Flip one bit of the tag.
		tag[15] ~= 0x80
		testing.expectf(t, !aead_open(&open, nonce[:], aad[:], ct, tag[:], out), "%s: bad tag accepted", name)
		tag[15] ~= 0x80

		// Other AAD.
		bad_aad := aad
		bad_aad[7] ~= 0x01
		testing.expectf(t, !aead_open(&open, nonce[:], bad_aad[:], ct, tag[:], out), "%s: wrong AAD accepted", name)
		testing.expectf(t, !aead_open(&open, nonce[:], nil, ct, tag[:], out), "%s: missing AAD accepted", name)

		// Other nonce.
		bad_nonce := nonce
		bad_nonce[11] ~= 0x01
		testing.expectf(t, !aead_open(&open, bad_nonce[:], aad[:], ct, tag[:], out), "%s: wrong nonce accepted", name)

		// The context still works after all those failures.
		testing.expectf(t, aead_open(&open, nonce[:], aad[:], ct, tag[:], out), "%s: good packet refused after failures", name)
		expect_bytes(t, out, pt, name)
	}
}

// Many packets with a changing nonce, many sizes, in place and not,
// with and without AAD. Also the empty packet.
@(test)
round_trip_many_sizes :: proc(t: ^testing.T) {
	sizes := [?]int{0, 1, 15, 16, 17, 63, 64, 65, 255, 512, 1400, 1500, 9000}
	for cipher in Aead_Cipher {
		key := make([]u8, aead_key_len(cipher), context.temp_allocator)
		for &b, i in key {
			b = u8(255 - i)
		}
		seal, open: Aead
		testing.expect_value(t, aead_init(&seal, cipher, key, .Seal), Error.None)
		testing.expect_value(t, aead_init(&open, cipher, key, .Open), Error.None)
		defer aead_destroy(&seal)
		defer aead_destroy(&open)

		counter: u64
		for size in sizes {
			for use_aad in 0 ..< 2 {
				for in_place in 0 ..< 2 {
					counter += 1
					nonce: [AEAD_NONCE_LEN]u8
					(^u64)(&nonce[4])^ = counter
					aad := [?]u8{9, 8, 7, 6}
					a := aad[:] if use_aad == 1 else nil

					pt := make([]u8, size, context.temp_allocator)
					for &b, i in pt {
						b = u8(i * 31 + size)
					}
					buf := make([]u8, size, context.temp_allocator)
					copy(buf, pt)
					tag: [AEAD_TAG_LEN]u8
					ok: bool
					if in_place == 1 {
						ok = aead_seal(&seal, nonce[:], a, buf, buf, tag[:])
					} else {
						ct := make([]u8, size, context.temp_allocator)
						ok = aead_seal(&seal, nonce[:], a, pt, ct, tag[:])
						buf = ct
					}
					testing.expectf(t, ok, "%v size %d: seal failed", cipher, size)
					if size >= 8 {
						// The ciphertext must differ from the plaintext.
						same := true
						for i in 0 ..< size {
							same &&= buf[i] == pt[i]
						}
						testing.expectf(t, !same, "%v size %d: not encrypted", cipher, size)
					}
					if in_place == 1 {
						ok = aead_open(&open, nonce[:], a, buf, tag[:], buf)
						expect_bytes(t, buf, pt, "in-place round trip")
					} else {
						out := make([]u8, size, context.temp_allocator)
						ok = aead_open(&open, nonce[:], a, buf, tag[:], out)
						expect_bytes(t, out, pt, "round trip")
					}
					testing.expectf(t, ok, "%v size %d: open failed", cipher, size)
				}
			}
		}
	}
}

@(test)
aead_argument_checks :: proc(t: ^testing.T) {
	a: Aead
	key16 := make([]u8, 16, context.temp_allocator)
	key32 := make([]u8, 32, context.temp_allocator)
	testing.expect_value(t, aead_init(&a, .AES_256_GCM, key16, .Seal), Error.Bad_Argument)
	testing.expect_value(t, aead_init(&a, .AES_128_GCM, key32, .Seal), Error.Bad_Argument)
	testing.expect_value(t, aead_init(&a, .CHACHA20_POLY1305, key16, .Seal), Error.Bad_Argument)

	seal, open: Aead
	testing.expect_value(t, aead_init(&seal, .AES_128_GCM, key16, .Seal), Error.None)
	testing.expect_value(t, aead_init(&open, .AES_128_GCM, key16, .Open), Error.None)
	defer aead_destroy(&seal)
	defer aead_destroy(&open)

	nonce: [AEAD_NONCE_LEN]u8
	tag: [AEAD_TAG_LEN]u8
	pt := make([]u8, 32, context.temp_allocator)
	ct := make([]u8, 32, context.temp_allocator)
	testing.expect(t, aead_seal(&seal, nonce[:], nil, pt, ct, tag[:]))
	// Wrong nonce size, wrong tag size, output too small.
	testing.expect(t, !aead_seal(&seal, nonce[:11], nil, pt, ct, tag[:]))
	testing.expect(t, !aead_seal(&seal, nonce[:], nil, pt, ct, tag[:15]))
	testing.expect(t, !aead_seal(&seal, nonce[:], nil, pt, ct[:31], tag[:]))
	// Wrong direction.
	testing.expect(t, !aead_seal(&open, nonce[:], nil, pt, ct, tag[:]))
	testing.expect(t, !aead_open(&seal, nonce[:], nil, ct, tag[:], pt))
	testing.expect(t, !aead_open(&open, nonce[:11], nil, ct, tag[:], pt))
	testing.expect(t, !aead_open(&open, nonce[:], nil, ct, tag[:], pt[:31]))
	testing.expect(t, aead_open(&open, nonce[:], nil, ct, tag[:], pt))
}

// --- one Aead shared by many threads ---

@(private = "file")
Share_Job :: struct {
	seal, open: ^Aead,
	index:      int,
	packets:    int,
	failures:   int, // packets that did not round-trip
}

@(private = "file")
share_worker :: proc(job: ^Share_Job) {
	pt, ct, back: [1400]u8
	tag: [AEAD_TAG_LEN]u8
	aad: [8]u8
	for i in 0 ..< job.packets {
		nonce: [AEAD_NONCE_LEN]u8
		(^u64)(&nonce[4])^ = u64(job.index) << 32 | u64(i)
		for &b, k in pt {
			b = u8(k + i + job.index)
		}
		n := 64 + (i * 37) % 1337
		ok := aead_seal(job.seal, nonce[:], aad[:], pt[:n], ct[:n], tag[:])
		ok = ok && aead_open(job.open, nonce[:], aad[:], ct[:n], tag[:], back[:n])
		ok = ok && string(back[:n]) == string(pt[:n])
		if !ok {
			job.failures += 1
		}
	}
}

@(private = "file")
share_run :: proc(t: ^testing.T) {
	THREADS :: 8
	for cipher in Aead_Cipher {
		key := make([]u8, aead_key_len(cipher), context.temp_allocator)
		for &b, i in key {
			b = u8(i * 7 + 1)
		}
		seal, open, ref: Aead
		testing.expect_value(t, aead_init(&seal, cipher, key, .Seal), Error.None)
		testing.expect_value(t, aead_init(&open, cipher, key, .Open), Error.None)
		testing.expect_value(t, aead_init(&ref, cipher, key, .Seal), Error.None)
		defer aead_destroy(&seal)
		defer aead_destroy(&open)
		defer aead_destroy(&ref)

		jobs: [THREADS]Share_Job
		threads: [THREADS]^thread.Thread
		for &j, i in jobs {
			j = {
				seal    = &seal,
				open    = &open,
				index   = i,
				packets = 20_000,
			}
			threads[i] = thread.create_and_start_with_poly_data(&j, share_worker)
		}
		for th in threads {
			thread.join(th)
			thread.destroy(th)
		}
		total := 0
		for j in jobs {
			total += j.failures
		}
		testing.expectf(t, total == 0, "%v: %d packets failed under sharing", cipher, total)

		// The shared context must give the same bytes as a private one.
		nonce: [AEAD_NONCE_LEN]u8
		(^u64)(&nonce[4])^ = u64(3) << 32 | 5
		pt: [100]u8
		c1, c2: [100]u8
		t1, t2: [AEAD_TAG_LEN]u8
		testing.expect(t, aead_seal(&seal, nonce[:], nil, pt[:], c1[:], t1[:]))
		testing.expect(t, aead_seal(&ref, nonce[:], nil, pt[:], c2[:], t2[:]))
		testing.expect(t, c1 == c2 && t1 == t2)
	}
}

// AWS-LC documents that seal and open may run on many threads at once on one
// context. With OpenSSL the context holds per-packet state, so each worker
// needs its own (README, "Thread rule"). The test skips there.
@(test)
aead_shared_across_threads :: proc(t: ^testing.T) {
	if NOIR_CRYPTO != "awslc" {
		log.warn("SKIP (openssl): an Aead is not safe to share between threads on this backend")
		return
	}
	share_run(t)
}

// `aead_init_library` never uses the AEAD override. `aead_init` uses it only
// for AES-GCM, and only when a build started one. Both give the same bytes.
@(test)
aead_override_choice :: proc(t: ^testing.T) {
	on := aead_override_name() != ""
	for cipher in Aead_Cipher {
		key := make([]u8, aead_key_len(cipher), context.temp_allocator)
		for &b, i in key {
			b = u8(i * 3 + 1)
		}
		a, b, o: Aead
		testing.expect_value(t, aead_init(&a, cipher, key, .Seal), Error.None)
		testing.expect_value(t, aead_init_library(&b, cipher, key, .Seal), Error.None)
		testing.expect_value(t, aead_init(&o, cipher, key, .Open), Error.None)
		defer aead_destroy(&a)
		defer aead_destroy(&b)
		defer aead_destroy(&o)
		testing.expect_value(t, aead_uses_override(&a), on && cipher != .CHACHA20_POLY1305)
		testing.expect(t, !aead_uses_override(&b))

		nonce: [AEAD_NONCE_LEN]u8
		aad := [?]u8{1, 2, 3, 4, 5, 6, 7, 8}
		pt: [300]u8
		for &x, i in pt {
			x = u8(i)
		}
		c1, c2, back: [300]u8
		t1, t2: [AEAD_TAG_LEN]u8
		testing.expect(t, aead_seal(&a, nonce[:], aad[:], pt[:], c1[:], t1[:]))
		testing.expect(t, aead_seal(&b, nonce[:], aad[:], pt[:], c2[:], t2[:]))
		testing.expectf(t, c1 == c2 && t1 == t2, "%v: the two paths differ", cipher)
		testing.expect(t, aead_open(&o, nonce[:], aad[:], c2[:], t2[:], back[:]))
		testing.expect(t, back == pt)
	}
	// An Aead that was never set up, or was destroyed, refuses every call.
	z: Aead
	nonce: [AEAD_NONCE_LEN]u8
	tag: [AEAD_TAG_LEN]u8
	buf: [16]u8
	testing.expect(t, !aead_seal(&z, nonce[:], nil, buf[:], buf[:], tag[:]))
	z.dir = .Open
	testing.expect(t, !aead_open(&z, nonce[:], nil, buf[:], tag[:], buf[:]))
	aead_destroy(&z)
}
