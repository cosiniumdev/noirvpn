// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "core:testing"

@(private = "file")
Hmac_Case :: struct {
	alg:  Hmac_Alg,
	key:  []u8,
	data: []u8,
	mac:  string,
}

@(private = "file")
fill :: proc(n: int, v: u8) -> []u8 {
	b := make([]u8, n, context.temp_allocator)
	for &x in b {
		x = v
	}
	return b
}

@(private = "file")
hmac_cases :: proc() -> [17]Hmac_Case {
	hi := transmute([]u8)string("Hi There")
	jefe := transmute([]u8)string("Jefe")
	what := transmute([]u8)string("what do ya want for nothing?")
	big := transmute([]u8)string("Test Using Larger Than Block-Size Key - Hash Key First")
	return(
		[17]Hmac_Case {
			// RFC 2202 (SHA-1) test cases 1, 2, 6.
			{.SHA1, fill(20, 0x0b), hi, "b617318655057264e28bc0b6fb378c8ef146be00"},
			{.SHA1, jefe, what, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},
			{.SHA1, fill(80, 0xaa), big, "aa4ae5e15272d00e95705637ce8a3b55ed402112"},
			// RFC 4231 (SHA-256, SHA-512) test cases 1, 2, 6.
			{.SHA256, fill(20, 0x0b), hi, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
			{.SHA256, jefe, what, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
			{.SHA256, fill(131, 0xaa), big, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
			{
				.SHA512,
				fill(20, 0x0b),
				hi,
				"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
			},
			{
				.SHA512,
				jefe,
				what,
				"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
			},
			{
				.SHA512,
				fill(131, 0xaa),
				big,
				"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
			},
			// RFC 4231 (SHA-224, SHA-384) test cases 1, 2, 6.
			{.SHA224, fill(20, 0x0b), hi, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"},
			{.SHA224, jefe, what, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"},
			{.SHA224, fill(131, 0xaa), big, "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"},
			{
				.SHA384,
				fill(20, 0x0b),
				hi,
				"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
			},
			{
				.SHA384,
				jefe,
				what,
				"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
			},
			{
				.SHA384,
				fill(131, 0xaa),
				big,
				"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
			},
			// Empty key and empty message.
			{.SHA256, nil, nil, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"},
			{.SHA1, nil, nil, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"},
		} \
	)
}

@(test)
hmac_one_shot_vectors :: proc(t: ^testing.T) {
	for c in hmac_cases() {
		out: [SHA512_LEN]u8
		n := hmac_size(c.alg)
		testing.expect(t, hmac(c.alg, c.key, c.data, out[:n]))
		expect_bytes(t, out[:n], unhex(c.mac), "hmac one-shot")
	}
}

@(test)
hmac_ctx_vectors_and_reuse :: proc(t: ^testing.T) {
	// One context signs all messages of its key, one after another, and
	// takes the data in pieces.
	for c in hmac_cases() {
		h: Hmac_Ctx
		testing.expect_value(t, hmac_ctx_init(&h, c.alg, c.key), Error.None)
		defer hmac_ctx_destroy(&h)
		n := hmac_size(c.alg)
		for _ in 0 ..< 3 {
			half := len(c.data) / 2
			testing.expect(t, hmac_ctx_update(&h, c.data[:half]))
			testing.expect(t, hmac_ctx_update(&h, nil))
			testing.expect(t, hmac_ctx_update(&h, c.data[half:]))
			out: [SHA512_LEN]u8
			testing.expect(t, hmac_ctx_final(&h, out[:n]))
			expect_bytes(t, out[:n], unhex(c.mac), "hmac ctx, message again with the same context")
		}
	}

	// Different messages, one context.
	h: Hmac_Ctx
	key := transmute([]u8)string("Jefe")
	testing.expect_value(t, hmac_ctx_init(&h, .SHA256, key), Error.None)
	defer hmac_ctx_destroy(&h)
	for msg in ([]string{"what do ya want for nothing?", "", "something else", "what do ya want for nothing?"}) {
		got, want: [SHA256_LEN]u8
		testing.expect(t, hmac_ctx_update(&h, transmute([]u8)msg))
		testing.expect(t, hmac_ctx_final(&h, got[:]))
		testing.expect(t, hmac(.SHA256, key, transmute([]u8)msg, want[:]))
		expect_bytes(t, got[:], want[:], "ctx equals one-shot")
	}

	// Output buffer that is too small.
	small: [SHA256_LEN - 1]u8
	testing.expect(t, !hmac_ctx_final(&h, small[:]))
	testing.expect(t, !hmac(.SHA256, key, nil, small[:]))
}

@(test)
digest_vectors :: proc(t: ^testing.T) {
	abc := transmute([]u8)string("abc")
	s1 := sha1(abc)
	s256 := sha256(abc)
	s512 := sha512(abc)
	expect_bytes(t, s1[:], unhex("a9993e364706816aba3e25717850c26c9cd0d89d"), "sha1")
	expect_bytes(
		t,
		s256[:],
		unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
		"sha256",
	)
	expect_bytes(
		t,
		s512[:],
		unhex(
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		),
		"sha512",
	)
	empty := sha256(nil)
	expect_bytes(
		t,
		empty[:],
		unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		"sha256 of nothing",
	)
}

// RFC 5869, test case 1 (extract, then expand), and test case 3 (empty salt and info).
@(test)
hkdf_rfc5869_vectors :: proc(t: ^testing.T) {
	ikm := fill(22, 0x0b)
	salt := unhex("000102030405060708090a0b0c")
	info := unhex("f0f1f2f3f4f5f6f7f8f9")
	prk: [SHA256_LEN]u8
	testing.expect(t, hkdf_extract(.SHA256, salt, ikm, prk[:]))
	expect_bytes(t, prk[:], unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), "PRK (case 1)")
	okm: [42]u8
	testing.expect(t, hkdf_expand(.SHA256, prk[:], info, okm[:]))
	expect_bytes(
		t,
		okm[:],
		unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
		"OKM (case 1)",
	)

	testing.expect(t, hkdf_extract(.SHA256, nil, ikm, prk[:]))
	expect_bytes(t, prk[:], unhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), "PRK (case 3)")
	testing.expect(t, hkdf_expand(.SHA256, prk[:], nil, okm[:]))
	expect_bytes(
		t,
		okm[:],
		unhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
		"OKM (case 3)",
	)
}

// Output longer than one hash block, for each hash. Expected values come
// from an independent implementation (Python `cryptography`).
@(test)
hkdf_multi_block :: proc(t: ^testing.T) {
	info := transmute([]u8)string("noir hkdf test")
	want := [Hmac_Alg]string {
		.SHA1   = "4ddd9aff1854dbc6a7a030a014b7d7d839ea60120c7757cd01c75ee591dafe538823704fc842413ef571452129071e73de728da9f691e884abfeffd94e9bedcaa51293991765c5a6377bd420e5b70b84749141d3990ac3b4a287da2ae481cd95531e0956af264ce0474b4b38916c796f53314fd11538663e1e8acebf14f3ecd1a0b0ff1bb4f28feba9b9eaf3c155b98e9519dfe17a22ee81594426d515990e68fb81fa5eb4ac76e6e1f5fef56afe9f22c205154717b7fccf79be1251548520963571206c5d0f0bee",
		.SHA256 = "e8d47fa736b212408fce89e4909e4b133df120b999466c9b648a5d883391a29d65f7dcc302ace26fc503c047e32ed33641154cbd92c703945ec666d7581feed67853b0674ad158a1c6a75f5f9455606f229221eb8c8257cfab4a76f2aa9a65b8736b392ead4dd0bc3861bf35e0028a82d83c51d4d810f8da4e744f4033b12d364b5e1e13de8214d012a05600a294206fff2b3102c4b793d72aab014df8e98472d244daa55d16f787ef7c309c6de768eeea72b827f149124c2e917db128d6c6b6b608dde5df306b3a",
		.SHA512 = "eb88813f03438df187ef99279023640bb8865de1feb39ba4a0fa1e72ef62d91b1514beceb6900350d9548adec896a858adf94c90235999900334bcefcb3f676c31806820480f68b9b648758ff70f5ccf0b147e23911a4dbcd7a0e5b1da0dd0c1076bdab1920fccb1eb46a397113790703db6407756339642818eb1f78c5f129087cde51c304b8a0e5845f6c1ed20d603ae81bf4221cd3af3344b64c98455525e178bac7295d0355d0e6ceb3aa26238af833d6c479bc6d591e04390abd935e3ce8fc1a69bba7c515e",
		.SHA224 = "80553a80cfbfdc3f49e01014a48f1766b9cf1f810877591bced866e836dd09f634dd2a04cf84c8612a36618ec95785ed5462776b24a3c4712cf7ed1978107aa8387418b3976545b648bc4ed6ed0fc3a6d7d230704f2b75a74c030ab0228b5ac32f132a5e939b5c7553d47a38b36f74a06edc9f908c70850426f184161e721a427e60ab4ce98aa493cc0668b0e59616c9a90811b0a42690a4a784f6d39fd6668cd6123aea78def1f0d07a251bcf5c47c716c92d11f58750400a7c79e093228d664822aee0789f7908",
		.SHA384 = "94224be08c69617e97c716df4a6b569e157eb06b4758193c0c4799f5c4a7ca9e23cd513dacd9c46cba464887115f30cac5f1e1ef70d78f21ef3b1ee9ec870d6d12f8f14d8d2dea35e3f7944b563109d69463d66f5f31f12f14d14cee408357bff6686b92625d4e361126c1a7e2b30bf6a4e5faf83b16b3dfe11314a22e0e49ddf3c358298f37a3c4aa71332a196fde38096551428f65c782ac87a54b2b2456f62b1eadf98c175f3089d0173b49d772eedb540d4db3e2d96d2331852c37d68a8d66a723288ac83574",
	}
	for alg in Hmac_Alg {
		prk := make([]u8, hmac_size(alg), context.temp_allocator)
		for &b, i in prk {
			b = u8(i + 1)
		}
		okm: [200]u8
		testing.expect(t, hkdf_expand(alg, prk, info, okm[:]))
		expect_bytes(t, okm[:], unhex(want[alg]), "hkdf_expand 200 bytes")
	}

	// The RFC limit is 255 hash blocks.
	big := make([]u8, 255 * SHA256_LEN + 1, context.temp_allocator)
	prk: [SHA256_LEN]u8
	testing.expect(t, hkdf_expand(.SHA256, prk[:], nil, big[:255 * SHA256_LEN]))
	testing.expect(t, !hkdf_expand(.SHA256, prk[:], nil, big))
}
