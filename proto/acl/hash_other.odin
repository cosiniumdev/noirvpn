// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !amd64
#+build !arm64
package acl

// Other CPU families: the SipHash form.

key_hash :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	return sip13_key(t.k0, t.k1, k)
}

@(private = "file")
key_hash_plain :: proc "contextless" (t: ^Table, k: ^Flow_Key) -> u32 {
	return sip13_key(t.k0, t.k1, k)
}

// The builds that this CPU can run. The first one is the build in use.
hash_variants :: proc "contextless" () -> (v: [3]Hash_Variant, n: int) {
	v[0] = {"plain", false, key_hash_plain}
	return v, 1
}
