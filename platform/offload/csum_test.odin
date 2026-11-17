// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package offload

import "core:testing"

@(test)
vnet_header_round_trip :: proc(t: ^testing.T) {
	h := Vnet_Hdr {
		flags       = F_NEEDS_CSUM,
		gso_type    = GSO_TCPV6 | GSO_ECN,
		hdr_len     = 0x0102,
		gso_size    = 0x0304,
		csum_start  = 0x0506,
		csum_offset = 0x0708,
	}
	b: [VNET_HDR_LEN]u8
	testing.expect(t, vnet_encode(b[:], h), "encode")
	// Little endian, as the kernel's `struct virtio_net_hdr` on this machine.
	want := [VNET_HDR_LEN]u8{1, 0x84, 0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07}
	testing.expect(t, b == want, "wire format")
	g, ok := vnet_decode(b[:])
	testing.expect(t, ok, "decode")
	testing.expect(t, g == h, "round trip")
	_, ok = vnet_decode(b[:9])
	testing.expect(t, !ok, "short decode")
	testing.expect(t, !vnet_encode(b[:9], h), "short encode")
}

@(test)
checksum_matches_naive :: proc(t: ^testing.T) {
	r := Rng {
		s = 99,
	}
	data := make([]u8, 70000 + 16, context.temp_allocator)
	for i in 0 ..< len(data) {
		data[i] = u8(rng_next(&r))
	}
	dst := make([]u8, len(data), context.temp_allocator)
	lens := [?]int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 39, 40, 63, 64, 65, 100, 1399, 1400, 1401, 4096, 65535, 65536}
	for n in lens {
		// Every start offset 0..7, so unaligned loads are tested.
		for off in 0 ..< 8 {
			src := data[off:][:n]
			want := naive_fold(naive_sum(src))
			got := csum_sum(src)
			testing.expectf(t, got == want, "csum_sum n=%d off=%d: %#x want %#x", n, off, got, want)
			for i in 0 ..< len(dst) {
				dst[i] = 0
			}
			got2 := csum_copy(dst[off:][:n], src)
			testing.expectf(t, got2 == want, "csum_copy n=%d off=%d: %#x want %#x", n, off, got2, want)
			ok := true
			for i in 0 ..< n {
				if dst[off + i] != src[i] {
					ok = false
				}
			}
			testing.expectf(t, ok, "csum_copy n=%d off=%d: bad copy", n, off)
			// Nothing written outside the range.
			for i in 0 ..< off {
				testing.expect(t, dst[i] == 0, "csum_copy wrote before dst")
			}
			testing.expect(t, dst[off + n] == 0, "csum_copy wrote after dst")
		}
	}
	// All ones and all zeros.
	ones := make([]u8, 1000, context.temp_allocator)
	for i in 0 ..< len(ones) {
		ones[i] = 0xff
	}
	testing.expect_value(t, csum_sum(ones), u16(0xffff))
	testing.expect_value(t, csum_sum(ones[:0]), u16(0))
	// A destination that is too short: nothing is done.
	small: [4]u8
	testing.expect_value(t, csum_copy(small[:], ones[:8]), u16(0))
	testing.expect(t, small == {}, "short dst was written")
}

@(test)
checksum_add :: proc(t: ^testing.T) {
	testing.expect_value(t, csum_add(0xffff, 1), u16(1))
	testing.expect_value(t, csum_add(0x8000, 0x8000), u16(1))
	testing.expect_value(t, csum_add(0x1234, 0x0001), u16(0x1235))
	testing.expect_value(t, csum_add(0xffff, 0xffff), u16(0xffff))
	// A sum in two pieces (at an even offset) is the sum of the whole.
	r := Rng {
		s = 5,
	}
	d := make([]u8, 3001, context.temp_allocator)
	for i in 0 ..< len(d) {
		d[i] = u8(rng_next(&r))
	}
	for cut in ([]int{0, 2, 20, 1000, 2998, 3000}) {
		got := csum_add(csum_sum(d[:cut]), csum_sum(d[cut:]))
		testing.expectf(t, got == csum_sum(d), "cut %d", cut)
	}
}
