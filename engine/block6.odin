// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

// `block-ipv6`: the data path drops each IPv6 packet at the tunnel. The test is
// the IP version in the first byte. A packet of zero bytes is not IPv6.
is_ipv6 :: proc "contextless" (pkt: []u8) -> bool {
	return len(pkt) > 0 && pkt[0] >> 4 == 6
}
