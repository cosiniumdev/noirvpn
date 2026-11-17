// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:testing"

@(test)
test_mss_text :: proc(t: ^testing.T) {
	testing.expect_value(t, mss_text(0), "off")
	testing.expect_value(t, mss_text(1360), "1360 (IPv6 1340)")
	testing.expect_value(t, mss_text(100), "100 (IPv6 80)")
}

@(test)
test_srv_mss_text :: proc(t: ^testing.T) {
	// Default: tun MTU 1400 is a fixed value, so the outer family does not matter.
	testing.expect_value(t, srv_mss_text({}, 1400, false, false), "1360 (IPv6 1340)")
	testing.expect_value(t, srv_mss_text({}, 1400, true, false), "1360 (IPv6 1340)")
	testing.expect_value(t, srv_mss_text({.Off, 0}, 1400, false, true), "off")
	// A fixed value does not depend on the overhead either.
	testing.expect_value(t, srv_mss_text({.Fixed, 1300}, 1400, false, true), "1260 (IPv6 1240)")
	// `mtu`: UDP overhead is 24, the IPv4 header 20, UDP 8, inner headers 40.
	testing.expect_value(
		t,
		srv_mss_text({.Mtu, 1500}, 1400, false, false),
		"1408 for IPv4 clients, 1388 for IPv6 clients (inner IPv6: 20 less)",
	)
	testing.expect_value(
		t,
		srv_mss_text({.Mtu, 1500}, 1400, false, true),
		"1408 for IPv4 clients, 1388 for IPv6 clients (inner IPv6: 20 less; 4 less with aead-epoch)",
	)
	// TCP adds the 2-byte length and a 20-byte header: 1500 - 20 - 20 - 26 - 40.
	testing.expect_value(
		t,
		srv_mss_text({.Mtu, 1500}, 1400, true, false),
		"1394 for IPv4 clients, 1374 for IPv6 clients (inner IPv6: 20 less)",
	)
	// Link: no outer header, so one value.
	testing.expect_value(t, srv_mss_text({.Link, 1400}, 1400, false, true), "1336 (IPv6 1316) (4 less with aead-epoch)")
}

@(test)
test_mtu_fit_warning :: proc(t: ^testing.T) {
	// The packets fit: no warning.
	testing.expect_value(t, mtu_fit_warning(1400, false, true, 28), "")
	testing.expect_value(t, mtu_fit_warning(1420, false, true, 28), "")
	testing.expect_value(t, mtu_fit_warning(1424, false, true, 28), "")
	testing.expect_value(t, mtu_fit_warning(1428, false, true, 24), "")
	testing.expect_value(t, mtu_fit_warning(1428, false, false, 28), "")
	// A TCP link has no packet limit.
	testing.expect_value(t, mtu_fit_warning(1500, true, true, 30), "")
	// 1428 with the epoch data format over IPv6 is 4 bytes over.
	testing.expect_value(
		t,
		mtu_fit_warning(1428, false, true, 28),
		"with tun-mtu 1428 a full tunnel packet is 1504 bytes on the wire over IPv6, which is more than a 1500-byte path allows, so large packets are split in two and the tunnel gets slow; set tun-mtu to 1424 or lower",
	)
	testing.expect_value(
		t,
		mtu_fit_warning(1500, false, false, 24),
		"with tun-mtu 1500 a full tunnel packet is 1552 bytes on the wire over IPv4, which is more than a 1500-byte path allows, so large packets are split in two and the tunnel gets slow; set tun-mtu to 1448 or lower",
	)
}
