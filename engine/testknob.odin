// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:os"
import "core:strconv"

// Knobs for the interop cells.
//
// `NOIRVPN_TEST_AEAD_LIMIT=<n>` lowers the AEAD usage limit (blocks plus
// packets) of every data key to `n` (a higher value has no
// effect, see `crypt.Key_Options`). In the epoch format the sender changes epoch
// every few packets, so a cell sees epoch changes against a stock peer without
// sending 2^36 blocks. Baseline format: a small value renegotiates constantly,
// so use epoch only. Undocumented; read once from the environment.
// Session layer unit tests use `Config.limit_override`. A wrong value is ignored.
test_aead_limit :: proc() -> u64 {
	v, ok := os.lookup_env("NOIRVPN_TEST_AEAD_LIMIT", context.temp_allocator)
	if !ok {
		return 0
	}
	n, pok := strconv.parse_u64(v)
	if !pok || n < 2 {
		return 0
	}
	return n
}

// `NOIRVPN_TEST_NO_PEER_ID=1`: treat the DCO service as lacking `CAP_PEER_ID` and
// `CAP_PEER_ADDR`, so the late TCP handover (older service) runs against a
// current one, in client and server.
test_no_peer_id :: proc() -> bool {
	v, ok := os.lookup_env("NOIRVPN_TEST_NO_PEER_ID", context.temp_allocator)
	return ok && v == "1"
}

// `NOIRVPN_TEST_OUTER_REKEY_BYTES=<n>` (client or server) replaces the plaintext
// byte count (default 32 GiB) after which a `tls` link updates its outer TLS
// keys, so a cell sees the update without sending 32 GiB. 0 or wrong: default.
test_outer_rekey_bytes :: proc() -> u64 {
	v, ok := os.lookup_env("NOIRVPN_TEST_OUTER_REKEY_BYTES", context.temp_allocator)
	if !ok {
		return 0
	}
	n, pok := strconv.parse_u64(v)
	if !pok {
		return 0
	}
	return n
}
