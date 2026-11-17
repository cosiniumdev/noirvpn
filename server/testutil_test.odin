// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:encoding/base64"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "noir:proto/config"
import "noir:proto/ossl"

SEC :: time.Second

// Small deterministic PRNG (xorshift64*), so every test repeats exactly.
Rng :: struct {
	s: u64,
}

rng_make :: proc(seed: u64) -> Rng {
	return Rng{seed * 0x9E3779B97F4A7C15 + 1}
}

rng_next :: proc(r: ^Rng) -> u64 {
	r.s ~= r.s >> 12
	r.s ~= r.s << 25
	r.s ~= r.s >> 27
	return r.s * 0x2545F4914F6CDD1D
}

rng_below :: proc(r: ^Rng, n: int) -> int {
	return int(rng_next(r) % u64(n))
}

// ---------------------------------------------------------------------------
// Config helpers

SERVER_BASE :: `server 10.8.0.0 255.255.255.0
dev tun
<ca>
CA
</ca>
<cert>
CERT
</cert>
<key>
KEY
</key>
`

PINNED_BASE :: `server 10.8.0.0 255.255.255.0
dev tun
<cert>
CERT
</cert>
<key>
KEY
</key>
peer-keys peers.txt
`

load_cfg :: proc(text: string) -> config.Config {
	return config.build(config.parse_text(text, "test.conf"))
}

// Builds a server config; fails the test on errors.
make_cfg :: proc(t: ^testing.T, base: string, extra := "", loc := #caller_location) -> (cfg: config.Config, ok: bool) {
	cfg = load_cfg(strings.concatenate({base, extra}, context.temp_allocator))
	if !config.ok(&cfg) {
		testing.expectf(
			t,
			false,
			"config errors:\n%s",
			config.format_diagnostics(cfg.diags, context.temp_allocator),
			loc = loc,
		)
		config.destroy(&cfg)
		return {}, false
	}
	return cfg, true
}

// ---------------------------------------------------------------------------
// In-memory files

Mem_Files :: map[string]string

mem_loader :: proc(user: rawptr, path: string, allocator: mem.Allocator) -> (data: []u8, ok: bool) {
	files := (^Mem_Files)(user)
	s, found := files[path]
	if !found {
		return nil, false
	}
	return transmute([]u8)strings.clone(s, allocator), true
}

// ---------------------------------------------------------------------------
// Keys and peers files

// A 32-byte digest that depends on `n` only.
digest_of :: proc(n: u64) -> (d: [32]u8) {
	r := rng_make(n + 12345)
	for i in 0 ..< 4 {
		v := rng_next(&r)
		for j in 0 ..< 8 {
			d[i * 8 + j] = u8(v >> u64(8 * j))
		}
	}
	return
}

pin_text :: proc(n: u64, kind := "sha256") -> string {
	d := digest_of(n)
	enc, _ := base64.encode(d[:], allocator = context.temp_allocator)
	return strings.concatenate({kind, ":", enc}, context.temp_allocator)
}

peer_key :: proc(n: u64) -> ossl.Peer_Key {
	return ossl.Peer_Key{spki_sha256 = digest_of(n), cert_sha256 = digest_of(n + 1000000)}
}

// A pin table from peers file text; fails the test on errors in the text.
make_pins :: proc(t: ^testing.T, text: string, loc := #caller_location) -> ^Pin_Table {
	peers := config.peers_parse(text, "peers.txt")
	if !config.peers_ok(&peers) {
		testing.expectf(
			t,
			false,
			"peers file errors:\n%s",
			config.format_diagnostics(peers.diags, context.temp_allocator),
			loc = loc,
		)
	}
	return pin_table_make(peers)
}

// ---------------------------------------------------------------------------
// Packets

ip4_packet :: proc(src, dst: [4]u8, size := 40) -> []u8 {
	src, dst := src, dst
	p := make([]u8, size, context.temp_allocator)
	p[0] = 0x45
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return p
}

ip6_packet :: proc(src, dst: [16]u8, size := 60) -> []u8 {
	src, dst := src, dst
	p := make([]u8, size, context.temp_allocator)
	p[0] = 0x60
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	return p
}

v6 :: proc(s: string) -> [16]u8 {
	a, _ := config.ipv6_parse(s)
	return a
}

v4 :: proc(s: string) -> [4]u8 {
	a, _ := config.ipv4_parse(s)
	return a
}

// A distinct transport address per number.
tkey :: proc(n: int) -> Addr_Key {
	return addr_key_v4({10, u8(n >> 16), u8(n >> 8), u8(n)}, u16(40000 + n % 1000), 0)
}

// fd00::<n>
v6n :: proc(n: int) -> (a: [16]u8) {
	a = v6("fd00::")
	a[14] = u8(n >> 8)
	a[15] = u8(n)
	return
}
