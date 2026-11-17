// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:log"
import "core:strings"
import "core:testing"

// Random input must never crash the parser or builder, and results must hold
// together. Deterministic (fixed seed), so a failure repeats. Also run under
// -sanitize:address.

FUZZ_ROUNDS :: 3000

// Words used to build random arguments.
VOCAB := [?]string {
	"0",
	"1",
	"-1",
	"5",
	"60",
	"443",
	"1194",
	"65535",
	"65536",
	"99999999999999999999",
	"udp",
	"tcp",
	"tcp-client",
	"tcp-server",
	"udp6",
	"tcp4-server",
	"10.8.0.0",
	"10.8.0.1",
	"255.255.255.0",
	"255.0.255.0",
	"192.168.1.0/24",
	"::1",
	"fd00::/64",
	"fd00::1/64",
	"2001:db8::/32",
	"subnet",
	"net30",
	"tun",
	"tap",
	"tun0",
	"yes",
	"no",
	"off",
	"on",
	"auto",
	"both",
	"pin",
	"require",
	"prefer",
	"server",
	"client",
	"def1",
	"bypass-dhcp",
	"ipv6",
	"local",
	"nopool",
	"dir",
	"mtu",
	"fixed",
	"infinite",
	"default",
	"vpn_gateway",
	"AES-256-GCM",
	"AES-128-GCM:CHACHA20-POLY1305",
	"AES-256-CBC",
	"?BF-CBC",
	"DEFAULT",
	"SHA1",
	"SHA256",
	"SHA512",
	"MD5",
	"1.2",
	"1.3",
	"1.0",
	"or-highest",
	"X25519MLKEM768",
	"X25519::P-256",
	"force-cookie",
	"allow-noncookie",
	"ca.crt",
	"/etc/x/y.key",
	"pkcs11:id=1",
	"file name",
	"DA:D1:56:B8:FA:CA:23:12:1E:77:FB:F8:A8:85:19:E1:7E:F1:A2:C5:83:B2:4E:55:1B:81:79:23:E1:67:2E:74",
	"uid",
	"gid",
	"read,admin",
	"mode",
	"660",
	"group",
	"ignore",
	"accept",
	"reject",
	"route 10.0.0.0 255.0.0.0",
	"username-only",
	"nointeract",
	"subject",
	"name",
	"name-prefix",
	"infinite",
	"ipv6only",
	"same-interface",
	"",
	"\\",
	"\"",
	"'",
	"#",
	";",
	"--",
	"<",
	">",
	"\xff\xfe",
	"a\tb",
}

// Characters for byte-level garbage; plenty of syntax characters.
GARBAGE := "abcdefghijklmnopqrstuvwxyz0123456789 \t\r\n\"'\\<>/#;-_.:,=!@\x00\x01\x7f\xc3\xa9\xff"

random_bytes :: proc(r: ^Rng, n: int) -> string {
	b := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		if rng_below(r, 4) == 0 {
			b[i] = u8(rng_next(r) >> 40)
		} else {
			b[i] = GARBAGE[rng_below(r, len(GARBAGE))]
		}
	}
	return string(b)
}

// Option lines built from table names and vocabulary words.
random_config :: proc(r: ^Rng, lines: int) -> string {
	tbl := option_table()
	sb := strings.builder_make(context.temp_allocator)
	if rng_below(r, 2) == 0 {
		strings.write_string(&sb, "client\n")
	} else {
		strings.write_string(&sb, "server 10.8.0.0 255.255.255.0\n")
	}
	for _ in 0 ..< lines {
		if rng_below(r, 10) == 0 {
			// A block, sometimes broken.
			names := [?]string {
				"ca",
				"cert",
				"key",
				"tls-crypt",
				"tls-auth",
				"connection",
				"peer-fingerprint",
				"auth-user-pass",
				"nonsense",
			}
			n := names[rng_below(r, len(names))]
			strings.write_string(&sb, "<")
			strings.write_string(&sb, n)
			strings.write_string(&sb, ">\n")
			if n == "connection" {
				strings.write_string(&sb, "remote ")
				strings.write_string(&sb, VOCAB[rng_below(r, len(VOCAB))])
				strings.write_string(&sb, "\nproto ")
				strings.write_string(&sb, VOCAB[rng_below(r, len(VOCAB))])
				strings.write_string(&sb, "\n")
			} else {
				strings.write_string(&sb, "body\n")
			}
			if rng_below(r, 6) != 0 {
				strings.write_string(&sb, "</")
				strings.write_string(&sb, n)
				strings.write_string(&sb, ">\n")
			}
			continue
		}
		o := tbl[rng_below(r, len(tbl))]
		strings.write_string(&sb, o.name)
		count := o.min_args
		if o.max_args > o.min_args {
			count += rng_below(r, o.max_args - o.min_args + 1)
		} else if o.max_args < 0 {
			count += rng_below(r, 3)
		}
		if rng_below(r, 8) == 0 {
			count += rng_below(r, 3) - 1
		}
		for _ in 0 ..< max(count, 0) {
			w := VOCAB[rng_below(r, len(VOCAB))]
			if rng_below(r, 2) == 0 {
				strings.write_byte(&sb, ' ')
				strings.write_string(&sb, w)
			} else {
				strings.write_string(&sb, " \"")
				strings.write_string(&sb, w)
				strings.write_string(&sb, "\"")
			}
		}
		strings.write_byte(&sb, '\n')
	}
	return strings.to_string(sb)
}

// Checks things that must hold for any built config.
check_invariants :: proc(t: ^testing.T, cfg: ^Config, text: string, loc := #caller_location) {
	// The diagnostics point inside the text.
	for d in cfg.diags {
		testing.expectf(t, d.message != "", "empty diagnostic message", loc = loc)
		testing.expect(t, d.line >= 0, "negative line", loc = loc)
	}
	if ok(cfg) {
		switch cfg.role {
		case .Client:
			testing.expect(
				t,
				len(cfg.client.connections) > 0,
				"a clean client has a remote",
				loc = loc,
			)
			testing.expect(t, len(cfg.client.data_ciphers) > 0, "data_ciphers empty", loc = loc)
		case .Server:
			testing.expect(t, len(cfg.server.listens) > 0, "a clean server listens", loc = loc)
			testing.expect(t, len(cfg.server.data_ciphers) > 0, "data_ciphers empty", loc = loc)
			testing.expect(
				t,
				cfg.server.net.prefix >= 1 && cfg.server.net.prefix <= 29,
				"server prefix out of range",
				loc = loc,
			)
		case .None:
			testing.expect(t, false, "a clean config has a role", loc = loc)
		}
	}
	// The report works on anything.
	r := check_config(cfg)
	text2 := format_report(&r)
	testing.expect(t, len(text2) > 0, loc = loc)
	delete(text2)
	report_destroy(&r)
}

@(test)
test_fuzz_random_bytes :: proc(t: ^testing.T) {
	r := Rng{0x9E3779B97F4A7C15}
	for i in 0 ..< FUZZ_ROUNDS {
		n := rng_below(&r, 400)
		text := random_bytes(&r, n)
		cfg := build(parse_text(text, "fuzz.conf"))
		check_invariants(t, &cfg, text)
		destroy(&cfg)
		ccd := build_client_specific(parse_text(text, "fuzz.ccd"))
		destroy(&ccd)
		peers := peers_parse(text)
		peers_destroy(&peers)
		free_all(context.temp_allocator)
		_ = i
	}
}

@(test)
test_fuzz_random_options :: proc(t: ^testing.T) {
	r := Rng{0xD1B54A32D192ED03}
	clean, errors, warnings := 0, 0, 0
	for _ in 0 ..< FUZZ_ROUNDS {
		text := random_config(&r, 1 + rng_below(&r, 40))
		cfg := build(parse_text(text, "fuzz.conf"))
		check_invariants(t, &cfg, text)
		if ok(&cfg) {
			clean += 1
		}
		for d in cfg.diags {
			if d.severity == .Error {
				errors += 1
			} else {
				warnings += 1
			}
		}
		destroy(&cfg)
		ccd := build_client_specific(parse_text(text, "fuzz.ccd"))
		destroy(&ccd)
		free_all(context.temp_allocator)
	}
	log.infof(
		"random options: %d of %d configs without errors, %d errors and %d warnings in all",
		clean,
		FUZZ_ROUNDS,
		errors,
		warnings,
	)
	// The generator must reach both outcomes.
	testing.expect(t, errors > FUZZ_ROUNDS)
}

@(test)
test_fuzz_mutated_samples :: proc(t: ^testing.T) {
	samples := []string {
		CLIENT_INLINE,
		SERVER_PEERKEYS,
		LEGACY,
		CLIENT_BASE,
		SERVER_BASE,
		IOP_USERPASS_SERVER,
		IOP_TCP_V2_CLIENT,
	}
	r := Rng{0xA24BAED4963EE407}
	for _ in 0 ..< FUZZ_ROUNDS {
		src := samples[rng_below(&r, len(samples))]
		b := make([dynamic]u8, context.temp_allocator)
		append(&b, src)
		for _ in 0 ..< 1 + rng_below(&r, 6) {
			if len(b) == 0 {
				break
			}
			pos := rng_below(&r, len(b))
			switch rng_below(&r, 5) {
			case 0:
				// flip a byte
				b[pos] = u8(rng_next(&r) >> 33)
			case 1:
				// delete a range
				end := min(len(b), pos + 1 + rng_below(&r, 30))
				remove_range(&b, pos, end)
			case 2:
				// insert garbage
				g := random_bytes(&r, 1 + rng_below(&r, 8))
				inject_at(&b, pos, ..transmute([]u8)g)
			case 3:
				// duplicate a range
				end := min(len(b), pos + 1 + rng_below(&r, 60))
				chunk := make([]u8, end - pos, context.temp_allocator)
				copy(chunk, b[pos:end])
				inject_at(&b, pos, ..chunk)
			case 4:
				// cut the file short
				resize(&b, pos)
			}
		}
		text := string(b[:])
		cfg := build(parse_text(text, "fuzz.conf"))
		check_invariants(t, &cfg, text)
		destroy(&cfg)
		free_all(context.temp_allocator)
	}
}

@(test)
test_fuzz_peers_mutated :: proc(t: ^testing.T) {
	sample :=
		"alice " +
		ALICE1 +
		" ifconfig-push=10.8.0.10\nbob " +
		BOB +
		" iroute=192.168.10.0/24 disabled\ncarol " +
		CAROL +
		" ifconfig-ipv6-push=fd00::1/64 iroute-ipv6=fd00:1::/64\n"
	r := Rng{0x1234567887654321}
	for _ in 0 ..< FUZZ_ROUNDS {
		b := make([dynamic]u8, context.temp_allocator)
		append(&b, sample)
		for _ in 0 ..< 1 + rng_below(&r, 5) {
			if len(b) == 0 {
				break
			}
			pos := rng_below(&r, len(b))
			switch rng_below(&r, 3) {
			case 0:
				b[pos] = u8(rng_next(&r) >> 33)
			case 1:
				remove_range(&b, pos, min(len(b), pos + 1 + rng_below(&r, 10)))
			case 2:
				g := random_bytes(&r, 1 + rng_below(&r, 6))
				inject_at(&b, pos, ..transmute([]u8)g)
			}
		}
		p := peers_parse(string(b[:]))
		// Lookups on whatever came out.
		for e in p.entries {
			_, found := peers_lookup(&p, e.pin)
			testing.expect(t, found, "an entry must be found by its own pin")
		}
		peers_destroy(&p)
		free_all(context.temp_allocator)
	}
}

// Every option with every argument count it accepts, a few values each, in a
// client, server and client-specific file. No handler may read an argument the
// table says can be missing.
@(test)
test_every_option_every_arity :: proc(t: ^testing.T) {
	words := []string{"1", "udp", "10.8.0.0", "nonsense", "255.255.255.0", "", "-1", "fd00::/64"}
	sb := strings.builder_make()
	defer strings.builder_destroy(&sb)
	runs := 0
	for o in option_table() {
		hi := o.max_args if o.max_args >= 0 else o.min_args + 2
		hi = min(hi, 5)
		for count in max(o.min_args - 1, 0) ..= hi + 1 {
			for w, wi in words {
				strings.builder_reset(&sb)
				strings.write_string(&sb, o.name)
				for k in 0 ..< count {
					// Mix the words so that arguments differ.
					strings.write_string(&sb, " \"")
					strings.write_string(&sb, words[(wi + k * 3) % len(words)])
					strings.write_string(&sb, "\"")
				}
				strings.write_byte(&sb, '\n')
				line := strings.to_string(sb)
				for base in ([]string{CLIENT_BASE, SERVER_BASE, ""}) {
					text := strings.concatenate({base, line}, context.temp_allocator)
					cfg := build(parse_text(text, "arity.conf"))
					testing.expectf(
						t,
						!has_diag(cfg.diags, .Error, 0, "internal error"),
						"'%s': %s",
						line,
						diag_text(cfg.diags),
					)
					destroy(&cfg)
					runs += 1
				}
				ccd := build_client_specific(parse_text(line, "arity.ccd"))
				testing.expectf(
					t,
					!has_diag(ccd.diags, .Error, 0, "internal error"),
					"ccd '%s': %s",
					line,
					diag_text(ccd.diags),
				)
				destroy(&ccd)
				_ = w
			}
			free_all(context.temp_allocator)
		}
		// As an inline block.
		if .Inline in o.flags {
			text := strings.concatenate(
				{CLIENT_BASE, "<", o.name, ">\nbody\n</", o.name, ">\n"},
				context.temp_allocator,
			)
			cfg := build(parse_text(text, "inline.conf"))
			destroy(&cfg)
			text2 := strings.concatenate(
				{SERVER_BASE, "<", o.name, ">\n\n</", o.name, ">\n"},
				context.temp_allocator,
			)
			cfg2 := build(parse_text(text2, "inline.conf"))
			destroy(&cfg2)
		}
	}
	testing.expect(t, runs > 10000)
}

// Random command lines.
@(test)
test_fuzz_command_line :: proc(t: ^testing.T) {
	r := Rng{0xC0FFEE}
	tbl := option_table()
	for _ in 0 ..< FUZZ_ROUNDS {
		args := make([dynamic]string, context.temp_allocator)
		for _ in 0 ..< rng_below(&r, 12) {
			if rng_below(&r, 3) == 0 {
				append(&args, VOCAB[rng_below(&r, len(VOCAB))])
			} else {
				append(
					&args,
					strings.concatenate(
						{"--", tbl[rng_below(&r, len(tbl))].name},
						context.temp_allocator,
					),
				)
			}
		}
		cfg := build(
			parse_args(args[:], Parse_Options{loader = mem_loader, loader_data = &Mem_Files{}}),
		)
		destroy(&cfg)
		free_all(context.temp_allocator)
	}
}

// Include loops and deep chains from random file sets.
@(test)
test_fuzz_includes :: proc(t: ^testing.T) {
	r := Rng{0xBADC0DE}
	for _ in 0 ..< 500 {
		files := Mem_Files{}
		n := 1 + rng_below(&r, 6)
		names := make([]string, n, context.temp_allocator)
		for i in 0 ..< n {
			names[i] = strings.concatenate(
				{"f", string([]u8{u8('0' + i)}), ".conf"},
				context.temp_allocator,
			)
		}
		for i in 0 ..< n {
			sb := strings.builder_make(context.temp_allocator)
			for _ in 0 ..< 1 + rng_below(&r, 4) {
				if rng_below(&r, 2) == 0 {
					strings.write_string(&sb, "config ")
					strings.write_string(&sb, names[rng_below(&r, n)])
					strings.write_byte(&sb, '\n')
				} else {
					strings.write_string(&sb, "verb 3\n")
				}
			}
			files[names[i]] = strings.to_string(sb)
		}
		p := parse_file(
			names[0],
			Parse_Options{loader = mem_loader, loader_data = &files, max_files = 40},
		)
		testing.expect(t, len(p.directives) <= 40 * 5 + 10)
		parsed_destroy(&p)
		delete(files)
		free_all(context.temp_allocator)
	}
}

// A valid base plus a few lines from the supported options only, so that many
// results get past the checks and reach the final validation.
@(test)
test_fuzz_supported_options_on_valid_base :: proc(t: ^testing.T) {
	supported: [dynamic]^Option
	defer delete(supported)
	for &o in option_table() {
		if (o.disp == .Supported || o.disp == .New) && .Push_Only not_in o.flags {
			append(&supported, &o)
		}
	}
	r := Rng{0x51F15E}
	clean := 0
	for _ in 0 ..< FUZZ_ROUNDS {
		sb := strings.builder_make(context.temp_allocator)
		base := CLIENT_BASE if rng_below(&r, 2) == 0 else SERVER_BASE
		strings.write_string(&sb, base)
		for _ in 0 ..< 1 + rng_below(&r, 4) {
			o := supported[rng_below(&r, len(supported))]
			strings.write_string(&sb, o.name)
			count := o.min_args
			if o.max_args > o.min_args {
				count += rng_below(&r, o.max_args - o.min_args + 1)
			} else if o.max_args < 0 {
				count += rng_below(&r, 3)
			}
			for _ in 0 ..< count {
				strings.write_byte(&sb, ' ')
				w := VOCAB[rng_below(&r, len(VOCAB))]
				strings.write_string(
					&sb,
					w if w != "" && !strings.contains_any(w, " \"'\\#;\t") else "1",
				)
			}
			strings.write_byte(&sb, '\n')
		}
		text := strings.to_string(sb)
		cfg := build(parse_text(text, "fuzz.conf"))
		check_invariants(t, &cfg, text)
		if ok(&cfg) {
			clean += 1
		}
		destroy(&cfg)
		free_all(context.temp_allocator)
	}
	log.infof(
		"supported options on a valid base: %d of %d configs without errors",
		clean,
		FUZZ_ROUNDS,
	)
	testing.expect(
		t,
		clean > 100,
		"too few clean configs: the generator is not reaching the checks",
	)
}
