// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Benchmark for package ossl: data-channel AEAD and TLS 1.3 handshakes. Shows
// which crypto backend is faster; runs with either (-define:NOIR_CRYPTO=openssl|awslc).
//
//	odin run proto/ossl/bench -collection:noir=. -o:speed
//	odin run proto/ossl/bench -collection:noir=. -o:speed -- -hs -threads=1,4
//
// Options (after `--`; by default everything runs):
//
//	-aead            AEAD seal and open, 1 thread, 3 ciphers, 3 packet sizes
//	-aead-threads    same at 1400 bytes with 4 threads (own context each, and one
//	                 shared context on AWS-LC)
//	-hs              TLS 1.3 handshakes per second (client and server in memory,
//	                 same thread)
//	-threads=1,4     thread counts for -hs and -aead-threads
//	-reps=3          repeat each measurement. Handshakes: median. AEAD: best (the
//	                 fastest run has the least noise)
//	-time=300        milliseconds per AEAD measurement
//	-hs-time=1500    milliseconds per handshake measurement
//
// Handshake runs use pinned mode (no chain check) with a certificate on both
// sides, like the VPN. A "handshake" is one client + server pair. "server us" is
// CPU time in the server's calls only. Every thread has its own sessions. TLS
// context sharing: "shared" (one Tls_Ctx for all threads) or "per-thread".
package ossl_bench

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "noir:proto/ossl"

Options :: struct {
	aead, aead_threads, hs: bool,
	threads:                []int,
	reps:                   int,
	aead_time, hs_time:     time.Duration,
}

DEFAULT_THREADS := [?]int{1, 4}

parse_options :: proc() -> (o: Options) {
	o.threads = DEFAULT_THREADS[:]
	o.reps = 3
	o.aead_time = 300 * time.Millisecond
	o.hs_time = 1500 * time.Millisecond
	any_selected := false
	for arg in os.args[1:] {
		switch {
		case arg == "-aead":
			o.aead, any_selected = true, true
		case arg == "-aead-threads":
			o.aead_threads, any_selected = true, true
		case arg == "-hs":
			o.hs, any_selected = true, true
		case strings.has_prefix(arg, "-threads="):
			list := make([dynamic]int)
			for part in strings.split(arg[len("-threads="):], ",", context.temp_allocator) {
				n, ok := strconv.parse_int(part)
				if ok && n > 0 {
					append(&list, n)
				}
			}
			o.threads = list[:]
		case strings.has_prefix(arg, "-reps="):
			o.reps = max(1, strconv.parse_int(arg[len("-reps="):]) or_else 3)
		case strings.has_prefix(arg, "-time="):
			o.aead_time = time.Duration(strconv.parse_int(arg[len("-time="):]) or_else 300) * time.Millisecond
		case strings.has_prefix(arg, "-hs-time="):
			o.hs_time = time.Duration(strconv.parse_int(arg[len("-hs-time="):]) or_else 1500) * time.Millisecond
		case:
			fmt.eprintfln("unknown option %q (see the comment at the top of main.odin)", arg)
			os.exit(2)
		}
	}
	if !any_selected {
		o.aead, o.aead_threads, o.hs = true, true, true
	}
	return
}

// --- AEAD ---

BATCH :: 1000
SIZES :: [?]int{64, 512, 1400}

Result :: struct {
	packets: u64,
	elapsed: time.Duration,
}

Ctx :: struct {
	seal, open:  ^ossl.Aead,
	pt, ct, out: []u8,
	aad:         [8]u8,
	tag:         [ossl.AEAD_TAG_LEN]u8,
}

nonce_for :: proc(counter: u64, thread_id: u64 = 0) -> (nonce: [ossl.AEAD_NONCE_LEN]u8) {
	(^u32)(&nonce[0])^ = u32(thread_id)
	(^u64)(&nonce[4])^ = counter
	return
}

seal_step :: proc(c: ^Ctx, counter: u64) -> bool {
	nonce := nonce_for(counter)
	return ossl.aead_seal(c.seal, nonce[:], c.aad[:], c.pt, c.ct, c.tag[:])
}

open_step :: proc(c: ^Ctx, counter: u64) -> bool {
	// Opens the same packet every time: only the call cost matters here.
	nonce := nonce_for(0)
	return ossl.aead_open(c.open, nonce[:], c.aad[:], c.ct, c.tag[:], c.out)
}

// Runs `step` in batches until `duration` has passed.
run :: proc(step: proc(ctx: ^Ctx, counter: u64) -> bool, ctx: ^Ctx, duration: time.Duration) -> Result {
	for i in 0 ..< u64(BATCH) { 	// warm up
		step(ctx, i)
	}
	start := time.tick_now()
	n: u64
	for time.tick_since(start) < duration {
		for _ in 0 ..< BATCH {
			if !step(ctx, n) {
				fmt.eprintln("operation failed")
				return {}
			}
			n += 1
		}
	}
	return {n, time.tick_since(start)}
}

// The best of `reps` runs.
best :: proc(step: proc(ctx: ^Ctx, counter: u64) -> bool, ctx: ^Ctx, o: Options) -> (best: Result) {
	best_pps: f64
	for _ in 0 ..< o.reps {
		r := run(step, ctx, o.aead_time)
		if pps := f64(r.packets) / time.duration_seconds(r.elapsed); pps > best_pps {
			best, best_pps = r, pps
		}
	}
	return
}

report :: proc(cipher, label: string, size: int, r: Result, extra := "") {
	secs := time.duration_seconds(r.elapsed)
	pps := f64(r.packets) / secs
	// Odin pads numbers with zeros when given a width, so no widths here.
	fmt.printf(
		"aead\t%s\t%s\t%d B\t%.1f ns/pkt\t%.3f Mpps\t%.2f Gbit/s%s\n",
		cipher,
		label,
		size,
		1e9 / pps,
		pps / 1e6,
		pps * f64(size) * 8 / 1e9,
		extra,
	)
}

make_key :: proc(cipher: ossl.Aead_Cipher) -> []u8 {
	key := make([]u8, ossl.aead_key_len(cipher))
	for &b, i in key {
		b = u8(i + 1)
	}
	return key
}

bench_aead :: proc(o: Options) {
	for cipher in ossl.Aead_Cipher {
		key := make_key(cipher)
		defer delete(key)
		for size in SIZES {
			seal, open: ossl.Aead
			assert(ossl.aead_init(&seal, cipher, key, .Seal) == .None)
			assert(ossl.aead_init(&open, cipher, key, .Open) == .None)
			c := Ctx {
				seal = &seal,
				open = &open,
				pt   = make([]u8, size),
				ct   = make([]u8, size),
				out  = make([]u8, size),
			}
			for &b, i in c.pt {
				b = u8(i)
			}
			name := ossl.aead_cipher_name(cipher)
			report(name, "seal", size, best(seal_step, &c, o))
			// Generate one valid packet for nonce 0, then time opening it.
			seal_step(&c, 0)
			report(name, "open", size, best(open_step, &c, o))
			ossl.aead_destroy(&seal)
			ossl.aead_destroy(&open)
			delete(c.pt)
			delete(c.ct)
			delete(c.out)
		}
	}
}

// --- AEAD with several threads ---

Aead_Worker :: struct {
	id:       u64,
	seal:     ^ossl.Aead,
	open:     ^ossl.Aead,
	size:     int,
	duration: time.Duration,
	go:       ^bool,
	packets:  u64, // seal calls plus open calls
	elapsed:  time.Duration,
}

aead_worker :: proc(w: ^Aead_Worker) {
	pt, ct, out := make([]u8, w.size), make([]u8, w.size), make([]u8, w.size)
	defer {
		delete(pt)
		delete(ct)
		delete(out)
	}
	aad: [8]u8
	tag: [ossl.AEAD_TAG_LEN]u8
	for !sync.atomic_load_explicit(w.go, .Acquire) {
		sync.cpu_relax()
	}
	start := time.tick_now()
	n: u64
	for time.tick_since(start) < w.duration {
		for _ in 0 ..< BATCH {
			nonce := nonce_for(n, w.id)
			ok := ossl.aead_seal(w.seal, nonce[:], aad[:], pt, ct, tag[:])
			ok = ok && ossl.aead_open(w.open, nonce[:], aad[:], ct, tag[:], out)
			if !ok {
				fmt.eprintln("operation failed")
				return
			}
			n += 1
		}
	}
	w.packets = n * 2
	w.elapsed = time.tick_since(start)
}

// Runs `count` threads that each seal and then open 1400-byte packets.
// `shared` = all threads use one Aead pair (only safe on AWS-LC).
run_aead_threads :: proc(cipher: ossl.Aead_Cipher, count: int, shared: bool, duration: time.Duration) -> f64 {
	key := make_key(cipher)
	defer delete(key)
	workers := make([]Aead_Worker, count)
	defer delete(workers)
	seals := make([]ossl.Aead, count)
	opens := make([]ossl.Aead, count)
	defer delete(seals)
	defer delete(opens)
	go := false
	for i in 0 ..< count {
		j := 0 if shared else i
		if i == 0 || !shared {
			assert(ossl.aead_init(&seals[j], cipher, key, .Seal) == .None)
			assert(ossl.aead_init(&opens[j], cipher, key, .Open) == .None)
		}
		workers[i] = {
			id       = u64(i),
			seal     = &seals[j],
			open     = &opens[j],
			size     = 1400,
			duration = duration,
			go       = &go,
		}
	}
	threads := make([]^thread.Thread, count)
	defer delete(threads)
	for i in 0 ..< count {
		threads[i] = thread.create_and_start_with_poly_data(&workers[i], aead_worker)
	}
	sync.atomic_store_explicit(&go, true, .Release)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	for i in 0 ..< count {
		if !shared || i == 0 {
			ossl.aead_destroy(&seals[i])
			ossl.aead_destroy(&opens[i])
		}
	}
	total_pps: f64
	for w in workers {
		total_pps += f64(w.packets) / time.duration_seconds(w.elapsed)
	}
	return total_pps
}

bench_aead_threads :: proc(o: Options) {
	for cipher in ossl.Aead_Cipher {
		name := ossl.aead_cipher_name(cipher)
		for count in o.threads {
			// Seal and open together, so one "packet" is a seal plus an open.
			pps: f64
			for _ in 0 ..< o.reps {
				pps = max(pps, run_aead_threads(cipher, count, false, o.aead_time))
			}
			fmt.printf(
				"aead-mt\t%s\t%d threads, own context\t1400 B\t%.3f Mpps (seal+open calls)\t%.2f Gbit/s\n",
				name,
				count,
				pps / 1e6,
				pps / 2 * 1400 * 8 / 1e9,
			)
			if ossl.NOIR_CRYPTO == "awslc" {
				pps = 0
				for _ in 0 ..< o.reps {
					pps = max(pps, run_aead_threads(cipher, count, true, o.aead_time))
				}
				fmt.printf(
					"aead-mt\t%s\t%d threads, shared context\t1400 B\t%.3f Mpps (seal+open calls)\t%.2f Gbit/s\n",
					name,
					count,
					pps / 1e6,
					pps / 2 * 1400 * 8 / 1e9,
				)
			}
		}
	}
}

// --- handshakes ---

Identity :: struct {
	cert, key: []u8,
}

ED_SERVER := Identity{#load("../testdata/ed25519_server.crt.pem"), #load("../testdata/ed25519_server.key.pem")}
ED_CLIENT := Identity{#load("../testdata/ed25519_client.crt.pem"), #load("../testdata/ed25519_client.key.pem")}
MLDSA_SERVER := Identity{#load("../testdata/mldsa65_server.crt.pem"), #load("../testdata/mldsa65_server.key.pem")}
MLDSA_CLIENT := Identity{#load("../testdata/mldsa65_client.crt.pem"), #load("../testdata/mldsa65_client.key.pem")}

Hs_Case :: struct {
	name:             string,
	client, server:   Identity,
	groups:           string,
}

CASES := [?]Hs_Case {
	{"Ed25519 + X25519", ED_CLIENT, ED_SERVER, "X25519"},
	{"Ed25519 + X25519MLKEM768", ED_CLIENT, ED_SERVER, "X25519MLKEM768"},
	{"ML-DSA-65 + X25519MLKEM768", MLDSA_CLIENT, MLDSA_SERVER, "X25519MLKEM768"},
}

make_ctx :: proc(role: ossl.Tls_Role, id: Identity, groups: string) -> ossl.Tls_Ctx {
	ctx, err := ossl.tls_ctx_create({
		role        = role,
		cert_pem    = id.cert,
		key_pem     = id.key,
		groups      = groups,
		min_version = .TLS_1_3,
		verify      = .Pinned,
		pin_check   = accept_any_key,
	})
	if err != .None {
		fmt.eprintfln("cannot create TLS context: %v", err)
		os.exit(1)
	}
	return ctx
}

Hs_Worker :: struct {
	cctx, sctx:            ^ossl.Tls_Ctx,
	go, stop:              ^bool,
	// Results.
	count:                 u64,
	failures:              u64,
	client_ns, server_ns:  i64,
	elapsed:               time.Duration,
}

hs_worker :: proc(w: ^Hs_Worker) {
	for !sync.atomic_load_explicit(w.go, .Acquire) {
		sync.cpu_relax()
	}
	start := time.tick_now()
	for !sync.atomic_load_explicit(w.stop, .Acquire) {
		c, e1 := ossl.tls_session_create(w.cctx)
		s, e2 := ossl.tls_session_create(w.sctx)
		if e1 != .None || e2 != .None {
			w.failures += 1
			break
		}
		cs, ss := ossl.Handshake_Status.Want_More, ossl.Handshake_Status.Want_More
		for _ in 0 ..< 8 {
			t0 := time.tick_now()
			if cs == .Want_More {
				cs = ossl.tls_handshake_step(&c)
			}
			t1 := time.tick_now()
			ossl.tls_move(&c, &s)
			t2 := time.tick_now()
			if ss == .Want_More {
				ss = ossl.tls_handshake_step(&s)
			}
			t3 := time.tick_now()
			ossl.tls_move(&s, &c)
			w.client_ns += i64(time.tick_diff(t0, t1))
			w.server_ns += i64(time.tick_diff(t2, t3))
			if cs != .Want_More && ss != .Want_More {
				break
			}
		}
		if cs != .Done || ss != .Done {
			w.failures += 1
		}
		ossl.tls_session_destroy(&c)
		ossl.tls_session_destroy(&s)
		w.count += 1
	}
	w.elapsed = time.tick_since(start)
}

Hs_Result :: struct {
	per_sec:   f64, // complete handshakes per second, summed over threads
	server_us: f64, // CPU time in the server's calls per handshake
	client_us: f64,
}

run_handshakes :: proc(hc: Hs_Case, threads: int, shared: bool, duration: time.Duration) -> Hs_Result {
	// Contexts are created before the clock starts.
	cctxs := make([]ossl.Tls_Ctx, threads if !shared else 1)
	sctxs := make([]ossl.Tls_Ctx, threads if !shared else 1)
	defer delete(cctxs)
	defer delete(sctxs)
	for i in 0 ..< len(cctxs) {
		cctxs[i] = make_ctx(.Client, hc.client, hc.groups)
		sctxs[i] = make_ctx(.Server, hc.server, hc.groups)
	}
	go, stop := false, false
	workers := make([]Hs_Worker, threads)
	defer delete(workers)
	ths := make([]^thread.Thread, threads)
	defer delete(ths)
	for i in 0 ..< threads {
		k := 0 if shared else i
		workers[i] = {
			cctx = &cctxs[k],
			sctx = &sctxs[k],
			go   = &go,
			stop = &stop,
		}
		ths[i] = thread.create_and_start_with_poly_data(&workers[i], hs_worker)
	}
	sync.atomic_store_explicit(&go, true, .Release)
	time.sleep(duration)
	sync.atomic_store_explicit(&stop, true, .Release)
	for th in ths {
		thread.join(th)
		thread.destroy(th)
	}
	for i in 0 ..< len(cctxs) {
		ossl.tls_ctx_destroy(&cctxs[i])
		ossl.tls_ctx_destroy(&sctxs[i])
	}

	r: Hs_Result
	total, cns, sns: u64
	for w in workers {
		if w.failures > 0 {
			fmt.eprintfln("handshake failures in %s (%d threads): %d", hc.name, threads, w.failures)
			os.exit(1)
		}
		r.per_sec += f64(w.count) / time.duration_seconds(w.elapsed)
		total += w.count
		cns += u64(w.client_ns)
		sns += u64(w.server_ns)
	}
	if total > 0 {
		r.server_us = f64(sns) / f64(total) / 1e3
		r.client_us = f64(cns) / f64(total) / 1e3
	}
	return r
}

median :: proc(rs: []Hs_Result) -> Hs_Result {
	slice.sort_by(rs, proc(a, b: Hs_Result) -> bool {return a.per_sec < b.per_sec})
	return rs[len(rs) / 2]
}

bench_handshakes :: proc(o: Options) {
	for hc in CASES {
		for threads in o.threads {
			for shared in ([]bool{true, false}) {
				if threads == 1 && !shared {
					continue // one thread: the two modes are the same
				}
				run_handshakes(hc, threads, shared, 200 * time.Millisecond) // warm up
				results := make([]Hs_Result, o.reps)
				defer delete(results)
				for &r in results {
					r = run_handshakes(hc, threads, shared, o.hs_time)
				}
				r := median(results)
				mode := "shared ctx" if shared else "per-thread ctx"
				if threads == 1 {
					mode = "-"
				}
				fmt.printf(
					"hs\t%s\t%d thr\t%s\t%.0f hs/s\tserver %.0f us\tclient %.0f us\t(min %.0f, max %.0f)\n",
					hc.name,
					threads,
					mode,
					r.per_sec,
					r.server_us,
					r.client_us,
					results[0].per_sec,
					results[len(results) - 1].per_sec,
				)
			}
		}
	}
}

main :: proc() {
	o := parse_options()
	fmt.printfln("backend: %s", ossl.backend_version())
	if o.aead {
		bench_aead(o)
	}
	if o.aead_threads {
		bench_aead_threads(o)
	}
	if o.hs {
		bench_handshakes(o)
	}
}

// The bench measures handshakes: accept every key.
accept_any_key :: proc "contextless" (peer: ossl.Peer_Key, user: rawptr) -> bool {
	return true
}
