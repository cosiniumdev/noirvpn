// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Benchmark for package crypt: seal and open of whole P_DATA_V2 packets. One
// thread, both formats, all three ciphers, two payload sizes.
//
//	odin run proto/crypt/bench -collection:noir=. -o:speed
//	odin run proto/crypt/bench -collection:noir=. -o:speed -- -time=500 -reps=5
//	build/musl.sh proto/crypt/bench crypt_bench && build/run-musl.sh crypt_bench
//	NOIR_CRYPTO=awslc build/musl.sh proto/crypt/bench crypt_bench_awslc -define:NOIR_CRYPTO=awslc
//
// Options (after `--`):
//
//	-time=300   milliseconds per measurement
//	-reps=3     repeat each measurement and report the best (least noise)
//	-sizes=64,1400   payload sizes in bytes
//
// - "seal" = `tx_seal`: packet id, header, AEAD, usage counters.
// - "open" = `rx_open`: header checks, AEAD, replay window, usage counters. Each
//   open is of a different genuine packet (a batch is sealed first, its replay
//   window reset between rounds), so the replay check does real work.
// - Sizes are the payload (tunnel packet). Wire packet: +24 bytes (baseline), +28
//   (epoch).
//
// Both formats of one cipher and size run in turns (baseline, epoch, baseline,
// ...), each keeping its best round, so machine load changes move both. Epoch rows
// end with the difference to the baseline row.
package crypt_bench

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import "noir:proto/crypt"
import "noir:proto/keys"
import "noir:proto/ossl"

BATCH :: 1024
DEFAULT_SIZES := [?]int{64, 1400}

Options :: struct {
	duration: time.Duration,
	reps:     int,
	sizes:    []int,
}

parse_options :: proc() -> (o: Options) {
	o.duration = 300 * time.Millisecond
	o.reps = 3
	o.sizes = DEFAULT_SIZES[:]
	for arg in os.args[1:] {
		switch {
		case strings.has_prefix(arg, "-time="):
			o.duration = time.Duration(strconv.parse_int(arg[len("-time="):]) or_else 300) * time.Millisecond
		case strings.has_prefix(arg, "-reps="):
			o.reps = max(1, strconv.parse_int(arg[len("-reps="):]) or_else 3)
		case strings.has_prefix(arg, "-sizes="):
			list := make([dynamic]int)
			for part in strings.split(arg[len("-sizes="):], ",", context.temp_allocator) {
				n, ok := strconv.parse_int(part)
				if ok && n > 0 {
					append(&list, n)
				}
			}
			o.sizes = list[:]
		case:
			fmt.eprintfln("unknown option %q (see the comment at the top of main.odin)", arg)
			os.exit(2)
		}
	}
	return
}

// Everything one measurement needs.
Rig :: struct {
	client, server: crypt.Data_Key,
	format:         keys.Format,
	size:           int,
	plain:          []u8,
	out:            []u8, // sealed packet
	plain_out:      []u8, // opened payload
	packets:        [BATCH][]u8, // genuine packets for the open test
}

rig_init :: proc(r: ^Rig, format: keys.Format, cipher: ossl.Aead_Cipher, size: int) -> bool {
	r.format = format
	r.size = size
	export: [keys.EXPORT_LEN]u8
	for &b, i in export {
		b = u8(i * 13 + 1)
	}
	cm, e1 := keys.derive_material(export[:], .Client, cipher)
	sm, e2 := keys.derive_material(export[:], .Server, cipher)
	if e1 != .None || e2 != .None {
		return false
	}
	defer keys.material_wipe(&cm)
	defer keys.material_wipe(&sm)
	if crypt.data_key_init(&r.client, format, cipher, 0, &cm) != .None {
		return false
	}
	if crypt.data_key_init(&r.server, format, cipher, 0, &sm) != .None {
		return false
	}
	overhead := crypt.packet_overhead(format)
	r.plain = make([]u8, size)
	for &b, i in r.plain {
		b = u8(i)
	}
	r.plain[0] = 0x45
	r.out = make([]u8, size + overhead)
	r.plain_out = make([]u8, size)
	for i in 0 ..< BATCH {
		r.packets[i] = make([]u8, size + overhead)
		n, err := crypt.tx_seal(&r.client.tx, 1, r.plain, r.packets[i])
		if err != .None || n != size + overhead {
			return false
		}
	}
	return true
}

rig_destroy :: proc(r: ^Rig) {
	crypt.data_key_destroy(&r.client)
	crypt.data_key_destroy(&r.server)
	delete(r.plain)
	delete(r.out)
	delete(r.plain_out)
	for p in r.packets {
		delete(p)
	}
}

// Forget the receive side's replay window and counters, so the batch can be
// opened again.
rx_rewind :: proc(rx: ^crypt.Rx_Key) {
	size: int
	st: ^crypt.Rx_State
	switch &b in rx.body {
	case crypt.Baseline_Rx:
		st = &b.st
	case crypt.Epoch_Rx:
		st = &b.slot[b.chain.current].st
	}
	size = crypt.replay_size(&st.replay)
	st^ = {}
	crypt.replay_init(&st.replay, size)
}

seal_round :: proc(r: ^Rig) -> bool {
	for _ in 0 ..< BATCH {
		_, err := crypt.tx_seal(&r.client.tx, 1, r.plain, r.out)
		if err != .None {
			return false
		}
	}
	return true
}

open_round :: proc(r: ^Rig) -> bool {
	rx_rewind(&r.server.rx)
	for i in 0 ..< BATCH {
		_, err := crypt.rx_open(&r.server.rx, r.packets[i], r.plain_out)
		if err != .None {
			return false
		}
	}
	return true
}

// Rounds of BATCH packets until `duration` has passed. Returns ns per packet.
measure_once :: proc(round: proc(r: ^Rig) -> bool, r: ^Rig, duration: time.Duration) -> (ns_per_packet: f64, ok: bool) {
	start := time.tick_now()
	packets: u64
	for time.tick_since(start) < duration {
		round(r) or_return
		packets += BATCH
	}
	return f64(time.duration_nanoseconds(time.tick_since(start))) / f64(packets), true
}

// The best of `o.reps` measurements of each rig, taken in turns.
measure_turns :: proc(round: proc(r: ^Rig) -> bool, rigs: []^Rig, o: Options) -> (best: [2]f64, ok: bool) {
	best = {max(f64), max(f64)}
	for r in rigs {
		round(r) or_return // warm up
	}
	for _ in 0 ..< o.reps {
		for r, i in rigs {
			ns := measure_once(round, r, o.duration) or_return
			best[i] = min(best[i], ns)
		}
	}
	return best, true
}

main :: proc() {
	o := parse_options()
	fmt.printfln("backend: %s %s", ossl.NOIR_CRYPTO, ossl.backend_version())
	fmt.println("format\tcipher\tpayload\tseal ns\tseal Gbit/s\topen ns\topen Gbit/s\tseal vs baseline\topen vs baseline")
	for cipher in ossl.Aead_Cipher {
		for size in o.sizes {
			rigs: [2]Rig
			for format, i in keys.Format {
				if !rig_init(&rigs[i], format, cipher, size) {
					fmt.eprintln("setup failed")
					os.exit(1)
				}
			}
			ptrs := [2]^Rig{&rigs[0], &rigs[1]}
			seal_ns, ok1 := measure_turns(seal_round, ptrs[:], o)
			open_ns, ok2 := measure_turns(open_round, ptrs[:], o)
			if !ok1 || !ok2 {
				fmt.eprintln("operation failed")
				os.exit(1)
			}
			gbit :: proc(ns: f64, size: int) -> f64 {
				return f64(size) * 8 / ns // bits per ns = Gbit/s
			}
			for format, i in keys.Format {
				diff_seal, diff_open := "", ""
				if format == .Epoch {
					diff_seal = fmt.tprintf("%+.1f%%", (seal_ns[i] / seal_ns[0] - 1) * 100)
					diff_open = fmt.tprintf("%+.1f%%", (open_ns[i] / open_ns[0] - 1) * 100)
				}
				fmt.printfln(
					"%v\t%s\t%d B\t%.1f\t%.2f\t%.1f\t%.2f\t%s\t%s",
					format,
					ossl.aead_cipher_name(cipher),
					size,
					seal_ns[i],
					gbit(seal_ns[i], size),
					open_ns[i],
					gbit(open_ns[i], size),
					diff_seal,
					diff_open,
				)
			}
			for &r in rigs {
				rig_destroy(&r)
			}
		}
	}
}
