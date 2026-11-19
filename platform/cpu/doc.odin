// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package cpu stops a program at its start, with a message, on a CPU that
// cannot run the build. A program imports it for that effect only:
//
//	import _ "noir:platform/cpu"
//
// An amd64 build uses the instructions of x86-64-v3 (AVX2, BMI2, FMA) in all
// of its code by default; see build/microarch.sh. A CPU without them stops
// the program with "Illegal instruction" in the entry code, before `main`.
//
//	loader --> start check (Linux) --> entry code --> main
//	             |
//	             +--> message on standard error, exit code 1
//
// Linux only. On Windows and macOS the program stops in the entry code with
// no message.
package cpu
