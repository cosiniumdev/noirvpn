// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
#+build amd64
package cpu

import "base:intrinsics"
import "core:sys/linux"

// True: the build uses the instructions of x86-64-v3.
NEEDS_V3 :: intrinsics.has_target_feature("avx2")

when NEEDS_V3 {
	// The C library calls the procedures of this section before the entry
	// code of the program.
	@(export, link_name = "noirvpn_cpu_check", link_section = ".init_array")
	start_check := check
}

// Does this CPU, with this operating system, run AVX, AVX2, BMI1, BMI2, F16C,
// FMA, LZCNT and MOVBE?
has_v3 :: proc "contextless" () -> bool {
	max_leaf, _, _, _ := intrinsics.x86_cpuid(0, 0)
	if max_leaf < 7 {
		return false
	}
	FMA :: 1 << 12
	MOVBE :: 1 << 22
	OSXSAVE :: 1 << 27
	AVX :: 1 << 28
	F16C :: 1 << 29
	LEAF1 :: FMA | MOVBE | OSXSAVE | AVX | F16C
	_, _, ecx, _ := intrinsics.x86_cpuid(1, 0)
	if ecx & LEAF1 != LEAF1 {
		return false
	}
	// The operating system keeps the XMM and YMM registers of a thread.
	if xcr0, _ := intrinsics.x86_xgetbv(0); xcr0 & 6 != 6 {
		return false
	}
	BMI1 :: 1 << 3
	AVX2 :: 1 << 5
	BMI2 :: 1 << 8
	LEAF7 :: BMI1 | AVX2 | BMI2
	_, ebx, _, _ := intrinsics.x86_cpuid(7, 0)
	if ebx & LEAF7 != LEAF7 {
		return false
	}
	LZCNT :: 1 << 5
	_, _, ecx, _ = intrinsics.x86_cpuid(0x8000_0001, 0)
	return ecx & LZCNT != 0
}

// Only system calls, with no procedure of a library between them: a library
// procedure of this build can have an instruction that the CPU does not run.
@(private)
check :: proc "c" () {
	if has_v3() {
		return
	}
	msg := "This program needs a CPU with the x86-64-v3 instructions (AVX2, BMI2, FMA), and this CPU does not have them. A build with NOIR_MICROARCH=x86-64-v2 runs on it.\n"
	intrinsics.syscall(linux.SYS_write, 2, uintptr(raw_data(msg)), uintptr(len(msg)))
	intrinsics.syscall(linux.SYS_exit_group, 1)
}
