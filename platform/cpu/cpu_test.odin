// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
#+build amd64
package cpu

import "core:os"
import "core:strings"
import "core:testing"

// A test binary of a v3 build runs only on a CPU with v3, so the check must
// agree. On any build, the check agrees with the flags that the kernel lists.
@(test)
test_has_v3_agrees_with_the_kernel :: proc(t: ^testing.T) {
	if NEEDS_V3 {
		testing.expect(t, has_v3())
	}
	data, err := os.read_entire_file("/proc/cpuinfo", context.temp_allocator)
	if err != nil {
		return
	}
	text := string(data)
	i := strings.index(text, "\nflags")
	if i < 0 {
		return
	}
	line := text[i + 1:]
	if j := strings.index_byte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	want := true
	for f in ([]string{" avx ", " avx2 ", " bmi1 ", " bmi2 ", " f16c ", " fma ", " abm ", " movbe "}) {
		want &&= strings.contains(strings.concatenate({line, " "}, context.temp_allocator), f)
	}
	testing.expect_value(t, has_v3(), want)
}
