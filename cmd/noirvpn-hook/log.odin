// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:runtime"
import "core:fmt"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:time"

// Log lines go to stderr: `2026-11-09T03:25:24Z NOTE  text`. `--verb` sets the
// amount shown:
//
//   0  errors
//   1  + warnings and notes: start, stop, a daemon restart, a gap in the events,
//        a dropped event, a command that failed or ran out of time
//   2  + every command that ran, with its exit status
//   3  + the commands started
//   4  + every event received
Level :: enum u8 {
	Error,
	Warn,
	Notice,
	Info,
	Verbose,
	Debug,
}

@(private = "file")
LEVEL_VERB := [Level]int {
	.Error   = 0,
	.Warn    = 1,
	.Notice  = 1,
	.Info    = 2,
	.Verbose = 3,
	.Debug   = 4,
}

@(private = "file")
LEVEL_TAG := [Level]string {
	.Error   = "ERROR",
	.Warn    = "WARN ",
	.Notice  = "NOTE ",
	.Info    = "INFO ",
	.Verbose = "VERB ",
	.Debug   = "DEBUG",
}

// Safe to use from several threads. A test sets `capture` to read the lines.
Logger :: struct {
	verb:    int,
	mu:      sync.Mutex,
	capture: ^[dynamic]string,
	// Allocates the copies in `capture` (the caller's, so any thread can log).
	alloc:   runtime.Allocator,
}

log_enabled :: proc(l: ^Logger, level: Level) -> bool {
	return LEVEL_VERB[level] <= l.verb
}

logf :: proc(l: ^Logger, level: Level, format: string, args: ..any) {
	if l == nil || !log_enabled(l, level) {
		return
	}
	buf: [2048]u8
	t := time.now()
	y, mo, d := time.date(t)
	h, mi, s := time.clock(t)
	head := fmt.bprintf(buf[:], "%04d-%02d-%02dT%02d:%02d:%02dZ %s ", y, int(mo), d, h, mi, s, LEVEL_TAG[level])
	n := len(head)
	body := fmt.bprintf(buf[n:len(buf) - 1], format, ..args)
	n += len(body)
	buf[n] = '\n'
	n += 1
	sync.mutex_lock(&l.mu)
	defer sync.mutex_unlock(&l.mu)
	if l.capture != nil {
		append(l.capture, strings.clone(string(buf[:n - 1]), l.alloc))
		return
	}
	_, _ = linux.write(2, buf[:n])
}
