// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:time"

// Log lines go to the log sink: `2026-11-09T03:25:24Z NOTE  text`. The host sets
// it with `log_set_sink` (the daemon writes each line to stderr); with no sink
// nothing is written. Sink and level are process-wide (one engine per process).
// The `verb` option sets how much is shown:
//
//	0  errors, and the status line when asked for
//	1  + warnings and the main events (connect, disconnect, reconnect)
//	2  + rekeys, pushed settings, what was applied
//	3  + every network step and plan note
//	4  + every session event
//
// Passwords and auth-tokens are never given to these procs.
Level :: enum u8 {
	Status, // a status line asked for with SIGUSR2: shown at any verb
	Error,
	Warn,
	Notice,
	Info,
	Verbose,
	Debug,
}

@(private = "file")
LEVEL_VERB := [Level]int {
	.Status  = 0,
	.Error   = 0,
	.Warn    = 1,
	.Notice  = 1,
	.Info    = 2,
	.Verbose = 3,
	.Debug   = 4,
}

@(private = "file")
LEVEL_TAG := [Level]string {
	.Status  = "STAT ",
	.Error   = "ERROR",
	.Warn    = "WARN ",
	.Notice  = "NOTE ",
	.Info    = "INFO ",
	.Verbose = "VERB ",
	.Debug   = "DEBUG",
}

// Writes one finished line, with its newline.
Log_Sink :: proc(line: []u8)

@(private = "file")
g_verb := 1

@(private = "file")
g_sink: Log_Sink

log_set_sink :: proc "contextless" (sink: Log_Sink) {
	g_sink = sink
}

log_set_verb :: proc(verb: int) {
	g_verb = verb
}

log_get_verb :: proc() -> int {
	return g_verb
}

log_enabled :: proc(level: Level) -> bool {
	return LEVEL_VERB[level] <= g_verb
}

logf :: proc(level: Level, format: string, args: ..any) {
	if !log_enabled(level) {
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
	if g_sink != nil {
		g_sink(buf[:n])
	}
}
