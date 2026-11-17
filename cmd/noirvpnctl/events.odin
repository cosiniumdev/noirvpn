// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:runtime"
import "core:strings"
import "core:time"
import "noir:bus"

// How often the loop looks at the stop flag while no event comes.
EVENT_POLL :: 200 * time.Millisecond

// `events`: print one line per event until a signal, `--count` events, or an
// error. The subscriber reconnects by itself when the daemon restarts; a
// restart or a gap in the sequence shows as a note on stderr.
run_events :: proc(c: ^Command, t: Target, io: ^Io, stop: ^Stop) -> Exit {
	sub, err := bus.subscribe(t.events, c.prefixes[:], c.wait)
	if err != .None {
		switch err {
		case .Daemon_Not_Running:
			err_line(io, "there is no events socket at %s (the daemon is not running, or bus-events is turned off); use --wait to wait for it", t.events)
		case .Permission_Denied:
			err_line(io, "permission denied on %s (%s)", t.events, ACCESS_HINT)
		case .Not_Service:
			err_line(io, "%s does not belong to the service because another user created it, so nothing was sent", t.events)
		case .None, .Bad_Url, .Timeout, .Io, .Bad_Reply, .No_Memory:
			err_line(io, "cannot follow the events at %s: %s", t.events, bus.call_error_string(err))
		}
		return exit_for_call_error(err)
	}
	defer bus.unsubscribe(&sub)

	seen: i64
	for !stop_requested(stop) {
		got, failed := event_step(c, io, &sub)
		if failed {
			err_line(io, "the connection to the event stream was lost")
			return .Failed
		}
		if got {
			seen += 1
			if c.count > 0 && seen >= c.count {
				break
			}
		}
	}
	return .Ok
}

// Wait for one event and print it. The temporary memory it used is given
// back at the end, so a long run does not grow.
@(private = "file")
event_step :: proc(c: ^Command, io: ^Io, sub: ^bus.Subscriber) -> (got, failed: bool) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	ev, serr := bus.next_event(sub, EVENT_POLL)
	switch serr {
	case .None:
	case .Timed_Out, .Bad_Event:
		return false, false
	case .Closed, .Io:
		return false, true
	}
	print_event(c, io, &ev)
	bus.event_destroy(&ev)
	return true, false
}

// One event: the notes first (on stderr), then its line.
print_event :: proc(c: ^Command, io: ^Io, ev: ^bus.Event) {
	if ev.restarted {
		note_line(io, "the daemon restarted (new run %s), so earlier events cannot be compared with the new ones", safe_text(ev.run))
	}
	if ev.gap > 0 {
		note_line(io, "missed %d event%s before this one (seq %d)", ev.gap, "" if ev.gap == 1 else "s", ev.seq)
	}
	if c.json {
		out_text(io, string(ev.raw))
		out_text(io, "\n")
		return
	}
	root, ok := view_parse(ev.raw)
	if !ok {
		return
	}
	b := strings.builder_make(context.temp_allocator)
	if format_event_line(&b, root) {
		out_text(io, strings.to_string(b))
	}
}
