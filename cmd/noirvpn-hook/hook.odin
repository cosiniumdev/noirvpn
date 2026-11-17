// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:runtime"
import "core:strings"
import "core:time"
import "noir:bus"

// The reader: follow the events of one daemon and hand each event that
// matches a rule to the runner. It never waits for a command.

// How often the loop looks at the stop flag while no event comes.
EVENT_POLL :: 100 * time.Millisecond

Hook_Exit :: enum u8 {
	Ok,
	// The events socket could not be followed.
	Bus_Failed,
	// The worker threads could not be started.
	Thread_Failed,
}

// Run until `stop`. `url` is the events socket. The subscriber waits for a
// daemon that is not there yet and reconnects when it restarts. `base` is the
// base environment of the commands (see `base_env`). `stats_out`, if given,
// receives the final counters.
hook_run :: proc(cfg: ^Config, url: string, stop: ^Stop, log: ^Logger, base: []string, stats_out: ^Runner_Stats = nil) -> Hook_Exit {
	// A command that closes its stdin early must not kill us.
	ignore_sigpipe()

	prefixes := subscription_prefixes(cfg)
	defer delete(prefixes)
	sub, err := bus.subscribe(url, prefixes, wait = true)
	if err != .None {
		logf(log, .Error, "cannot follow the events at %s: %s", url, bus.call_error_string(err))
		return .Bus_Failed
	}
	defer bus.unsubscribe(&sub)

	r: Runner
	if !runner_start(&r, cfg, log) {
		logf(log, .Error, "cannot start the worker threads")
		return .Thread_Failed
	}
	logf(
		log,
		.Notice,
		"following %s: %d rule(s), up to %d at a time, queue %d, timeout %ds",
		url, len(cfg.rules), cfg.max_parallel, cfg.max_queue, int(cfg.timeout / time.Second),
	) // fmt: skip

	for !stop_requested(stop) {
		ev, serr := bus.next_event(&sub, EVENT_POLL)
		switch serr {
		case .None:
			handle_event(&r, cfg, log, base, &ev)
			bus.event_destroy(&ev)
		case .Timed_Out:
		case .Bad_Event:
			logf(log, .Debug, "skipped a message that is not an event")
		case .Closed:
			logf(log, .Error, "the event connection was closed")
			runner_stop(&r, cfg.grace, stop)
			return .Bus_Failed
		case .Io:
			logf(log, .Warn, "event connection error, trying again")
			time.sleep(EVENT_POLL)
		}
	}
	logf(log, .Notice, "stopping")
	runner_stop(&r, cfg.grace, stop)
	st := runner_stats(&r)
	logf(
		log,
		.Notice,
		"stopped: %d command(s) run (%d failed), %d event(s) dropped",
		st.finished, st.failed, st.dropped + st.discarded,
	) // fmt: skip
	if stats_out != nil {
		stats_out^ = st
	}
	return .Ok
}

// One event: report a restart or a gap, then queue a job for every rule
// whose prefix matches.
handle_event :: proc(r: ^Runner, cfg: ^Config, log: ^Logger, base: []string, ev: ^bus.Event) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	if ev.restarted {
		logf(log, .Notice, "the daemon restarted (run %s), so events before this point cannot be compared with the new ones", ev.run)
	}
	if ev.gap > 0 {
		logf(log, .Warn, "%d event(s) were missed before seq=%d topic=%s, so some hooks may not have run", ev.gap, ev.seq, ev.topic)
	}
	logf(log, .Debug, "event seq=%d topic=%s", ev.seq, ev.topic)
	for rule in cfg.rules {
		if !strings.has_prefix(ev.topic, rule.prefix) {
			continue
		}
		j := new(Job, r.alloc)
		j.seq = ev.seq
		j.topic = strings.clone(ev.topic, r.alloc)
		j.argv = rule.argv
		j.env = build_env(ev, base, r.alloc)
		j.input = make([]byte, len(ev.raw) + 1, r.alloc)
		copy(j.input, ev.raw)
		j.input[len(ev.raw)] = '\n'
		if !runner_submit(r, j) {
			logf(log, .Warn, "the queue is full (%d), so event seq=%d topic=%s for %s was dropped", cfg.max_queue, ev.seq, ev.topic, rule.argv[0])
			job_destroy(j, r.alloc)
		}
	}
}
