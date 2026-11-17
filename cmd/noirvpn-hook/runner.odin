// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "base:intrinsics"
import "base:runtime"
import "core:fmt"
import "core:sync"
import "core:thread"
import "core:time"

// Runs commands without blocking the event reader: a bounded queue of jobs and a
// fixed number of worker threads. The reader calls `runner_submit`, which never
// waits; a job that does not fit is refused and the reader reports it.

// One command to run for one event. The runner owns it from `runner_submit`.
Job :: struct {
	seq:   u64,
	topic: string,
	// Points into the config rule; not owned.
	argv:  []string,
	env:   []string,
	input: []byte,
}

job_destroy :: proc(j: ^Job, allocator: runtime.Allocator) {
	delete(j.topic, allocator)
	env_destroy(j.env, allocator)
	delete(j.input, allocator)
	free(j, allocator)
}

Runner_Stats :: struct {
	// Jobs accepted into the queue.
	submitted: u64,
	// Jobs refused because the queue was full.
	dropped:   u64,
	// Jobs that were queued when the runner stopped.
	discarded: u64,
	// Commands that ended (any way), and how many of them did not succeed
	// (exit code other than 0, a signal, a timeout, could not start).
	finished:  u64,
	failed:    u64,
	timed_out: u64,
}

Runner :: struct {
	cfg:       ^Config,
	log:       ^Logger,
	alloc:     runtime.Allocator,
	mu:        sync.Mutex,
	cond:      sync.Cond,
	queue:     [dynamic]^Job,
	stopping:  bool,
	// Set when the grace time is over: running commands are killed.
	kill_now:  bool,
	threads:   [dynamic]^thread.Thread,
	stats:     Runner_Stats,
}

// Start the worker threads. `cfg` and `log` must outlive the runner.
runner_start :: proc(r: ^Runner, cfg: ^Config, log: ^Logger) -> bool {
	r.cfg = cfg
	r.log = log
	r.alloc = context.allocator
	r.queue.allocator = r.alloc
	r.threads.allocator = r.alloc
	for _ in 0 ..< cfg.max_parallel {
		t := thread.create(worker_main)
		if t == nil {
			runner_stop(r, 0, nil)
			return false
		}
		t.data = r
		thread.start(t)
		append(&r.threads, t)
	}
	return true
}

// Queue a job. False if the queue is full (the caller still owns the job)
// or the runner is stopping.
runner_submit :: proc(r: ^Runner, j: ^Job) -> bool {
	sync.mutex_lock(&r.mu)
	defer sync.mutex_unlock(&r.mu)
	if r.stopping || len(r.queue) >= r.cfg.max_queue {
		intrinsics.atomic_add(&r.stats.dropped, 1)
		return false
	}
	append(&r.queue, j)
	intrinsics.atomic_add(&r.stats.submitted, 1)
	sync.cond_signal(&r.cond)
	return true
}

runner_stats :: proc(r: ^Runner) -> Runner_Stats {
	return Runner_Stats {
		submitted = intrinsics.atomic_load(&r.stats.submitted),
		dropped = intrinsics.atomic_load(&r.stats.dropped),
		discarded = intrinsics.atomic_load(&r.stats.discarded),
		finished = intrinsics.atomic_load(&r.stats.finished),
		failed = intrinsics.atomic_load(&r.stats.failed),
		timed_out = intrinsics.atomic_load(&r.stats.timed_out),
	}
}

// How many jobs wait, and how many run.
runner_load :: proc(r: ^Runner) -> (queued: int) {
	sync.mutex_lock(&r.mu)
	defer sync.mutex_unlock(&r.mu)
	return len(r.queue)
}

// Stop: drop the queued jobs, give running commands `grace` to finish, then kill
// them, and wait for the threads. A `forced` that returns true ends the wait
// early. Safe to call once.
runner_stop :: proc(r: ^Runner, grace: time.Duration, stop: ^Stop) {
	sync.mutex_lock(&r.mu)
	r.stopping = true
	for j in r.queue {
		intrinsics.atomic_add(&r.stats.discarded, 1)
		logf(r.log, .Warn, "stopping: event seq=%d topic=%s was still queued, so it is dropped", j.seq, j.topic)
		job_destroy(j, r.alloc)
	}
	clear(&r.queue)
	sync.cond_broadcast(&r.cond)
	sync.mutex_unlock(&r.mu)

	began := mono_now()
	for {
		if all_done(r) {
			break
		}
		if mono_now() - began >= grace || (stop != nil && stop_forced(stop)) {
			break
		}
		time.sleep(5 * time.Millisecond)
	}
	if !all_done(r) {
		logf(r.log, .Warn, "stopping: killing the commands that are still running")
		intrinsics.atomic_store(&r.kill_now, true)
	}
	for t in r.threads {
		thread.join(t)
		thread.destroy(t)
	}
	delete(r.queue)
	delete(r.threads)
}

@(private = "file")
all_done :: proc(r: ^Runner) -> bool {
	for t in r.threads {
		if !thread.is_done(t) {
			return false
		}
	}
	return true
}

@(private = "file")
cancel_requested :: proc(data: rawptr) -> bool {
	r := (^Runner)(data)
	return intrinsics.atomic_load(&r.kill_now)
}

@(private = "file")
worker_main :: proc(t: ^thread.Thread) {
	r := (^Runner)(t.data)
	context.allocator = r.alloc
	for {
		sync.mutex_lock(&r.mu)
		for len(r.queue) == 0 && !r.stopping {
			sync.cond_wait(&r.cond, &r.mu)
		}
		if len(r.queue) == 0 {
			sync.mutex_unlock(&r.mu)
			return
		}
		j := r.queue[0]
		ordered_remove(&r.queue, 0)
		sync.mutex_unlock(&r.mu)

		run_job(r, j)
		job_destroy(j, r.alloc)
	}
}

@(private = "file")
run_job :: proc(r: ^Runner, j: ^Job) {
	// Give back the temporary memory (log texts) when the job is done.
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	logf(r.log, .Verbose, "run seq=%d topic=%s: %s", j.seq, j.topic, j.argv[0])
	start := mono_now()
	res := run_command(j.argv, j.env, j.input, r.cfg.timeout, cancel_requested, r)
	secs := time.duration_seconds(mono_now() - start)
	intrinsics.atomic_add(&r.stats.finished, 1)
	what := fmt.tprintf("seq=%d topic=%s %s", j.seq, j.topic, j.argv[0])
	switch res.status {
	case .Exited:
		if res.code == 0 {
			logf(r.log, .Info, "%s: exit 0 (%.3fs)", what, secs)
		} else {
			intrinsics.atomic_add(&r.stats.failed, 1)
			logf(r.log, .Warn, "%s: exit %d (%.3fs)", what, res.code, secs)
		}
	case .Signaled:
		intrinsics.atomic_add(&r.stats.failed, 1)
		logf(r.log, .Warn, "%s: killed by signal %d (%.3fs)", what, res.signal, secs)
	case .Timed_Out:
		intrinsics.atomic_add(&r.stats.failed, 1)
		intrinsics.atomic_add(&r.stats.timed_out, 1)
		logf(r.log, .Warn, "%s: timed out after %ds, so its process group was killed", what, int(r.cfg.timeout / time.Second))
	case .Cancelled:
		intrinsics.atomic_add(&r.stats.failed, 1)
		logf(r.log, .Warn, "%s: killed at shutdown", what)
	case .Spawn_Failed:
		intrinsics.atomic_add(&r.stats.failed, 1)
		logf(r.log, .Warn, "%s: cannot start: %v", what, res.errno)
	}
}
