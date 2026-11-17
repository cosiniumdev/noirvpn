// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// A fake daemon for the tests: a real bus host with an events socket in a
// private temp directory. The tests publish events on it, close it and open
// it again to look like a restart.

import "base:runtime"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"
import "noir:bus"

Fake :: struct {
	dir:   string,
	host:  ^bus.Host,
	alloc: runtime.Allocator,
}

fake_open :: proc(t: ^testing.T, tag: string) -> ^Fake {
	f := new(Fake)
	f.alloc = context.allocator
	f.dir = make_dir(t, tag)
	if !fake_start(f, t) {
		testing.fail_now(t, "cannot open the bus")
	}
	return f
}

fake_start :: proc(f: ^Fake, t: ^testing.T) -> bool {
	opts := bus.Host_Options {
		mode      = .Server,
		events    = bus.Endpoint{path = fake_events_path(f)},
		allocator = context.allocator,
	}
	h, err, nerr := bus.host_open(opts)
	testing.expectf(t, err == .None, "host_open: %s (%v)", bus.open_error_string(err), nerr)
	f.host = h
	return err == .None
}

// Stop the daemon and start another one on the same socket.
fake_restart :: proc(f: ^Fake, t: ^testing.T) {
	bus.host_close(f.host)
	f.host = nil
	fake_start(f, t)
}

fake_events_path :: proc(f: ^Fake) -> string {
	return fmt.tprintf("%s/fake.events", f.dir)
}

fake_close :: proc(f: ^Fake) {
	if f.host != nil {
		bus.host_close(f.host)
	}
	remove_dir(f.dir)
	free(f)
}

// Keep publishing `topic` until `done` says stop or the time is up: a new
// subscriber misses the first events, so a test cannot publish just once.
publish_until :: proc(f: ^Fake, topic, data: string, limit: time.Duration, ctx: rawptr, done: proc(ctx: rawptr) -> bool) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if done(ctx) {
			return true
		}
		bus.publish(f.host, topic, transmute([]byte)data)
		time.sleep(20 * time.Millisecond)
	}
	return done(ctx)
}

make_dir :: proc(t: ^testing.T, tag: string) -> string {
	base, _ := os.temp_directory(context.temp_allocator)
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.make_directory_temp(base, fmt.tprintf("noir-hook-%s-*", tag), context.allocator)
	testing.expectf(t, err == nil, "cannot create a temp dir: %v", err)
	// The bus wants a directory nobody else can write to.
	posix.chmod(strings.clone_to_cstring(dir, context.temp_allocator), transmute(posix.mode_t)u32(0o700))
	return dir
}

remove_dir :: proc(dir: string) {
	os.remove_all(dir)
	delete(dir)
}

// Write an executable script into `dir` and return its path.
write_script :: proc(t: ^testing.T, dir, name, body: string) -> string {
	path := fmt.tprintf("%s/%s", dir, name)
	text := strings.concatenate({"#!/bin/sh\n", body, "\n"}, context.temp_allocator)
	err := os.write_entire_file(path, text)
	testing.expectf(t, err == nil, "cannot write %s: %v", path, err)
	posix.chmod(strings.clone_to_cstring(path, context.temp_allocator), transmute(posix.mode_t)u32(0o755))
	return path
}

// Wait until `cond` is true, at most `limit`.
wait_for :: proc(limit: time.Duration, ctx: rawptr, cond: proc(ctx: rawptr) -> bool) -> bool {
	start := time.now()
	for time.since(start) < limit {
		if cond(ctx) {
			return true
		}
		time.sleep(5 * time.Millisecond)
	}
	return cond(ctx)
}
