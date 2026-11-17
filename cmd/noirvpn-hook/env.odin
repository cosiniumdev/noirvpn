// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:encoding/json"
import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"
import "noir:bus"

// Environment of a hook command.
//
// The command gets only a short base (`BASE_ENV_NAMES`, copied from the runner
// when set) and these event variables:
//
//   NOIR_TOPIC, NOIR_SEQ, NOIR_RUN, NOIR_TS  envelope fields
//   NOIR_GAP        events missed just before this one (only if there were some)
//   NOIR_RESTARTED  "1" when the daemon restarted (only then)
//   NOIR_<FIELD>    each top-level `data` field that is a string, number,
//                   boolean or null (null is the empty string)
//
// A field name becomes upper case, with each character outside A-Z, 0-9 and `_`
// turned into `_`. A value with a NUL byte is left out. A value longer than
// ENV_VALUE_MAX bytes is cut. Nested objects and arrays are not passed (the
// command reads them from stdin).

// Variables copied from the runner's own environment, if it has them.
BASE_ENV_NAMES :: [?]string{"PATH", "HOME", "LANG", "LC_ALL", "TZ"}

// The PATH of a command when the runner has none.
DEFAULT_PATH :: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ENV_VALUE_MAX :: 4096

// The names the runner sets itself. A data field cannot replace them.
@(rodata)
RESERVED_NAMES := [?]string{"NOIR_TOPIC", "NOIR_SEQ", "NOIR_RUN", "NOIR_TS", "NOIR_GAP", "NOIR_RESTARTED"}

// `NOIR_` and the field name changed to be safe for an environment variable name.
env_name :: proc(field: string, allocator := context.allocator) -> (name: string, ok: bool) {
	if len(field) == 0 {
		return "", false
	}
	b := strings.builder_make(allocator)
	strings.write_string(&b, "NOIR_")
	for r in field {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			strings.write_rune(&b, r)
		case r >= 'a' && r <= 'z':
			strings.write_rune(&b, r - 'a' + 'A')
		case:
			strings.write_byte(&b, '_')
		}
	}
	return strings.to_string(b), true
}

// Cut `s` to at most `max` bytes, at a character boundary.
cut_utf8 :: proc(s: string, max: int) -> string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8.rune_start(s[end]) {
		end -= 1
	}
	return s[:end]
}

// The text of a scalar JSON value for an environment variable. `ok` is false
// for an object or an array.
scalar_env_text :: proc(v: json.Value, allocator := context.allocator) -> (text: string, ok: bool) {
	#partial switch x in v {
	case json.Null:
		return "", true
	case json.Boolean:
		return "true" if bool(x) else "false", true
	case json.Integer:
		return fmt.aprintf("%d", i64(x), allocator = allocator), true
	case json.Float:
		buf: [40]byte
		s := strconv.write_float(buf[:], f64(x), 'g', -1, 64)
		return strings.clone(strings.trim_left(s, "+"), allocator), true
	case json.String:
		return string(x), true
	}
	return "", false
}

// The `NAME=value` lines for one event. `base` is the base environment (see
// `base_env`). Strings use `allocator`; free them with `env_destroy`.
build_env :: proc(ev: ^bus.Event, base: []string, allocator := context.allocator) -> []string {
	out := make([dynamic]string, allocator)
	for b in base {
		append(&out, strings.clone(b, allocator))
	}
	append(&out, fmt.aprintf("NOIR_TOPIC=%s", ev.topic, allocator = allocator))
	append(&out, fmt.aprintf("NOIR_SEQ=%d", ev.seq, allocator = allocator))
	append(&out, fmt.aprintf("NOIR_RUN=%s", ev.run, allocator = allocator))
	append(&out, fmt.aprintf("NOIR_TS=%s", ev.ts, allocator = allocator))
	if ev.gap > 0 {
		append(&out, fmt.aprintf("NOIR_GAP=%d", ev.gap, allocator = allocator))
	}
	if ev.restarted {
		append(&out, strings.clone("NOIR_RESTARTED=1", allocator))
	}

	obj, is_obj := ev.data.(json.Object)
	if !is_obj {
		return out[:]
	}
	// Sorted by field name, so the result is the same every time and, when
	// two names become the same variable, the first one wins.
	keys := make([dynamic]string, context.temp_allocator)
	for k in obj {
		append(&keys, k)
	}
	slice.sort(keys[:])
	taken := make(map[string]bool, context.temp_allocator)
	for r in RESERVED_NAMES {
		taken[r] = true
	}
	for k in keys {
		name, name_ok := env_name(k, context.temp_allocator)
		if !name_ok || name in taken {
			continue
		}
		text, scalar := scalar_env_text(obj[k], context.temp_allocator)
		if !scalar || strings.contains_rune(text, 0) {
			continue
		}
		taken[name] = true
		append(&out, fmt.aprintf("%s=%s", name, cut_utf8(text, ENV_VALUE_MAX), allocator = allocator))
	}
	return out[:]
}

env_destroy :: proc(env: []string, allocator := context.allocator) {
	for e in env {
		delete(e, allocator)
	}
	delete(env, allocator)
}

// The base environment: the variables of `BASE_ENV_NAMES` that `lookup` knows
// (the runner's own environment), and PATH set to DEFAULT_PATH when missing.
base_env :: proc(lookup: proc(name: string) -> (string, bool), allocator := context.allocator) -> []string {
	out := make([dynamic]string, allocator)
	have_path := false
	for name in BASE_ENV_NAMES {
		value, found := lookup(name)
		if !found || strings.contains_rune(value, 0) {
			continue
		}
		if name == "PATH" {
			if value == "" {
				continue
			}
			have_path = true
		}
		append(&out, fmt.aprintf("%s=%s", name, value, allocator = allocator))
	}
	if !have_path {
		append(&out, strings.clone("PATH=" + DEFAULT_PATH, allocator))
	}
	return out[:]
}
