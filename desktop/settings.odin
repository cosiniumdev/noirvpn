// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Settings the user picks in the Settings view, the renderer, and the window position.
// They are stored as "key = value" lines in settings.ini in the user's config directory.

import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"

SCALE_MIN :: 100
SCALE_MAX :: 300
SCALE_STEP :: 25

// Renderer is how the window gets its pixels: Gpu draws through an SDL renderer, Cpu
// rasterizes the frame in the program and hands the pixels to the window. Auto picks
// Gpu on Windows and Cpu on every other system.
Renderer :: enum u8 {
	Auto,
	Gpu,
	Cpu,
}

Settings :: struct {
	scale:    int, // percent of the normal size, or 0 for automatic
	renderer: Renderer, // read at program start; there is no control in the Settings view
	pos:      Maybe([2]i32), // window position (window_x, window_y), when stored
}

scale_valid :: proc(pct: int) -> bool {
	return pct == 0 || (pct >= SCALE_MIN && pct <= SCALE_MAX && pct % SCALE_STEP == 0)
}

// parse_scale reads "auto", or a percentage with an optional "%" sign.
parse_scale :: proc(s: string) -> (pct: int, ok: bool) {
	t := strings.trim_space(s)
	if strings.equal_fold(t, "auto") {
		return 0, true
	}
	n, parsed := strconv.parse_int(strings.trim_suffix(t, "%"), 10)
	if !parsed || n == 0 || !scale_valid(n) {
		return 0, false
	}
	return n, true
}

scale_text :: proc(pct: int) -> string {
	return pct == 0 ? "auto" : tprint("%d", pct)
}

// parse_renderer reads "auto", "gpu" or "cpu".
parse_renderer :: proc(s: string) -> (r: Renderer, ok: bool) {
	t := strings.trim_space(s)
	switch {
	case strings.equal_fold(t, "auto"):
		return .Auto, true
	case strings.equal_fold(t, "gpu"):
		return .Gpu, true
	case strings.equal_fold(t, "cpu"):
		return .Cpu, true
	}
	return .Auto, false
}

// renderer_pick resolves Auto to the renderer of this system.
renderer_pick :: proc(r: Renderer) -> Renderer {
	if r == .Auto {
		return ODIN_OS == .Windows ? .Gpu : .Cpu
	}
	return r
}

// settings_path is the settings file of the user, or "" when the config
// directory is not known.
settings_path :: proc() -> string {
	dir, err := os.user_config_dir(context.allocator, true)
	if err != nil {
		return ""
	}
	defer delete(dir)
	p, perr := filepath.join({dir, "noirvpn", "settings.ini"})
	return perr == nil ? p : ""
}

// ini_split splits a "key = value" line. Blank lines and comments give ok false.
ini_split :: proc(line: string) -> (key, value: string, ok: bool) {
	t := strings.trim_space(line)
	if t == "" || t[0] == '#' || t[0] == ';' {
		return
	}
	i := strings.index_byte(t, '=')
	if i < 0 {
		return
	}
	return strings.trim_space(t[:i]), strings.trim_space(t[i + 1:]), true
}

// settings_load reads the file. A missing file, an unknown key or a bad value
// leaves the default.
settings_load :: proc(path: string) -> (s: Settings) {
	if path == "" {
		return
	}
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {
		return
	}
	text := string(data)
	x, y: i32
	have_x, have_y: bool
	for line in strings.split_lines_iterator(&text) {
		key, value, ok := ini_split(line)
		if !ok {
			continue
		}
		switch key {
		case "scale":
			if pct, good := parse_scale(value); good {
				s.scale = pct
			}
		case "renderer":
			if r, good := parse_renderer(value); good {
				s.renderer = r
			}
		case "window_x":
			n, good := strconv.parse_int(value, 10)
			x, have_x = i32(n), good && n == int(i32(n))
		case "window_y":
			n, good := strconv.parse_int(value, 10)
			y, have_y = i32(n), good && n == int(i32(n))
		}
	}
	if have_x && have_y {
		s.pos = [2]i32{x, y}
	}
	return
}

// settings_save writes the scale. Lines with other keys stay as they are.
settings_save :: proc(path: string, s: Settings) -> bool {
	return ini_update(path, {{"scale", scale_text(s.scale)}})
}

// settings_save_pos writes the window position. Lines with other keys stay as they are.
settings_save_pos :: proc(path: string, x, y: i32) -> bool {
	return ini_update(path, {{"window_x", tprint("%d", x)}, {"window_y", tprint("%d", y)}})
}

Ini_Pair :: struct {
	key, value: string,
}

// ini_update sets the given keys in the file and keeps the other lines. It writes
// through a temporary file and a rename.
ini_update :: proc(path: string, pairs: []Ini_Pair) -> bool {
	if path == "" {
		return false
	}
	b: strings.Builder
	strings.builder_init(&b, context.temp_allocator)
	if data, err := os.read_entire_file(path, context.temp_allocator); err == nil {
		text := string(data)
		lines: for line in strings.split_lines_iterator(&text) {
			if key, _, ok := ini_split(line); ok {
				for p in pairs {
					if key == p.key {
						continue lines
					}
				}
			}
			if strings.trim_space(line) != "" {
				strings.write_string(&b, line)
				strings.write_byte(&b, '\n')
			}
		}
	}
	for p in pairs {
		strings.write_string(&b, p.key)
		strings.write_string(&b, " = ")
		strings.write_string(&b, p.value)
		strings.write_byte(&b, '\n')
	}
	dir := filepath.dir(path)
	if err := os.make_directory_all(dir); err != nil && !os.is_dir(dir) {
		return false
	}
	tmp := strings.concatenate({path, ".tmp"}, context.temp_allocator)
	if os.write_entire_file(tmp, strings.to_string(b)) != nil {
		return false
	}
	if os.rename(tmp, path) != nil {
		_ = os.remove(tmp)
		return false
	}
	return true
}
