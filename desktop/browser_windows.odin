// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build windows
package main

// Starts the browser for a web sign-in with ShellExecuteW: the link (default
// browser), or the profile's program with the link as last argument.

import "core:strings"
import win "core:sys/windows"

BROWSER_DEFAULT :: ""

browser_spawn :: proc(words: []string, url: string) -> bool {
	file, params: string
	if len(words) == 0 {
		file = url
	} else {
		file = words[0]
		b := strings.builder_make(context.temp_allocator)
		for w in words[1:] {
			win_quote(&b, w)
			strings.write_byte(&b, ' ')
		}
		win_quote(&b, url)
		params = strings.to_string(b)
	}
	op := win.utf8_to_wstring("open", context.temp_allocator)
	wfile := win.utf8_to_wstring(file, context.temp_allocator)
	wparams: win.LPCWSTR
	if params != "" {
		wparams = win.utf8_to_wstring(params, context.temp_allocator)
	}
	// A value above 32 is success.
	r := win.ShellExecuteW(nil, op, wfile, wparams, nil, win.SW_SHOWNORMAL)
	return uintptr(rawptr(r)) > 32
}

// file_open opens a file with the program of its type; file_reveal opens
// Explorer at its folder, with the file selected.
file_open :: proc(path: string) -> bool {
	return browser_spawn({}, path)
}

file_reveal :: proc(path: string) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "/select,")
	win_quote(&b, path)
	op := win.utf8_to_wstring("open", context.temp_allocator)
	wfile := win.utf8_to_wstring("explorer.exe", context.temp_allocator)
	wparams := win.utf8_to_wstring(strings.to_string(b), context.temp_allocator)
	r := win.ShellExecuteW(nil, op, wfile, wparams, nil, win.SW_SHOWNORMAL)
	return uintptr(rawptr(r)) > 32
}

// win_quote writes one argument for the command line rules of
// CommandLineToArgvW: quotes when needed, backslashes before a quote doubled.
win_quote :: proc(b: ^strings.Builder, s: string) {
	if s != "" && strings.index_any(s, " \t\"") < 0 {
		strings.write_string(b, s)
		return
	}
	strings.write_byte(b, '"')
	slashes := 0
	for ch in transmute([]u8)s {
		switch ch {
		case '\\':
			slashes += 1
		case '"':
			for _ in 0 ..< slashes + 1 {
				strings.write_byte(b, '\\')
			}
			slashes = 0
		case:
			slashes = 0
		}
		strings.write_byte(b, ch)
	}
	for _ in 0 ..< slashes {
		strings.write_byte(b, '\\')
	}
	strings.write_byte(b, '"')
}
