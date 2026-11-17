// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:strings"
import "noir:proto/config"
import "noir:proto/push"

// Option lines a bus controller adds to one client (`auth.decide` with `allow`
// and `push`). A controller may set what a `client-config-dir` file may set,
// and push a short list of per-client options. Every line is checked; one bad
// line rejects the whole list.
// Allowed lines:
//   per-client settings (ccd file syntax):
//     ifconfig-push, ifconfig-ipv6-push, iroute, iroute-ipv6, session-timeout
//   pushed options (PUSH_REPLY item syntax):
//     route, route-ipv6, dhcp-option, dns, redirect-gateway, redirect-private,
//     inactive
// Anything else is refused. A controller must not change tunnel essentials
// (topology, peer-id, ifconfig), cipher settings or keepalive, and must not cause
// the client run scripts.
// The result is the text of a ccd file. `client_params_build` reads it after the
// client's real file (`Connect_Request.extra`), so the ccd address checks apply:
// the pools decide, a taken address is refused.

// Most lines in one decision, and the longest line.
CONTROLLER_MAX_LINES :: 64
CONTROLLER_MAX_LINE :: 256

@(private)
CCD_LINES :: [?]string{"ifconfig-push", "ifconfig-ipv6-push", "iroute", "iroute-ipv6", "session-timeout"}

@(private)
PUSHED_LINES :: [?]string{"route", "route-ipv6", "dhcp-option", "dns", "redirect-gateway", "redirect-private", "inactive"}

// Checks the lines.
// - Success: `text` is a client-config-dir file (allocated with `allocator`)
//   and `bad` is 0.
// - Failure: `bad` is the number of the first bad line (from 1; 0 with `why`
//   for a problem with the whole list). `why` says what is wrong (a static
//   string or temp allocated).
controller_check :: proc(lines: []string, allocator := context.allocator) -> (text: string, bad: int, why: string) {
	if len(lines) > CONTROLLER_MAX_LINES {
		return "", 0, "there are too many push lines (the limit is 64)"
	}
	sb := strings.builder_make(allocator)
	for line, i in lines {
		n := i + 1
		ccd_text, w := controller_line(line)
		if w != "" {
			strings.builder_destroy(&sb)
			return "", n, w
		}
		strings.write_string(&sb, ccd_text)
		strings.write_byte(&sb, '\n')
	}
	return strings.to_string(sb), 0, ""
}

// One line to its client-config-dir form. `why` is empty when it is fine.
@(private)
controller_line :: proc(line: string) -> (text: string, why: string) {
	if len(line) == 0 || len(line) > CONTROLLER_MAX_LINE {
		return "", "the line is empty or longer than 256 bytes"
	}
	for c in transmute([]u8)line {
		switch c {
		case 0 ..< 0x20, 0x7f:
			return "", "the line contains a control character"
		case '"', '\'', '\\', '#', ';', ',':
			return "", "the line contains a quote, backslash, comma, semicolon or hash"
		}
	}
	fields := strings.fields(line, context.temp_allocator)
	if len(fields) == 0 {
		return "", "the line is empty"
	}
	name := fields[0]
	as_ccd := false
	for n in CCD_LINES {
		as_ccd ||= n == name
	}
	as_push := false
	for n in PUSHED_LINES {
		as_push ||= n == name
	}
	if !as_ccd && !as_push {
		return "", strings.concatenate({"the option '", name, "' cannot be set by a controller"}, context.temp_allocator)
	}
	clean := strings.join(fields, " ", context.temp_allocator)
	if as_push {
		po: push.Pushed_Options
		push.pushed_options_init(&po, context.temp_allocator)
		err := push.pushed_options_add_option(&po, clean)
		if err != .None || len(po.notes) > 0 {
			return "", strings.concatenate({"the option '", name, "' is not valid"}, context.temp_allocator)
		}
		return strings.concatenate({"push \"", clean, "\""}, context.temp_allocator), ""
	}
	parsed := config.parse_text(clean, "auth.decide")
	cfg := config.build_client_specific(parsed)
	defer config.destroy(&cfg)
	if !config.ok(&cfg) {
		return "", strings.concatenate({"the option '", name, "' is not valid"}, context.temp_allocator)
	}
	if name == "ifconfig-push" {
		ip, has := cfg.specific.ifconfig_push.?
		if !has || !ip.local_is_ip {
			return "", "ifconfig-push requires an IPv4 address"
		}
	}
	return strings.clone(clean, context.temp_allocator), ""
}

// Merges the settings of a controller into `spec` (the ccd file's). A static
// address of the controller replaces the file's. Lists are appended.
// Everything allocated uses `a`.
@(private)
merge_controller :: proc(spec: ^config.Client_Specific, ctl: config.Client_Specific, a: mem.Allocator) {
	if ctl.ifconfig_push != nil {
		spec.ifconfig_push = ctl.ifconfig_push
	}
	if ctl.ifconfig_ipv6_push != nil {
		spec.ifconfig_ipv6_push = ctl.ifconfig_ipv6_push
	}
	if len(ctl.iroutes) > 0 {
		list := make([]config.Iroute, len(spec.iroutes) + len(ctl.iroutes), a)
		copy(list, spec.iroutes)
		copy(list[len(spec.iroutes):], ctl.iroutes)
		spec.iroutes = list
	}
	if len(ctl.iroutes6) > 0 {
		list := make([]config.Iroute6, len(spec.iroutes6) + len(ctl.iroutes6), a)
		copy(list, spec.iroutes6)
		copy(list[len(spec.iroutes6):], ctl.iroutes6)
		spec.iroutes6 = list
	}
	if len(ctl.push) > 0 {
		list := make([]string, len(spec.push) + len(ctl.push), a)
		copy(list, spec.push)
		copy(list[len(spec.push):], ctl.push)
		spec.push = list
	}
	if ctl.session_timeout > 0 {
		spec.session_timeout = ctl.session_timeout
	}
}
