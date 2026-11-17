// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "core:time"
import "noir:bus"
import "noir:proto/push"
import "noir:proto/session"

// Web sign-in. The client sends `IV_SSO=webauth`; the server holds the login and
// sends `INFO_PRE,WEB_AUTH:<flags>:<url>`. The daemon checks the URL, logs only
// its host, and publishes `client.auth_needed` (kind `web_auth`) without the URL
// (the events socket has no roles). `status` gives the URL to senders that may
// control the tunnel (`web_url_reader`). The result is the connection state.
//
//	session Auth_Pending -> web_on_pending (the time the server gives)
//	session Info_Pre     -> web_on_info_pre -> web_auth_read (the checks)
//	                          good -> client.auth_needed (kind web_auth)
//	                          bad  -> fail_connection(.Auth_Failed), with a detail
//	session Up, the end of the attempt -> web_clear

// The whole `INFO_PRE` message with its NUL (management-notes.txt).
WEB_MSG_MAX :: push.CMD_SEND_MAX_LEN
WEB_HOST_MAX :: 255
WEB_FLAGS_MAX :: 8
WEB_FLAG_LEN :: 32

// A checked sign-in request. The strings are slices of the text it was read from.
Web_Auth :: struct {
	url:     string,
	host:    string,
	flags:   [WEB_FLAGS_MAX]string, // without `proxy=...`, which can hold a password
	n_flags: int,
}

// The sign-in that waits now. `active` is false when none waits.
Web_Wait :: struct {
	active:   bool,
	url:      [session.INFO_PRE_MAX]u8,
	url_n:    int,
	host:     [WEB_HOST_MAX + 2]u8,
	host_n:   int,
	flags:    [WEB_FLAGS_MAX][WEB_FLAG_LEN]u8,
	flag_n:   [WEB_FLAGS_MAX]int,
	n_flags:  int,
	deadline: time.Time,
	// Seconds of the last `AUTH_PENDING`, 0 when it gave none.
	pending:  int,
}

// Reads an `INFO_PRE` text. `is_web` is false if it is no web sign-in
// (`CR_TEXT`, `NOTIFY`, other). For web sign-in, `problem` is "" if the URL
// passes the checks, else the detail for the user (never holds the URL).
web_auth_read :: proc(text: string, cut: bool) -> (wa: Web_Auth, problem: string, is_web: bool) {
	p := push.info_pre_parse(text)
	if p.kind != .Web_Auth && p.kind != .Open_Url {
		return {}, "", false
	}
	if cut || len("INFO_PRE,") + len(text) + 1 > WEB_MSG_MAX {
		return {}, "the sign-in message is longer than 1024 bytes", true
	}
	url := p.text
	for c in transmute([]u8)url {
		if c <= 0x20 || c >= 0x7f {
			return {}, "the sign-in URL has a byte that is not printable ASCII", true
		}
	}
	if len(url) < 8 || !strings.equal_fold(url[:8], "https://") {
		return {}, "the sign-in URL is not https", true
	}
	rest := url[8:]
	end := len(rest)
	for c, i in transmute([]u8)rest {
		if c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority := rest[:end]
	if strings.index_byte(authority, '@') >= 0 {
		return {}, "the sign-in URL has a user part", true
	}
	host, port := authority, ""
	if len(authority) > 0 && authority[0] == '[' {
		close := strings.index_byte(authority, ']')
		if close < 0 {
			return {}, "the sign-in URL has a host that is not valid", true
		}
		host, port = authority[:close + 1], authority[close + 1:]
	} else if i := strings.last_index_byte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i:]
	}
	if host == "" || host == "[]" {
		return {}, "the sign-in URL has no host", true
	}
	if !web_host_ok(host) {
		return {}, "the sign-in URL has a host that is not valid", true
	}
	if port != "" && !web_port_ok(port) {
		return {}, "the sign-in URL has a port that is not valid", true
	}
	wa.url, wa.host = url, host
	rest_flags := p.flags
	for len(rest_flags) > 0 {
		item, _ := push.next_item(&rest_flags, ',')
		item = strings.trim_space(item)
		if item == "" || strings.has_prefix(item, "proxy=") || !web_flag_ok(item) {
			continue
		}
		if wa.n_flags < WEB_FLAGS_MAX {
			wa.flags[wa.n_flags] = item
			wa.n_flags += 1
		}
	}
	return wa, "", true
}

// Letters, digits, '-' and '.'; in brackets also ':' (an IPv6 address).
@(private = "file")
web_host_ok :: proc(host: string) -> bool {
	if len(host) > WEB_HOST_MAX {
		return false
	}
	inner := host
	v6 := false
	if host[0] == '[' {
		inner, v6 = host[1:len(host) - 1], true
	}
	for c in transmute([]u8)inner {
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '.':
		case ':':
			if !v6 {
				return false
			}
		case:
			return false
		}
	}
	return true
}

// ":" and 1 to 65535.
@(private = "file")
web_port_ok :: proc(port: string) -> bool {
	if len(port) < 2 || len(port) > 6 || port[0] != ':' {
		return false
	}
	v := 0
	for c in transmute([]u8)port[1:] {
		if c < '0' || c > '9' {
			return false
		}
		v = v * 10 + int(c - '0')
	}
	return v >= 1 && v <= 65535
}

@(private = "file")
web_flag_ok :: proc(f: string) -> bool {
	if len(f) > WEB_FLAG_LEN {
		return false
	}
	for c in transmute([]u8)f {
		switch c {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '_':
		case:
			return false
		}
	}
	return true
}

// A server notice for the log: printable ASCII, at most 160 bytes.
@(private = "file")
notice_text :: proc(s: string) -> string {
	n := min(len(s), 160)
	b := make([]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		c := s[i]
		b[i] = c if c >= 0x20 && c < 0x7f else '?'
	}
	return string(b)
}

// "webauth" when the list of methods has it.
@(private = "file")
sso_has_webauth :: proc(methods: string) -> bool {
	rest := methods
	for len(rest) > 0 {
		item, _ := push.next_item(&rest, ',')
		if strings.trim_space(item) == "webauth" {
			return true
		}
	}
	return false
}

// IV_SSO value of the next login, or "". A service sends it if the `sso`
// argument of `profile.set` asked. A daemon with a config file sends it for
// `setenv IV_SSO webauth`, and only with a control socket (the URL shows only
// there).
client_sso :: proc(d: ^Daemon) -> string {
	if d.service {
		return "webauth" if d.prof_sso else ""
	}
	if d.cfg.iv_sso == "" {
		return ""
	}
	if !sso_has_webauth(d.cfg.iv_sso) {
		if !d.sso_warned {
			logf(.Warn, "setenv IV_SSO: this client only supports the webauth method, so IV_SSO will not be sent")
			d.sso_warned = true
		}
		return ""
	}
	if !host_control_on(d) {
		if !d.sso_warned {
			logf(.Warn, "setenv IV_SSO webauth: the sign-in link can only be shown on the control bus, which is off, so IV_SSO will not be sent")
			d.sso_warned = true
		}
		return ""
	}
	return "webauth"
}

// The sign-in is over: it worked, or the attempt ended.
web_clear :: proc(d: ^Daemon) {
	d.web = {}
}

web_url :: proc(d: ^Daemon) -> string {
	return string(d.web.url[:d.web.url_n])
}

web_host :: proc(d: ^Daemon) -> string {
	return string(d.web.host[:d.web.host_n])
}

// `AUTH_PENDING`: the server gives more time. A wait that is shown gets the new time.
web_on_pending :: proc(d: ^Daemon, secs: int) {
	d.web.pending = max(secs, 0)
	if d.web.active {
		web_set_deadline(d)
		web_publish(d)
	}
}

web_set_deadline :: proc(d: ^Daemon) {
	left, ok := session.session_push_wait_left(&d.s, now_of(d))
	if !ok {
		left = time.Duration(d.web.pending) * time.Second
	}
	d.web.deadline = time.time_add(time.now(), left)
}

// Seconds until the server stops waiting, rounded up.
web_left :: proc(d: ^Daemon) -> i64 {
	left := time.diff(time.now(), d.web.deadline)
	if left <= 0 {
		return 0
	}
	return i64((left + time.Second - 1) / time.Second)
}

// `INFO_PRE` from the server.
web_on_info_pre :: proc(d: ^Daemon) {
	text, cut := session.session_info_pre(&d.s)
	wa, problem, is_web := web_auth_read(text, cut)
	if !is_web {
		p := push.info_pre_parse(text)
		#partial switch p.kind {
		case .Cr_Text:
			logf(.Notice, "the server asked a question (CR_TEXT), but this client does not support it")
		case .Notify:
			logf(.Notice, "server notice: %s", notice_text(p.text))
		case:
			logf(.Notice, "the server sent an INFO_PRE message of an unknown kind (%d bytes, not shown)", len(text))
		}
		return
	}
	if d.up {
		logf(.Notice, "the server asked for a web sign-in while the tunnel is up, and this client will ignore it")
		return
	}
	if client_sso(d) == "" {
		logf(.Notice, "the server sent a web sign-in link, but web sign-in is off, so the link will be ignored")
		return
	}
	if problem != "" {
		logf(.Error, "web sign-in refused: %s", problem)
		d.detail_next = problem
		fail_connection(d, .Auth_Failed, {})
		return
	}
	w := &d.web
	w.active = true
	w.url_n = copy(w.url[:], wa.url)
	w.host_n = copy(w.host[:], wa.host)
	w.n_flags = wa.n_flags
	for i in 0 ..< wa.n_flags {
		w.flag_n[i] = copy(w.flags[i][:], wa.flags[i])
	}
	web_set_deadline(d)
	logf(.Notice, "web sign-in: the server will wait %d s for you to sign in at %s", web_left(d), web_host(d))
	web_publish(d)
}

// The wait is shown while the state is `handshake`.
web_shown :: proc(d: ^Daemon) -> bool {
	return d.web.active && client_bus_state(d) == "handshake"
}

web_publish :: proc(d: ^Daemon) {
	if w := ev_begin(d); w != nil {
		web_write_fields(w, d, false)
		ev_emit(d, "client.auth_needed")
	}
}

// The fields of `client.auth_needed` for a web sign-in. `url`: the sender may
// read the URL; else the field is null.
web_write_fields :: proc(w: ^bus.Writer, d: ^Daemon, url: bool) {
	bus.kv_str(w, "kind", "web_auth")
	bus.kv_str(w, "reason", "web_auth")
	bus.kv_null(w, "username")
	bus.kv_null(w, "prompt")
	bus.kv_bool(w, "echo", false)
	bus.kv_int(w, "timeout_s", web_left(d))
	bus.kv_str_or_null(w, "url", web_url(d), url)
	bus.kv_str(w, "host", web_host(d))
	bus.kv_arr(w, "flags")
	for i in 0 ..< d.web.n_flags {
		bus.val_str(w, string(d.web.flags[i][:d.web.flag_n[i]]))
	}
	bus.end(w)
	buf: [24]u8
	bus.kv_str(w, "deadline", bus.format_ts(d.web.deadline, &buf))
}

// May the sender read the sign-in URL? Role `admin`, and an `operator` that may
// control the tunnel: in a service, the profile owner (service mode).
web_url_reader :: proc(d: ^Daemon, c: ^Caller) -> bool {
	if .Admin in c.roles {
		return true
	}
	if .Operator not_in c.roles {
		return false
	}
	return !d.service || service_owner_ok(d, c)
}
