// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// View model of the connection (Conn), profile rows, simulated connection
// script and value formatting. link.odin sets Conn from the service; the
// script sets it in the simulated form.

import "core:c/libc"
import "core:fmt"
import "core:math"
import "core:strings"
import "ui"

MAX_PROFILES :: 64
MAX_DOMAINS :: 8
HISTORY :: 61 // one sample per second, 60 s window

Login :: enum u8 {
	None,
	User_Pass,
	Web,
}

// Where a row of the profile list comes from.
Source :: enum u8 {
	Sample, // simulated
	Daemon, // a client daemon with its own config file
	Stored, // a profile of the store (profile_rows.odin)
}

Profile :: struct {
	source:    Source,
	id:        string, // store id of a Stored row
	name:      string,
	host:      string,
	port:      int,
	proto:     string,
	login:     Login,
	user:      string,
	server_ip: string, // the server address of the last connection, or ""
	last_used: i64, // Unix seconds of the last connection, 0 for never
	created:   bool, // a simulated row created with the form
}

// Route is one route of the tunnel, as the service reports it.
Route :: struct {
	net:     string,
	gateway: string,
}

Phase :: enum u8 {
	Connecting,
	Handshake,
	Credentials,
	Web_Sign_In, // the server waits for a sign-in in the browser
	Up,
	Disconnected,
	Stopped,
	Failed,
	Closing,
}

// phase_busy is true while the tunnel is being set up.
phase_busy :: proc(p: Phase) -> bool {
	return p == .Connecting || p == .Handshake
}

Conn :: struct {
	profile:     int,
	phase:       Phase,
	phase_start: f64,
	attempt:     int,
	failure:     string, // last failure text, or ""
	// Counters and the series while up.
	up_start:    f64,
	next_sample: f64,
	down, up:    [HISTORY]f32, // bit/s
	count:       int, // samples held
	rx_bytes:    f64,
	tx_bytes:    f64,
	rx_packets:  int,
	tx_packets:  int,
	seed:        u32,
	user:        ui.Field,
	pass:        ui.Field,
	plan:        Plan,
	signed_in:   bool,
	// Details of the tunnel, as the service reports them ("" when unknown).
	remote:      string, // "host:port" being tried
	proto:       string, // udp, tcp or tls
	address:     string,
	cipher:      string,
	data_format: string,
	datapath:    string, // dco, udco or userspace
	tun:         string,
	// What the server pushed (client.tunnel_settings); settings_ok is false
	// until the service sends them for this connection.
	settings_ok: bool,
	peer4:       string, // the tunnel address of the server (route gateway)
	routes:      [dynamic]Route,
	dns_servers: [dynamic]string,
	dns_domains: [dynamic]string,
	redirect:    bool, // the server sends all traffic through the tunnel
	mtu:         int, // 0 = not known
	mss4, mss6:  int, // TCP MSS clamp; 0 = none
	peer_id:     int, // -1 = not known
	pushed:      [dynamic]string, // the pushed option lines
}

// Plan scripts what a simulated connect does.
Plan :: enum u8 {
	Direct, // connecting, then up
	Retry, // a failed attempt, then up
	Sign_In, // connecting, then asks for credentials, then up
}

// rand_next is a small deterministic generator, so screenshots repeat.
rand_next :: proc(c: ^Conn) -> f32 {
	c.seed = c.seed * 1664525 + 1013904223
	return f32((c.seed >> 8) & 0xffff) / 65535
}

conn_reset :: proc(c: ^Conn, profile: int, plan: Plan, now: f64) {
	user, pass := c.user, c.pass
	for s in ([?]string{c.failure, c.remote, c.proto, c.address, c.cipher, c.data_format, c.datapath, c.tun}) {
		delete(s)
	}
	conn_settings_clear(c)
	routes, servers, domains, pushed := c.routes, c.dns_servers, c.dns_domains, c.pushed
	c^ = {}
	c.user, c.pass = user, pass
	c.routes, c.dns_servers, c.dns_domains, c.pushed = routes, servers, domains, pushed
	c.profile = profile
	c.plan = plan
	c.phase = .Connecting
	c.phase_start = now
	c.attempt = 1
	c.seed = 12345
}

// conn_settings_clear forgets the pushed settings of the last connection.
conn_settings_clear :: proc(c: ^Conn) {
	for r in c.routes {
		delete(r.net)
		delete(r.gateway)
	}
	for s in c.dns_servers {
		delete(s)
	}
	for s in c.dns_domains {
		delete(s)
	}
	for s in c.pushed {
		delete(s)
	}
	clear(&c.routes)
	clear(&c.dns_servers)
	clear(&c.dns_domains)
	clear(&c.pushed)
	c.mtu, c.mss4, c.mss6, c.peer_id = 0, 0, 0, -1
	set_text(&c.peer4, "")
	c.redirect = false
	c.settings_ok = false
}

// conn_sample adds one rate sample (bit/s) to the series.
conn_sample :: proc(c: ^Conn, d, u: f32) {
	if c.count < HISTORY {
		c.down[c.count] = d
		c.up[c.count] = u
		c.count += 1
	} else {
		copy(c.down[:], c.down[1:])
		copy(c.up[:], c.up[1:])
		c.down[HISTORY - 1] = d
		c.up[HISTORY - 1] = u
	}
}

conn_clear_series :: proc(c: ^Conn) {
	c.count = 0
	c.down, c.up = {}, {}
}

// conn_push adds one second of simulated traffic.
conn_push :: proc(c: ^Conn) {
	// A random walk around a slowly drifting base, with bursts.
	base := 95_000 + 15_000 * math.sin(f32(c.count) * 0.21)
	d := base * (0.6 + rand_next(c) * 0.8)
	u := 11_000 + 9_000 * rand_next(c)
	if c.count > 0 {
		// Blend with the last sample so the series moves in waves.
		last := min(c.count, HISTORY) - 1
		d = 0.5 * c.down[last] + 0.5 * d
		u = 0.5 * c.up[last] + 0.5 * u
	}
	conn_sample(c, d, u)
	c.rx_bytes += f64(d) / 8
	c.tx_bytes += f64(u) / 8
	c.rx_packets += int(d / 8 / 900) + 1
	c.tx_packets += int(u / 8 / 700) + 1
}

// conn_prefill fills the series as if the tunnel had run for seconds.
conn_prefill :: proc(c: ^Conn, seconds: int) {
	for _ in 0 ..< seconds {
		conn_push(c)
	}
}

// conn_tick advances the script. It returns true when what is shown changed.
conn_tick :: proc(c: ^Conn, now: f64) -> bool {
	el := now - c.phase_start
	switch c.phase {
	case .Connecting:
		switch c.plan {
		case .Direct:
			if el > 1.2 {
				return conn_handshake(c, now)
			}
		case .Retry:
			if c.attempt == 1 && el > 1.6 {
				c.attempt = 2
				set_text(&c.failure, "The secure connection could not be set up")
				c.phase_start = now
				return true
			}
			if c.attempt == 2 && el > 1.0 {
				return conn_handshake(c, now)
			}
		case .Sign_In:
			if !c.signed_in && el > 1.6 {
				c.phase = .Credentials
				c.phase_start = now
				return true
			}
			if c.signed_in && el > 0.6 {
				return conn_handshake(c, now)
			}
		}
	case .Handshake:
		if el > (c.plan == .Sign_In ? 0.6 : 1.0) {
			conn_up(c, now)
			return true
		}
	case .Credentials, .Web_Sign_In, .Disconnected, .Stopped, .Failed, .Closing:
	case .Up:
		changed := false
		for now >= c.next_sample {
			conn_push(c)
			c.next_sample += 1
			changed = true
		}
		return changed
	}
	return false
}

conn_handshake :: proc(c: ^Conn, now: f64) -> bool {
	c.phase = .Handshake
	c.phase_start = now
	return true
}

conn_up :: proc(c: ^Conn, now: f64) {
	c.phase = .Up
	c.up_start = now
	c.next_sample = now + 1
	c.count = 0
	c.rx_bytes, c.tx_bytes = 0, 0
	c.rx_packets, c.tx_packets = 0, 0
	set_text(&c.address, "10.8.0.6")
	set_text(&c.cipher, "AES-256-GCM")
	set_text(&c.data_format, "epoch")
	set_text(&c.datapath, "dco")
	conn_settings_clear(c)
	set_text(&c.peer4, "10.8.0.1")
	append(&c.routes, Route{strings.clone("10.0.0.0/8"), strings.clone("10.8.0.1")})
	append(&c.routes, Route{strings.clone("172.16.0.0/12"), strings.clone("10.8.0.1")})
	append(&c.dns_servers, strings.clone("10.8.0.1"))
	append(&c.dns_domains, strings.clone("corp.example.com"))
	for l in ([?]string{"route 10.0.0.0 255.0.0.0", "route 172.16.0.0 255.240.0.0", "dhcp-option DNS 10.8.0.1", "dhcp-option DOMAIN corp.example.com", "route-gateway 10.8.0.1", "topology subnet", "ping 10", "ping-restart 60", "ifconfig 10.8.0.6 255.255.255.0", "peer-id 3", "cipher AES-256-GCM"}) {
		append(&c.pushed, strings.clone(l))
	}
	c.mtu, c.mss4, c.mss6, c.peer_id = 1500, 1388, 1368, 3
	c.settings_ok = true
	conn_push(c)
}

// datapath_label is the user text for a data path of the service.
datapath_label :: proc(d: string) -> string {
	switch d {
	case "dco":
		return "Kernel module"
	case "udco":
		return "DCO service"
	case "userspace":
		return "Service process"
	}
	return d
}

// ---- Formatting ----

fmt_rate :: proc(bits: f32) -> string {
	switch {
	case bits < 1000:
		return fmt.tprintf("%d bit/s", int(bits))
	case bits < 1e6:
		return fmt.tprintf("%.1f kbit/s", bits / 1e3)
	case:
		return fmt.tprintf("%.2f Mbit/s", bits / 1e6)
	}
}

fmt_bytes :: proc(b: f64) -> string {
	switch {
	case b < 1000:
		return fmt.tprintf("%d B", int(b))
	case b < 1e6:
		return fmt.tprintf("%.0f kB", b / 1e3)
	case:
		return fmt.tprintf("%.1f MB", b / 1e6)
	}
}

fmt_duration :: proc(seconds: f64) -> string {
	s := int(seconds)
	if s >= 3600 {
		return fmt.tprintf("%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
	}
	return fmt.tprintf("%d:%02d", s / 60, s % 60)
}

// row_address is the server of a list row: the address of the last
// connection, else the host name of the profile.
row_address :: proc(p: ^Profile) -> string {
	if p.server_ip != "" {
		return p.server_ip
	}
	return p.host
}

// fmt_last_used is the last connection of a row in local time.
fmt_last_used :: proc(t: i64) -> string {
	s := fmt_local_time(t)
	return "Never used" if s == "" else fmt.tprintf("Last used %s", s)
}

// fmt_local_time is a time in Unix seconds as "16 Nov 2026, 10:42" in local
// time; "" for none.
fmt_local_time :: proc(t: i64) -> string {
	if t <= 0 {
		return ""
	}
	tt := libc.time_t(t)
	tm := libc.localtime(&tt)
	if tm == nil {
		return ""
	}
	months := [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	return fmt.tprintf("%d %s %d, %02d:%02d", tm.tm_mday, months[clamp(int(tm.tm_mon), 0, 11)], int(tm.tm_year) + 1900, tm.tm_hour, tm.tm_min)
}

profile_make :: proc(name, host: string, port: int, proto: string, login: Login, server_ip := "", last_used: i64 = 0) -> Profile {
	return {
		name = strings.clone(name),
		host = strings.clone(host),
		port = port,
		proto = strings.clone(proto),
		login = login,
		server_ip = strings.clone(server_ip),
		last_used = last_used,
	}
}

// fmt_axis formats the top of the graph axis without a needless fraction.
fmt_axis :: proc(bits: f32) -> string {
	switch {
	case bits < 1000:
		return fmt.tprintf("%g bit/s", bits)
	case bits < 1e6:
		return fmt.tprintf("%g kbit/s", bits / 1e3)
	case:
		return fmt.tprintf("%g Mbit/s", bits / 1e6)
	}
}
