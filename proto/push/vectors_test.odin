// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package push

import "core:encoding/json"
import "core:strings"
import "core:testing"

// Captured from stock OpenVPN 2.6.23 and 2.7.7 by the interop harness.
KEYMETHOD_JSON :: #load("../testdata/vectors/control-keymethod.json")
PUSH_JSON :: #load("../testdata/vectors/control-push.json")
COMMANDS_JSON :: #load("../testdata/vectors/control-commands.json")

role_of :: proc(s: string) -> Role {
	return .Client if s == "client" || s == "c2s" else .Server
}

// The receiver of a captured direction: c2s goes to the server.
receiver_of :: proc(direction: string) -> Role {
	return .Server if direction == "c2s" else .Client
}

ip4 :: proc(s: string) -> [4]u8 {
	a, ok := parse_ipv4(s)
	assert(ok, "bad address in a vector")
	return a
}

// A JSON array of two address strings.
ip4_pair :: proc(v: json.Value, key: string) -> (a, b: [4]u8, ok: bool) {
	arr := jarr(v, key)
	if len(arr) != 2 {
		return
	}
	sa, _ := arr[0].(json.String)
	sb, _ := arr[1].(json.String)
	return ip4(string(sa)), ip4(string(sb)), true
}

// ----------------------------------------------------------- key-method-2

@(test)
vectors_keymethod_decode_and_reencode :: proc(t: ^testing.T) {
	root, ok := load_json(t, KEYMETHOD_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	cases := jarr(root, "cases")
	testing.expect(t, len(cases) >= 16)
	for c in cases {
		name := jstr(c, "name")
		sender := role_of(jstr(c, "sender"))
		raw := unhex(jstr(c, "hex"))
		testing.expectf(t, len(raw) == jint(c, "length"), "%s: length", name)
		want := jget(c, "expect")

		km: Key_Method
		used, err := keymethod_decode(raw, sender, &km)
		testing.expectf(t, err == .None, "%s: decode: %v", name, err)
		testing.expectf(t, used == len(raw), "%s: consumed %d of %d", name, used, len(raw))
		testing.expectf(t, len(km.random) == jint(want, "random_len"), "%s: random_len", name)
		testing.expectf(t, km.options == jstr(want, "options"), "%s: options %q", name, km.options)
		testing.expectf(t, len(km.options) + 1 == jint(want, "options_declared_len"), "%s: options length", name)
		testing.expectf(t, km.username == jstr(want, "username"), "%s: username", name)
		testing.expectf(t, km.peer_info == jstr(want, "peer_info"), "%s: peer_info", name)
		pi_decl := jint(want, "peer_info_declared_len")
		testing.expectf(t, (len(km.peer_info) == 0 && pi_decl == 0) || len(km.peer_info) + 1 == pi_decl, "%s: peer_info length", name)
		u_decl := jint(want, "username_declared_len")
		testing.expectf(t, (len(km.username) == 0 && u_decl == 0) || len(km.username) + 1 == u_decl, "%s: username length", name)
		testing.expectf(t, !km.username_too_long && !km.password_too_long, "%s: too long flags", name)
		pw_decl := jint(want, "password_declared_len")
		testing.expectf(t, (len(km.password) == 0 && pw_decl == 0) || len(km.password) + 1 == pw_decl, "%s: password length", name)
		if pw, is_str := jget(want, "password").(json.String); is_str {
			testing.expectf(t, km.password == string(pw), "%s: password", name)
		}
		testing.expectf(t, strings.has_prefix(km.password, jstr(want, "password_prefix")), "%s: password prefix", name)
		// The captured peer-info of a client parses and carries what the
		// capture says about the cell.
		if sender == .Client {
			pi: Peer_Info
			testing.expect_value(t, peer_info_parse(km.peer_info, &pi), Error.None)
			testing.expectf(t, pi.ver == jstr(jget(c, "stock"), "client"), "%s: IV_VER %q", name, pi.ver)
			testing.expectf(t, pi.plat == "linux" && pi.tcp_nonlinear && pi.mtu == 1600, "%s: peer-info basics", name)
			if pi.ver == "2.7.7" {
				testing.expectf(t, pi.proto == IV_PROTO_USERSPACE, "%s: IV_PROTO", name)
			} else {
				testing.expectf(t, iv_proto_value(pi.proto) == 990, "%s: IV_PROTO", name)
			}
		}

		// Encoding the decoded message gives the captured bytes back.
		out: [KEY_METHOD_MAX_LEN]u8
		n, eerr := keymethod_encode(out[:], &km)
		testing.expectf(t, eerr == .None, "%s: encode: %v", name, eerr)
		expect_bytes(t, out[:n], raw, name)

		// Every shorter cut needs more input; none panics.
		for cut in 0 ..< len(raw) {
			var: Key_Method
			_, cerr := keymethod_decode(raw[:cut], sender, &var)
			testing.expectf(t, cerr == .Need_More, "%s: cut %d: %v", name, cut, cerr)
		}
	}
}

@(test)
vectors_keymethod_server_stream :: proc(t: ^testing.T) {
	// The server's first plaintext is its key-method message and then the
	// PUSH_REPLY of an early push, all in one TLS read. The decoder reports how
	// much it used and the command reader takes the rest.
	root, ok := load_json(t, KEYMETHOD_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	seen := 0
	for c in jarr(root, "cases") {
		stream_hex := jstr(c, "stream_hex")
		if len(stream_hex) == 0 {
			continue
		}
		seen += 1
		name := jstr(c, "name")
		stream := unhex(stream_hex)
		km: Key_Method
		used, err := keymethod_decode(stream, .Server, &km)
		testing.expectf(t, err == .None, "%s: %v", name, err)
		testing.expectf(t, used == jint(c, "length"), "%s: used %d", name, used)
		rest := stream[used:]
		r: Cmd_Reader
		want := jarr(c, "stream_commands")
		got := 0
		for len(rest) > 0 {
			text, st := cmd_reader_next(&r, &rest)
			if st != .Command {
				continue
			}
			testing.expectf(t, got < len(want) && text == string(want[got].(json.String)), "%s: command %d", name, got)
			cmd, cerr := command_parse(text, .Client)
			testing.expect_value(t, cerr, Error.None)
			_, is_reply := cmd.(Push_Reply_Msg)
			testing.expect(t, is_reply)
			got += 1
		}
		testing.expectf(t, got == len(want), "%s: %d commands", name, got)
	}
	testing.expect(t, seen >= 2)
}

// Parameters for our builders from what a captured message says.
Cell_Build :: struct {
	options: Options_Params,
	skip:    bool, // items noirvpn does not send (tls-auth, keydir)
}

@(test)
vectors_keymethod_builders_match_stock :: proc(t: ^testing.T) {
	// Our options builder, peer-info builder and key-method encoder produce the
	// bytes a stock peer wrote, apart from the random block. With the stock
	// random block put in, the whole message is identical.
	root, ok := load_json(t, KEYMETHOD_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	built := 0
	skipped := 0
	for c in jarr(root, "cases") {
		name := jstr(c, "name")
		sender := role_of(jstr(c, "sender"))
		raw := unhex(jstr(c, "hex"))
		km: Key_Method
		_, err := keymethod_decode(raw, sender, &km)
		testing.expect_value(t, err, Error.None)

		info: Options_Info
		testing.expect_value(t, options_parse(km.options, &info), Error.None)
		if info.tls_auth {
			// tls-auth and keydir are items 7 and 8: noirvpn uses tls-crypt or
			// no wrapping and never writes them.
			skipped += 1
			continue
		}
		op := Options_Params {
			role      = sender,
			transport = .Tcp if strings.has_prefix(info.proto, "TCPv4") else .Udp,
			cipher    = cipher_from_name(info.cipher),
			tun_mtu   = info.tun_mtu.? or_else 0,
		}
		obuf: [OPTIONS_MAX_LEN]u8
		opts, oerr := options_build(obuf[:], &op)
		testing.expect_value(t, oerr, Error.None)
		testing.expectf(t, opts == km.options, "%s: options\n  got  %s\n  want %s", name, opts, km.options)

		// Peer-info of a client.
		pbuf: [KEY_METHOD_MAX_LEN]u8
		peer := ""
		if sender == .Client {
			pi: Peer_Info
			testing.expect_value(t, peer_info_parse(km.peer_info, &pi), Error.None)
			ciphers: [8]Cipher
			for i in 0 ..< pi.cipher_count {
				ciphers[i] = cipher_from_name(pi.ciphers[i])
			}
			pp := Peer_Info_Params {
				version       = pi.ver,
				platform      = pi.plat,
				tcp_nonlinear = pi.tcp_nonlinear,
				mtu           = pi.mtu,
				ciphers       = ciphers[:pi.cipher_count],
				proto         = pi.proto,
				extra         = {"IV_LZO_STUB=1", "IV_COMP_STUB=1", "IV_COMP_STUBv2=1"},
			}
			perr: Error
			peer, perr = peer_info_build(pbuf[:], &pp)
			testing.expect_value(t, perr, Error.None)
			testing.expectf(t, peer == km.peer_info, "%s: peer-info\n  got  %q\n  want %q", name, peer, km.peer_info)
		}

		// Our message with the stock random block: identical bytes.
		ours := Key_Method {
			sender    = sender,
			random    = km.random,
			options   = opts,
			username  = km.username,
			password  = km.password,
			peer_info = peer,
		}
		out: [KEY_METHOD_MAX_LEN]u8
		n, eerr := keymethod_encode(out[:], &ours)
		testing.expect_value(t, eerr, Error.None)
		expect_bytes(t, out[:n], raw, name)

		// With our own random block, everything but that block is identical.
		ours.random = fake_random(len(km.random), 3)
		n2, eerr2 := keymethod_encode(out[:], &ours)
		testing.expect_value(t, eerr2, Error.None)
		testing.expect_value(t, n2, len(raw))
		expect_bytes(t, out[:KEY_METHOD_PREFIX_LEN], raw[:KEY_METHOD_PREFIX_LEN], name)
		tail_at := KEY_METHOD_PREFIX_LEN + len(km.random)
		expect_bytes(t, out[tail_at:n2], raw[tail_at:], name)
		built += 1
	}
	testing.expect_value(t, skipped, 2)
	testing.expect(t, built >= 14)
}

// ---------------------------------------------------------------- PUSH_REPLY

// Feeds the captured messages of one case to an assembler.
assemble_case :: proc(t: ^testing.T, c: json.Value, a: ^Push_Assembler) -> (cont_values: [dynamic]int) {
	name := jstr(c, "name")
	msgs := jarr(c, "messages")
	sizes := jarr(c, "message_sizes_with_nul")
	testing.expectf(t, len(msgs) == len(sizes) && len(msgs) > 0, "%s: sizes", name)
	cont_values = make([dynamic]int, context.temp_allocator)
	for m, i in msgs {
		text := string(m.(json.String))
		testing.expectf(t, len(text) + 1 == int(sizes[i].(json.Integer)), "%s: message %d size", name, i)
		testing.expect(t, len(text) + 1 <= PUSH_MESSAGE_MAX)
		cmd, cerr := command_parse(text, .Client)
		testing.expectf(t, cerr == .None, "%s: command_parse: %v", name, cerr)
		pr, is_reply := cmd.(Push_Reply_Msg)
		testing.expectf(t, is_reply, "%s: not a PUSH_REPLY", name)
		cv, cverr := find_continuation(pr.options)
		testing.expect_value(t, cverr, Error.None)
		append(&cont_values, cv)
		st, ferr := push_assembler_feed(a, pr.options)
		testing.expectf(t, ferr == .None, "%s: feed %d: %v", name, i, ferr)
		last := i == len(msgs) - 1
		testing.expectf(t, (st == .Complete) == last, "%s: status after message %d", name, i)
	}
	return
}

@(test)
vectors_push_reply_fields :: proc(t: ^testing.T) {
	root, ok := load_json(t, PUSH_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	cases := jarr(root, "cases")
	testing.expect(t, len(cases) >= 7)
	for c in cases {
		name := jstr(c, "name")
		want := jget(c, "expect")
		a: Push_Assembler
		push_assembler_init(&a)
		defer push_assembler_destroy(&a)
		conts := assemble_case(t, c, &a)
		po := &a.po

		if expected_conts := jarr(want, "continuation_values"); len(expected_conts) > 0 {
			testing.expectf(t, len(conts) == len(expected_conts), "%s: continuation count", name)
			for v, i in expected_conts {
				testing.expectf(t, i < len(conts) && conts[i] == int(v.(json.Integer)), "%s: continuation %d", name, i)
			}
		} else {
			testing.expectf(t, len(conts) == 1 && conts[0] == 0, "%s: single message", name)
		}
		testing.expectf(t, len(po.notes) == jint(want, "notes"), "%s: %d notes", name, len(po.notes))
		if jbool(want, "token_only") {
			testing.expectf(t, pushed_options_token_only(po), "%s: token only", name)
		} else {
			testing.expectf(t, !pushed_options_token_only(po), "%s: not token only", name)
		}
		if pre := jstr(want, "auth_token_prefix"); len(pre) > 0 {
			testing.expectf(t, strings.has_prefix(po.auth_token, pre), "%s: auth-token prefix", name)
		} else {
			testing.expectf(t, len(po.auth_token) == 0, "%s: no auth-token", name)
		}
		if u, is_str := jget(want, "auth_token_user").(json.String); is_str {
			testing.expectf(t, po.auth_token_user == string(u), "%s: auth-token-user", name)
		}
		if jbool(want, "token_only") {
			continue
		}

		testing.expectf(t, po.topology == .Subnet && jstr(want, "topology") == "subnet", "%s: topology", name)
		if ia, ib, has := ip4_pair(want, "ifconfig"); has {
			ic, set := po.ifconfig.?
			testing.expectf(t, set && ic.a == ia && ic.b == ib, "%s: ifconfig", name)
		}
		gw, gw_set := po.route_gateway.?
		testing.expectf(t, gw_set && gw == ip4(jstr(want, "route_gateway")), "%s: route-gateway", name)
		testing.expectf(t, po.ping == jint(want, "ping"), "%s: ping", name)
		testing.expectf(t, po.ping_restart == jint(want, "ping_restart"), "%s: ping-restart", name)
		testing.expectf(t, po.peer_id == u32(jint(want, "peer_id")), "%s: peer-id", name)
		testing.expectf(t, po.cipher == jstr(want, "cipher"), "%s: cipher %q", name, po.cipher)
		testing.expectf(t, po.tun_mtu == jint(want, "tun_mtu"), "%s: tun-mtu", name)
		flags: Protocol_Flags
		for f in jarr(want, "protocol_flags") {
			pf, known := protocol_flag_from_name(string(f.(json.String)))
			testing.expect(t, known)
			flags += {pf}
		}
		testing.expectf(t, po.protocol_flags == flags, "%s: protocol-flags %v", name, po.protocol_flags)
		testing.expectf(t, !po.key_derivation_ekm, "%s: key-derivation", name)
		testing.expectf(t, len(po.routes) == jint(want, "route_count"), "%s: %d routes", name, len(po.routes))
		if fa, fb, has := ip4_pair(want, "first_route"); has {
			testing.expect(t, len(po.routes) > 0 && po.routes[0].net == fa && po.routes[0].mask == fb)
		}
		if la, lb, has := ip4_pair(want, "last_route"); has {
			n := len(po.routes)
			testing.expect(t, n > 0 && po.routes[n - 1].net == la && po.routes[n - 1].mask == lb)
		}
		for r in po.routes {
			testing.expectf(t, r.gateway.kind == .Default, "%s: route gateway", name)
		}

		// What a client does with it.
		own := ALL_CIPHERS
		vp := Validate_Params {
			own_ciphers           = own[:],
			server_options_cipher = "AES-256-GCM",
			iv_mtu                = 1600,
			have_peer_id          = true,
		}
		res := pushed_options_validate(po, &vp)
		testing.expectf(t, res.failure == .None, "%s: validate %v", name, res.failure)
		testing.expectf(t, cipher_name(res.cipher) == po.cipher, "%s: chosen cipher", name)
	}
}

// Parameters for the builder from a parsed reply.
params_from :: proc(po: ^Pushed_Options) -> Push_Reply_Params {
	return Push_Reply_Params {
		routes = po.routes[:],
		route_gateway = po.route_gateway,
		topology = po.topology,
		ping = po.ping,
		ping_restart = po.ping_restart,
		ifconfig = po.ifconfig,
		peer_id = po.peer_id,
		auth_token = po.auth_token,
		auth_token_user = po.auth_token_user,
		cipher = cipher_from_name(po.cipher),
		protocol_flags = po.protocol_flags,
		legacy_key_derivation = po.key_derivation_ekm,
		tun_mtu = po.tun_mtu,
	}
}

@(test)
vectors_push_reply_builder_matches_stock :: proc(t: ^testing.T) {
	// From the parsed capture back to messages: the same bytes, the same cuts
	// (a stock server's 930, 939 and last-part sizes).
	root, ok := load_json(t, PUSH_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	multi := 0
	for c in jarr(root, "cases") {
		name := jstr(c, "name")
		a: Push_Assembler
		push_assembler_init(&a)
		defer push_assembler_destroy(&a)
		_ = assemble_case(t, c, &a)
		p := params_from(&a.po)
		msgs, err := push_reply_build(&p)
		defer push_messages_destroy(msgs)
		testing.expectf(t, err == .None, "%s: build: %v", name, err)
		want := jarr(c, "messages")
		testing.expectf(t, len(msgs) == len(want), "%s: built %d messages, want %d", name, len(msgs), len(want))
		for i in 0 ..< min(len(msgs), len(want)) {
			w := string(want[i].(json.String))
			testing.expectf(t, msgs[i] == w, "%s: message %d\n  got  %s\n  want %s", name, i, msgs[i], w)
		}
		if len(want) > 1 {
			multi += 1
		}
	}
	testing.expect_value(t, multi, 2)
}

// ------------------------------------------------------------ text commands

@(test)
vectors_commands :: proc(t: ^testing.T) {
	root, ok := load_json(t, COMMANDS_JSON)
	if !ok {
		return
	}
	defer json.destroy_value(root)
	cases := jarr(root, "cases")
	testing.expect(t, len(cases) >= 16)
	kinds_seen: bit_set[Command_Kind]
	for c in cases {
		name := jstr(c, "name")
		receiver := receiver_of(jstr(c, "direction"))
		cmds := jarr(c, "commands")
		typed := jarr(c, "typed")
		testing.expectf(t, len(cmds) == len(typed) && len(cmds) > 0, "%s: commands and typed differ", name)

		// All commands in one stream, with a NUL after each, through the reader.
		stream := make([dynamic]u8, context.temp_allocator)
		for cm in cmds {
			text := string(cm.(json.String))
			append(&stream, text)
			append(&stream, 0)
		}
		r: Cmd_Reader
		rest := stream[:]
		i := 0
		for len(rest) > 0 {
			text, st := cmd_reader_next(&r, &rest)
			if st != .Command {
				testing.expectf(t, st == .Need_More, "%s: reader status %v", name, st)
				continue
			}
			testing.expectf(t, i < len(typed), "%s: too many commands", name)
			if i >= len(typed) {
				break
			}
			want := typed[i]
			cmd, err := command_parse(text, receiver)
			testing.expectf(t, err == .None, "%s: %q: %v", name, text, err)
			check_typed(t, name, text, cmd, want)
			kinds_seen += {command_kind(text)}
			i += 1
		}
		testing.expectf(t, i == len(cmds), "%s: read %d of %d commands", name, i, len(cmds))

		// The formatters write what the stock peer wrote. (Only for texts that
		// carry no trailing newline: those are the stock reason-file quirk.)
		for cm, k in cmds {
			text := string(cm.(json.String))
			buf: [MAX_COMMAND_LEN]u8
			n := 0
			ferr := Error.None
			w := typed[k]
			switch typed_kind(w) {
			case "Push_Request":
				n, ferr = format_push_request(buf[:])
			case "Exit":
				n, ferr = format_exit(buf[:])
			case "Restart":
				n, ferr = format_restart(buf[:], jstr(w, "text"), jbool(w, "keep"), jbool(w, "next"))
			case "Plain":
				if !strings.has_suffix(text, "\n") {
					n, ferr = format_auth_failed(buf[:])
				}
			case "Reason":
				n, ferr = format_auth_failed(buf[:], jstr(w, "reason"))
			case "Session":
				if !strings.has_suffix(text, "\n") {
					n, ferr = format_auth_failed_session(buf[:])
				}
			case "Temp":
				if !strings.has_suffix(text, "\n") {
					adv := Temp_Advance.Addr if jstr(w, "advance") == "Addr" else Temp_Advance.Unset
					n, ferr = format_auth_failed_temp(buf[:], jint(w, "backoff"), adv, jstr(w, "reason"))
				}
			}
			if n > 0 {
				testing.expectf(t, ferr == .None, "%s: format: %v", name, ferr)
				testing.expectf(t, string(buf[:n - 1]) == text && buf[n - 1] == 0, "%s: formatted %q, captured %q", name, string(buf[:n - 1]), text)
			}
		}
	}
	for k in ([]Command_Kind{.Push_Request, .Exit, .Restart, .Auth_Failed}) {
		testing.expectf(t, k in kinds_seen, "kind %v not covered", k)
	}
}

// A typed entry is an object with a kind, or just the kind as a string.
typed_kind :: proc(want: json.Value) -> string {
	if s, is_str := want.(json.String); is_str {
		return string(s)
	}
	return jstr(want, "kind")
}

check_typed :: proc(t: ^testing.T, name, text: string, cmd: Command, want: json.Value, loc := #caller_location) {
	kind := typed_kind(want)
	switch kind {
	case "Push_Request":
		_, ok := cmd.(Push_Request)
		testing.expectf(t, ok, "%s: %q is not a Push_Request", name, text, loc = loc)
	case "Exit":
		_, ok := cmd.(Exit_Cmd)
		testing.expectf(t, ok, "%s: %q is not an Exit", name, text, loc = loc)
	case "Restart":
		r, ok := cmd.(Restart)
		testing.expectf(t, ok, "%s: %q is not a Restart", name, text, loc = loc)
		testing.expectf(t, r.keep_credentials == jbool(want, "keep"), "%s: keep", name, loc = loc)
		testing.expectf(t, r.next_remote == jbool(want, "next"), "%s: next", name, loc = loc)
		testing.expectf(t, r.text == jstr(want, "text"), "%s: text", name, loc = loc)
	case "Plain", "Reason", "Session", "Temp":
		a, ok := cmd.(Auth_Failed)
		testing.expectf(t, ok, "%s: %q is not an Auth_Failed", name, text, loc = loc)
		wk: Auth_Failed_Kind
		switch kind {
		case "Plain":
			wk = .Plain
		case "Reason":
			wk = .Reason
		case "Session":
			wk = .Session
		case "Temp":
			wk = .Temp
		}
		testing.expectf(t, a.kind == wk, "%s: kind %v", name, a.kind, loc = loc)
		if kind == "Reason" || kind == "Temp" {
			testing.expectf(t, a.reason == jstr(want, "reason"), "%s: reason %q", name, a.reason, loc = loc)
		}
		if kind == "Temp" {
			testing.expectf(t, a.temp.backoff == jint(want, "backoff"), "%s: backoff", name, loc = loc)
			testing.expectf(t, a.temp.advance == .Addr && jstr(want, "advance") == "Addr", "%s: advance", name, loc = loc)
		}
	case:
		testing.expectf(t, false, "%s: unknown kind %q in the vector", name, kind, loc = loc)
	}
}
