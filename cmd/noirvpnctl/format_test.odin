// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "core:encoding/json"
import "core:strings"
import "core:testing"

view_of :: proc(t: ^testing.T, json_text: string, loc := #caller_location) -> View {
	v, ok := view_parse(transmute([]byte)json_text)
	testing.expectf(t, ok, "cannot parse %q", json_text, loc = loc)
	return v
}

flat_of :: proc(t: ^testing.T, json_text: string, loc := #caller_location) -> string {
	b := strings.builder_make(context.temp_allocator)
	format_flat(&b, view_of(t, json_text, loc))
	return strings.to_string(b)
}

// ---- the JSON view ----

@(test)
view_keeps_key_order_and_number_text :: proc(t: ^testing.T) {
	v := view_of(t, `{"zeta":1,"alpha":18446744073709551615,"mid":{"b":-2.5e3,"a":null},"list":[1,"x",true]}`)
	testing.expect_value(t, v.kind, View_Kind.Object)
	testing.expect_value(t, len(v.keys), 4)
	testing.expect_value(t, v.keys[0], "zeta")
	testing.expect_value(t, v.keys[1], "alpha")
	testing.expect_value(t, v.keys[2], "mid")
	testing.expect_value(t, v.keys[3], "list")
	// A u64 above 2^63 is kept exactly.
	a, _ := view_get(v, "alpha")
	testing.expect_value(t, a.text, "18446744073709551615")
	mid, _ := view_get(v, "mid")
	testing.expect_value(t, mid.keys[0], "b")
	b, _ := view_get(mid, "b")
	testing.expect_value(t, b.text, "-2.5e3")
	n, _ := view_get(mid, "a")
	testing.expect_value(t, n.kind, View_Kind.Null)
	list, _ := view_get(v, "list")
	testing.expect_value(t, len(list.items), 3)
	testing.expect_value(t, list.items[2].kind, View_Kind.Bool)
	testing.expect_value(t, list.items[2].text, "true")
	_, found := view_get(v, "nope")
	testing.expect(t, !found)
}

@(test)
view_unescapes_strings :: proc(t: ^testing.T) {
	v := view_of(t, `["a\"b\\c\/d\n\téA", "😀", "\ud83d x", "\udc00", "plain", ""]`)
	testing.expect_value(t, v.items[0].text, "a\"b\\c/d\n\téA")
	testing.expect_value(t, v.items[1].text, "\U0001F600")
	// A lone surrogate becomes U+FFFD.
	testing.expect_value(t, v.items[2].text, "� x")
	testing.expect_value(t, v.items[3].text, "�")
	testing.expect_value(t, v.items[4].text, "plain")
	testing.expect_value(t, v.items[5].text, "")
}

@(test)
view_rejects_bad_json :: proc(t: ^testing.T) {
	bad := []string{"", "{", "[1,", `{"a"}`, `{"a":}`, `{"a":1,}x`, `"abc`, `tru`, `[1 2]`, `{"a":1} x`, `"\x"`, `"\u12"`, `{1:2}`}
	for s in bad {
		_, ok := view_parse(transmute([]byte)s)
		testing.expectf(t, !ok, "accepted %q", s)
	}
	// Deep nesting is refused.
	deep := strings.repeat("[", 100, context.temp_allocator)
	_, ok := view_parse(transmute([]byte)deep)
	testing.expect(t, !ok)
}

// ---- text for a terminal ----

@(test)
terminal_text_is_made_safe :: proc(t: ^testing.T) {
	// A plain string is returned as it is.
	testing.expect_value(t, safe_text("alice@example.org"), "alice@example.org")
	testing.expect_value(t, safe_text("café"), "café")
	// An escape sequence, a bell, a C1 control, a bidi override, DEL.
	testing.expect_value(t, safe_text("a\x1b[31mred"), `a\u001b[31mred`)
	testing.expect_value(t, safe_text("a\x07b"), `a\u0007b`)
	testing.expect_value(t, safe_text("a\u009bb"), `a\u009bb`)
	testing.expect_value(t, safe_text("a\u202eb"), `a\u202eb`)
	testing.expect_value(t, safe_text("a\x7fb"), `a\u007fb`)
	// A byte that is not UTF-8.
	testing.expect_value(t, safe_text("a\xffb"), `a\ufffdb`)
	// Quoting.
	testing.expect_value(t, quote_text(`a "b" \ c`), `"a \"b\" \\ c"`)
	testing.expect_value(t, quote_text("x\ny\x1b"), `"x\ny\u001b"`)
	testing.expect_value(t, quote_text(""), `""`)
}

// ---- results ----

@(test)
flat_output_is_aligned_and_ordered :: proc(t: ^testing.T) {
	got := flat_of(t, `{"mode":"server","pid":12,"bus":{"run":"abc","events":true},"config":null,"listen":["udp 0.0.0.0:1194","tcp [::]:1194"],"none":[],"name":"","u":18446744073709551615}`)
	want := `mode        server
pid         12
bus.run     abc
bus.events  true
config      -
listen      udp 0.0.0.0:1194, tcp [::]:1194
none        -
name        ""
u           18446744073709551615
`
	testing.expect_value(t, got, want)
}

@(test)
flat_output_numbers_arrays_of_objects :: proc(t: ^testing.T) {
	got := flat_of(t, `{"routes":[{"net":"10.0.0.0/8","gateway":null},{"net":"::/0","gateway":"fe80::1"}],"empty":{}}`)
	want := `routes.0.net      10.0.0.0/8
routes.0.gateway  -
routes.1.net      ::/0
routes.1.gateway  fe80::1
`
	testing.expect_value(t, got, want)
	// A bare scalar result.
	testing.expect_value(t, flat_of(t, `5`), "result  5\n")
	testing.expect_value(t, flat_of(t, `{}`), "")
}

@(test)
flat_output_cleans_strings_from_the_network :: proc(t: ^testing.T) {
	got := flat_of(t, `{"name":"evil\u001b[2J","k\u001b":"v"}`)
	testing.expect(t, !strings.contains(got, "\x1b"), got)
	testing.expect(t, strings.contains(got, `evil\u001b[2J`))
}

@(test)
status_output :: proc(t: ^testing.T) {
	v := view_of(
		t,
		`{"mode":"client","name":"work","version":"0.1","pid":99,"started":"2026-11-09T12:00:00.000Z","uptime_s":5,"config":null,"verb":2,"bus":{"run":"9f3a0c51d27be8a4","seq":3,"events":true,"publish_errors":0},"client":{"state":"up","remote":"vpn.example.org:1194","vpn4":"10.8.0.2","vpn6":null,"auth_needed":null}}`,
	)
	b := strings.builder_make(context.temp_allocator)
	format_status(&b, v)
	want := `mode                client
name                work
version             0.1
pid                 99
started             2026-11-09T12:00:00.000Z
uptime_s            5
config              -
verb                2
bus.run             9f3a0c51d27be8a4
bus.seq             3
bus.events          true
bus.publish_errors  0
client.state        up
client.remote       vpn.example.org:1194
client.vpn4         10.8.0.2
client.vpn6         -
client.auth_needed  -
`
	testing.expect_value(t, strings.to_string(b), want)
}

// ---- the peers table ----

PEERS_JSON :: `{"count":3,"peers":[
{"session":"s-1","peer_id":0,"name":"alice","pin":"sha256:aa","state":"active","real_addr":"203.0.113.5:51000","proto":"udp","vpn4":"10.8.0.2","vpn6":null,"cipher":"AES-256-GCM","connected_at":"2026-11-09T12:34:56.789Z","bytes_in":1536,"bytes_out":12582912,"packets_in":9,"packets_out":10},
{"session":"s-2","peer_id":null,"name":null,"pin":null,"state":"handshake","real_addr":"[2001:db8::1]:51000","proto":"tcp","vpn4":null,"vpn6":null,"cipher":null,"connected_at":null,"bytes_in":0,"bytes_out":999,"packets_in":0,"packets_out":0},
{"session":"s-3","name":"b\u001b[0mob","state":"active","real_addr":"198.51.100.1:1","proto":"udp","bytes_in":3221225472,"bytes_out":1099511627776}]}`

@(test)
peers_table :: proc(t: ^testing.T) {
	root := view_of(t, PEERS_JSON)
	list, _ := view_get(root, "peers")
	b := strings.builder_make(context.temp_allocator)
	format_peers_table(&b, list.items)
	lines := strings.split_lines(strings.to_string(b), context.temp_allocator)
	testing.expect_value(t, len(lines), 5) // header, 3 peers, empty after the last newline
	want_head := "SESSION  NAME          STATE      PROTO  REAL_ADDR            VPN4      VPN6  CONNECTED                 IN    OUT"
	testing.expect_value(t, lines[0], want_head)
	testing.expect_value(
		t,
		lines[1],
		"s-1      alice         active     udp    203.0.113.5:51000    10.8.0.2  -     2026-11-09T12:34:56.789Z  1.5K  12.0M",
	)
	testing.expect_value(
		t,
		lines[2],
		"s-2      -             handshake  tcp    [2001:db8::1]:51000  -         -     -                         0B    999B",
	)
	// The name of s-3 has an escape sequence; it is shown inert.
	testing.expect(t, strings.contains(lines[3], `b\u001b[0mob`))
	testing.expect(t, strings.contains(lines[3], "3.0G"))
	testing.expect(t, strings.contains(lines[3], "1.0T"))
	testing.expect(t, !strings.contains(strings.to_string(b), "\x1b"))
	// No trailing spaces.
	for l in lines {
		testing.expect(t, !strings.has_suffix(l, " "), l)
	}
}

@(test)
peers_table_of_nobody_is_a_header :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	format_peers_table(&b, nil)
	lines := strings.split_lines(strings.to_string(b), context.temp_allocator)
	testing.expect_value(t, len(lines), 2)
	testing.expect(t, strings.has_prefix(lines[0], "SESSION"))
}

@(test)
byte_counts_are_shown_with_units :: proc(t: ^testing.T) {
	testing.expect_value(t, human_bytes("0"), "0B")
	testing.expect_value(t, human_bytes("1023"), "1023B")
	testing.expect_value(t, human_bytes("1024"), "1.0K")
	testing.expect_value(t, human_bytes("1048576"), "1.0M")
	testing.expect_value(t, human_bytes("18446744073709551615"), "16.0E")
	testing.expect_value(t, human_bytes("-5"), "-5")
	testing.expect_value(t, human_bytes("1.5"), "1.5")
}

@(test)
one_peer_is_shown_as_key_value_lines :: proc(t: ^testing.T) {
	root := view_of(t, `{"peer":{"session":"s-1","peer_id":3,"name":"alice","vpn6":null}}`)
	b := strings.builder_make(context.temp_allocator)
	format_peer(&b, root)
	testing.expect_value(t, strings.to_string(b), "session  s-1\npeer_id  3\nname     alice\nvpn6     -\n")
}

// ---- event lines ----

event_line_of :: proc(t: ^testing.T, envelope: string) -> string {
	b := strings.builder_make(context.temp_allocator)
	ok := format_event_line(&b, view_of(t, envelope))
	testing.expect(t, ok)
	return strings.to_string(b)
}

@(test)
event_line_has_ts_topic_and_fields_in_order :: proc(t: ^testing.T) {
	line := event_line_of(
		t,
		`{"v":1,"run":"9f3a0c51d27be8a4","seq":42,"ts":"2026-11-09T12:34:56.789Z","topic":"peer.connect","data":{"session":"s-17","peer_id":3,"name":"alice smith","pin":null,"vpn4":"10.8.0.2","real_addr":"[2001:db8::1]:51000","push":["route 10.0.0.0 255.0.0.0"],"ok":true,"empty":"","q":"a\"b","info":{"IV_VER":"2.6.8"}}}`,
	)
	want := `2026-11-09T12:34:56.789Z peer.connect session=s-17 peer_id=3 name="alice smith" pin=null vpn4=10.8.0.2 real_addr=[2001:db8::1]:51000 push=["route 10.0.0.0 255.0.0.0"] ok=true empty="" q="a\"b" info={"IV_VER":"2.6.8"}` + "\n"
	testing.expect_value(t, line, want)
}

@(test)
event_line_without_data :: proc(t: ^testing.T) {
	line := event_line_of(t, `{"v":1,"run":"9f3a0c51d27be8a4","seq":1,"ts":"2026-11-09T12:34:56.789Z","topic":"daemon.stop","data":{}}`)
	testing.expect_value(t, line, "2026-11-09T12:34:56.789Z daemon.stop\n")
}

@(test)
event_line_neutralises_control_characters :: proc(t: ^testing.T) {
	line := event_line_of(
		t,
		`{"v":1,"run":"9f3a0c51d27be8a4","seq":1,"ts":"2026-11-09T12:34:56.789Z","topic":"auth.fail","data":{"name":"x\u001b]0;pwned\u0007","detail":"line1\nline2","bad\u001bkey":1}}`,
	)
	testing.expect(t, !strings.contains(line, "\x1b"))
	testing.expect(t, !strings.contains(line, "\x07"))
	// One line only.
	testing.expect_value(t, strings.count(line, "\n"), 1)
}

@(test)
event_line_needs_a_topic :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	testing.expect(t, !format_event_line(&b, view_of(t, `{"v":1,"data":{}}`)))
}

// ---- profiles ----

@(test)
format_profile_table :: proc(t: ^testing.T) {
	v := view_of(
		t,
		`{"options":[{"name":"client","line":1,"disposition":"supported","note":null},{"name":"verb","line":9,"disposition":"ignored","note":"no effect in a profile"}],"sha256":"abc","label":"Work","notes":["float: x"]}`,
	)
	b := strings.builder_make(context.temp_allocator)
	format_profile(&b, v)
	want := `OPTION  LINE  DISPOSITION  NOTE
client  1     supported
verb    9     ignored      no effect in a profile

sha256  abc
label   Work
note    float: x
`
	testing.expect_value(t, strings.to_string(b), want)
}

@(test)
format_profile_escapes_control_characters :: proc(t: ^testing.T) {
	v := view_of(t, `{"options":[{"name":"a\u001b[31mb","line":1,"disposition":"supported","note":null}],"sha256":"x","label":"y\u0007","notes":[]}`)
	b := strings.builder_make(context.temp_allocator)
	format_profile(&b, v)
	testing.expect(t, !strings.contains(strings.to_string(b), "\x1b"))
	testing.expect(t, !strings.contains(strings.to_string(b), "\x07"))
}

@(test)
format_problems_table :: proc(t: ^testing.T) {
	details, err := json.parse(
		transmute([]byte)string(`[{"line":3,"option":"ca","class":"path","reason":"a file"},{"line":0,"option":"","class":"invalid","reason":"no identity"}]`),
		.JSON,
		true,
		context.temp_allocator,
	)
	testing.expect_value(t, err, json.Error.None)
	b := strings.builder_make(context.temp_allocator)
	format_problems(&b, details)
	want := `LINE  OPTION  CLASS    REASON
3     ca      path     a file
-     -       invalid  no identity
`
	testing.expect_value(t, strings.to_string(b), want)
	empty := strings.builder_make(context.temp_allocator)
	format_problems(&empty, json.Null{})
	testing.expect_value(t, strings.to_string(empty), "")
}
