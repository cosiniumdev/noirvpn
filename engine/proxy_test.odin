// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:strings"
import "core:testing"
import "noir:proto/config"

request_text :: proc(r: Proxy_Request) -> string {
	out, ok := proxy_request_build(r, context.temp_allocator)
	if !ok {
		return "<not ok>"
	}
	return string(out)
}

@(test)
proxy_request_plain :: proc(t: ^testing.T) {
	got := request_text(Proxy_Request{host = "vpn.example", port = 443})
	testing.expect_value(t, got, "CONNECT vpn.example:443 HTTP/1.1\r\nHost: vpn.example:443\r\n\r\n")
}

@(test)
proxy_request_version_1_0 :: proc(t: ^testing.T) {
	got := request_text(Proxy_Request{host = "vpn.example", port = 443, http10 = true})
	testing.expect_value(t, got, "CONNECT vpn.example:443 HTTP/1.0\r\nHost: vpn.example:443\r\n\r\n")
}

@(test)
proxy_request_ipv6_literal_in_brackets :: proc(t: ^testing.T) {
	got := request_text(Proxy_Request{host = "2001:db8::1", port = 8443})
	testing.expect_value(t, got, "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n")
	// Already in brackets: left as written.
	got = request_text(Proxy_Request{host = "[2001:db8::1]", port = 8443})
	testing.expect(t, strings.has_prefix(got, "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"), got)
	// An address of IPv4 has no brackets.
	got = request_text(Proxy_Request{host = "192.0.2.7", port = 443})
	testing.expect(t, strings.has_prefix(got, "CONNECT 192.0.2.7:443 HTTP/1.1\r\n"), got)
}

@(test)
proxy_request_with_basic_agent_and_headers :: proc(t: ^testing.T) {
	headers := []config.Proxy_Header{{"X-Site", "lab"}, {"X-Two", "two words"}}
	got := request_text(
		Proxy_Request {
			host = "vpn.example",
			port = 443,
			agent = "noirvpn/1",
			basic = true,
			user = "Aladdin",
			pass = "open sesame",
			headers = headers,
		},
	)
	want := "CONNECT vpn.example:443 HTTP/1.1\r\n" +
	"Host: vpn.example:443\r\n" +
	"User-Agent: noirvpn/1\r\n" +
	"Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n" +
	"X-Site: lab\r\n" +
	"X-Two: two words\r\n" +
	"\r\n"
	testing.expect_value(t, got, want)
}

@(test)
proxy_request_without_basic_has_no_login :: proc(t: ^testing.T) {
	// The credentials are there but not asked for yet (`auto` before the 407).
	got := request_text(Proxy_Request{host = "vpn.example", port = 443, basic = false, user = "u", pass = "p"})
	testing.expect(t, !strings.contains(got, "Proxy-Authorization"), got)
}

@(test)
proxy_request_refuses_line_breaks :: proc(t: ^testing.T) {
	testing.expect_value(t, request_text(Proxy_Request{host = "a\r\nX: y", port = 443}), "<not ok>")
	testing.expect_value(t, request_text(Proxy_Request{host = "a b", port = 443}), "<not ok>")
	testing.expect_value(t, request_text(Proxy_Request{host = "", port = 443}), "<not ok>")
	testing.expect_value(t, request_text(Proxy_Request{host = "a", port = 443, agent = "x\ny"}), "<not ok>")
	bad := []config.Proxy_Header{{"X", "a\r\nY: b"}}
	testing.expect_value(t, request_text(Proxy_Request{host = "a", port = 443, headers = bad}), "<not ok>")
}

parse :: proc(text: string) -> (Proxy_Reply, Proxy_Parse) {
	return proxy_parse_reply(transmute([]u8)text)
}

@(test)
proxy_reply_200 :: proc(t: ^testing.T) {
	text := "HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n"
	r, st := parse(text)
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.code, 200)
	testing.expect_value(t, r.status_line, "HTTP/1.1 200 Connection established")
	testing.expect_value(t, r.end, len(text))
}

@(test)
proxy_reply_http_1_0_and_bare_lf :: proc(t: ^testing.T) {
	text := "HTTP/1.0 200 OK\n\n"
	r, st := parse(text)
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.code, 200)
	testing.expect_value(t, r.end, len(text))
}

@(test)
proxy_reply_407_basic :: proc(t: ^testing.T) {
	text := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n"
	r, st := parse(text)
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.code, 407)
	testing.expect_value(t, r.scheme, "Basic")
	testing.expect(t, r.basic)
}

@(test)
proxy_reply_407_ntlm_only :: proc(t: ^testing.T) {
	text := "HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: NTLM\r\n\r\n"
	r, st := parse(text)
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.code, 407)
	testing.expect_value(t, r.scheme, "NTLM")
	testing.expect(t, !r.basic)
}

@(test)
proxy_reply_407_several_challenges :: proc(t: ^testing.T) {
	// Basic among others: in one header, or in a later one.
	r, st := parse("HTTP/1.1 407 x\r\nProxy-Authenticate: Negotiate, Basic realm=\"p\"\r\n\r\n")
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.scheme, "Negotiate")
	testing.expect(t, r.basic)
	r, st = parse("HTTP/1.1 407 x\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: Basic realm=p\r\n\r\n")
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.scheme, "NTLM")
	testing.expect(t, r.basic)
	// A realm that says "basic" is not an offer.
	r, st = parse("HTTP/1.1 407 x\r\nProxy-Authenticate: Digest realm=\"basic\"\r\n\r\n")
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect(t, !r.basic)
}

@(test)
proxy_reply_503 :: proc(t: ^testing.T) {
	r, st := parse("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n")
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.code, 503)
	testing.expect_value(t, r.status_line, "HTTP/1.1 503 Service Unavailable")
}

@(test)
proxy_reply_leftover_after_the_blank_line :: proc(t: ^testing.T) {
	head := "HTTP/1.1 200 Connection established\r\n\r\n"
	text := strings.concatenate({head, "\x16\x03\x03tunnel bytes"}, context.temp_allocator)
	r, st := parse(text)
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.end, len(head))
	testing.expect_value(t, text[r.end:], "\x16\x03\x03tunnel bytes")
}

@(test)
proxy_reply_split_across_reads :: proc(t: ^testing.T) {
	text := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\n\r\nrest"
	// Every prefix that stops before the blank line asks for more; the whole
	// header, then, is done at the same place whatever the cut.
	end := strings.index(text, "\r\n\r\n") + 4
	for n in 0 ..< end {
		_, st := parse(text[:n])
		testing.expectf(t, st == .Need_More, "prefix of %d bytes: %v", n, st)
	}
	for n in end ..= len(text) {
		r, st := parse(text[:n])
		testing.expectf(t, st == .Done && r.end == end && r.code == 407 && r.basic, "prefix of %d bytes: %v", n, st)
	}
}

@(test)
proxy_reply_over_the_cap :: proc(t: ^testing.T) {
	// No blank line within 8 KiB.
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "HTTP/1.1 200 OK\r\n")
	for strings.builder_len(sb) < PROXY_HEADER_MAX {
		strings.write_string(&sb, "X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	_, st := parse(strings.to_string(sb))
	testing.expect_value(t, st, Proxy_Parse.Too_Long)
	// Just under the cap, still waiting.
	_, st = parse(strings.to_string(sb)[:PROXY_HEADER_MAX - 1])
	testing.expect_value(t, st, Proxy_Parse.Need_More)
	// A blank line that comes after the cap is too late.
	strings.write_string(&sb, "\r\n")
	_, st = parse(strings.to_string(sb))
	testing.expect_value(t, st, Proxy_Parse.Too_Long)
}

@(test)
proxy_reply_just_inside_the_cap :: proc(t: ^testing.T) {
	// A header of exactly the cap, with the blank line at the end, is fine.
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "HTTP/1.1 200 OK\r\nX-Pad: ")
	for strings.builder_len(sb) < PROXY_HEADER_MAX - 4 {
		strings.write_byte(&sb, 'a')
	}
	strings.write_string(&sb, "\r\n\r\n")
	testing.expect_value(t, strings.builder_len(sb), PROXY_HEADER_MAX)
	r, st := parse(strings.to_string(sb))
	testing.expect_value(t, st, Proxy_Parse.Done)
	testing.expect_value(t, r.end, PROXY_HEADER_MAX)
}

@(test)
proxy_reply_not_http :: proc(t: ^testing.T) {
	for text in ([]string{"SSH-2.0-OpenSSH_9.6\r\n\r\n", "HTTP/1.1\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n", "HTTP/1.1 2x0 OK\r\n\r\n", "HTTP/1.1 2000 OK\r\n\r\n", "\x16\x03\x03\x00\x05"}) {
		_, st := parse(text)
		testing.expectf(t, st == .Malformed, "%q: %v", text, st)
	}
	// An empty buffer, and the start of an HTTP line, wait for more.
	_, st := parse("")
	testing.expect_value(t, st, Proxy_Parse.Need_More)
	_, st = parse("HT")
	testing.expect_value(t, st, Proxy_Parse.Need_More)
}

@(test)
proxy_target_text :: proc(t: ^testing.T) {
	testing.expect_value(t, proxy_target("a.example", 443, context.temp_allocator), "a.example:443")
	testing.expect_value(t, proxy_target("::1", 443, context.temp_allocator), "[::1]:443")
}
