// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:encoding/json"
import "core:strings"
import "core:testing"
import "noir:bus"
import "noir:client"

@(test)
test_web_auth_read_good :: proc(t: ^testing.T) {
	wa, problem, is_web := web_auth_read("WEB_AUTH:proxy=10.0.0.1;8080;dXNlcg==;cGFzcw==,hidden,external:https://login.example.com:8443/a?b=c#d", false)
	testing.expect(t, is_web)
	testing.expect_value(t, problem, "")
	testing.expect_value(t, wa.url, "https://login.example.com:8443/a?b=c#d")
	testing.expect_value(t, wa.host, "login.example.com")
	// The proxy flag can hold a password: it is never kept.
	testing.expect_value(t, wa.n_flags, 2)
	testing.expect_value(t, wa.flags[0], "hidden")
	testing.expect_value(t, wa.flags[1], "external")

	wa, problem, is_web = web_auth_read("OPEN_URL:HTTPS://[2001:db8::1]/x", false)
	testing.expect(t, is_web && problem == "")
	testing.expect_value(t, wa.host, "[2001:db8::1]")
	testing.expect_value(t, wa.n_flags, 0)

	wa, problem, is_web = web_auth_read("WEB_AUTH::https://idp.example", false)
	testing.expect(t, is_web && problem == "" && wa.host == "idp.example")
}

@(test)
test_web_auth_read_refused :: proc(t: ^testing.T) {
	cases := [?]struct {
		text, want: string,
	} {
		{"WEB_AUTH::http://login.example.com/", "the sign-in URL is not https"},
		{"WEB_AUTH::javascript:alert(1)", "the sign-in URL is not https"},
		{"WEB_AUTH::https://login.example.com/a b", "the sign-in URL has a byte that is not printable ASCII"},
		{"WEB_AUTH::https://login.example.com/é", "the sign-in URL has a byte that is not printable ASCII"},
		{"WEB_AUTH::https://good.example@evil.example/", "the sign-in URL has a user part"},
		{"WEB_AUTH::https:///path", "the sign-in URL has no host"},
		{"WEB_AUTH::https://:443/", "the sign-in URL has no host"},
		{"WEB_AUTH::https://evil.example\\.good.example/", "the sign-in URL has a host that is not valid"},
		{"WEB_AUTH::https://a%2eb/", "the sign-in URL has a host that is not valid"},
		{"WEB_AUTH::https://[2001:db8::1/", "the sign-in URL has a host that is not valid"},
		{"WEB_AUTH::https://a.example:99999/", "the sign-in URL has a port that is not valid"},
		{"WEB_AUTH::https://a.example:x/", "the sign-in URL has a port that is not valid"},
	}
	for c in cases {
		_, problem, is_web := web_auth_read(c.text, false)
		testing.expectf(t, is_web && problem == c.want, "%q: %q", c.text, problem)
		testing.expect(t, !strings.contains(problem, "example"), "the problem text has the URL")
	}
	long := strings.concatenate({"WEB_AUTH::https://a.example/", strings.repeat("x", 1000, context.temp_allocator)}, context.temp_allocator)
	_, problem, _ := web_auth_read(long, false)
	testing.expect_value(t, problem, "the sign-in message is longer than 1024 bytes")
	_, problem, _ = web_auth_read("WEB_AUTH::https://a.example/", true)
	testing.expect_value(t, problem, "the sign-in message is longer than 1024 bytes")
	// 1024 bytes with "INFO_PRE," and the NUL pass.
	fit := strings.concatenate({"WEB_AUTH::https://a.example/", strings.repeat("x", 1024 - 1 - 9 - 28, context.temp_allocator)}, context.temp_allocator)
	_, problem, _ = web_auth_read(fit, false)
	testing.expect_value(t, problem, "")
}

@(test)
test_web_auth_read_other_kinds :: proc(t: ^testing.T) {
	for text in ([?]string{"CR_TEXT:E:code?", "NOTIFY::hello", "something", "WEBAUTH:https://a"}) {
		_, problem, is_web := web_auth_read(text, false)
		testing.expectf(t, !is_web && problem == "", "%q", text)
	}
}

@(private = "file")
web_fields_of :: proc(t: ^testing.T, d: ^Daemon, url: bool) -> (json.Object, string) {
	w: bus.Writer
	bus.writer_init(&w, context.temp_allocator)
	bus.begin_obj(&w)
	web_write_fields(&w, d, url)
	bus.end(&w)
	text := strings.clone(bus.writer_string(&w), context.temp_allocator)
	v, err := json.parse(transmute([]u8)text, .JSON, true, context.temp_allocator)
	testing.expect_value(t, err, json.Error.None)
	o, _ := v.(json.Object)
	return o, text
}

@(test)
test_web_fields :: proc(t: ^testing.T) {
	d := new(Daemon)
	defer free(d)
	wa, _, _ := web_auth_read("WEB_AUTH:proxy=1.2.3.4;80;;,external:https://login.example.com/x?state=abc", false)
	d.web.active = true
	d.web.url_n = copy(d.web.url[:], wa.url)
	d.web.host_n = copy(d.web.host[:], wa.host)
	d.web.n_flags = wa.n_flags
	for i in 0 ..< wa.n_flags {
		d.web.flag_n[i] = copy(d.web.flags[i][:], wa.flags[i])
	}
	o, text := web_fields_of(t, d, false)
	testing.expect_value(t, string(o["kind"].(json.String)), "web_auth")
	testing.expect_value(t, string(o["host"].(json.String)), "login.example.com")
	_, url_null := o["url"].(json.Null)
	testing.expect(t, url_null, "the URL is given to a reader without the right")
	testing.expect(t, !strings.contains(text, "state=abc") && !strings.contains(text, "1.2.3.4"))
	flags, _ := o["flags"].(json.Array)
	testing.expect(t, len(flags) == 1 && string(flags[0].(json.String)) == "external")
	_, has_deadline := o["deadline"].(json.String)
	testing.expect(t, has_deadline)
	o, _ = web_fields_of(t, d, true)
	testing.expect_value(t, string(o["url"].(json.String)), "https://login.example.com/x?state=abc")
}

@(test)
test_web_url_reader :: proc(t: ^testing.T) {
	d := new(Daemon)
	defer free(d)
	req: Caller
	req.uid = 1000
	req.roles = {.Read}
	testing.expect(t, !web_url_reader(d, &req), "read")
	req.roles = {.Operator}
	testing.expect(t, web_url_reader(d, &req), "operator of a daemon with a config file")
	req.roles = {.Admin}
	testing.expect(t, web_url_reader(d, &req), "admin")
	when ODIN_OS != .Windows {
		d.service = true
		d.prof_loaded = true
		d.owner = u32(1000)
		req.roles = {.Operator}
		testing.expect(t, web_url_reader(d, &req), "the owner")
		req.uid = 1001
		testing.expect(t, !web_url_reader(d, &req), "another operator")
		req.roles = {.Admin}
		testing.expect(t, web_url_reader(d, &req), "admin of a service")
	}
}

@(test)
test_web_sso_of_a_service :: proc(t: ^testing.T) {
	d := new(Daemon)
	defer free(d)
	d.service = true
	testing.expect_value(t, client_sso(d), "")
	d.prof_sso = true
	testing.expect_value(t, client_sso(d), "webauth")
}

@(test)
test_refused_token_signs_in_again :: proc(t: ^testing.T) {
	// The plain AUTH_FAILED of an expired token: log in again, with no token.
	o, _ := failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Plain, used_token = true})
	testing.expect_value(t, o, client.Outcome.Local_Restart)
	o, _ = failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Reason, used_token = true})
	testing.expect_value(t, o, client.Outcome.Local_Restart)
	// TEMP keeps its back-off.
	o, _ = failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Temp, backoff = 3, used_token = true})
	testing.expect_value(t, o, client.Outcome.Auth_Failed_Temp)
	// Without a token a refusal stays a refusal.
	o, _ = failure_outcome(.Auth_Failed, false, Pending{kind = .Auth_Failed, auth_kind = .Plain})
	testing.expect_value(t, o, client.Outcome.Auth_Failed)
}
