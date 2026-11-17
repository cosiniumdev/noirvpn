// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:strings"
import "core:testing"

// `http-proxy` and its companions, and `tls-transport-strict`.

@(test)
test_proxy_plain :: proc(t: ^testing.T) {
	cfg := load_client("proto tcp-client\nhttp-proxy proxy.example 3128\n")
	defer destroy(&cfg)
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.diags), 0)
		p, ok := cfg.client.connections[0].proxy.?
		testing.expect(t, ok)
		testing.expect_value(t, p.host, "proxy.example")
		testing.expect_value(t, p.port, u16(3128))
		testing.expect_value(t, p.auth, Proxy_Auth.None)
		testing.expect(t, !key_source_is_set(p.creds))
		testing.expect(t, !p.http10)
		testing.expect_value(t, p.agent, "")
		testing.expect_value(t, len(p.headers), 0)
	}
}

@(test)
test_proxy_none_without_option :: proc(t: ^testing.T) {
	cfg := load_client("")
	defer destroy(&cfg)
	testing.expect(t, cfg.client.connections[0].proxy == nil)
}

@(test)
test_proxy_authfile_and_methods :: proc(t: ^testing.T) {
	// An AUTHFILE sends Basic from the first request.
	cfg := load_client("proto tcp-client\nhttp-proxy proxy.example 3128 proxy.auth\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.Basic)
		testing.expect_value(t, p.creds.path, "proxy.auth")
	}
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nhttp-proxy proxy.example 3128 proxy.auth basic\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.Basic)
		testing.expect_value(t, p.creds.path, "proxy.auth")
	}
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nhttp-proxy proxy.example 3128 proxy.auth none\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.Basic)
	}
	destroy(&cfg)
	// `none` as the file is no authentication.
	cfg = load_client("proto tcp-client\nhttp-proxy proxy.example 3128 none\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.None)
	}
	destroy(&cfg)
}

@(test)
test_proxy_auto_and_user_pass :: proc(t: ^testing.T) {
	cfg := load_client("proto tcp-client\nhttp-proxy proxy.example 3128 auto\nhttp-proxy-user-pass up.txt\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.diags), 0)
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.Auto)
		testing.expect_value(t, p.creds.path, "up.txt")
		testing.expect(t, !p.creds.is_inline)
	}
	destroy(&cfg)
	// The inline block, given after the `http-proxy` line or before it.
	for order in ([]string {
			"http-proxy proxy.example 3128 auto\n<http-proxy-user-pass>\nbob\nsecret\n</http-proxy-user-pass>\n",
			"<http-proxy-user-pass>\nbob\nsecret\n</http-proxy-user-pass>\nhttp-proxy proxy.example 3128 auto\n",
		}) {
		cfg = load_client(strings.concatenate({"proto tcp-client\n", order}, context.temp_allocator))
		if expect_clean(t, cfg.diags) {
			p, _ := cfg.client.connections[0].proxy.?
			testing.expect_value(t, p.auth, Proxy_Auth.Auto)
			testing.expect(t, p.creds.is_inline)
			testing.expect_value(t, p.creds.data, "bob\nsecret\n")
		}
		destroy(&cfg)
	}
}

@(test)
test_proxy_basic_takes_user_pass :: proc(t: ^testing.T) {
	cfg := load_client("proto tcp-client\nhttp-proxy proxy.example 3128 none basic\nhttp-proxy-user-pass up.txt\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.auth, Proxy_Auth.Basic)
		testing.expect_value(t, p.creds.path, "up.txt")
	}
	destroy(&cfg)
	// The AUTHFILE wins over http-proxy-user-pass.
	cfg = load_client("proto tcp-client\nhttp-proxy proxy.example 3128 mine.txt\nhttp-proxy-user-pass up.txt\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect_value(t, p.creds.path, "mine.txt")
	}
	destroy(&cfg)
}

@(test)
test_proxy_options :: proc(t: ^testing.T) {
	cfg := load_client(
		"proto tcp-client\nhttp-proxy proxy.example 3128\nhttp-proxy-option VERSION 1.0\nhttp-proxy-option AGENT noirvpn/1\nhttp-proxy-option CUSTOM-HEADER X-Site lab\nhttp-proxy-option CUSTOM-HEADER X-Two \"two words\"\n",
	)
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, len(cfg.diags), 0)
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect(t, p.http10)
		testing.expect_value(t, p.agent, "noirvpn/1")
		testing.expect_value(t, len(p.headers), 2)
		if len(p.headers) == 2 {
			testing.expect_value(t, p.headers[0], Proxy_Header{"X-Site", "lab"})
			testing.expect_value(t, p.headers[1], Proxy_Header{"X-Two", "two words"})
		}
	}
	destroy(&cfg)
	// Before the `http-proxy` line, and VERSION 1.1 back again.
	cfg = load_client("proto tcp-client\nhttp-proxy-option AGENT a\nhttp-proxy-option VERSION 1.0\nhttp-proxy-option VERSION 1.1\nhttp-proxy proxy.example 3128\n")
	if expect_clean(t, cfg.diags) {
		p, _ := cfg.client.connections[0].proxy.?
		testing.expect(t, !p.http10)
		testing.expect_value(t, p.agent, "a")
	}
	destroy(&cfg)
}

@(test)
test_proxy_option_errors :: proc(t: ^testing.T) {
	Bad :: struct {
		text: string,
		part: string,
	}
	bads := []Bad {
		{"http-proxy-option EXT1 x\n", "unknown proxy option type 'EXT1'"},
		{"http-proxy-option TIMEOUT 5\n", "unknown proxy option type 'TIMEOUT'"},
		{"http-proxy-option VERSION 2.0\n", "VERSION must be 1.0 or 1.1"},
		{"http-proxy-option VERSION\n", "needs 1 argument"},
		{"http-proxy-option AGENT a b\n", "needs 1 argument"},
		{"http-proxy-option CUSTOM-HEADER X-Only\n", "needs 2 arguments"},
		{"http-proxy-option CUSTOM-HEADER \"X: bad\" v\n", "is not a valid header name"},
		{"http-proxy-option AGENT \"a\x01b\"\n", "control character"},
	}
	for b in bads {
		cfg := load_client(b.text)
		expect_error(t, cfg.diags, 0, b.part)
		destroy(&cfg)
	}
}

@(test)
test_proxy_startup_errors :: proc(t: ^testing.T) {
	Bad :: struct {
		text: string,
		part: string,
	}
	bads := []Bad {
		{"proto tcp-client\nhttp-proxy proxy.example 3128 up.txt ntlm\n", "only basic proxy authentication is available"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 up.txt ntlm2\n", "only basic proxy authentication is available"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 up.txt digest\n", "only basic proxy authentication is available"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 auto negotiate\n", "only basic proxy authentication is available"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 auto-nct\n", "there is no proxy authentication method without clear text"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 none basic\n", "basic proxy authentication needs credentials"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 auto basic\n", "basic proxy authentication needs credentials"},
		{"http-proxy proxy.example 3128\n", "uses udp"},
		{"remote t.example 443 tcp-client\nhttp-proxy proxy.example 3128\nremote u.example 1194 udp\n", "remote u.example uses udp"},
		{"proto tcp-client\nhttp-proxy proxy.example 0\n", "port must be a number"},
		{"proto tcp-client\nhttp-proxy proxy.example\n", "needs 2 to 4 arguments"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 a basic extra\n", "needs 2 to 4 arguments"},
		{"proto tcp-client\nhttp-proxy proxy.example 3128 auto\n<http-proxy-user-pass>\n</http-proxy-user-pass>\n", "the inline block is empty"},
	}
	for b in bads {
		cfg := load_client(b.text)
		expect_error(t, cfg.diags, 0, b.part)
		destroy(&cfg)
	}
}

@(test)
test_proxy_rejected_options :: proc(t: ^testing.T) {
	cfg := load_client("proto tcp-client\nsocks-proxy socks.example 1080\n")
	expect_error(t, cfg.diags, 0, "SOCKS is not supported")
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nsocks-proxy-retry\n")
	expect_error(t, cfg.diags, 0, "SOCKS is not supported")
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nhttp-proxy-retry\n")
	expect_error(t, cfg.diags, 0, "removed in OpenVPN 2.4")
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nhttp-proxy-timeout 5\n")
	expect_error(t, cfg.diags, 0, "removed in OpenVPN 2.4")
	destroy(&cfg)
}

@(test)
test_proxy_in_connection_block :: proc(t: ^testing.T) {
	// One remote through a proxy with its own options, one direct, one tls
	// through another proxy that needs a login. The global lines before the
	// blocks are the defaults of the blocks.
	text := `proto tcp-client
http-proxy-option AGENT global
<connection>
remote a.example 443 tls-client
http-proxy p1.example 3128 auto
http-proxy-option VERSION 1.0
<http-proxy-user-pass>
u
p
</http-proxy-user-pass>
</connection>
<connection>
remote b.example 443
</connection>
<connection>
remote c.example 443
http-proxy p2.example 8080 creds.txt
http-proxy-option CUSTOM-HEADER X-C 1
</connection>
`
	cfg := load_client(text)
	defer destroy(&cfg)
	if !expect_clean(t, cfg.diags) {
		return
	}
	conns := cfg.client.connections
	// The CLIENT_BASE remote comes first.
	testing.expect_value(t, len(conns), 4)
	testing.expect(t, conns[0].proxy == nil)
	p1, ok1 := conns[1].proxy.?
	testing.expect(t, ok1)
	testing.expect_value(t, p1.host, "p1.example")
	testing.expect_value(t, p1.auth, Proxy_Auth.Auto)
	testing.expect(t, p1.http10)
	testing.expect_value(t, p1.agent, "global")
	testing.expect(t, p1.creds.is_inline)
	testing.expect(t, conns[1].tls)
	testing.expect(t, conns[2].proxy == nil)
	p3, ok3 := conns[3].proxy.?
	testing.expect(t, ok3)
	testing.expect_value(t, p3.port, u16(8080))
	testing.expect_value(t, p3.auth, Proxy_Auth.Basic)
	testing.expect(t, !p3.http10)
	testing.expect_value(t, p3.agent, "global")
	testing.expect_value(t, len(p3.headers), 1)
	// The first block's CUSTOM-HEADER did not reach the global state.
	cfg2 := load_client("proto tcp-client\nhttp-proxy-option CUSTOM-HEADER A 1\n<connection>\nremote x.example 443\nhttp-proxy p.example 3128\nhttp-proxy-option CUSTOM-HEADER B 2\n</connection>\n<connection>\nremote y.example 443\nhttp-proxy p.example 3128\n</connection>\n")
	defer destroy(&cfg2)
	if expect_clean(t, cfg2.diags) {
		a, _ := cfg2.client.connections[1].proxy.?
		b, _ := cfg2.client.connections[2].proxy.?
		testing.expect_value(t, len(a.headers), 2)
		testing.expect_value(t, len(b.headers), 1)
	}
}

@(test)
test_proxy_udp_block_error :: proc(t: ^testing.T) {
	cfg := load_client("<connection>\nremote x.example 1194 udp\nhttp-proxy p.example 3128\n</connection>\n")
	expect_error(t, cfg.diags, 0, "remote x.example uses udp")
	destroy(&cfg)
}

@(test)
test_proxy_stray_options_warn :: proc(t: ^testing.T) {
	cfg := load_client("proto tcp-client\nhttp-proxy-option AGENT x\n")
	if expect_clean(t, cfg.diags) {
		expect_warning(t, cfg.diags, 0, "there is no `http-proxy`")
	}
	destroy(&cfg)
	cfg = load_client("proto tcp-client\nhttp-proxy proxy.example 3128 auto\n")
	if expect_clean(t, cfg.diags) {
		expect_warning(t, cfg.diags, 0, "`auto` has no credentials")
	}
	destroy(&cfg)
}

@(test)
test_tls_transport_strict :: proc(t: ^testing.T) {
	cfg := load_client("remote t.example 443 tls-client\ntls-transport-strict\n")
	if expect_clean(t, cfg.diags) {
		testing.expect(t, cfg.client.tls_transport_strict)
		testing.expect_value(t, len(cfg.diags), 0)
	}
	destroy(&cfg)
	cfg = load_client("")
	testing.expect(t, !cfg.client.tls_transport_strict)
	destroy(&cfg)
	// No tls remote: a warning.
	cfg = load_client("tls-transport-strict\n")
	if expect_clean(t, cfg.diags) {
		expect_warning(t, cfg.diags, 0, "no remote uses `proto tls-client`")
	}
	destroy(&cfg)
	// It takes no argument and is for clients.
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-strict yes\n")
	expect_error(t, cfg.diags, 0, "needs 0 arguments")
	destroy(&cfg)
	cfg = load_server("tls-transport-strict\n")
	expect_error(t, cfg.diags, 0, "applies to clients only")
	destroy(&cfg)
}

@(test)
test_tls_transport_hello :: proc(t: ^testing.T) {
	cfg := load_client("remote t.example 443 tls-client\ntls-transport-hello chrome\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls_transport_hello, Tls_Hello.Chrome)
	}
	destroy(&cfg)
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-hello default\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls_transport_hello, Tls_Hello.Default)
	}
	destroy(&cfg)
	cfg = load_client("remote t.example 443 tls-client\n")
	testing.expect_value(t, cfg.client.tls_transport_hello, Tls_Hello.Default)
	destroy(&cfg)
	// Not a tls remote: an error.
	cfg = load_client("remote t.example 443 tcp-client\ntls-transport-hello chrome\n")
	expect_error(t, cfg.diags, 0, "tls-transport-hello needs proto tls-client")
	destroy(&cfg)
	cfg = load_client("tls-transport-hello chrome\n")
	expect_error(t, cfg.diags, 0, "tls-transport-hello needs proto tls-client")
	destroy(&cfg)
	// Another value, a missing one, a server.
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-hello firefox\n")
	expect_error(t, cfg.diags, 0, "must be default or chrome")
	destroy(&cfg)
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-hello\n")
	expect_error(t, cfg.diags, 0, "needs 1 argument")
	destroy(&cfg)
	cfg = load_server("tls-transport-hello chrome\n")
	expect_error(t, cfg.diags, 0, "applies to clients only")
	destroy(&cfg)
}

@(test)
test_tls_transport_ws :: proc(t: ^testing.T) {
	cfg := load_client("remote t.example 443 tls-client\ntls-transport-ws /vpn\n")
	if expect_clean(t, cfg.diags) {
		testing.expect_value(t, cfg.client.tls.transport_ws, "/vpn")
	}
	destroy(&cfg)
	cfg = load_client("")
	testing.expect_value(t, cfg.client.tls.transport_ws, "")
	destroy(&cfg)
	// Not a tls remote: an error.
	cfg = load_client("remote t.example 443 tcp-client\ntls-transport-ws /vpn\n")
	expect_error(t, cfg.diags, 0, "tls-transport-ws needs proto tls-client")
	destroy(&cfg)
	cfg = load_client("tls-transport-ws /vpn\n")
	expect_error(t, cfg.diags, 0, "tls-transport-ws needs proto tls-client")
	destroy(&cfg)
	// A bad path.
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-ws vpn\n")
	expect_error(t, cfg.diags, 0, "is not a valid path")
	destroy(&cfg)
	cfg = load_client("remote t.example 443 tls-client\ntls-transport-ws /a /b\n")
	expect_error(t, cfg.diags, 0, "needs 1 argument")
	destroy(&cfg)
}
