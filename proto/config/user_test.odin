// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package config

import "core:mem"
import "core:os"
import "core:strings"
import "core:testing"

// A client profile as a provider hands it out, with inline keys.
STOCK_PROFILE :: `client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
mute 20
auth-nocache
<ca>
CA-TEXT
</ca>
<cert>
CERT-TEXT
</cert>
<key>
SECRET-KEY-TEXT
</key>
<tls-crypt>
SECRET-TLS-CRYPT-TEXT
</tls-crypt>
`

@(private = "file")
profile :: proc(extra: string) -> User_Profile {
	return user_profile_build(strings.concatenate({STOCK_PROFILE, extra}, context.temp_allocator))
}

@(private = "file")
find_problem :: proc(p: ^User_Profile, option: string) -> (User_Problem, bool) {
	for pr in p.problems {
		if pr.option == option {
			return pr, true
		}
	}
	return {}, false
}

@(private = "file")
expect_problem :: proc(
	t: ^testing.T,
	p: ^User_Profile,
	option, class: string,
	loc := #caller_location,
) {
	pr, found := find_problem(p, option)
	if !found {
		testing.expectf(t, false, "no problem for '%s'; got %d problems", option, len(p.problems), loc = loc)
		return
	}
	testing.expect_value(t, pr.class, class, loc = loc)
	testing.expect(t, pr.reason != "", loc = loc)
}

@(private = "file")
find_entry :: proc(p: ^User_Profile, name: string) -> (User_Entry, bool) {
	for e in p.entries {
		if e.name == name {
			return e, true
		}
	}
	return {}, false
}

@(test)
test_user_class_of_every_row :: proc(t: ^testing.T) {
	lists := [?][]string{USER_ALLOWED[:], USER_PATH[:], USER_SERVICE[:], USER_IGNORED[:]}
	names := [?]string{"ALLOWED", "PATH", "SERVICE", "IGNORED"}
	// Every name of a list is a table row, and no name is in two lists.
	for list, i in lists {
		for n in list {
			testing.expectf(t, option_find(n) != nil, "%s lists '%s', which is not a table row", names[i], n)
			for other, j in lists {
				if j > i {
					testing.expectf(
						t,
						!in_list(other, n),
						"'%s' is in the lists %s and %s",
						n,
						names[i],
						names[j],
					)
				}
			}
		}
	}
	for &o in option_table() {
		listed := 0
		for list in lists {
			if in_list(list, o.name) {
				listed += 1
			}
		}
		c, derived := user_class_derived(&o)
		if derived {
			// The table decides, so the row is in no list.
			testing.expectf(t, listed == 0, "'%s' has a class from the table and is also in a list", o.name)
			testing.expect_value(t, user_class(&o), c)
			continue
		}
		if o.disp == .Ignored {
			// Ignored by the table, or refused as a path or a service setting.
			ok_listed := listed == 0 || (listed == 1 && (in_list(USER_PATH[:], o.name) || in_list(USER_SERVICE[:], o.name)))
			testing.expectf(t, ok_listed, "ignored row '%s' is in a list that does not fit", o.name)
			continue
		}
		testing.expectf(
			t,
			listed == 1,
			"table row '%s' is in %d class lists; give it exactly one (user.odin)",
			o.name,
			listed,
		)
	}
}

@(test)
test_user_class_examples :: proc(t: ^testing.T) {
	cls :: proc(name: string) -> User_Class {
		return user_class(option_find(name))
	}
	testing.expect_value(t, cls("remote"), User_Class.Allowed)
	testing.expect_value(t, cls("block-ipv6"), User_Class.Allowed)
	testing.expect_value(t, cls("ca"), User_Class.Allowed)
	testing.expect_value(t, cls("verb"), User_Class.Ignored)
	testing.expect_value(t, cls("mute"), User_Class.Ignored)
	testing.expect_value(t, cls("daemon"), User_Class.Ignored)
	testing.expect_value(t, cls("log"), User_Class.Path)
	testing.expect_value(t, cls("writepid"), User_Class.Path)
	testing.expect_value(t, cls("capath"), User_Class.Path)
	testing.expect_value(t, cls("bus-allow"), User_Class.Service)
	testing.expect_value(t, cls("user"), User_Class.Service)
	testing.expect_value(t, cls("client-service"), User_Class.Service)
	testing.expect_value(t, cls("server"), User_Class.Server_Only)
	testing.expect_value(t, cls("up"), User_Class.Not_Supported)
	testing.expect_value(t, cls("auth-token"), User_Class.Not_Supported)
	testing.expect_value(t, cls("status"), User_Class.Not_Supported)
}

@(test)
test_user_profile_stock_is_ok :: proc(t: ^testing.T) {
	p := profile("")
	defer user_profile_destroy(&p)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	testing.expect_value(t, len(p.problems), 0)
	testing.expect_value(t, p.cfg.role, Role.Client)
	testing.expect_value(t, len(p.cfg.client.connections), 1)
	testing.expect_value(t, p.cfg.client.connections[0].host, "vpn.example.com")
	testing.expect(t, p.cfg.client.tls.key.is_inline)
	// One entry for each directive, in the order read.
	testing.expect_value(t, len(p.entries), 18)
	e, found := find_entry(&p, "remote")
	testing.expect(t, found)
	testing.expect_value(t, e.line, 4)
	testing.expect(t, !e.ignored)
	e, found = find_entry(&p, "verb")
	testing.expect(t, found)
	testing.expect(t, e.ignored)
	testing.expect(t, e.note != "")
	e, found = find_entry(&p, "persist-key")
	testing.expect(t, found && e.ignored)
	e, found = find_entry(&p, "cipher")
	testing.expect(t, found && e.ignored && e.note != "")
}

@(test)
test_user_profile_path_class :: proc(t: ^testing.T) {
	p := user_profile_build("client\nremote a.example\nca /etc/ca.crt\nconfig other.ovpn\nlog /var/log/x\ncd /tmp\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	for name in ([?]string{"ca", "config", "log", "cd"}) {
		expect_problem(t, &p, name, "path")
	}
	pr, _ := find_problem(&p, "ca")
	testing.expect_value(t, pr.line, 3)
}

@(test)
test_user_profile_inline_only :: proc(t: ^testing.T) {
	text := `client
remote a.example 1194 tcp
ca ca.pem
cert c.pem
key k.pem
tls-crypt t.key
tls-auth t.key 1
tls-crypt-v2 t2.key
crl-verify crl.pem
crl-verify /crls dir
auth-user-pass creds.txt
http-proxy proxy.example 3128 authfile.txt
http-proxy-user-pass pass.txt
extra-certs more.pem
`
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	// `auth-user-pass FILE` is the one form that passes (see below).
	testing.expect_value(t, len(p.problems), 11)
	for pr in p.problems {
		testing.expect_value(t, pr.class, "path")
		testing.expect(t, pr.option != "auth-user-pass")
	}
	// The forms that name no file are fine.
	ok_text := `client
remote a.example 1194 tcp
http-proxy proxy.example 3128 auto
http-proxy proxy.example 3128 none
auth-user-pass
auth-user-pass username-only
peer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
`
	q := user_profile_build(ok_text)
	defer user_profile_destroy(&q)
	for pr in q.problems {
		testing.expectf(t, pr.line == 0 || pr.line > 100, "unexpected problem: %v", pr)
	}
	for e in q.entries {
		testing.expect(t, e.name != "")
	}
	testing.expect_value(t, len(q.entries), 7)
	// An inline block is fine.
	r := user_profile_build("client\nremote a.example\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n<crl-verify>\nCRL\n</crl-verify>\n<ca>\nCA\n</ca>\n")
	defer user_profile_destroy(&r)
	for pr in r.problems {
		testing.expectf(t, pr.class != "path", "unexpected problem: %v", pr)
	}
	testing.expect_value(t, len(r.entries), 5)
}

@(test)
test_user_profile_service_class :: proc(t: ^testing.T) {
	text := `client
remote a.example
bus-allow uid 1000 operator
bus-control /tmp/x
datapath udco
workers 2
user nobody
client-service
setenv opt bus-allow uid 0 admin
`
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	for name in ([?]string{"bus-allow", "bus-control", "datapath", "workers", "user", "client-service"}) {
		expect_problem(t, &p, name, "service")
	}
	// The setenv line is checked as the option inside it.
	n := 0
	for pr in p.problems {
		if pr.line == 9 {
			n += 1
			testing.expect_value(t, pr.option, "bus-allow")
			testing.expect_value(t, pr.class, "service")
		}
	}
	testing.expect_value(t, n, 1)
	// A profile with client-service does not become a base config.
	testing.expect(t, !p.cfg.client.service)
	testing.expect_value(t, len(p.cfg.client.bus_allow), 0)
	testing.expect_value(t, p.cfg.client.workers, 0)
}

@(test)
test_user_profile_server_and_unsupported :: proc(t: ^testing.T) {
	p := user_profile_build("client\nremote a.example\nserver 10.8.0.0 255.255.255.0\nup /bin/x\ncomp-lzo\nsocks-proxy h 1080\nauth-token abc\n")
	defer user_profile_destroy(&p)
	expect_problem(t, &p, "server", "server_only")
	expect_problem(t, &p, "up", "not_supported")
	expect_problem(t, &p, "comp-lzo", "not_supported")
	expect_problem(t, &p, "socks-proxy", "not_supported")
	expect_problem(t, &p, "auth-token", "not_supported")
	pr, _ := find_problem(&p, "up")
	testing.expect(t, strings.contains(pr.reason, "scripts"))
	testing.expect(t, !p.ok)
}

@(test)
test_user_profile_server_config :: proc(t: ^testing.T) {
	p := user_profile_build("server 10.8.0.0 255.255.255.0\ndev tun\n<ca>\nCA\n</ca>\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	expect_problem(t, &p, "server", "server_only")
	// Global build errors of a refused profile are not listed.
	testing.expect_value(t, len(p.problems), 1)
}

@(test)
test_user_profile_not_a_client :: proc(t: ^testing.T) {
	p := user_profile_build("dev tun\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	testing.expect_value(t, len(p.problems), 1)
	testing.expect_value(t, p.problems[0].class, "invalid")
	testing.expect_value(t, p.problems[0].line, 0)
	// A server role that only a kept option shows.
	q := user_profile_build("mode server\n")
	defer user_profile_destroy(&q)
	testing.expect(t, !q.ok)
	testing.expect(t, len(q.problems) >= 1)
}

@(test)
test_user_profile_unknown :: proc(t: ^testing.T) {
	p := profile("frobnicate 1\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	expect_problem(t, &p, "frobnicate", "unknown")

	q := profile("ignore-unknown-option frobnicate\nfrobnicate 1\nother 2\n")
	defer user_profile_destroy(&q)
	expect_problem(t, &q, "other", "unknown")
	testing.expect_value(t, len(q.problems), 1)
	e, found := find_entry(&q, "frobnicate")
	testing.expect(t, found && e.ignored)

	r := profile("setenv FORWARD_COMPATIBLE 1\nfrobnicate 1\nother 2\n")
	defer user_profile_destroy(&r)
	testing.expectf(t, r.ok, "problems: %v", r.problems)
	e, found = find_entry(&r, "other")
	testing.expect(t, found && e.ignored)

	s := profile("setenv opt frobnicate 1\n")
	defer user_profile_destroy(&s)
	testing.expectf(t, s.ok, "problems: %v", s.problems)
}

@(test)
test_user_profile_stray_key_text_is_not_echoed :: proc(t: ^testing.T) {
	text := "client\nremote a.example\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----BEGIN PRIVATE KEY-----\n"
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	n := 0
	for pr in p.problems {
		if pr.class != "unknown" {
			continue
		}
		n += 1
		testing.expect_value(t, pr.option, "?")
		testing.expect(t, !strings.contains(pr.reason, "MIIE"))
	}
	testing.expect_value(t, n, 2)
}

@(test)
test_user_profile_ignored_have_no_effect :: proc(t: ^testing.T) {
	p := profile("verb 9\nmlock\ndisable-dco\ndaemon\nnice 5\nsetenv opt verb 11\nsetenv FOO bar\n")
	defer user_profile_destroy(&p)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	testing.expect_value(t, p.cfg.client.verb, 1)
	testing.expect(t, !p.cfg.client.mlock)
	testing.expect_value(t, p.cfg.client.datapath, Datapath.Userspace)
	testing.expect_value(t, p.cfg.client.writepid, "")
	for name in ([?]string{"verb", "mlock", "daemon", "nice"}) {
		e, found := find_entry(&p, name)
		testing.expectf(t, found && e.ignored, "'%s' is not an ignored entry", name)
	}
	// disable-dco is kept: the connections of the profile run without DCO.
	dd, dd_found := find_entry(&p, "disable-dco")
	testing.expect(t, dd_found && !dd.ignored && dd.note == DISABLE_DCO_NOTE)
	testing.expect(t, p.cfg.client.disable_dco)
	// The GUI decides IV_SSO (the `sso` argument), not the profile.
	s := profile("setenv IV_SSO webauth\n")
	defer user_profile_destroy(&s)
	testing.expectf(t, s.ok, "problems: %v", s.problems)
	testing.expect_value(t, s.cfg.client.iv_sso, "")
	e, found := find_entry(&s, "setenv")
	testing.expect(t, found && e.ignored && strings.contains(e.note, "web sign-in"), "setenv IV_SSO is not ignored in a profile")
	// disable-dco does not conflict with the data path of the service.
	q := user_profile_build("client\nremote a.example\ndisable-dco\ndatapath udco\n<ca>\nCA\n</ca>\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n")
	defer user_profile_destroy(&q)
	testing.expect_value(t, len(q.problems), 1)
	expect_problem(t, &q, "datapath", "service")
}

@(test)
test_user_profile_all_problems_in_one_pass :: proc(t: ^testing.T) {
	text := `client
remote a.example
ca /etc/ca.crt
up /bin/x
bus-control off
frobnicate
route 10.0.0.0 bogus
verb 4
`
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	// Four class problems, and the build error of a kept line.
	testing.expect_value(t, len(p.problems), 5)
	last := 0
	for pr in p.problems {
		testing.expect(t, pr.line >= last)
		last = pr.line
	}
	expect_problem(t, &p, "route", "invalid")
	pr, _ := find_problem(&p, "route")
	testing.expect_value(t, pr.line, 7)
	// "no ca" and the like are a result of the removed lines: not reported.
	for q in p.problems {
		testing.expect(t, q.line > 0)
	}
}

@(test)
test_user_profile_build_errors_are_invalid :: proc(t: ^testing.T) {
	p := profile("route 10.0.0.0 bogus\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	testing.expect_value(t, len(p.problems), 1)
	testing.expect_value(t, p.problems[0].class, "invalid")
	testing.expect_value(t, p.problems[0].option, "route")
	testing.expect(t, p.problems[0].line > 0)
	// Without a refused option the global errors show.
	q := user_profile_build("client\n")
	defer user_profile_destroy(&q)
	testing.expect(t, !q.ok)
	found := false
	for pr in q.problems {
		testing.expect_value(t, pr.class, "invalid")
		if strings.contains(pr.reason, "remote") {
			found = true
		}
	}
	testing.expect(t, found)
}

@(test)
test_user_profile_warning_is_a_note :: proc(t: ^testing.T) {
	p := profile("max-packet-size 99999\n")
	defer user_profile_destroy(&p)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	e, found := find_entry(&p, "max-packet-size")
	testing.expect(t, found)
	testing.expect(t, !e.ignored)
	testing.expect(t, strings.contains(e.note, "2048"))
}

// The DNS lines of the desktop overrides pass the check and reach the client
// config.
@(test)
test_user_profile_dns_override_lines :: proc(t: ^testing.T) {
	lines :: `pull-filter ignore "dhcp-option DNS"
pull-filter ignore "dhcp-option DOMAIN"
pull-filter ignore "dns"
dhcp-option DOMAIN lab.example.org
dns server 0 address 9.9.9.9
dns server 1 address 2620:fe::fe
dns server -1 address 192.0.2.53
dns search-domains home.example
`
	p := profile(lines)
	defer user_profile_destroy(&p)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	testing.expect_value(t, len(p.problems), 0)
	for name in ([]string{"pull-filter", "dhcp-option", "dns"}) {
		e, found := find_entry(&p, name)
		testing.expectf(t, found && !e.ignored, "%s: found %v, ignored %v", name, found, e.ignored)
	}
	testing.expect_value(t, len(p.cfg.client.dns_options), 5)
	testing.expect_value(t, len(p.cfg.client.pull_filters), 3)
}

@(test)
test_user_profile_connection_block_is_checked :: proc(t: ^testing.T) {
	text := `client
<connection>
remote a.example 1194 udp
ca /etc/ca.crt
verb 9
config more.ovpn
</connection>
<connection>
remote b.example 443 tcp
</connection>
<ca>
CA
</ca>
<cert>
C
</cert>
<key>
K
</key>
`
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	expect_problem(t, &p, "ca", "path")
	expect_problem(t, &p, "config", "path")
	pr, _ := find_problem(&p, "ca")
	testing.expect_value(t, pr.line, 4)
	e, found := find_entry(&p, "verb")
	testing.expect(t, found && e.ignored && e.line == 5)
	testing.expect_value(t, len(p.cfg.client.connections), 2)

	q := user_profile_build("client\n<connection>\nremote a.example 1194 udp\n</connection>\n<ca>\nCA\n</ca>\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n")
	defer user_profile_destroy(&q)
	testing.expectf(t, q.ok, "problems: %v", q.problems)
	testing.expect_value(t, len(q.cfg.client.connections), 1)
}

@(test)
test_user_profile_reads_no_file :: proc(t: ^testing.T) {
	base, _ := os.temp_directory(context.temp_allocator)
	path := strings.concatenate({base, "/noir-user-profile-test.conf"}, context.temp_allocator)
	err := os.write_entire_file(path, "remote leaked.example 1194\nverb 9\n")
	testing.expect(t, err == nil)
	defer os.remove(path)

	text := strings.concatenate({"client\nremote a.example\nconfig ", path, "\ncd ", base, "\n"}, context.temp_allocator)
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	expect_problem(t, &p, "config", "path")
	expect_problem(t, &p, "cd", "path")
	for c in p.cfg.client.connections {
		testing.expect(t, c.host != "leaked.example")
	}
	testing.expect_value(t, len(p.cfg.client.connections), 1)
	testing.expect_value(t, p.cfg.client.cd, "")
	testing.expect_value(t, len(p.cfg.parsed.files), 0)

	// The parser does not call a loader in this mode.
	Probe :: struct {
		calls: int,
	}
	probe: Probe
	loader :: proc(user: rawptr, path: string, allocator: mem.Allocator) -> ([]u8, bool) {
		(^Probe)(user).calls += 1
		return nil, false
	}
	parsed := parse_text(text, "x", Parse_Options{no_files = true, loader = loader, loader_data = &probe})
	defer parsed_destroy(&parsed)
	testing.expect_value(t, probe.calls, 0)
	testing.expect_value(t, len(parsed.diags), 0)
	testing.expect_value(t, parsed.directives[2].name, "config")
	testing.expect_value(t, parsed.directives[3].name, "cd")

	// parse_file and parse_args report an error for a file.
	pf := parse_file(path, Parse_Options{no_files = true})
	defer parsed_destroy(&pf)
	testing.expect_value(t, len(pf.directives), 0)
	testing.expect(t, diags_have_error(pf.diags))
}

@(test)
test_user_profile_wipes_memory :: proc(t: ^testing.T) {
	big := strings.repeat("A", 20000, context.temp_allocator)
	text := strings.concatenate(
		{"client\nremote a.example\n<ca>\nCA\n</ca>\n<cert>\nC\n</cert>\n<key>\n", big, "\nSECRET-KEY-TEXT\n</key>\n"},
		context.temp_allocator,
	)
	p := user_profile_build(text)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	key := p.cfg.client.tls.key.data
	testing.expect(t, len(key) > 20000)
	testing.expect(t, strings.contains(key, "SECRET-KEY-TEXT"))
	store_wipe(p.cfg.parsed.store)
	zero := true
	for ch in transmute([]u8)key {
		if ch != 0 {
			zero = false
		}
	}
	testing.expect(t, zero, "the key text was not overwritten")
	user_profile_destroy(&p)
	// A destroyed profile can be destroyed again.
	user_profile_destroy(&p)
}

@(test)
test_user_profile_no_secret_in_text :: proc(t: ^testing.T) {
	// Errors about a line of a block do not repeat the content of the block.
	p := user_profile_build("client\nremote a.example\n<tls-auth>\n</tls-auth>\n<key>\nSECRET-KEY-TEXT\n</key>\nauth-user-pass pw-file\n")
	defer user_profile_destroy(&p)
	for pr in p.problems {
		testing.expect(t, !strings.contains(pr.reason, "SECRET"))
		testing.expect(t, !strings.contains(pr.option, "SECRET"))
	}
	for e in p.entries {
		testing.expect(t, !strings.contains(e.note, "SECRET"))
	}
}

// ----------------------------------------------------------------------------
// The base config of a service (`client-service`)

@(test)
test_service_config_needs_no_profile :: proc(t: ^testing.T) {
	cfg := load("client-service\n")
	defer destroy(&cfg)
	testing.expectf(t, ok(&cfg), "%s", diag_text(cfg.diags))
	testing.expect_value(t, cfg.role, Role.Client)
	testing.expect(t, cfg.client.service)
	testing.expect_value(t, len(cfg.client.connections), 0)
}

@(test)
test_service_config_allowed_options :: proc(t: ^testing.T) {
	text := `client-service
bus-allow uid 1000 operator
bus-control /run/noirvpn/control.sock mode 660 group noirvpn
bus-events /run/noirvpn/events.sock
verb 4
stats-interval 5
workers 2
datapath udco
dco-socket /run/udco/udco.sock
writepid /run/noirvpn/noirvpn.pid
`
	cfg := load(text)
	defer destroy(&cfg)
	testing.expectf(t, ok(&cfg), "%s", diag_text(cfg.diags))
	testing.expect(t, cfg.client.service)
	testing.expect_value(t, cfg.client.verb, 4)
	testing.expect_value(t, cfg.client.workers, 2)
	testing.expect_value(t, cfg.client.datapath, Datapath.Udco)
	testing.expect_value(t, len(cfg.client.bus_allow), 1)
	testing.expect_value(t, cfg.client.stats_interval, 5)
	dis := load("client-service\ndisable-dco\n")
	defer destroy(&dis)
	testing.expectf(t, ok(&dis), "%s", diag_text(dis.diags))
}

@(test)
test_service_config_refuses_profile_options :: proc(t: ^testing.T) {
	cfg := load("client-service\nverb 3\nremote vpn.example.com 1194\nproto udp\n<ca>\nCA\n</ca>\nuser nobody\n")
	defer destroy(&cfg)
	testing.expect(t, !ok(&cfg))
	expect_error(t, cfg.diags, 3, "remote: is a profile option, but a config with client-service can only hold service settings")
	expect_error(t, cfg.diags, 4, "proto: is a profile option")
	expect_error(t, cfg.diags, 5, "ca: is a profile option")
	expect_error(t, cfg.diags, 8, "user: is a profile option")
	testing.expect(t, !has_diag(cfg.diags, .Error, 2, ""))

	blk := load("client-service\n<connection>\nremote a.example\n</connection>\n")
	defer destroy(&blk)
	expect_error(t, blk.diags, 2, "connection: is a profile option")

	unk := load("client-service\nfrobnicate\n")
	defer destroy(&unk)
	expect_error(t, unk.diags, 2, "unknown option")
}

@(test)
test_service_config_with_server_directive :: proc(t: ^testing.T) {
	cfg := load("client-service\nserver 10.8.0.0 255.255.255.0\n")
	defer destroy(&cfg)
	testing.expect(t, !ok(&cfg))
}

@(test)
test_ordinary_client_config_is_unchanged :: proc(t: ^testing.T) {
	cfg := load_client("")
	defer destroy(&cfg)
	testing.expect(t, ok(&cfg))
	testing.expect(t, !cfg.client.service)
	testing.expect_value(t, len(cfg.client.connections), 1)
	// Without client-service a client still needs a remote and a key.
	bare := load("client\n")
	defer destroy(&bare)
	testing.expect(t, !ok(&bare))
	expect_error(t, bare.diags, 0, "at least one `remote`")
	expect_error(t, bare.diags, 0, "no way to verify the server")
}

@(test)
test_client_service_option_row :: proc(t: ^testing.T) {
	o := option_find("client-service")
	testing.expect(t, o != nil)
	if o != nil {
		testing.expect_value(t, o.disp, Disposition.New)
		testing.expect_value(t, o.applies, Applies.Client)
		testing.expect_value(t, o.max_args, 0)
	}
}

// ---- network rules ----

@(test)
test_user_dev_name_rules :: proc(t: ^testing.T) {
	good := [?]string{"tun", "tun5", "work0", "a", "0vpn", "my-vpn_1.x", "abcdefghijklmno"}
	for n in good {
		testing.expectf(t, user_dev_problem(n) == "", "%q should be valid", n)
	}
	bad := [?]string{"", "abcdefghijklmnop", "-a", "_a", ".a", "a b", "a/b", "a:b", "t\xc3\xbcn", "a\"b", "a;b", "a$b"}
	for n in bad {
		testing.expectf(t, user_dev_problem(n) != "", "%q should be refused", n)
	}
}

// A profile that is complete except for the extra lines, so that only the lines under test fail.
@(private = "file")
NET_BASE :: "client\nremote a.example\n<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n"

@(private = "file")
net_profile :: proc(extra: string) -> User_Profile {
	return user_profile_build(strings.concatenate({NET_BASE, extra}, context.temp_allocator))
}

@(test)
test_user_profile_dev_name :: proc(t: ^testing.T) {
	for dev in ([]string{"tun", "work0", "noir7", "tun5"}) {
		p := net_profile(strings.concatenate({"dev ", dev, "\n"}, context.temp_allocator))
		testing.expectf(t, p.ok, "dev %s: %v", dev, p.problems)
		user_profile_destroy(&p)
	}
	p := net_profile("dev bad/name\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	expect_problem(t, &p, "dev", "network")
	pr, _ := find_problem(&p, "dev")
	testing.expect_value(t, pr.line, 12)

	long := net_profile("dev abcdefghijklmnop\n")
	defer user_profile_destroy(&long)
	expect_problem(t, &long, "dev", "network")
}

@(test)
test_user_profile_low_port :: proc(t: ^testing.T) {
	refused := [?]string {
		"local 192.0.2.1\nlport 80\n",
		"local 192.0.2.1 80\n",
		"lport 80\nlocal 192.0.2.1\n",
		"local 192.0.2.1\nport 443\n",
		"local 192.0.2.1\nlport 1023\n",
		"remote b.example 1194\nlocal 192.0.2.1 22\n",
	}
	for extra in refused {
		p := net_profile(extra)
		testing.expectf(t, !p.ok, "%q should be refused", extra)
		found := false
		for pr in p.problems {
			if pr.class == "network" {
				found = true
			}
		}
		testing.expectf(t, found, "%q: no problem of class network: %v", extra, p.problems)
		user_profile_destroy(&p)
	}
	accepted := [?]string {
		"port 443\n",
		"lport 80\n",
		"nobind\nlport 80\n",
		"local 192.0.2.1\nnobind\nlport 80\n",
		"local 192.0.2.1 80\nnobind\n",
		"local 192.0.2.1\nlport 1024\n",
		"local 192.0.2.1\nlport 0\n",
		"local 192.0.2.1 0\n",
		"local 192.0.2.1\n",
	}
	for extra in accepted {
		p := net_profile(extra)
		testing.expectf(t, p.ok, "%q should be accepted: %v", extra, p.problems)
		user_profile_destroy(&p)
	}
}

@(test)
test_user_profile_low_port_line :: proc(t: ^testing.T) {
	p := net_profile("local 192.0.2.1\nlport 80\n")
	defer user_profile_destroy(&p)
	pr, found := find_problem(&p, "lport")
	testing.expect(t, found)
	testing.expect_value(t, pr.line, 13)
	testing.expect_value(t, pr.class, "network")

	blk := "client\n<connection>\nremote a.example\nlocal 192.0.2.1\nlport 80\n</connection>\n<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n"
	q := user_profile_build(blk)
	defer user_profile_destroy(&q)
	pr, found = find_problem(&q, "lport")
	testing.expect(t, found)
	testing.expect_value(t, pr.line, 5)
}

@(test)
test_user_profile_route_table :: proc(t: ^testing.T) {
	for tab in ([]string{"253", "255"}) {
		p := net_profile(strings.concatenate({"route-table ", tab, "\n"}, context.temp_allocator))
		testing.expectf(t, !p.ok, "route-table %s should be refused", tab)
		expect_problem(t, &p, "route-table", "network")
		pr, _ := find_problem(&p, "route-table")
		testing.expect_value(t, pr.line, 12)
		user_profile_destroy(&p)
	}
	for tab in ([]string{"1", "100", "252", "254", "256", "2147483647"}) {
		p := net_profile(strings.concatenate({"route-table ", tab, "\n"}, context.temp_allocator))
		testing.expectf(t, p.ok, "route-table %s should be accepted: %v", tab, p.problems)
		user_profile_destroy(&p)
	}
}

@(test)
test_user_profile_network_in_one_pass :: proc(t: ^testing.T) {
	p := net_profile("dev bad/name\nroute-table 255\nlocal 192.0.2.1\nlport 80\nlog /tmp/x\nfrobnicate\n")
	defer user_profile_destroy(&p)
	testing.expect(t, !p.ok)
	expect_problem(t, &p, "dev", "network")
	expect_problem(t, &p, "route-table", "network")
	expect_problem(t, &p, "lport", "network")
	expect_problem(t, &p, "log", "path")
	expect_problem(t, &p, "frobnicate", "unknown")
	// In the order of the lines.
	last := 0
	for pr in p.problems {
		testing.expect(t, pr.line >= last)
		last = pr.line
	}
}

@(test)
test_config_file_has_no_network_rules :: proc(t: ^testing.T) {
	// The common build gives no diagnostic for these lines.
	cfg := load_client("route-table 253\nlocal 192.0.2.1\nlport 80\n")
	defer destroy(&cfg)
	testing.expectf(t, ok(&cfg), "%s", diag_text(cfg.diags))
	cfg2 := load_client("dev-type tun\ndev a/b\nroute-table 255\n")
	defer destroy(&cfg2)
	testing.expectf(t, ok(&cfg2), "%s", diag_text(cfg2.diags))
	testing.expect_value(t, cfg2.client.route_table, 255)
	// The common build still wants a name that starts with tun.
	cfg3 := load_client("dev work0\n")
	defer destroy(&cfg3)
	testing.expect(t, !ok(&cfg3))
}

@(test)
test_user_profile_block_ipv6 :: proc(t: ^testing.T) {
	p := profile("block-ipv6\n")
	defer user_profile_destroy(&p)
	testing.expectf(t, p.ok, "problems: %v", p.problems)
	testing.expect(t, p.cfg.client.block_ipv6)
	e, found := find_entry(&p, "block-ipv6")
	testing.expect(t, found && !e.ignored)
}

// `auth-user-pass FILE` and `askpass FILE`: the desktop app reads the file. The
// service accepts the line, never opens the path, builds the form with no file.
// On mobile both stay refused.
@(test)
test_user_profile_secret_files :: proc(t: ^testing.T) {
	text := "client\nremote a.example 1194 tcp\npeer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\nauth-user-pass /etc/shadow\naskpass /root/pass.txt\n"
	p := user_profile_build(text)
	defer user_profile_destroy(&p)
	testing.expectf(t, len(p.problems) == 0, "%v", p.problems)
	notes := 0
	for e in p.entries {
		if e.name == "auth-user-pass" || e.name == "askpass" {
			testing.expect(t, !e.ignored)
			testing.expect_value(t, e.note, SECRET_FILE_NOTE)
			notes += 1
		}
	}
	testing.expect_value(t, notes, 2)
	aup, has := p.cfg.client.auth_user_pass.?
	testing.expect(t, has && !aup.is_inline && aup.file == "")
	ap, has_ap := p.cfg.client.tls.askpass.?
	testing.expect(t, has_ap && ap == "")
	for d in p.cfg.parsed.directives {
		if d.name == "auth-user-pass" || d.name == "askpass" {
			testing.expect_value(t, len(d.args), 0)
		}
	}

	m := user_profile_build_for(text, true)
	defer user_profile_destroy(&m)
	testing.expect_value(t, len(m.problems), 2)
	for pr in m.problems {
		testing.expect_value(t, pr.class, "path")
	}

	// `setenv opt` gives no way around the rule.
	q := user_profile_build("client\nremote a.example 1194 tcp\npeer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\nsetenv opt auth-user-pass /etc/shadow\n")
	defer user_profile_destroy(&q)
	testing.expect_value(t, len(q.problems), 1)
	testing.expect_value(t, q.problems[0].class, "path")
}

// `disable-dco` in a profile: kept on desktop (runs without DCO), ignored on
// mobile and through setenv. Without it the profile cannot ask for DCO
// (`datapath` is a service setting).
@(test)
test_user_profile_disable_dco :: proc(t: ^testing.T) {
	base := "client\nremote a.example\npeer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\nauth-user-pass\n"
	off := user_profile_build(strings.concatenate({base, "disable-dco\n"}, context.temp_allocator))
	defer user_profile_destroy(&off)
	testing.expectf(t, len(off.problems) == 0, "%v", off.problems)
	testing.expect(t, off.cfg.client.disable_dco)

	plain := user_profile_build(base)
	defer user_profile_destroy(&plain)
	testing.expect(t, !plain.cfg.client.disable_dco)

	m := user_profile_build_for(strings.concatenate({base, "disable-dco\n"}, context.temp_allocator), true)
	defer user_profile_destroy(&m)
	testing.expect(t, !m.cfg.client.disable_dco)
	e, found := find_entry(&m, "disable-dco")
	testing.expect(t, found && e.ignored)

	sv := user_profile_build(strings.concatenate({base, "setenv opt disable-dco\n"}, context.temp_allocator))
	defer user_profile_destroy(&sv)
	testing.expect(t, !sv.cfg.client.disable_dco)

	on := user_profile_build(strings.concatenate({base, "datapath dco\n"}, context.temp_allocator))
	defer user_profile_destroy(&on)
	expect_problem(t, &on, "datapath", "service")

	// A config file: disable-dco is datapath userspace, as before.
	cfg := load_client("disable-dco\n")
	defer destroy(&cfg)
	testing.expect_value(t, cfg.client.datapath, Datapath.Userspace)
	testing.expect(t, cfg.client.disable_dco)
}
