// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "core:fmt"
import "core:os"
import "core:time"
import "noir:proto/config"
import "noir:proto/ossl"
import "noir:proto/session"

// `crl-verify`: revocation lists for peer certificates in the control channel TLS
// (server checks client certs, client checks the server cert).
//
// File mode: the daemon reads the file at start. Before each new TLS session
// (connection or renegotiation) `crl_prepare` looks at the file (at most once a
// second); if it changed, the list is read again and every TLS context gets a
// new store. If the file is unreadable or has no CRL, the list is lost: every
// peer certificate is refused until a later read works. The check runs in the
// verify path of the TLS contexts (`ossl.tls_ctx_crl_lost`).
//
// Directory mode (`crl-verify DIR dir`): a certificate is revoked if a file named
// by its serial number in decimal is in DIR.
//
// Runs on the thread that runs TLS handshakes (main thread; crypto workers only
// seal and open data packets), with no context change during a handshake.

CRL_POLL_NS :: i64(1_000_000_000) // the file is looked at once a second at most

// What `stat` says about the file. `ok` false: the stat failed.
Crl_Stat :: struct {
	ok:       bool,
	mtime_ns: i64,
	size:     i64,
	ino:      u64,
}

Crl_Action :: enum {
	Keep, // nothing to do
	Reload, // read the file
	Lose, // the file is gone: the list is lost
}

// What to do now. `loaded`: stat of the file when the list was read. `lost`:
// no list. `cur`: stat now. A lost list is read again on every call whatever
// the stat says: the file may be fixed with no time change (a permission).
crl_decide :: proc "contextless" (loaded: Crl_Stat, lost: bool, cur: Crl_Stat) -> Crl_Action {
	switch {
	case !cur.ok:
		return .Keep if lost else .Lose
	case lost:
		return .Reload
	case cur != loaded:
		return .Reload
	}
	return .Keep
}

// True when the stat may be done now: never done, or at least `CRL_POLL_NS`
// ago, or the clock went back. Times are monotonic nanoseconds.
crl_poll_due :: proc "contextless" (last_ns, now_ns: i64) -> bool {
	return last_ns == 0 || now_ns < last_ns || now_ns - last_ns >= CRL_POLL_NS
}

Crl_State :: struct {
	on:       bool, // `crl-verify` is set (and applies: there is a chain check)
	server:   bool, // the role, for the texts
	dir:      bool, // directory mode
	inline:   bool, // the list is in the config: never read again
	path:     string, // the file or the directory
	ca_pem:   []u8, // the trust anchors (borrowed from the settings)
	pem:      []u8, // the list that is in force (owned)
	count:    int,
	revision: u64, // grows with each change of the list (and when it is lost)
	lost:     bool,
	loaded:   Crl_Stat,
	last_ns:  i64,
	// The statistics of the last load, for the start line.
	infos:    [CRL_INFO_MAX]ossl.Crl_Info,
}

CRL_INFO_MAX :: 8

crl_destroy :: proc(cs: ^Crl_State) {
	delete(cs.pem)
	cs^ = {}
}

// Reads the setting at start. Adds to `errors` when the file cannot be used
// and to `warnings` for a CRL that is out of date. Returns false on an error.
crl_init :: proc(cs: ^Crl_State, c: config.Crl_Verify, ca_pem: []u8, server: bool, errors, warnings: ^[dynamic]string) -> bool {
	cs^ = {}
	cs.on = true
	cs.server = server
	cs.ca_pem = ca_pem
	cs.revision = 1
	if c.dir {
		cs.dir = true
		cs.path = c.src.path
		if c.src.is_inline || !os.is_dir(c.src.path) {
			append(errors, fmt.aprintf("crl-verify: %s is not a directory", c.src.path if !c.src.is_inline else "an inline block"))
			return false
		}
		return true
	}
	errors_before := len(errors)
	if c.src.is_inline {
		cs.inline = true
	} else {
		cs.path = c.src.path
		cs.loaded = crl_stat(cs.path) // before the read: a change in between is seen at the next look
	}
	cs.pem = read_key_source(errors, c.src, "crl-verify")
	if len(cs.pem) == 0 {
		if len(errors) == errors_before {
			append(errors, fmt.aprintf("crl-verify: %s does not contain a CRL", cs.path if cs.path != "" else "the inline block"))
		}
		return false
	}
	n, ok := ossl.crl_inspect(cs.pem, cs.infos[:])
	if !ok {
		append(errors, fmt.aprintf("crl-verify: %s does not contain a CRL, or its CRL cannot be read", cs.path if cs.path != "" else "the inline block"))
		return false
	}
	cs.count = n
	for info, i in cs.infos {
		if i >= min(n, CRL_INFO_MAX) {
			break
		}
		if info.expired {
			append(warnings, fmt.aprintf("crl-verify: the CRL of %s has expired, so no certificate from that issuer will be accepted until the CRL is replaced", crl_issuer(&cs.infos[i])))
		}
	}
	return true
}

@(private = "file")
crl_issuer :: proc(info: ^ossl.Crl_Info) -> string {
	if info.issuer_len == 0 {
		return "an unnamed issuer"
	}
	return string(info.issuer[:info.issuer_len])
}

// The start line of the log.
crl_log_start :: proc(cs: ^Crl_State) {
	if !cs.on {
		return
	}
	if cs.dir {
		logf(.Info, "crl-verify: revoked certificates will be looked up by serial number in the directory %s", cs.path)
		return
	}
	logf(.Info, "crl-verify: %d CRL(s) loaded from %s", cs.count, cs.path if cs.path != "" else "the config")
}

// ---------------------------------------------------------------- the file

// The list is lost: log it once and let every context refuse.
@(private = "file")
crl_lose :: proc(cs: ^Crl_State, why: string) -> (changed: bool) {
	if cs.lost {
		return false
	}
	cs.lost = true
	cs.revision += 1
	logf(
		.Error,
		"crl-verify: cannot read %s: %s; %s",
		cs.path,
		why,
		"every client will be refused until the list can be loaded" if cs.server else "the server certificate will be refused until the list can be loaded",
	)
	return true
}

// Looks at the file and loads it again when needed. `force`: skip the
// once-a-second limit. Returns true if the list or its state changed.
crl_poll :: proc(cs: ^Crl_State, force := false) -> (changed: bool) {
	if !cs.on || cs.dir || cs.inline {
		return false
	}
	now := time.tick_now()._nsec
	if !force && !crl_poll_due(cs.last_ns, now) {
		return false
	}
	cs.last_ns = now
	cur := crl_stat(cs.path)
	switch crl_decide(cs.loaded, cs.lost, cur) {
	case .Keep:
		return false
	case .Lose:
		return crl_lose(cs, crl_stat_why(cs.path))
	case .Reload:
	}
	data, rerr := os.read_entire_file(cs.path, context.allocator)
	if rerr != nil {
		delete(data)
		return crl_lose(cs, fmt.tprintf("%v", rerr))
	}
	infos: [CRL_INFO_MAX]ossl.Crl_Info
	n, ok := ossl.crl_inspect(data, infos[:])
	if !ok {
		delete(data)
		return crl_lose(cs, "the file does not contain a CRL, or its CRL cannot be read")
	}
	delete(cs.pem)
	cs.pem = data
	cs.count = n
	cs.infos = infos
	cs.loaded = cur
	cs.revision += 1
	was_lost := cs.lost
	cs.lost = false
	if was_lost {
		logf(.Notice, "crl-verify: %s was reloaded: %d CRL(s)", cs.path, n)
	} else {
		logf(.Notice, "crl-verify: %s changed: %d CRL(s) loaded", cs.path, n)
	}
	for i in 0 ..< min(n, CRL_INFO_MAX) {
		if infos[i].expired {
			logf(.Warn, "crl-verify: the CRL of %s has expired, so no certificate from that issuer will be accepted until the CRL is replaced", crl_issuer(&infos[i]))
		}
	}
	return true
}

// The hook of the session layer: runs before each new TLS session. Brings the
// context to the list that is in force.
crl_prepare :: proc(user: rawptr, ctx: ^ossl.Tls_Ctx) {
	cs := (^Crl_State)(user)
	if !cs.on || cs.dir {
		return
	}
	crl_poll(cs)
	if ctx.revision == cs.revision {
		return
	}
	if cs.lost {
		ossl.tls_ctx_crl_lost(ctx)
		ctx.revision = cs.revision
		return
	}
	if err := ossl.tls_ctx_set_crl(ctx, cs.ca_pem, cs.pem, cs.revision); err != .None {
		// Not expected: the list was checked when it was read. Refuse everyone.
		logf(.Error, "crl-verify: the TLS library cannot use the list: %v; every peer certificate will be refused until the list loads", err)
		ossl.tls_ctx_crl_lost(ctx)
		ctx.revision = cs.revision
	}
}

// ------------------------------------------------------------- the directory

// Directory mode: is a file named by the serial number (decimal) in the
// directory? Runs inside the TLS library: must not allocate. Anything but "no
// such file" counts as revoked, so an unsearchable directory refuses everyone.
crl_dir_check :: proc "contextless" (serial_dec: string, depth: int, user: rawptr) -> bool {
	cs := (^Crl_State)(user)
	buf: [4096 + 64]u8
	n := len(cs.path) + 1 + len(serial_dec)
	if len(serial_dec) == 0 || n >= len(buf) {
		return true
	}
	copy(buf[:], cs.path)
	buf[len(cs.path)] = '/'
	copy(buf[len(cs.path) + 1:], serial_dec)
	buf[n] = 0
	return !crl_file_absent(cstring(&buf[0]))
}

// ------------------------------------------------------------- the session

// Puts the settings in a client session config.
crl_client_config :: proc(c: ^session.Config, cs: ^Crl_State) {
	if !cs.on || c.verify != .Chain {
		return
	}
	c.crl_pem = cs.pem
	c.tls_prepare_user = cs
	if cs.dir {
		c.revoked_check = crl_dir_check
		c.revoked_user = cs
		return
	}
	c.tls_prepare = crl_prepare
}

// The same for the session config of a server.
crl_server_config :: proc(c: ^session.Server_Config, cs: ^Crl_State) {
	if !cs.on || (c.verify != .Chain && c.verify != .Pin_Or_Chain) {
		return
	}
	c.crl_pem = cs.pem
	c.tls_prepare_user = cs
	if cs.dir {
		c.revoked_check = crl_dir_check
		c.revoked_user = cs
		return
	}
	c.tls_prepare = crl_prepare
}
