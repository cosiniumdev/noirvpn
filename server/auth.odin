// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:time"
import "noir:proto/config"
import "noir:proto/ossl"

// Who is this client, and may it connect now?
//
// The daemon calls `auth_decide` after TLS, with the client key, certificate
// name, TLS result and optional username. Results:
//   Accept           - with the identity
//   Reject           - with a reason and how to tell the client
//   Pending_Password - the hash file must check the password first
//   Pending_External - a bus controller must decide first
// The password never reaches this package, only `has_password`, so it cannot be
// stored.
//
// Proofs the config accepts (`Auth_Policy.proofs`):
//   Pin       `peer-keys`: key in the peers file and not disabled
//   Chain     `ca`: certificate has a chain to the CA
//   Password  `peer-passwords`: user name and password pass the hash file
//             (`auth-external` also checks a password, but a controller does)
//
// Certificate rules, by config:
//   pins only       Key must be in the peers file and not disabled. Identity is
//                   the entry username. A client username must match; none is
//                   fine. Certificate name ignored.
//   chain only      Identity is the certificate name (CN, or `x509-username-field`,
//                   extracted by the session layer). TLS must have verified the
//                   chain (`proof`), else refused. Client username ignored unless
//                   a password is checked.
//   fingerprint     `peer-fingerprint`: TLS enforces it. Identity as chain only.
//   chain and pin   `peer-keys-mode both`: both required. Identity is the pinned
//                   username. Names are not compared: the CA vouches for the
//                   key, the peers file says whose it is, so a re-issued
//                   certificate with another CN keeps its user.
//   pin, else chain `peer-keys-mode either`: a key in the peers file is judged as
//                   pins only (a disabled key is refused, no fallback to the
//                   chain). Any other key: as chain only.
//
// Password rules, with a password source (`peer-passwords` or `auth-external`;
// `verify-client-cert optional` always has one):
//   certificate passes, password sent
//       Username must equal the certificate identity (ASCII case fold), else
//       Username_Mismatch. Hash file: Pending_Password. Only `auth-external`:
//       the controller checks it.
//   certificate passes, no password
//       Hash file and `verify-client-cert require`: Password_Missing. Else
//       accepted by the certificate (`auth-external`: the controller still
//       decides, with an empty password).
//   no certificate (`verify-client-cert optional` only)
//       Needs username and password, else refused before any password source.
//       Identity is the username, never a certificate identity.
// No password source (`verify-client-cert require` only): a password is ignored.
//
// Web sign-in (`auth-web`, needs `auth-external`):
//   - No certificate, no password, `IV_SSO=webauth`: web login. No identity; it
//     waits for the controller (`Decision.web_login`), which names it
//     (`auth_name_web`). Without `auth-web` the client is refused.
//   - A password that looks like a session token is never a password. The daemon
//     checks it and sets `Auth_Input.token`. Valid: token identity, proof
//     `.Token`, controller still decides.
//   - Invalid token, or token-like password with a certificate: `.Token_Invalid`.
//   - No certificate, non-token password: normal path.
//
// The pin lookup repeats the one in TLS on purpose: a bug in either must not let
// a key in.
//
// Hash file (`Pending_Password`):
//   1. The daemon checks username and password. Fail: `server_deny_password`.
//   2. Pass: `auth_password_passed` rechecks limits (the world may have changed)
//      and adds proof `.Password`. Result: Accept, or Pending_External if
//      `auth-external` is also set (hash file first).
//
// `auth-external`: would-be Accept becomes Pending_External with the identity.
//   1. The daemon publishes `peer.auth_pending`, waits up to `external_timeout`.
//   2. Yes: `auth_resume` (rechecks limits). Else `.External_Denied` or
//      `.External_Timeout`.
//
// Limits, in order: `connect-freq` (per source address), `max-clients`,
// `duplicate-cn`. With `duplicate-cn` off, a new session replaces the old
// session(s) of that identity (`kicks`):
//   - login by pinned key: the old session with the same key
//   - any other login: old sessions with no pin proof (see `check_limits`)
// The daemon must remove the kicks (registry_remove, pools release, session
// close) before building the new client's parameters, so the new client can get
// the old address back. Identities compare with ASCII case ignored (`name_equal`).

// A way to prove who the client is.
Proof :: enum u8 {
	Pin,
	Chain,
	Password,
	// A session token that the daemon created for an earlier web sign-in.
	Token,
}

Proof_Set :: bit_set[Proof;u8]

Auth_Policy :: struct {
	// The proofs of the config. `.Pin`: a peers file, or `peer-fingerprint`
	// (`fingerprint`). `.Chain`: a CA. `.Password`: the hash file.
	proofs:           Proof_Set,
	// `peer-keys-mode both`: a certificate needs the chain and the pin.
	both:             bool,
	// `peer-fingerprint`: the pin is a certificate fingerprint that TLS checks;
	// the identity is the certificate name.
	fingerprint:      bool,
	// `verify-client-cert optional`: a client may send no certificate.
	optional:         bool,
	// `duplicate-cn`.
	duplicate_cn:     bool,
	// `max-clients`; 0 = no limit here.
	max_clients:      int,
	// `auth-external` is configured: every accept waits for a controller.
	external:         bool,
	// `auth-web`: a client may wait for a web sign-in, and tokens are in use.
	web:              bool,
	external_timeout: int,
	// `connect-freq` (count per seconds, per source address).
	connect_freq:     config.Rate_Limit,
	connect_freq_set: bool,
}

// The policy a server config asks for. Config checks have already checked
// that the combination is valid (`optional` has a password source, and so on).
auth_policy_from_config :: proc(cfg: ^config.Server_Config) -> (p: Auth_Policy) {
	has_ca := config.key_source_is_set(cfg.tls.ca) || cfg.tls.capath != ""
	switch {
	case cfg.peer_keys != "":
		p.proofs = {.Pin}
		switch cfg.peer_keys_mode {
		case .Pin:
		case .Both:
			p.proofs += {.Chain}
			p.both = true
		case .Either:
			p.proofs += {.Chain}
		}
	case has_ca:
		p.proofs = {.Chain}
	case len(cfg.tls.fingerprints) > 0:
		p.proofs = {.Pin}
		p.fingerprint = true
	case cfg.verify_client_cert == .Optional:
		// Passwords only: the server asks for no certificate, so there is no
		// certificate proof at all.
	case:
		p.proofs = {.Pin} // nothing else can verify a client; the pin store will refuse all
	}
	if cfg.peer_passwords != "" {
		p.proofs += {.Password}
	}
	p.optional = cfg.verify_client_cert == .Optional
	p.web = cfg.auth_web
	p.duplicate_cn = cfg.duplicate_cn
	p.max_clients = cfg.max_clients
	if ae, ok := cfg.auth_external.?; ok {
		p.external = true
		p.external_timeout = ae.timeout
	}
	if cf, ok := cfg.connect_freq.?; ok {
		p.connect_freq, p.connect_freq_set = cf, true
	}
	return
}

// True if the pins alone say who may come in (a pin store with no chain, or a
// chain and a pin both needed). Then the pin of a refused client is worth
// reporting.
auth_pins_decide :: proc "contextless" (p: ^Auth_Policy) -> bool {
	return .Pin in p.proofs && !p.fingerprint && (.Chain not_in p.proofs || p.both)
}

// What the session layer knows when it asks.
Auth_Input :: struct {
	// The client's key, if it sent a certificate.
	key:            ossl.Peer_Key,
	has_key:        bool,
	// The certificate name (CN or `x509-username-field`), "" if none.
	cert_name:      string,
	// What TLS found: `.None` if the client sent no certificate, else the check
	// that let it in (a pin or the chain). These are refused: a key with
	// `.None`, and `.Pin` or `.Chain` with no key.
	proof:          ossl.Peer_Proof,
	// The username of `auth-user-pass`, "" if the client sent none.
	username:       string,
	// The client sent a password. The password itself is not an input.
	has_password:   bool,
	// The client said `IV_SSO=webauth`: it can show a sign-in URL.
	web_auth:       bool,
	// What the daemon found when it looked at the password as a session token
	// (only with `auth-web`). `.None`: it is no token.
	token:          Token_State,
	// `.Valid`: the identity of the token.
	token_identity: string,
	// Where the packets come from.
	src:            Addr_Key,
	// Sessions that wait for a controller (not in the peer table). They count
	// against `max-clients`, so a flood of parked logins cannot fill the server.
	parked:         int,
}

// The password of a login, seen as a session token.
Token_State :: enum u8 {
	None,
	Valid,
	Invalid,
}

Decision_Kind :: enum u8 {
	Reject,
	Accept,
	// The hash file must check the username and password first. The identity
	// is set. Go on with `auth_password_passed`, or refuse with
	// `server_deny_password`.
	Pending_Password,
	// A controller must decide. The identity is set.
	Pending_External,
}

// Where the identity came from.
Identity_Source :: enum u8 {
	None,
	Pin,
	Cert_Name,
	Username,
	// The controller named the client (web sign-in), or a token that it
	// allowed earlier did.
	Controller,
}

MAX_KICKS :: 4

Decision :: struct {
	kind:             Decision_Kind,
	identity:         Identity,
	source:           Identity_Source,
	// Accept: the key it came with. Pass it on in the `Connect_Request`.
	spki:             [config.PIN_LEN]u8,
	pinned:           bool,
	// Either mode: the chain let the key in (it is not pinned). A peers file
	// that later lists the key as disabled, or under another name, ends the session.
	by_chain:         bool,
	// The proofs that passed so far (for the events). `.Password` joins the set
	// in `auth_password_passed`. A password that only a controller checks is
	// not in the set.
	proofs:           Proof_Set,
	reject:           Reject,
	// Sessions to remove before this one is built (duplicate-cn off).
	kicks:            [MAX_KICKS]Peer_Handle,
	n_kicks:          int,
	// Pending_External: seconds to wait for the controller.
	external_timeout: int,
	// A web login: no identity yet. The controller names the client when it
	// allows the login (`auth_name_web`).
	web_login:        bool,
}

Auth_Stats :: struct {
	accepted: u64,
	// Decisions that wait for a controller.
	pending:  u64,
	// Decisions that wait for the hash file check.
	pending_password: u64,
	rejected: [Reject_Reason]u64,
}

Auth_State :: struct {
	policy:    Auth_Policy,
	// nil unless the policy uses pins.
	pins:      ^Pin_Store,
	limiter:   Rate_Limiter,
	stats:     Auth_Stats,
	allocator: mem.Allocator,
}

auth_init :: proc(
	a: ^Auth_State,
	policy: Auth_Policy,
	pins: ^Pin_Store,
	rate_sources := DEFAULT_RATE_SOURCES,
	hash_seed: u64 = 0,
	allocator := context.allocator,
) -> bool {
	a^ = {}
	a.policy = policy
	a.pins = pins
	a.allocator = allocator
	per := Rate_Params{}
	if policy.connect_freq_set {
		per = Rate_Params{policy.connect_freq.count, policy.connect_freq.seconds}
	}
	return rate_limiter_init(&a.limiter, per, {}, rate_sources, hash_seed, allocator)
}

auth_destroy :: proc(a: ^Auth_State) {
	rate_limiter_destroy(&a.limiter)
	a^ = {}
}

@(private)
reject_with :: proc(a: ^Auth_State, reason: Reject_Reason) -> Decision {
	a.stats.rejected[reason] += 1
	return Decision{kind = .Reject, reject = reject_make(reason)}
}

// Decides. `pt` is the peer table, for `max-clients` and `duplicate-cn`.
auth_decide :: proc(a: ^Auth_State, pt: ^Peer_Table, in_: Auth_Input, now: time.Duration) -> Decision {
	// The rate limit first, and for every attempt: a flood of bad logins must
	// not be free.
	if a.policy.connect_freq_set && !rate_limiter_allow(&a.limiter, rate_key(in_.src), now) {
		return reject_with(a, .Rate_Limited)
	}
	d, ok := identify(a, in_)
	if !ok {
		return d
	}
	need_password := d.kind == .Pending_Password
	if (d.web_login || .Token in d.proofs) && !a.policy.external {
		// Only a controller can end a web sign-in. The config checks ensure this
		// impossible; refuse to be safe.
		return reject_with(a, .Internal)
	}
	r := check_limits(a, pt, d, in_.parked)
	if r.kind == .Reject {
		return r
	}
	// Kicks are worked out again when the password check or the controller has
	// replied.
	switch {
	case need_password:
		a.stats.pending_password += 1
		r.n_kicks = 0
		r.kind = .Pending_Password
		return r
	case a.policy.external:
		a.stats.pending += 1
		r.n_kicks = 0
		r.kind = .Pending_External
		r.external_timeout = a.policy.external_timeout
		return r
	}
	a.stats.accepted += 1
	return r
}

// After the hash file said yes to a `.Pending_Password` decision. Adds the
// proof, rechecks the limits (`connect-freq` is not charged again) and fills in
// the kicks.
// - With `auth-external`: `.Pending_External`, the controller decides next.
// - `parked`: number of OTHER sessions waiting for a controller.
// - `form`: the user name as the hash file spells it, "" if none. A client with
//   no certificate takes it as identity (must match, ASCII case ignored).
auth_password_passed :: proc(a: ^Auth_State, pt: ^Peer_Table, d: Decision, form := "", parked := 0) -> Decision {
	if d.kind != .Pending_Password {
		return reject_known(a, d, .Internal)
	}
	d := d
	d.proofs += {.Password}
	if form != "" && d.source == .Username {
		if !name_equal(form, identity_str(&d.identity)) {
			return reject_known(a, d, .Internal)
		}
		id, valid := identity_make(form)
		if !valid {
			return reject_known(a, d, .Bad_Identity)
		}
		d.identity = id
	}
	r := check_limits(a, pt, d, parked)
	if r.kind == .Reject {
		return r
	}
	if a.policy.external {
		a.stats.pending += 1
		r.n_kicks = 0
		r.kind = .Pending_External
		r.external_timeout = a.policy.external_timeout
		return r
	}
	a.stats.accepted += 1
	return r
}

// After a controller said yes. Checks the limits again (`connect-freq` is not
// charged a second time) and fills in the kicks. `parked` is the number of
// OTHER sessions that wait for a controller (not this one).
auth_resume :: proc(a: ^Auth_State, pt: ^Peer_Table, d: Decision, parked := 0) -> Decision {
	if d.web_login || d.identity.len == 0 {
		// A web login has no identity until the controller names it.
		return reject_known(a, d, .No_Identity)
	}
	r := check_limits(a, pt, d, parked)
	if r.kind != .Reject {
		a.stats.accepted += 1
	}
	return r
}

// The controller names the client of a web login. A name that is not a valid
// identity is refused (`.Bad_Identity`). A decision that is not a web login is
// refused too: it has an identity already, and this one must not replace it.
auth_name_web :: proc(a: ^Auth_State, d: Decision, name: string) -> Decision {
	if !d.web_login || d.identity.len > 0 {
		return reject_known(a, d, .Internal)
	}
	id, valid := identity_make(name)
	if !valid {
		return reject_known(a, d, .Bad_Identity)
	}
	d := d
	d.identity, d.source, d.web_login = id, .Controller, false
	return d
}

// What identifies a client that has a certificate: the proof, the identity and
// the key. Then the password rules. A decision of kind `.Accept` or
// `.Pending_Password` comes back with `ok`. The limits are not checked yet.
@(private)
identify :: proc(a: ^Auth_State, in_: Auth_Input) -> (d: Decision, ok: bool) {
	switch {
	case in_.has_key && in_.proof == .None:
		// A certificate that no check vouched for.
		return reject_with(a, no_cert_reason(&a.policy)), false
	case !in_.has_key && in_.proof != .None:
		return reject_with(a, .Internal), false
	case !in_.has_key:
		return identify_without_certificate(a, in_)
	}
	d, ok = identify_certificate(a, in_)
	if !ok {
		return
	}
	if a.policy.web && in_.token != .None {
		// Tokens are for logins with no certificate. A password of this form
		// never goes to the hash file.
		return reject_known(a, d, .Token_Invalid), false
	}
	return password_rules(a, in_, d)
}

// The reason to give when a certificate is missing or nothing vouched for it.
@(private)
no_cert_reason :: proc "contextless" (p: ^Auth_Policy) -> Reject_Reason {
	if p.fingerprint || (.Chain in p.proofs && .Pin not_in p.proofs) {
		return .Chain_Not_Verified
	}
	return .Key_Not_Pinned
}

// Is there a password source: the hash file, or a controller?
@(private)
has_password_source :: proc "contextless" (p: ^Auth_Policy) -> bool {
	return .Password in p.proofs || p.external
}

// A client that sent no certificate. Only `verify-client-cert optional` goes
// on. The client needs a username and a password. Its identity is the
// username. Nothing here gives it a certificate identity.
@(private)
identify_without_certificate :: proc(a: ^Auth_State, in_: Auth_Input) -> (d: Decision, ok: bool) {
	p := &a.policy
	switch {
	case !p.optional:
		return reject_with(a, no_cert_reason(p)), false
	case p.web && in_.token == .Invalid:
		return reject_with(a, .Token_Invalid), false
	case p.web && in_.token == .Valid:
		id, valid := identity_make(in_.token_identity)
		if !valid {
			return reject_with(a, .Token_Invalid), false
		}
		d.identity, d.source, d.proofs = id, .Controller, {.Token}
		d.kind = .Accept
		return d, true
	case p.web && in_.web_auth && !in_.has_password:
		// The client has nothing to show: the controller does a web sign-in.
		d.web_login, d.kind = true, .Accept
		return d, true
	case in_.username == "":
		return reject_with(a, .No_Identity), false
	case !has_password_source(p):
		// The config checks cannot allow this; refuse to be safe.
		return reject_with(a, .Internal), false
	case !in_.has_password:
		return reject_with(a, .Password_Missing), false
	}
	id, valid := identity_make(in_.username)
	if !valid {
		return reject_with(a, .Bad_Identity), false
	}
	d.identity, d.source = id, .Username
	d.kind = .Pending_Password if .Password in p.proofs else .Accept
	return d, true
}

// A client with a certificate that TLS accepted: who it is, by the pins and
// the chain of the config. The username rule of pins is here. The rules of a
// password are in `password_rules`.
@(private)
identify_certificate :: proc(a: ^Auth_State, in_: Auth_Input) -> (d: Decision, ok: bool) {
	p := &a.policy
	pins := .Pin in p.proofs && !p.fingerprint
	chain := .Chain in p.proofs
	chain_ok := in_.proof == .Chain
	switch {
	case pins:
		if chain && p.both && !chain_ok {
			return reject_with(a, .Chain_Not_Verified), false
		}
		e: ^config.Peer_Entry
		if a.pins != nil {
			if t := pin_store_current(a.pins); t != nil {
				e = pin_table_find(t, in_.key.spki_sha256)
			}
		}
		if e == nil && chain && !p.both {
			// Not pinned: the chain decides.
			if !chain_ok {
				return reject_with(a, .Chain_Not_Verified), false
			}
			if in_.cert_name == "" {
				return reject_with(a, .No_Identity), false
			}
			id, valid := identity_make(in_.cert_name)
			if !valid {
				return reject_with(a, .Bad_Identity), false
			}
			d.identity, d.source = id, .Cert_Name
			d.spki, d.by_chain = in_.key.spki_sha256, true
			d.proofs = {.Chain}
		} else {
			switch {
			case e == nil:
				return reject_with(a, .Key_Not_Pinned), false
			case e.disabled || e.client.disable:
				return reject_with(a, .Key_Disabled), false
			}
			if in_.username != "" && !name_equal(in_.username, e.user) {
				return reject_with(a, .Username_Mismatch), false
			}
			id, valid := identity_make(e.user)
			if !valid {
				return reject_with(a, .Bad_Identity), false
			}
			d.identity, d.source = id, .Pin
			d.spki, d.pinned = in_.key.spki_sha256, true
			d.proofs = {.Pin, .Chain} if chain && p.both else {.Pin}
		}
	case chain || p.fingerprint:
		// The chain, or the fingerprint that TLS enforces.
		if !chain_ok && !(p.fingerprint && in_.proof == .Pin) {
			return reject_with(a, .Chain_Not_Verified), false
		}
		if in_.cert_name == "" {
			return reject_with(a, .No_Identity), false
		}
		id, valid := identity_make(in_.cert_name)
		if !valid {
			return reject_with(a, .Bad_Identity), false
		}
		d.identity, d.source = id, .Cert_Name
		d.spki = in_.key.spki_sha256
		d.proofs = {.Chain} if chain_ok else {.Pin}
	case:
		// Nothing in the config can verify a certificate.
		return reject_with(a, .Key_Not_Pinned), false
	}
	d.kind = .Accept
	return d, true
}

// The username and password of a client whose certificate passed. See the
// rules at the top of this file.
@(private)
password_rules :: proc(a: ^Auth_State, in_: Auth_Input, d: Decision) -> (r: Decision, ok: bool) {
	p := &a.policy
	r = d
	if !has_password_source(p) {
		// The password that the client sends is not looked at.
		return r, true
	}
	if !in_.has_password {
		if .Password in p.proofs && !p.optional {
			// The hash file checks each client and this one sent no password.
			return reject_known(a, d, .Password_Missing), false
		}
		return r, true
	}
	// Both are checked: the username must be the identity of the certificate.
	if !name_equal(in_.username, identity_str(&r.identity)) {
		return reject_known(a, d, .Username_Mismatch), false
	}
	if .Password in p.proofs {
		r.kind = .Pending_Password
	}
	return r, true
}

// `max-clients` and `duplicate-cn`. Returns an Accept with the kicks filled in,
// or a Reject.
// Without `duplicate-cn`, the old sessions to end depend on the login:
//   login by pin    - sessions with this same key. Another key of the name stays
//                     (one session per system), and so does any session with no
//                     pin proof.
//   any other login - sessions with no pin proof (chain, password, token,
//                     controller). A pin session stays.
// A session with a pin proof and a password proof is a pin session.
@(private)
check_limits :: proc(a: ^Auth_State, pt: ^Peer_Table, d: Decision, parked := 0) -> Decision {
	d := d
	d.kind = .Accept
	d.n_kicks = 0
	name := identity_str(&d.identity)
	if !a.policy.duplicate_cn && d.identity.len > 0 {
		found: [MAX_KICKS + 1]Peer_Handle
		n := 0
		h, p := peers_by_identity(pt, name)
		for p != nil {
			key := pt.keys[h.index]
			if d.pinned ? (key.pinned && key.spki == d.spki) : !key.pinned {
				if n >= len(found) {
					// More old sessions than the daemon should ever have: do not guess.
					return reject_known(a, d, .Internal)
				}
				found[n] = h
				n += 1
			}
			h, p = peers_next_same_identity(pt, h)
		}
		if n > MAX_KICKS {
			return reject_known(a, d, .Internal)
		}
		for i in 0 ..< n {
			d.kicks[i] = found[i]
		}
		d.n_kicks = n
	}
	if a.policy.max_clients > 0 && peers_count(pt) + parked - d.n_kicks >= a.policy.max_clients {
		return reject_known(a, d, .Max_Clients)
	}
	return d
}

// A reject after the client was identified: the identity, key and source stay
// in the decision, so the daemon can say who was refused.
@(private)
reject_known :: proc(a: ^Auth_State, d: Decision, reason: Reject_Reason) -> Decision {
	r := reject_with(a, reason)
	r.identity, r.source, r.spki, r.pinned, r.proofs = d.identity, d.source, d.spki, d.pinned, d.proofs
	return r
}
