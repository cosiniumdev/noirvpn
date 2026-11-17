// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ossl

import "base:runtime"
import "core:sync"

// TLS over memory BIOs. A session never touches a socket: the caller moves bytes.
//
//	tls_feed(s, bytes)          bytes that arrived from the peer
//	tls_handshake_step(s)       run the handshake as far as it goes
//	tls_pending_out(s)          how many bytes wait to be sent
//	tls_take(s, buf)            copy those bytes out
//
// In the VPN these bytes travel in control-channel packets. After the
// handshake, `tls_write_app` and `tls_read_app` carry application data (push
// messages and the like).
//
// Typical flow:
//
//	ctx, _ := tls_ctx_create({role = .Client, ...})
//	s, _   := tls_session_create(&ctx)
//	for tls_handshake_step(&s) == .Want_More {
//		// send everything tls_take() gives, feed what comes back
//	}
//
// A "link" session uses a custom BIO over a socket (`tls_session_init_link`).
// The BIO calls the hooks of a `Link_Io`: it writes records straight into the
// caller's buffer and reads the socket straight into the library's buffer.
// `tls_feed` and `tls_take` do not apply to it.
//
// Threads: one thread at a time per `Tls_Session`. A `Tls_Ctx` may be shared.

Tls_Role :: enum {
	Client,
	Server,
}

// `Any` as a minimum means TLS 1.2 (our floor); as a maximum it means no limit.
Tls_Version :: enum {
	Any,
	TLS_1_2,
	TLS_1_3,
}

// How the peer certificate is judged.
Peer_Verify :: enum {
	// Normal PKI: the chain must lead to a CA in `Tls_Config.ca_pem`.
	Chain,
	// Key pinning. No chain, date or name check (a self-signed certificate is
	// fine). The peer must still send a certificate (a client too) and prove it
	// holds the private key. `Tls_Config.pin_check` decides during the handshake.
	// A refusal fails it with a TLS alert, so a session at `.Done` passed the pin check.
	Pinned,
	// Nothing is checked. For a transport that another layer authenticates (the
	// outer TLS of the `tls` transport). A server asks no client certificate.
	// A client takes any server certificate (it still proves it holds the key).
	// `tls_peer_key` tells which key it was, so the caller can judge it.
	None,
	// A pin, else a chain. Server only. `Tls_Config.pin_lookup` judges the key first:
	// - pinned: accepted without the chain check (self-signed is fine)
	// - refused by the lookup: fails at once (no fallback to the chain)
	// - any other key: needs a chain to `ca_pem`, with the `.Chain` revocation settings
	// `tls_chain_verified` tells afterwards which one let the peer in.
	Pin_Or_Chain,
}

// What a server knows about the client certificate after the handshake
// (`tls_peer_proof`).
Peer_Proof :: enum u8 {
	// The client sent no certificate (`Tls_Config.client_cert_optional`), or
	// nothing was checked (`.None`).
	None,
	// A pin let the client in: `.Pinned`, or a pinned key of `.Pin_Or_Chain`.
	Pin,
	// The chain to `ca_pem` let the client in.
	Chain,
}

// What `Pin_Lookup` says about a key in `.Pin_Or_Chain` mode.
Pin_Verdict :: enum u8 {
	// Not pinned: the chain decides.
	Unknown,
	// Pinned and allowed.
	Accepted,
	// Pinned and not allowed (a disabled key).
	Refused,
}

// What the pin check sees of the peer's leaf certificate.
Peer_Key :: struct {
	spki_sha256: [SHA256_LEN]u8, // SHA-256 of the DER public key: the pin
	cert_sha256: [SHA256_LEN]u8, // SHA-256 of the whole DER certificate (upstream `peer-fingerprint`)
}

// Decides whether a peer key is accepted in `.Pinned` mode. Runs inside the TLS
// library on the `tls_handshake_step` thread: be quick, never block.
// `user` is `Tls_Config.pin_user`.
Pin_Check :: #type proc "contextless" (peer: Peer_Key, user: rawptr) -> bool

// The pin check of `.Pin_Or_Chain` mode. Same rules as `Pin_Check`.
Pin_Lookup :: #type proc "contextless" (peer: Peer_Key, user: rawptr) -> Pin_Verdict

// The ClientHello definition of a client (a server ignores it). `.Default` is the
// library's. `.Chrome` looks like Chrome's as far as the library allows.
// See README.md, "ClientHello profile".
Hello_Profile :: enum u8 {
	Default,
	Chrome,
}

// Chrome's TLS 1.2 cipher list, in its order (the TLS 1.3 suites come first on
// the wire; see `Tls_Config.tls13_ciphersuites`). Both libraries take this text.
@(private)
CHROME_CIPHERS :: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"

Tls_Config :: struct {
	role:        Tls_Role,
	// Our certificate (leaf first, then chain) and private key, as PEM. A server
	// needs both. A client needs them when the server asks for a client
	// certificate (always, for VPN peers). An encrypted key fails with
	// `.Key_Encrypted`: use `key_pem_decrypt` first.
	cert_pem:    []u8,
	key_pem:     []u8,
	// Key exchange groups, colon separated, e.g. "X25519MLKEM768:X25519".
	// Portable names: X25519MLKEM768, X25519, P-256, P-384, P-521. Both backends
	// also take a leading "*" (OpenSSL: "send this key share at once") and
	// OpenSSL spellings (secp256r1 ...). Empty: library default. See README.md.
	groups:      string,
	min_version: Tls_Version,
	max_version: Tls_Version,
	verify:      Peer_Verify,
	// Server only. Also complete the handshake if the client sends no certificate
	// (`tls_peer_proof` then says `.None`). A certificate that is sent is judged
	// by `verify`, and a bad one ends the handshake. Without this flag a server
	// refuses a client with none. A client gets `.Bad_Config`. `.None` ignores it.
	client_cert_optional: bool,
	// Trust anchors (PEM, one or more certificates) for `.Chain`.
	ca_pem:      []u8,
	// Required for `.Pinned` (else tls_ctx_create fails with `.Bad_Config`).
	// `pin_user` goes to every call and must stay valid for the context's life.
	pin_check:   Pin_Check,
	pin_user:    rawptr,
	// Required for `.Pin_Or_Chain`, with `pin_user`.
	pin_lookup:  Pin_Lookup,
	// Revocation, see crl.odin. `.Chain` and `.Pin_Or_Chain` only.
	// - crl_pem: one or more CRLs. Every chain certificate is checked. An issuer
	//   with no CRL is accepted.
	// - revoked_check: asked about each verified chain certificate. `revoked_user`
	//   goes to it and must stay valid for the context's life.
	// Either one enables `tls_ctx_set_crl` and `tls_ctx_crl_lost`.
	crl_pem:       []u8,
	revoked_check: Revoked_Check,
	revoked_user:  rawptr,
	// Checks on the peer's leaf certificate, after the chain or pin check
	// (`.Chain` and `.Pinned`). See leaf.odin. A failed rule fails the
	// handshake, and `tls_last_error` says why.
	rules:         Leaf_Rules,
	// TLS 1.3 cipher suites in order of preference, colon separated, library
	// names (e.g. "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"). Empty keeps
	// the default. TLS 1.2 suites are not touched.
	tls13_ciphersuites: string,
	// Client ClientHello profile. `.Chrome` replaces the TLS 1.2 cipher list, the
	// signature algorithms and the extensions (as far as the backend allows),
	// and keeps the session ticket extension on. It does not change `groups` or
	// `tls13_ciphersuites`: set them too. Sessions need `tls_session_set_alpn`
	// (and the ALPS setting on AWS-LC).
	hello:      Hello_Profile,
}

Tls_Ctx :: struct {
	ctx:       SSL_CTX,
	role:      Tls_Role,
	hello:     Hello_Profile, // what `tls_ctx_create` applied (`.Default` for a server)
	pin:       ^Pin_Hook, // `.Pinned` and `.Pin_Or_Chain`; the C library holds this pointer
	crl:       ^Crl_Hook, // `.Chain` or `.Pin_Or_Chain` with a CRL list or a `revoked_check`; the C library holds this pointer
	rules:     ^Rules_Hook, // `cfg.rules` were set; the C library holds this pointer
	// Which CRL list the context has: the `revision` of the last `tls_ctx_set_crl`
	// (0 if none). For the caller's own use.
	revision:  u64,
	verify:    Peer_Verify,
	mode:      cint, // the SSL_VERIFY_* mode that was set
	allocator: Maybe(runtime.Allocator),
}

@(private)
Pin_Hook :: struct {
	check:  Pin_Check,
	user:   rawptr,
	// `.Pin_Or_Chain`: the lookup, and the revocation hook of the chain (nil without one).
	lookup: Pin_Lookup,
	crl:    ^Crl_Hook,
}

TLS_ERROR_TEXT_MAX :: 240

Tls_State :: enum {
	Handshaking,
	Established,
	Failed,
}

// What the library may ask of a `Link_Io` read hook, besides a count above 0.
IO_RETRY :: -1 // no bytes now: ask again when the socket is readable
IO_END :: 0 // the end of the stream
IO_ERROR :: -2 // the stream failed; the hook has noted why

// Hooks of a session over a stream. They run inside TLS library calls
// (`tls_read_app` and others) on the calling thread. They are plain C procs: no
// Odin context. `user` goes to each and must stay valid for the session's life.
Link_Io :: struct {
	user:        rawptr,
	// Takes up to `n` bytes the library wants to send. Returns the count taken
	// (0 < r <= n). 0: no room now. The library keeps the rest and offers it again.
	write:       proc "c" (user: rawptr, data: [^]u8, n: int) -> int,
	// Puts up to `n` received bytes at `buf`. Returns the count, or `IO_RETRY`,
	// `IO_END` or `IO_ERROR`.
	read:        proc "c" (user: rawptr, buf: [^]u8, n: int) -> int,
	// Bytes received (fed earlier) and not read yet; bytes written to the hook
	// and not sent yet. Optional: nil counts as 0.
	pending_in:  proc "c" (user: rawptr) -> int,
	pending_out: proc "c" (user: rawptr) -> int,
}

Tls_Session :: struct {
	ssl:     SSL,
	rbio:    BIO, // we write incoming bytes here (owned by `ssl`)
	wbio:    BIO, // we read outgoing bytes from here (owned by `ssl`)
	// A link session: `rbio` and `wbio` are one custom BIO that points to `io`.
	// The session must not move in memory: set it up in place with
	// `tls_session_init_link`, never copy it.
	link:    bool,
	io:      Link_Io,
	state:   Tls_State,
	err:     [TLS_ERROR_TEXT_MAX]u8,
	err_len: int,
	hello:   bool, // the context has the `.Chrome` profile
	either:  bool, // the context has `.Pin_Or_Chain`
	verify:  Peer_Verify, // what the context has
	// Library verify result of a failed handshake (X509_V_ERR_* number, 0 if
	// none), and how many certificates passed for lack of a CRL of their issuer.
	verify_err:  int,
	crl_skipped: int,
	// The handshake failed because the peer's certificate broke a leaf rule.
	rule_failed: bool,
}

Handshake_Status :: enum {
	Want_More, // needs bytes from the peer (send `tls_take` output first)
	Done,
	Failed, // see `tls_last_error`; the alert (if any) is still in `tls_take`
}

Io_Status :: enum {
	Ok,
	Want_More, // no data now; feed more bytes from the peer
	Closed, // the peer sent close_notify
	Failed,
	Not_Ready, // the handshake is not finished
}

// --- context ---

// Builds a TLS context from `cfg`. Session tickets and the session cache are
// off (a VPN renegotiates with a full handshake). The `.Chrome` client profile
// offers the ticket extension, but the cache stays off. In `.Pinned` mode a
// small hook is allocated with `allocator` and freed by `tls_ctx_destroy`.
tls_ctx_create :: proc(cfg: Tls_Config, allocator := context.allocator) -> (ctx: Tls_Ctx, err: Error) {
	ERR_clear_error()
	sc := SSL_CTX_new(TLS_method())
	if sc == nil {
		ERR_clear_error()
		return {}, .Alloc
	}
	defer if err != .None {
		SSL_CTX_free(sc)
		ERR_clear_error()
	}

	if cfg.min_version == .TLS_1_3 && cfg.max_version == .TLS_1_2 {
		return {}, .Bad_Config
	}
	min_v := TLS1_3_VERSION if cfg.min_version == .TLS_1_3 else TLS1_2_VERSION
	if SSL_CTX_set_min_proto_version(sc, min_v) != 1 {
		return {}, .Bad_Config
	}
	switch cfg.max_version {
	case .Any:
	case .TLS_1_2:
		if SSL_CTX_set_max_proto_version(sc, TLS1_2_VERSION) != 1 {
			return {}, .Bad_Config
		}
	case .TLS_1_3:
		if SSL_CTX_set_max_proto_version(sc, TLS1_3_VERSION) != 1 {
			return {}, .Bad_Config
		}
	}
	if !backend_ctx_setup(sc) {
		return {}, .Bad_Config
	}
	// The `.Chrome` profile offers the ticket extension, as a browser does. The
	// session cache stays off, so a ticket that comes back is never used.
	chrome := cfg.hello == .Chrome && cfg.role == .Client
	if !chrome {
		SSL_CTX_set_options(sc, SSL_OP_NO_TICKET)
	}
	SSL_CTX_set_session_cache_mode(sc, SSL_SESS_CACHE_OFF)
	SSL_CTX_set_num_tickets(sc, 0)

	if len(cfg.groups) > 0 {
		buf: [256]u8 // room for a NUL byte
		if len(cfg.groups) >= len(buf) {
			return {}, .Bad_Argument
		}
		copy(buf[:], cfg.groups)
		backend_groups_list(buf[:])
		if SSL_CTX_set1_groups_list(sc, cstring(&buf[0])) != 1 {
			return {}, .Bad_Config
		}
	}

	if len(cfg.tls13_ciphersuites) > 0 {
		buf: [256]u8 // room for a NUL byte
		if len(cfg.tls13_ciphersuites) >= len(buf) {
			return {}, .Bad_Argument
		}
		copy(buf[:], cfg.tls13_ciphersuites)
		if SSL_CTX_set_ciphersuites(sc, cstring(&buf[0])) != 1 {
			return {}, .Bad_Config
		}
	}

	if chrome && !backend_hello_ctx(sc) {
		return {}, .Bad_Config
	}

	if len(cfg.cert_pem) > 0 || len(cfg.key_pem) > 0 || cfg.role == .Server {
		if e := load_identity(sc, cfg.cert_pem, cfg.key_pem); e != .None {
			return {}, e
		}
	}

	hook: ^Pin_Hook
	crl: ^Crl_Hook
	rules: ^Rules_Hook
	defer if err != .None && crl != nil {
		free(crl, allocator)
	}
	defer if err != .None && hook != nil {
		free(hook, allocator)
	}
	defer if err != .None && rules != nil {
		free(rules, allocator)
	}
	verify_cb_fn: verify_cb
	switch cfg.verify {
	case .Chain, .Pin_Or_Chain:
		store := SSL_CTX_get_cert_store(sc)
		if e := add_trust_anchors(store, cfg.ca_pem); e != .None {
			return {}, e
		}
		if len(cfg.crl_pem) > 0 || cfg.revoked_check != nil {
			if len(cfg.crl_pem) > 0 {
				if _, e := add_crls(store, cfg.crl_pem); e != .None {
					return {}, e
				}
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)
			}
			alloc_err: runtime.Allocator_Error
			crl, alloc_err = new(Crl_Hook, allocator)
			if alloc_err != nil {
				return {}, .Alloc
			}
			crl^ = Crl_Hook{cfg.revoked_check, cfg.revoked_user, false}
			SSL_CTX_set_cert_verify_callback(sc, crl_cert_verify, crl)
			verify_cb_fn = crl_verify_cb
		}
		if cfg.verify == .Pin_Or_Chain {
			if cfg.role != .Server || cfg.pin_lookup == nil {
				return {}, .Bad_Config
			}
			alloc_err: runtime.Allocator_Error
			hook, alloc_err = new(Pin_Hook, allocator)
			if alloc_err != nil {
				return {}, .Alloc
			}
			hook^ = Pin_Hook {
				user   = cfg.pin_user,
				lookup = cfg.pin_lookup,
				crl    = crl,
			}
			SSL_CTX_set_cert_verify_callback(sc, either_cert_verify, hook)
		}
	case .None:
	case .Pinned:
		if cfg.pin_check == nil {
			return {}, .Bad_Config // fail closed: pinning without a pin list is an error
		}
		alloc_err: runtime.Allocator_Error
		hook, alloc_err = new(Pin_Hook, allocator)
		if alloc_err != nil {
			return {}, .Alloc
		}
		hook^ = Pin_Hook {
			check = cfg.pin_check,
			user  = cfg.pin_user,
		}
		SSL_CTX_set_cert_verify_callback(sc, check_pin, hook)
	}
	if cfg.verify != .None && leaf_rules_active(cfg.rules) {
		alloc_err: runtime.Allocator_Error
		rules, alloc_err = new(Rules_Hook, allocator)
		if alloc_err != nil {
			return {}, .Alloc
		}
		if e := leaf_hook_fill(&rules.leaf, cfg.rules); e != .None {
			return {}, e
		}
		rules.pin, rules.crl = hook, crl
		SSL_CTX_set_cert_verify_callback(sc, rules_cert_verify, rules)
	}
	// A server always asks the client for a certificate. It refuses a client
	// with none, unless `client_cert_optional` says it may go on.
	if cfg.client_cert_optional && cfg.role != .Server {
		return {}, .Bad_Config
	}
	mode: cint = SSL_VERIFY_PEER
	if cfg.role == .Server && !cfg.client_cert_optional {
		mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	}
	if cfg.verify == .None {
		mode = SSL_VERIFY_NONE
	}
	SSL_CTX_set_verify(sc, mode, verify_cb_fn)

	applied := Hello_Profile.Chrome if chrome else Hello_Profile.Default
	out := Tls_Ctx {
		ctx    = sc,
		role   = cfg.role,
		hello  = applied,
		verify = cfg.verify,
		mode   = mode,
		pin    = hook,
		crl    = crl,
		rules  = rules,
	}
	if hook != nil || crl != nil || rules != nil {
		out.allocator = allocator
	}
	return out, .None
}

// One line that says what the `.Chrome` profile does with the linked library
// and what it cannot do (for the start-up log of a client).
tls_hello_note :: proc() -> string {
	return backend_hello_note()
}

tls_ctx_destroy :: proc(ctx: ^Tls_Ctx) {
	if ctx.ctx != nil {
		SSL_CTX_free(ctx.ctx) // sessions keep their own reference
	}
	// Sessions created from this context also use the hook, so destroy them first.
	if ctx.pin != nil {
		if a, ok := ctx.allocator.?; ok {
			free(ctx.pin, a)
		}
	}
	if ctx.crl != nil {
		if a, ok := ctx.allocator.?; ok {
			free(ctx.crl, a)
		}
	}
	if ctx.rules != nil {
		if a, ok := ctx.allocator.?; ok {
			free(ctx.rules, a)
		}
	}
	ctx^ = {}
}

// Replaces chain verification in `.Pinned` mode: hash the leaf and ask the
// caller's pin check. The handshake's own signature check still runs.
@(private)
check_pin :: proc "c" (store_ctx: X509_STORE_CTX, arg: rawptr) -> cint {
	hook := (^Pin_Hook)(arg)
	x := X509_STORE_CTX_get0_cert(store_ctx) // borrowed
	peer: Peer_Key
	ok1, ok2 := false, false
	if x != nil {
		peer.spki_sha256, ok1 = spki_sha256_of(x)
		peer.cert_sha256, ok2 = cert_sha256_of(x)
	}
	if !ok1 || !ok2 || !hook.check(peer, hook.user) {
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED)
		return 0
	}
	return 1
}

// Replaces chain verification in `.Pin_Or_Chain` mode. A key the lookup accepts
// leaves X509_V_ERR_CERT_UNTRUSTED in the store context, with success. The
// library keeps it as the verify result, and `tls_chain_verified` reads it to
// know that no chain was checked.
@(private)
either_cert_verify :: proc "c" (store_ctx: X509_STORE_CTX, arg: rawptr) -> cint {
	hook := (^Pin_Hook)(arg)
	x := X509_STORE_CTX_get0_cert(store_ctx) // borrowed
	peer: Peer_Key
	ok1, ok2 := false, false
	if x != nil {
		peer.spki_sha256, ok1 = spki_sha256_of(x)
		peer.cert_sha256, ok2 = cert_sha256_of(x)
	}
	if !ok1 || !ok2 {
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED)
		return 0
	}
	switch hook.lookup(peer, hook.user) {
	case .Accepted:
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_UNTRUSTED)
		return 1
	case .Refused:
		X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED)
		return 0
	case .Unknown:
	}
	if hook.crl != nil {
		return crl_cert_verify(store_ctx, hook.crl)
	}
	return 1 if X509_verify_cert(store_ctx) > 0 else 0
}

// `.Pin_Or_Chain` session, after the handshake: true if the chain let the peer
// in, false if its pin did. Other modes: true after any successful handshake.
tls_chain_verified :: proc(s: ^Tls_Session) -> bool {
	return s.ssl != nil && SSL_get_verify_result(s.ssl) == X509_V_OK
}

// Did the peer send a certificate? False before the handshake is done.
tls_peer_has_cert :: proc(s: ^Tls_Session) -> bool {
	if s.ssl == nil {
		return false
	}
	x := peer_cert(s)
	if x == nil {
		return false
	}
	X509_free(x)
	return true
}

// Server session, after the handshake: how the client certificate was accepted.
// `.None` if the client sent none (and in `.None` mode). Fails closed: a
// certificate the chain did not verify is `.None`.
tls_peer_proof :: proc(s: ^Tls_Session) -> Peer_Proof {
	if s.ssl == nil || s.state != .Established {
		return .None
	}
	x := peer_cert(s)
	if x == nil {
		return .None
	}
	X509_free(x)
	switch s.verify {
	case .None:
		return .None
	case .Pinned:
		return .Pin
	case .Chain:
		return .Chain if tls_chain_verified(s) else .None
	case .Pin_Or_Chain:
		return .Chain if tls_chain_verified(s) else .Pin
	}
	return .None
}

// Password callback that never asks. Without it the C library would prompt
// on the terminal for encrypted keys.
@(private)
no_password :: proc "c" (buf: [^]u8, size: cint, rwflag: cint, userdata: rawptr) -> cint {
	return 0
}

@(private)
pem_bio :: proc(pem: []u8) -> BIO {
	if len(pem) == 0 || len(pem) > 1 << 30 {
		return nil
	}
	return BIO_new_mem_buf(raw_data(pem), cint(len(pem)))
}

@(private = "file")
load_identity :: proc(sc: SSL_CTX, cert_pem, key_pem: []u8) -> Error {
	cbio := pem_bio(cert_pem)
	if cbio == nil {
		ERR_clear_error()
		return .Bad_Cert
	}
	defer BIO_free(cbio)

	leaf := PEM_read_bio_X509(cbio, nil, no_password, nil)
	if leaf == nil {
		ERR_clear_error()
		return .Bad_Cert
	}
	defer X509_free(leaf)
	if SSL_CTX_use_certificate(sc, leaf) != 1 {
		ERR_clear_error()
		return .Bad_Cert
	}
	// The rest of the file is the chain. The call takes ownership.
	for {
		extra := PEM_read_bio_X509(cbio, nil, no_password, nil)
		if extra == nil {
			break
		}
		if SSL_CTX_add_extra_chain_cert(sc, extra) != 1 {
			X509_free(extra)
			ERR_clear_error()
			return .Bad_Cert
		}
	}
	ERR_clear_error() // the loop above ends with a "no start line" entry

	kbio := pem_bio(key_pem)
	if kbio == nil {
		ERR_clear_error()
		return .Bad_Key
	}
	defer BIO_free(kbio)
	pkey := PEM_read_bio_PrivateKey(kbio, nil, no_password, nil)
	if pkey == nil {
		ERR_clear_error()
		return .Key_Encrypted if key_pem_encrypted(key_pem) else .Bad_Key
	}
	defer EVP_PKEY_free(pkey)
	if SSL_CTX_use_PrivateKey(sc, pkey) != 1 || SSL_CTX_check_private_key(sc) != 1 {
		ERR_clear_error()
		return .Bad_Key
	}
	return .None
}

@(private)
add_trust_anchors :: proc(store: X509_STORE, ca_pem: []u8) -> Error {
	bio := pem_bio(ca_pem)
	if bio == nil {
		return .Bad_Config
	}
	defer BIO_free(bio)
	count := 0
	for {
		x := PEM_read_bio_X509(bio, nil, no_password, nil)
		if x == nil {
			break
		}
		ok := X509_STORE_add_cert(store, x) == 1
		X509_free(x)
		if !ok {
			ERR_clear_error()
			return .Bad_Config
		}
		count += 1
	}
	ERR_clear_error()
	return .None if count > 0 else .Bad_Config
}

// --- session ---

tls_session_create :: proc(ctx: ^Tls_Ctx) -> (s: Tls_Session, err: Error) {
	if ctx.ctx == nil {
		return {}, .Bad_Argument
	}
	ssl := SSL_new(ctx.ctx)
	rbio := BIO_new(BIO_s_mem())
	wbio := BIO_new(BIO_s_mem())
	if ssl == nil || rbio == nil || wbio == nil {
		if ssl != nil {
			SSL_free(ssl)
		}
		if rbio != nil {
			BIO_free(rbio)
		}
		if wbio != nil {
			BIO_free(wbio)
		}
		ERR_clear_error()
		return {}, .Alloc
	}
	SSL_set_bio(ssl, rbio, wbio) // from now on `ssl` frees both
	switch ctx.role {
	case .Client:
		SSL_set_connect_state(ssl)
	case .Server:
		SSL_set_accept_state(ssl)
	}
	s.ssl = ssl
	s.rbio = rbio
	s.wbio = wbio
	s.either = ctx.verify == .Pin_Or_Chain
	s.verify = ctx.verify
	if ctx.hello == .Chrome {
		s.hello = true
		backend_hello_session(ssl)
	}
	return s, .None
}

// Sets up a session in place on a custom BIO that calls `io`. Otherwise the same
// as `tls_session_create`. The session points to itself (inside the BIO): do
// not copy or move it until `tls_session_destroy`.
tls_session_init_link :: proc(s: ^Tls_Session, ctx: ^Tls_Ctx, io: Link_Io) -> Error {
	if ctx.ctx == nil || io.write == nil || io.read == nil {
		return .Bad_Argument
	}
	s^ = {}
	sync.once_do(&link_method_once, make_link_method)
	if link_method == nil {
		return .Alloc
	}
	ssl := SSL_new(ctx.ctx)
	bio := BIO_new(link_method)
	if ssl == nil || bio == nil {
		if ssl != nil {
			SSL_free(ssl)
		}
		if bio != nil {
			BIO_free(bio)
		}
		ERR_clear_error()
		return .Alloc
	}
	s.io = io
	BIO_set_data(bio, &s.io)
	SSL_set_bio(ssl, bio, bio) // one reference, owned by `ssl`
	// Read what the socket has in one go (up to a record and a bit): one read call
	// for each record.
	SSL_set_read_ahead(ssl, 1)
	switch ctx.role {
	case .Client:
		SSL_set_connect_state(ssl)
	case .Server:
		SSL_set_accept_state(ssl)
	}
	s.ssl = ssl
	s.rbio = bio
	s.wbio = bio
	s.link = true
	s.either = ctx.verify == .Pin_Or_Chain
	s.verify = ctx.verify
	if ctx.hello == .Chrome {
		s.hello = true
		backend_hello_session(ssl)
	}
	return .None
}

// One BIO method for all link sessions, created at the first use. It is never
// freed (it is a few hundred bytes).
@(private = "file")
link_method: BIO_METHOD
@(private = "file")
link_method_once: sync.Once

@(private = "file")
make_link_method :: proc "contextless" () {
	// A fixed type: a source/sink BIO with an index of our own (the library's
	// counter of indexes is small and not meant for one method per session).
	m := BIO_meth_new(BIO_TYPE_SOURCE_SINK | 0x7e, "noirvpn link")
	if m == nil {
		return
	}
	ok := BIO_meth_set_write(m, link_bio_write) == 1
	ok &&= BIO_meth_set_read(m, link_bio_read) == 1
	ok &&= BIO_meth_set_ctrl(m, link_bio_ctrl) == 1
	ok &&= BIO_meth_set_create(m, link_bio_create) == 1
	ok &&= BIO_meth_set_destroy(m, link_bio_destroy) == 1
	if !ok {
		BIO_meth_free(m)
		return
	}
	link_method = m
}

// The BIO callbacks. They run inside the C library and touch only the hooks.

@(private = "file")
link_io_of :: proc "contextless" (b: BIO) -> ^Link_Io {
	return (^Link_Io)(BIO_get_data(b))
}

@(private = "file")
link_bio_create :: proc "c" (b: BIO) -> cint {
	BIO_set_init(b, 1)
	return 1
}

@(private = "file")
link_bio_destroy :: proc "c" (b: BIO) -> cint {
	BIO_set_init(b, 0)
	BIO_set_data(b, nil)
	return 1
}

@(private = "file")
link_bio_write :: proc "c" (b: BIO, data: [^]u8, n: cint) -> cint {
	bio_clear_retry(b)
	io := link_io_of(b)
	if io == nil || n <= 0 {
		return 0
	}
	r := io.write(io.user, data, int(n))
	if r <= 0 {
		// No room: the library keeps the record and tries again later.
		bio_retry_write(b)
		return -1
	}
	return cint(min(r, int(n)))
}

@(private = "file")
link_bio_read :: proc "c" (b: BIO, buf: [^]u8, n: cint) -> cint {
	bio_clear_retry(b)
	io := link_io_of(b)
	if io == nil || n <= 0 {
		return 0
	}
	r := io.read(io.user, buf, int(n))
	switch {
	case r > 0:
		return cint(min(r, int(n)))
	case r == IO_RETRY:
		bio_retry_read(b)
		return -1
	case r == IO_END:
		return 0
	}
	return -1 // a failure: no retry flag
}

@(private = "file")
link_bio_ctrl :: proc "c" (b: BIO, cmd: cint, larg: clong, parg: rawptr) -> clong {
	io := link_io_of(b)
	switch cmd {
	case BIO_CTRL_FLUSH:
		return 1 // the bytes are the hook's: nothing to flush here
	case BIO_CTRL_PENDING:
		if io != nil && io.pending_in != nil {
			return clong(io.pending_in(io.user))
		}
	case BIO_CTRL_WPENDING:
		if io != nil && io.pending_out != nil {
			return clong(io.pending_out(io.user))
		}
	}
	return 0
}

tls_session_destroy :: proc(s: ^Tls_Session) {
	if s.ssl != nil {
		SSL_free(s.ssl)
	}
	s^ = {}
}

// Longest server name or ALPN list the setters below take.
TLS_NAME_MAX :: 255

// Client: the server name in the ClientHello (SNI). A host name only (RFC 6066
// bars an IP literal). False if empty, too long, has a NUL byte, or the library
// refuses.
tls_session_set_sni :: proc(s: ^Tls_Session, name: string) -> bool {
	if len(name) == 0 || len(name) > TLS_NAME_MAX {
		return false
	}
	buf: [TLS_NAME_MAX + 1]u8
	for c, i in transmute([]u8)name {
		if c == 0 {
			return false
		}
		buf[i] = c
	}
	ok := SSL_set_tlsext_host_name(s.ssl, cstring(&buf[0])) == 1
	if !ok {
		ERR_clear_error()
	}
	return ok
}

// Client: the ALPN protocols the ClientHello offers, most wanted first (e.g.
// {"http/1.1"}). A server ignores what it is offered. False if a name is empty
// or over 255 bytes, the list is too long, or the library refuses.
tls_session_set_alpn :: proc(s: ^Tls_Session, protos: []string) -> bool {
	wire: [TLS_NAME_MAX + 1]u8
	n := 0
	for p in protos {
		if len(p) == 0 || len(p) > TLS_NAME_MAX || n + 1 + len(p) > len(wire) {
			return false
		}
		wire[n] = u8(len(p))
		copy(wire[n + 1:], p)
		n += 1 + len(p)
	}
	ok := SSL_set_alpn_protos(s.ssl, raw_data(wire[:]), n) == 1
	if ok && s.hello {
		ok = backend_hello_alpn(s.ssl, protos)
	}
	if !ok {
		ERR_clear_error()
	}
	return ok
}

// The ALPN protocol the server chose, e.g. "h2". Empty if the client offered
// none or the server chose none. Valid until the session ends.
tls_alpn_selected :: proc(s: ^Tls_Session) -> string {
	data: [^]u8
	n: cuint
	SSL_get0_alpn_selected(s.ssl, &data, &n)
	if data == nil || n == 0 {
		return ""
	}
	return string(data[:n])
}

// Gives the session bytes that arrived from the peer. False only if the C
// library cannot store them (out of memory), and always for a link session
// (it reads from its `Link_Io`).
tls_feed :: proc(s: ^Tls_Session, data: []u8) -> bool {
	if s.link {
		return len(data) == 0
	}
	if len(data) == 0 {
		return true
	}
	if len(data) > 1 << 30 {
		return false
	}
	return BIO_write(s.rbio, raw_data(data), cint(len(data))) == cint(len(data))
}

// Bytes the session wants to send. A link session writes to its `Link_Io` at
// once, so this counts what that hook reports as unsent.
tls_pending_out :: proc(s: ^Tls_Session) -> int {
	if s.link {
		return s.io.pending_out(s.io.user) if s.io.pending_out != nil else 0
	}
	return bio_pending(s.wbio)
}

// Copies up to len(out) waiting bytes and returns the count. Call it until
// `tls_pending_out` is 0. The caller cuts the bytes into packets. A link
// session has nothing to take: 0.
tls_take :: proc(s: ^Tls_Session, out: []u8) -> int {
	if s.link {
		return 0
	}
	n := min(len(out), tls_pending_out(s), 1 << 30)
	if n == 0 {
		return 0
	}
	r := BIO_read(s.wbio, raw_data(out), cint(n))
	return int(r) if r > 0 else 0
}

// Runs the handshake as far as the fed bytes allow. Call it after every
// `tls_feed` and once at the start of a client session. Output bytes may wait
// in `tls_take` whatever it returns.
tls_handshake_step :: proc(s: ^Tls_Session) -> Handshake_Status {
	switch s.state {
	case .Established:
		return .Done
	case .Failed:
		return .Failed
	case .Handshaking:
	}
	ERR_clear_error()
	verify_note = {}
	crl_skipped = 0
	ret := SSL_do_handshake(s.ssl)
	s.crl_skipped += crl_skipped
	if ret == 1 {
		s.state = .Established
		return .Done
	}
	switch SSL_get_error(s.ssl, ret) {
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		return .Want_More
	}
	fail(s)
	return .Failed
}

tls_state :: proc(s: ^Tls_Session) -> Tls_State {
	return s.state
}

// The first error the C library reported for this session, as text.
// Valid until the session changes or is destroyed. Empty if none.
tls_last_error :: proc(s: ^Tls_Session) -> string {
	return string(s.err[:s.err_len])
}

@(private = "file")
fail :: proc(s: ^Tls_Session) {
	s.state = .Failed
	if e := ERR_get_error(); e != 0 {
		ERR_error_string_n(e, &s.err[0], len(s.err))
		for s.err_len < len(s.err) && s.err[s.err_len] != 0 {
			s.err_len += 1
		}
	}
	ERR_clear_error()
	// A pinned key in `.Pin_Or_Chain` mode leaves CERT_UNTRUSTED: it is not the cause.
	if vr := SSL_get_verify_result(s.ssl); vr != X509_V_OK && !(s.either && vr == X509_V_ERR_CERT_UNTRUSTED) {
		s.verify_err = int(vr)
		s.rule_failed = verify_note.set && verify_note.rule != .None && verify_note.err == cint(vr)
		verify_text(s, int(vr))
	}
	verify_note = {}
}

// Adds `text` to the error text of the session, as far as it fits.
@(private)
err_put :: proc(s: ^Tls_Session, text: string) {
	n := min(len(text), len(s.err) - s.err_len)
	copy(s.err[s.err_len:], text[:n])
	s.err_len += n
}

// Our text for a failed certificate check: the library's message plus what the
// verify callbacks saw (name, serial, place in the chain). Replaces the library's.
@(private = "file")
verify_text :: proc(s: ^Tls_Session, vr: int) {
	note := &verify_note
	s.err_len = 0
	put :: err_put
	if vr != X509_V_ERR_CERT_REVOKED {
		put(s, "certificate verify failed: ")
	}
	switch {
	case note.set && note.lost:
		put(s, "the CRL is not loaded")
		return
	case s.rule_failed:
		rule_text(s, note)
	case vr == X509_V_ERR_CRL_HAS_EXPIRED:
		put(s, "the CRL has expired")
	case:
		put(s, string(X509_verify_cert_error_string(clong(vr))))
	}
	if note.set && note.err == cint(vr) {
		put(s, " (")
		if note.cn_len > 0 {
			put(s, "CN ")
			put(s, string(note.cn[:note.cn_len]))
			put(s, ", ")
		}
		if note.serial_len > 0 {
			put(s, "serial ")
			put(s, string(note.serial[:note.serial_len]))
			put(s, ", ")
		}
		put(s, "depth ")
		if note.depth >= 10 {
			put(s, "9+")
		} else {
			num := [1]u8{u8('0' + note.depth)}
			put(s, string(num[:]))
		}
		put(s, ")")
	}
}

// True if the handshake failed because a certificate is revoked.
tls_cert_revoked :: proc(s: ^Tls_Session) -> bool {
	return s.verify_err == X509_V_ERR_CERT_REVOKED
}

// True if the handshake failed because of the CRL list itself: it is lost, a
// CRL has expired, is not valid yet or has a bad signature.
tls_crl_failed :: proc(s: ^Tls_Session) -> bool {
	switch s.verify_err {
	case X509_V_ERR_UNABLE_TO_GET_CRL, 8, 11, X509_V_ERR_CRL_HAS_EXPIRED, 33:
		return true // 8 CRL signature failure, 11 CRL not yet valid, 33 unable to get CRL issuer
	}
	return false
}

// --- application data ---

// Reads decrypted application data. `n` bytes were copied to `buf`.
// This also processes post-handshake messages from the peer.
tls_read_app :: proc(s: ^Tls_Session, buf: []u8) -> (n: int, status: Io_Status) {
	if s.state != .Established {
		return 0, .Failed if s.state == .Failed else .Not_Ready
	}
	if len(buf) == 0 {
		return 0, .Ok
	}
	ERR_clear_error()
	ret := SSL_read(s.ssl, raw_data(buf), cint(min(len(buf), 1 << 30)))
	if ret > 0 {
		return int(ret), .Ok
	}
	switch SSL_get_error(s.ssl, ret) {
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		return 0, .Want_More
	case SSL_ERROR_ZERO_RETURN:
		return 0, .Closed
	}
	fail(s)
	return 0, .Failed
}

// Encrypts application data.
// - `.Ok`: all of `data` was taken. Get the bytes from `tls_take` (a link
//   session already handed them to its `Link_Io`).
// - `.Want_More`: link session only, its hook had no room. The library keeps the
//   record. Repeat the same call when there is room.
tls_write_app :: proc(s: ^Tls_Session, data: []u8) -> Io_Status {
	if s.state != .Established {
		return .Failed if s.state == .Failed else .Not_Ready
	}
	if len(data) == 0 {
		return .Ok
	}
	if len(data) > 1 << 30 {
		return .Failed
	}
	ERR_clear_error()
	ret := SSL_write(s.ssl, raw_data(data), cint(len(data)))
	if ret == cint(len(data)) {
		return .Ok
	}
	if ret <= 0 && SSL_get_error(s.ssl, ret) == SSL_ERROR_WANT_WRITE {
		// Link session, hook had no room. The library keeps the record and wants
		// the same call again. The caller must free room first (see `Link_Io.write`).
		return .Want_More
	}
	fail(s)
	return .Failed
}

// --- key export and peer identity ---

// RFC 5705 / RFC 8446 section 7.5 exporter, with no context. Fills `out`.
// Both sides get the same bytes. Returns false before the handshake is done.
tls_export_keying_material :: proc(s: ^Tls_Session, label: string, out: []u8) -> bool {
	if s.state != .Established || len(out) == 0 {
		return false
	}
	ERR_clear_error()
	r := SSL_export_keying_material(s.ssl, raw_data(out), csize(len(out)), raw_data(label), csize(len(label)), nil, 0, 0)
	if r != 1 {
		ERR_clear_error()
	}
	return r == 1
}

// Largest SubjectPublicKeyInfo we accept. ML-DSA-87 is about 2.6 kB and
// RSA-8192 about 1.1 kB.
SPKI_MAX :: 8192

// SHA-256 over the DER SubjectPublicKeyInfo of the peer's certificate: the pin.
// It stays the same if the peer re-issues the certificate with the same key.
// `ok` is false if the peer sent no certificate.
tls_peer_spki_sha256 :: proc(s: ^Tls_Session) -> (hash: [SHA256_LEN]u8, ok: bool) {
	x := peer_cert(s)
	if x == nil {
		return
	}
	defer X509_free(x)
	return spki_sha256_of(x)
}

// SHA-256 over the whole DER certificate of the peer. This is what upstream
// `peer-fingerprint` compares. `ok` is false if the peer sent no certificate.
tls_peer_cert_sha256 :: proc(s: ^Tls_Session) -> (hash: [SHA256_LEN]u8, ok: bool) {
	x := peer_cert(s)
	if x == nil {
		return
	}
	defer X509_free(x)
	return cert_sha256_of(x)
}

// What the peer's leaf certificate holds: the pin and certificate hash (as
// `Pin_Check` gets). `ok` is false if there is no certificate (a client never
// asked, or before the handshake).
tls_peer_key :: proc(s: ^Tls_Session) -> (key: Peer_Key, ok: bool) {
	x := peer_cert(s)
	if x == nil {
		return
	}
	defer X509_free(x)
	ok1, ok2: bool
	key.spki_sha256, ok1 = spki_sha256_of(x)
	key.cert_sha256, ok2 = cert_sha256_of(x)
	if !ok1 || !ok2 {
		return {}, false
	}
	return key, true
}

// Longest common name `tls_peer_common_name` returns (the X.520 limit is 64).
COMMON_NAME_MAX :: 64

// The subject common name (CN) of the peer's leaf certificate, copied into
// `buf`. It is peer text: in `.Chain` mode the CA vouched for it, in `.Pinned`
// mode nobody did, so use it as a label only. `ok` is false if:
// - no certificate, no CN, or more than one CN
// - the CN is not a UTF8String, PrintableString or IA5String
// - it has a NUL byte, is empty, or does not fit `buf`
tls_peer_common_name :: proc(s: ^Tls_Session, buf: []u8) -> (n: int, ok: bool) {
	x := peer_cert(s)
	if x == nil {
		return
	}
	defer X509_free(x)
	return common_name_of(x, buf)
}

@(private)
common_name_of :: proc "contextless" (x: X509, buf: []u8) -> (n: int, ok: bool) {
	name := X509_get_subject_name(x) // borrowed from `x`
	if name == nil {
		return
	}
	first := X509_NAME_get_index_by_NID(name, NID_COMMON_NAME, -1)
	if first < 0 || X509_NAME_get_index_by_NID(name, NID_COMMON_NAME, first) >= 0 {
		return
	}
	entry := X509_NAME_get_entry(name, first)
	if entry == nil {
		return
	}
	str := X509_NAME_ENTRY_get_data(entry)
	if str == nil {
		return
	}
	// ASN.1 string types: 12 UTF8String, 19 PrintableString, 22 IA5String.
	switch ASN1_STRING_type(str) {
	case 12, 19, 22:
	case:
		return
	}
	l := int(ASN1_STRING_length(str))
	data := ASN1_STRING_get0_data(str)
	if l <= 0 || l > len(buf) || data == nil {
		return
	}
	for i in 0 ..< l {
		if data[i] == 0 {
			return
		}
	}
	copy(buf[:l], data[:l])
	return l, true
}

// The peer's leaf certificate serial as big-endian bytes with no leading zero
// (serial 0 is 0 bytes), copied into `out`. `ok` is false if there is no
// certificate, or the serial is negative or over `SERIAL_BYTES_MAX` bytes.
tls_peer_serial :: proc(s: ^Tls_Session, out: ^[SERIAL_BYTES_MAX]u8) -> (n: int, ok: bool) {
	x := peer_cert(s)
	if x == nil {
		return
	}
	defer X509_free(x)
	return serial_bytes_of(x, out)
}

@(private)
serial_bytes_of :: proc "contextless" (x: X509, out: ^[SERIAL_BYTES_MAX]u8) -> (n: int, ok: bool) {
	sn := X509_get0_serialNumber(x) // borrowed from `x`
	if sn == nil || ASN1_STRING_type(sn) != 2 { // V_ASN1_INTEGER; 0x102 is a negative one
		return
	}
	data := ASN1_STRING_get0_data(sn)
	l := int(ASN1_STRING_length(sn))
	if data == nil || l < 0 {
		return
	}
	start := 0
	for start < l && data[start] == 0 {
		start += 1
	}
	if l - start > SERIAL_BYTES_MAX {
		return
	}
	for i in start ..< l {
		out[i - start] = data[i]
	}
	return l - start, true
}

@(private = "file")
spki_sha256_of :: proc "contextless" (x: X509) -> (hash: [SHA256_LEN]u8, ok: bool) {
	pkey := X509_get0_pubkey(x) // borrowed from `x`
	if pkey == nil {
		ERR_clear_error()
		return
	}

	n := i2d_PUBKEY(pkey, nil) // size only
	if n <= 0 || n > SPKI_MAX {
		ERR_clear_error()
		return
	}
	buf: [SPKI_MAX]u8
	p := raw_data(buf[:])
	if i2d_PUBKEY(pkey, &p) != n {
		ERR_clear_error()
		return
	}
	return sha256(buf[:n]), true
}

@(private = "file")
cert_sha256_of :: proc "contextless" (x: X509) -> (hash: [SHA256_LEN]u8, ok: bool) {
	n: cuint
	if X509_digest(x, EVP_sha256(), &hash[0], &n) != 1 || n != SHA256_LEN {
		ERR_clear_error()
		return {}, false
	}
	return hash, true
}

// A server: the name the client put in its SNI extension, or "" if it sent
// none. Text from the peer. The string is valid until the session changes.
tls_server_name :: proc(s: ^Tls_Session) -> string {
	name := SSL_get_servername(s.ssl, 0) // TLSEXT_NAMETYPE_host_name
	return string(name) if name != nil else ""
}

// Name of the cipher suite in use, e.g. "TLS_AES_128_GCM_SHA256". Empty
// before the handshake is done. The string is a constant of the library.
tls_cipher_name :: proc(s: ^Tls_Session) -> string {
	if s.state != .Established {
		return ""
	}
	c := SSL_get_current_cipher(s.ssl)
	if c == nil {
		return ""
	}
	return string(SSL_CIPHER_get_name(c))
}

// Queues a close_notify alert (read it with `tls_take`). Best effort: it does not
// wait for the peer's. False if the handshake is not done or the library refuses.
tls_shutdown :: proc(s: ^Tls_Session) -> bool {
	if s.state != .Established {
		return false
	}
	ERR_clear_error()
	r := SSL_shutdown(s.ssl)
	if r < 0 {
		ERR_clear_error()
	}
	return r >= 0
}

// True if `tls_read_app` has data without more peer bytes: decrypted bytes
// wait, or fed bytes not decrypted yet (maybe only part of a record, then the
// next read says `.Want_More`). A link session also counts bytes the library
// read ahead from the socket.
tls_has_input :: proc(s: ^Tls_Session) -> bool {
	if s.link && SSL_has_pending(s.ssl) > 0 {
		return true
	}
	return SSL_pending(s.ssl) > 0 || bio_pending(s.rbio) > 0
}

// Is the session TLS 1.3 (the only version with a key update)?
tls_is_tls13 :: proc(s: ^Tls_Session) -> bool {
	return s.state == .Established && tls_version_name(s) == "TLSv1.3"
}

// Updates our sending keys (TLS 1.3, RFC 8446 section 4.6.3) without asking the
// peer to do the same. The KeyUpdate goes out with the next `tls_write_app`,
// ahead of its data. False for TLS 1.2, a session not established, or a library
// refusal. Peer key updates need no call: `tls_read_app` takes them in.
tls_key_update :: proc(s: ^Tls_Session) -> bool {
	if !tls_is_tls13(s) {
		return false
	}
	ERR_clear_error()
	ok := SSL_key_update(s.ssl, SSL_KEY_UPDATE_NOT_REQUESTED) == 1
	if !ok {
		ERR_clear_error()
	}
	return ok
}

// What kind of public key a certificate has.
Key_Kind :: enum {
	Invalid, // not a certificate we can read
	Rsa,
	Ec, // ECDSA (a NIST curve)
	Ed25519,
	Other, // anything else, ML-DSA among it
}

// The kind of the public key of the first certificate in `cert_pem`.
cert_key_kind :: proc(cert_pem: []u8) -> Key_Kind {
	bio := pem_bio(cert_pem)
	if bio == nil {
		ERR_clear_error()
		return .Invalid
	}
	defer BIO_free(bio)
	x := PEM_read_bio_X509(bio, nil, no_password, nil)
	if x == nil {
		ERR_clear_error()
		return .Invalid
	}
	defer X509_free(x)
	pkey := X509_get0_pubkey(x) // borrowed
	if pkey == nil {
		ERR_clear_error()
		return .Invalid
	}
	switch pkey_nid(pkey) {
	case 6, 912: // rsaEncryption, rsassaPss
		return .Rsa
	case 408: // id-ecPublicKey
		return .Ec
	case NID_ED25519:
		return .Ed25519
	}
	return .Other
}

// Protocol version of the session, e.g. "TLSv1.3".
tls_version_name :: proc(s: ^Tls_Session) -> string {
	return string(SSL_get_version(s.ssl))
}

// --- helper for tests and tools ---

// Moves everything `from` wants to send into `to`. Returns the byte count.
tls_move :: proc(from, to: ^Tls_Session) -> int {
	buf: [2048]u8
	total := 0
	for tls_pending_out(from) > 0 {
		n := tls_take(from, buf[:])
		if n == 0 || !tls_feed(to, buf[:n]) {
			break
		}
		total += n
	}
	return total
}

// Runs a whole handshake between two sessions in memory, no sockets.
// Returns the final status of each side.
tls_loopback :: proc(client, server: ^Tls_Session, max_rounds := 32) -> (cs, ss: Handshake_Status) {
	cs, ss = .Want_More, .Want_More
	for _ in 0 ..< max_rounds {
		moved := 0
		if cs == .Want_More {
			cs = tls_handshake_step(client)
		}
		moved += tls_move(client, server)
		if ss == .Want_More {
			ss = tls_handshake_step(server)
		}
		moved += tls_move(server, client)
		if cs != .Want_More && ss != .Want_More {
			break
		}
		if moved == 0 {
			break // stuck: nobody has anything to send
		}
	}
	return
}
