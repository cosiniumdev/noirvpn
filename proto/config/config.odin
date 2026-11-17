// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package config reads noirvpn configuration: upstream-style config syntax, the
// option table, typed client and server settings, and the peers file.
//
// Layers, from bytes to settings:
//
//   lexer.odin     one config line -> tokens (quotes, backslashes, comments)
//   parser.odin    files, inline <blocks>, includes, command line -> `Parsed`
//   table.odin     one row per upstream option, with its disposition
//   build*.odin    `Parsed` -> `Config` (Client_Config or Server_Config), checked
//   peers.odin     the peers file (`peer-keys`)
//   check.odin     the --check-config report
//
// Typical use:
//
//   parsed := config.parse_file("/etc/noirvpn/server.conf")
//   cfg    := config.build(parsed)      // takes ownership of `parsed`
//   defer config.destroy(&cfg)
//   if !config.ok(&cfg) {
//       // print config.format_diagnostics(cfg.diags)
//   }
//
// Memory: every result owns one arena on the caller's allocator. `destroy`
// frees it all. Strings and slices in a result stay valid until then. Destroy
// is safe after errors too.
//
// No environment reads, no global state. File access goes through a `Loader`
// (a mobile host can supply its own).
package config

import "core:mem"

// ----------------------------------------------------------------------------
// Diagnostics

Severity :: enum u8 {
	Error,
	Warning,
}

// An error or warning with the place that caused it.
Diagnostic :: struct {
	severity: Severity,
	// Config file name, "<command line>" for argument errors, "" if none.
	file:     string,
	// 1-based line in `file`; for the command line, the 1-based argument index.
	// 0 if there is no position.
	line:     int,
	message:  string,
}

// ----------------------------------------------------------------------------
// Memory

// One growing arena plus the allocator it grows from.
Store :: struct {
	arena:     mem.Dynamic_Arena,
	backing:   mem.Allocator,
	// Set by `store_new` with `wipeable`: every large allocation is listed so
	// that `store_wipe` can reach it.
	wipeable:  bool,
	large:     [dynamic]Large_Alloc,
}

@(private)
Large_Alloc :: struct {
	ptr:  rawptr,
	size: int,
}

// With `wipeable`, `store_wipe` can overwrite all memory of the store.
store_new :: proc(backing: mem.Allocator, wipeable := false) -> ^Store {
	s := new(Store, backing)
	mem.dynamic_arena_init(&s.arena, backing, backing)
	s.backing = backing
	s.wipeable = wipeable
	s.large.allocator = backing
	return s
}

store_allocator :: proc(s: ^Store) -> mem.Allocator {
	if s.wipeable {
		return mem.Allocator{procedure = wipeable_proc, data = s}
	}
	return mem.dynamic_arena_allocator(&s.arena)
}

@(private)
wipeable_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	s := (^Store)(data)
	bytes, err := mem.dynamic_arena_allocator_proc(
		&s.arena,
		mode,
		size,
		alignment,
		old_memory,
		old_size,
		loc,
	)
	if err == nil && size >= s.arena.out_band_size && len(bytes) > 0 {
		#partial switch mode {
		case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
			append(&s.large, Large_Alloc{raw_data(bytes), len(bytes)})
		}
	}
	return bytes, err
}

// Overwrites all memory of a `wipeable` store with zeros. Call it before
// `store_free` when the store held secrets.
store_wipe :: proc(s: ^Store) {
	if s == nil || !s.wipeable {
		return
	}
	a := &s.arena
	if a.current_block != nil {
		mem.zero_explicit(a.current_block, a.block_size)
	}
	for blk in a.used_blocks {
		mem.zero_explicit(blk, a.block_size)
	}
	for blk in a.unused_blocks {
		mem.zero_explicit(blk, a.block_size)
	}
	for l in s.large {
		mem.zero_explicit(l.ptr, l.size)
	}
}

store_free :: proc(s: ^Store) {
	if s == nil {
		return
	}
	backing := s.backing
	delete(s.large)
	mem.dynamic_arena_destroy(&s.arena)
	free(s, backing)
}

// ----------------------------------------------------------------------------
// Parsed syntax

// One directive after lexing. Includes are already expanded in place.
Directive :: struct {
	// Option name without a leading "--".
	name:     string,
	args:     []string,
	file:     string,
	line:     int,
	// Inline block: `<name> ... </name>`. The body has "\n" after every line.
	body:     string,
	has_body: bool,
	// `<connection>` blocks: the directives inside.
	block:    []Directive,
	// Came from the command line.
	cmdline:  bool,
}

// The result of parsing: directives in order, and what went wrong.
Parsed :: struct {
	directives: []Directive,
	// Every file that was read, in the order first opened (for reload).
	files:      []string,
	diags:      []Diagnostic,
	store:      ^Store,
}

// ----------------------------------------------------------------------------
// The option table

// What noirvpn does with an option.
Disposition :: enum u8 {
	// Works as upstream.
	Supported,
	// Parsed and accepted, no effect. Reported as a warning.
	Ignored,
	// A start-up error that names the reason and the replacement.
	Rejected,
	// A noirvpn extension.
	New,
}

// Which kind of config an option belongs in.
Applies :: enum u8 {
	Both,
	Client,
	Server,
}

Flag :: enum u8 {
	// A server may push it to clients.
	Pushable,
	// May be given as an inline block: `<name> ... </name>`.
	Inline,
	// Allowed inside a `<connection>` block (and then also sets the default).
	Connection,
	// Legal in a client-specific file (client-config-dir) as well as globally.
	Ccd,
	// Legal only in a client-specific file (or the peers file).
	Ccd_Only,
	// Only valid when pushed.
	Push_Only,
}

Flags :: bit_set[Flag;u8]

// One row of the option table.
Option :: struct {
	name:     string,
	disp:     Disposition,
	applies:  Applies,
	// Argument count range. `max_args` is -1 for "any number".
	min_args: int,
	max_args: int,
	flags:    Flags,
	// Man page section, for the generated documentation.
	section:  string,
	// For Rejected: the reason and the replacement. For Ignored: why it has no
	// effect. For Supported and New: a one-line summary.
	note:     string,
}

// ----------------------------------------------------------------------------
// Typed settings

// Whether a config is for a client or a server, otherwise `None` (the file has
// neither a client nor a server directive).
Role :: enum u8 {
	None,
	Client,
	Server,
}

Proto :: enum u8 {
	Udp,
	Tcp,
}

// IP version restriction from a 4 or 6 suffix (udp4, tcp6-client, ...).
Family :: enum u8 {
	Any,
	V4,
	V6,
}

// A key, certificate or list given as a file name or as an inline block.
Key_Source :: struct {
	// File name, empty when inline.
	path:      string,
	// Inline text, empty when from a file.
	data:      string,
	is_inline: bool,
}

key_source_is_set :: proc(k: Key_Source) -> bool {
	return k.is_inline || k.path != ""
}

// `key-direction` / the second argument of `tls-auth`.
Key_Dir :: enum u8 {
	// No direction: both sides use the same key half.
	None,
	Zero,
	One,
}

// The `auth` digest for tls-auth.
Auth_Digest :: enum u8 {
	Sha1, // upstream default
	Sha256,
	Sha512,
}

Cipher :: enum u8 {
	Aes_256_Gcm,
	Aes_128_Gcm,
	Chacha20_Poly1305,
}

Tls_Version :: enum u8 {
	// Not set: noirvpn's own default applies.
	Default,
	V1_2,
	V1_3,
}

Pq_Mode :: enum u8 {
	// Default: hybrid key exchange first, classical groups as fallback.
	Prefer,
	Off,
	Require,
}

Peer_Keys_Mode :: enum u8 {
	// Pins only (default).
	Pin,
	// Certificate chain and pin both.
	Both,
	// A pin, else a chain: a key in the peers file counts by pin, any other key
	// needs a chain to `ca`. Also the mode of `ca` with `peer-keys` when
	// `peer-keys-mode` is not set.
	Either,
}

// The most crypto worker threads `workers` accepts.
MAX_WORKERS :: 64

// Who runs the data channel:
//   Userspace - this process (default)
//   Udco      - userspace DCO service on a Unix socket (`dco-socket`)
//   Dco       - Linux `ovpn` kernel driver (Linux 6.16 or later, module `ovpn`)
//   Auto      - kernel driver if there, else the service, else this process
// Udco and Dco fall back to this process if unusable: no service or module,
// device cannot be created, or a server has more than one listening socket.
// Auto: a server decides at start. A client also decides at each attempt, for
// what it found at start.
Datapath :: enum u8 {
	Userspace,
	Auto,
	// A userspace DCO service over its socket (`dco-socket`).
	Udco,
	// The kernel `ovpn` driver.
	Dco,
}

// The value as the config and the bus spell it.
datapath_name :: proc "contextless" (d: Datapath) -> string {
	switch d {
	case .Userspace:
		return "userspace"
	case .Auto:
		return "auto"
	case .Udco:
		return "udco"
	case .Dco:
		return "dco"
	}
	return "userspace"
}

// Does the mode name a data channel outside this process (`udco` or `dco`)?
datapath_is_dco :: proc "contextless" (d: Datapath) -> bool {
	return d == .Udco || d == .Dco
}

// The default of `dco-socket`.
DCO_SOCKET_DEFAULT :: "/run/udco/udco.sock"

Verify_Client_Cert :: enum u8 {
	Require,
	Optional,
	None,
}

// `tls-crypt-v2` server policy for clients that cannot resend their wrapped key.
Cookie_Mode :: enum u8 {
	// noirvpn default.
	Force,
	Allow_Noncookie,
}

// The extended key usage that `remote-cert-tls server` and `client` require
// (the long names of serverAuth and clientAuth).
REMOTE_EKU_SERVER :: "TLS Web Server Authentication"
REMOTE_EKU_CLIENT :: "TLS Web Client Authentication"

// Most values `remote-cert-ku` takes.
REMOTE_CERT_KU_MAX :: 16

Remote_Cert_Tls :: enum u8 {
	None,
	Server,
	Client,
}

Auth_Retry :: enum u8 {
	None,
	Nointeract,
	Interact,
}

Mtu_Disc :: enum u8 {
	Default,
	No,
	Maybe,
	Yes,
}

Mssfix_Kind :: enum u8 {
	// Not set: the default (1492 as an MTU) applies.
	Default,
	// `mssfix 0`.
	Off,
	// `mssfix N`: N is the UDP payload size.
	Link,
	// `mssfix N mtu`: N includes IP and UDP headers.
	Mtu,
	// `mssfix N fixed`: N limits the payload IP packet.
	Fixed,
}

Mssfix :: struct {
	kind:  Mssfix_Kind,
	value: int,
}

Pull_Action :: enum u8 {
	Accept,
	Ignore,
	Reject,
}

Pull_Filter :: struct {
	action: Pull_Action,
	// Matched as a prefix of the pushed option line.
	text:   string,
}

Redirect_Flag :: enum u8 {
	Local,
	Autolocal,
	Def1,
	Bypass_Dhcp,
	Bypass_Dns,
	Block_Local,
	Ipv6,
	Not_Ipv4,
}

Redirect_Flags :: bit_set[Redirect_Flag;u16]

Bus_Role :: enum u8 {
	Read,
	Operator,
	Auth,
	Admin,
}

Bus_Roles :: bit_set[Bus_Role;u8]

Bus_State :: enum u8 {
	// Not configured: the daemon uses its default socket.
	Default,
	Off,
	Custom,
}

// `bus-events` / `bus-control`.
Bus_Endpoint :: struct {
	state: Bus_State,
	// A path or an ipc:// URL, as written.
	path:  string,
	// Socket file mode, 0 if not set.
	mode:  u32,
	// Group name or number, "" if not set.
	group: string,
}

Bus_Id_Kind :: enum u8 {
	Uid,
	Gid,
	// A Windows SID or account name, always in `name`.
	Sid,
}

// One `bus-allow` line.
Bus_Allow :: struct {
	kind:  Bus_Id_Kind,
	// Numeric id; only valid when `name` is empty.
	id:    u32,
	// User or group name when the id was not a number.
	name:  string,
	roles: Bus_Roles,
}

Auth_Digest_Default :: Auth_Digest.Sha1

Tls_Auth :: struct {
	key:    Key_Source,
	dir:    Key_Dir,
	digest: Auth_Digest,
}

Tls_Crypt_V2 :: struct {
	key:    Key_Source,
	cookie: Cookie_Mode,
}

// Control channel wrapping. A client uses at most one. A server may combine
// tls-crypt-v2 with one of the others.
Wrap :: struct {
	tls_auth:     Maybe(Tls_Auth),
	tls_crypt:    Maybe(Key_Source),
	tls_crypt_v2: Maybe(Tls_Crypt_V2),
}

// How the client logs in at an HTTP proxy. Only Basic exists.
Proxy_Auth :: enum u8 {
	// No credentials: a 407 from the proxy is an error.
	None,
	// Send `Proxy-Authorization: Basic` with the first request.
	Basic,
	// Send nothing at first. When the proxy responds with 407 and offers Basic, the
	// next attempt sends it.
	Auto,
}

// One `http-proxy-option CUSTOM-HEADER name content`.
Proxy_Header :: struct {
	name:    string,
	content: string,
}

// A remote that is reached through an HTTP CONNECT proxy: `http-proxy`,
// `http-proxy-option` and `http-proxy-user-pass`.
Http_Proxy :: struct {
	host:    string,
	port:    u16,
	auth:    Proxy_Auth,
	// The user name (line 1) and the password (line 2): the AUTHFILE of
	// `http-proxy`, else `http-proxy-user-pass`. Not set: no credentials.
	creds:   Key_Source,
	// `http-proxy-option VERSION 1.0` (the default is 1.1).
	http10:  bool,
	// `http-proxy-option AGENT`: the User-Agent header, "" for none.
	agent:   string,
	headers: []Proxy_Header,
}

// Options that may also appear inside a `<connection>` block (a client has one
// copy per remote) and the defaults for the ones that do not.
Link_Settings :: struct {
	proto:                  Proto,
	// `proto` is `.Tcp` and the stream runs inside an outer TLS stream
	// (`tls-client`, `tls-server`). Everything that is true for TCP stays true.
	tls:                    bool,
	family:                 Family,
	// Local and remote port. Default 1194.
	lport:                  u16,
	rport:                  u16,
	// `local host`: "" = any address.
	local_host:             string,
	nobind:                 bool,
	bind_v6only:            bool,
	float:                  bool,
	mssfix:                 Mssfix,
	tun_mtu:                int,
	// Second argument of tun-mtu, 0 if not given.
	occ_mtu:                int,
	// 0 = off. `explicit-exit-notify` without a number means 1.
	explicit_exit_notify:   int,
	// Seconds between attempts (default 1), cap for the back-off (default 300).
	connect_retry:          int,
	connect_retry_max_wait: int,
	// Tries per remote, 0 = unlimited.
	connect_retry_max:      int,
	connect_timeout:        int,
	mtu_disc:               Mtu_Disc,
	wrap:                   Wrap,
	// Reach the remote through this HTTP proxy. Only for `.Tcp` (also `tls`).
	proxy:                  Maybe(Http_Proxy),
}

// One entry of the client's remote list (a `remote` line or a `<connection>` block).
Connection :: struct {
	using link: Link_Settings,
	host:       string,
}

// A `local` line of a server: one listening socket.
Listen :: struct {
	// "" = any address.
	host:   string,
	port:   u16,
	proto:  Proto,
	// `proto` is `.Tcp` and the connections carry an outer TLS stream (`tls-server`).
	tls:    bool,
	family: Family,
}

// `route` (client and server) as written, with defaults left empty.
Route :: struct {
	network: string,
	netmask: string,
	gateway: string,
	// -1 = not given.
	metric:  int,
}

// `route-ipv6`.
Route6 :: struct {
	// "addr/bits" as written.
	prefix:  string,
	gateway: string,
	metric:  int,
}

// An option kept as written, for pushed-style options that the client applies later.
Raw_Option :: struct {
	name: string,
	args: []string,
}

Verify_X509_Kind :: enum u8 {
	Subject,
	Name,
	Name_Prefix,
}

X509_Name :: struct {
	name: string,
	kind: Verify_X509_Kind,
}

Crl_Verify :: struct {
	src: Key_Source,
	// `crl-verify dir flag`: a directory of CRLs.
	dir: bool,
}

// TLS and certificate settings.
Tls_Config :: struct {
	ca:                  Key_Source,
	cert:                Key_Source,
	key:                 Key_Source,
	// A server's certificate (leaf first, then the chain) and key for the outer
	// TLS of `tls-server` listeners. Not set: `cert` and `key` serve there too.
	transport_cert:      Key_Source,
	transport_key:       Key_Source,
	// `tls-transport-accept-tcp`: a `tls-server` listener also serves raw
	// OpenVPN `tcp-client` connections (told apart by the first bytes).
	transport_accept_tcp: bool,
	// `tls-transport-dev`: the name of the second tun device of a server with
	// `datapath dco` or `udco` and a `tls-server` listener. Empty: `tls_tun_name` derives it.
	transport_dev:       string,
	// `tls-transport-ws PATH`: the tls transport runs in a WebSocket at this path
	// (a client asks for it; `tls-server` and `tcp-server` listeners serve it).
	// Empty: none.
	transport_ws:        string,
	extra_certs:         Key_Source,
	// `askpass [FILE]`: the passphrase of encrypted keys is the first line of
	// FILE. "" (no file, or `stdin`): it is typed at the terminal.
	askpass:             Maybe(string),
	capath:              string,
	crl_verify:          Maybe(Crl_Verify),
	// `peer-fingerprint`: SHA-256 of the whole certificate.
	fingerprints:        [][32]u8,
	remote_cert_tls:     Remote_Cert_Tls,
	// `remote-cert-ku` values (hex, 1 to ff). `remote_cert_ku_set`: the key usage
	// extension is required (`remote-cert-tls`, or `remote-cert-ku` with or
	// without values).
	remote_cert_ku:      []u16,
	remote_cert_ku_set:  bool,
	// The extended key usage that is required (an OID or a name): the value of
	// `remote-cert-eku`, or the one of `remote-cert-tls` if that came later.
	remote_cert_eku:     string,
	verify_x509_name:    Maybe(X509_Name),
	// Read and not applied: the name rules use the common name.
	x509_username_field: string,
	// Raw `tls-groups` list.
	tls_groups:          string,
	version_min:         Tls_Version,
	version_max:         Tls_Version,
	pq_mode:             Pq_Mode,
	// Seconds. Defaults 60, 3600, 2.
	hand_window:         int,
	tran_window:         int,
	tls_timeout:         int,
	// `reneg-sec max [min]`: default 3600, min -1 = derived by the role.
	reneg_sec:           int,
	reneg_sec_min:       int,
	reneg_bytes:         i64,
	reneg_pkts:          i64,
}

// Settings both roles have.
Common_Config :: struct {
	verb:                  int,
	user:                  string,
	group:                 string,
	cd:                    string,
	writepid:              string,
	mlock:                 bool,
	// `persist-tun`: a client keeps its tun device, addresses and routes across
	// reconnects. A server keeps its device for its whole run anyway.
	persist_tun:           bool,
	// `block-ipv6`: the daemon drops each IPv6 packet at the tunnel, in both
	// directions. A client also turns it on when the server pushes it.
	block_ipv6:            bool,
	// `dev` as written ("tun", "tun0", "utun3", ...).
	dev:                   string,
	data_ciphers:          []Cipher,
	data_ciphers_fallback: Maybe(Cipher),
	tls:                   Tls_Config,
	link:                  Link_Settings,
	// Keepalive and idle handling, seconds. 0 = off.
	ping:                  int,
	ping_exit:             int,
	ping_restart:          int,
	ping_timer_rem:        bool,
	inactive_secs:         int,
	inactive_bytes:        int,
	session_timeout:       int,
	replay_window:         int,
	replay_time:           int,
	// Control packet size limit (154..2048); 0 = default 1250.
	max_packet_size:       int,
	sndbuf:                int,
	rcvbuf:                int,
	// tun transmit queue length in packets, 0 = the daemon's default.
	txqueuelen:            int,
	// Linux packet mark, 0 = none.
	mark:                  u32,
	route_table:           int,
	ifconfig_noexec:       bool,
	route_noexec:          bool,
	// `topology subnet` seen (the only accepted value).
	topology_subnet:       bool,
	routes:                []Route,
	routes6:               []Route6,
	// noirvpn extensions.
	// `workers`: crypto worker threads (MAX_WORKERS at most). 0 (default): the data
	// path runs on the main thread.
	workers:               int,
	datapath:              Datapath,
	// `disable-dco` seen (`datapath` is then userspace). A client service profile
	// keeps it when the service sets the data path: its connections run in the
	// service process.
	disable_dco:           bool,
	// `dco-socket`: the socket of the DCO service (DCO_SOCKET_DEFAULT when not given).
	dco_socket:            string,
	bus_events:            Bus_Endpoint,
	bus_control:           Bus_Endpoint,
	bus_allow:             []Bus_Allow,
	// `stats-interval`: seconds between `stats.tick` bus events, 0 = off.
	stats_interval:        int,
}

// The ClientHello of the outer TLS of a `tls-client` remote (`tls-transport-hello`).
Tls_Hello :: enum u8 {
	Default, // what the TLS library sends
	Chrome, // as close to Chrome's as the library allows
}

Client_Config :: struct {
	using common:         Common_Config,
	// `client-service`: the config is the base config of a service. It holds
	// service settings only, so there is no remote list and no key.
	service:              bool,
	// Remote list in order, each with its own link settings.
	connections:          []Connection,
	remote_random:        bool,
	// `resolv-retry`: seconds, -1 = infinite (the default).
	resolv_retry:         int,
	// `proto-force`: Udp or Tcp, only if given. Tcp also keeps the `tls` remotes.
	proto_force:          Maybe(Proto),
	// `tls-transport-sni`: the server name of the outer TLS ClientHello. Empty:
	// the `remote` host when it is a name, none for an address.
	tls_transport_sni:    string,
	// `tls-transport-hello`: the definition of the outer ClientHello.
	tls_transport_hello:  Tls_Hello,
	// `tls-transport-strict`: an outer certificate that is not the server's
	// key fails the attempt.
	tls_transport_strict: bool,
	auth_user_pass:       Maybe(Auth_User_Pass),
	auth_retry:           Auth_Retry,
	pull_filters:         []Pull_Filter,
	route_nopull:         bool,
	push_peer_info:       bool,
	// `setenv IV_SSO <methods>`: the sign-in methods to announce, as written
	// (such as "webauth"). Empty when the line is not there.
	iv_sso:               string,
	redirect_gateway:     Redirect_Flags,
	// True if `redirect-gateway` was given (flags may be empty).
	redirect_gateway_set: bool,
	redirect_private:     Redirect_Flags,
	redirect_private_set: bool,
	route_gateway:        string,
	route_ipv6_gateway:   string,
	route_metric:         int,
	// `ifconfig` / `ifconfig-ipv6` given locally (normally pushed).
	ifconfig:             Maybe([2]string),
	ifconfig_ipv6:        Maybe([2]string),
	// `dns` and `dhcp-option` lines, as written.
	dns_options:          []Raw_Option,
}

// `auth-user-pass`.
Auth_User_Pass :: struct {
	// Credentials file, or "" to prompt.
	file:          string,
	// Inline `<auth-user-pass>` text.
	data:          string,
	is_inline:     bool,
	// `auth-user-pass username-only`.
	username_only: bool,
}

// `server network netmask`, expanded (man page, "--server").
Server_Net :: struct {
	network:     [4]u8,
	prefix:      u8,
	netmask:     [4]u8,
	// The server's own tunnel address: network + 1.
	server_addr: [4]u8,
	nopool:      bool,
}

// A pool of client addresses.
Pool4 :: struct {
	start: [4]u8,
	end:   [4]u8,
}

// `server-ipv6 addr/bits`, expanded.
Server_Net6 :: struct {
	prefix:      [16]u8,
	bits:        u8,
	// Server tunnel address.
	server_addr: [16]u8,
	// First address of the pool. The server allocator offsets it by the
	// position in the IPv4 pool (man page, "--ifconfig-ipv6-pool").
	pool_base:   [16]u8,
}

Pool_Persist :: struct {
	file:    string,
	// Seconds; 0 = read-only. Default 600.
	seconds: int,
}

// Connection-rate limit: `connect-freq n sec`.
Rate_Limit :: struct {
	count:   int,
	seconds: int,
}

Auth_External :: struct {
	// Seconds to wait for the controller; default 30.
	timeout: int,
}

Server_Config :: struct {
	using common:          Common_Config,
	// `local` lines. Never empty: if no `local` is given, one entry for any
	// address with the default port and protocol.
	listens:               []Listen,
	net:                   Server_Net,
	net6:                  Maybe(Server_Net6),
	// Explicit `ifconfig-pool` / `ifconfig-ipv6-pool` (override the derived pool).
	pool:                  Maybe(Pool4),
	pool6:                 Maybe([16]u8),
	pool_persist:          Maybe(Pool_Persist),
	// Everything to push, in order. Entries created by `server`, `server-ipv6` and
	// `keepalive` come first where those directives stand.
	push:                  []string,
	client_to_client:      bool,
	client_config_dir:     string,
	ccd_exclusive:         bool,
	duplicate_cn:          bool,
	max_clients:           int,
	max_routes_per_client: int,
	connect_freq:          Maybe(Rate_Limit),
	// Default 100 per 10 seconds.
	connect_freq_initial:  Rate_Limit,
	// `connect-freq-source`: initial replies for one source address in the
	// `connect-freq-initial` window. Not set: the session's default (20).
	// 0: no limit.
	connect_freq_source:   Maybe(int),
	multihome:             bool,
	multihome_same_iface:  bool,
	verify_client_cert:    Verify_Client_Cert,
	// `tls-crypt-v2-max-age`, days; 0 = off.
	tls_crypt_v2_max_age:  int,
	// noirvpn extensions.
	peer_keys:             string,
	peer_keys_mode:        Peer_Keys_Mode,
	// `peer-passwords`: the file of user names and password hashes ("" if not
	// set). A password source, with `auth-external`.
	peer_passwords:        string,
	auth_external:         Maybe(Auth_External),
	// `auth-web`: a client that says `IV_SSO=webauth` and sends no certificate and
	// no password waits for a controller that does a web sign-in.
	auth_web:              bool,
}

// Per-client settings from a client-config-dir file or a peers file line.
Client_Specific :: struct {
	ifconfig_push:      Maybe(Ifconfig_Push),
	ifconfig_ipv6_push: Maybe(Ifconfig6_Push),
	iroutes:            []Iroute,
	iroutes6:           []Iroute6,
	push:               []string,
	push_remove:        []string,
	push_reset:         bool,
	disable:            bool,
	session_timeout:    int,
	max_routes:         int,
}

// `ifconfig-push local remote-netmask [alias]`. A peers file line has only the address.
Ifconfig_Push :: struct {
	local:          string,
	remote_netmask: string,
	alias:          string,
	// `local` as an address, if it is a literal one.
	local_ip:       [4]u8,
	local_is_ip:    bool,
}

// `ifconfig-ipv6-push addr/bits [remote]`.
Ifconfig6_Push :: struct {
	addr:   [16]u8,
	bits:   u8,
	remote: string,
}

// `iroute network [netmask]`.
Iroute :: struct {
	network: [4]u8,
	prefix:  u8,
}

Iroute6 :: struct {
	prefix: [16]u8,
	bits:   u8,
}

// Everything `build` produces. `role` tells which of `client` and `server` is
// filled in. The other one is zero.
Config :: struct {
	role:     Role,
	client:   Client_Config,
	server:   Server_Config,
	// Set by `build_client_specific` (a client-config-dir file); empty otherwise.
	specific: Client_Specific,
	// Parse errors, then validation errors and warnings, in order of appearance.
	diags:    []Diagnostic,
	// The parsed directives. This also owns the memory of everything above.
	parsed:   Parsed,
}

// The settings both roles share, whichever is filled in.
config_common :: proc(c: ^Config) -> ^Common_Config {
	if c.role == .Server {
		return &c.server.common
	}
	return &c.client.common
}
