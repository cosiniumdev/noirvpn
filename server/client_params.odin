// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package server

import "core:mem"
import "core:strings"
import "core:time"
import "noir:proto/config"
import "noir:proto/push"

// Everything one client gets, from the server config, the client-config-dir
// file, the peers file entry and the address pools.
//
// Sources, in order:
//   1. Peers file entry of the key (if connected by pin): `disabled`,
//      `ifconfig-push=`, `ifconfig-ipv6-push=`, `iroute=`, `iroute-ipv6=`.
//   2. `client-config-dir/<identity>`, else `client-config-dir/DEFAULT`.
//      (SPEC-GAP: DEFAULT is from the stock man page, not in the config notes.)
//   3. Server config (`push` lines, `max-routes-per-client`).
//
// Merge rules:
//   - `disable` in either: client refused.
//   - `ifconfig-push` / `ifconfig-ipv6-push`: peers entry wins over the ccd file
//     (key beats name).
//   - iroutes: both lists, repeats dropped.
//   - push: server `push` lines (none after `push-reset`), then ccd `push` lines,
//     then `push-remove` on the whole list. `push-remove X` drops every line
//     containing X (man page: "substring"). SPEC-GAP: stock matching is not
//     documented; substring is the widest reading, so nothing meant to go stays.
//   - Tunnel essentials come from assignment fields:
//     `topology subnet`, `route-gateway`, `tun-ipv6`, `ifconfig`,
//     `ifconfig-ipv6`, `peer-id`. Such lines in `push` or ccd are dropped, so
//     `push-reset` cannot break the tunnel. `ping` and `ping-restart` (from
//     `keepalive`) survive `push-reset`, else the server times out a client that
//     never pings. (SPEC-GAP: stock `push-reset` is not documented; safe choice.)
//   - A pushed line with a comma or control byte cannot go in a PUSH_REPLY:
//     dropped and noted.
//
// Static address rules: `pools_check_static4`, `pools_check_static6`.
// SPEC-GAP: netmask of `ifconfig-push` and prefix length of `ifconfig-ipv6-push`
// are ignored with a note (`Assignment.notes`): a `topology subnet` tunnel has one
// netmask, the server's. Stock may error or use a per-client mask. Unknown.
//
// iroutes: one overlapping the server network is refused (a client could send as
// any other client; the source check trusts iroutes). Count limit:
// `max-routes-per-client` (or the ccd value).
// A missing ccd file is fine, unless `ccd-exclusive`. A ccd error refuses the
// client (`Config_Error`, diagnostic in `detail`).

// The names a push line may not use (see above). Compared exactly.
@(private)
STRUCTURAL :: [?]string{"topology", "route-gateway", "route-ipv6-gateway", "tun-ipv6", "ifconfig", "ifconfig-ipv6", "peer-id"}

// Kept by `push-reset`.
@(private)
KEPT_ON_RESET :: [?]string{"ping", "ping-restart"}

// A largest ccd file, in bytes.
MAX_CCD_SIZE :: 1 << 20

Params_Env :: struct {
	cfg:         ^config.Server_Config,
	pools:       ^Pools,
	// The pin store, for the peers file entries. nil if there is none.
	pins:        ^Pin_Store,
	// Reads ccd files. nil = the OS (where there is one).
	loader:      config.Loader,
	loader_data: rawptr,
}

Connect_Request :: struct {
	identity: string,
	// The client's key (SHA-256 of its SPKI), when it connected by pin.
	spki:     [config.PIN_LEN]u8,
	pinned:   bool,
	// The peer-id taken for this client.
	peer_id:  u32,
	// Extra per-client lines from a bus controller, as the text of a
	// client-config-dir file (`controller_check` generates it). Applied after the
	// real file. Its static addresses win over the file and the peers file.
	extra:    string,
}

Assignment :: struct {
	peer_id:         u32,
	lease:           Lease,
	has4:            bool,
	addr4:           [4]u8,
	netmask4:        [4]u8,
	// `route-gateway`: the server's tunnel address.
	gateway4:        [4]u8,
	has6:            bool,
	addr6:           [16]u8,
	prefix6:         u8,
	gateway6:        [16]u8,
	iroutes4:        []config.Iroute,
	iroutes6:        []config.Iroute6,
	// The option lines to push, besides the tunnel essentials. Plain
	// `name arg arg` text, as `Push_Reply_Params.extra` takes them.
	push:            []string,
	// From the ccd file, seconds, 0 = none.
	session_timeout: int,
	// Things the operator may want to know (an ignored netmask, a dropped line).
	notes:           []string,
	// The ccd file was found (a named one or DEFAULT).
	had_ccd:         bool,
	// Owns every slice and string above.
	store:           ^config.Store,
}

assignment_destroy :: proc(a: ^Assignment) {
	config.store_free(a.store)
	a^ = {}
}

// Fills the per-client part of a PUSH_REPLY: `topology`, `route_gateway`,
// `ifconfig`, `ifconfig6`, `peer_id`, `extra`.
// - The caller sets cipher, protocol flags, DNS and the rest.
// - The caller must not push `ping` or `ping-restart` again (already in `extra`
//   if the server config has them).
// - Strings in `extra` live as long as the assignment.
assignment_push_params :: proc(a: ^Assignment, p: ^push.Push_Reply_Params) {
	p.topology = .Subnet
	p.route_gateway = a.gateway4
	p.peer_id = a.peer_id
	p.extra = a.push
	if a.has4 {
		p.ifconfig = push.Ifconfig{a.addr4, a.netmask4}
	}
	if a.has6 {
		p.ifconfig6 = push.Ifconfig6{a.addr6, a.prefix6, a.gateway6}
	}
}

// Builds the assignment, takes the addresses from the pools, and returns a
// reject (with kind) if the client may not connect.
// - On a reject nothing is held. `detail` may carry text for the log,
//   allocated with the temp allocator.
// - On success the lease is held. Give it back with `pools_release` (the
//   registry returns it from `registry_remove`).
client_params_build :: proc(
	env: ^Params_Env,
	req: Connect_Request,
	now: time.Duration,
	allocator := context.allocator,
) -> (
	a: Assignment,
	rej: Reject,
	detail: string,
) {
	cfg := env.cfg
	store := config.store_new(allocator)
	sa := config.store_allocator(store)
	failed := true
	defer if failed {
		config.store_free(store)
	}

	// 1. The peers file entry.
	entry: ^config.Peer_Entry
	if req.pinned && env.pins != nil {
		if t := pin_store_current(env.pins); t != nil {
			entry = pin_table_find(t, req.spki)
		}
		if entry != nil && (entry.disabled || entry.client.disable) {
			return {}, reject_make(.Client_Disabled), ""
		}
	}

	// 2. The ccd file.
	spec: config.Client_Specific
	ccd_cfg: config.Config
	have_ccd := false
	defer if have_ccd {
		config.destroy(&ccd_cfg)
	}
	if cfg.client_config_dir != "" {
		text, file, found := read_ccd(env, req.identity)
		if found {
			parsed := config.parse_text(
				text,
				ccd_name(cfg.client_config_dir, file, context.temp_allocator),
				config.Parse_Options{loader = env.loader, loader_data = env.loader_data},
			)
			ccd_cfg = config.build_client_specific(parsed)
			have_ccd = true
			if !config.ok(&ccd_cfg) {
				return {}, reject_make(.Config_Error), config.format_diagnostics(ccd_cfg.diags, context.temp_allocator)
			}
			spec = ccd_cfg.specific
			a.had_ccd = true
		} else if cfg.ccd_exclusive {
			return {}, reject_make(.Ccd_Required), ""
		}
	}
	if spec.disable {
		return {}, reject_make(.Client_Disabled), ""
	}
	ctl_cfg: config.Config
	have_ctl := false
	defer if have_ctl {
		config.destroy(&ctl_cfg)
	}
	ctl: config.Client_Specific
	if req.extra != "" {
		ctl_cfg = config.build_client_specific(config.parse_text(req.extra, "auth.decide"))
		have_ctl = true
		if !config.ok(&ctl_cfg) {
			return {}, reject_make(.Config_Error), config.format_diagnostics(ctl_cfg.diags, context.temp_allocator)
		}
		ctl = ctl_cfg.specific
		merge_controller(&spec, ctl, sa)
	}

	notes := make([dynamic]string, sa)

	// 3. Static addresses: the peers file entry over the ccd file.
	static4: Maybe([4]u8)
	static6: Maybe([16]u8)
	if ip, ok := spec.ifconfig_push.?; ok {
		if !ip.local_is_ip {
			return {}, reject_make(.Bad_Static_Address), "ifconfig-push requires an IP address rather than a host name"
		}
		static4 = ip.local_ip
		if m, mok := config.ipv4_parse(ip.remote_netmask); !mok || m != cfg.net.netmask {
			append(&notes, "the ifconfig-push netmask is ignored, and the netmask of the server network is used instead")
		}
	}
	if ip6, ok := spec.ifconfig_ipv6_push.?; ok {
		static6 = ip6.addr
		if n6, has := cfg.net6.?; has && ip6.bits != n6.bits {
			append(&notes, "the ifconfig-ipv6-push prefix length is ignored, and the server prefix length is used instead")
		}
	}
	if entry != nil {
		if ip, ok := entry.client.ifconfig_push.?; ok {
			static4 = ip.local_ip
		}
		if ip6, ok := entry.client.ifconfig_ipv6_push.?; ok {
			static6 = ip6.addr
		}
	}
	// A controller's static address wins over the peers file.
	if ip, ok := ctl.ifconfig_push.?; ok {
		static4 = ip.local_ip
	}
	if ip6, ok := ctl.ifconfig_ipv6_push.?; ok {
		static6 = ip6.addr
	}

	// 4. iroutes: both lists, no repeats, no overlap with the server network.
	max_routes := cfg.max_routes_per_client
	if spec.max_routes > 0 {
		max_routes = spec.max_routes
	}
	ir4 := make([dynamic]config.Iroute, sa)
	ir6 := make([dynamic]config.Iroute6, sa)
	add_ir4 :: proc(list: ^[dynamic]config.Iroute, r: config.Iroute) {
		for x in list {
			if x == r {
				return
			}
		}
		append(list, r)
	}
	add_ir6 :: proc(list: ^[dynamic]config.Iroute6, r: config.Iroute6) {
		for x in list {
			if x == r {
				return
			}
		}
		append(list, r)
	}
	for r in spec.iroutes {
		add_ir4(&ir4, r)
	}
	for r in spec.iroutes6 {
		add_ir6(&ir6, r)
	}
	if entry != nil {
		for r in entry.client.iroutes {
			add_ir4(&ir4, r)
		}
		for r in entry.client.iroutes6 {
			add_ir6(&ir6, r)
		}
	}
	if len(ir4) + len(ir6) > max_routes {
		return {}, reject_make(.Too_Many_Routes), ""
	}
	for r in ir4 {
		if iroute4_overlaps(r, cfg.net) {
			return {}, reject_make(.Bad_Iroute), ""
		}
	}
	if n6, has := cfg.net6.?; has {
		for r in ir6 {
			if iroute6_overlaps(r, n6) {
				return {}, reject_make(.Bad_Iroute), ""
			}
		}
	}

	// 5. The push list.
	push_lines := build_push_list(cfg.push, spec, &notes, sa)

	// 6. Addresses. Last, so the failures above hold nothing.
	lease, aerr := pools_acquire(env.pools, req.identity, static4, static6, now)
	switch aerr {
	case .None:
	case .Bad_Static_Address:
		return {}, reject_make(.Bad_Static_Address), ""
	case .Address_In_Use:
		holder := pools_static_holder(env.pools, static4, static6)
		if holder != "" && name_equal(holder, req.identity) {
			// Two keys of one name met a fixed address that belongs to the name.
			return {}, reject_make(.Address_In_Use), "another session of this name already has the fixed address: a client-config-dir file assigns the same address to every key of the name, so set ifconfig-push for each key in the peers file instead"
		}
		return {}, reject_make(.Address_In_Use), ""
	case .Pool_Exhausted:
		return {}, reject_make(.Pool_Exhausted), ""
	case .No_Address:
		return {}, reject_make(.Pool_Exhausted), "the client has no static address and the server has no dynamic pool (server `nopool`)"
	}

	a.peer_id = req.peer_id
	a.lease = lease
	a.has4 = lease.kind4 != .None
	a.addr4 = lease.addr4
	a.netmask4 = cfg.net.netmask
	a.gateway4 = cfg.net.server_addr
	if n6, has := cfg.net6.?; has && lease.kind6 != .None {
		a.has6 = true
		a.addr6 = lease.addr6
		a.prefix6 = n6.bits
		a.gateway6 = n6.server_addr
		// `tun-ipv6` first: old clients need it before `ifconfig-ipv6`.
		with_tun6 := make([]string, len(push_lines) + 1, sa)
		with_tun6[0] = "tun-ipv6"
		copy(with_tun6[1:], push_lines)
		push_lines = with_tun6
	}
	a.iroutes4 = ir4[:]
	a.iroutes6 = ir6[:]
	a.push = push_lines
	a.session_timeout = spec.session_timeout
	a.notes = notes[:]
	a.store = store
	failed = false
	return a, {}, ""
}

// ---------------------------------------------------------------------------

@(private)
ccd_name :: proc(dir, file: string, allocator: mem.Allocator) -> string {
	if strings.has_suffix(dir, "/") {
		return strings.concatenate({dir, file}, allocator)
	}
	return strings.concatenate({dir, "/", file}, allocator)
}

// Reads `<dir>/<identity>`, else `<dir>/<identity in ASCII lower case>`, else
// `<dir>/DEFAULT`. Any identity source (pinned name, certificate name, user
// name) gets the same lookup. The text is on the temp allocator. `file` is the
// name that was read.
@(private)
read_ccd :: proc(env: ^Params_Env, identity: string) -> (text: string, file: string, found: bool) {
	loader := env.loader
	if loader == nil {
		loader = config.default_loader
	}
	if loader == nil {
		return "", "", false
	}
	lower := make([]u8, len(identity), context.temp_allocator)
	for i in 0 ..< len(identity) {
		lower[i] = ascii_lower(identity[i])
	}
	for name, i in ([3]string{identity, string(lower), "DEFAULT"}) {
		if i == 1 && name == identity {
			continue // the same file
		}
		path := ccd_name(env.cfg.client_config_dir, name, context.temp_allocator)
		data, ok := loader(env.loader_data, path, context.temp_allocator)
		if ok && len(data) <= MAX_CCD_SIZE {
			return string(data), name, true
		}
	}
	return "", "", false
}

@(private)
push_name :: proc(line: string) -> string {
	end := 0
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end += 1
	}
	return line[:end]
}

@(private)
is_structural :: proc(name: string) -> bool {
	for s in STRUCTURAL {
		if s == name {
			return true
		}
	}
	return false
}

@(private)
kept_on_reset :: proc(name: string) -> bool {
	for s in KEPT_ON_RESET {
		if s == name {
			return true
		}
	}
	return false
}

// The final list of push lines. See the rules at the top of the file.
@(private)
build_push_list :: proc(
	server_push: []string,
	spec: config.Client_Specific,
	notes: ^[dynamic]string,
	a: mem.Allocator,
) -> []string {
	out := make([dynamic]string, a)
	take :: proc(out: ^[dynamic]string, notes: ^[dynamic]string, line: string, a: mem.Allocator) {
		name := push_name(line)
		switch {
		case name == "" || is_structural(name):
			// Replaced by the assignment's own fields.
		case !pushable_text(line):
			append(notes, strings.concatenate({"dropped a push line that contains a comma or control byte: ", name}, a))
		case:
			append(out, strings.clone(line, a))
		}
	}
	for line in server_push {
		if spec.push_reset && !kept_on_reset(push_name(line)) {
			continue
		}
		take(&out, notes, line, a)
	}
	for line in spec.push {
		take(&out, notes, line, a)
	}
	if len(spec.push_remove) > 0 {
		kept := make([dynamic]string, a)
		for line in out {
			drop := false
			for r in spec.push_remove {
				if len(r) > 0 && strings.contains(line, r) {
					drop = true
					break
				}
			}
			if !drop {
				append(&kept, line)
			}
		}
		return kept[:]
	}
	return out[:]
}

// A PUSH_REPLY option cannot hold a comma or a control byte.
@(private)
pushable_text :: proc "contextless" (s: string) -> bool {
	for c in transmute([]u8)s {
		if c == ',' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return len(s) > 0
}

// True if the iroute and the server network share any address.
@(private)
iroute4_overlaps :: proc(r: config.Iroute, net: config.Server_Net) -> bool {
	n := min(int(r.prefix), int(net.prefix))
	m := config.ipv4_to_u32(config.ipv4_prefix_mask(n))
	return config.ipv4_to_u32(r.network) & m == config.ipv4_to_u32(net.network) & m
}

@(private)
iroute6_overlaps :: proc(r: config.Iroute6, net: config.Server_Net6) -> bool {
	n := min(int(r.bits), int(net.bits))
	for i in 0 ..< 16 {
		keep := clamp(n - 8 * i, 0, 8)
		m := u8(0xff) << u8(8 - keep) if keep < 8 else u8(0xff)
		if r.prefix[i] & m != net.prefix[i] & m {
			return false
		}
	}
	return true
}
