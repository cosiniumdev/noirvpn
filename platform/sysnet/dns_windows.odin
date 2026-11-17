// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import cnet "core:net"
import "core:mem"
import "core:strings"
import win "core:sys/windows"

// DNS on Windows uses two things:
//  1. Name servers and search list of the tunnel interface
//     (SetInterfaceDnsSettings, Windows 10 2004 and later). Windows asks the
//     interface with the lowest metric first; the client gives the tunnel a
//     low metric.
//  2. One NRPT rule (Name Resolution Policy Table) `noirvpn-<ifname>` for the
//     routing domains, and for root "." if `default_route` is set. Those names
//     go to the tunnel's servers only, whatever the metrics.
//
// Split DNS (routing domains, no `default_route`): the servers go into the
// NRPT rule only, so other names keep using other interfaces. Search domains
// always go to the interface. Servers with a port other than 53 are dropped
// with a warning (Windows has no port setting).
//
// `dns_apply` sets every interface field, empty ones too, to replace values a
// crashed run left. After each change the DNS Client service rereads its
// settings and the cache is flushed.
// NRPT rules from Group Policy replace local ones: `dns_apply` adds a warning.

DNS_Backend :: enum {
	None,
	// SetInterfaceDnsSettings and NRPT rules.
	Ip_Helper,
}

// The registry keys under HKLM. The strings must outlive every `DNS` created
// with them.
DNS_Env :: struct {
	// Where the local NRPT rules are.
	nrpt_key: string,
	// Where Group Policy puts its NRPT rules.
	gpo_key:  string,
	// Use this backend and skip detection. `.None`: detect.
	force:    DNS_Backend,
}

NRPT_KEY :: `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
NRPT_GPO_KEY :: `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
// Every NRPT rule of ours starts with this.
NRPT_PREFIX :: "noirvpn-"

// The keys of a normal Windows system.
dns_env_default :: proc() -> DNS_Env {
	return DNS_Env{nrpt_key = NRPT_KEY, gpo_key = NRPT_GPO_KEY}
}

// One applied DNS configuration. Zero value = nothing applied.
DNS :: struct {
	env:       DNS_Env,
	backend:   DNS_Backend,
	active:    bool,
	allocator: mem.Allocator,
	ifname:    string,
	guid:      win.GUID,
	// The interface settings were written.
	interface: bool,
	// The NRPT rule was written.
	nrpt:      bool,
	// Things that could not be done, for the log. Valid until the next apply.
	warnings:  [dynamic]string,
}

dns_destroy :: proc(d: ^DNS) {
	delete(d.ifname, d.allocator)
	for w in d.warnings {
		delete(w, d.warnings.allocator)
	}
	delete(d.warnings)
	d^ = {}
}

// `.Ip_Helper` when SetInterfaceDnsSettings exists, else `.None`.
dns_detect :: proc(env: DNS_Env) -> DNS_Backend {
	if env.force != .None {
		return env.force
	}
	if set_interface_dns_settings() != nil {
		return .Ip_Helper
	}
	return .None
}

// Apply the settings for the interface named `ifname`. `d` is set up from
// scratch. On an error nothing stays applied.
dns_apply :: proc(
	d: ^DNS,
	env: DNS_Env,
	ifname: string,
	s: DNS_Settings,
	allocator := context.allocator,
) -> DNS_Error {
	if d.active {
		return .Invalid
	}
	d^ = {}
	d.env = env
	d.allocator = allocator
	d.warnings.allocator = allocator
	if !dns_valid_ifname(ifname) {
		return .Invalid
	}
	if err := dns_settings_check(s); err != .None {
		return err
	}
	d.backend = dns_detect(env)
	if d.backend == .None {
		return .Unsupported
	}
	guid, gerr := interface_guid(ifname)
	if gerr != .None {
		return gerr
	}
	d.guid = guid
	d.ifname = strings.clone(ifname, allocator)

	v4 := make([dynamic]string, context.temp_allocator)
	v6 := make([dynamic]string, context.temp_allocator)
	all := make([dynamic]string, context.temp_allocator)
	for sv in s.servers {
		text := cnet.address_to_string(sv.address, context.temp_allocator)
		if sv.port != 0 && sv.port != 53 {
			dns_warn(&d.warnings, "dropped the name server %s:%d because Windows cannot use a custom port", text, sv.port)
			continue
		}
		if _, is6 := sv.address.(IP6_Address); is6 {
			append(&v6, text)
		} else {
			append(&v4, text)
		}
		append(&all, text)
	}
	if len(all) == 0 {
		dns_destroy(d)
		return .Invalid
	}
	if gpo_has_rules(env) {
		dns_warn(&d.warnings, "Group Policy sets NRPT rules, so the routing domains of this tunnel will not be used")
	}

	split := len(s.routing_domains) > 0 && !s.default_route
	search := strings.join(s.search_domains, ",", context.temp_allocator)
	err: DNS_Error
	if split {
		err = set_interface_dns(guid, "", "", search)
	} else {
		err = set_interface_dns(guid, strings.join(v4[:], ",", context.temp_allocator), strings.join(v6[:], ",", context.temp_allocator), search)
	}
	if err != .None {
		dns_destroy(d)
		return err
	}
	d.interface = true

	names := make([dynamic]string, context.temp_allocator)
	for r in s.routing_domains {
		if r == "." {
			append(&names, ".")
		} else {
			append(&names, strings.concatenate({".", strings.trim_right(r, ".")}, context.temp_allocator))
		}
	}
	if s.default_route {
		append(&names, ".")
	}
	if len(names) > 0 {
		if err = nrpt_write(env, ifname, names[:], strings.join(all[:], ";", context.temp_allocator)); err != .None {
			_ = set_interface_dns(guid, "", "", "")
			notify_dns_client(nil)
			dns_destroy(d)
			return err
		}
		d.nrpt = true
	}
	notify_dns_client(&d.warnings)
	d.active = true
	return .None
}

// Take the settings away again. After the call `d` holds nothing applied,
// whatever the result.
dns_revert :: proc(d: ^DNS) -> DNS_Error {
	if !d.active {
		return .Not_Applied
	}
	err: DNS_Error
	if d.nrpt {
		err = nrpt_delete(d.env, d.ifname)
	}
	if d.interface {
		// The interface may be gone with its settings.
		ierr := set_interface_dns(d.guid, "", "", "")
		if ierr != .None && err == .None {
			if _, gerr := interface_guid(d.ifname); gerr == .None {
				err = ierr
			}
		}
	}
	notify_dns_client(nil)
	d.active = false
	d.nrpt = false
	d.interface = false
	return err
}

// Call once at start-up, before `dns_apply`, to undo what a crashed run left
// for `ifname`: our NRPT rule, and the interface settings when the interface
// exists. Returns true if something was removed.
dns_cleanup_stale :: proc(env: DNS_Env, ifname: string) -> (restored: bool, err: DNS_Error) {
	if !dns_valid_ifname(ifname) {
		return false, .Invalid
	}
	if nrpt_exists(env, ifname) {
		err = nrpt_delete(env, ifname)
		restored = err == .None
	}
	if guid, gerr := interface_guid(ifname); gerr == .None && set_interface_dns_settings() != nil {
		_ = set_interface_dns(guid, "", "", "")
	}
	if restored {
		notify_dns_client(nil)
	}
	return restored, err
}

// Only the NRPT rule for `ifname` of `dns_cleanup_stale`. It does not touch the
// settings of other interfaces, so it is safe while another client runs a tunnel.
dns_cleanup_stale_record :: proc(env: DNS_Env, ifname: string) -> DNS_Error {
	if !dns_valid_ifname(ifname) {
		return .Invalid
	}
	if !nrpt_exists(env, ifname) {
		return .None
	}
	err := nrpt_delete(env, ifname)
	if err == .None {
		notify_dns_client(nil)
	}
	return err
}

// ---- the clean-up records of the daemons ----

// The name of a backend in a clean-up record.
dns_backend_name :: proc "contextless" (b: DNS_Backend) -> string {
	switch b {
	case .Ip_Helper:
		return "ip-helper"
	case .None:
	}
	return "none"
}

dns_backend_parse :: proc(name: string) -> (b: DNS_Backend, ok: bool) {
	if name == "ip-helper" {
		return .Ip_Helper, true
	}
	return .None, false
}

// Windows has no DNS setting that two daemons share: the rules and the
// interface settings are per interface.
dns_backend_shared :: proc(name: string) -> bool {
	return false
}

// What the backend changes for `ifname`, for the reader of a record.
dns_record_detail :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, allocator := context.temp_allocator) -> string {
	if b != .Ip_Helper {
		return ""
	}
	return strings.concatenate({"nrpt ", NRPT_PREFIX, ifname}, allocator)
}

// Reverts the DNS change of a daemon that is dead, from its record: the NRPT
// rule of `ifname`, and the interface settings when the interface exists.
dns_cleanup_dead :: proc(env: DNS_Env, b: DNS_Backend, ifname: string, link_exists: bool) -> (restored: bool, err: DNS_Error) {
	if b != .Ip_Helper {
		return false, .Invalid
	}
	if !link_exists {
		return false, dns_cleanup_stale_record(env, ifname)
	}
	return dns_cleanup_stale(env, ifname)
}

// Empty the cache of the DNS Client service.
dns_flush_cache :: proc() -> bool {
	return DnsFlushResolverCache() != win.FALSE
}

// The names of the NRPT rules of ours, allocated from `allocator`.
dns_nrpt_rules :: proc(env: DNS_Env, allocator := context.allocator) -> []string {
	return nrpt_list(env, allocator)
}

// ---- helpers ----

@(private)
interface_guid :: proc(ifname: string) -> (guid: win.GUID, err: DNS_Error) {
	luid: NET_LUID
	if ConvertInterfaceAliasToLuid(win.utf8_to_wstring(ifname, context.temp_allocator), &luid) != 0 {
		return {}, .Invalid
	}
	if ConvertInterfaceLuidToGuid(&luid, &guid) != 0 {
		return {}, .Invalid
	}
	return guid, .None
}

// Write the IPv4 servers, IPv6 servers and search list of one interface. Empty
// strings clear them. DNS registration of the tunnel address is turned off.
@(private)
set_interface_dns :: proc(guid: win.GUID, v4, v6, search: string) -> DNS_Error {
	fn := set_interface_dns_settings()
	if fn == nil {
		return .Unsupported
	}
	s4 := DNS_INTERFACE_SETTINGS {
		version              = DNS_INTERFACE_SETTINGS_VERSION1,
		flags                = DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST | DNS_SETTING_REGISTRATION_ENABLED,
		name_server          = win.utf8_to_wstring(v4, context.temp_allocator),
		search_list          = win.utf8_to_wstring(search, context.temp_allocator),
		registration_enabled = 0,
	}
	if e := fn(guid, &s4); e != 0 {
		return map_reg_error(e)
	}
	s6 := DNS_INTERFACE_SETTINGS {
		version     = DNS_INTERFACE_SETTINGS_VERSION1,
		flags       = DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER,
		name_server = win.utf8_to_wstring(v6, context.temp_allocator),
	}
	if e := fn(guid, &s6); e != 0 && len(v6) > 0 {
		// An interface without IPv6 takes no IPv6 servers; clearing them
		// there is not an error.
		return map_reg_error(e)
	}
	return .None
}

@(private)
map_reg_error :: proc "contextless" (e: u32) -> DNS_Error {
	switch e {
	case ERROR_ACCESS_DENIED:
		return .Permission
	case ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY:
		return .Out_Of_Memory
	case ERROR_INVALID_PARAMETER:
		return .Invalid
	}
	return .Io
}

@(private)
nrpt_key_path :: proc(env: DNS_Env, ifname: string) -> win.wstring {
	return win.utf8_to_wstring(strings.concatenate({env.nrpt_key, `\`, NRPT_PREFIX, ifname}, context.temp_allocator), context.temp_allocator)
}

// UTF-16 text with a NUL after each part, and one more NUL for a REG_MULTI_SZ.
@(private)
wide_parts :: proc(parts: []string, multi: bool) -> []u16 {
	out := make([dynamic]u16, context.temp_allocator)
	for p in parts {
		append(&out, ..win.utf8_to_utf16(p, context.temp_allocator))
		append(&out, 0)
	}
	if multi {
		append(&out, 0)
	}
	return out[:]
}

// The values follow what `Add-DnsClientNrptRule -Namespace ... -NameServers
// ...` writes.
@(private)
nrpt_write :: proc(env: DNS_Env, ifname: string, names: []string, servers: string) -> DNS_Error {
	key: win.HKEY
	st := win.RegCreateKeyExW(
		win.HKEY_LOCAL_MACHINE,
		nrpt_key_path(env, ifname),
		0,
		nil,
		win.REG_OPTION_NON_VOLATILE,
		win.KEY_WRITE | win.KEY_WOW64_64KEY,
		nil,
		&key,
		nil,
	)
	if st != 0 {
		return map_reg_error(u32(st))
	}
	defer win.RegCloseKey(key)

	set_dword :: proc(key: win.HKEY, name: win.wstring, v: u32) -> i32 {
		v := v
		return win.RegSetValueExW(key, name, 0, win.REG_DWORD, (^win.BYTE)(&v), size_of(v))
	}
	set_text :: proc(key: win.HKEY, name: win.wstring, kind: u32, w: []u16) -> i32 {
		return win.RegSetValueExW(key, name, 0, kind, (^win.BYTE)(raw_data(w)), u32(len(w) * 2))
	}
	name_list := wide_parts(names, true)
	server_text := wide_parts({servers}, false)
	empty := wide_parts({""}, false)
	results := [?]i32 {
		set_dword(key, win.L("Version"), 2),
		set_text(key, win.L("Name"), win.REG_MULTI_SZ, name_list),
		set_text(key, win.L("GenericDNSServers"), win.REG_SZ, server_text),
		// 0x8: the rule sets generic DNS servers.
		set_dword(key, win.L("ConfigOptions"), 8),
		set_text(key, win.L("IPSECCARestriction"), win.REG_SZ, empty),
	}
	for r in results {
		if r != 0 {
			_ = nrpt_delete(env, ifname)
			return map_reg_error(u32(r))
		}
	}
	return .None
}

@(private)
nrpt_delete :: proc(env: DNS_Env, ifname: string) -> DNS_Error {
	st := RegDeleteTreeW(win.HKEY_LOCAL_MACHINE, nrpt_key_path(env, ifname))
	if st == 0 || u32(st) == ERROR_FILE_NOT_FOUND {
		return .None
	}
	return map_reg_error(u32(st))
}

@(private)
nrpt_exists :: proc(env: DNS_Env, ifname: string) -> bool {
	key: win.HKEY
	if win.RegOpenKeyExW(win.HKEY_LOCAL_MACHINE, nrpt_key_path(env, ifname), 0, win.KEY_READ | win.KEY_WOW64_64KEY, &key) != 0 {
		return false
	}
	win.RegCloseKey(key)
	return true
}

@(private)
nrpt_list :: proc(env: DNS_Env, allocator: mem.Allocator) -> []string {
	out := make([dynamic]string, allocator)
	key: win.HKEY
	path := win.utf8_to_wstring(env.nrpt_key, context.temp_allocator)
	if win.RegOpenKeyExW(win.HKEY_LOCAL_MACHINE, path, 0, win.KEY_READ | win.KEY_WOW64_64KEY, &key) != 0 {
		return out[:]
	}
	defer win.RegCloseKey(key)
	for i := u32(0); ; i += 1 {
		buf: [256]u16
		n := u32(len(buf))
		if win.RegEnumKeyExW(key, i, raw_data(buf[:]), &n, nil, nil, nil, nil) != 0 {
			break
		}
		name, _ := win.utf16_to_utf8(buf[:n], allocator)
		if strings.has_prefix(name, NRPT_PREFIX) {
			append(&out, name)
		} else {
			delete(name, allocator)
		}
	}
	return out[:]
}

@(private)
gpo_has_rules :: proc(env: DNS_Env) -> bool {
	if len(env.gpo_key) == 0 {
		return false
	}
	key: win.HKEY
	path := win.utf8_to_wstring(env.gpo_key, context.temp_allocator)
	if win.RegOpenKeyExW(win.HKEY_LOCAL_MACHINE, path, 0, win.KEY_READ | win.KEY_WOW64_64KEY, &key) != 0 {
		return false
	}
	defer win.RegCloseKey(key)
	subkeys: u32
	if win.RegQueryInfoKeyW(key, nil, nil, nil, &subkeys, nil, nil, nil, nil, nil, nil, nil) != 0 {
		return false
	}
	return subkeys > 0
}

// Have the DNS Client service read the NRPT again, then flush its cache.
@(private)
notify_dns_client :: proc(warnings: ^[dynamic]string) {
	ok := false
	e: u32
	if m := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT); m != nil {
		if svc := OpenServiceW(m, win.L("Dnscache"), SERVICE_PAUSE_CONTINUE); svc != nil {
			status: SERVICE_STATUS
			ok = ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &status) != win.FALSE
			if !ok {
				e = win.GetLastError()
			}
			CloseServiceHandle(svc)
		} else {
			e = win.GetLastError()
		}
		CloseServiceHandle(m)
	} else {
		e = win.GetLastError()
	}
	if !ok {
		dns_warn(warnings, "could not notify the DNS Client service about the change (error %d)", e)
	}
	if !dns_flush_cache() {
		dns_warn(warnings, "could not flush the DNS cache")
	}
}
