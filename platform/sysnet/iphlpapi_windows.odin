// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package sysnet

import win "core:sys/windows"

// The parts of the IP Helper API (netioapi.h), the DNS client API and the
// service and registry calls that this package uses. Layouts match the Windows
// SDK 10.0.26100 headers. iphlpapi_windows_test.odin checks sizes and offsets
// printed by a C program built against them.

@(private)
NET_LUID :: u64

@(private)
AF_UNSPEC :: 0
@(private)
AF_INET :: 2
@(private)
AF_INET6 :: 23

// SOCKADDR_INET: a union of sockaddr_in and sockaddr_in6, 28 bytes.
@(private)
SOCKADDR_INET :: struct #raw_union {
	v4:     win.sockaddr_in,
	v6:     win.sockaddr_in6,
	family: u16,
}

@(private)
IP_ADDRESS_PREFIX :: struct {
	prefix:     SOCKADDR_INET,
	prefix_len: u8,
}

@(private)
MIB_IPFORWARD_ROW2 :: struct {
	luid:               NET_LUID,
	index:              u32,
	destination:        IP_ADDRESS_PREFIX,
	next_hop:           SOCKADDR_INET,
	site_prefix_len:    u8,
	valid_lifetime:     u32,
	preferred_lifetime: u32,
	metric:             u32,
	protocol:           u32,
	loopback:           bool,
	autoconfigure:      bool,
	publish:            bool,
	immortal:           bool,
	age:                u32,
	origin:             u32,
}

@(private)
MIB_IPFORWARD_TABLE2 :: struct {
	count: u32,
	table: [1]MIB_IPFORWARD_ROW2,
}

@(private)
MIB_UNICASTIPADDRESS_ROW :: struct {
	address:            SOCKADDR_INET,
	luid:               NET_LUID,
	index:              u32,
	prefix_origin:      u32,
	suffix_origin:      u32,
	valid_lifetime:     u32,
	preferred_lifetime: u32,
	on_link_prefix_len: u8,
	skip_as_source:     bool,
	dad_state:          u32,
	scope_id:           u32,
	creation_time:      i64,
}

@(private)
MIB_UNICASTIPADDRESS_TABLE :: struct {
	count: u32,
	table: [1]MIB_UNICASTIPADDRESS_ROW,
}

@(private)
MIB_IPINTERFACE_ROW :: struct {
	family:                       u16,
	luid:                         NET_LUID,
	index:                        u32,
	max_reassembly_size:          u32,
	interface_identifier:         u64,
	min_router_adv_interval:      u32,
	max_router_adv_interval:      u32,
	advertising_enabled:          bool,
	forwarding_enabled:           bool,
	weak_host_send:               bool,
	weak_host_receive:            bool,
	use_automatic_metric:         bool,
	use_neighbor_unreachability:  bool,
	managed_address_config:       bool,
	other_stateful_config:        bool,
	advertise_default_route:      bool,
	router_discovery_behavior:    i32,
	dad_transmits:                u32,
	base_reachable_time:          u32,
	retransmit_time:              u32,
	path_mtu_discovery_timeout:   u32,
	link_local_address_behavior:  i32,
	link_local_address_timeout:   u32,
	zone_indices:                 [16]u32,
	site_prefix_len:              u32,
	metric:                       u32,
	nl_mtu:                       u32,
	connected:                    bool,
	supports_wake_up_patterns:    bool,
	supports_neighbor_discovery:  bool,
	supports_router_discovery:    bool,
	reachable_time:               u32,
	transmit_offload:             u8,
	receive_offload:              u8,
	disable_default_routes:       bool,
}

@(private)
MIB_IPINTERFACE_TABLE :: struct {
	count: u32,
	table: [1]MIB_IPINTERFACE_ROW,
}

@(private)
DNS_INTERFACE_SETTINGS :: struct {
	version:               u32,
	flags:                 u64,
	domain:                win.wstring,
	name_server:           win.wstring,
	search_list:           win.wstring,
	registration_enabled:  u32,
	register_adapter_name: u32,
	enable_llmnr:          u32,
	query_adapter_name:    u32,
	profile_name_server:   win.wstring,
}

@(private)
DNS_INTERFACE_SETTINGS_VERSION1 :: 1
@(private)
DNS_SETTING_IPV6 :: 0x0001
@(private)
DNS_SETTING_NAMESERVER :: 0x0002
@(private)
DNS_SETTING_SEARCHLIST :: 0x0004
@(private)
DNS_SETTING_REGISTRATION_ENABLED :: 0x0008

// NL_ROUTE_PROTOCOL: a route added by hand ("static").
@(private)
MIB_IPPROTO_NETMGMT :: 3

@(private)
IF_MAX_STRING_SIZE :: 256

// Interface types in the high 16 bits of a NET_LUID.
@(private)
IF_TYPE_SOFTWARE_LOOPBACK :: 24
// The type of a wintun adapter.
@(private)
IF_TYPE_PROP_VIRTUAL :: 53

// Win32 error codes.
@(private)
ERROR_FILE_NOT_FOUND :: 2
@(private)
ERROR_PATH_NOT_FOUND :: 3
@(private)
ERROR_ACCESS_DENIED :: 5
@(private)
ERROR_NOT_ENOUGH_MEMORY :: 8
@(private)
ERROR_NOT_SUPPORTED :: 50
@(private)
ERROR_INVALID_PARAMETER :: 87
@(private)
ERROR_INSUFFICIENT_BUFFER :: 122
@(private)
ERROR_NO_MORE_ITEMS :: 259
@(private)
ERROR_SERVICE_NOT_ACTIVE :: 1062
@(private)
ERROR_NOT_FOUND :: 1168
@(private)
ERROR_NETWORK_UNREACHABLE :: 1231
@(private)
ERROR_HOST_UNREACHABLE :: 1232
@(private)
ERROR_OBJECT_ALREADY_EXISTS :: 5010

foreign import iphlpapi "system:iphlpapi.lib"

@(default_calling_convention = "system", private)
foreign iphlpapi {
	InitializeIpForwardEntry :: proc(row: ^MIB_IPFORWARD_ROW2) ---
	CreateIpForwardEntry2 :: proc(row: ^MIB_IPFORWARD_ROW2) -> u32 ---
	DeleteIpForwardEntry2 :: proc(row: ^MIB_IPFORWARD_ROW2) -> u32 ---
	SetIpForwardEntry2 :: proc(row: ^MIB_IPFORWARD_ROW2) -> u32 ---
	GetIpForwardTable2 :: proc(family: u16, table: ^^MIB_IPFORWARD_TABLE2) -> u32 ---
	GetBestRoute2 :: proc(luid: ^NET_LUID, index: u32, source: ^SOCKADDR_INET, destination: ^SOCKADDR_INET, sort_options: u32, best_route: ^MIB_IPFORWARD_ROW2, best_source: ^SOCKADDR_INET) -> u32 ---
	InitializeUnicastIpAddressEntry :: proc(row: ^MIB_UNICASTIPADDRESS_ROW) ---
	CreateUnicastIpAddressEntry :: proc(row: ^MIB_UNICASTIPADDRESS_ROW) -> u32 ---
	DeleteUnicastIpAddressEntry :: proc(row: ^MIB_UNICASTIPADDRESS_ROW) -> u32 ---
	GetUnicastIpAddressTable :: proc(family: u16, table: ^^MIB_UNICASTIPADDRESS_TABLE) -> u32 ---
	InitializeIpInterfaceEntry :: proc(row: ^MIB_IPINTERFACE_ROW) ---
	GetIpInterfaceEntry :: proc(row: ^MIB_IPINTERFACE_ROW) -> u32 ---
	SetIpInterfaceEntry :: proc(row: ^MIB_IPINTERFACE_ROW) -> u32 ---
	GetIpInterfaceTable :: proc(family: u16, table: ^^MIB_IPINTERFACE_TABLE) -> u32 ---
	FreeMibTable :: proc(memory: rawptr) ---
	ConvertInterfaceAliasToLuid :: proc(alias: win.wstring, luid: ^NET_LUID) -> u32 ---
	ConvertInterfaceLuidToAlias :: proc(luid: ^NET_LUID, alias: [^]u16, length: uint) -> u32 ---
	ConvertInterfaceLuidToIndex :: proc(luid: ^NET_LUID, index: ^u32) -> u32 ---
	ConvertInterfaceIndexToLuid :: proc(index: u32, luid: ^NET_LUID) -> u32 ---
	ConvertInterfaceLuidToGuid :: proc(luid: ^NET_LUID, guid: ^win.GUID) -> u32 ---
}

foreign import dnsapi "system:dnsapi.lib"

@(default_calling_convention = "system", private)
foreign dnsapi {
	// Exported by dnsapi.dll since Windows 2000; not in the SDK headers.
	DnsFlushResolverCache :: proc() -> win.BOOL ---
}

@(private)
SC_HANDLE :: distinct rawptr

@(private)
SERVICE_STATUS :: struct {
	service_type:              u32,
	current_state:             u32,
	controls_accepted:         u32,
	win32_exit_code:           u32,
	service_specific_exit_code: u32,
	check_point:               u32,
	wait_hint:                 u32,
}

foreign import advapi32 "system:advapi32.lib"

@(default_calling_convention = "system", private)
foreign advapi32 {
	OpenSCManagerW :: proc(machine: win.wstring, database: win.wstring, access: u32) -> SC_HANDLE ---
	OpenServiceW :: proc(manager: SC_HANDLE, name: win.wstring, access: u32) -> SC_HANDLE ---
	ControlService :: proc(service: SC_HANDLE, control: u32, status: ^SERVICE_STATUS) -> win.BOOL ---
	CloseServiceHandle :: proc(handle: SC_HANDLE) -> win.BOOL ---
	RegDeleteTreeW :: proc(key: win.HKEY, subkey: win.wstring) -> i32 ---
}

@(private)
SC_MANAGER_CONNECT :: 0x0001
@(private)
SERVICE_PAUSE_CONTINUE :: 0x0040
@(private)
SERVICE_CONTROL_PARAMCHANGE :: 0x00000006

// SetInterfaceDnsSettings is in iphlpapi.dll from Windows 10 2004 (build
// 19041). It is looked up at run time, so the program still starts on an older
// system; DNS is then `.Unsupported`.
@(private)
Set_Interface_Dns_Settings :: #type proc "system" (guid: win.GUID, settings: ^DNS_INTERFACE_SETTINGS) -> u32

@(private)
set_interface_dns_settings :: proc() -> Set_Interface_Dns_Settings {
	@(static) fn: Set_Interface_Dns_Settings
	@(static) looked: bool
	if !looked {
		looked = true
		m := win.GetModuleHandleW(win.L("iphlpapi.dll"))
		if m == nil {
			m = win.LoadLibraryExW(win.L("iphlpapi.dll"), nil, {.LOAD_LIBRARY_SEARCH_SYSTEM32})
		}
		if m != nil {
			fn = Set_Interface_Dns_Settings(win.GetProcAddress(m, "SetInterfaceDnsSettings"))
		}
	}
	return fn
}
