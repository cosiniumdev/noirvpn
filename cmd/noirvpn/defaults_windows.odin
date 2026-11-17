// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// The options of a client service when no config file gives them (defaults.odin):
// users who are logged on at this computer may load a profile and connect, as
// the config of `noirvpn service install` says. The control pipes get their names
// from the instance name.
service_default_args :: proc() -> []string {
	out := make([dynamic]string, context.temp_allocator)
	append(&out, "--verb", "3", "--bus-allow", "sid", "S-1-5-4", "operator")
	return out[:]
}
