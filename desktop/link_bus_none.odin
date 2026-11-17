// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
#+build !darwin
#+build !freebsd
#+build !openbsd
#+build !netbsd
#+build !windows
package main

// The bus form of the link on systems where the service cannot be reached
// (no bus transport). The attach view says so.

BUS_LINK :: false

Job_Kind :: enum u8 {
	Search,
	Status,
	Stats,
	Connect,
	Disconnect,
	Auth_Supply,
	Profile_Set,
	Profile_Check,
	Profile_Clear,
	Stop,
}

Bus_Impl :: struct {}

bus_start :: proc(app: ^App, socket: string) {
	app.link.state = .Not_Found
	attach_enter(app)
}

bus_stop :: proc(app: ^App) {}

bus_register_again :: proc(app: ^App) {}

bus_request :: proc(app: ^App, kind: Job_Kind) {}

bus_auth_supply :: proc(app: ^App, user, pass: string) {}

bus_auth_supply_key :: proc(app: ^App, pass: string) {}

bus_profile_job :: proc(app: ^App, kind: Job_Kind, text, label: string, web: bool) {}

link_poll :: proc(app: ^App) -> bool {
	return false
}
