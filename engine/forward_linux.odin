// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

// Linux: the listeners of `forward` are limited to the tunnel device
// (SO_BINDTODEVICE). A Linux host takes packets for one of its addresses on
// every interface. With a bind to the tunnel address alone, a host on another
// network of the client that routes the tunnel address to the client reaches
// a forward port, and `allow-inbound` does not see those packets.
fwd_device :: proc(d: ^Daemon) -> (name: string, limited: bool) {
	return tun_name(d), true
}
