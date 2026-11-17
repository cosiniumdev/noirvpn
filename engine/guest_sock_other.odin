// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build !linux
package engine

import cnet "core:net"
import net "noir:platform/net"

// A TCP connection of the engine. Only Linux (Android) needs `protect` before
// the connect, so this is the plain call.
engine_tcp_connect :: proc(d: ^Daemon, ep: cnet.Endpoint, opts: net.TCP_Options) -> (s: net.Socket, in_progress: bool, err: net.Error) {
	return net.tcp_connect(ep, opts)
}
