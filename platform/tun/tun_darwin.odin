// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package tun

import "core:c"
import "core:sys/posix"

// Tunnel on macOS: a utun interface, created with the kernel control
// "com.apple.net.utun_control" (<net/if_utun.h>, <sys/kern_control.h>,
// <sys/sys_domain.h>). No Network Extension: the process opens the control
// socket itself, so it must be root. MTU, addresses and routes are not set
// here: platform/sysnet does them with ifconfig(8) and route(8).
//
// Differences from Linux:
//   - The descriptor is a PF_SYSTEM datagram socket. Every `read` and `write`
//     has a 4 byte header before the packet: the address family as a
//     big-endian u32 (AF_INET 2, AF_INET6 30). `read` removes it and `write`
//     adds it, so callers see plain IP packets.
//   - A utun interface is named `utunN` and cannot be renamed. `Options.name`
//     is "" (the kernel picks the lowest free N) or `utunN` (that unit;
//     `.Busy` if it exists). Any other name is `.Invalid`.
//   - No offloads (`vnet` is false), no multi-queue.
//   - An interface not configured yet accepts reads and writes.
//   - The interface goes away when the descriptor closes.

// Longest interface name including the terminating NUL.
IFNAMSIZ :: 16

// The size of the family header in front of every packet.
AF_HEADER_LEN :: 4

DEFAULT_NAME :: "utun"

// One utun interface.
Device :: struct {
	fd:       i32,
	name_buf: [IFNAMSIZ]u8,
	name_len: int,
	blocking: bool,
	// True if `close` should close `fd`. False for a descriptor the host
	// application gave us.
	owned:    bool,
	// Always false and empty on macOS: utun has no offloads.
	vnet:     bool,
	offloads: Offload_Set,
}

// The interface name (a view into the Device).
name :: proc "contextless" (dev: ^Device) -> string {
	return string(dev.name_buf[:dev.name_len])
}

is_open :: proc "contextless" (dev: ^Device) -> bool {
	return dev.fd >= 0
}

// The prefix of every utun name.
@(private)
NAME_PREFIX :: "utun"

// Values from the system headers.
@(private)
PF_SYSTEM :: 32
@(private)
AF_SYSTEM :: 32
@(private)
SYSPROTO_CONTROL :: 2
@(private)
AF_SYS_CONTROL :: 2
@(private)
UTUN_OPT_IFNAME :: 2
@(private)
UTUN_CONTROL_NAME :: "com.apple.net.utun_control"
// _IOWR('N', 3, struct ctl_info)
@(private)
CTLIOCGINFO :: c.ulong(0xC0644E03)
@(private)
AF_INET :: 2
@(private)
AF_INET6 :: 30

// struct ctl_info.
@(private)
Ctl_Info :: struct {
	id:   u32,
	name: [96]u8,
}
#assert(size_of(Ctl_Info) == 100)

// struct sockaddr_ctl.
@(private)
Sockaddr_Ctl :: struct {
	len:      u8,
	family:   u8,
	sysaddr:  u16,
	id:       u32,
	unit:     u32,
	reserved: [5]u32,
}
#assert(size_of(Sockaddr_Ctl) == 32)

foreign import libsystem "system:System"

@(default_calling_convention = "c")
foreign libsystem {
	// Variadic in C: the Odin declaration must say so, because arguments after
	// the named ones go on the stack on Apple's arm64 ABI.
	ioctl :: proc(fd: c.int, request: c.ulong, #c_vararg args: ..any) -> c.int ---
	socket :: proc(domain, type, protocol: c.int) -> c.int ---
	connect :: proc(fd: c.int, addr: rawptr, len: u32) -> c.int ---
	getsockopt :: proc(fd: c.int, level, name: c.int, value: rawptr, len: ^u32) -> c.int ---
}

map_errno :: proc "contextless" (e: posix.Errno) -> Error {
	#partial switch e {
	case .NONE:
		return .None
	case .ENOENT, .ENODEV, .ENXIO, .EPROTONOSUPPORT, .EAFNOSUPPORT:
		return .No_Device
	case .EPERM, .EACCES:
		return .Permission
	case .EBUSY, .EADDRINUSE:
		return .Busy
	case .EINVAL:
		return .Invalid
	case .ENOTTY, .EOPNOTSUPP, .ENOSYS:
		return .Unsupported
	case .EAGAIN, .ENOBUFS:
		return .Would_Block
	case .EMSGSIZE:
		return .Message_Too_Long
	case .EIO:
		return .Io
	case .EBADF:
		return .Closed
	}
	return .Other
}

// The unit of a name: "" is 0 (the kernel picks), `utunN` is N+1.
@(private)
unit_of_name :: proc "contextless" (s: string) -> (unit: u32, ok: bool) {
	if len(s) == 0 {
		return 0, true
	}
	if len(s) <= len(NAME_PREFIX) || s[:len(NAME_PREFIX)] != NAME_PREFIX {
		return 0, false
	}
	digits := s[len(NAME_PREFIX):]
	if len(digits) > 6 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	n: u32
	for ch in transmute([]u8)digits {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n * 10 + u32(ch - '0')
	}
	return n + 1, true
}

// Whether `s` is a name a utun interface can have (`utun` and a number).
is_utun_name :: proc "contextless" (s: string) -> bool {
	if len(s) == 0 {
		return false
	}
	_, ok := unit_of_name(s)
	return ok
}

// Create a utun interface. Needs root. `opts.offload`, `opts.multi_queue`
// and `opts.blocking` are explained at the top of this file.
open :: proc(opts: Options = {}) -> (dev: Device, err: Error) {
	dev = {
		fd = -1,
	}
	if opts.multi_queue {
		return dev, .Unsupported
	}
	unit, ok := unit_of_name(opts.name)
	if !ok {
		return dev, .Invalid
	}

	fd := socket(PF_SYSTEM, c.int(posix.Sock.DGRAM), SYSPROTO_CONTROL)
	if fd < 0 {
		return dev, map_errno(posix.errno())
	}
	posix.fcntl(posix.FD(fd), .SETFD, posix.FD_CLOEXEC)

	info: Ctl_Info
	copy(info.name[:], UTUN_CONTROL_NAME)
	if ioctl(fd, CTLIOCGINFO, &info) < 0 {
		e := map_errno(posix.errno())
		posix.close(posix.FD(fd))
		// ENOENT here means the kernel has no utun control.
		return dev, e
	}
	sa := Sockaddr_Ctl {
		len     = size_of(Sockaddr_Ctl),
		family  = AF_SYSTEM,
		sysaddr = AF_SYS_CONTROL,
		id      = info.id,
		unit    = unit,
	}
	if connect(fd, &sa, size_of(Sockaddr_Ctl)) < 0 {
		e := map_errno(posix.errno())
		posix.close(posix.FD(fd))
		// The unit is taken (EBUSY) or the kernel has no such control (ENOENT).
		return dev, e
	}

	dev, err = from_fd(fd, !opts.blocking, true)
	if err != .None {
		posix.close(posix.FD(fd))
		return dev, err
	}
	return dev, .None
}

// Wrap a descriptor of a utun interface that something else created. `owned`
// causes `close` to close it.
from_fd :: proc(fd: i32, nonblocking := true, owned := false) -> (dev: Device, err: Error) {
	dev = {
		fd = -1,
	}
	buf: [IFNAMSIZ]u8
	size := u32(len(buf))
	if getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, raw_data(buf[:]), &size) < 0 {
		return dev, .Unsupported
	}
	n := 0
	for n < int(size) && n < len(buf) && buf[n] != 0 {
		n += 1
	}
	dev.fd = fd
	dev.name_buf = buf
	dev.name_len = n
	dev.blocking = !nonblocking
	dev.owned = owned
	if e := set_nonblocking(fd, nonblocking); e != .None {
		dev.fd = -1
		return dev, e
	}
	return dev, .None
}

set_nonblocking :: proc(fd: i32, on: bool) -> Error {
	fl := posix.fcntl(posix.FD(fd), .GETFL)
	if fl < 0 {
		return map_errno(posix.errno())
	}
	if on {
		fl |= posix.O_NONBLOCK
	} else {
		fl &~= posix.O_NONBLOCK
	}
	if posix.fcntl(posix.FD(fd), .SETFL, fl) < 0 {
		return map_errno(posix.errno())
	}
	return .None
}

close :: proc(dev: ^Device) {
	if dev.fd >= 0 && dev.owned {
		posix.close(posix.FD(dev.fd))
	}
	dev.fd = -1
}

// Read one packet. Returns its length. `.Would_Block` when none waits. `buf`
// should be at least the MTU: a longer packet is cut. The family header is
// removed.
read :: proc(dev: ^Device, buf: []u8) -> (n: int, err: Error) {
	if dev.fd < 0 {
		return 0, .Closed
	}
	hdr: [AF_HEADER_LEN]u8
	iov := [2]posix.iovec{{iov_base = raw_data(hdr[:]), iov_len = AF_HEADER_LEN}, {iov_base = raw_data(buf), iov_len = uint(len(buf))}}
	for {
		got := posix.readv(posix.FD(dev.fd), raw_data(iov[:]), 2)
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return 0, map_errno(e)
		}
		if got <= AF_HEADER_LEN {
			// Not a packet. A utun never gives this; treat it as nothing there.
			return 0, .Would_Block
		}
		return int(got) - AF_HEADER_LEN, .None
	}
}

// The family header for the packet that starts with `b`.
@(private)
af_header :: proc "contextless" (b: []u8) -> (hdr: [AF_HEADER_LEN]u8, ok: bool) {
	if len(b) == 0 {
		return {}, false
	}
	switch b[0] >> 4 {
	case 4:
		hdr[3] = AF_INET
	case 6:
		hdr[3] = AF_INET6
	case:
		return {}, false
	}
	return hdr, true
}

// Inject one packet into the host's network stack (it arrives as if received
// from the tunnel). The whole packet is written or the call fails. The family
// header is added.
write :: proc(dev: ^Device, pkt: []u8) -> Error {
	pieces := [1][]u8{pkt}
	return write_v(dev, pieces[:])
}

// The most pieces `write_v` takes.
MAX_PIECES :: 63

// Write one packet that is built from several pieces (writev). The first piece
// must not be empty.
write_v :: proc(dev: ^Device, pieces: [][]u8) -> Error {
	if dev.fd < 0 {
		return .Closed
	}
	if len(pieces) == 0 || len(pieces) > MAX_PIECES {
		return .Invalid
	}
	hdr, ok := af_header(pieces[0])
	if !ok {
		return .Invalid
	}
	iov: [MAX_PIECES + 1]posix.iovec
	iov[0] = {
		iov_base = raw_data(hdr[:]),
		iov_len  = AF_HEADER_LEN,
	}
	total := AF_HEADER_LEN
	for p, i in pieces {
		iov[i + 1] = {
			iov_base = raw_data(p),
			iov_len  = uint(len(p)),
		}
		total += len(p)
	}
	for {
		got := posix.writev(posix.FD(dev.fd), raw_data(iov[:]), c.int(len(pieces) + 1))
		if got < 0 {
			e := posix.errno()
			if e == .EINTR {
				continue
			}
			return map_errno(e)
		}
		if int(got) != total {
			return .Io
		}
		return .None
	}
}
