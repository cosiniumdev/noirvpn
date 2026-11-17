// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package tun

import "core:sys/linux"

// Longest interface name including the terminating NUL.
IFNAMSIZ :: 16

// One descriptor of a tun interface. A multi-queue interface has one per queue.
Device :: struct {
	fd:          i32,
	name_buf:    [IFNAMSIZ]u8,
	name_len:    int,
	multi_queue: bool,
	blocking:    bool,
	// True if `close` should close `fd`. False for a descriptor the host
	// application gave us.
	owned:       bool,
	// The device has IFF_VNET_HDR: reads return `VNET_HDR_LEN` bytes of header
	// before the packet, and writes need it.
	vnet:        bool,
	// What the kernel accepted for TUNSETOFFLOAD (empty without `vnet`, or when
	// the descriptor came from `from_fd`).
	offloads:    Offload_Set,
}

// The interface name (a view into the Device).
name :: proc "contextless" (dev: ^Device) -> string {
	return string(dev.name_buf[:dev.name_len])
}

is_open :: proc "contextless" (dev: ^Device) -> bool {
	return dev.fd >= 0
}

// Constants from <linux/if_tun.h>, <linux/if.h> and <linux/sockios.h>. Ioctl
// numbers are _IOC(dir, type, nr, size) = dir<<30 | size<<16 | type<<8 | nr
// (generic layout, shared by all Linux targets Odin supports).
IFF_TUN         :: 0x0001
IFF_TAP         :: 0x0002
IFF_NO_PI       :: 0x1000
IFF_VNET_HDR    :: 0x4000
IFF_MULTI_QUEUE :: 0x0100
IFF_ATTACH_QUEUE :: 0x0200
IFF_DETACH_QUEUE :: 0x0400

TUNSETIFF        :: u32(1 << 30 | 4 << 16 | 'T' << 8 | 202) // _IOW('T', 202, int)
TUNGETIFF        :: u32(2 << 30 | 4 << 16 | 'T' << 8 | 210) // _IOR('T', 210, unsigned int)
TUNSETOFFLOAD    :: u32(1 << 30 | 4 << 16 | 'T' << 8 | 208) // _IOW('T', 208, unsigned int)
TUNGETVNETHDRSZ  :: u32(2 << 30 | 4 << 16 | 'T' << 8 | 215) // _IOR('T', 215, int)
TUNSETVNETHDRSZ  :: u32(1 << 30 | 4 << 16 | 'T' << 8 | 216) // _IOW('T', 216, int)
TUNSETQUEUE      :: u32(1 << 30 | 4 << 16 | 'T' << 8 | 217) // _IOW('T', 217, int)
SIOCGIFFLAGS :: 0x8913
SIOCGIFMTU   :: 0x8921
SIOCSIFMTU   :: 0x8922

// struct ifreq: a 16 byte name, then a 24 byte union (on 64-bit; 16 on 32-bit).
// The kernel copies the size of its own ifreq, so use the larger one.
@(private)
Ifreq :: struct {
	name: [IFNAMSIZ]u8,
	using _: struct #raw_union {
		flags: i16,
		value: i32,
		_pad:  [24]u8,
	},
}
#assert(size_of(Ifreq) == 40)

@(private)
TUN_PATH :: "/dev/net/tun"

map_errno :: proc "contextless" (e: linux.Errno) -> Error {
	#partial switch e {
	case .NONE:
		return .None
	case .ENOENT, .ENODEV, .ENXIO:
		return .No_Device
	case .EPERM, .EACCES:
		return .Permission
	case .EBUSY:
		return .Busy
	case .EINVAL:
		return .Invalid
	case .ENOTTY, .EOPNOTSUPP, .ENOSYS:
		return .Unsupported
	case .EAGAIN:
		return .Would_Block
	case .EMSGSIZE:
		return .Message_Too_Long
	case .EIO, .EBADFD:
		return .Io
	case .EBADF:
		return .Closed
	}
	return .Other
}

@(private)
sys_ioctl :: proc "contextless" (fd: i32, request: u32, arg: rawptr) -> linux.Errno {
	ret := linux.syscall(linux.SYS_ioctl, linux.Fd(fd), request, arg)
	return linux.Errno(-ret) if ret < 0 else .NONE
}

// Create (or attach to) a tun interface: IP-only (IFF_TUN), no packet-info
// header. With `opts.offload` it also gets the virtio header and the offloads
// the kernel allows (see tun.odin). If the kernel refuses them, the device
// opens without.
open :: proc(opts: Options = {}) -> (dev: Device, err: Error) {
	if opts.offload {
		dev, err = open_one(opts, true)
		if err == .None || err == .Permission || err == .Busy || err == .No_Device {
			return
		}
		// The kernel does not do the header or the offloads: try without.
		close(&dev)
	}
	return open_one(opts, false)
}

@(private)
open_one :: proc(opts: Options, offload: bool) -> (dev: Device, err: Error) {
	dev = {
		fd = -1,
	}
	if len(opts.name) >= IFNAMSIZ {
		return dev, .Invalid
	}
	for c in transmute([]u8)opts.name {
		if c == 0 || c == '/' || c == ' ' {
			return dev, .Invalid
		}
	}

	flags := linux.Open_Flags{.RDWR, .CLOEXEC}
	if !opts.blocking {
		flags += {.NONBLOCK}
	}
	fd, e := linux.open(TUN_PATH, flags)
	if e != .NONE {
		return dev, map_errno(e)
	}

	ifr: Ifreq
	copy(ifr.name[:], opts.name)
	ifr.flags = IFF_TUN | IFF_NO_PI
	if opts.multi_queue {
		ifr.flags |= IFF_MULTI_QUEUE
	}
	if offload {
		ifr.flags |= IFF_VNET_HDR
	}
	if ie := sys_ioctl(i32(fd), TUNSETIFF, &ifr); ie != .NONE {
		// A deferred close could not clear the returned fd, so close here.
		linux.close(fd)
		return dev, map_errno(ie)
	}
	dev.fd = i32(fd)
	dev.owned = true
	dev.blocking = opts.blocking
	dev.multi_queue = opts.multi_queue
	if offload {
		// The header is 10 bytes: say so, and ask for the offloads.
		sz := i32(VNET_HDR_LEN)
		if se := sys_ioctl(dev.fd, TUNSETVNETHDRSZ, &sz); se != .NONE {
			return dev, map_errno(se)
		}
		set, oe := negotiate_offloads(dev.fd)
		if oe != .None {
			return dev, oe
		}
		dev.vnet = true
		dev.offloads = set
	}
	// The kernel writes back the real name.
	n := 0
	for n < IFNAMSIZ && ifr.name[n] != 0 {
		n += 1
	}
	copy(dev.name_buf[:], ifr.name[:n])
	dev.name_len = n
	return dev, .None
}

// Tells the kernel which offloads we take. Starts with all and drops what the
// kernel refuses: first the UDP ones (kernel 6.2), then the ECN flag, then the
// TCP ones. Returns what was accepted. EINVAL for every try: no offloads at
// all.
@(private)
negotiate_offloads :: proc(fd: i32) -> (set: Offload_Set, err: Error) {
	tries := [?]Offload_Set {
		OFFLOADS_WANTED,
		{.Csum, .Tso4, .Tso6, .Tso_Ecn},
		{.Csum, .Tso4, .Tso6},
		{.Csum},
	}
	last := linux.Errno.NONE
	for want in tries {
		arg := u32(transmute(u32)want)
		last = sys_ioctl(fd, TUNSETOFFLOAD, rawptr(uintptr(arg)))
		if last == .NONE {
			return want, .None
		}
		if last != .EINVAL {
			break
		}
	}
	return {}, map_errno(last)
}

// Open another queue of the same multi-queue interface, for another thread.
// `dev` must be opened with `multi_queue = true`. The queue gets the same
// header and offloads as `dev` (the kernel keeps one setting per device).
open_queue :: proc(dev: ^Device) -> (queue: Device, err: Error) {
	if !dev.multi_queue {
		return {fd = -1}, .Unsupported
	}
	return open({name = name(dev), multi_queue = true, blocking = dev.blocking, offload = dev.vnet})
}

// Wrap a descriptor the host application gave us (for example from Android's
// VpnService). It must be a tun descriptor in IP mode without packet info.
// `owned`: whether `close` may close it. The name is read back if it is a tun
// device, else left empty.
from_fd :: proc(fd: i32, nonblocking := true, owned := false) -> (dev: Device, err: Error) {
	dev = {
		fd    = fd,
		owned = owned,
	}
	if fd < 0 {
		return {fd = -1}, .Closed
	}
	if nonblocking {
		if fe := set_nonblocking(fd, true); fe != .None {
			return {fd = -1}, fe
		}
	} else {
		dev.blocking = true
	}
	ifr: Ifreq
	if sys_ioctl(fd, TUNGETIFF, &ifr) == .NONE {
		n := 0
		for n < IFNAMSIZ && ifr.name[n] != 0 {
			n += 1
		}
		copy(dev.name_buf[:], ifr.name[:n])
		dev.name_len = n
		dev.multi_queue = ifr.flags & IFF_MULTI_QUEUE != 0
		// A descriptor that was created with the header in front of its packets.
		dev.vnet = ifr.flags & IFF_VNET_HDR != 0
	}
	return dev, .None
}

// Switch a descriptor between blocking and non-blocking mode.
set_nonblocking :: proc(fd: i32, on: bool) -> Error {
	flags, e := linux.fcntl_getfl(linux.Fd(fd), .GETFL)
	if e != .NONE {
		return map_errno(e)
	}
	if on {
		flags += {.NONBLOCK}
	} else {
		flags -= {.NONBLOCK}
	}
	return map_errno(linux.fcntl_setfl(linux.Fd(fd), .SETFL, flags))
}

close :: proc(dev: ^Device) {
	if dev.fd >= 0 && dev.owned {
		linux.close(linux.Fd(dev.fd))
	}
	dev.fd = -1
}

// Read one packet. Returns its length. `.Would_Block` when none waits. `buf`
// should be at least the MTU: a longer packet is cut.
//
// With `dev.vnet`: the first `VNET_HDR_LEN` bytes are the virtio header, then
// the IP packet. It can be a large TSO or USO packet, up to 65535 bytes. Give
// `VNET_HDR_LEN + 65535` bytes: the kernel cuts what does not fit and the rest
// of that packet is lost.
read :: proc(dev: ^Device, buf: []u8) -> (n: int, err: Error) {
	for {
		got, e := linux.read(linux.Fd(dev.fd), buf)
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return 0, map_errno(e)
		}
		return got, .None
	}
}

// Inject one packet into the host's network stack (it arrives as if received
// from the tunnel). The whole packet is written or the call fails. The
// interface must be up (else the kernel returns EIO, `.Io`).
//
// A device with `vnet` needs the virtio header before the packet. This call
// adds a zero one (plain packet, the kernel checks checksums). Use `write_v`
// for a header of your own.
write :: proc(dev: ^Device, pkt: []u8) -> Error {
	if dev.vnet {
		zero: [VNET_HDR_LEN]u8
		pieces := [2][]u8{zero[:], pkt}
		return write_v(dev, pieces[:])
	}
	for {
		got, e := linux.write(linux.Fd(dev.fd), pkt)
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return map_errno(e)
		}
		if got != len(pkt) {
			return .Io
		}
		return .None
	}
}

// A slice and a `struct iovec` have the same layout: pointer, then length.
#assert(size_of([]u8) == size_of(linux.IO_Vec))

// Write one packet built from several pieces (writev). With `vnet` the first
// piece must be the virtio header. The kernel joins the pieces: all is
// written or the call fails. At most 1024 pieces (the kernel's IOV_MAX).
write_v :: proc(dev: ^Device, pieces: [][]u8) -> Error {
	if len(pieces) == 0 || len(pieces) > 1024 {
		return .Invalid
	}
	total := 0
	for p in pieces {
		total += len(p)
	}
	iov := transmute([]linux.IO_Vec)pieces
	for {
		got, e := linux.writev(linux.Fd(dev.fd), iov)
		if e == .EINTR {
			continue
		}
		if e != .NONE {
			return map_errno(e)
		}
		if got != total {
			return .Io
		}
		return .None
	}
}

// Run an interface ioctl on a throwaway socket (the interface lives in the
// network namespace of this process).
@(private)
if_ioctl :: proc(request: u32, ifr: ^Ifreq) -> Error {
	// Any socket works for interface ioctls. IPv4 first; a unix socket if the
	// kernel has no IPv4.
	fd, e := linux.socket(.INET, .DGRAM, {.CLOEXEC}, .UNSPECIFIED)
	if e != .NONE {
		fd, e = linux.socket(.UNIX, .DGRAM, {.CLOEXEC}, .UNSPECIFIED)
		if e != .NONE {
			return map_errno(e)
		}
	}
	defer linux.close(fd)
	return map_errno(sys_ioctl(i32(fd), request, ifr))
}

// Set the interface MTU (SIOCSIFMTU). The device must have a name (it came
// from `open`, or `from_fd` could read it).
set_mtu :: proc(dev: ^Device, mtu: int) -> Error {
	if dev.name_len == 0 {
		return .Unsupported
	}
	ifr: Ifreq
	copy(ifr.name[:], name(dev))
	ifr.value = i32(mtu)
	return if_ioctl(SIOCSIFMTU, &ifr)
}

// Read the interface MTU (SIOCGIFMTU).
get_mtu :: proc(dev: ^Device) -> (mtu: int, err: Error) {
	if dev.name_len == 0 {
		return 0, .Unsupported
	}
	ifr: Ifreq
	copy(ifr.name[:], name(dev))
	if e := if_ioctl(SIOCGIFMTU, &ifr); e != .None {
		return 0, e
	}
	return int(ifr.value), .None
}

// Read the TUNSETIFF flags back (TUNGETIFF).
get_flags :: proc(dev: ^Device) -> (flags: u16, err: Error) {
	ifr: Ifreq
	if e := sys_ioctl(dev.fd, TUNGETIFF, &ifr); e != .NONE {
		return 0, map_errno(e)
	}
	return u16(ifr.flags), .None
}
