// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package tun opens and uses a layer 3 tunnel device.
//   Linux    /dev/net/tun (kernel tuntap.rst, tun(4))
//   Windows  wintun adapter (tun_windows.odin)
//   macOS    utun interface created by the process (tun_darwin.odin has the
//            4 byte family header and the `utunN` names)
// Each file provides the same names. The rest of this comment is Linux.
//
// The device is a file descriptor. One `read` returns one IP packet, one
// `write` injects one, no packet-info header (IFF_NO_PI). The
// first nibble gives the IP version.
//
// Offloads (`Options.offload`): the device opens with IFF_VNET_HDR and the
// kernel may hand over TCP and UDP segmentation offload packets
// (TUNSETOFFLOAD). Then:
//   - `read` returns a 10 byte `struct virtio_net_hdr` and the IP packet (up
//     to 65535 bytes, partial checksum)
//   - `write` takes the same header first (`write` and `write_v` add a zero
//     header for a plain packet)
//   - the caller cuts large packets and completes checksums (platform/offload)
//   - if the kernel refuses, the device works without a header (`dev.vnet`
//     is false)
//
// Rules:
//   - Non-blocking by default. `.Would_Block`: wait for readiness in the
//     event loop.
//   - Buffers are the caller's. No allocation.
//   - `read` into a buffer smaller than the packet cuts it silently. Give at
//     least the MTU (2048 is safe for MTU 1500).
//   - A device created by `open` disappears when its last descriptor closes.
//     Opening needs CAP_NET_ADMIN, or a device a privileged helper created.
//
// Multi-queue (server workers): open the first queue with `multi_queue =
// true`, then one descriptor per worker with `open_queue`. The kernel spreads
// flows over the queues.
package tun

Error :: enum {
	None,
	// /dev/net/tun does not exist or the driver is missing.
	No_Device,
	// No permission: CAP_NET_ADMIN is needed, or the device node is closed to us.
	Permission,
	// The name is taken (and the device is not multi-queue), or the device is busy.
	Busy,
	// The name is too long or has bad characters, or the kernel refused the
	// name, the flags, the MTU or the packet (EINVAL).
	Invalid,
	// The descriptor is not a tun device, or the kernel lacks a feature.
	Unsupported,
	// Nothing to read, or no room to write. Wait for readiness.
	Would_Block,
	// The packet is larger than the interface MTU.
	Message_Too_Long,
	// The device is down or was removed (EIO). A write to an interface that is
	// not up fails like this.
	Io,
	// The Device has no open descriptor.
	Closed,
	// The system call failed in a way not listed above.
	Other,
}

Options :: struct {
	// Interface name. Empty: the kernel chooses (`tun0`, `tun1`, ...). A
	// pattern such as `noir%d` is allowed. At most 15 bytes. On Windows: the
	// adapter name (empty: `noirvpn`), at most `IFNAMSIZ - 1` bytes;
	// `multi_queue` is `.Unsupported`; `blocking` and `offload` do nothing.
	name:        string,
	// Set the device to multi-queue (IFF_MULTI_QUEUE), so `open_queue` works.
	multi_queue: bool,
	// Leave the descriptor in blocking mode. Default is non-blocking.
	blocking:    bool,
	// Ask for the virtio header and the offloads in `Offload_Set` (all that
	// the kernel takes). See the top of this file.
	offload:     bool,
}

// What the kernel may hand over (TUNSETOFFLOAD, TUN_F_*). The numbers are the
// bit positions of the TUN_F_* values.
Offload_Flag :: enum u32 {
	Csum    = 0, // packets with a partial checksum (TUN_F_CSUM)
	Tso4    = 1, // TCP segmentation offload, IPv4 (TUN_F_TSO4)
	Tso6    = 2, // TCP segmentation offload, IPv6 (TUN_F_TSO6)
	Tso_Ecn = 3, // TSO packets with the CWR flag (TUN_F_TSO_ECN)
	Uso4    = 5, // UDP segmentation offload, IPv4 (TUN_F_USO4)
	Uso6    = 6, // UDP segmentation offload, IPv6 (TUN_F_USO6)
}

Offload_Set :: bit_set[Offload_Flag;u32]

// The offloads `open` asks for.
OFFLOADS_WANTED :: Offload_Set{.Csum, .Tso4, .Tso6, .Tso_Ecn, .Uso4, .Uso6}

// Size of the virtio header (`struct virtio_net_hdr`, without `num_buffers`)
// in front of every packet of a device with `vnet`.
VNET_HDR_LEN :: 10
