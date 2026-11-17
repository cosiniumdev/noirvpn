// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// Package offload splits and joins IP packets for a tun device that uses
// IFF_VNET_HDR. It does no I/O, takes no locks and does not allocate.
//
// With IFF_VNET_HDR each tun read returns a 10 byte `struct virtio_net_hdr`
// and one IP packet. It may be a "super-packet": a TSO (TCP) or USO (UDP)
// burst of up to 65535 bytes, not cut into MTU packets, with a checksum that
// may be partial. Each write takes the same header and a packet, so a run of
// TCP segments can cross into the kernel as one packet.
//
//	split   tun -> link. `split_init` / `split_next` cut a super-packet into
//	        ordinary packets (correct lengths, sequence numbers, IPv4 ids,
//	        flags, full checksums). Needed before encryption: the peer (stock
//	        OpenVPN) expects ordinary packets.
//	coal    link -> tun. `coal_push` takes decrypted TCP segments and joins
//	        consecutive segments of one flow. `coal_pop` gives the packets to
//	        write: a virtio header and a list of pieces for `writev`.
//
// Formats: virtio_net_hdr from <linux/virtio_net.h> (legacy 10 byte form, used
// by a tun device unless TUNSETVNETHDRSZ says otherwise), RFC 791 (IPv4),
// RFC 8200 (IPv6), RFC 793 (TCP), RFC 768 (UDP), RFC 1071 (checksum).
//
// Rules:
//
//   - Every procedure that reads a packet checks all lengths first. A short,
//     lying or garbage packet gives an error (split) or passes as a plain
//     packet (coal). No index outside a slice: bounds checks are on in
//     release builds, so a mistake would crash.
//   - `hdr_len` and the flag `DATA_VALID` are not trusted. Header sizes come
//     from the packet.
//   - Tests (*_test.odin) use their own slow checksum and packet builder.
package offload

// The format is little endian on the wire of the tun (native endian) and this
// package reads and writes it that way.
#assert(ODIN_ENDIAN == .Little)

// Size of the legacy `struct virtio_net_hdr`.
VNET_HDR_LEN :: 10

// `Vnet_Hdr.flags`.
F_NEEDS_CSUM :: 1 // the checksum is partial: see csum_start and csum_offset
F_DATA_VALID :: 2 // the checksum was checked already

// `Vnet_Hdr.gso_type`.
GSO_NONE :: 0 // one ordinary packet
GSO_TCPV4 :: 1 // TCP over IPv4 (TSO)
GSO_UDP :: 3 // IPv4 UDP fragmentation (UFO): not supported, always refused
GSO_TCPV6 :: 4 // TCP over IPv6
GSO_UDP_L4 :: 5 // UDP over IPv4 or IPv6 (USO)
GSO_ECN :: 0x80 // flag added to a TCP type: the packet may carry CWR

// The virtio header before every packet on the tun.
//
// F_NEEDS_CSUM: the transport checksum is partial. `csum_start` is where the
// transport header starts in the IP packet. `csum_offset` is where its
// checksum field is, from `csum_start` (16 for TCP, 6 for UDP). The field
// holds the folded pseudo-header sum, not inverted.
Vnet_Hdr :: struct {
	flags:       u8,
	gso_type:    u8,
	hdr_len:     u16,
	gso_size:    u16,
	csum_start:  u16,
	csum_offset: u16,
}

// Reads a header from the first 10 bytes of `b`.
vnet_decode :: proc "contextless" (b: []u8) -> (h: Vnet_Hdr, ok: bool) {
	if len(b) < VNET_HDR_LEN {
		return {}, false
	}
	h.flags = b[0]
	h.gso_type = b[1]
	h.hdr_len = u16(b[2]) | u16(b[3]) << 8
	h.gso_size = u16(b[4]) | u16(b[5]) << 8
	h.csum_start = u16(b[6]) | u16(b[7]) << 8
	h.csum_offset = u16(b[8]) | u16(b[9]) << 8
	return h, true
}

// Writes the 10 bytes of the header to the start of `b`.
vnet_encode :: proc "contextless" (b: []u8, h: Vnet_Hdr) -> bool {
	if len(b) < VNET_HDR_LEN {
		return false
	}
	b[0] = h.flags
	b[1] = h.gso_type
	b[2], b[3] = u8(h.hdr_len), u8(h.hdr_len >> 8)
	b[4], b[5] = u8(h.gso_size), u8(h.gso_size >> 8)
	b[6], b[7] = u8(h.csum_start), u8(h.csum_start >> 8)
	b[8], b[9] = u8(h.csum_offset), u8(h.csum_offset >> 8)
	return true
}

Error :: enum {
	None,
	// The packet is empty or shorter than its headers say.
	Short,
	// The first nibble is not 4 or 6.
	Not_Ip,
	// A header field is wrong: IP version or protocol does not fit the GSO
	// type, a header length points outside the packet, or csum_start or
	// csum_offset is not where the transport checksum is.
	Bad_Header,
	// The length in the IP header is not the length of the packet.
	Bad_Length,
	// A kind of packet that is not handled: UFO, an IPv6 fragment header, ...
	Unsupported,
	// The output would be larger than the caller can take, or there would be
	// too many segments.
	Too_Big,
}

// Flag bits of a TCP header (byte 13).
@(private)
TCP_FIN :: 0x01
@(private)
TCP_SYN :: 0x02
@(private)
TCP_RST :: 0x04
@(private)
TCP_PSH :: 0x08
@(private)
TCP_ACK :: 0x10
@(private)
TCP_URG :: 0x20
@(private)
TCP_ECE :: 0x40
@(private)
TCP_CWR :: 0x80

@(private)
PROTO_TCP :: 6
@(private)
PROTO_UDP :: 17

@(private)
be16 :: #force_inline proc "contextless" (b: []u8) -> u16 {
	return u16(b[0]) << 8 | u16(b[1])
}

@(private)
be32 :: #force_inline proc "contextless" (b: []u8) -> u32 {
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}

@(private)
put_be16 :: #force_inline proc "contextless" (b: []u8, v: u16) {
	b[0] = u8(v >> 8)
	b[1] = u8(v)
}

@(private)
put_be32 :: #force_inline proc "contextless" (b: []u8, v: u32) {
	b[0] = u8(v >> 24)
	b[1] = u8(v >> 16)
	b[2] = u8(v >> 8)
	b[3] = u8(v)
}
