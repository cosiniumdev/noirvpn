// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package wire

import "core:mem"

// TCP framing: a 16-bit big-endian length, then that
// many bytes of packet. The length does not count itself. Zero is invalid.

FRAME_PREFIX_LEN :: 2
MAX_FRAME_LEN :: 65535

// Default receive bound: the larger of 2048 and the biggest data packet is
// the caller's choice; this is the floor.
DEFAULT_MAX_FRAME :: 2048

// Writes the length prefix and the packet into `buf`. Returns the bytes
// written. `pkt` may be empty only by mistake: that is `.Zero_Length`.
frame_encode :: proc "contextless" (buf: []u8, pkt: []u8) -> (n: int, err: Error) {
	if len(pkt) == 0 {
		return 0, .Zero_Length
	}
	if len(pkt) > MAX_FRAME_LEN {
		return 0, .Oversize
	}
	if len(buf) < FRAME_PREFIX_LEN + len(pkt) {
		return 0, .Buffer_Too_Small
	}
	put_u16(buf, u16(len(pkt)))
	copy(buf[FRAME_PREFIX_LEN:], pkt)
	return FRAME_PREFIX_LEN + len(pkt), .None
}

// Reads one frame from the start of `data`. `pkt` points into `data`.
// `consumed` includes the prefix.
//
//   .None                     a whole packet
//   .Need_More                valid so far, more bytes needed
//   .Zero_Length, .Oversize   stream broken; close the connection
frame_decode :: proc "contextless" (data: []u8, max_packet: int) -> (pkt: []u8, consumed: int, err: Error) {
	if len(data) < FRAME_PREFIX_LEN {
		return nil, 0, .Need_More
	}
	l := int(get_u16(data))
	if l == 0 {
		return nil, 0, .Zero_Length
	}
	if l > max_packet {
		return nil, 0, .Oversize
	}
	if len(data) < FRAME_PREFIX_LEN + l {
		return nil, 0, .Need_More
	}
	return data[FRAME_PREFIX_LEN:][:l], FRAME_PREFIX_LEN + l, .None
}

// Incremental splitter for a TCP byte stream. Buffers into memory the caller
// provides, so it never allocates.
//
//	for rest := chunk; len(rest) > 0; {
//		n := splitter_feed(&s, rest)
//		rest = rest[n:]
//		for {
//			pkt, err := splitter_next(&s)
//			if err == .Need_More { break }
//			if err != .None { /* close the connection */ }
//			/* use pkt */
//		}
//	}
//
// A packet from `splitter_next` stays valid until the next `splitter_feed`.
// After a fatal error the splitter stays failed (no resync possible).
Stream_Splitter :: struct {
	buf:        []u8,
	max_packet: int,
	start:      int,
	end:        int,
	failed:     Error,
}

// `buf` must hold at least a prefix plus `max_packet` bytes. `max_packet` is
// 1 to 65535.
splitter_init :: proc "contextless" (s: ^Stream_Splitter, buf: []u8, max_packet: int) -> Error {
	s^ = {}
	if max_packet < 1 || max_packet > MAX_FRAME_LEN {
		return .Oversize
	}
	if len(buf) < FRAME_PREFIX_LEN + max_packet {
		return .Buffer_Too_Small
	}
	s.buf = buf
	s.max_packet = max_packet
	return .None
}

// Forget buffered bytes and any failure (a new connection).
splitter_reset :: proc "contextless" (s: ^Stream_Splitter) {
	s.start, s.end, s.failed = 0, 0, .None
}

// Bytes buffered but not yet returned as packets.
splitter_pending :: proc "contextless" (s: ^Stream_Splitter) -> int {
	return s.end - s.start
}

// Copies as many bytes of `data` as fit into the buffer. Returns how many
// bytes it took. Returns 0 after a fatal error, or if the buffer is full of
// whole packets that the caller has not collected yet.
splitter_feed :: proc "contextless" (s: ^Stream_Splitter, data: []u8) -> int {
	if s.failed != .None || len(data) == 0 {
		return 0
	}
	if s.start == s.end {
		s.start, s.end = 0, 0
	}
	if len(s.buf) - s.end < len(data) && s.start > 0 {
		// Move the unread bytes to the front to free room.
		mem.copy(raw_data(s.buf), raw_data(s.buf[s.start:]), s.end - s.start)
		s.end -= s.start
		s.start = 0
	}
	n := min(len(data), len(s.buf) - s.end)
	copy(s.buf[s.end:], data[:n])
	s.end += n
	return n
}

// Returns the next whole packet, `.Need_More` when none is complete yet, or a
// fatal stream error (`.Zero_Length`, `.Oversize`).
splitter_next :: proc "contextless" (s: ^Stream_Splitter) -> (pkt: []u8, err: Error) {
	if s.failed != .None {
		return nil, s.failed
	}
	p, used, ferr := frame_decode(s.buf[s.start:s.end], s.max_packet)
	if ferr == .Need_More {
		return nil, .Need_More
	}
	if ferr != .None {
		s.failed = ferr
		return nil, ferr
	}
	s.start += used
	return p, .None
}
