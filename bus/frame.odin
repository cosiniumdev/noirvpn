// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

// Framing of the named pipe transport: 4-byte length (host byte order), then
// that many bytes of JSON. Both ends are one build on one machine. An events
// frame holds `<topic> SP <envelope>` (one nng event message).
// The reader checks the length before it allocates and reads exactly that many
// bytes. Length 0 or above the limit is an error: the transport closes the
// connection with no reply. Host and client both use `Frame_Reader` (no I/O,
// so a test can feed it any bytes).

import "core:mem"

FRAME_HEADER :: 4

// The hard limit of a frame on the control pipe from a client: twice the
// largest request, as with nng (a request between the limit of its operation
// and this limit gets a proper reply).
FRAME_MAX_REQUEST :: 2 * MAX_PROFILE_REQUEST_SIZE

// The hard limit of a reply frame, and of an events frame.
FRAME_MAX_REPLY :: MAX_REPLY_SIZE
FRAME_MAX_EVENT :: MAX_TOPIC_LEN + 1 + MAX_EVENT_SIZE

Frame_Status :: enum u8 {
	// Read more into `frame_want`.
	More,
	// A frame is complete: take it with `frame_take`.
	Done,
	// A length of 0 or above the limit. Close the connection.
	Bad_Length,
	No_Memory,
}

Frame_Reader :: struct {
	max:       int,
	allocator: mem.Allocator,
	hdr:       [FRAME_HEADER]u8,
	hdr_n:     int,
	body:      []u8,
	body_n:    int,
}

frame_reader_init :: proc(fr: ^Frame_Reader, max: int, allocator := context.allocator) {
	fr^ = {
		max       = max,
		allocator = allocator,
	}
}

// Free a body that was not taken. It is overwritten first (it may hold a
// secret).
frame_reader_destroy :: proc(fr: ^Frame_Reader) {
	if fr.body != nil {
		mem.zero_explicit(raw_data(fr.body), len(fr.body))
		delete(fr.body, fr.allocator)
	}
	fr.body = nil
	fr.hdr_n, fr.body_n = 0, 0
}

// The buffer that the next read fills. It is never empty.
frame_want :: proc(fr: ^Frame_Reader) -> []u8 {
	if fr.body == nil {
		return fr.hdr[fr.hdr_n:]
	}
	return fr.body[fr.body_n:]
}

// Count `n` bytes that a read put into the buffer of `frame_want`.
frame_got :: proc(fr: ^Frame_Reader, n: int) -> Frame_Status {
	if fr.body == nil {
		fr.hdr_n += n
		if fr.hdr_n < FRAME_HEADER {
			return .More
		}
		size := int((^u32)(&fr.hdr)^)
		if size == 0 || size > fr.max {
			return .Bad_Length
		}
		body, err := make([]u8, size, fr.allocator)
		if err != nil {
			return .No_Memory
		}
		fr.body = body
		fr.body_n = 0
		return .More
	}
	fr.body_n += n
	if fr.body_n < len(fr.body) {
		return .More
	}
	return .Done
}

// Take the finished frame (the caller frees it with the reader's allocator).
// The reader is ready for the next frame.
frame_take :: proc(fr: ^Frame_Reader) -> []u8 {
	b := fr.body
	fr.body = nil
	fr.hdr_n, fr.body_n = 0, 0
	return b
}

// The header of a frame of `n` bytes.
frame_header :: proc "contextless" (n: int) -> (h: [FRAME_HEADER]u8) {
	(^u32)(&h)^ = u32(n)
	return
}
