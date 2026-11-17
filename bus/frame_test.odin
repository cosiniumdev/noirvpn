// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:encoding/json"
import "core:math/rand"
import "core:strings"
import "core:testing"

// Feed `data` to a reader in chunks of random size. Returns the frames and
// whether the reader refused a length.
@(private = "file")
feed :: proc(data: []u8, max: int, gen: rand.Generator) -> (frames: [dynamic][]u8, bad: bool) {
	fr: Frame_Reader
	frame_reader_init(&fr, max)
	defer frame_reader_destroy(&fr)
	off := 0
	for off < len(data) {
		want := frame_want(&fr)
		n := min(len(want), len(data) - off, 1 + int(rand.uint32(gen) % 64))
		copy(want, data[off:off + n])
		off += n
		switch frame_got(&fr, n) {
		case .More:
		case .Done:
			append(&frames, frame_take(&fr))
		case .Bad_Length, .No_Memory:
			return frames, true
		}
	}
	return frames, false
}

@(private = "file")
frames_destroy :: proc(frames: [dynamic][]u8) {
	for f in frames {
		delete(f)
	}
	delete(frames)
}

@(private = "file")
encode :: proc(b: ^[dynamic]u8, body: string) {
	h := frame_header(len(body))
	append(b, ..h[:])
	append(b, ..transmute([]u8)body)
}

@(test)
frame_reader_splits_frames :: proc(t: ^testing.T) {
	gen := rand.default_random_generator()
	bodies := []string{"{}", `{"v":1,"id":"a","op":"status"}`, strings.repeat("x", 5000, context.temp_allocator)}
	stream: [dynamic]u8
	defer delete(stream)
	for _ in 0 ..< 20 {
		for b in bodies {
			encode(&stream, b)
		}
	}
	frames, bad := feed(stream[:], 8192, gen)
	defer frames_destroy(frames)
	testing.expect(t, !bad)
	testing.expect_value(t, len(frames), 60)
	for f, i in frames {
		testing.expect_value(t, string(f), bodies[i % 3])
	}
}

@(test)
frame_reader_refuses_bad_lengths :: proc(t: ^testing.T) {
	fr: Frame_Reader
	frame_reader_init(&fr, 100)
	defer frame_reader_destroy(&fr)
	zero := frame_header(0)
	copy(frame_want(&fr), zero[:])
	testing.expect_value(t, frame_got(&fr, FRAME_HEADER), Frame_Status.Bad_Length)

	// Above the limit: refused before anything is allocated.
	frame_reader_init(&fr, 100)
	big := frame_header(101)
	copy(frame_want(&fr), big[:2])
	testing.expect_value(t, frame_got(&fr, 2), Frame_Status.More)
	copy(frame_want(&fr), big[2:])
	testing.expect_value(t, frame_got(&fr, 2), Frame_Status.Bad_Length)
	testing.expect(t, fr.body == nil)

	huge := [4]u8{0xff, 0xff, 0xff, 0xff}
	frame_reader_init(&fr, FRAME_MAX_REQUEST)
	copy(frame_want(&fr), huge[:])
	testing.expect_value(t, frame_got(&fr, 4), Frame_Status.Bad_Length)
	testing.expect(t, fr.body == nil)

	// Exactly the limit is accepted.
	frame_reader_init(&fr, 100)
	ok := frame_header(100)
	copy(frame_want(&fr), ok[:])
	testing.expect_value(t, frame_got(&fr, 4), Frame_Status.More)
	testing.expect_value(t, len(frame_want(&fr)), 100)
}

// Random bytes, random chunks: the reader never reads past a frame, never
// allocates above the limit, and the parser takes whatever comes out.
@(test)
frame_and_json_fuzz :: proc(t: ^testing.T) {
	gen := rand.default_random_generator()
	MAX :: 4096
	for round in 0 ..< 400 {
		data: [dynamic]u8
		defer delete(data)
		switch round % 4 {
		case 0:
			// Pure noise.
			for _ in 0 ..< 1 + rand.uint32(gen) % 3000 {
				append(&data, u8(rand.uint32(gen)))
			}
		case 1:
			// Valid frames of random JSON-like text.
			for _ in 0 ..< 1 + rand.uint32(gen) % 8 {
				body := random_jsonish(gen, 1 + int(rand.uint32(gen) % 600))
				encode(&data, body)
			}
		case 2:
			// Valid frames with a bad length somewhere.
			encode(&data, `{"v":1,"id":"x","op":"status"}`)
			bad := frame_header(int(rand.uint32(gen)))
			append(&data, ..bad[:])
			append(&data, "junk")
		case 3:
			// Mutations of a real request.
			req := `{"v":1,"id":"r-1","op":"peer.kick","args":{"session":"s-1","x":[1,2,{"a":"b"}]}}`
			body := make([]u8, len(req), context.temp_allocator)
			copy(body, req)
			for _ in 0 ..< 1 + rand.uint32(gen) % 6 {
				body[rand.uint32(gen) % u32(len(body))] = u8(rand.uint32(gen))
			}
			encode(&data, string(body))
		}
		frames, _ := feed(data[:], MAX, gen)
		for f in frames {
			testing.expect(t, len(f) > 0 && len(f) <= MAX)
			p, _, _, _ := parse_request(f, context.allocator)
			parsed_destroy(&p, context.allocator)
			if v, ok := parse_json(f, context.allocator); ok {
				json.destroy_value(v, context.allocator)
			}
		}
		frames_destroy(frames)
	}
}

@(private = "file")
random_jsonish :: proc(gen: rand.Generator, n: int) -> string {
	alphabet := `{}[]":,0123456789abc\ -.etruflsn`
	b := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< n {
		strings.write_byte(&b, alphabet[rand.uint32(gen) % u32(len(alphabet))])
	}
	return strings.to_string(b)
}

@(test)
json_limits :: proc(t: ^testing.T) {
	long := strings.concatenate({`{"a":"`, strings.repeat("x", 300, context.temp_allocator), `"}`}, context.temp_allocator)
	ok, _ := json_limits_ok(transmute([]u8)long, 16, 300)
	testing.expect(t, ok)
	ok, _ = json_limits_ok(transmute([]u8)long, 16, 299)
	testing.expect(t, !ok)

	items := strings.concatenate({"[", strings.repeat("1,", 9, context.temp_allocator), "1]"}, context.temp_allocator)
	ok, _ = json_limits_ok(transmute([]u8)items, 16, 100, 10)
	testing.expect(t, ok)
	ok, _ = json_limits_ok(transmute([]u8)items, 16, 100, 9)
	testing.expect(t, !ok)

	// The default limits hold for a request.
	many := strings.concatenate({`{"v":1,"id":"a","op":"status","args":{"l":[`, strings.repeat("0,", MAX_JSON_ITEMS, context.temp_allocator), `0]}}`}, context.temp_allocator)
	p, code, _, pok := parse_request(transmute([]u8)many, context.allocator)
	parsed_destroy(&p, context.allocator)
	testing.expect(t, !pok)
	testing.expect_value(t, code, Error_Code.Bad_Request)

	deep := strings.concatenate({strings.repeat("[", 40, context.temp_allocator), strings.repeat("]", 40, context.temp_allocator)}, context.temp_allocator)
	_, dok := parse_json(transmute([]u8)deep, context.allocator)
	testing.expect(t, !dok)
}
