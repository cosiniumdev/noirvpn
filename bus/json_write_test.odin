// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package bus

import "core:encoding/json"
import "core:testing"

@(private = "file")
quoted :: proc(w: ^Writer, s: string) -> string {
	writer_reset(w)
	write_string(w, s)
	return writer_string(w)
}

@(test)
string_escaping :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)

	testing.expect_value(t, quoted(&w, "plain"), `"plain"`)
	testing.expect_value(t, quoted(&w, ""), `""`)
	testing.expect_value(t, quoted(&w, `a"b`), `"a\"b"`)
	testing.expect_value(t, quoted(&w, `a\b`), `"a\\b"`)
	testing.expect_value(t, quoted(&w, "a\nb\rc\td"), `"a\nb\rc\td"`)
	testing.expect_value(t, quoted(&w, "\b\f"), `"\b\f"`)
	testing.expect_value(t, quoted(&w, "\x00\x01\x1f"), `"\u0000\u0001\u001f"`)
	// Slash and DEL stay as they are.
	testing.expect_value(t, quoted(&w, "a/b\x7f"), "\"a/b\x7f\"")
	// UTF-8 passes through unchanged.
	testing.expect_value(t, quoted(&w, "café ✓ 日本 😀"), `"café ✓ 日本 😀"`)
	// Bytes that are not UTF-8 become U+FFFD: lone continuation, truncated
	// sequence, overlong form, surrogate, and a bad byte between good text.
	testing.expect_value(t, quoted(&w, "a\x80b"), "\"a\xef\xbf\xbdb\"")
	testing.expect_value(t, quoted(&w, "a\xe2\x82"), "\"a\xef\xbf\xbd\xef\xbf\xbd\"")
	testing.expect_value(t, quoted(&w, "\xc0\xaf"), "\"\xef\xbf\xbd\xef\xbf\xbd\"")
	testing.expect_value(t, quoted(&w, "\xed\xa0\x80"), "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"")
}

// Whatever bytes go in, valid JSON comes out.
@(test)
string_escaping_is_always_valid_json :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	bad: [256]u8
	for i in 0 ..< 256 {
		bad[i] = u8(i)
	}
	for start in 0 ..< 256 {
		s := string(bad[start:])
		writer_reset(&w)
		write_string(&w, s)
		if !json.is_valid(writer_bytes(&w), .JSON) {
			testing.expectf(t, false, "invalid JSON for input from byte %d", start)
			return
		}
	}
	// And it round-trips for text without bad bytes.
	input := "ctl:\x01\x02 quote:\" back:\\ nl:\n uni:é✓"
	writer_reset(&w)
	write_string(&w, input)
	v, err := json.parse(writer_bytes(&w), .JSON)
	defer json.destroy_value(v)
	testing.expect_value(t, err, json.Error.None)
	s, _ := v.(json.String)
	testing.expect_value(t, s, input)
}

@(test)
object_and_array_building :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)

	begin_obj(&w)
	kv_str(&w, "name", "alice")
	kv_int(&w, "n", -5)
	kv_u64(&w, "big", max(u64))
	kv_bool(&w, "up", true)
	kv_null(&w, "gone")
	kv_str_or_null(&w, "pin", "sha256:ab", true)
	kv_str_or_null(&w, "pin2", "", false)
	kv_arr(&w, "addrs")
	val_str(&w, "10.8.0.2")
	val_str(&w, "fd00::2")
	end(&w)
	kv_obj(&w, "counters")
	kv_u64(&w, "rx", 1)
	kv_u64(&w, "tx", 2)
	end(&w)
	kv_raw(&w, "raw", transmute([]byte)string(`[1,2]`))
	kv_arr(&w, "mixed")
	val_int(&w, 1)
	begin_obj(&w)
	end(&w)
	begin_arr(&w)
	end(&w)
	val_null(&w)
	end(&w)
	end(&w)

	testing.expect(t, writer_complete(&w))
	want := `{"name":"alice","n":-5,"big":18446744073709551615,"up":true,"gone":null,"pin":"sha256:ab","pin2":null,` +
		`"addrs":["10.8.0.2","fd00::2"],"counters":{"rx":1,"tx":2},"raw":[1,2],"mixed":[1,{},[],null]}`
	testing.expect_value(t, writer_string(&w), want)
	testing.expect(t, json.is_valid(writer_bytes(&w), .JSON))
}

@(test)
numbers :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	begin_arr(&w)
	val_int(&w, min(i64))
	val_int(&w, 0)
	val_u64(&w, 0)
	val_f64(&w, 1.5)
	val_f64(&w, -0.25)
	val_f64(&w, 0)
	val_f64(&w, 1e300)
	inf := transmute(f64)u64(0x7ff0_0000_0000_0000)
	nan := transmute(f64)u64(0x7ff8_0000_0000_0000)
	val_f64(&w, nan)
	val_f64(&w, inf)
	val_f64(&w, -inf)
	end(&w)
	testing.expect(t, json.is_valid(writer_bytes(&w), .JSON))
	testing.expect_value(t, writer_string(&w), `[-9223372036854775808,0,0,1.5,-0.25,0,1e+300,null,null,null]`)
}

@(test)
writer_failure_flags :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	end(&w) // nothing open
	testing.expect(t, w.failed)

	writer_reset(&w)
	testing.expect(t, !w.failed)
	for _ in 0 ..< WRITER_MAX_DEPTH + 1 {
		begin_arr(&w)
	}
	testing.expect(t, w.failed)

	writer_reset(&w)
	begin_obj(&w)
	testing.expect(t, !writer_complete(&w))
	key(&w, "k")
	testing.expect(t, !writer_complete(&w))
}

@(test)
writer_reuse_keeps_memory :: proc(t: ^testing.T) {
	w: Writer
	writer_init(&w)
	defer writer_destroy(&w)
	for i in 0 ..< 3 {
		writer_reset(&w)
		begin_obj(&w)
		kv_int(&w, "i", i64(i))
		end(&w)
	}
	testing.expect_value(t, writer_string(&w), `{"i":2}`)
}
