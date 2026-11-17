// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:os"
import "core:strings"
import "core:testing"

@(test)
test_peers_line_name :: proc(t: ^testing.T) {
	cases := [][2]string {
		{"alice", "alice"},
		{"Alice Laptop", "Alice_Laptop"},
		{"a \t\n b", "a_b"},
		{"a/b\\c", "a_b_c"},
		{"#home", "_home"},
		{"a#b", "a#b"},
		{"", "client"},
		{".", "client"},
		{"..", "client"},
		{" ", "_"},
		{"x\x01\x02y", "x_y"},
		{"Zoë", "Zoë"},
	}
	for c in cases {
		testing.expectf(t, peers_line_name(c[0], context.temp_allocator) == c[1], "%q -> %q", c[0], peers_line_name(c[0], context.temp_allocator))
	}
	// Cut to 255 bytes on a character boundary.
	long := strings.repeat("é", 200, context.temp_allocator)
	n := peers_line_name(long, context.temp_allocator)
	testing.expect_value(t, len(n), 254)
	testing.expect_value(t, peers_line("Alice Laptop", "sha256:AAA=", context.temp_allocator), "Alice_Laptop sha256:AAA=")
	testing.expect_value(t, peers_line("alice", "", context.temp_allocator), "")
}

@(test)
test_common_name_valid :: proc(t: ^testing.T) {
	testing.expect(t, common_name_valid("alice"))
	testing.expect(t, common_name_valid("  alice  "))
	testing.expect(t, common_name_valid(strings.repeat("a", 64, context.temp_allocator)))
	testing.expect(t, !common_name_valid(strings.repeat("a", 65, context.temp_allocator)))
	testing.expect(t, !common_name_valid(""))
	testing.expect(t, !common_name_valid("   "))
	testing.expect(t, !common_name_valid("a\tb"))
}

@(test)
test_request_file_name :: proc(t: ^testing.T) {
	testing.expect_value(t, request_file_name("alice", context.temp_allocator), "alice.csr")
	testing.expect_value(t, request_file_name("Alice Laptop/2", context.temp_allocator), "Alice_Laptop_2.csr")
	testing.expect_value(t, request_file_name("..x", context.temp_allocator), "x.csr")
	testing.expect_value(t, request_file_name("éé", context.temp_allocator), "request.csr")
	testing.expect_value(t, request_file_name("", context.temp_allocator), "request.csr")
}

@(test)
test_store_request :: proc(t: ^testing.T) {
	base := test_dir(t)
	defer test_dir_remove(base)
	s := store_open(base)
	defer store_close(&s)
	id, ok := store_create(s, "Office", "client\n")
	defer delete(id)
	testing.expect(t, ok)

	_, has := store_request_load(s, id, context.temp_allocator)
	testing.expect(t, !has)
	req := Request{csr = "-----BEGIN CERTIFICATE REQUEST-----\nAA\n-----END CERTIFICATE REQUEST-----\n", pin = "sha256:AAA=", common_name = "alice", key_type = "p256", created = 1_800_000_000}
	testing.expect(t, store_request_save(s, id, "KEY TEXT\n", req))
	when ODIN_OS != .Windows {
		fi, err := os.stat(file_path(s, id, REQUEST_KEY_FILE), context.temp_allocator)
		testing.expect(t, err == nil)
		testing.expect_value(t, fi.mode & os.Permissions_All, FILE_MODE)
	}
	got, gok := store_request_load(s, id, context.temp_allocator)
	testing.expect(t, gok)
	testing.expect_value(t, got.csr, req.csr)
	testing.expect_value(t, got.pin, req.pin)
	testing.expect_value(t, got.common_name, "alice")
	testing.expect_value(t, got.key_type, "p256")
	testing.expect_value(t, got.created, req.created)
	key, kok := store_request_key(s, id, context.temp_allocator)
	testing.expect(t, kok)
	testing.expect_value(t, key, "KEY TEXT\n")

	// The list still has the profile; a copy has no request.
	testing.expect_value(t, len(store_list(s, context.temp_allocator)), 1)
	copy_id, cok := store_duplicate(s, id, "Copy", context.temp_allocator)
	testing.expect(t, cok)
	_, has = store_request_load(s, copy_id, context.temp_allocator)
	testing.expect(t, !has)

	testing.expect(t, store_request_clear(s, id))
	_, has = store_request_load(s, id, context.temp_allocator)
	testing.expect(t, !has)
	testing.expect(t, !os.exists(file_path(s, id, REQUEST_KEY_FILE)))

	// Delete removes a request and its key with the profile.
	testing.expect(t, store_request_save(s, id, "KEY TEXT\n", req))
	testing.expect(t, store_delete(s, id))
	testing.expect(t, !os.exists(file_path(s, id, "")))
}
