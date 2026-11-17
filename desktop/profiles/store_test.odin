// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package profiles

import "core:encoding/json"
import "core:os"
import "core:strings"
import "core:testing"

@(private = "file")
expect_mode :: proc(t: ^testing.T, path: string, mode: os.Permissions, loc := #caller_location) {
	when ODIN_OS != .Windows {
		fi, err := os.stat(path, context.temp_allocator)
		testing.expect(t, err == nil, loc = loc)
		testing.expect_value(t, fi.mode & os.Permissions_All, mode, loc)
	}
}

@(test)
test_store_open :: proc(t: ^testing.T) {
	s := store_open("/x/y")
	testing.expect_value(t, s.dir, "/x/y")
	store_close(&s)
	d := store_open()
	defer store_close(&d)
	if d.dir != "" {
		want, _ := os.join_path({"noirvpn", "profiles"}, context.temp_allocator)
		testing.expect(t, strings.has_suffix(d.dir, want))
	}
}

@(test)
test_id_valid :: proc(t: ^testing.T) {
	testing.expect(t, id_valid("0123456789abcdef"))
	for id in ([]string{"", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "../../etc/passwd", "0123456789abcde/", "0123456789abcdeg"}) {
		testing.expectf(t, !id_valid(id), "%q", id)
	}
}

@(test)
test_store_round_trip :: proc(t: ^testing.T) {
	base := test_dir(t)
	defer test_dir_remove(base)
	root, _ := os.join_path({base, "noirvpn", "profiles"}, context.temp_allocator)
	s := store_open(root)
	defer store_close(&s)

	id, ok := store_create(s, "Office", "client\nremote a\n")
	defer delete(id)
	testing.expect(t, ok)
	testing.expect(t, id_valid(id))
	expect_mode(t, file_path(s, id, ""), DIR_MODE)
	expect_mode(t, file_path(s, id, PROFILE_FILE), FILE_MODE)
	expect_mode(t, file_path(s, id, META_FILE), FILE_MODE)

	meta, text, lok := store_load(s, id)
	testing.expect(t, lok)
	testing.expect_value(t, text, "client\nremote a\n")
	testing.expect_value(t, meta.id, id)
	testing.expect_value(t, meta.name, "Office")
	testing.expect(t, meta.created > 1_700_000_000)
	testing.expect_value(t, meta.last_connected, 0)
	delete(text)

	meta.last_connected = 1_800_000_000
	meta.overrides.ignore_server_dns = true
	append(&meta.overrides.domains, strings.clone("corp.example"))
	append(&meta.overrides.dns_servers, strings.clone("10.0.0.53"))
	delete(meta.browser)
	meta.browser = strings.clone("firefox --new-window")
	testing.expect(t, store_save_meta(s, meta))
	testing.expect(t, store_save_text(s, id, "client\nremote b\n"))
	meta_destroy(&meta)

	m2, t2, ok2 := store_load(s, id)
	defer {
		meta_destroy(&m2)
		delete(t2)
	}
	testing.expect(t, ok2)
	testing.expect_value(t, t2, "client\nremote b\n")
	testing.expect_value(t, m2.last_connected, 1_800_000_000)
	testing.expect(t, m2.overrides.ignore_server_dns && !m2.overrides.ignore_redirect)
	testing.expect_value(t, len(m2.overrides.domains), 1)
	testing.expect_value(t, m2.overrides.domains[0], "corp.example")
	testing.expect_value(t, m2.overrides.dns_servers[0], "10.0.0.53")
	testing.expect_value(t, m2.browser, "firefox --new-window")

	// No temp files stay behind.
	entries, _ := os.read_all_directory_by_path(file_path(s, id, ""), context.temp_allocator)
	testing.expect_value(t, len(entries), 2)

	testing.expect(t, store_delete(s, id))
	testing.expect(t, !os.exists(file_path(s, id, "")))
	testing.expect(t, !store_delete(s, id))
	_, _, gone := store_load(s, id)
	testing.expect(t, !gone)
}

@(test)
test_store_list :: proc(t: ^testing.T) {
	root := test_dir(t)
	defer test_dir_remove(root)
	s := store_open(root)
	defer store_close(&s)
	names := []string{"beta", "Alpha", "gamma", "alpha 2"}
	for n in names {
		id, ok := store_create(s, n, "client\n")
		testing.expect(t, ok)
		delete(id)
	}
	// Folders that are skipped.
	test_mkdir(t, root, "not-an-id")
	no_meta := test_mkdir(t, root, "00000000000000aa")
	test_write(t, no_meta, PROFILE_FILE, "client\n")
	bad := test_mkdir(t, root, "00000000000000bb")
	test_write(t, bad, PROFILE_FILE, "client\n")
	test_write(t, bad, META_FILE, "{\"name\": ")
	wrong := test_mkdir(t, root, "00000000000000cc")
	test_write(t, wrong, PROFILE_FILE, "client\n")
	test_write(t, wrong, META_FILE, "{\"name\": \"x\", \"created\": \"yesterday\"}")
	no_text := test_mkdir(t, root, "00000000000000dd")
	test_write(t, no_text, META_FILE, "{\"name\": \"x\"}")
	test_write(t, root, "0000000000000eee", "a file")
	// Unknown keys are ignored, another id in the file is replaced, an empty
	// name becomes the id.
	extra := test_mkdir(t, root, "00000000000000ee")
	test_write(t, extra, PROFILE_FILE, "client\n")
	test_write(t, extra, META_FILE, "{\"id\": \"../x\", \"name\": \"\", \"future\": {\"a\": [1, 2]}, \"created\": 5}")

	list := store_list(s)
	defer metas_destroy(list)
	got := make([dynamic]string, context.temp_allocator)
	for m in list {
		append(&got, m.name)
	}
	testing.expect_value(t, len(got), 5)
	want := []string{"00000000000000ee", "Alpha", "alpha 2", "beta", "gamma"}
	for w, i in want {
		if i < len(got) {
			testing.expect_value(t, got[i], w)
		}
	}
	for m in list {
		if m.name == "00000000000000ee" {
			testing.expect_value(t, m.id, "00000000000000ee")
			testing.expect_value(t, m.created, 5)
		}
	}

	empty := store_list(Store{})
	defer metas_destroy(empty)
	testing.expect_value(t, len(empty), 0)
}

@(test)
test_store_bad_ids :: proc(t: ^testing.T) {
	root := test_dir(t)
	defer test_dir_remove(root)
	s := store_open(root)
	defer store_close(&s)
	outside := test_mkdir(t, root, "outside")
	test_write(t, outside, PROFILE_FILE, "client\n")
	test_write(t, outside, META_FILE, "{\"name\": \"x\"}")
	for id in ([]string{"outside", "../outside", "", "0123456789ABCDEF"}) {
		_, _, ok := store_load(s, id)
		testing.expect(t, !ok)
		testing.expect(t, !store_delete(s, id))
		testing.expect(t, !store_save_text(s, id, "x"))
		testing.expect(t, !store_save_meta(s, Meta{id = id, name = "x"}))
		_, dok := store_duplicate(s, id, "copy")
		testing.expect(t, !dok)
		testing.expect(t, !store_export(s, id, file_path(s, "", "out.ovpn")))
	}
	testing.expect(t, os.exists(file_path(s, "outside", PROFILE_FILE)))

	// A valid id with no folder.
	testing.expect(t, !store_save_meta(s, Meta{id = "0123456789abcdef", name = "x"}))
	testing.expect(t, !os.exists(file_path(s, "0123456789abcdef", "")))

	when ODIN_OS != .Windows {
		// A folder that is a link is refused.
		link := file_path(s, "00000000000000ff", "")
		testing.expect(t, os.symlink(outside, link) == nil)
		_, _, ok := store_load(s, "00000000000000ff")
		testing.expect(t, !ok)
		testing.expect(t, !store_delete(s, "00000000000000ff"))
		list := store_list(s)
		defer metas_destroy(list)
		testing.expect_value(t, len(list), 0)
	}

	none := Store{}
	_, cok := store_create(none, "x", "client\n")
	testing.expect(t, !cok)
}

@(test)
test_store_delete_keeps_other_files :: proc(t: ^testing.T) {
	root := test_dir(t)
	defer test_dir_remove(root)
	s := store_open(root)
	defer store_close(&s)
	id, _ := store_create(s, "x", "client\n")
	defer delete(id)
	test_write(t, file_path(s, id, ""), "notes.txt", "mine")
	testing.expect(t, !store_delete(s, id))
	testing.expect(t, os.exists(file_path(s, id, "notes.txt")))
	testing.expect(t, !os.exists(file_path(s, id, PROFILE_FILE)))
}

@(test)
test_store_duplicate_export :: proc(t: ^testing.T) {
	root := test_dir(t)
	defer test_dir_remove(root)
	s := store_open(root)
	defer store_close(&s)
	id, _ := store_create(s, "Home", "client\nremote h\n")
	defer delete(id)
	meta, text, _ := store_load(s, id)
	delete(text)
	meta.overrides.ignore_redirect = true
	append(&meta.overrides.dns_servers, strings.clone("1.1.1.1"))
	meta.browser = strings.clone("chromium")
	meta.last_connected = 99
	testing.expect(t, store_save_meta(s, meta))
	meta_destroy(&meta)

	cid, ok := store_duplicate(s, id, "Home copy")
	defer delete(cid)
	testing.expect(t, ok)
	testing.expect(t, cid != id)
	cm, ct, cok := store_load(s, cid)
	defer {
		meta_destroy(&cm)
		delete(ct)
	}
	testing.expect(t, cok)
	testing.expect_value(t, cm.name, "Home copy")
	testing.expect_value(t, ct, "client\nremote h\n")
	testing.expect(t, cm.overrides.ignore_redirect)
	testing.expect_value(t, cm.overrides.dns_servers[0], "1.1.1.1")
	testing.expect_value(t, cm.browser, "chromium")
	testing.expect_value(t, cm.last_connected, 0)

	out := file_path(s, "", "export.ovpn")
	testing.expect(t, store_export(s, id, out))
	data, err := os.read_entire_file(out, context.temp_allocator)
	testing.expect(t, err == nil)
	testing.expect_value(t, string(data), "client\nremote h\n")
	expect_mode(t, out, FILE_MODE)
	// An export replaces an existing file.
	testing.expect(t, store_export(s, cid, out))
	testing.expect(t, !store_export(s, id, file_path(s, "", "no/such/dir/x.ovpn")))
}

@(test)
test_write_file_atomic :: proc(t: ^testing.T) {
	dir := test_dir(t)
	defer test_dir_remove(dir)
	p := test_write(t, dir, "f.txt", "old")
	testing.expect(t, write_file_atomic(p, transmute([]u8)string("new")))
	data, _ := os.read_entire_file(p, context.temp_allocator)
	testing.expect_value(t, string(data), "new")
	entries, _ := os.read_all_directory_by_path(dir, context.temp_allocator)
	testing.expect_value(t, len(entries), 1)
	testing.expect(t, !write_file_atomic(dir, transmute([]u8)string("x")))
}

@(test)
test_meta_clone :: proc(t: ^testing.T) {
	m := Meta {
		id      = "0123456789abcdef",
		name    = "n",
		created = 7,
		browser = "b",
	}
	append(&m.overrides.domains, "d.example")
	c := meta_clone(m)
	delete(m.overrides.domains)
	testing.expect_value(t, c.id, m.id)
	testing.expect_value(t, c.name, "n")
	testing.expect_value(t, c.created, 7)
	testing.expect_value(t, c.overrides.domains[0], "d.example")
	meta_destroy(&c)
	testing.expect_value(t, c.name, "")
}

@(test)
test_store_note_use :: proc(t: ^testing.T) {
	root := test_dir(t)
	defer test_dir_remove(root)
	s := store_open(root)
	defer store_close(&s)

	// A meta.json of an older version: no server_ip.
	old := test_mkdir(t, root, "00000000000000ab")
	test_write(t, old, PROFILE_FILE, "client\n")
	test_write(t, old, META_FILE, "{\"name\": \"Old\", \"created\": 5, \"last_connected\": 7}")
	m, mt, ok := store_load(s, "00000000000000ab")
	testing.expect(t, ok)
	testing.expect_value(t, m.server_ip, "")
	testing.expect_value(t, m.last_connected, 7)
	meta_destroy(&m)
	delete(mt)

	testing.expect(t, store_note_use(s, "00000000000000ab", 1_800_000_000, "203.0.113.7"))
	testing.expect(t, store_note_use(s, "00000000000000ab", 1_800_000_100, ""))
	m2, t2, ok2 := store_load(s, "00000000000000ab")
	defer {
		meta_destroy(&m2)
		delete(t2)
	}
	testing.expect(t, ok2)
	testing.expect_value(t, m2.name, "Old")
	testing.expect_value(t, m2.created, 5)
	testing.expect_value(t, m2.last_connected, 1_800_000_100)
	testing.expect_value(t, m2.server_ip, "203.0.113.7")
	testing.expect(t, !store_note_use(s, "00000000000000ff", 1, "x"))

	// A copy is a new profile: no use yet.
	id, dok := store_duplicate(s, "00000000000000ab", "Copy")
	defer delete(id)
	testing.expect(t, dok)
	m3, t3, ok3 := store_load(s, id)
	defer {
		meta_destroy(&m3)
		delete(t3)
	}
	testing.expect(t, ok3)
	testing.expect_value(t, m3.last_connected, 0)
	testing.expect_value(t, m3.server_ip, "")
}

@(test)
test_store_block_ipv6 :: proc(t: ^testing.T) {
	base := test_dir(t)
	defer test_dir_remove(base)
	s := store_open(base)
	defer store_close(&s)
	id, ok := store_create(s, "Office", "client\n", context.temp_allocator)
	testing.expect(t, ok)
	path := file_path(s, id, META_FILE)

	raw, _ := os.read_entire_file(path, context.temp_allocator)
	testing.expect(t, strings.contains(string(raw), "\"block_ipv6\": false"))
	meta, _, _ := store_load(s, id, context.temp_allocator)
	testing.expect(t, !meta.overrides.block_ipv6)

	meta.overrides.block_ipv6 = true
	testing.expect(t, store_save_meta(s, meta))
	raw, _ = os.read_entire_file(path, context.temp_allocator)
	testing.expect(t, strings.contains(string(raw), "\"block_ipv6\": true"))
	back, _, found := store_load(s, id, context.temp_allocator)
	testing.expect(t, found && back.overrides.block_ipv6)

	// A program that does not know the field still reads the file.
	Old_Overrides :: struct {
		ignore_server_dns: bool `json:"ignore_server_dns"`,
		ignore_redirect:   bool `json:"ignore_redirect"`,
	}
	Old_Meta :: struct {
		name:      string `json:"name"`,
		overrides: Old_Overrides `json:"overrides"`,
	}
	old: Old_Meta
	testing.expect(t, json.unmarshal(raw, &old, allocator = context.temp_allocator) == nil)
	testing.expect_value(t, old.name, "Office")

	// An old meta.json has no field: off.
	testing.expect(t, os.write_entire_file(path, `{"id":"x","name":"Old","created":1,"overrides":{"ignore_redirect":true}}`) == nil)
	om, _, ofound := store_load(s, id, context.temp_allocator)
	testing.expect(t, ofound && om.name == "Old" && om.overrides.ignore_redirect && !om.overrides.block_ipv6)
}

// The Use DCO switch: no_dco is kept in the meta.
@(test)
test_store_no_dco :: proc(t: ^testing.T) {
	base := test_dir(t)
	defer test_dir_remove(base)
	s := store_open(base)
	defer store_close(&s)
	id, ok := store_create(s, "Office", "client\n", context.temp_allocator)
	testing.expect(t, ok)
	path := file_path(s, id, META_FILE)
	meta, _, _ := store_load(s, id, context.temp_allocator)
	testing.expect(t, !meta.overrides.no_dco)
	meta.overrides.no_dco = true
	testing.expect(t, store_save_meta(s, meta))
	raw, _ := os.read_entire_file(path, context.temp_allocator)
	testing.expect(t, strings.contains(string(raw), "\"no_dco\": true"))
	back, _, found := store_load(s, id, context.temp_allocator)
	testing.expect(t, found && back.overrides.no_dco)
	c := overrides_clone(back.overrides, context.temp_allocator)
	testing.expect(t, c.no_dco)
	testing.expect_value(t, override_lines(Overrides{no_dco = true}, context.temp_allocator), "disable-dco\n")
	testing.expect_value(t, compose("client\n", Overrides{no_dco = true}, context.temp_allocator), "client\ndisable-dco\n")
}
