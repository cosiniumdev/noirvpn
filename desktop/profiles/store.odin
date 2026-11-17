// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

// The profile store: `<dir>/<id>/profile.ovpn` (mode 0600) and
// `<dir>/<id>/meta.json`, folders mode 0700. Only the GUI reads it. A new key
// and certificate request adds `request.key` (mode 0600) and `request.json`.
//
//	store_open(dir, allocator) -> Store
//	store_close(s, allocator)
//	store_list(s, allocator) -> []Meta
//	store_load(s, id, allocator) -> (meta: Meta, text: string, ok: bool)
//	store_profile_path(s, id, allocator) -> string
//	store_create(s, name, text, allocator) -> (id: string, ok: bool)
//	store_create_form(s, name, text, form, allocator) -> (id: string, ok: bool)
//	store_save_meta(s, meta) -> bool
//	store_save_text(s, id, text) -> bool
//	store_delete(s, id) -> bool
//	store_duplicate(s, id, new_name, allocator) -> (id: string, ok: bool)
//	store_export(s, id, path) -> bool
//	store_note_use(s, id, at, server_ip) -> bool
//	store_request_save(s, id, key, req) -> bool
//	store_request_load(s, id, allocator) -> (req: Request, ok: bool)
//	store_request_key(s, id, allocator) -> (key: string, ok: bool)
//	store_request_clear(s, id) -> bool
//	id_valid(id) -> bool
//	meta_clone(m, allocator) -> Meta
//	meta_destroy(m, allocator)
//	metas_destroy(ms, allocator)
package profiles

import "core:crypto"
import "core:encoding/hex"
import "core:encoding/json"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"
import "core:time"
import "core:unicode"
import "core:unicode/utf8"

PROFILE_FILE :: "profile.ovpn"
META_FILE :: "meta.json"
META_MAX :: 64 * 1024
REQUEST_FILE :: "request.json"
REQUEST_KEY_FILE :: "request.key"
ID_LEN :: 16

Store :: struct {
	// "" when the config folder of the user is not known; every call fails.
	dir: string,
}

// The content of meta.json. Unknown keys are ignored when it is read.
Meta :: struct {
	id:             string `json:"id"`,
	name:           string `json:"name"`,
	// Unix seconds.
	created:        i64 `json:"created"`,
	// Unix seconds; 0 = never.
	last_connected: i64 `json:"last_connected"`,
	// The address of the server at the last connection, as the service
	// reports it after the name lookup; "" = not known.
	server_ip:      string `json:"server_ip"`,
	overrides:      Overrides `json:"overrides"`,
	// The server signs the user in with a web page.
	web_sign_in:    bool `json:"web_sign_in"`,
	// A browser command for web sign-in; "" = the system default.
	browser:        string `json:"browser"`,
	// The form of a profile that the GUI created; nil for an imported one.
	form:           Maybe(Form) `json:"form,omitempty"`,
}

// `dir` "" gives `<user config dir>/noirvpn/profiles`.
store_open :: proc(dir := "", allocator := context.allocator) -> Store {
	if dir != "" {
		return Store{strings.clone(dir, allocator)}
	}
	cfg, err := os.user_config_dir(allocator, true)
	if err != nil {
		return {}
	}
	defer delete(cfg, allocator)
	p, jerr := os.join_path({cfg, "noirvpn", "profiles"}, allocator)
	if jerr != nil {
		return {}
	}
	return Store{p}
}

store_close :: proc(s: ^Store, allocator := context.allocator) {
	delete(s.dir, allocator)
	s^ = {}
}

// 16 lower-case hex characters.
id_valid :: proc(id: string) -> bool {
	if len(id) != ID_LEN {
		return false
	}
	for c in transmute([]u8)id {
		switch c {
		case '0' ..= '9', 'a' ..= 'f':
		case:
			return false
		}
	}
	return true
}

// Sorted by name without case. A folder with a missing or bad meta.json or
// no profile.ovpn is left out.
store_list :: proc(s: Store, allocator := context.allocator) -> []Meta {
	out := make([dynamic]Meta, allocator)
	if s.dir == "" {
		return out[:]
	}
	entries, err := os.read_all_directory_by_path(s.dir, allocator)
	if err != nil {
		return out[:]
	}
	defer os.file_info_slice_delete(entries, allocator)
	for fi in entries {
		if fi.type != .Directory || !id_valid(fi.name) || !os.is_file(file_path(s, fi.name, PROFILE_FILE)) {
			continue
		}
		if m, ok := meta_read(s, fi.name, allocator); ok {
			append(&out, m)
		}
	}
	slice.sort_by(out[:], meta_less)
	return out[:]
}

store_load :: proc(
	s: Store,
	id: string,
	allocator := context.allocator,
) -> (
	meta: Meta,
	text: string,
	ok: bool,
) {
	if !profile_exists(s, id) {
		return
	}
	meta = meta_read(s, id, allocator) or_return
	data, real, err := read_capped(file_path(s, id, PROFILE_FILE), FILE_MAX, allocator)
	delete(real, allocator)
	if err != .None {
		meta_destroy(&meta, allocator)
		return {}, "", false
	}
	return meta, string(data), true
}

store_create :: proc(
	s: Store,
	name, text: string,
	allocator := context.allocator,
) -> (
	id: string,
	ok: bool,
) {
	return create(s, Meta{name = name}, text, allocator)
}

// A profile that the GUI created: the text and the form it came from.
store_create_form :: proc(
	s: Store,
	name, text: string,
	form: Form,
	allocator := context.allocator,
) -> (
	id: string,
	ok: bool,
) {
	return create(s, Meta{name = name, form = form}, text, allocator)
}

// Writes meta.json of an existing profile (meta.id names it).
store_save_meta :: proc(s: Store, meta: Meta) -> bool {
	if !profile_exists(s, meta.id) {
		return false
	}
	return meta_write(s, meta)
}

store_save_text :: proc(s: Store, id, text: string) -> bool {
	if !profile_exists(s, id) {
		return false
	}
	return write_file_atomic(file_path(s, id, PROFILE_FILE), transmute([]u8)text)
}

// Removes profile.ovpn, meta.json, a request and its key, and the folder. A
// folder with other files stays and the result is false.
store_delete :: proc(s: Store, id: string) -> bool {
	if !profile_exists(s, id) {
		return false
	}
	for f in ([]string{REQUEST_KEY_FILE, REQUEST_FILE, PROFILE_FILE, META_FILE}) {
		if err := os.remove(file_path(s, id, f)); err != nil && err != .Not_Exist {
			return false
		}
	}
	return os.remove(file_path(s, id, "")) == nil
}

// A new profile with the text, overrides and browser of `id`.
store_duplicate :: proc(
	s: Store,
	id, new_name: string,
	allocator := context.allocator,
) -> (
	new_id: string,
	ok: bool,
) {
	meta, text := store_load(s, id, allocator) or_return
	defer {
		meta_destroy(&meta, allocator)
		delete(text, allocator)
	}
	return create(s, Meta{name = new_name, overrides = meta.overrides, web_sign_in = meta.web_sign_in, browser = meta.browser, form = meta.form}, text, allocator)
}

// Records a connection: the time (Unix seconds) and the server address.
// An empty `server_ip` keeps the address of the last connection.
store_note_use :: proc(s: Store, id: string, at: i64, server_ip: string) -> bool {
	meta, _ := store_load(s, id, context.temp_allocator) or_return
	meta.last_connected = at
	if server_ip != "" {
		meta.server_ip = server_ip
	}
	return meta_write(s, meta)
}

// Writes the profile text to `path` (mode 0600).
store_export :: proc(s: Store, id, path: string) -> bool {
	if !profile_exists(s, id) {
		return false
	}
	data, real, err := read_capped(file_path(s, id, PROFILE_FILE), FILE_MAX, context.allocator)
	delete(real)
	if err != .None {
		return false
	}
	defer delete(data)
	return write_file_atomic(path, data)
}

// Keeps a new key and its request, replacing an old request. The key file is
// written first, so request.json never names a missing key.
store_request_save :: proc(s: Store, id, key: string, req: Request) -> bool {
	if !profile_exists(s, id) {
		return false
	}
	data, err := json.marshal(req, {spec = .JSON, pretty = true, use_spaces = true, spaces = 2})
	if err != nil {
		return false
	}
	defer delete(data)
	text := strings.concatenate({string(data), "\n"}, context.temp_allocator)
	if !write_file_atomic(file_path(s, id, REQUEST_KEY_FILE), transmute([]u8)key) {
		return false
	}
	if !write_file_atomic(file_path(s, id, REQUEST_FILE), transmute([]u8)text) {
		_ = os.remove(file_path(s, id, REQUEST_KEY_FILE))
		return false
	}
	return true
}

// The request of a profile; ok is false when there is none (or no key for it).
store_request_load :: proc(s: Store, id: string, allocator := context.allocator) -> (req: Request, ok: bool) {
	if !profile_exists(s, id) || !os.is_file(file_path(s, id, REQUEST_KEY_FILE)) {
		return
	}
	data, real, err := read_capped(file_path(s, id, REQUEST_FILE), META_MAX, allocator)
	delete(real, allocator)
	if err != .None {
		return
	}
	defer delete(data, allocator)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena, allocator, allocator)
	defer mem.dynamic_arena_destroy(&arena)
	tmp: Request
	if json.unmarshal(data, &tmp, allocator = mem.dynamic_arena_allocator(&arena)) != nil || tmp.csr == "" || tmp.pin == "" {
		return
	}
	return Request {
			csr = strings.clone(tmp.csr, allocator),
			pin = strings.clone(tmp.pin, allocator),
			common_name = strings.clone(tmp.common_name, allocator),
			key_type = strings.clone(tmp.key_type, allocator),
			created = tmp.created,
		},
		true
}

// The private key of the request (PEM). It is a secret: wipe it (wipe_string).
store_request_key :: proc(s: Store, id: string, allocator := context.allocator) -> (key: string, ok: bool) {
	if !profile_exists(s, id) {
		return
	}
	data, real, err := read_capped(file_path(s, id, REQUEST_KEY_FILE), META_MAX, allocator)
	delete(real, allocator)
	if err != .None || len(data) == 0 {
		wipe_string(string(data), allocator)
		return
	}
	return string(data), true
}

// Deletes the request and its key. True when none is left.
store_request_clear :: proc(s: Store, id: string) -> bool {
	if !profile_exists(s, id) {
		return false
	}
	ok := true
	for f in ([]string{REQUEST_KEY_FILE, REQUEST_FILE}) {
		if err := os.remove(file_path(s, id, f)); err != nil && err != .Not_Exist {
			ok = false
		}
	}
	return ok
}

meta_clone :: proc(m: Meta, allocator := context.allocator) -> Meta {
	c := Meta {
		id = strings.clone(m.id, allocator),
		name = strings.clone(m.name, allocator),
		created = m.created,
		last_connected = m.last_connected,
		server_ip = strings.clone(m.server_ip, allocator),
		overrides = overrides_clone(m.overrides, allocator),
		web_sign_in = m.web_sign_in,
		browser = strings.clone(m.browser, allocator),
	}
	if f, ok := m.form.?; ok {
		c.form = form_clone(f, allocator)
	}
	return c
}

meta_destroy :: proc(m: ^Meta, allocator := context.allocator) {
	delete(m.id, allocator)
	delete(m.name, allocator)
	delete(m.browser, allocator)
	delete(m.server_ip, allocator)
	overrides_destroy(&m.overrides, allocator)
	if f, ok := &m.form.?; ok {
		form_destroy(f, allocator)
	}
	m^ = {}
}

metas_destroy :: proc(ms: []Meta, allocator := context.allocator) {
	for &m in ms {
		meta_destroy(&m, allocator)
	}
	delete(ms, allocator)
}

// The new id is random; `tmpl` gives the name, overrides and browser.
@(private)
create :: proc(s: Store, tmpl: Meta, text: string, allocator: mem.Allocator) -> (id: string, ok: bool) {
	if s.dir == "" {
		return
	}
	_ = os.make_directory_all(s.dir, DIR_MODE)
	buf: [ID_LEN]u8
	made := false
	for _ in 0 ..< 8 {
		rnd: [ID_LEN / 2]u8
		crypto.rand_bytes(rnd[:])
		hex_id := hex.encode(rnd[:], context.temp_allocator)
		copy(buf[:], hex_id)
		err := os.make_directory(file_path(s, string(buf[:]), ""), DIR_MODE)
		if err == nil {
			made = true
			break
		}
		if err != .Exist {
			return
		}
	}
	if !made {
		return
	}
	m := tmpl
	m.id = string(buf[:])
	m.created = time.time_to_unix(time.now())
	m.last_connected = 0
	if !write_file_atomic(file_path(s, m.id, PROFILE_FILE), transmute([]u8)text) || !meta_write(s, m) {
		_ = store_delete(s, m.id)
		return
	}
	return strings.clone(m.id, allocator), true
}

// store_profile_path is the path of the profile text of `id`, the file that
// the user may open and change (the app reads it again with Reload), or "".
store_profile_path :: proc(s: Store, id: string, allocator := context.allocator) -> string {
	if !profile_exists(s, id) {
		return ""
	}
	return strings.clone(file_path(s, id, PROFILE_FILE), allocator)
}

// The path of `file` in the folder of `id` (the folder itself for ""), in
// the temp allocator.
@(private)
file_path :: proc(s: Store, id, file: string) -> string {
	p, _ := os.join_path({s.dir, id, file}, context.temp_allocator)
	return p
}

// The id is valid and its folder is a real folder (no symlink).
@(private)
profile_exists :: proc(s: Store, id: string) -> bool {
	if s.dir == "" || !id_valid(id) {
		return false
	}
	fi, err := os.lstat(file_path(s, id, ""), context.temp_allocator)
	return err == nil && fi.type == .Directory
}

@(private)
meta_read :: proc(s: Store, id: string, allocator: mem.Allocator) -> (m: Meta, ok: bool) {
	data, real, err := read_capped(file_path(s, id, META_FILE), META_MAX, allocator)
	delete(real, allocator)
	if err != .None {
		return
	}
	defer delete(data, allocator)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena, allocator, allocator)
	defer mem.dynamic_arena_destroy(&arena)
	tmp: Meta
	if json.unmarshal(data, &tmp, allocator = mem.dynamic_arena_allocator(&arena)) != nil {
		return
	}
	tmp.id = id
	if strings.trim_space(tmp.name) == "" {
		tmp.name = id
	}
	return meta_clone(tmp, allocator), true
}

@(private)
meta_write :: proc(s: Store, m: Meta) -> bool {
	data, err := json.marshal(m, {spec = .JSON, pretty = true, use_spaces = true, spaces = 2})
	if err != nil {
		return false
	}
	defer delete(data)
	text := strings.concatenate({string(data), "\n"}, context.temp_allocator)
	return write_file_atomic(file_path(s, m.id, META_FILE), transmute([]u8)text)
}

// Names without case, then the id.
@(private)
meta_less :: proc(a, b: Meta) -> bool {
	x, y := a.name, b.name
	for x != "" && y != "" {
		rx, nx := utf8.decode_rune_in_string(x)
		ry, ny := utf8.decode_rune_in_string(y)
		lx, ly := unicode.to_lower(rx), unicode.to_lower(ry)
		if lx != ly {
			return lx < ly
		}
		x, y = x[nx:], y[ny:]
	}
	if len(x) != len(y) {
		return x == ""
	}
	return a.id < b.id
}
