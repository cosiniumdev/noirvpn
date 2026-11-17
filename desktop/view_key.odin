// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// New key and certificate request (CSR) of an imported profile:
// 1. generate a new private key and a CSR for a certificate authority
// 2. keep both in the profile folder until the certificate comes back
// 3. set the new key and certificate in the profile text
// With no certificate, the new key gets a self-signed one, for a noirvpn server
// that pins keys. The private key is never shown.
//
// States: no request (common name, key type, Make), a request (CSR, key pin,
// certificate import, Set new key, Discard), done.

import "core:math"
import "core:mem"
import "core:os"
import "core:strings"
import "core:time"
import mu "vendor:microui"
import "noir:proto/config"
import pf "profiles"
import "ui"

REQ_INTRO :: "Create a new private key on this device and a request (CSR) for your certificate authority. The private key never leaves this device."
REQ_TYPE_CAPTION :: "Use ECDSA P-256 if your certificate authority does not sign Ed25519 keys. ML-DSA-65 is post-quantum and only works with a noirvpn server."
REQ_GIVE_CAPTION :: "Give the request to your certificate authority. Give the key pin to the administrator of a noirvpn server that pins keys."
REQ_SET_CAPTION :: "Set new key will replace the key of this profile. The connection will not work until the server accepts the new key."
REQ_DISCARD_TEXT :: "The new key will be deleted, and the profile will keep its current key."
REQ_SET_SELF_SIGNED :: "Your current key will be deleted, and this profile will use the new key with a self-signed certificate. The connection will not work until the server knows the new key: the administrator must add the key pin to the peers file of the server. This cannot be undone."
REQ_SET_IMPORTED :: "Your current key will be deleted, and this profile will use the new key and the imported certificate. The connection will not work until the server accepts the new certificate. This cannot be undone."
REQ_MISMATCH :: "This certificate does not match the key of the request."

REQ_KEY_TYPES := [3]string{pf.KEY_ED25519, pf.KEY_P256, pf.KEY_MLDSA65}
REQ_KEY_LABELS := [3]string{"Ed25519", "ECDSA P-256", "ML-DSA-65"}

// What the GUI shows of an imported certificate. All of it is public.
Cert_Read :: struct {
	cert, chain:           string, // PEM
	subject, issuer:       string,
	common_name:           string,
	not_before, not_after: string, // ISO 8601 in UTC
	pin:                   string,
	spki:                  [32]u8,
}

cert_read_destroy :: proc(c: ^Cert_Read) {
	delete(c.cert)
	delete(c.chain)
	delete(c.subject)
	delete(c.issuer)
	delete(c.common_name)
	delete(c.not_before)
	delete(c.not_after)
	delete(c.pin)
	c^ = {}
}

Key_Req :: struct {
	cn:         ui.Field,
	key_type:   int, // index in REQ_KEY_TYPES
	tried:      bool, // Make was pressed: a bad common name shows its error
	has:        bool, // a request waits
	req:        pf.Request,
	has_cert:   bool,
	cert:       Cert_Read,
	done:       bool,
	done_line:  string, // the key pin of the new key, as the line of the peers file
	// Set by the view for the tests.
	make_at:    mu.Rect,
	set_at:     mu.Rect,
	discard_at: mu.Rect,
}

Confirm_Kind :: enum u8 {
	None,
	Set_Key,
	Discard_Request,
}

// A question in a modal card over the window: Cancel and one danger button.
Confirm :: struct {
	kind:  Confirm_Kind,
	fresh: bool,
}

CONFIRM_MODAL :: "confirm"
CONFIRM_CANCEL :: "Cancel"

key_request_init :: proc(kr: ^Key_Req) {
	ui.field_init(&kr.cn)
}

@(private = "file")
key_request_forget :: proc(kr: ^Key_Req) {
	pf.request_destroy(&kr.req)
	cert_read_destroy(&kr.cert)
	kr.has, kr.has_cert = false, false
}

// key_request_open shows the view for the profile of the profile view.
key_request_open :: proc(app: ^App) {
	e := &app.edit
	kr := &app.keyreq
	key_request_forget(kr)
	kr.done, kr.tried = false, false
	kr.key_type = 0
	set_text(&kr.done_line, "")
	if e.id != "" {
		req, ok := pf.store_request_load(app.store, e.id)
		if ok {
			kr.req, kr.has = req, true
		}
	} else if e.request {
		key_request_sample(kr)
	}
	cn := e.cn if e.cn != "" else pf.peers_name(ui.field_text(&e.name), context.temp_allocator)
	ui.field_set(&kr.cn, cn)
	e.status = ""
	push_view(app, .Key_Request)
}

// The request of the simulation and the pictures.
SAMPLE_CSR :: "-----BEGIN CERTIFICATE REQUEST-----\n" +
	"MIIBNzCB3gIBADAQMQ4wDAYDVQQDDAVhbGljZTBZMBMGByqGSM49AgEGCCqGSM49\n" +
	"AwEHA0IABHq3pXcV0b9Ck6m8nW2sQh1fT4ZrJ0yLx7uE5aGdP3oKcN6vB8wR1tYf\n" +
	"S2jMh4UeL9iQz7DnA0kXbVq5oPw3RCigazBpBgkqhkiG9w0BCQ4xXDBaMA4GA1Ud\n" +
	"DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUq8nTz2Lw\n" +
	"5vJxY0bR3kHfA9mC1sEwFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49BAMC\n" +
	"A0gAMEUCIQDk7b4Wq0yZr1nH9cS5tLm2xVfJ8aPe3oQ6uG0iN4wRbAIgW1zT7qYc\n" +
	"F3hK9mVd2oJ5rX0bLp8sE6nQ4wUa1yTg7Ck=\n" +
	"-----END CERTIFICATE REQUEST-----\n"

key_request_sample :: proc(kr: ^Key_Req) {
	pf.request_destroy(&kr.req)
	kr.req = pf.Request {
		csr         = strings.clone(SAMPLE_CSR),
		pin         = strings.clone(SAMPLE_PIN),
		common_name = strings.clone("alice"),
		key_type    = strings.clone(pf.KEY_P256),
		created     = 1794472920,
	}
	kr.has = true
}

// key_request_make generates the key and the request and stores both.
key_request_make :: proc(app: ^App) {
	e := &app.edit
	kr := &app.keyreq
	kr.tried = true
	cn := strings.trim_space(ui.field_text(&kr.cn))
	if !pf.common_name_valid(cn) {
		return
	}
	kt := REQ_KEY_TYPES[kr.key_type]
	if e.id == "" {
		key_request_sample(kr)
		set_text(&kr.req.common_name, cn)
		set_text(&kr.req.key_type, kt)
		e.request = true
		return
	}
	csr, key, pin, ok := request_new(kt, cn)
	if !ok {
		edit_status(app, "The key could not be created.", true)
		return
	}
	defer pf.wipe_string(key)
	req := pf.Request {
		csr         = csr,
		pin         = pin,
		common_name = strings.clone(cn),
		key_type    = strings.clone(kt),
		created     = time.time_to_unix(time.now()),
	}
	if !pf.store_request_save(app.store, e.id, key, req) {
		pf.request_destroy(&req)
		edit_status(app, "The key could not be saved.", true)
		return
	}
	key_request_forget(kr)
	kr.req, kr.has = req, true
	e.request = true
	e.status = ""
}

// key_request_save_start asks where to save the request.
key_request_save_start :: proc(app: ^App) {
	d := &app.dialog
	if d.kind != .None || app.headless {
		return
	}
	d.kind = .Save_Request
	name := pf.request_file_name(app.keyreq.req.common_name, context.temp_allocator)
	sdl_save_dialog(app, csr_filters[:], name)
}

// key_request_save_to writes the request to the file the user chose.
key_request_save_to :: proc(app: ^App, path: string) {
	kr := &app.keyreq
	if !kr.has {
		return
	}
	if os.write_entire_file(path, transmute([]u8)kr.req.csr) != nil {
		edit_status(app, "The request could not be saved there.", true)
		return
	}
	edit_status(app, tprint("The request was saved to %s.", path))
}

// key_request_choose asks for a certificate file.
key_request_choose :: proc(app: ^App) {
	d := &app.dialog
	if d.kind != .None || app.headless {
		return
	}
	d.kind = .Open_Cert
	sdl_open_dialog(app, cert_filters[:])
}

// key_request_file reads a certificate file: PEM or DER, at most 1 MiB.
key_request_file :: proc(app: ^App, path: string) {
	fi, serr := os.stat(path, context.temp_allocator)
	if serr != nil || fi.type != .Regular {
		edit_status(app, "The file could not be read.", true)
		return
	}
	if fi.size > pf.CERT_FILE_MAX {
		edit_status(app, "The file is larger than 1 MiB.", true)
		return
	}
	data, rerr := os.read_entire_file(path, context.temp_allocator)
	if rerr != nil {
		edit_status(app, "The file could not be read.", true)
		return
	}
	if len(data) == 0 {
		edit_status(app, "The file is empty.", true)
		return
	}
	cert_take(app, data)
}

// key_request_paste takes a certificate from the clipboard.
key_request_paste :: proc(app: ^App) {
	s, ok := ui.clipboard_paste()
	if !ok || strings.trim_space(s) == "" {
		edit_status(app, "Paste the certificate first.", true)
		return
	}
	cert_take(app, transmute([]u8)s)
}

// cert_take reads a certificate for the request.
cert_take :: proc(app: ^App, data: []u8) {
	kr := &app.keyreq
	c, ok := cert_load(data)
	if !ok {
		edit_status(app, "The certificate could not be read.", true)
		return
	}
	cert_read_destroy(&kr.cert)
	kr.cert, kr.has_cert = c, true
	app.edit.status = ""
}

// cert_matches is true when the imported certificate is for the key of the
// request.
cert_matches :: proc(kr: ^Key_Req) -> bool {
	return kr.has_cert && kr.cert.pin == kr.req.pin
}

// iso_now is the time now as the certificates give it: ISO 8601 in UTC.
iso_now :: proc() -> string {
	now := time.now()
	y, mon, d := time.date(now)
	hh, mm, ss := time.clock(now)
	return tprint("%04d-%02d-%02dT%02d:%02d:%02dZ", y, int(mon), d, hh, mm, ss)
}

// key_set sets the new key: with the imported certificate, else with a
// self-signed one. The new text goes through profile.check like a Save.
key_set :: proc(app: ^App) {
	e := &app.edit
	kr := &app.keyreq
	if !kr.has {
		edit_status(app, "There is no pending request.", true)
		return
	}
	if kr.has_cert && !cert_matches(kr) {
		edit_status(app, REQ_MISMATCH, true)
		return
	}
	if e.id == "" {
		key_set_commit(app, "", "")
		return
	}
	key, kok := pf.store_request_key(app.store, e.id)
	defer pf.wipe_string(key)
	if !kok {
		edit_status(app, "There is no pending request.", true)
		return
	}
	cert, chain := kr.cert.cert, kr.cert.chain
	if !kr.has_cert {
		c, ok := self_signed_cert(key, kr.req.common_name, context.temp_allocator)
		if !ok {
			edit_status(app, "The key could not be created.", true)
			return
		}
		cert = c
	}
	// The certificate must be for the key of the request.
	spki, sok := key_spki(key)
	info, iok := cert_load(transmute([]u8)cert)
	same := sok && iok && info.spki == spki
	cert_read_destroy(&info)
	if !same {
		edit_status(app, REQ_MISMATCH, true)
		return
	}
	meta, text, ok := pf.store_load(app.store, e.id, context.temp_allocator)
	defer if len(text) > 0 {
		mem.zero_explicit(raw_data(text), len(text))
	}
	if !ok {
		edit_status(app, "The profile no longer exists.", true)
		return
	}
	blocks := config.identity_blocks(cert, key, chain)
	out := config.identity_text(text, blocks)
	pf.wipe_string(blocks)
	pending_start(app, .Key_Set, out, meta.name, "", "", {})
	form_send(app)
}

// key_set_commit stores the checked text and deletes the request.
key_set_commit :: proc(app: ^App, text, note: string) {
	e := &app.edit
	kr := &app.keyreq
	cn := kr.cert.common_name if kr.has_cert else kr.req.common_name
	line := pf.peers_line(cn, kr.req.pin, context.temp_allocator)
	if e.id != "" {
		if !pf.store_save_text(app.store, e.id, text) {
			edit_status(app, "The key could not be saved.", true)
			return
		}
		_ = pf.store_request_clear(app.store, e.id)
		store_reload(app)
		id := strings.clone(e.id, context.temp_allocator)
		if k := row_of(app, id); k >= 0 {
			_ = edit_load_stored(app, e, k)
		}
	} else {
		set_text(&e.cn, cn)
		set_text(&e.pin, kr.req.pin)
		e.request = false
	}
	set_text(&kr.done_line, line)
	kr.done = true
	key_request_forget(kr)
	msg := note
	if e.index == app.conn.profile && conn_active(app) {
		msg = "The new key applies after you reconnect."
	}
	edit_status(app, msg)
}

// key_discard deletes the request and its key.
key_discard :: proc(app: ^App) {
	e := &app.edit
	kr := &app.keyreq
	if e.id != "" && !pf.store_request_clear(app.store, e.id) {
		edit_status(app, "The request could not be deleted.", true)
		return
	}
	key_request_forget(kr)
	kr.tried = false
	e.request = false
	e.status = ""
}

// key_request_leave goes back to the profile; a check on its way is forgotten.
key_request_leave :: proc(app: ^App) {
	if app.pending.kind == .Key_Set {
		pending_drop(app)
	}
	app.edit.status = ""
	pop_view(app)
}

// kv_line is a label and a value in a group, the value shortened to fit.
kv_line :: proc(app: ^App, label, value: string, col := ui.TEXT) {
	u := &app.u
	rr := inner(app, 24)
	lw: i32 = 116
	ui.text(u, ui.ST_BODY, rr.x, rr.y + 3, label, ui.MUTED)
	ui.text(u, ui.ST_BODY, rr.x + lw, rr.y + 3, ui.fit_text(u, ui.ST_BODY, value if value != "" else "–", f32(rr.w - lw)), col)
}

// csr_well draws the request in the mono face, broken at any character. A
// long request scrolls inside a well of at most CSR_LINES lines.
CSR_LINES :: 10

csr_well :: proc(app: ^App, s: string) {
	u := &app.u
	probe := inner(app, 0)
	cw := ui.text_w(u, ui.ST_MONO, "0")
	per := max(int(f32(probe.w - 20 - 12) / max(cw, 1)), 8)
	lines := make([dynamic]string, 0, 16, context.temp_allocator)
	rest := strings.trim_right(s, "\r\n")
	for l in strings.split_lines_iterator(&rest) {
		t := strings.trim_right(l, "\r")
		for len(t) > per {
			append(&lines, t[:per])
			t = t[per:]
		}
		append(&lines, t)
	}
	shown := min(len(lines), CSR_LINES)
	rr := inner(app, 18 + i32(shown) * 16)
	ui.well(u, rr)
	ctx := &u.ctx
	mu.layout_set_next(ctx, {rr.x + 1, rr.y + 1, rr.w - 2, rr.h - 2}, false)
	mu.begin_panel(ctx, "csr", {.NO_FRAME})
	mu.layout_row(ctx, {-1}, 16 + i32(len(lines)) * 16)
	b := mu.layout_next(ctx)
	for l, i in lines {
		ui.text(u, ui.ST_MONO, b.x + 9, b.y + 8 + i32(i) * 16, l, ui.TEXT)
	}
	mu.end_panel(ctx)
}

view_key_request :: proc(app: ^App) {
	u := &app.u
	kr := &app.keyreq
	w, h := u.size.x, u.size.y
	res := topbar(app, {back = true, title = "Key request", simulated = app.link.kind == .Sim})
	if res.back {
		key_request_leave(app)
		return
	}
	busy := app.pending.kind != .None
	scroll_begin(app, "keyreq", {0, ui.TOPBAR_H, w, h - ui.TOPBAR_H})
	gap(app, 14)
	switch {
	case kr.done:
		section(app, "NEW KEY")
		g, y0 := group_open(app)
		rr := inner(app, 17)
		ui.text(u, ui.ST_BODY_BOLD, rr.x, rr.y, "The new key is set.", ui.OK)
		gap(app, 10)
		key_pin_row(app, kr.done_line)
		gap(app, 6)
		group_caption(app, PIN_CAPTION)
		status_line(app)
		group_close(app, g, y0)

	case !kr.has:
		section(app, "NEW KEY AND CERTIFICATE REQUEST")
		g, y0 := group_open(app)
		body_text(app, REQ_INTRO)
		gap(app, 14)
		cn := strings.trim_space(ui.field_text(&kr.cn))
		cn_err := "Use 1 to 64 characters." if kr.tried && !pf.common_name_valid(cn) else ""
		field_label(app, "Common name")
		rr := inner(app, ui.FIELD_H)
		_, _ = ui.field(u, rr, &kr.cn, "", {enabled = true, error = cn_err != ""})
		field_error(app, cn_err)
		gap(app, 12)
		field_label(app, "Key type")
		for label, k in REQ_KEY_LABELS {
			if k > 0 {
				gap(app, 6)
			}
			rr = inner(app, ui.FIELD_H)
			if ui.choice(u, rr, label, k == kr.key_type) {
				kr.key_type = k
			}
		}
		gap(app, 8)
		group_caption(app, REQ_TYPE_CAPTION)
		gap(app, 14)
		rr = inner(app, i32(ui.button_height()))
		mw := i32(math.ceil(ui.button_width(u, "Create key and request", .Primary)))
		kr.make_at = {rr.x, rr.y, mw, rr.h}
		if ui.button(u, kr.make_at, "Create key and request", .Primary, !busy, ui.SURFACE) {
			key_request_make(app)
		}
		status_line(app)
		group_close(app, g, y0)

	case:
		section(app, "REQUEST")
		g, y0 := group_open(app)
		kt := kr.req.key_type
		for t, k in REQ_KEY_TYPES {
			if t == kr.req.key_type {
				kt = REQ_KEY_LABELS[k]
			}
		}
		kv_line(app, "Common name", kr.req.common_name)
		kv_line(app, "Key type", kt)
		kv_line(app, "Made", fmt_local_time(kr.req.created))
		gap(app, 10)
		csr_well(app, kr.req.csr)
		gap(app, 10)
		rr := inner(app, 35)
		copied := app.copied == kr.req.csr
		cl := "Copied" if copied else "Copy request"
		cw := i32(math.ceil(ui.button_width(u, "Copy request", .Secondary)))
		if ui.button(u, {rr.x, rr.y, cw, 35}, cl, .Secondary, true, ui.SURFACE) {
			copy_text(app, kr.req.csr)
		}
		sw := i32(math.ceil(ui.button_width(u, "Save request…", .Secondary)))
		if ui.button(u, {rr.x + cw + 8, rr.y, sw, 35}, "Save request…", .Secondary, !app.headless, ui.SURFACE) {
			key_request_save_start(app)
		}
		gap(app, 12)
		key_pin_row(app, pf.peers_line(kr.req.common_name, kr.req.pin, context.temp_allocator))
		gap(app, 6)
		group_caption(app, REQ_GIVE_CAPTION)
		group_close(app, g, y0)

		section(app, "CERTIFICATE")
		g, y0 = group_open(app)
		group_caption(app, "Import the certificate (a PEM or DER file) that your certificate authority issued for this request.")
		gap(app, 10)
		rr = inner(app, 35)
		fw := i32(math.ceil(ui.button_width(u, "Choose file…", .Secondary)))
		if ui.button(u, {rr.x, rr.y, fw, 35}, "Choose file…", .Secondary, !app.headless, ui.SURFACE) {
			key_request_choose(app)
		}
		pw := i32(math.ceil(ui.button_width(u, "Paste", .Secondary)))
		if ui.button(u, {rr.x + fw + 8, rr.y, pw, 35}, "Paste", .Secondary, true, ui.SURFACE) {
			key_request_paste(app)
		}
		if kr.has_cert {
			group_sep(app)
			c := &kr.cert
			kv_line(app, "Subject", c.subject)
			kv_line(app, "Issuer", c.issuer)
			kv_line(app, "Valid until", c.not_after[:min(len(c.not_after), 10)])
			gap(app, 6)
			mu.push_id(&u.ctx, "cert")
			key_pin_row(app, pf.peers_line(c.common_name, c.pin, context.temp_allocator))
			mu.pop_id(&u.ctx)
			now := iso_now()
			warn := ""
			switch {
			case c.not_after != "" && c.not_after < now:
				warn = "This certificate has expired."
			case c.not_before != "" && c.not_before > now:
				warn = "This certificate is not valid yet."
			}
			if !cert_matches(kr) {
				gap(app, 10)
				rr = inner(app, 35)
				clw := i32(math.ceil(ui.button_width(u, "Clear", .Secondary)))
				lines := ui.wrap_text(u, ui.ST_BODY, REQ_MISMATCH, f32(rr.w - clw - 12))
				for l, i in lines {
					ui.text(u, ui.ST_BODY, rr.x, rr.y + i32(i) * 17, l, ui.ERROR)
				}
				if ui.button(u, {rr.x + rr.w - clw, rr.y, clw, 35}, "Clear", .Secondary, true, ui.SURFACE) {
					cert_read_destroy(&kr.cert)
					kr.has_cert = false
				}
			} else if warn != "" {
				gap(app, 8)
				group_caption(app, warn, ui.WARN)
			}
		}
		group_close(app, g, y0)

		section(app, "NEW KEY")
		g, y0 = group_open(app)
		group_caption(app, REQ_SET_CAPTION)
		gap(app, 12)
		rr = inner(app, i32(ui.button_height()))
		stw := i32(math.ceil(ui.button_width(u, "Set new key", .Primary)))
		dw := i32(math.ceil(ui.button_width(u, "Discard request", .Secondary)))
		kr.set_at = {rr.x, rr.y, stw, rr.h}
		kr.discard_at = {rr.x + rr.w - dw, rr.y, dw, rr.h}
		if ui.button(u, kr.set_at, "Set new key", .Primary, !busy && !(kr.has_cert && !cert_matches(kr)), ui.SURFACE) {
			confirm_open(app, .Set_Key)
		}
		if ui.button(u, kr.discard_at, "Discard request", .Secondary, !busy, ui.SURFACE) {
			confirm_open(app, .Discard_Request)
		}
		status_line(app)
		group_close(app, g, y0)
	}
	gap(app, 10)
	scroll_end(app)
}

// body_text draws a wrapped text in the body face in a group.
body_text :: proc(app: ^App, text: string, col := ui.TEXT) {
	probe := inner(app, 0)
	for l in ui.wrap_text(&app.u, ui.ST_BODY, text, f32(probe.w)) {
		rr := inner(app, 18)
		ui.text(&app.u, ui.ST_BODY, rr.x, rr.y, l, col)
	}
}

// status_line draws the status of the profile view in a group, if any.
@(private = "file")
status_line :: proc(app: ^App) {
	e := &app.edit
	if e.status == "" {
		return
	}
	gap(app, 10)
	body_text(app, e.status, ui.ERROR if e.status_error else ui.OK)
}

// ---- Confirmation ----

confirm_open :: proc(app: ^App, kind: Confirm_Kind) {
	app.confirm = {
		kind  = kind,
		fresh = true,
	}
}

@(private = "file")
confirm_texts :: proc(app: ^App) -> (title, body, ok_label: string) {
	switch app.confirm.kind {
	case .Set_Key:
		return "Set new key?", REQ_SET_IMPORTED if app.keyreq.has_cert else REQ_SET_SELF_SIGNED, "Set new key"
	case .Discard_Request:
		return "Discard request?", REQ_DISCARD_TEXT, "Discard"
	case .None:
	}
	return
}

// view_confirm draws the question when one is open and acts on its buttons.
// It runs after the other popups, so it lies above everything.
view_confirm :: proc(app: ^App) {
	c := &app.confirm
	if c.kind == .None {
		return
	}
	u := &app.u
	if !ui.modal_begin(u, CONFIRM_MODAL, c.fresh) {
		return
	}
	defer ui.modal_end(u)
	if c.fresh {
		c.fresh = false
		u.focus = mu.get_id(&u.ctx, CONFIRM_CANCEL)
		u.focus_visible = true
	}
	title, body, ok_label := confirm_texts(app)
	card_w := u.size.x - 2 * QUIT_MARGIN
	inner_w := card_w - 2 * QUIT_PAD
	lines := ui.wrap_text(u, ui.ST_BODY, body, f32(inner_w))
	line_h := i32(ui.line_height(ui.ST_BODY)) + 2
	title_h := i32(ui.line_height(ui.ST_HEADING))
	bh := i32(ui.button_height())
	card_h := QUIT_PAD + title_h + 12 + i32(len(lines)) * line_h + 16 + bh + QUIT_PAD
	card := mu.Rect{QUIT_MARGIN, (u.size.y - card_h) / 2, card_w, card_h}

	mu.draw_rect(&u.ctx, {0, 0, u.size.x, u.size.y}, ui.SCRIM)
	if ui.interact(u, mu.get_id(&u.ctx, "scrim"), {0, 0, u.size.x, u.size.y}, false, true, card).clicked {
		c.kind = .None
		return
	}
	ui.card_flat(u, card)
	x := card.x + QUIT_PAD
	ty := card.y + QUIT_PAD
	ui.text(u, ui.ST_HEADING, x, ty, title, ui.TEXT)
	by := ty + title_h + 12
	for l, i in lines {
		ui.text(u, ui.ST_BODY, x, by + i32(i) * line_h, l, ui.MUTED)
	}
	yb := by + i32(len(lines)) * line_h + 16
	ow := i32(math.ceil(ui.button_width(u, ok_label, .Danger)))
	cw := i32(math.ceil(ui.button_width(u, CONFIRM_CANCEL, .Ghost)))
	okr := mu.Rect{card.x + card_w - QUIT_PAD - ow, yb, ow, bh}
	cr := mu.Rect{okr.x - QUIT_GAP - cw, yb, cw, bh}
	ok := ui.button(u, okr, ok_label, .Danger, true, ui.CARD_FLAT)
	cancel := ui.button(u, cr, CONFIRM_CANCEL, .Ghost, true, ui.CARD_FLAT)
	if u.escape || cancel {
		c.kind = .None
		return
	}
	if ok {
		kind := c.kind
		c.kind = .None
		switch kind {
		case .Set_Key:
			key_set(app)
		case .Discard_Request:
			key_discard(app)
		case .None:
		}
	}
}

// edit_status sets the status of the profile view (and of the views above it)
// to a copy of text.
edit_status :: proc(app: ^App, text: string, error := false) {
	e := &app.edit
	set_text(&e.status_owned, text)
	e.status = e.status_owned
	e.status_error = error
}
