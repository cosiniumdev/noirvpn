// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

// Section bar: a row of icons with labels under the top bar of a view with
// many sections. A click scrolls the view to the section. The section at the
// top of the view is marked.

import "core:math"
import mu "vendor:microui"
import "ui"

NAV_H :: 54
NAV_MAX :: 10
NAV_ITEM_MAX :: 92 // widest item
NAV_OFFSET :: 10 // space above a section label after a jump
NAV_SPY :: 64 // a section whose label is this close to the top of the area is the one marked

Nav_Item :: struct {
	label: string,
	icon:  ui.Icon_Id,
	y:     i32, // top of the section label in the scroll area
}

Nav :: struct {
	area:       string, // scroll area of the view that has the bar
	top:        i32, // window y of the scroll area
	scroll:     i32, // scroll of the area in this frame
	collecting: bool, // section() adds items
	items:      [NAV_MAX]Nav_Item, // sections of the last frame
	n:          int,
	rects:      [NAV_MAX]mu.Rect, // items as last drawn
	next:       [NAV_MAX]Nav_Item, // sections of this frame
	n_next:     int,
	picked:     int, // item of the last click, -1 for none
	picked_at:  i32, // scroll that the click gave
	jumped:     bool, // a click set the scroll in this frame
}

// nav_entry is the item of a section label. ok is false for a section that
// has no item.
@(private = "file")
nav_entry :: proc(section: string) -> (label: string, icon: ui.Icon_Id, ok: bool) {
	switch section {
	case "NAME":
		return "Name", .Tag, true
	case "SERVER":
		return "Server", .Server, true
	case "IDENTITY":
		return "Identity", .Badge, true
	case "YOUR KEY":
		return "Key", .Key, true
	case "TUNNEL":
		return "Tunnel", .Tunnel, true
	case "SIGN-IN":
		return "Sign-in", .Person, true
	case "OVERRIDES":
		return "Overrides", .Sliders, true
	case "PROFILE FILE":
		return "File", .Document, true
	case "INBOUND RULES":
		return "Rules", .Shield, true
	case "ADVANCED", "ADVANCED OPTIONS":
		return "Advanced", .Gear, true
	case "PROFILE TEXT":
		return "Text", .Code, true
	case "IN FORCE":
		return "In force", .Shield, true
	case "RECENTLY BLOCKED":
		return "Blocked", .Block, true
	case "CONFIG FILE":
		return "Config", .Document, true
	case "PROFILE":
		return "Profile", .Edit, true
	case "DEFINE A RULE":
		return "Define", .Plus, true
	case "LINES TO COPY":
		return "Copy", .Copy, true
	}
	return
}

// nav_note adds the section with this label, whose label row starts at window
// y, to the bar of the current view.
nav_note :: proc(app: ^App, section: string, y: i32) {
	nv := &app.nav
	if !nv.collecting || nv.n_next >= NAV_MAX {
		return
	}
	label, icon, ok := nav_entry(section)
	if !ok {
		return
	}
	nv.next[nv.n_next] = {label, icon, y - nv.top + nv.scroll}
	nv.n_next += 1
}

// nav_area_begin draws the section bar at the top of r and opens the scroll
// area called name below it. Close it with nav_area_end.
nav_area_begin :: proc(app: ^App, name: string, r: mu.Rect) {
	nv := &app.nav
	if nv.area != name {
		nv.area = name
		nv.n = 0
		nv.picked = -1
	}
	cnt := mu.get_container(&app.u.ctx, name)
	nav_bar(app, {r.x, r.y, r.w, NAV_H}, cnt)
	area := mu.Rect{r.x, r.y + NAV_H, r.w, r.h - NAV_H}
	scroll_begin(app, name, area)
	cnt = mu.get_current_container(&app.u.ctx)
	if nv.jumped {
		// The scroll is now limited to the content.
		nv.picked_at = cnt.scroll.y
		nv.jumped = false
	}
	nv.top = area.y
	nv.scroll = cnt.scroll.y
	nv.n_next = 0
	nv.collecting = true
}

nav_area_end :: proc(app: ^App) {
	scroll_end(app)
	nv := &app.nav
	nv.items = nv.next
	nv.n = nv.n_next
	nv.collecting = false
}

// nav_active is the item to mark: the clicked one while the scroll stays where
// the click put it, else the last section whose label is near the top of the
// area or above it.
nav_active :: proc(nv: ^Nav, scroll: i32) -> int {
	if nv.picked >= 0 && nv.picked < nv.n && scroll == nv.picked_at {
		return nv.picked
	}
	nv.picked = -1
	active := 0
	for i in 0 ..< nv.n {
		if nv.items[i].y <= scroll + NAV_SPY {
			active = i
		}
	}
	return active
}

@(private = "file")
nav_bar :: proc(app: ^App, r: mu.Rect, cnt: ^mu.Container) {
	u := &app.u
	nv := &app.nav
	ui.hline(u, r.x, r.y + r.h - 1, r.w)
	n := i32(nv.n)
	if n == 0 {
		return
	}
	active := nav_active(nv, cnt.scroll.y)
	iw := min((r.w - 2 * ui.MARGIN) / n, NAV_ITEM_MAX)
	x0 := r.x + (r.w - iw * n) / 2
	for i in 0 ..< nv.n {
		it := nv.items[i]
		ir := mu.Rect{x0 + iw * i32(i), r.y + 3, iw, r.h - 7}
		nv.rects[i] = ir
		res := ui.interact(u, mu.get_id(&u.ctx, tprint("nav %s", it.label)), ir)
		on := i == active
		col := on ? ui.ACCENT : (res.hover ? ui.TEXT : ui.MUTED)
		rf := ui.Rectf{f32(ir.x) + 2, f32(ir.y), f32(ir.w) - 4, f32(ir.h)}
		if res.hover || res.down {
			ui.emit(u, {kind = .Rrect, r = rf, radius = ui.RADIUS_BUTTON, c1 = ui.SURFACE_RAISED})
		}
		size: f32 = 16
		ui.emit(u, {kind = .Icon, r = {math.round(rf.x + (rf.w - size) / 2), rf.y + 7, size, size}, icon = it.icon, c1 = col}, 0)
		label := ui.fit_text(u, ui.ST_CHIP, it.label, rf.w - 8)
		tw := ui.text_w(u, ui.ST_CHIP, label)
		ui.text(u, ui.ST_CHIP, i32(math.round(rf.x + (rf.w - tw) / 2)), ir.y + 27, label, col)
		if on {
			lw := min(tw + 12, rf.w - 8)
			ui.emit(u, {kind = .Rrect, r = {math.round(rf.x + (rf.w - lw) / 2), f32(r.y + r.h) - 2, lw, 2}, radius = 1, c1 = ui.ACCENT})
		}
		if res.ring {
			ui.focus_ring(u, rf, ui.RADIUS_BUTTON)
		}
		if res.clicked {
			// The first section goes to the top of the view.
			cnt.scroll.y = i == 0 ? 0 : max(it.y - NAV_OFFSET, 0)
			nv.picked = i
			nv.jumped = true
		}
	}
}
