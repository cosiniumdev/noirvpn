// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package ui

// Theme tokens.
// All sizes are logical units (one unit is one pixel at 1x density).

import mu "vendor:microui"

Color :: mu.Color

// Colours.
BG :: Color{0x0b, 0x1a, 0x21, 255} // wells, text on accent, and the clear colour
SURFACE :: Color{0x0f, 0x2a, 0x35, 255}
SURFACE_RAISED :: Color{0x17, 0x3a, 0x4a, 255}
BORDER :: Color{0x2f, 0x4d, 0x5c, 255}
TEXT :: Color{0xe3, 0xe8, 0xf2, 255}
TEXT_STRONG :: Color{0xf9, 0xf9, 0xf9, 255} // profile name, server, state pill
MUTED :: Color{0xa4, 0xb3, 0xba, 255}
ACCENT :: Color{0x5c, 0xc8, 0xf0, 255}
OK :: Color{0x5f, 0xb9, 0x8a, 255}
WARN :: Color{0xd9, 0xa4, 0x41, 255}
ERROR :: Color{0xe0, 0x6c, 0x75, 255}

// Window background: vertical gradient, top to bottom.
BG_TOP :: Color{0x0f, 0x31, 0x3d, 255}
BG_BOTTOM :: Color{0x12, 0x28, 0x30, 255}

// Card: vertical gradient with three stops (top, middle, bottom) and a border.
CARD_TOP :: Color{0x10, 0x22, 0x2b, 255}
CARD_MID :: Color{0x0f, 0x2f, 0x3f, 255}
CARD_BOTTOM :: Color{0x0c, 0x43, 0x5f, 255}
CARD_BORDER :: Color{0x4f, 0x61, 0x72, 255}
CARD_FLAT :: Color{0x10, 0x22, 0x2b, 255} // fill of a secondary card, one colour
CARD_RULE :: Color{0x6c, 0x7f, 0x6d, 255} // separator inside a card

// One-unit outline of the frameless window, for platforms without a system frame.
WINDOW_BORDER :: Color{0x3a, 0x4f, 0x5e, 255}

// Bottom bar over the window gradient.
BAR_FILL :: Color{0x0b, 0x1a, 0x21, 140}

// Dimming layer behind a modal dialog.
SCRIM :: Color{0, 0, 0, 140}

// State pill: fill, border and glow of each tone. The glow is drawn with the
// alpha of its colour times the glow strength of the state.
PILL_OK_FILL :: Color{0x3d, 0x91, 0x32, 255}
PILL_OK_BORDER :: Color{0x0c, 0xce, 0x12, 255}
PILL_OK_GLOW :: Color{0x0c, 0xce, 0x12, 105}
PILL_WARN_FILL :: Color{0x9c, 0x6d, 0x14, 255}
PILL_WARN_BORDER :: Color{0xf2, 0xb0, 0x1e, 255}
PILL_WARN_GLOW :: Color{0xf2, 0xb0, 0x1e, 105}
PILL_ERROR_FILL :: Color{0xa2, 0x3b, 0x3b, 255}
PILL_ERROR_BORDER :: Color{0xff, 0x5c, 0x5c, 255}
PILL_ERROR_GLOW :: Color{0xff, 0x5c, 0x5c, 105}
PILL_IDLE_FILL :: Color{0x43, 0x55, 0x5e, 255}
PILL_IDLE_BORDER :: Color{0x8a, 0x9a, 0xa3, 255}
PILL_IDLE_GLOW :: Color{0x8a, 0x9a, 0xa3, 0}
PILL_TEXT :: Color{0xff, 0xff, 0xff, 255}

// Connection card: graph lines, axis labels, rates and the transport label.
GRAPH_DOWN :: Color{0x72, 0xd5, 0xff, 255}
GRAPH_UP :: Color{0x3a, 0xaa, 0x41, 255}
GRAPH_LABEL :: Color{0xcc, 0xcc, 0xcc, 255}
STAT_LABEL :: Color{0xb6, 0xb6, 0xb6, 255}
STAT_DOWN :: Color{0x2d, 0xb1, 0xc3, 255}
STAT_UP :: Color{0x08, 0xc9, 0x7f, 255}
TRANSPORT :: Color{0x24, 0xc6, 0xc3, 255}
// An empty cell of the rate matrix: BORDER at about 0.18.
GRAPH_EMPTY :: Color{0x2f, 0x4d, 0x5c, 46}
// The backing of the scale label over the matrix: CARD_TOP at about 0.85.
GRAPH_SCALE_BG :: Color{0x10, 0x22, 0x2b, 217}
// The main card while connected: the border is CARD_BORDER mixed 0.55 toward
// PILL_OK_BORDER, with a soft glow of PILL_OK_BORDER at about 0.35.
CARD_UP_BORDER :: Color{0x2a, 0x9d, 0x3d, 255}
CARD_UP_GLOW :: Color{0x0c, 0xce, 0x12, 89}

// The tile behind a program icon in About.
ABOUT_ICON_BG :: Color{0x00, 0x00, 0x00, 255}

// Plain text field (sign-in form).
FIELD_PLAIN_BG :: Color{0x0b, 0x1a, 0x21, 255}
FIELD_PLAIN_BORDER :: Color{0x8a, 0x9a, 0xa3, 255}
FIELD_PLAIN_BORDER_HOT :: Color{0xc4, 0xcd, 0xd2, 255}

// Colours of a disabled button.
DISABLED_BG :: Color{0x4f, 0x55, 0x64, 255}
DISABLED_TEXT :: Color{0x86, 0x8c, 0x9b, 255}

// The logo behind the content of the connection view: a little lighter than
// the window background.
LOGO_SHADE :: Color{0x17, 0x34, 0x3f, 255}

// Scrollbar thumb.
SCROLL_THUMB :: Color{133, 133, 133, 255}

// Radii.
RADIUS_BUTTON :: 8
RADIUS_FIELD :: 8
RADIUS_PANEL :: 10
RADIUS_CARD :: 8
RADIUS_PILL :: 12
RADIUS_CHIP :: 10
RADIUS_MENU :: 8

// Metrics.
TOPBAR_H :: 56
CARD_MARGIN :: 22 // side margin of the cards on the connection view
PILL_W :: 170
PILL_H :: 34
ICON_BUTTON :: 40
MARGIN :: 16
FIELD_H :: 38
LABEL_W :: 132 // the label column of the details, DNS, routes and tunnel cards
ABOUT_ICON :: 80 // a program icon in About
ABOUT_LOGO_W :: 200 // the logo in About
BUTTON_PAD_X :: 16
BUTTON_PAD_Y :: 8

// with_alpha returns c with its alpha multiplied by a (0 to 1).
with_alpha :: proc(c: Color, a: f32) -> Color {
	r := c
	r.a = u8(clamp(f32(c.a) * a, 0, 255) + 0.5)
	return r
}

// mix blends from a to b by t (0 to 1).
mix :: proc(a, b: Color, t: f32) -> Color {
	m :: proc(x, y: u8, t: f32) -> u8 {
		return u8(clamp(f32(x) + (f32(y) - f32(x)) * t, 0, 255) + 0.5)
	}
	return {m(a.r, b.r, t), m(a.g, b.g, t), m(a.b, b.b, t), m(a.a, b.a, t)}
}

// Font_Id picks one of the embedded faces.
Font_Id :: enum u8 {
	Regular,
	Medium,
	Semi_Bold,
	Bold,
	Mono,
}

// Text_Style is a face and a size in logical units.
Text_Style :: struct {
	font: Font_Id,
	size: f32,
}

ST_BODY := Text_Style{.Regular, 14}
ST_BODY_BOLD := Text_Style{.Bold, 14}
ST_TITLE := Text_Style{.Semi_Bold, 18}
ST_HEADING := Text_Style{.Semi_Bold, 15}
ST_CAPTION := Text_Style{.Regular, 12.5}
ST_ROW_PROTO := Text_Style{.Semi_Bold, 12.5}
ST_SECTION := Text_Style{.Semi_Bold, 12.5}
ST_LABEL := Text_Style{.Regular, 12.5}
ST_MONO := Text_Style{.Mono, 12.5}
ST_CHIP := Text_Style{.Medium, 12}
ST_BUTTON := Text_Style{.Medium, 14}
ST_BUTTON_PRIMARY := Text_Style{.Semi_Bold, 14}
ST_GRAPH := Text_Style{.Regular, 10}
ST_STAT_LABEL := Text_Style{.Regular, 11.5}
ST_BAR_TITLE := Text_Style{.Bold, 16}
ST_STAT := Text_Style{.Bold, 16}
ST_PILL := Text_Style{.Bold, 16}
ST_TRANSPORT := Text_Style{.Regular, 14}

// Tone is a colour role: chips, state dots and messages use it.
Tone :: enum u8 {
	Neutral,
	Accent,
	Ok,
	Warn,
	Error,
}

tone_color :: proc(t: Tone) -> Color {
	switch t {
	case .Neutral:
		return MUTED
	case .Accent:
		return ACCENT
	case .Ok:
		return OK
	case .Warn:
		return WARN
	case .Error:
		return ERROR
	}
	return MUTED
}

// Pill_Colors are the colours of a state pill.
Pill_Colors :: struct {
	fill, border, glow: Color,
}

pill_colors :: proc(t: Tone) -> Pill_Colors {
	switch t {
	case .Ok:
		return {PILL_OK_FILL, PILL_OK_BORDER, PILL_OK_GLOW}
	case .Warn:
		return {PILL_WARN_FILL, PILL_WARN_BORDER, PILL_WARN_GLOW}
	case .Error:
		return {PILL_ERROR_FILL, PILL_ERROR_BORDER, PILL_ERROR_GLOW}
	case .Accent, .Neutral:
	}
	return {PILL_IDLE_FILL, PILL_IDLE_BORDER, PILL_IDLE_GLOW}
}
