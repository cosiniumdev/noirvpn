// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build darwin
package main

// The CPU renderer on macOS. The rasterizer writes a frame into an IOSurface and the
// surface becomes the contents of a CALayer on the content view of the window. No
// Metal device, command queue or SDL renderer exists in the process, so the graphics
// driver reserves no memory for it.
//
// A pool of IOSurfaces holds the frames. The window server reads the surface that is
// on screen, so a frame goes into a surface that is off screen and that
// IOSurfaceIsInUse reports as free.

import CF "core:sys/darwin/CoreFoundation"
import CG "core:sys/darwin/CoreGraphics"
import NS "core:sys/darwin/Foundation"
import sdl "vendor:sdl3"
import "ui"

@(export, require)
foreign import io "system:IOSurface.framework"
@(export, require)
foreign import qc "system:QuartzCore.framework"
@(export, require)
foreign import appkit "system:AppKit.framework"

IOSurfaceRef :: distinct rawptr

PIXEL_FORMAT_BGRA :: 0x42475241 // 'BGRA'
SURFACE_POOL :: 3

@(objc_class = "NSWindow", objc_superclass = NS.Object)
Cocoa_Window :: struct {
	using _: NS.Object,
}

@(objc_class = "NSView", objc_superclass = NS.Object)
Cocoa_View :: struct {
	using _: NS.Object,
}

@(objc_class = "CALayer", objc_superclass = NS.Object)
Layer :: struct {
	using _: NS.Object,
}

@(objc_class = "CATransaction", objc_superclass = NS.Object)
Transaction :: struct {
	using _: NS.Object,
}

foreign appkit {
	@(objc_type = Cocoa_Window, objc_selector = "contentView", objc_name = "contentView")
	Window_contentView :: proc(self: ^Cocoa_Window) -> ^Cocoa_View ---

	@(objc_type = Cocoa_View, objc_selector = "setWantsLayer:", objc_name = "setWantsLayer")
	View_setWantsLayer :: proc(self: ^Cocoa_View, flag: bool) ---

	@(objc_type = Cocoa_View, objc_selector = "layer", objc_name = "layer")
	View_layer :: proc(self: ^Cocoa_View) -> ^Layer ---
}

foreign qc {
	@(objc_type = Layer, objc_selector = "layer", objc_name = "layer", objc_is_class_method = true)
	Layer_layer :: proc() -> ^Layer ---

	@(objc_type = Layer, objc_selector = "addSublayer:", objc_name = "addSublayer")
	Layer_addSublayer :: proc(self: ^Layer, layer: ^Layer) ---

	@(objc_type = Layer, objc_selector = "removeFromSuperlayer", objc_name = "removeFromSuperlayer")
	Layer_removeFromSuperlayer :: proc(self: ^Layer) ---

	@(objc_type = Layer, objc_selector = "setFrame:", objc_name = "setFrame")
	Layer_setFrame :: proc(self: ^Layer, frame: NS.Rect) ---

	@(objc_type = Layer, objc_selector = "setContentsScale:", objc_name = "setContentsScale")
	Layer_setContentsScale :: proc(self: ^Layer, scale: f64) ---

	@(objc_type = Layer, objc_selector = "setOpaque:", objc_name = "setOpaque")
	Layer_setOpaque :: proc(self: ^Layer, flag: bool) ---

	@(objc_type = Layer, objc_selector = "setContents:", objc_name = "setContents")
	Layer_setContents :: proc(self: ^Layer, contents: rawptr) ---

	@(objc_type = Transaction, objc_selector = "begin", objc_name = "begin", objc_is_class_method = true)
	Transaction_begin :: proc() ---

	@(objc_type = Transaction, objc_selector = "commit", objc_name = "commit", objc_is_class_method = true)
	Transaction_commit :: proc() ---

	@(objc_type = Transaction, objc_selector = "flush", objc_name = "flush", objc_is_class_method = true)
	Transaction_flush :: proc() ---

	@(objc_type = Transaction, objc_selector = "setDisableActions:", objc_name = "setDisableActions", objc_is_class_method = true)
	Transaction_setDisableActions :: proc(flag: bool) ---
}

foreign io {
	IOSurfaceCreate :: proc(properties: CF.DictionaryRef) -> IOSurfaceRef ---
	IOSurfaceLock :: proc(buffer: IOSurfaceRef, options: u32, seed: ^u32) -> i32 ---
	IOSurfaceUnlock :: proc(buffer: IOSurfaceRef, options: u32, seed: ^u32) -> i32 ---
	IOSurfaceGetBaseAddress :: proc(buffer: IOSurfaceRef) -> rawptr ---
	IOSurfaceGetBytesPerRow :: proc(buffer: IOSurfaceRef) -> uint ---
	IOSurfaceIsInUse :: proc(buffer: IOSurfaceRef) -> bool ---
	IOSurfaceSetValue :: proc(buffer: IOSurfaceRef, key: CF.StringRef, value: CF.TypeRef) ---

	kIOSurfaceWidth: CF.StringRef
	kIOSurfaceHeight: CF.StringRef
	kIOSurfaceBytesPerElement: CF.StringRef
	kIOSurfacePixelFormat: CF.StringRef
	kIOSurfaceColorSpace: CF.StringRef
}

Presenter :: struct {
	window:   ^sdl.Window,
	layer:    ^Layer, // our sublayer of the content view
	surfaces: [SURFACE_POOL]IOSurfaceRef,
	w, h:     i32, // pixel size of the surfaces
	shown:    int, // the surface that is the contents of the layer, or -1
	locked:   int, // the surface that the rasterizer writes, or -1
	pt_w:     f64, // layer size in points and its contents scale, to see a change
	pt_h:     f64,
	scale:    f64,
}

// presenter_open adds the layer to the content view of the window. It returns the
// reason when that fails.
presenter_open :: proc(p: ^Presenter, window: ^sdl.Window) -> string {
	NS.scoped_autoreleasepool()
	p.window = window
	p.shown, p.locked = -1, -1
	win := (^Cocoa_Window)(sdl.GetPointerProperty(sdl.GetWindowProperties(window), sdl.PROP_WINDOW_COCOA_WINDOW_POINTER, nil))
	if win == nil {
		return "the window has no Cocoa window"
	}
	view := win->contentView()
	if view == nil {
		return "the window has no content view"
	}
	view->setWantsLayer(true)
	root := view->layer()
	if root == nil {
		return "the content view has no layer"
	}
	pw, ph: i32
	if !sdl.GetWindowSizeInPixels(window, &pw, &ph) || pw <= 0 || ph <= 0 {
		return "the window has no size"
	}
	// A surface that cannot be created ends the start here, before the layer exists.
	probe := surface_make(pw, ph)
	if probe == nil {
		return "IOSurfaceCreate failed"
	}
	p.surfaces[0], p.w, p.h = probe, pw, ph
	p.layer = Layer.layer()
	p.layer->setOpaque(true)
	root->addSublayer(p.layer)
	return ""
}

presenter_close :: proc(p: ^Presenter) {
	NS.scoped_autoreleasepool()
	if p.locked >= 0 {
		IOSurfaceUnlock(p.surfaces[p.locked], 0, nil)
		p.locked = -1
	}
	if p.layer != nil {
		p.layer->setContents(nil)
		p.layer->removeFromSuperlayer()
		p.layer = nil
	}
	surfaces_free(p)
}

@(private = "file")
surfaces_free :: proc(p: ^Presenter) {
	for &s in p.surfaces {
		if s != nil {
			CF.Release(CF.TypeRef(s))
			s = nil
		}
	}
	p.shown = -1
}

// surface_make creates a BGRA surface tagged as sRGB, the colour space of the
// window (SDL sets it on the window, and its Metal layer follows it).
@(private = "file")
surface_make :: proc(w, h: i32) -> IOSurfaceRef {
	w, h := w, h
	bytes_per_element: i32 = 4
	format: i32 = PIXEL_FORMAT_BGRA
	keys := [4]rawptr{rawptr(kIOSurfaceWidth), rawptr(kIOSurfaceHeight), rawptr(kIOSurfaceBytesPerElement), rawptr(kIOSurfacePixelFormat)}
	values := [4]rawptr {
		rawptr(CF.NumberCreate(nil, .SInt32Type, &w)),
		rawptr(CF.NumberCreate(nil, .SInt32Type, &h)),
		rawptr(CF.NumberCreate(nil, .SInt32Type, &bytes_per_element)),
		rawptr(CF.NumberCreate(nil, .SInt32Type, &format)),
	}
	dict := CF.DictionaryCreate(nil, &keys[0], &values[0], 4, &CF.kTypeDictionaryKeyCallBacks, &CF.kTypeDictionaryValueCallBacks)
	for v in values {
		CF.Release(CF.TypeRef(v))
	}
	if dict == nil {
		return nil
	}
	defer CF.Release(CF.TypeRef(dict))
	s := IOSurfaceCreate(dict)
	if s == nil {
		return nil
	}
	if space := CG.ColorSpaceCreateWithName(CG.ColorSpaceSRGB); space != nil {
		if plist := CG.ColorSpaceCopyPropertyList(space); plist != nil {
			IOSurfaceSetValue(s, kIOSurfaceColorSpace, plist)
			CF.Release(plist)
		}
		CG.ColorSpaceRelease(space)
	}
	return s
}

// presenter_acquire returns the pixels of a surface that the system does not use, locked
// for writing, or false when every surface is busy. It is the frame source of Gfx.
presenter_acquire :: proc(data: rawptr, w, h: i32) -> (ui.Raster_Target, bool) {
	p := (^Presenter)(data)
	if w <= 0 || h <= 0 {
		return {}, false
	}
	if p.locked >= 0 {
		// A frame that was never shown.
		IOSurfaceUnlock(p.surfaces[p.locked], 0, nil)
		p.locked = -1
	}
	if w != p.w || h != p.h {
		surfaces_free(p)
		p.w, p.h = w, h
	}
	for k in 1 ..= SURFACE_POOL {
		i := (max(p.shown, 0) + k) % SURFACE_POOL
		if i == p.shown {
			continue
		}
		if p.surfaces[i] == nil {
			p.surfaces[i] = surface_make(w, h)
			if p.surfaces[i] == nil {
				return {}, false
			}
		} else if IOSurfaceIsInUse(p.surfaces[i]) {
			continue
		}
		s := p.surfaces[i]
		if IOSurfaceLock(s, 0, nil) != 0 {
			continue
		}
		p.locked = i
		return {
				pixels = ([^]u32)(IOSurfaceGetBaseAddress(s)),
				stride = int(IOSurfaceGetBytesPerRow(s) / 4),
				w = int(w),
				h = int(h),
			},
			true
	}
	return {}, false
}

// presenter_show makes the surface that was just drawn the contents of the layer. The
// change has no animation, and the transaction is flushed because SDL runs the event
// loop and no run loop iteration commits it.
presenter_show :: proc(p: ^Presenter) {
	if p.locked < 0 {
		return
	}
	NS.scoped_autoreleasepool()
	i := p.locked
	p.locked = -1
	IOSurfaceUnlock(p.surfaces[i], 0, nil)
	pt_w, pt_h: i32
	_ = sdl.GetWindowSize(p.window, &pt_w, &pt_h)
	Transaction.begin()
	Transaction.setDisableActions(true)
	scale := pt_w > 0 ? f64(p.w) / f64(pt_w) : 1
	if f64(pt_w) != p.pt_w || f64(pt_h) != p.pt_h || scale != p.scale {
		p.pt_w, p.pt_h, p.scale = f64(pt_w), f64(pt_h), scale
		p.layer->setFrame(NS.Rect{origin = {0, 0}, size = {p.pt_w, p.pt_h}})
		p.layer->setContentsScale(scale)
	}
	p.layer->setContents(rawptr(p.surfaces[i]))
	p.shown = i
	Transaction.commit()
	Transaction.flush()
}
