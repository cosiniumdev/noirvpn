// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

#+build linux
package main

import "core:strings"
import "core:testing"
import "core:time"
import "noir:bus"
import "noir:client"
import "noir:engine"
import "noir:platform/dco"
import "noir:proto/config"

// Tests of the backend choice and the kernel driver paths, against fake
// backends.
// The driver itself is proven on two hosts.

// A fake link for the hook: what `dco_link_connect` creates for each kind.
Probe :: struct {
	kernel_st:  int, // what the kernel try returns
	service_st: int,
	order:      [dynamic]dco.Backend_Kind, // the tries, in order
	// The fake kernel backend.
	kbe:        Fake_Be,
	open_idx:   u32,
	// Capabilities that the fake service has besides the usual ones.
	service_caps: u32,
}

@(thread_local)
probe: Probe

probe_hook :: proc(l: ^Dco_Link, kind: dco.Backend_Kind, path: string) -> int {
	append(&probe.order, kind)
	st := probe.kernel_st if kind == .Kernel else probe.service_st
	if st != 0 {
		return st
	}
	fake_link_up(l)
	l.be = fake_be(&probe.kbe)
	l.be.kind = kind
	l.be.fd = 5
	if kind == .Kernel {
		l.be.caps = dco.CAP_TCP
		l.be.mss_clamp = false
		l.be.err_text = proc(user: rawptr) -> string {
			return (^Fake_Be)(user).etext
		}
	} else {
		l.be.caps = dco.CAP_TCP | dco.CAP_PEER_ID | dco.CAP_PEER_ADDR | dco.CAP_KEY_TABLE | probe.service_caps
		l.be.mss_clamp = true
	}
	return 0
}

probe_begin :: proc(kernel_st, service_st: int) {
	delete(probe.order)
	probe = {}
	probe.kernel_st = kernel_st
	probe.service_st = service_st
	probe.kbe.fail = make(map[string]int)
	probe.kbe.open_idx = 7
	engine.dco_connect_hook = probe_hook
}

probe_end :: proc() {
	engine.dco_connect_hook = nil
	delete(probe.order)
	delete(probe.kbe.fail)
	delete(probe.kbe.calls)
	probe = {}
}

@(test)
test_dco_pick_order :: proc(t: ^testing.T) {
	// userspace: no try at all.
	probe_begin(0, 0)
	defer probe_end()
	l: Dco_Link
	p := dco_pick(&l, .Userspace, "/s", 0)
	testing.expect(t, !p.found)
	testing.expect_value(t, len(probe.order), 0)

	// dco: the kernel only, found or not.
	p = dco_pick(&l, .Dco, "/s", 0)
	testing.expect(t, p.found && p.kind == .Kernel)
	testing.expect_value(t, len(probe.order), 1)
	probe.kernel_st = dco.ENO_OVPN
	clear(&probe.order)
	p = dco_pick(&l, .Dco, "/s", 0)
	testing.expect(t, !p.found)
	testing.expect_value(t, p.kernel_st, dco.ENO_OVPN)
	testing.expect(t, !p.tried_service)
	testing.expect_value(t, len(probe.order), 1)

	// udco: the service only.
	clear(&probe.order)
	p = dco_pick(&l, .Udco, "/s", 0)
	testing.expect(t, p.found && p.kind == .Service)
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, probe.order[0], dco.Backend_Kind.Service)

	// auto: the kernel first, then the service, then nothing.
	probe.kernel_st = 0
	clear(&probe.order)
	p = dco_pick(&l, .Auto, "/s", 0)
	testing.expect(t, p.found && p.kind == .Kernel)
	testing.expect_value(t, len(probe.order), 1)

	probe.kernel_st = dco.ENO_OVPN
	clear(&probe.order)
	p = dco_pick(&l, .Auto, "/s", 0)
	testing.expect(t, p.found && p.kind == .Service)
	testing.expect_value(t, len(probe.order), 2)
	testing.expect_value(t, probe.order[0], dco.Backend_Kind.Kernel)
	testing.expect_value(t, probe.order[1], dco.Backend_Kind.Service)

	probe.service_st = dco.ENOENT
	clear(&probe.order)
	p = dco_pick(&l, .Auto, "/s", 0)
	testing.expect(t, !p.found)
	testing.expect_value(t, p.kernel_st, dco.ENO_OVPN)
	testing.expect_value(t, p.service_st, dco.ENOENT)
	testing.expect_value(t, len(probe.order), 2)
}

@(test)
test_dco_connect_text :: proc(t: ^testing.T) {
	testing.expect_value(t, dco_connect_text(.Kernel, dco.ENO_OVPN), "the kernel has no ovpn module")
	testing.expect_value(t, dco_connect_text(.Kernel, dco.EINVAL), "EINVAL")
	testing.expect_value(t, dco_connect_text(.Service, dco.ENO_OVPN), dco_status_text(dco.ENO_OVPN))
	testing.expect_value(t, dco_who(.Kernel), "the kernel ovpn driver")
	testing.expect_value(t, dco_who(.Service), "the DCO service")
	testing.expect_value(t, dco_datapath_name(.Kernel), "dco")
	testing.expect_value(t, dco_datapath_name(.Service), "udco")
	testing.expect_value(t, dco_path_of(.Kernel), Dco_Path.Dco)
	testing.expect_value(t, dco_path_of(.Service), Dco_Path.Udco)
}

@(test)
test_dco_why_adds_the_kernels_words :: proc(t: ^testing.T) {
	probe_begin(0, 0)
	defer probe_end()
	l: Dco_Link
	testing.expect_value(t, engine.dco_connect_hook(&l, .Kernel, ""), 0)
	testing.expect_value(t, dco_why(&l, dco.EEXIST), "EEXIST")
	probe.kbe.etext = "a device with this name exists and is not an ovpn device"
	testing.expect_value(t, dco_why(&l, dco.EEXIST), "EEXIST (a device with this name exists and is not an ovpn device)")
	// A backend without err_text (the service) gives the status only.
	l.be.err_text = nil
	testing.expect_value(t, dco_why(&l, dco.EEXIST), "EEXIST")

	// The owner keeps the words of its first failure.
	r: Rig
	rig_init(&r)
	defer rig_free(&r)
	r.be.fail["NEW_PEER"] = dco.EINVAL
	r.be.etext = "unsupported cipher"
	r.link.be.err_text = proc(user: rawptr) -> string {
		return (^Fake_Be)(user).etext
	}
	p := dco.New_Peer {
		peer_id = 3,
		flags   = dco.PEER_REMOTE,
	}
	st := dco_peer_create(&r.o, &p, 5)
	testing.expect_value(t, st, dco.EINVAL)
	dco_fail(&r.o, "KEY_NEW", dco.EINVAL)
	testing.expect_value(t, dco_err_text(&r.o), "EINVAL (unsupported cipher)")
}

@(test)
test_dco_classify_device_gone :: proc(t: ^testing.T) {
	ev := dco.Event {
		kind   = .Peer_Del,
		reason = .Teardown,
	}
	// The kernel ends every peer with "teardown" when its device is deleted.
	testing.expect_value(t, dco_classify(&ev, .Kernel), Dco_Act.Device_Gone)
	// The service never reports it that way: it stays what it was.
	testing.expect_value(t, dco_classify(&ev, .Service), Dco_Act.None)
	testing.expect_value(t, dco_classify(&ev), Dco_Act.None)
	// What we deleted ourselves is "userspace" and no news.
	ev.reason = .Userspace
	testing.expect_value(t, dco_classify(&ev, .Kernel), Dco_Act.None)
	ev.reason = .Expired
	testing.expect_value(t, dco_classify(&ev, .Kernel), Dco_Act.Expired)
}

// The kernel has two key slots: a swap with an empty secondary slot leaves the
// peer without a sending key. Over many rekeys no SWAP_KEYS may come before the
// key it activates is in the secondary slot, and every swap needs one.
@(test)
test_dco_kernel_never_swaps_an_empty_slot :: proc(t: ^testing.T) {
	r: Rig
	rig_init(&r) // no CAP_KEY_TABLE: the two slots, as the kernel backend
	defer rig_free(&r)
	install(&r, 0, 10)
	testing.expect_value(t, new_peer(&r, 9), 0)
	ids := []u8{1, 2, 3, 4, 5, 6, 7, 1, 2, 3}
	for id in ids {
		r.now += 100 * time.Second
		kind(&r, .Rekey_Started)
		n := len(r.be.calls)
		install(&r, id, 40 + id)
		// In each batch the new key goes into the secondary slot before a swap.
		put := false
		for c in r.be.calls[n:] {
			if c.what == "NEW_KEY" && c.slot == u32(dco.Key_Slot.Secondary) {
				put = true
			}
			if c.what == "SWAP_KEYS" {
				testing.expect(t, put, "SWAP_KEYS before the secondary slot has the new key")
			}
		}
		testing.expect(t, put)
	}
	testing.expect_value(t, r.o.err, 0)
	// The key that sends is always one the owner put in a slot.
	testing.expect(t, r.o.held[0] >= 0)
}

@(test)
test_dco_attempt_kernel_down_and_back :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Dco)
	d.dco.kind = .Kernel
	dial_status = dco.ENO_OVPN
	// The module is not there: the attempt runs here, each attempt asks again.
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, d.dco.lost)
	testing.expect(t, !dco_for_attempt(&d, .Tcp, false))
	testing.expect_value(t, dial_calls, 2)
	// The module is loaded: the attempt uses the kernel (UDP and TCP), the state is over.
	dial_status = 0
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	testing.expect(t, !d.dco.lost)
	testing.expect(t, dco_for_attempt(&d, .Tcp, false))
	// A tls remote always runs here.
	testing.expect(t, !dco_for_attempt(&d, .Tcp, true))
	testing.expect_value(t, dco_mode_name(&d), "dco")
}

@(test)
test_dco_kernel_setup_failure_is_dco_failed :: proc(t: ^testing.T) {
	cfg: config.Client_Config
	d: Daemon
	choice_init(&d, &cfg, .Dco)
	d.dco.kind = .Kernel
	dial_status = 0
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
	d.dco.path = .Dco
	outcome := close_outcome(.Datapath)
	testing.expect_value(t, outcome, client.Outcome.Datapath_Failed)
	testing.expect_value(t, state_reason(outcome, .None, .Ok, true), "dco_failed")
	testing.expect_value(t, state_reason(.Local_Stop, .Datapath, .Ok, true), "dco_failed")
	testing.expect_value(t, state_reason(outcome, .None, .Ok), "udco_failed")
	testing.expect_value(t, state_reason(outcome, .None, .Ok, false), "udco_failed")
	dco_attempt_ended(&d, outcome)
	testing.expect(t, d.dco.skip)
	// The next attempt runs in this process at once, the one after it tries the kernel again.
	testing.expect(t, !dco_for_attempt(&d, .Udp, false))
	testing.expect(t, dco_for_attempt(&d, .Udp, false))
}

@(test)
test_client_state_datapath_dco :: proc(t: ^testing.T) {
	d: Daemon
	w: bus.Writer
	bus.writer_init(&w)
	defer bus.writer_destroy(&w)
	d.stats.attempts = 1
	d.dco.path = .Dco
	bus.begin_obj(&w)
	client_state_write(&w, &d, "handshake", "connecting", "")
	text := bus.writer_string(&w)
	testing.expect(t, strings.contains(text, `"datapath":"dco"`), text)
	name, ok := client_datapath(&d)
	testing.expect(t, ok)
	testing.expect_value(t, name, "dco")
}

@(test)
test_client_mss_line :: proc(t: ^testing.T) {
	d: Daemon
	d.mss4 = 1360
	// This process clamps.
	testing.expect_value(t, client_mss_line(&d), "1360 (IPv6 1340)")
	// The kernel does not: the line says so, unless mssfix is off.
	d.dco.active = true
	d.dco.link.be.mss_clamp = false
	testing.expect_value(t, client_mss_line(&d), MSS_NOT_APPLIED)
	testing.expect_value(t, MSS_NOT_APPLIED, "not applied (the kernel data path does not clamp)")
	d.mss4 = 0
	testing.expect_value(t, client_mss_line(&d), "off")
	// The service clamps.
	d.mss4 = 1360
	d.dco.link.be.mss_clamp = true
	testing.expect_value(t, client_mss_line(&d), "1360 (IPv6 1340)")
}

// -------------------------------------------------------------- the server

@(test)
test_srv_dco_init_kernel :: proc(t: ^testing.T) {
	listens := []config.Listen{{port = 1194, proto = .Udp}}
	cfg: config.Server_Config
	cfg.listens = listens
	cfg.dco_socket = "/nonexistent/dco.sock"
	cfg.dev = "nvk1"

	// `dco` with the module: the kernel creates the MP device, the server runs on it.
	probe_begin(0, 0)
	defer probe_end()
	d: Srv
	d.cfg = &cfg
	d.dco.no_watch = true
	cfg.datapath = .Dco
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, d.dco.on)
	testing.expect_value(t, d.dco.kind, dco.Backend_Kind.Kernel)
	testing.expect_value(t, d.ifindex, u32(7))
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, bus_dp(&d), "dco")
	testing.expect(t, !d.dco.early) // the kernel has no CAP_PEER_ID: TCP goes over at the login

	// `dco` without the module: a warning, and the run is in this process.
	probe_end()
	probe_begin(dco.ENO_OVPN, 0)
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)
	testing.expect_value(t, len(probe.order), 1)
	testing.expect_value(t, bus_dp(&d), "userspace")

	// The kernel cannot create the device (another kind of device has the name): the same.
	probe_end()
	probe_begin(0, 0)
	probe.kbe.fail["OPEN"] = dco.EEXIST
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on && !d.dco.link.up)

	// `auto`: the kernel if it is there, else the service, else this process.
	probe_end()
	probe_begin(0, 0)
	cfg.datapath = .Auto
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, d.dco.on)
	testing.expect_value(t, d.dco.kind, dco.Backend_Kind.Kernel)
	testing.expect_value(t, len(probe.order), 1)

	probe_end()
	probe_begin(dco.ENO_OVPN, 0)
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, d.dco.on)
	testing.expect_value(t, d.dco.kind, dco.Backend_Kind.Service)
	testing.expect_value(t, len(probe.order), 2)
	testing.expect_value(t, bus_dp(&d), "udco")

	probe_end()
	probe_begin(dco.ENO_OVPN, dco.ENOENT)
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on)

	// Two listeners: `dco` is a config error, `auto` runs here and asks nobody.
	probe_end()
	probe_begin(0, 0)
	two := []config.Listen{{port = 1194, proto = .Udp}, {port = 1195, proto = .Udp}}
	cfg.listens = two
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	testing.expect(t, srv_dco_init(&d))
	testing.expect(t, !d.dco.on)
	d = {}
	d.cfg = &cfg
	d.dco.no_watch = true
	cfg.datapath = .Dco
	testing.expect(t, !srv_dco_init(&d))
	testing.expect_value(t, d.exit_code, Exit.Config)
	testing.expect_value(t, len(probe.order), 0)
}

// The `datapath` of the status for a server, without the global state.
bus_dp :: proc(d: ^Srv) -> string {
	return dco_datapath_name(d.dco.kind) if d.dco.on else "userspace"
}

@(test)
test_srv_dco_stats_interval_for_the_kernel :: proc(t: ^testing.T) {
	testing.expect(t, DCO_STATS_KERNEL < DCO_STATS_SLOW)
	testing.expect(t, DCO_STATS_KERNEL >= DCO_STATS_FAST)
}
