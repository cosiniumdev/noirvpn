// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package engine

import "noir:client"
import "noir:platform/sysnet"

// Clean-up record of the daemon (client/record.odin). Client and server record
// what they change on the system; the clean-up at start reverts only records of
// dead daemons.
//
//	daemon_init / srv_init -> bus_prepare_dirs  the socket folder first
//	                       -> rec_start         open the record, clean up
//	apply_network          -> client_rec_sync   with the plan, then without it
//	teardown_network       -> client_rec_sync
//	daemon_destroy         -> client_rec_end
//
// No usable state folder: the daemon runs without clean-up at start (it cannot
// tell live routes from dead ones).

// Opens the record and runs the clean-up at start. `dns_hint` is the interface
// name whose DNS leftovers of an older version go ("" for none).
rec_start :: proc(f: ^client.Record_File, conn: ^sysnet.Conn, env: sysnet.DNS_Env, name: string, role: client.Record_Role, dns_hint: string) {
	dir := client.record_default_dir()
	if err := client.record_open(f, dir, name, role); err != .None {
		logf(.Warn, "cannot use the state folder %s (%v), so there will be no clean-up at start and no record of this run", dir, err)
		return
	}
	rep := client.record_cleanup(f, conn, env, dns_hint)
	if rep.err != .None {
		logf(.Warn, "clean-up at start: cannot remove the old routes: %v", rep.err)
	}
	if rep.dns_err != .None {
		logf(.Warn, "clean-up at start: cannot restore the old DNS settings: %v", rep.dns_err)
	}
	if rep.bad_records > 0 {
		logf(.Warn, "clean-up at start: %d record(s) in %s cannot be used", rep.bad_records, dir)
	}
	if rep.live_unknown {
		logf(.Warn, "clean-up at start: the record of a running daemon cannot be read, so routes that are not in any record will be kept")
	}
	if text := client.cleanup_report_text(rep); text != "" {
		logf(.Warn, "%s", text)
	}
}

// Writes the record. A failure is a warning: the tunnel works, but a crash
// of this run leaves its changes for a later clean-up by hand.
rec_save :: proc(f: ^client.Record_File) {
	if err := client.record_write(f); err != .None {
		logf(.Warn, "cannot write the clean-up record: %v", err)
	}
}

// Ends the record. It goes if it holds no route or DNS change, else it stays for
// the next start (the lock ends with the process). A daemon that gave up root
// cannot remove it and leaves it empty.
rec_end :: proc(f: ^client.Record_File) {
	if !f.ok {
		return
	}
	if len(f.rec.routes) == 0 && len(f.rec.dns) == 0 {
		if !client.record_close(f) {
			logf(.Info, "the record of this run cannot be removed from the state folder (the daemon runs without root), so it is left empty and the next start will remove it")
		}
	} else {
		logf(.Warn, "the network changes of this run are still in place, and the next start will remove them")
		client.record_release(f)
	}
}

// Client record: its device, the routes of `d.nc`, the DNS change. With
// `pending`, also the routes and DNS of the plan about to run.
client_rec_sync :: proc(d: ^Daemon, pending: ^client.Plan = nil) {
	f := &d.rec
	if !f.ok {
		return
	}
	client.record_clear(&f.rec)
	if d.nc_ok {
		client.record_add_dev(&f.rec, d.ifindex, tun_name(d))
		client.record_add_netcfg(&f.rec, &d.nc)
	}
	if pending != nil {
		client.record_add_plan(&f.rec, pending, &d.sys, d.ifindex)
	}
	if d.dns.active {
		b := d.dns.backend
		client.record_add_dns(&f.rec, sysnet.dns_backend_name(b), d.dns.ifname, sysnet.dns_record_detail(d.dns_env, b, d.dns.ifname))
	}
	if pending != nil && pending.has_dns && d.nc_ok {
		b := sysnet.dns_detect(d.dns_env)
		name := tun_name(d)
		client.record_add_dns(&f.rec, sysnet.dns_backend_name(b), name, sysnet.dns_record_detail(d.dns_env, b, name))
	}
	rec_save(f)
}

client_rec_end :: proc(d: ^Daemon) {
	client_rec_sync(d)
	rec_end(&d.rec)
}
