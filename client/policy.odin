// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package client

import "core:mem"
import cnet "core:net"
import "core:time"
import "noir:proto/config"

// What happened to a connection attempt. The daemon maps session events to
// these, reports one with `policy_outcome`, then asks `policy_next` what to do.
//
// Mapping from session events:
//
//	session reached PUSH_REPLY and the options were applied   .Connected
//	TCP connect refused / unreachable, UDP send error         .Connect_Failed
//	no server reply, or no PUSH_REPLY, within the timeout     .Handshake_Timeout
//	TLS alert, certificate or pin refused, bad wrap key       .Handshake_Failed
//	PUSH_REPLY failed validation (net30, cipher, topology)    .Push_Rejected
//	AUTH_FAILED, AUTH_FAILED,reason, AUTH_FAILED,SESSION      .Auth_Failed
//	  (SESSION: first retry with stored credentials inside the session layer;
//	   report .Auth_Failed only if that fails too)
//	AUTH_FAILED,TEMP[...]                                     .Auth_Failed_Temp
//	RESTART[,flags]                                           .Server_Restart
//	HALT[,flags]                                              .Server_Halt
//	ping-restart timer, or a renegotiation that never ended   .Ping_Restart
//	EXIT from the server                                      .Remote_Exit
//	`inactive` limit reached                                  .Inactive
//	`session-timeout` reached                                 .Session_Timeout
//	stop requested by the user (signal, bus `disconnect`)     .Local_Stop
//	reconnect requested by the user (bus `connect`)           .Local_Restart
//	the DCO service failed the setup of the data path         .Datapath_Failed
Outcome :: enum u8 {
	// The tunnel is up. Resets the back-off and every try counter.
	Connected,
	Connect_Failed,
	Handshake_Timeout,
	Handshake_Failed,
	Push_Rejected,
	// Stops the client unless `auth-retry` is `nointeract` or `interact`.
	Auth_Failed,
	Auth_Failed_Temp,
	Server_Restart,
	// Stops the client.
	Server_Halt,
	Ping_Restart,
	Remote_Exit,
	// These three stop the client.
	Inactive,
	Session_Timeout,
	Local_Stop,
	// Reconnect at once to the same server.
	Local_Restart,
	// The userspace DCO service could not set up the data path. Same as
	// `Local_Restart`: the next attempt follows at once, on the same server, and
	// does not count as a failed try (the daemon runs it with the data path in
	// its own process).
	Datapath_Failed,
}

// Which remote or address to try after a failure.
Advance :: enum u8 {
	// Not given: the rule of the outcome applies.
	Default,
	// Stay on the same remote and address.
	No,
	// The next address of the same remote; after the last one, the next remote.
	Addr,
	// The next remote.
	Remote,
}

// Details that come with some outcomes.
Outcome_Info :: struct {
	// `.Auth_Failed_Temp`: `backoff <n>` seconds, 0 if not given.
	backoff_secs: int,
	// `.Auth_Failed_Temp`: the `advance` flag.
	advance:      Advance,
	// `.Server_Restart`: the `[N]` flag.
	next_remote:  bool,
}

Stop_Reason :: enum u8 {
	None,
	// AUTH_FAILED and `auth-retry none`.
	Auth_Failed,
	// HALT from the server.
	Halted,
	// `connect-retry-max` tries used up on every remote.
	Retries_Exhausted,
	// `resolv-retry` time used up on every remote.
	Resolve_Failed,
	Inactive,
	Session_Timeout,
	Local_Stop,
	// The remote list is empty (nothing matches `proto-force`).
	No_Remote,
}

Action_Kind :: enum u8 {
	// Look up `host` (family filter in `family`) and report with `policy_resolved`.
	// Through an HTTP proxy `host` and `port` are the proxy's (`via_proxy`).
	Resolve,
	// Start a connection to `endpoint`. Arm a timer for `attempt_timeout`.
	// If it fires first, report `.Handshake_Timeout`. Report `.Connected` when
	// the tunnel is up, or the failure.
	Connect,
	// Nothing to do until `wake_at`. Call `policy_next` again then.
	Wait,
	// Give up. The reason is in `stop`.
	Stop,
}

Action :: struct {
	kind:            Action_Kind,
	// Index into `cfg.connections` of the remote in use. Its `Link_Settings`
	// (proto, ports, local address, wrap, ...) are the settings for this attempt.
	entry:           int,
	// Resolve:
	host:            string,
	family:          config.Family,
	// Resolve and Connect:
	port:            u16,
	proto:           config.Proto,
	// The remote is reached through its HTTP proxy (`cfg.connections[entry].proxy`).
	// `host`, `port` and `endpoint` are the proxy's. The remote's own name and
	// port go to the proxy in the CONNECT request.
	via_proxy:       bool,
	// Connect:
	endpoint:        cnet.Endpoint,
	attempt_timeout: time.Duration, // 0: no limit
	// Wait: an absolute time on the same clock as the `now` you pass in.
	wake_at:         time.Duration,
	// Stop:
	stop:            Stop_Reason,
}

@(private)
Phase :: enum u8 {
	Resolve,
	Connect,
	Stopped,
}

@(private)
Entry_State :: struct {
	// Failed attempts since the last success. Drives the back-off.
	fails:      int,
	// Passes over this remote since the last success. Compared with
	// `connect-retry-max`.
	tries:      int,
	// `resolv-retry` ran out: the remote is skipped until the next success.
	dead:       bool,
	// When the current run of failed look-ups started.
	resolve_t0: Maybe(time.Duration),
	// The addresses of the last look-up that worked, in its order. A failed
	// look-up uses them. A success of the connection does not clear them.
	known:      [KNOWN_ADDRS]cnet.Address,
	known_n:    int,
}

// How many addresses of a name the policy keeps for a failed look-up.
KNOWN_ADDRS :: 8

// Reconnect state machine. No I/O, no clock: calls that need time take `now`
// (any monotonic `time.Duration`, e.g. `time.tick_now()._nsec`). Not thread safe.
// Rules:
//   - Remotes are tried in list order (shuffled once by `remote-random`). All
//     addresses of a name are tried before the next remote.
//   - After a failed attempt the next waits `connect-retry` seconds, growing
//     (see `backoff_seconds`). A success resets everything.
//   - `connect-retry-max` counts passes over one remote. When every remote has
//     used its tries, the policy stops.
//   - `resolv-retry` limits how long look-up failures of one remote are
//     retried. `infinite` (default) never gives up.
//   - If a look-up fails for a name that resolved before, use the old addresses.
//     Reason: with `persist-tun` the name servers may be reachable only through
//     the tunnel, which is down during reconnect.
Policy :: struct {
	cfg:        ^config.Client_Config,
	allocator:  mem.Allocator,
	// Indices into cfg.connections in try order.
	order:      []int,
	state:      []Entry_State, // by index into cfg.connections
	// Position in `order`.
	pos:        int,
	phase:      Phase,
	addrs:      [dynamic]cnet.Address,
	addr_idx:   int,
	wait_until: time.Duration,
	stop:       Stop_Reason,
	// Set by `.Connected`, cleared by the next failure.
	connected:  bool,
	// When the tunnel came up (valid while `up_known`), for the EXIT back-off.
	up_at:      time.Duration,
	up_known:   bool,
	// EXIT notices that ended a short session (or a try that never came up) in a
	// row. Not reset by `.Connected`: a loop of replaced sessions connects each time.
	exit_runs:  int,
	// Temporary refusals (AUTH_FAILED,TEMP) in a row. Reset by a success.
	temp_runs:  int,
}

// `cfg` must outlive the policy. `seed` only matters with `remote-random`.
policy_init :: proc(
	p: ^Policy,
	cfg: ^config.Client_Config,
	seed: u64,
	allocator := context.allocator,
) -> mem.Allocator_Error {
	p^ = {}
	p.cfg = cfg
	p.allocator = allocator
	p.order = remote_order(cfg, seed, allocator) or_return
	p.state = make([]Entry_State, len(cfg.connections), allocator) or_return
	p.addrs = make([dynamic]cnet.Address, 0, 4, allocator)
	p.phase = .Resolve
	if len(p.order) == 0 {
		p.phase = .Stopped
		p.stop = .No_Remote
	}
	return nil
}

policy_destroy :: proc(p: ^Policy) {
	delete(p.order, p.allocator)
	delete(p.state, p.allocator)
	delete(p.addrs)
	p^ = {}
}

// Set a stopped (or running) policy ready for a new run of attempts.
// - Clears the counters, the back-off and the stop reason. The first remote is
//   next.
// - Keeps the addresses of the last good look-up, so a name that cannot be
//   resolved now still has them.
policy_rearm :: proc(p: ^Policy) {
	reset_counters(p)
	clear(&p.addrs)
	p.addr_idx = 0
	p.pos = 0
	p.wait_until = 0
	p.stop = .None
	p.connected = false
	p.phase = .Resolve
	if len(p.order) == 0 {
		p.phase = .Stopped
		p.stop = .No_Remote
	}
}

// The remote the policy is on (valid unless stopped for `.No_Remote`).
policy_entry :: proc(p: ^Policy) -> int {
	return p.order[p.pos] if len(p.order) > 0 else 0
}

// Why the policy stopped, if it did.
policy_stopped :: proc(p: ^Policy) -> (reason: Stop_Reason, stopped: bool) {
	return p.stop, p.phase == .Stopped
}

// What to do now. Calling it again without reporting anything returns the
// same action, so it is safe to call from a timer.
policy_next :: proc(p: ^Policy, now: time.Duration) -> Action {
	if p.phase == .Stopped {
		return Action{kind = .Stop, stop = p.stop}
	}
	e := policy_entry(p)
	conn := &p.cfg.connections[e]
	if now < p.wait_until {
		return Action{kind = .Wait, entry = e, wake_at = p.wait_until}
	}
	a := Action {
		entry  = e,
		host   = conn.host,
		family = conn.family,
		port   = conn.rport,
		proto  = conn.proto,
	}
	if px, ok := conn.proxy.?; ok {
		a.host, a.port, a.via_proxy = px.host, px.port, true
	}
	switch p.phase {
	case .Resolve:
		a.kind = .Resolve
	case .Connect:
		a.kind = .Connect
		a.endpoint = cnet.Endpoint {
			address = p.addrs[p.addr_idx],
			port    = int(a.port),
		}
		a.attempt_timeout = time.Duration(conn.connect_timeout) * time.Second
	case .Stopped:
	}
	return a
}

// The result of a `.Resolve` action.
//   addrs - the addresses in the order to try. Addresses of the wrong family
//           for the remote (`udp4`, `tcp6`, ...) are dropped.
//   ok    - false, or an empty `addrs`, is a failed look-up.
//   kept  - true if the look-up failed and the policy goes on with the
//           addresses of the last look-up that worked.
policy_resolved :: proc(p: ^Policy, addrs: []cnet.Address, ok: bool, now: time.Duration) -> (kept: bool) {
	if p.phase != .Resolve {
		return false
	}
	e := policy_entry(p)
	conn := &p.cfg.connections[e]
	clear(&p.addrs)
	if ok {
		for a in addrs {
			if family_allowed(conn.family, a) {
				append(&p.addrs, a)
			}
		}
	}
	st := &p.state[e]
	if len(p.addrs) > 0 {
		st.known_n = min(len(p.addrs), KNOWN_ADDRS)
		copy(st.known[:], p.addrs[:st.known_n])
	} else if st.known_n > 0 {
		append(&p.addrs, ..st.known[:st.known_n])
		kept = true
	}
	if len(p.addrs) > 0 {
		st.resolve_t0 = nil
		p.addr_idx = 0
		p.phase = .Connect
		return kept
	}

	// A failed look-up. Count it as a failed attempt on this remote.
	if st.resolve_t0 == nil {
		st.resolve_t0 = now
	}
	t0, _ := st.resolve_t0.?
	if p.cfg.resolv_retry >= 0 && now - t0 >= time.Duration(p.cfg.resolv_retry) * time.Second {
		st.dead = true
	}
	st.fails += 1
	p.wait_until = now + wait_for(conn, st.fails)
	p.connected = false
	move_to_next_entry(p, true)
	return false
}

@(private)
family_allowed :: proc "contextless" (f: config.Family, a: cnet.Address) -> bool {
	_, is_v6 := a.(cnet.IP6_Address)
	switch f {
	case .Any:
		return true
	case .V4:
		return !is_v6
	case .V6:
		return is_v6
	}
	return true
}

@(private)
wait_for :: proc(conn: ^config.Connection, fails: int) -> time.Duration {
	return time.Duration(backoff_seconds(conn.connect_retry, conn.connect_retry_max_wait, fails)) * time.Second
}

// True while the remote may still be tried.
@(private)
entry_live :: proc(p: ^Policy, e: int) -> bool {
	st := &p.state[e]
	if st.dead {
		return false
	}
	max_tries := p.cfg.connections[e].connect_retry_max
	return max_tries <= 0 || st.tries < max_tries
}

// Leave the current remote for the next live one (the same one again if it is
// the only one left). `count_try` adds a try to the remote that is left.
@(private)
move_to_next_entry :: proc(p: ^Policy, count_try: bool) {
	e := policy_entry(p)
	if count_try {
		p.state[e].tries += 1
	}
	p.phase = .Resolve
	clear(&p.addrs)
	p.addr_idx = 0
	settle(p, 1)
}

// Put `pos` on a live remote, starting `step` places on (0: the current one
// is checked first). Stops the policy if no remote is live.
@(private)
settle :: proc(p: ^Policy, step: int) {
	n := len(p.order)
	pos := (p.pos + step) % n
	for _ in 0 ..< n {
		if entry_live(p, p.order[pos]) {
			if pos != p.pos {
				p.phase = .Resolve
				clear(&p.addrs)
				p.addr_idx = 0
			}
			p.pos = pos
			return
		}
		pos = (pos + 1) % n
	}
	p.phase = .Stopped
	any_dead := false
	any_tries := false
	for e in p.order {
		if p.state[e].dead {
			any_dead = true
		} else {
			any_tries = true
		}
	}
	p.stop = .Resolve_Failed if any_dead && !any_tries else .Retries_Exhausted
}

// Report how the attempt went. Call `policy_next` afterwards.
policy_outcome :: proc(p: ^Policy, outcome: Outcome, now: time.Duration, info: Outcome_Info = {}) {
	if p.phase == .Stopped {
		return
	}
	// The time the tunnel came up belongs to the session that ends now.
	up_known, up_at := p.up_known, p.up_at
	if outcome != .Connected {
		p.up_known = false
	}
	switch outcome {
	case .Local_Stop:
		stop_with(p, .Local_Stop)
	case .Inactive:
		stop_with(p, .Inactive)
	case .Session_Timeout:
		stop_with(p, .Session_Timeout)
	case .Server_Halt:
		stop_with(p, .Halted)
	case .Connected:
		if p.phase == .Connect {
			reset_counters(p)
			p.connected = true
			p.up_at, p.up_known = now, true
		}
	case .Auth_Failed:
		if p.cfg.auth_retry == .None {
			stop_with(p, .Auth_Failed)
		} else {
			failed(p, .No, 0, now)
		}
	case .Auth_Failed_Temp:
		// `advance` not given: next address, as for any other failure. The wait
		// grows with each refusal in a row; the server hint is a floor.
		p.temp_runs += 1
		failed(p, .Addr if info.advance == .Default else info.advance, info.backoff_secs, now, p.temp_runs)
	case .Connect_Failed, .Handshake_Timeout, .Handshake_Failed, .Push_Rejected, .Ping_Restart:
		failed(p, .Addr, 0, now)
	case .Server_Restart:
		// The server said it is going away: not a failure, so no growth in the
		// back-off. The base wait applies.
		advance := Advance.Remote if info.next_remote else Advance.No
		conn := &p.cfg.connections[policy_entry(p)]
		p.wait_until = now + time.Duration(max(conn.connect_retry, 0)) * time.Second
		p.connected = false
		step(p, advance, false)
	case .Remote_Exit:
		// EXIT ends the session for good (for example, a login with the same key
		// replaced it). This is no failure of the remote, but a client that keeps
		// being ended must not loop at once: a short session lets the wait grow,
		// a long one resets it.
		conn := &p.cfg.connections[policy_entry(p)]
		long := up_known && now - up_at >= EXIT_LONG_SESSION
		p.exit_runs = 0 if long else p.exit_runs + 1
		wait := time.Duration(max(conn.connect_retry, 0)) * time.Second
		if !long {
			wait = max(wait, exit_backoff(p.exit_runs))
		}
		p.wait_until = now + wait
		p.connected = false
		step(p, .No, false)
	case .Local_Restart, .Datapath_Failed:
		p.wait_until = now
		p.connected = false
		step(p, .No, false)
	}
}

// A session this long resets the wait after an EXIT.
EXIT_LONG_SESSION :: 60 * time.Second
EXIT_WAIT_FIRST :: 5 * time.Second
EXIT_WAIT_MAX :: 60 * time.Second

// The wait after the `runs`-th EXIT in a row that ended a short session
// (counting from 1): 5 s, doubling, up to 60 s.
exit_backoff :: proc "contextless" (runs: int) -> time.Duration {
	w := EXIT_WAIT_FIRST
	for _ in 1 ..< runs {
		w *= 2
		if w >= EXIT_WAIT_MAX {
			return EXIT_WAIT_MAX
		}
	}
	return w
}

// The wait after the `runs`-th temporary refusal in a row (counting from 1):
// 2 s, doubling, up to 60 s. A hint of the server is the floor.
TEMP_WAIT_FIRST :: 2 * time.Second
TEMP_WAIT_MAX :: 60 * time.Second
TEMP_HINT_MAX_SECS :: 3600

temp_backoff :: proc "contextless" (runs: int) -> time.Duration {
	w := TEMP_WAIT_FIRST
	for _ in 1 ..< runs {
		w *= 2
		if w >= TEMP_WAIT_MAX {
			return TEMP_WAIT_MAX
		}
	}
	return w
}

@(private)
stop_with :: proc(p: ^Policy, reason: Stop_Reason) {
	p.phase = .Stopped
	p.stop = reason
}

@(private)
reset_counters :: proc(p: ^Policy) {
	p.temp_runs = 0
	for &st in p.state {
		st = {
			known   = st.known,
			known_n = st.known_n,
		}
	}
}

// A failed attempt on the current remote. `wait_secs` > 0 is a floor for the
// computed wait (`AUTH_FAILED,TEMP[backoff N]`).
@(private)
failed :: proc(p: ^Policy, advance: Advance, wait_secs: int, now: time.Duration, temp_runs := 0) {
	if p.phase != .Connect {
		return
	}
	e := policy_entry(p)
	conn := &p.cfg.connections[e]
	st := &p.state[e]
	st.fails += 1
	wait := wait_for(conn, st.fails)
	if temp_runs > 0 {
		wait = max(wait, temp_backoff(temp_runs))
	}
	if wait_secs > 0 {
		wait = max(wait, time.Duration(min(wait_secs, TEMP_HINT_MAX_SECS)) * time.Second)
	}
	p.wait_until = now + wait
	p.connected = false
	step(p, advance, true)
}

// Move the cursor. `count` adds a try to the remote that is left (or retried).
@(private)
step :: proc(p: ^Policy, advance: Advance, count: bool) {
	if p.phase != .Connect {
		return
	}
	e := policy_entry(p)
	switch advance {
	case .Default, .No:
		if count {
			p.state[e].tries += 1
		}
		// A stay keeps the resolved addresses. If the remote has no tries
		// left, settle moves on.
		settle(p, 0)
	case .Addr:
		if p.addr_idx + 1 < len(p.addrs) {
			p.addr_idx += 1
			return
		}
		move_to_next_entry(p, count)
	case .Remote:
		move_to_next_entry(p, count)
	}
}
