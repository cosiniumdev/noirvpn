# platform/event

A single-thread event loop for noirvpn: file descriptor readiness and timers,
one blocking call (`wait`). Linux uses epoll (`event_linux.odin`) and Windows
uses wait handles (`event_windows.odin`, see "Windows" below). macOS uses
kqueue (`event_darwin.odin`, see "macOS" below). They share `event.odin` (types
and the timer heap).

```odin
loop: event.Loop
event.init(&loop)
defer event.destroy(&loop)

event.add_fd(&loop, i32(sock), {.Read}, on_readable, &state)
event.timer_add(&loop, 10 * time.Second, on_keepalive, &state, interval = 10 * time.Second)

for {
	event.wait(&loop, engine_next_deadline)   // or event.run(&loop) until event.stop
}
```

## API

| Call | Meaning |
|------|---------|
| `init`, `destroy` | Create and free a loop (an epoll fd and an eventfd). |
| `add_fd`, `modify_fd`, `remove_fd` | Watch a descriptor for `{.Read, .Write, .Edge}`. Errors and hangups are always reported. |
| `timer_add(delay)`, `timer_add_at(deadline)` | Arm a timer, one-shot or repeating. Returns a `Timer_Id`. |
| `timer_cancel`, `timer_reset`, `timer_reset_at`, `timer_next` | Cancel, move (no allocation), or read the earliest deadline. |
| `wait(until)` | Block until a descriptor is ready, a timer is due, `until` passes, `wake`, or a signal. Then run handlers. |
| `run`, `stop` | Loop on `wait` until `stop`. |
| `wake`, `stop` | Safe from other threads. All other calls belong to the loop's thread. |
| `now()` | The monotonic clock as a `time.Duration`. Same value in every thread. |

`wait(until)` is the hook for the sans-I/O protocol engine: it returns "next
deadline" values on the `now()` clock, and the client loop passes the smallest
one as `until`. The loop's own timers are included automatically.

## Decision: epoll directly, not core:nbio

core:nbio was evaluated on Odin `dev-2026-11-nightly` (`core/nbio`,
`impl_linux.odin`). It is not used, for these reasons:

1. **It is io_uring only on Linux, and io_uring is often not there.** In the
   rootless podman container we use for musl builds (default seccomp profile),
   `nbio.acquire_thread_event_loop()` returns `Unsupported`; the same code works
   on the dev machine. We checked this only with podman. Other container
   runtimes, hardened kernels (`kernel.io_uring_disabled`) and Android's app
   filter are also known to block io_uring, but we did not test them. The
   client must run there.
2. **It is completion based and one operation per packet.** The data path
   wants `recvmmsg`/`sendmmsg` batches, UDP GSO/GRO control messages and a tun
   `read` that returns one packet. nbio exposes `recvmsg` per operation, with a
   pooled `Operation` object and a callback for each packet. That is more
   work per packet than one `recvmmsg` call for 32 packets.
3. **Callbacks run with the loop caller's context and operations are pooled
   and allocated by the library.** Our rule is no allocation on the data
   path and a fixed packet pool per worker. With readiness events we keep
   buffers and state in our own structs, and the handler is a plain
   procedure on a registered descriptor.
4. **Timers.** nbio timeouts are "intentionally slightly inaccurate" and
   cannot be moved cheaply. We need cancel and reset of a timer per packet
   (keepalive) without allocation. Our heap does that in O(log n).
5. **Other fds.** tun, netlink and eventfd are plain readiness sources in
   epoll. In nbio they need positional read operations (an offset on a
   non-seekable file) or poll operations.

What we lose: nbio is already cross-platform (kqueue on macOS, IOCP on
Windows). We accept that: the macOS version is one more small file, and the
Windows version is one more file of readiness events (below).

Revisit if io_uring becomes a goal for the server path. Nothing in the
public API above depends on epoll, so a different backend can sit behind it.

## Decision: level triggered by default

- A handler may stop early (it hit its batch limit, it is waiting for a
  slower peer, it wants to let another descriptor run). With level
  triggering the descriptor is simply reported again on the next `wait`.
  With edge triggering the handler must read until the call would block, or the
  rest of the data waits for the next arrival.
- With `recvmmsg` batches the loop reads at most N packets per wake-up, so
  one busy socket cannot starve the timers or the tun device.
- Cost: a ready descriptor is reported on each `wait` while data remains. That is
  the same number of `epoll_wait` calls edge mode would need, since the handler
  must come back to hit EAGAIN anyway.
- Write interest in level mode must be switched on only while output is
  pending (`modify_fd`), or the loop spins. TCP code does this.
- `.Edge` is available per registration (for example a TCP socket with
  write interest left on).

## Things to know

- **Time.** `now()` is `CLOCK_MONOTONIC`, read with a real system call (Odin
  has no vDSO fast path; a static musl build has none either). The loop caches
  it once per `wait`. `timer_add(delay)` and `timer_reset` count from that
  cached time, so a per-packet keepalive reset costs no system call. Use
  `now()` or `update_time` when exact time matters.
- **Suspend.** `CLOCK_MONOTONIC` stops during suspend, so a timer set for 60 s
  does not fire "early" after a laptop sleeps. Detecting a dead tunnel
  after resume needs `CLOCK_BOOTTIME` or a wall clock check in the client
  (not done here).
- **Timer order.** Equal deadlines fire in the order they were armed. A
  timer armed by a handler never runs in the same `wait` that armed it, so
  `timer_add(loop, 0, ...)` inside a handler cannot spin the loop.
- **Stale events.** If a handler removes a descriptor (or closes it and a new
  descriptor takes the same number) while events for it are still queued in
  the same batch, those events are dropped. Each registration has a
  generation number in the epoll data.
- **Timer precision.** `epoll_wait` takes milliseconds; the loop rounds up,
  so a timer is never early and at most about 1 ms late. (`epoll_pwait2` has
  nanoseconds but needs Linux 5.11.)
- **Signals.** `EINTR` makes `wait` return 0. A `signalfd` or a self-pipe
  can be added as an ordinary descriptor by the daemon later.

## macOS

`event_darwin.odin` has the same API on kqueue. It is level triggered by
default, as epoll is.

- A descriptor has one kqueue filter for each direction. `wait` merges the
  events of one descriptor into one handler call, so a readable and writable
  socket gives `{.Read, .Write}` as on Linux. `.Edge` is `EV_CLEAR`.
- `.Hangup` is `EV_EOF`. A socket with a pending error also gets `.Error`: the
  error is in the `fflags` of the event.
- `wake` is an `EVFILT_USER` event with `EV_CLEAR`: no descriptor, safe from any
  thread, and a wake-up before `wait` is not lost.
- `now()` is `CLOCK_UPTIME_RAW` (`clock_gettime_nsec_np`), the clock that kevent
  timeouts count on. It stops while the Mac sleeps. The loop rounds a timeout up
  to a millisecond.
- A registration is checked when it is made (`EV_RECEIPT`), so a descriptor
  that kqueue refuses gives `.Register_Failed` at `add_fd`.
- Closing a descriptor drops its filters; `remove_fd` after the close only
  cleans the table.
- Tests: `event_darwin_test.odin`.

## Windows

`event_windows.odin` has the same API on `WaitForMultipleObjects`, plus wait
handles for the things that are not sockets.

| Call | Meaning |
|------|---------|
| `add_fd`, `modify_fd`, `remove_fd` | A socket (the `SOCKET` value as an `i32`). All sockets of a loop use one WSA event (`WSAEventSelect`). |
| `add_handle`, `remove_handle` | Any waitable handle: the wintun read event, the event of an overlapped pipe operation. The `Handle_Handler` runs when it is signaled. |
| `handle_again` | Report an auto-reset event again on the next `wait`. A handler that stops before its source is empty must call it: the wait has reset the event. |

- **Limit.** One wait takes 64 objects: the wake event, the timer, the event
  of the sockets and `MAX_HANDLES` (61) handles. `add_handle` returns
  `.Register_Failed` when the handle table is full; a client needs three.
  Sockets have no fixed limit, because they all use one event that
  only ends the wait.
- **Level triggering.** WSA events are edge-like (set once per new event).
  Before it blocks and after it wakes, the loop asks `WSAPoll` which sockets
  are ready now, so a socket with data left is reported again, as on Linux.
  That is one call for all sockets. A closed peer is reported as `.Hangup`.
  A socket that was closed without `remove_fd` is dropped without a report,
  but Windows can give its value to the next new socket at once, and the
  loop then reports that socket. Call `remove_fd` before `closesocket`.
- **Recorded events.** The loop reads the events that Winsock recorded for a
  socket (`WSAEnumNetworkEvents`) only in two cases, so a socket that waits
  for data costs no system call of its own:
  - `.Edge`: the socket is reported from its recorded events only, once for
    each new event.
  - Write interest: a connect that fails is reported as `{.Error, .Write}`.
    `WSAPoll` reports it only since Windows 10 2004, so register a
    connecting socket with `.Write`.
- **Timers.** A high resolution waitable timer
  (`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`, Windows 10 1803 and later) wakes
  the loop, so a 2 ms timer fires after about 2 ms. Without it the wait
  timeout is in milliseconds and the system tick (about 15.6 ms) applies.
- **Time.** `now()` is `QueryUnbiasedInterruptTimePrecise` (from
  KernelBase.dll; it stops during sleep, like `CLOCK_MONOTONIC`), or the
  performance counter when the call is missing.
- **Winsock.** `init` calls `WSAStartup` once for the process.
