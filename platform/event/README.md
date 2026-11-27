# platform/event

A single-thread event loop for noirvpn: file descriptor readiness and timers,
one blocking call (`wait`).

- Linux uses epoll (`event_linux.odin`)
- Windows uses wait handles (`event_windows.odin`, see "Windows" below)
- macOS uses kqueue (`event_darwin.odin`, see "macOS" below).

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


## Things to know

- **Time.** `now()` is `CLOCK_MONOTONIC`, read with a system call.
- **Suspend.** `CLOCK_MONOTONIC` stops during suspend, so a timer set for 60s
  does not fire "early" after a laptop sleeps. Detecting a dead tunnel
  after resume needs `CLOCK_BOOTTIME` or a wall clock check in the client
  (not done here).
- **Stale events.** If a handler removes a descriptor (or closes it and a new
  descriptor takes the same number) while events for it are still queued in
  the same batch, those events are dropped.
- **Timer precision.** `epoll_wait` takes milliseconds; the loop rounds up,
  so a timer is never early and at most about 1 ms late.
- **Signals.** `EINTR` makes `wait` return 0. A `signalfd` or a self-pipe
  can be added as an ordinary descriptor by the daemon later.

## macOS

`event_darwin.odin` has the same API on kqueue. It is level triggered by
default, as epoll is.


## Windows

`event_windows.odin` has the same API on `WaitForMultipleObjects`, plus wait
handles for the things that are not sockets.

| Call | Meaning |
|------|---------|
| `add_fd`, `modify_fd`, `remove_fd` | A socket (the `SOCKET` value as an `i32`). All sockets of a loop use one WSA event (`WSAEventSelect`). |
| `add_handle`, `remove_handle` | Any waitable handle: the wintun read event, the event of an overlapped pipe operation. The `Handle_Handler` runs when it is signaled. |
| `handle_again` | Report an auto-reset event again on the next `wait`. A handler that stops before its source is empty must call it: the wait has reset the event. |

