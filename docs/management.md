# Management interface

Every noirvpn daemon, server or client, has a local management interface: the
**control bus**. It replaces the OpenVPN management interface, the
`client-connect` and `client-disconnect` scripts, and the auth scripts and
plugins. noirvpn refuses the `management*` options.

The bus has two local sockets:

- an **event stream** that tells what the daemon does (peers connect, keys
  rotate, the connection state changes);
- a **request channel** where you ask questions and give commands (list the
  peers, kick a peer, decide a login, stop the daemon).

All messages are JSON. The bus uses [nng](https://nng.nanomsg.org): the event
stream is an nng PUB/SUB socket and the request channel is an nng REQ/REP
socket, so you can write a tool in any language that has an nng binding. The
bus is local only. To manage a remote host, log in to it and run `noirvpnctl`
there.

Contents:

- [Sockets](#sockets)
- [Messages](#messages)
- [Events](#events)
- [Requests](#requests)
- [Roles](#roles)
- [External authentication](#external-authentication)
- [noirvpnctl](#noirvpnctl)
- [noirvpn-hook](#noirvpn-hook)
- [Writing your own tool](#writing-your-own-tool)

## Sockets

| Socket | nng protocols | Default path | Used for |
|--------|---------------|--------------|----------|
| events | PUB (daemon), SUB (tools) | `<dir>/<name>.events` | The event stream. |
| control | REP (daemon), REQ (tools) | `<dir>/<name>.control` | Requests and replies. |

- `<dir>` is `/run/noirvpn` for a daemon that runs as root. For another user it
  is `$XDG_RUNTIME_DIR/noirvpn`, or `/tmp/noirvpn-<uid>`.
- `<name>` is the instance name: the `--name NAME` option of the daemon, else
  the base name of the config file without its extension
  (`/etc/noirvpn/server.conf` gives `server`), else `noirvpn`. Give each daemon
  on one host its own name.
- On Windows the sockets are the named pipes `\\.\pipe\noirvpn-<name>-control`
  and `\\.\pipe\noirvpn-<name>-events`. The installed service uses the name
  `desktop` (see [the client on Windows](client.md#windows)).

### Options

| Option | Meaning |
|--------|---------|
| `bus-control off` or `bus-control PATH [mode MODE] [group GROUP]` | The control socket. |
| `bus-events off` or `bus-events PATH [mode MODE] [group GROUP]` | The events socket. |
| `bus-allow uid\|gid\|sid ID ROLE[,ROLE...]` | Who may do what on the control socket. See [Roles](#roles). |
| `stats-interval SECONDS` | Publish a `stats.tick` event every `SECONDS` seconds (0 to 86400). 0 or not set: off. |
| `auth-external [SECONDS]` | A controller decides each login. See [External authentication](#external-authentication). |

- `PATH` is an absolute path or an `ipc://` URL, at most 103 bytes.
- `mode` is an octal file mode. The default is `0660`. `group` is a group name
  or number.
- Without the option, the socket is at its default path.
- `daemon.reload` applies `stats-interval` and `bus-allow`. The socket options
  need a restart.

```
bus-control /run/noirvpn/server.control mode 0660 group noirvpn
bus-events  /run/noirvpn/server.events  mode 0640 group noirvpn
bus-allow uid 0 admin
bus-allow gid noirvpn read
```

### Let a user in without a config

Linux and macOS. Two flags of the daemon give one user or one group the role
`operator` for this run. They are not written to a config file.

```
sudo noirvpn --allow-user alice
sudo noirvpn --allow-group vpnusers
```

- `--allow-user NAME`: both sockets belong to the user, with mode `0600`.
- `--allow-group NAME`: both sockets get the group, with mode `0660`.
- With both, the sockets belong to the user and the group, with mode `0660`.
- The socket folder gets mode `0755`, so that the user or the group can enter
  it. The socket modes keep other users out.
- Each flag can be given once. A name that does not exist stops the start.
- `daemon.reload` keeps them.
- A daemon that runs as root, with sockets that only root can use, logs a line
  that names these flags.

**Protect the events socket.** `bus-allow` does not apply to it. Every process
that can connect to it receives every event, including user names, key pins
and addresses. Use `mode` and `group`.

## Messages

- One nng message is one JSON object in UTF-8. Standard JSON only: no
  comments, no trailing commas, integers as integers.
- Every message has `"v": 1`, the protocol version.
- **Ignore unknown fields and accept unknown values.** The daemon can add
  fields, counter names and `reason` values without a change of `v`.
- Time stamps (`ts`) are RFC 3339 UTC with milliseconds:
  `2026-01-15T09:26:53.589Z`.
- A `session` is an opaque string, for example `s-17`. Do not parse it. Pass it
  back as you got it.
- A `pin` is `sha256:` and 64 hex digits, or `null`.

### Event envelope

An event is one PUB message: the topic, one space, and the JSON envelope.

```
peer.rekey {"v":1,"run":"9f3a0c51d27be8a4","seq":42,"ts":"2026-01-15T09:26:53.589Z","topic":"peer.rekey","data":{"session":"s-17","peer_id":3,"key_id":1,"by":"local","count":1}}
```

| Field | Meaning |
|-------|---------|
| `run` | 16 random hex digits. A new value at every daemon start. |
| `seq` | 1 for the first event of a run, then plus 1 for every event, across all topics. |
| `ts` | When the daemon created the event. |
| `topic` | The same text as before the space. |
| `data` | The fields of the topic. |

A subscriber that reads too slowly loses events. A jump in `seq` shows the
loss, and a new `run` shows a restart. Nothing that matters for security
depends on delivery.

### Request and reply

A tool sends one REQ message and receives one REP message.

```json
{"v":1,"id":"c1f0b6e2a94d4f3b8a7e55d01c9a2b17","op":"peer.kick","args":{"session":"s-17"}}
```

```json
{"v":1,"id":"c1f0b6e2a94d4f3b8a7e55d01c9a2b17","ok":true,"result":{"kicked":["s-17"]}}
```

```json
{"v":1,"id":"c1f0b6e2a94d4f3b8a7e55d01c9a2b17","ok":false,"error":{"code":"not_found","message":"no such session"}}
```

- `id` is 1 to 64 printable ASCII characters. Use 32 random hex digits.
- `args` is optional. A missing `args` means `{}`.
- The reply `id` is `null` when the daemon could not read an `id`.
- Use `error.code` in a program. `message` is for people.

| Error code | Meaning |
|------------|---------|
| `bad_request` | The request or an argument is not valid. |
| `unknown_op` | No operation with that name. |
| `denied` | Your roles do not allow the operation. |
| `not_found` | The session, peer or name does not exist. |
| `busy` | The daemon cannot accept it now. Nothing was done. Retry later. |
| `conflict` | The request does not fit the current state, or the `id` was used for a different request. |
| `timeout` | The daemon did not reply in 30 seconds. **It can still apply the request.** |
| `internal` | The daemon failed, for example a file could not be read. |
| `unsupported` | A server operation sent to a client, or the other way round. |

**Repeating a request.** For an operation that changes state, the daemon
remembers the reply for each pair of user id and request `id` for 120 seconds.
After a timeout, send the **same** `id` and the same bytes again: the daemon
returns the stored reply and does not do the work twice. Use a new `id` for
every new request.

## Events

Both modes publish these:

| Topic | When | Key fields |
|-------|------|------------|
| `daemon.start` | The first event of a run. | `mode`, `name`, `version`, `pid`, `config`, `datapath`, `control`, `events` |
| `daemon.stop` | The last event of a run. | `reason` (`signal`, `request`, `error`), `detail` |
| `daemon.reload` | After each `daemon.reload` request. | `ok`, `reloaded`, `error` |
| `stats.tick` | Every `stats-interval` seconds. | The `stats.get` result and `interval_s` |

A server publishes these. A session goes through `peer.handshake`, then
`peer.auth_pending` (only with `auth-external`), then `peer.connect` or
`auth.fail`:

| Topic | When | Key fields |
|-------|------|------------|
| `peer.handshake` | TLS is done and the identity is known. | `session`, `name`, `pin`, `real_addr`, `proto` |
| `peer.auth_pending` | The login waits for a controller. | As `peer.handshake`, and `identity_source`, `web_auth`, `proofs`, `peer_info`, `timeout_s`, `deadline` |
| `peer.connect` | The session is active. | The [peer object](#the-peer-object) and `push` |
| `peer.rekey` | The session has a new key. | `session`, `peer_id`, `key_id`, `by` (`peer` or `local`), `count` |
| `peer.float` | The address of the peer changed. | `session`, `peer_id`, `old_addr`, `new_addr` |
| `peer.disconnect` | A session that had `peer.connect` ended. | `session`, `name`, `pin`, `reason`, `detail`, `duration_s`, the final counters |
| `auth.fail` | The daemon refused a session before it became active. | `session` (or `null`), `name`, `pin`, `real_addr`, `proto`, `reason`, `detail` |

`peer.disconnect` `reason` values: `client_exit`, `timeout`, `kicked`,
`replaced`, `server_stop`, `session_timeout`, `key_revoked`, `cert_revoked`,
`crl_failed`, `protocol_error`, `transport_closed`, `user_removed`,
`password_changed`, `reauth_failed`, `sign_in_ended`, `error`.

`auth.fail` `reason` values: `unknown_key`, `key_disabled`, `bad_certificate`,
`name_mismatch`, `password_missing`, `password_failed`, `password_busy`,
`token_invalid`, `max_clients`, `rate_limit`, `external_denied`,
`external_timeout`, `cert_revoked`, `crl_failed`, `tls_failed`, `client_left`,
`assignment_failed`.

A client publishes these:

| Topic | When | Key fields |
|-------|------|------------|
| `client.state` | The connection state changed. | `state`, `prev`, `reason`, `remote`, `attempt`, `datapath` |
| `client.tunnel_settings` | The pushed settings, once per connection, before `up`. | `peer_id`, `cipher`, `ifconfig`, `mtu`, `routes`, `dns_servers`, `dns_domains`, `redirect_gateway`, `push` |
| `client.auth_needed` | The daemon needs credentials. Respond with `auth.supply`. | `kind` (`credentials` or `key_pass`), `reason`, `username` |
| `acl.deny` | The inbound filter (`allow-inbound`) dropped a packet. At most 10 each second. | `reason`, `proto`, `src`, `dst`, `sport`, `dport`, `skipped` |
| `acl.forward` | A connection of a port forward (`forward`) opened or closed. At most 20 each second. | `what` (`open` or `close`), `proto`, `port`, `peer`, `peer_port`, `target`; on `close` also `bytes_in`, `bytes_out`
| `acl.rules` | A reload changed the `allow-inbound` or `forward` rules. | `filter`, `source`, `rules`, `forwards`, `pending` |, `reason` |

The client states are `waiting`, `connecting`, `handshake`, `up`, `closing` and
`stopped`. The `dns_servers` and `dns_domains` fields let a helper that runs
without root apply the DNS settings (see [DNS](client.md#dns)).

```json
{"v":1,"run":"41c07a2e90d3b5f8","seq":9,"ts":"2026-01-15T09:00:01.204Z","topic":"client.state","data":{"state":"up","prev":"handshake","reason":null,"remote":"198.51.100.7:1194","attempt":1,"datapath":"userspace"}}
```

### The peer object

`peer.connect`, `peers.list` and `peer.get` describe a server session with this
object. All keys are present. A value that does not apply yet is `null`.

| Field | Meaning |
|-------|---------|
| `session`, `peer_id` | The session id, and the peer id once the session is active. |
| `name`, `pin` | The client identity and its key pin. |
| `identity_source` | `pin`, `certificate`, `username` or `controller`. |
| `state` | `handshake`, `auth_pending` or `active`. |
| `real_addr`, `proto` | The address of the peer now, and `udp`, `tcp`, `tls` or `ws`. |
| `backend` | `daemon`, `service` (`datapath udco`) or `kernel` (`datapath dco`). |
| `vpn4`, `vpn6` | The tunnel addresses. |
| `cipher`, `data_format` | For example `AES-256-GCM`, and `epoch` or `baseline`. |
| `connected_at` | When the session became active. |
| `bytes_in`, `bytes_out`, `packets_in`, `packets_out` | The counters. |
| `proofs` | The checks that the daemon made: `pin`, `chain`, `password`. Empty when it checked nothing. |

### Following the stream

A monitor or a controller that needs the state and every change does this:

1. Subscribe to **everything** (an empty prefix) and connect. Do not filter
   topics in nng, because `seq` counts all topics.
2. Call `status`. Keep `bus.run` and `bus.seq`. Read the state you need
   (`peers.list`, page by page).
3. Read events. Skip an event with a `seq` up to `bus.seq`.
4. For every event, check `run` and `seq`. A new `run`, or a `seq` that is not
   the last one plus 1, means that you missed something: go back to step 2.

Apply events as updates keyed by `session`.

## Requests

"Role" is the lowest role that may call the operation (see [Roles](#roles)).

| Operation | Role | Daemon | What it does | Arguments |
|-----------|------|--------|--------------|-----------|
| `status` | read | both | Mode, version, state, and the bus position (`bus.run`, `bus.seq`). | none |
| `stats.get` | read | both | Totals and counters of the daemon, or of one peer. | `session` (server, optional) |
| `peers.list` | read | server | A page of peer objects and the total `count`. | `all`, `name`, `limit` (1 to 2000, default 500), `offset` |
| `peer.get` | read | server | One peer object. | `session` or `peer_id` |
| `peer.kick` | operator | server | Disconnects sessions. Returns `kicked`. | one of `session`, `peer_id`, `name`, `serial`, `pin` (`name` can go with `serial` or `pin`); `halt`; `reason` |
| `peers.reload` | operator | server | Reads the `peer-keys` file again and ends sessions of removed keys. | none |
| `passwords.reload` | operator | server | Reads the `peer-passwords` file again. | none |
| `log.level` | operator | both | Sets the log level. Returns `verb` and `previous`. | `verb` (0 to 4) |
| `auth.decide` | auth | server | Decides a waiting login. | `session`, `decision`, and more below |
| `auth.credentials` | auth | server | Returns the user name and password that a waiting client sent. Once only. | `session` |
| `daemon.reload` | admin | both | Reads the config again and applies what can change. Returns `reloaded` and `ignored`. | none |
| `daemon.shutdown` | admin | both | Replies `{"stopping":true}`, then stops. | `timeout_s` (0 to 60, default 5) |
| `connect` | operator | client | Connects now and skips the back-off. | none |
| `disconnect` | operator | client | Disconnects and stays disconnected until `connect`. | none |
| `auth.supply` | operator | client | Responds to `client.auth_needed`. | `username`, `password`, `key_pass` |
| `acl.get` | read | client | The `allow-inbound` and `forward` rules in force, and where they come from. | none |
| `acl.reload` | operator | client | Reads the config file again and applies only its `allow-inbound` and `forward` lines. | none |

`acl.get` returns:

- `filter`: true when `allow-inbound` is in force. Then a new connection from
  the tunnel passes only when a rule lets it in.
- `source`: `config`, or `profile` for the rules of a profile that a client
  service holds. null when `filter` is false.
- `rules`: one object for each destination, with `dest` (as the config writes
  it, such as `:22` or `nas.lan:445`), `protos`, `source`, and for a host name
  `addresses` (the addresses of the last lookup).
- `forwards`: `port`, `protos` and `target`.
- `denied`: the inbound packets that the filter dropped, or null.
- `pending`: true when the connection runs on DCO. The rules apply at the next
  connection.
- `profile_ignored`: the destinations of the profile that the service config
  overrides.

`acl.reload` changes the rules in place: connections that exist stay open, and
new connections see the new rules. When the `forward` lines change, the
connections of the port forwards close. A config file with an error changes
nothing; the reply is `bad_request` with the problems in `details` (`line`,
`option`, `reason`). The result has `changed`, `filter`, `rules`, `forwards`,
`pending`, `closed` (forward connections that closed) and `ignored`
(`acl-max-flows` needs a restart). In a client service, only the user who loaded
the profile can reload, as for `connect`. `daemon.reload` applies the same lines.

<a id="peerkick"></a>`peer.kick` with `halt` `true` tells the client not to reconnect. Without it,
the client gets a restart notice. `reason` (up to 128 characters) goes to the
log and to `detail` of `peer.disconnect`. The client does not get it. With
`serial` (a certificate serial in hex) no match is not an error: use it after
you revoke a certificate.

## Roles

| Role | Grants |
|------|--------|
| `read` | `status`, `stats.get`, `peers.list`, `peer.get` |
| `operator` | `read`, and `peer.kick`, `peers.reload`, `passwords.reload`, `log.level`, `connect`, `disconnect`, `auth.supply` |
| `auth` | `read`, and `auth.decide`, `auth.credentials` |
| `admin` | Every operation |

`operator` and `auth` are separate: a controller that decides logins cannot
kick peers. Give a process both roles if it needs both.

```
bus-allow uid 0 admin
bus-allow uid noirvpn-ctl operator
bus-allow gid 1500 read
bus-allow uid auth-controller auth
```

- `ID` is a user or group number or name. For `sid` (Windows) it is a SID or an
  account or group name.
- A process holds the union of the roles of all matching rules. A `gid` rule
  also matches a user who is a member of the group.
- The daemon checks the user id and group id that the kernel reports for the
  other end of the socket.
- **Default:** with no `bus-allow` line, root and the user of the daemon get
  `admin` (on Windows, LocalSystem and Administrators). **Once there is any
  `bus-allow` line, only the lines count.** Write `bus-allow uid 0 admin` if
  root must keep its access.
- To reach the control socket at all, a process also needs write permission on
  the socket file and access to its directory.

## External authentication

With `auth-external`, a controller (a process with the `auth` role) decides
each login. It can check a password, ask for a second factor, or assign an
address from another system.

```
auth-external 30
```

`SECONDS` is 1 to 3600, default 30. The option needs the control socket. It
adds a check on top of the usual certificate and pin checks. It does not
replace them.

### Server flow

1. The client finishes TLS and passes the checks of the daemon. The daemon
   tells the client `AUTH_PENDING` and publishes `peer.auth_pending` with a
   `deadline`.
2. The controller looks at `name`, `pin`, `proofs` and `peer_info`. If it needs
   the password, it calls `auth.credentials` once.
3. <a id="authdecide"></a>The controller calls `auth.decide`:
   - `allow`, with optional `push` lines: the daemon publishes `peer.connect`.
   - `deny`, with an optional `reason` for the client: the daemon publishes
     `auth.fail` with `external_denied`.
   - `pending`, with an optional `timeout` (1 to 3600 seconds): the daemon
     moves the deadline. Use it while an MFA prompt is open. A later `allow` or
     `deny` is still needed.
4. **No decision before the deadline is a deny** (`auth.fail` with
   `external_timeout`). This is a temporary deny, so the client tries again.

Rules:

- The password is never in an event. `auth.credentials` returns it once, and
  the daemon does not store that reply. If you lose it, deny the login.
- An empty `proofs` array means that the daemon checked nothing. Then the
  controller must check the client itself. Do not allow a client that has
  neither a certificate nor a password.
- `push` takes at most 64 lines of these options: `ifconfig-push`,
  `ifconfig-ipv6-push`, `iroute`, `iroute-ipv6`, `session-timeout`, `route`,
  `route-ipv6`, `dhcp-option`, `dns`, `redirect-gateway`, `redirect-private`,
  `inactive`. One bad line rejects the request.
- After `allow`, the daemon can still refuse the client (for example
  `max_clients`). Watch for `auth.fail` with the same `session`.

```
EVENT peer.auth_pending {"v":1,"run":"9f3a0c51d27be8a4","seq":57,"ts":"2026-01-15T09:30:02.114Z","topic":"peer.auth_pending","data":{"session":"s-21","name":"carol","pin":"sha256:89ab...","real_addr":"203.0.113.77:50122","proto":"udp","proofs":["pin"],"peer_info":{"IV_VER":"2.6.8","IV_PLAT":"linux"},"timeout_s":30,"deadline":"2026-01-15T09:30:32.114Z"}}
REQ {"v":1,"id":"01010101010101010101010101010101","op":"auth.credentials","args":{"session":"s-21"}}
REP {"v":1,"id":"01010101010101010101010101010101","ok":true,"result":{"session":"s-21","username":"carol","password":"correct horse"}}
REQ {"v":1,"id":"03030303030303030303030303030303","op":"auth.decide","args":{"session":"s-21","decision":"allow","push":["ifconfig-push 10.8.0.50 255.255.255.0","route 192.168.5.0 255.255.255.0"]}}
REP {"v":1,"id":"03030303030303030303030303030303","ok":true,"result":{"session":"s-21","decision":"allow"}}
```

### Web sign-in

With `auth-web` on the server (see [Web sign-in](server.md#web-sign-in)), a
client without a certificate or password can sign in through a web page of the
controller.

1. The daemon publishes `peer.auth_pending` with `web_auth` `true`, `name`
   `null` and no proofs.
2. The controller creates a sign-in page and calls `auth.decide` with
   `pending`, a `timeout` and a `url`. The client shows the page.
3. The user signs in. The controller calls `auth.decide` with `allow`, a `name`
   (the user identity) and a `token_lifetime` (60 to 2592000 seconds).
4. The daemon pushes a session token. At a reconnect, the client sends the
   token, and the daemon publishes `peer.auth_pending` with that `name` and the
   proof `token`. The controller decides again, without a `name`.

`auth.decide` arguments for a web sign-in:

| Argument | With | Meaning |
|----------|------|---------|
| `url` | `pending` | The sign-in page. `https`, printable ASCII, a host, no user part, at most 1024 bytes. The daemon never logs it. |
| `flags` | `pending` and `url` | `hidden` (an embedded web view stays hidden) or `external` (the system browser opens the page). |
| `name` | `allow` | The identity: 1 to 255 bytes, no control byte, no `/` or `\`. Required for a web login. |
| `token_lifetime` | `allow` | How long the session token is valid. Without it, the client gets no token. |

`peer.kick` with `halt`, a `deny` and a daemon restart end the sign-in.

### Client flow

A client daemon waits for credentials from the bus when the config has
`auth-user-pass` with no file, standard input is not a terminal, and the
control socket is on. It publishes `client.auth_needed` and waits for
`auth.supply` from a process with the `operator` role. With `auth-retry
interact` it does the same after a refused login.

```
EVENT client.auth_needed {"v":1,"run":"41c07a2e90d3b5f8","seq":2,"ts":"2026-01-15T09:00:00.310Z","topic":"client.auth_needed","data":{"kind":"credentials","reason":"no_credentials","username":null,"prompt":null,"echo":false,"timeout_s":null}}
REQ {"v":1,"id":"05050505050505050505050505050505","op":"auth.supply","args":{"username":"carol","password":"correct horse"}}
REP {"v":1,"id":"05050505050505050505050505050505","ok":true,"result":{"accepted":true}}
```

## noirvpnctl

`noirvpnctl` is the command line tool for the bus.

```
noirvpnctl [--name NAME | --socket PATH] [--json] [--timeout SECONDS] COMMAND [arguments]
```

- Without `--name` and `--socket`, it uses the only daemon it finds in
  `/run/noirvpn` and the directory of your user. With several daemons, specify
  `--name`.
- `--json` prints the raw reply. `--timeout` is 5 seconds by default.
- After a timeout, the tool sends the request once more with the same id. If
  that also times out, it prints the id. Run the command again with `--id ID`
  to get the stored reply.

| Command | Daemon | What it does |
|---------|--------|--------------|
| `status` | both | Shows the mode, state and bus position. |
| `stats [SESSION]` | both | Shows the counters. |
| `log-level LEVEL` | both | Sets the log level, 0 to 4. |
| `reload` | both | Reads the config again. |
| `shutdown [--timeout S]` | both | Stops the daemon. |
| `events [-n COUNT] [--wait] [PREFIX...]` | both | Prints events, one line each. |
| `peers [--all] [--user NAME]` | server | Shows a table of peers. |
| `peer SESSION` or `peer --peer-id N` | server | Shows one peer. |
| `kick SESSION`, `kick --peer-id N`, `kick --user NAME`, `kick --serial HEX [--user NAME]`, `kick --pin PIN [--user NAME]` | server | Disconnects sessions. Add `--halt` and `--reason TEXT`. |
| `reload-peers`, `reload-passwords` | server | Reads the peers file or the password file again. |
| `auth allow SESSION [--push LINE]... [--name NAME] [--token-lifetime S]` | server | Allows a waiting login. |
| `auth deny SESSION [--reason TEXT]` | server | Refuses a waiting login. |
| `auth pending SESSION [--timeout S] [--url URL] [--flag hidden\|external]` | server | Keeps a login waiting. |
| `auth credentials SESSION` | server | Shows the password that a waiting client sent. Once only. |
| `connect`, `disconnect` | client | Connects now, or disconnects and stays down. |
| `auth-supply [--username U] [--password-stdin \| --password-file FILE] [--key-pass-stdin \| --key-pass-file FILE]` | client | Supplies credentials or a key passphrase. |
| `rules` | client | Shows the `allow-inbound` and `forward` rules in force. |
| `reload-rules` | client | Reads the config file again and applies its `allow-inbound` and `forward` lines. |

A password never comes from the command line. Examples:

```
noirvpnctl status
noirvpnctl --name server peers
noirvpnctl kick --user alice --halt --reason "left the company"
noirvpnctl events peer. auth.
noirvpnctl auth allow s-21 --push "ifconfig-push 10.8.0.50 255.255.255.0"
printf '%s\n' "$PASSWORD" | noirvpnctl auth-supply --username carol --password-stdin
```

```
$ noirvpnctl peers
SESSION  NAME   STATE   PROTO  REAL_ADDR          VPN4      VPN6  CONNECTED                 IN    OUT
s-17     alice  active  udp    203.0.113.5:51000  10.8.0.6  -     2026-01-15T09:26:53.589Z  1.2K  3.4M
```

| Exit code | Meaning |
|-----------|---------|
| 0 | OK. |
| 1 | The daemon replied with an error other than `denied`. |
| 2 | Usage error, or several daemons found. |
| 3 | The daemon is not running. |
| 4 | Permission denied. |
| 5 | Timeout. The daemon can still apply the request. |
| 6 | Another failure. |

## noirvpn-hook

`noirvpn-hook` runs a command for each event that matches a rule. It replaces
the connect and disconnect scripts of OpenVPN. It is a separate process, so a
slow script cannot hold up the daemon. It only reads events. A script that must
act calls `noirvpnctl`.

```
noirvpn-hook --name server --config /etc/noirvpn/hook.conf
noirvpn-hook --name server --on peer.connect=/usr/local/bin/on-connect
```

Run it as its own unprivileged user that can connect to the events socket (use
the `group` of `bus-events`). It refuses to run as root without `--allow-root`.

| Option | Meaning |
|--------|---------|
| `--name NAME`, `--socket PATH` | The daemon, or its events socket. |
| `-c FILE`, `--config FILE` | Read rules and settings from a file. |
| `--on PREFIX=/CMD` | Run `/CMD` for topics that start with `PREFIX`. `*` matches every event. |
| `--timeout SECONDS` | Kill a command after this time. Default 30. |
| `--max-parallel N` | Commands that run at one time. Default 4. Set 1 for strict order. |
| `--max-queue N` | Events that wait for a free slot. Default 100. When full, the hook drops the event and logs it. |
| `--check-config` | Print what would run, and exit. |

Config file:

```
# /etc/noirvpn/hook.conf
timeout 10
max-parallel 1
on peer.connect    run /usr/local/bin/log-peer
on peer.disconnect run /usr/local/bin/log-peer
on peer.auth_      run /usr/local/bin/notify "a login is waiting"
```

The command is an absolute path and runs **without a shell**. What it gets:

- Standard input: the JSON envelope of the event and a newline.
- `NOIR_TOPIC`, `NOIR_SEQ`, `NOIR_RUN`, `NOIR_TS`, and `NOIR_GAP` (events
  missed) or `NOIR_RESTARTED` (`1` after a daemon restart) when they apply.
- `NOIR_<FIELD>` for each top level field of `data` that is a string, number,
  boolean or `null` (as an empty string). `peer_id` becomes `NOIR_PEER_ID`.
  Read objects and arrays from standard input.
- Only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TZ` of the environment.

```sh
#!/bin/sh
case "$NOIR_TOPIC" in
peer.connect)
    logger -t noirvpn "connect name=$NOIR_NAME vpn4=$NOIR_VPN4 from=$NOIR_REAL_ADDR"
    ;;
peer.disconnect)
    logger -t noirvpn "disconnect name=$NOIR_NAME reason=$NOIR_REASON in=$NOIR_BYTES_IN out=$NOIR_BYTES_OUT"
    ;;
esac
```

Treat every value as untrusted text and quote variables. A user name or a
reason can hold any text that a client chose.

## Writing your own tool

You need an nng binding with PUB/SUB, REQ/REP and the `ipc://` transport.

To read events: open a SUB socket, subscribe to everything, dial
`ipc:///run/noirvpn/<name>.events`, and split each message at the first space.
Check `run` and `seq` as in [Following the stream](#following-the-stream).

To send requests:

1. Open a REQ socket. Set send and receive timeouts (for example 5 seconds).
2. Set the maximum receive size to 8 MiB.
3. Turn off the resend timer of the REQ socket.
4. Dial `ipc:///run/noirvpn/<name>.control`. A dial fails at once when the
   daemon is not running.
5. Send one request, read one reply, check that the `id` matches, and check
   `ok` and `error.code`.

Security:

- No event holds a password or a token. Only the reply of `auth.credentials`
  holds a password. Do not log it.
- Treat every string as untrusted: names, reasons, `peer_info` values and push
  lines can come from a client. Do not pass them to a shell. Escape them when
  you show them.
- Run a controller as its own user with only the roles it needs. A process with
  `admin` can stop the daemon.
- Do not forward the sockets to a network. The bus has no encryption, and the
  local user id is its only authentication.

`examples/auth` in the source tree is a login controller for `auth-external`,
written in Go. It is an example only.
