# The noirvpn server

This page explains how to configure and run the noirvpn server. The server reads the OpenVPN config syntax. An option that noirvpn supports works the same way as in OpenVPN; see the [OpenVPN reference manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/) or the openvpn(8) man page. This page describes only what is new or different. For the client, see [client.md](client.md). For every option, see [options.md](options.md).

## What the server is

The server is the `noirvpn` program with a config that has `server` (or `mode server`). One daemon serves many clients. The server runs on Linux only.

- It works at layer 3, on a tun device. There is no tap device and no bridging.
- The only topology is `topology subnet`.
- The data channel uses AEAD ciphers only. There is no compression.
- It runs in the foreground and logs to standard error. Use a service manager to run it in the background.
- It needs `CAP_NET_ADMIN` and `/dev/net/tun`. A port below 1024 also needs `CAP_NET_BIND_SERVICE`.
- It does not turn on IP forwarding and does not set up NAT. See [Forwarding and NAT](#forwarding-and-nat).

noirvpn clients and OpenVPN 2.6 and 2.7 clients can use the same server. A client that offers the epoch data format gets it. Other clients get the baseline format.

## Start and stop

```
noirvpn --config server.conf [--name NAME] [--option [args...]] ...
noirvpn --check-config --config server.conf
```

`--name NAME` sets the instance name of the control bus. The default is the config file name without its extension.

| Exit code | Meaning |
|---|---|
| 0 | Clean stop, or a check with no error. |
| 1 | A config error, a key file or the peers file cannot be used. |
| 2 | The command line is wrong. |
| 3 | A system error: no `CAP_NET_ADMIN`, no tun device, a socket that cannot listen, the bus sockets. |
| 7 | The tun device is up but its addresses or routes could not be set. |

| Signal | Effect |
|---|---|
| SIGINT, SIGTERM | Stop. Every client gets RESTART (with `explicit-exit-notify`) or EXIT. |
| SIGHUP | Reads the peers file and the password file again. It does not read the main config. |
| SIGUSR2 | Writes the status to the log. |
| SIGUSR1 | Ignored. |

`noirvpnctl reload` (the bus request `daemon.reload`) reads the main config again. It applies `bus-allow`, `verb`, `stats-interval`, the peers file and the password file. Other changed options need a restart.

`user` and `group` work on Linux: the daemon opens its devices, sockets and listeners, changes to the user and keeps only `CAP_NET_ADMIN`. The user must still be able to read the peers file, the password file, the `crl-verify` file and the `client-config-dir` files.

### Check a configuration

`--check-config` reads the config and every file that it specifies: the certificate, the key, the CA, the control channel keys, the peers file and the password file. It opens no device and no socket, and it needs no root. It exits with 0 when there is no error and 1 when there is one.

```
config check: server, 8 options in 1 file
  supported  server.conf:2  server
  new        server.conf:8  peer-keys
  ...
summary: 7 supported, 1 new, 0 ignored, 0 rejected, 0 unknown
result: ok (0 errors, 0 warnings)
daemon: server, 1 listener(s), 4 key(s) in the peers file
```

Each option shows its class: `supported`, `new`, `ignored`, `rejected` or `unknown`. Lines that start with `daemon:` come from the checks of the daemon. The check does not read the `client-config-dir` files.

## A first server

A server needs a tunnel network, a certificate and key for itself, and a way to know its clients. This server knows its clients by pinned keys and needs no CA:

```conf
server 10.8.0.0 255.255.255.0
port 1194
proto udp

cert /etc/noirvpn/server.crt
key /etc/noirvpn/server.key
peer-keys /etc/noirvpn/peers
tls-crypt /etc/noirvpn/tls-crypt.key

keepalive 10 60
```

For a first test, create a self-signed server certificate. Clients pin it with `peer-fingerprint`:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout server.key -out server.crt -subj "/CN=vpn.example.com" \
    -addext "subjectAltName=DNS:vpn.example.com" -days 3650
openssl x509 -in server.crt -noout -fingerprint -sha256
```

A key with a passphrase needs `askpass FILE`, or `askpass` with no file to type it at the terminal at start. The same passphrase opens `key` and `tls-transport-key`. There is no inline `<askpass>` block.

## Client identity

A server knows its clients in one of these ways:

| Way | Options | Name of the session |
|---|---|---|
| A certificate authority | `ca` | The certificate CN. |
| Pinned keys | `peer-keys FILE` | The name in the peers file. |
| Certificate fingerprints | `peer-fingerprint FP ...` | The certificate CN. |
| A pin and a CA | `ca`, `peer-keys`, `peer-keys-mode` | The pinned name, or the CN. |
| A password | `verify-client-cert optional`, `peer-passwords` or `auth-external` | The user name. |
| A web sign-in | `auth-web` | The name that the controller gives. |

With `ca`, `crl-verify`, `remote-cert-tls client`, `remote-cert-ku`, `remote-cert-eku` and `verify-x509-name` work as in OpenVPN. `capath` is not supported: put all CA certificates in one `ca` file. `ca` together with `peer-fingerprint` is an error.

### Identity by pinned keys

The peers file has one line for each client key. The server accepts a client when the SHA-256 hash of the public key of its certificate is in the file. The client can use a self-signed certificate.

```text
# username   pin                                                            options
alice        sha256:EEdckfvr1RFzY9Di1QZKLSTburVA1g5a1196kqf4Ggw=
alice        sha256:u71INZi4g51GDiQRtoLUQJjxDlECXqu6UnkdLUaMTSE=            # a second device
carol        sha256:s1bZtq+1tYCqfLLoLAqmzfICXVkFcldVI0CZP0+nYkI=            ifconfig-push=10.8.0.10 iroute=192.168.50.0/24
dave         sha256:9m3+R01bogXhO9OMMqwdLtyAXNZ3uaa9U7dXoB8ZvHs=            disabled
```

The pin is the SHA-256 hash of the DER public key (SubjectPublicKeyInfo), in base64. Compute it from the client certificate:

```
openssl x509 -in alice.crt -noout -pubkey | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | base64 -w0
```

A pin with the prefix `mldsa65-sha256:` is the hash of an ML-DSA-65 public key.

#### File format

- One key on each line: `NAME PIN [OPTIONS...]`, separated by spaces or tabs. A `#` at the start of a field begins a comment.
- `NAME` has at most 255 bytes, no control character, no `/` and no `\`, and is not `.` or `..`. It is the name in `client-config-dir`, the address pool, the log and the bus.
- One name can have several lines (several devices of one user). A pin can be in the file only once.

| Option | Meaning |
|---|---|
| `ifconfig-push=ADDR` | A fixed IPv4 tunnel address for this key. |
| `ifconfig-ipv6-push=ADDR/BITS` | A fixed IPv6 tunnel address for this key. |
| `iroute=NET/LEN` | A network behind this client. Can be repeated. |
| `iroute-ipv6=NET/BITS` | An IPv6 network behind this client. Can be repeated. |
| `disabled` | The key is known and refused. |

Rules:

- One bad line invalidates the whole file. At start, the server exits with 1. On a reload, the old table stays.
- Keys of one name can be connected at the same time, with no `duplicate-cn`. A new login with the key of a connected session replaces that session only.
- A client that also sends a user name must send its pinned name (case does not matter).
- SIGHUP or `noirvpnctl reload-peers` reads the file again. Sessions of keys that are removed, disabled or moved to another name end with HALT. A session whose line changed only its options stays up.

### Identity by certificate fingerprint

`peer-fingerprint` accepts the SHA-256 fingerprints of whole client certificates, with no peers file. The name of the session is the CN. A pin in the peers file is better when certificates change often: a renewed certificate with the same key still matches.

### Certificate and pin together

`peer-keys-mode` sets how `ca` and `peer-keys` work together:

| Mode | Meaning |
|---|---|
| `pin` | The default without `ca`. Only the pin counts. With `ca` it is an error. |
| `both` | The chain must verify against `ca` and the key must be in the peers file. The name is the pinned name. |
| `either` | A pin, else a chain. This is the mode of `ca` with `peer-keys` and no `peer-keys-mode`. |

A key marked `disabled` is refused in every mode, also with a good certificate.

```conf
ca /etc/noirvpn/ca.crt
peer-keys /etc/noirvpn/peers
peer-keys-mode both
```

### Login by password

`peer-passwords FILE` specifies a file of user names and password hashes. The server checks the password itself and needs no controller.

- With `verify-client-cert require` (the default), a client sends a certificate that passes, and also a user name and a password. The user name must be the identity of the certificate (the pinned name or the CN), with no regard to case.
- With `verify-client-cert optional`, a client can log in with a user name and a password and no certificate. It needs a password source: `peer-passwords` or `auth-external`. A certificate that a client does send must still pass.
- `verify-client-cert none` is an error.
- A user name that is not in the file and a wrong password get the same response after the same time.
- Use `tls-crypt` or `tls-auth` so that only clients with the key reach the password check. `connect-freq` limits the rate of guesses.

### The password file

One line for each user: the user name, a TAB, and the hash.

```
alice	pbkdf2-sha256:260000:tlR8PflSyvwU4SiVJ1dYZw==:M5u90+gFC4NZiRlWRcMkzei4kAaLK1I5Ys9VFsz8ms4=
```

| Part | Rule |
|---|---|
| User name | 1 to 255 bytes. No control characters, no `/` or `\`. Not `.` or `..`. |
| `pbkdf2-sha256` | The only scheme. |
| Iterations | 1 to 10000000. Use 260000 or more. |
| Salt | Standard base64 with padding, 1 to 64 bytes. |
| Hash | Standard base64 with padding, 16 to 64 bytes: the PBKDF2-HMAC-SHA256 output. |

To create a line:

```
python3 -c 'import base64,hashlib,os,sys
salt=os.urandom(16); pw=sys.argv[2].encode()
h=hashlib.pbkdf2_hmac("sha256",pw,salt,260000,32)
print("%s\tpbkdf2-sha256:260000:%s:%s"%(sys.argv[1],base64.b64encode(salt).decode(),base64.b64encode(h).decode()))' alice 'the password'
```

Rules:

- A line that is wrong is skipped with a warning. The other lines are used.
- Write a new file and rename it, so that the server never reads half of it. Make it readable only by the user of the server.
- The server reads the file again when it changes, on SIGHUP, and on `noirvpnctl reload-passwords`. A removed user loses its sessions for good (HALT). A user with a new hash reconnects (RESTART).
- A session that logged in with a password sends it again at each renegotiation, and the server checks it again.

### Password only

With `verify-client-cert optional`, a password source and none of `ca`, `peer-keys` and `peer-fingerprint`, the server asks no client for a certificate. The identity of a client is its user name.

```
server 10.8.0.0 255.255.255.0
cert server.crt
key server.key
tls-crypt tc.key
verify-client-cert optional
peer-passwords /etc/noirvpn/users
```

There is no certificate check in front of the password check. Use `tls-crypt` or `tls-crypt-v2`, and `connect-freq`.

### Protect the control channel

`tls-auth`, `tls-crypt` and `tls-crypt-v2` work as in OpenVPN. Generate the keys with `openvpn --genkey`; noirvpn has no key generator. Differences:

- `tls-crypt-v2` defaults to `force-cookie` over UDP. `allow-noncookie` also accepts clients without the cookie exchange.
- A server can have `tls-crypt-v2` together with `tls-crypt` or `tls-auth`, for clients of both kinds.
- `tls-crypt-v2-max-age DAYS` refuses old client keys. `tls-crypt-v2-verify` is rejected.

## External authentication

With `auth-external [SECONDS]`, a program on the control bus (a controller) decides each login. It replaces `auth-user-pass-verify` and the plugins of OpenVPN.

1. The daemon runs its own checks first: the certificate or the pin, and the limits.
2. It tells the client to wait (`AUTH_PENDING`) and publishes `peer.auth_pending`.
3. The controller can read the user name and password with `auth.credentials`.
4. The controller responds with `auth.decide`: `allow` (with optional `push` lines for this client), `deny`, or `pending` (wait longer).
5. With no response in time (default 30 seconds, at most 3600), the login is refused.

```conf
cert /etc/noirvpn/server.crt
key /etc/noirvpn/server.key
peer-keys /etc/noirvpn/peers

auth-external 30
bus-allow uid 1001 auth,read
```

`auth-external` needs the control socket, and the controller needs the role `auth`. With `auth-external` and no `peer-passwords`, the controller checks the passwords. With both, the file checks first. `noirvpnctl auth allow`, `auth deny`, `auth pending` and `auth credentials` do the same by hand. [management.md](management.md) describes the messages.

### Web sign-in

With `auth-web`, the controller signs a user in through a web page. The client has no certificate and no password. It says that it can do a web sign-in (`IV_SSO=webauth`, see [Web sign-in](client.md#web-sign-in) of the client).

```
verify-client-cert optional
auth-external 30
auth-web
bus-control /run/noirvpn/server.control mode 0660 group noirbus
bus-allow uid 1002 auth
```

1. The client connects. The daemon publishes `peer.auth_pending` with `web_auth` `true`.
2. The controller calls `auth.decide` with `pending`, a `timeout` and a `url`. The client shows the link.
3. The user signs in. The controller calls `auth.decide` with `allow`, a `name` and a `token_lifetime`.
4. The daemon pushes a session token. The client uses it at each renegotiation and reconnect.

The URL must be `https`. The daemon never writes it to the log.

#### The session token

- The token starts with `noirt2.`. The daemon signs it with a key that it creates at start and never writes to disk.
- `token_lifetime` is 60 to 2592000 seconds. Without it, the session ends at its first renegotiation.
- At a renegotiation the daemon checks the token itself. At a reconnect the controller decides again.
- When the lifetime ends, the session closes and the client asks for a new sign-in.
- A restart of the daemon ends all sign-ins.
- `auth-gen-token` is rejected. The server issues tokens only for a web sign-in.

## Listeners

| Option | Meaning |
|---|---|
| `proto udp`, `tcp-server`, `tls-server` | The protocol. `tls-server` is TCP inside an outer TLS stream, for noirvpn clients. |
| `local HOST [PORT [PROTO]]` | One listener. `*` means any address. `PORT` and `PROTO` default to `port` and `proto`. |
| `tls-transport-accept-tcp` | A `tls-server` listener also serves raw OpenVPN `tcp-client` connections on the same port. |
| `tls-transport-ws PATH` | Serves WebSocket clients at this path on `tls-server` and `tcp-server` listeners. |
| `tls-transport-cert FILE`, `tls-transport-key FILE` | The certificate and key of the outer TLS. The default is `cert` and `key`. |

Each `local` line opens one listener, up to 8. All listeners share one tunnel, one address pool and one set of clients.

```conf
local 192.0.2.10 1194 udp4
local 2001:db8::10 1194 udp6
local * 443 tls-server
tls-transport-accept-tcp
```

- A UDP server always replies from the address that the client sent to. `multihome` is accepted and not needed.
- `connect-freq N SEC` counts each source address (an IPv6 source by its /64). In OpenVPN it counts all sources together.
- `connect-freq-initial N SEC` (default `100 10`) and `connect-freq-source N` (default 20) limit the replies to first UDP packets.

For the `tls-server` options, WebSocket and the nginx recipes, see [tls-transport.md](tls-transport.md).

## Addresses and per-client settings

`server`, `server-ipv6`, `ifconfig-pool`, `ifconfig-pool-persist`, `client-config-dir`, `iroute` and `push` work as in OpenVPN. Differences:

- The IPv6 pool follows the IPv4 pool: the client in IPv4 slot *i* gets IPv6 slot *i*.
- A line in the peers file can set a fixed address and iroutes for one key. It wins over the `client-config-dir` file, which belongs to the name.
- An `iroute` adds a kernel route to the tunnel when the client logs in, and removes it when the client leaves. A `route` line for it is not needed.
- Without `client-to-client`, the server drops a packet from one client to another client, also when IP forwarding is on.
- Names are compared with no regard to ASCII case. `Alice` and `alice` are one user.
- A pin session and a session with no pin (a certificate chain, a password or a web sign-in) of the same name do not replace each other.

## Data path and performance

By default the daemon does all the work in one process. It uses the tun offloads, UDP GSO and UDP GRO when the kernel has them. The environment variable `NOIRVPN_NO_OFFLOAD` (`tun`, `gso`, `gro` or `all`) turns them off.

UDP GRO also needs GRO on the network device that receives the tunnel:

- The status block (`SIGUSR2`, and when the daemon stops) has an `offload` line. If `coalesced` is 0 in that line after a large upload from a client, the device joined no datagrams.
- A VMware guest with the `vmxnet3` driver joins no UDP datagrams while LRO is on. `ethtool -K DEVICE lro off` turns LRO off, and the receive rate of the daemon goes up.

`workers N` (0 to 64, default 0) starts `N` threads that seal and open data packets. Each client stays on one worker. Use workers when you have many clients.

| `datapath` | Meaning |
|---|---|
| `userspace` | The default. This process does everything. |
| `dco` | The `ovpn` module of the kernel (Linux 6.16 or later) does the data channel. |
| `udco` | A userspace DCO service does the data channel. `dco-socket PATH` sets its socket (default `/run/udco/udco.sock`). |
| `auto` | The kernel module if it is there, else the service, else this process. |

Rules for `dco` and `udco`:

- The server can have exactly one listener besides the `tls-server` ones.
- If the kernel or the service is not usable at start, the server logs a warning and runs in this process.
- If the service goes away or the device is deleted, the server ends every session and runs in this process until a restart.
- Not available: the epoch data format and `workers`.
- The kernel does not clamp the MSS.
- `client-to-client` needs IP forwarding, because the packets cross the tun device. Without `client-to-client`, add a firewall rule to keep the clients apart, for example `nft add rule inet filter forward iifname "tun0" oifname "tun0" drop`.
- A DCO service is any program that implements [dco-interface.md](dco-interface.md).

### A mixed server

A server with `datapath dco` or `udco` can also have a `tls-server` listener. The kernel or the service serves the UDP or TCP clients. The daemon serves the tls clients on a second tun device.

```conf
server 10.8.0.0 255.255.255.0
dev tun0
datapath udco

local 192.0.2.10 1194 udp
local 192.0.2.10 443 tls-server
tls-transport-dev tun0-tls

cert /etc/noirvpn/server.crt
key /etc/noirvpn/server.key
peer-keys /etc/noirvpn/peers
keepalive 10 60
```

- The default name of the second device is the `dev` name with `-tls` added.
- Traffic between the two kinds of client crosses the kernel, so IP forwarding must be on.
- Firewall rules must cover both devices, for example with `tun0*`.

### Blocking IPv6 (`block-ipv6`)

`block-ipv6` drops every IPv6 packet at the tunnel, in both directions, for each client. The server sends no ICMPv6 reply. To make noirvpn clients drop IPv6 too, add `push "block-ipv6"`. Push an IPv6 address and `redirect-gateway ipv6`, or the IPv6 traffic of the clients does not reach the tunnel.

The kernel data path cannot drop IPv6. With `block-ipv6`, the server does not use `datapath dco`. A DCO service must have the capability for it.

### Forwarding and NAT

The server does not change the forwarding settings of the host:

```
sysctl -w net.ipv4.ip_forward=1
nft add table ip nat
nft add chain ip nat postrouting '{ type nat hook postrouting priority 100 ; }'
nft add rule ip nat postrouting ip saddr 10.8.0.0/24 oifname "eth0" masquerade
```

## Status and monitoring

There is no status file and no management port. The server has a control bus instead.

- SIGUSR2 writes the status text to the log. The server also writes it at exit.
- The bus publishes events (`peer.connect`, `peer.disconnect`, `auth.fail` and others) and takes requests (`status`, `peers.list`, `peer.kick`, `peers.reload`, `passwords.reload`, `daemon.reload`, `auth.decide` and others).
- `noirvpn-hook` runs a command for each event. It replaces the `client-connect` and `client-disconnect` scripts.

| Option | Default | Meaning |
|---|---|---|
| `bus-events off\|PATH [mode M] [group G]` | `/run/noirvpn/NAME.events` | The events socket. |
| `bus-control off\|PATH [mode M] [group G]` | `/run/noirvpn/NAME.control` | The control socket. |
| `bus-allow uid\|gid ID\|NAME ROLE[,ROLE...]` | root and the daemon user are `admin` | The roles: `read`, `operator`, `auth`, `admin`. |
| `stats-interval SECONDS` | off | Publishes `stats.tick`. |

```
noirvpnctl status
noirvpnctl peers
noirvpnctl kick --user alice
noirvpnctl reload-peers
noirvpnctl events
```

See [management.md](management.md) for the formats and the commands.

## Running under systemd

This unit runs the daemon as a user without a login, with only `CAP_NET_ADMIN`:

```ini
# /etc/systemd/system/noirvpn-server.service
[Unit]
Description=noirvpn server
After=network-online.target
Wants=network-online.target

[Service]
User=noirvpn
Group=noirvpn
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
ExecStart=/usr/local/bin/noirvpn --config /etc/noirvpn/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartPreventExitStatus=1 2
TimeoutStopSec=10
RuntimeDirectory=noirvpn
RuntimeDirectoryMode=0750
StateDirectory=noirvpn
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

The config for this unit adds:

```conf
ifconfig-pool-persist /var/lib/noirvpn/ipp.txt 600
bus-control /run/noirvpn/server.control
bus-events /run/noirvpn/server.events
```

- The user needs read access to the key, for example mode `0640` with the group `noirvpn`.
- `RestartPreventExitStatus=1 2` stops restarts after a config error.
- For a port below 1024, add `CAP_NET_BIND_SERVICE` to both capability lines.
- With `datapath udco`, start the DCO service first. With `datapath dco`, load the `ovpn` module first.
- `ExecReload` reads the peers file again. To read the config again, use `noirvpnctl reload`.

## Differences from OpenVPN servers

The server reads the same config syntax. It does not run scripts and has no management port. It uses the control bus and a peers file instead. `--check-config` marks the options below `rejected` (the server does not start) or `ignored` (a note).

| Other server | In noirvpn |
|--------------|------------|
| `client-connect`, `client-disconnect`, `learn-address`, `up`, `down`, `route-up`, `ipchange` scripts | Rejected. Use the events of the control bus, or `noirvpn-hook`. |
| `auth-user-pass-verify`, `tls-verify`, `auth-user-pass-optional`, `username-as-common-name`, `override-username` | Rejected. Use the peers file, `peer-passwords` or `auth-external`. |
| `plugin` | Rejected. |
| `management`, `management-*` | Rejected. Use the control bus and `noirvpnctl`. |
| `status`, `status-version` | Rejected. Use `noirvpnctl status`, SIGUSR2 and `stats-interval`. |
| `compress`, `comp-lzo` | Rejected. There is no compression. |
| `dev tap`, `server-bridge`, `vlan-*` | Rejected. The server works at layer 3 only. |
| `topology net30`, `topology p2p`, `mode p2p`, `ifconfig-pool-linear` | Rejected. Use `topology subnet`. |
| `secret` and static key mode | Rejected. |
| `port-share`, `chroot`, `fragment` | Rejected. |
| `client-cert-not-required` | Rejected. Use `verify-client-cert optional` with `peer-passwords` or `auth-external`. |
| `auth-gen-token`, `auth-gen-token-secret` | Rejected. The server issues a token only for a [web sign-in](#web-sign-in) (`auth-web`). |
| `single-session` | Rejected. Use `disabled` in the peers file or `disable` in a client file. |
| `replay-persist`, `tls-export-cert`, `x509-track`, `tls-crypt-v2-verify` | Rejected. For old client keys, use `tls-crypt-v2-max-age`. |
| `pkcs11-*`, `pkcs12` | Rejected. Use PEM files. |
| `askpass` | A file or the prompt at a terminal. There is no inline `<askpass>` block. |
| `user`, `group` | Linux only. The daemon keeps `CAP_NET_ADMIN` after the change. |
| `verify-client-cert none` | Rejected. Use `optional` with `peer-passwords` or `auth-external`. See [Login by password](#login-by-password). |
| `capath` | Rejected. Use one `ca` file. |
| `cipher`, `ncp-disable`, `data-ciphers-fallback` | Do nothing on a server. Use `data-ciphers`. |
| `replay-window`, `mark`, `mlock`, `mtu-disc`, `ping-exit`, `inactive`, `session-timeout` (global) | Accepted and not applied. The check shows a warning. |
| `dh` | Ignored. |
| `connect-freq` | Per source address. In OpenVPN it is for all sources together. |
| `tls-crypt-v2` | Over UDP, the default is `force-cookie`. |

Other differences:

- A client identity can be a pinned key. The client then needs no CA and no certificate chain.
- With `auth-external` and no `peer-passwords`, a client that sends a certificate and a password must use the certificate name as its user name. Stock OpenVPN with `auth-user-pass-verify` accepts any name.
- User names are compared with no regard to ASCII case. A `client-config-dir` file is found by the exact name, then by the name in lower case.
- Revocation uses `crl-verify`, the peers file, a client file or a controller.

[options.md](options.md) lists every option and its status.

## Troubleshooting

Start with `noirvpn --check-config --config FILE`. It finds most errors without root and without a network. Use `verb 3` to see more of a handshake.

| Message | Fix |
|---|---|
| `there is no way to verify clients: ...` | Add `ca`, `peer-keys` or `peer-fingerprint`, or use [password only](#password-only). |
| `peers file FILE: ...` | A line of the peers file is wrong. The text says what. |
| `login of CLIENT refused: the client key is not in the peers file` | Add the pin of the client, then send SIGHUP. |
| `login of CLIENT refused: client username does not match the identity of its certificate` | The client sends another user name than its pinned name or CN. |
| `login of CLIENT refused: the password check failed` | The user is not in the password file, or the password is wrong. |
| `only up to 8 local lines are supported` | Use fewer `local` lines. |
| `raw OpenVPN connection from [ADDRESS] on a tls listener refused ...` | Set `tls-transport-accept-tcp`, or connect with `tls-client`. |
| `datapath dco: the kernel has no ovpn module ...` | Run `modprobe ovpn` and start the daemon again. |
| Clients connect and no traffic flows | Check IP forwarding, the pushed routes, NAT, and that the firewall covers every tun device. |
