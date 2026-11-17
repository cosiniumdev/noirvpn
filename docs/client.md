# The noirvpn client

`noirvpn` is a VPN client and server in one program. This page describes the client. It connects to an OpenVPN 2.6 or 2.7 server, or to a noirvpn server, and sends IP traffic through a `tun` device.

The client reads the OpenVPN config syntax. An option that noirvpn supports works as in OpenVPN; see the [OpenVPN reference manual](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/) or the openvpn(8) man page. This page describes only what is new or different. [options.md](options.md) lists every option and what noirvpn does with it.

Related pages:

- [server.md](server.md): the server.
- [tls-transport.md](tls-transport.md): the TLS transport.
- [management.md](management.md): the control bus, `noirvpnctl` and `noirvpn-hook`.

## Platforms

| Platform | What runs |
|---|---|
| Linux | The client and the server. Needs `CAP_NET_ADMIN` and `/dev/net/tun`. |
| Windows 10 (2004 or later) and 11, x64 | The client only, with the userspace data path. Uses wintun. See [Windows](#windows). |
| macOS | The client only, with the userspace data path. Runs under `sudo` and uses utun. See [macOS](#macos). |

One `noirvpn` process holds one tunnel. For more tunnels, run one process for each config.

The client does not run scripts. To act on tunnel changes, subscribe to the events of the [control bus](#the-control-bus).

## Running the client

```
noirvpn --config FILE [--option [args...]] ...
noirvpn FILE
noirvpn [--option [args...]] ...        # no config file
```

Any config option can go on the command line with two leading dashes. Command-line options come after the files and win.

| Argument | Effect |
|---|---|
| `--config FILE`, or a bare `FILE` | Reads a config file. |
| `--check-config` | Checks the config, prints the result and exits. Nothing starts. No root is needed. |
| `--name NAME` | Sets the instance name of the control bus. |
| `--version`, `-V` | Prints the version and exits. |
| `--help`, `-h` | Prints the usage and exits. |

### Starting without a config file

With no config file, `noirvpn` runs as a [client service](#service-mode) with default settings. Options on the command line change them:

```
sudo noirvpn                                  # the defaults
sudo noirvpn --verb 4 --workers 2             # the defaults, with these changed
```

With `--config FILE` and a missing FILE, `noirvpn` creates the file from the same defaults and the command-line options, then reads it. A file that exists is never changed.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean exit. |
| 1 | The config has errors, or the passphrase of the key is wrong. |
| 2 | Usage error. |
| 3 | A system call failed (no `CAP_NET_ADMIN`, the tun device, a socket, the DCO service). |
| 4 | The server refused the login (`AUTH_FAILED` with `auth-retry none`), or there are no credentials. |
| 5 | The server sent `HALT`. |
| 6 | `connect-retry-max` or `resolv-retry` is used up. |
| 7 | The tunnel is up, but the addresses, the routes or the MTU could not be set. |
| 8 | The `inactive` or `session-timeout` limit was reached. |

Do not let a service manager restart the client on 1, 2 and 4: the same config fails again.

Signals: SIGINT and SIGTERM stop the client. SIGHUP and SIGUSR1 reconnect. SIGUSR2 prints the status to the log.

### Privileges

On Linux, `user` and `group` change to that user after start-up. The client keeps `CAP_NET_ADMIN` for the tunnel and the routes, and drops all other capabilities. After the change, the client does not set the DNS settings of the system; the bus event `client.tunnel_settings` contains them for a helper. The user needs read and write access to `/dev/net/tun`. There is no `chroot`.

You can also start the client as an unprivileged user with the capability, for example with `AmbientCapabilities=CAP_NET_ADMIN` in systemd.

### The clean-up at start

A client that ends without its teardown (a crash, `kill -9`) can leave routes and DNS settings behind. Each noirvpn daemon keeps a record of its changes in `/run/noirvpn/state/` while it runs. The next daemon that starts reverts the records of daemons that are gone, and leaves alone what a running daemon has set.

## Checking a config

```
noirvpn --check-config --config /etc/noirvpn/work.conf
```

The output has one line for each option, with its class:

- `supported`: noirvpn applies it.
- `new`: an option that OpenVPN does not have.
- `ignored`: read with a warning, no effect.
- `rejected`: an error, with the reason and the replacement.

Lines that start with `daemon:` come from the checks that the running client also makes (files that cannot be read, conflicting settings). `result: ok` exits with 0, `result: FAILED` with 1.

## Identity

### The server certificate

Use `ca FILE` or `peer-fingerprint FP [FP ...]`, not both. `peer-fingerprint` pins the SHA-256 fingerprint of the whole server certificate:

```
openssl x509 -in vpn-server.crt -noout -fingerprint -sha256
```

`capath` is not supported. `crl-verify`, `remote-cert-tls`, `remote-cert-ku`, `remote-cert-eku`, `verify-x509-name` and `tls-version-min` work as in OpenVPN. `verify-x509-name ... subject` uses the subject form of OpenVPN 2.8, with a backslash before special characters (`O=Acme\, Inc.`).

### The client identity

A client has `cert` and `key` (PEM), or `auth-user-pass`, or both. PKCS#11 and PKCS#12 are not supported.

A noirvpn server can know a client by the hash of the public key of its certificate (a pin). It then needs no CA, so a self-signed certificate is enough:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout alice.key -out alice.crt -subj "/CN=alice" -days 3650
```

This prints the line that the server operator adds to the peers file (see [server.md](server.md#identity-by-pinned-keys)):

```
echo "alice sha256:$(openssl x509 -in alice.crt -noout -pubkey |
    openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64 -w0)"
```

A minimal config with a pinned server certificate:

```
client
dev tun
remote vpn.example.com 1194 udp
cert /etc/noirvpn/alice.crt
key /etc/noirvpn/alice.key
peer-fingerprint AD:95:BD:7F:C7:92:9A:AA:45:42:46:F3:9A:26:20:8D:23:FB:59:E6:C8:95:0F:3D:D2:63:EF:46:FD:B1:9C:FE
tls-crypt /etc/noirvpn/tls-crypt.key
```

### Encrypted keys (`askpass`)

A key with a passphrase needs `askpass`:

- `askpass FILE`: the first line of FILE is the passphrase. Make the file readable only by root (`chmod 600`).
- `askpass` with no file: the client asks at the terminal at start. This does not work under systemd or as a Windows service.

The client decrypts the key once at start and wipes the passphrase. There is no inline `<askpass>` block. A [service mode](#service-mode) profile gets the passphrase over the control bus.

### User name and password

`auth-user-pass` and `auth-retry` work as in OpenVPN. With no file and no terminal, the client waits for the credentials on the control bus (`client.auth_needed`). Challenge/response (`static-challenge`) is not supported.

### Web sign-in

Some servers sign you in through a web page, for example a single sign-on page. The server sends a link, you open it in a browser, and the tunnel comes up.

- In the desktop app or a client service: turn on "Web sign-in" for the profile, or use `noirvpnctl profile set FILE --sso webauth`.
- With a config file: add `setenv IV_SSO webauth`. The control bus must be on, because the client shows the link through the bus. The config needs no `cert`, `key` or `auth-user-pass`.

`noirvpnctl connect --follow` prints the link and the time left. The client opens only `https` links and never logs the whole link. For the server side, see [Web sign-in](server.md#web-sign-in).

## The data channel

- Ciphers are AEAD only: `AES-256-GCM`, `AES-128-GCM` and `CHACHA20-POLY1305`. The default is `data-ciphers AES-256-GCM:CHACHA20-POLY1305`. `cipher` is ignored, and a cipher that is not AEAD is an error.
- Compression is removed. `compress` and `comp-lzo` are errors.
- The server chooses the packet format. With OpenVPN 2.7 and noirvpn servers it is `epoch`. With OpenVPN 2.6 it is `baseline`.

### Post-quantum key exchange

`pq-mode` sets the key exchange groups of the TLS session:

| Value | Groups |
|---|---|
| `prefer` (default) | The hybrid group `X25519MLKEM768` first, then the classical groups. |
| `off` | `X25519:P-256:P-384:P-521`. |
| `require` | `X25519MLKEM768` only. The connection fails if the server cannot use it. |

`tls-groups` wins over `pq-mode`. `pq-mode` also sets the groups of the outer TLS of a `tls-client` remote.

## Blocking IPv6 (`block-ipv6`)

`block-ipv6` drops every IPv6 packet at the tunnel, in both directions. IPv4 is not touched. The server can push it. `route-nopull` does not stop it.

- The client sends no ICMPv6 reply. An application waits until its own timeout. A stock OpenVPN client replies with "no route to host".
- IPv6 that does not enter the tunnel still leaves through the normal interface. To block all IPv6 of the host, also send it into the tunnel:

```
client
remote vpn.example.com 1194 udp
ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1
redirect-gateway ipv6
block-ipv6
```

The kernel data path cannot drop IPv6. With `block-ipv6`, the client does not use `datapath dco`. A DCO service drops IPv6 only if it has the capability for it. Otherwise the data path runs in the client process.

## The data path

| `datapath` | Meaning |
|---|---|
| `userspace` (default) | The client process does the crypto. |
| `dco` | The Linux `ovpn` kernel module does the data path. |
| `udco` | A userspace DCO service does the data path. `dco-socket PATH` specifies its socket (default `/run/udco/udco.sock`). |
| `auto` | The kernel module if it is there, else the service if it responds, else the process. |

`disable-dco` means `datapath userspace`.

```
client
dev tun
remote vpn.example.com 1194 udp
ca /etc/noirvpn/ca.crt
cert /etc/noirvpn/client.crt
key /etc/noirvpn/client.key
datapath auto
```

Rules:

- `datapath dco` needs Linux 6.16 or later with the `ovpn` module (`modprobe ovpn`). It works for UDP and TCP.
- The client never stops because the kernel or the service is missing. It logs a warning and runs the data path itself. It asks again at each later connection attempt.
- If the kernel or the service fails a setup step, the client connects again at once with the data path in its own process.
- A `tls-client` remote always runs in the client process.
- The kernel does not clamp the MSS and has no `epoch` format. Use a smaller `tun-mtu` if large packets do not pass.
- A DCO service is any program that implements [dco-interface.md](dco-interface.md).

The environment variable `NOIRVPN_NO_OFFLOAD` turns off the segmentation offloads of the in-process data path. Its value is a comma list of `tun`, `gso` and `gro`, or `all`.

## Transports

| Transport | `proto` |
|---|---|
| UDP | `udp`, `udp4`, `udp6` |
| TCP | `tcp-client`, `tcp4-client`, `tcp6-client` |
| TLS | `tls-client`, `tls4-client`, `tls6-client`: TCP inside an outer TLS stream, for noirvpn servers only. |

The `tls` transport has its own options for the server name, a strict check, WebSocket and the ClientHello profile. See [tls-transport.md](tls-transport.md).

`http-proxy` supports HTTP CONNECT with no login or Basic login only. It works with `tcp-client` and `tls-client` remotes. `socks-proxy` is not supported.

## MTU

The tunnel MTU is 1400, unless you set `tun-mtu` or the server pushes it. `mssfix` works as in OpenVPN. With no `mssfix` line and the default MTU, the MSS is 1360 (IPv6: 1340).

## DNS

The client merges the pushed DNS options with the `dns` and `dhcp-option` lines of your config, as OpenVPN 2.6 does. Differences:

- Plain DNS only. A `dns server` group with DoH or DoT is skipped.
- Each `dhcp-option DOMAIN` value is a search domain. OpenVPN keeps only the last one.
- `dns-updown` is rejected.

On Linux the client uses systemd-resolved, else resolvconf, else it writes `/etc/resolv.conf` and restores it later. If DNS cannot be set, the tunnel stays up.

## Status and logs

- The client writes its log to standard error. `log`, `log-append`, `syslog` and `daemon` are ignored. Capture the output with the service manager.
- `status` and `status-version` are errors. Use `noirvpnctl status` or SIGUSR2.

## The control bus

The client has a control bus, on by default, in place of the OpenVPN management interface. It has a control socket for requests and an events socket for notifications. For root they are `/run/noirvpn/NAME.control` and `/run/noirvpn/NAME.events`.

| Option | Meaning |
|---|---|
| `bus-control off\|PATH [mode OCTAL] [group G]` | The control socket. |
| `bus-events off\|PATH [mode OCTAL] [group G]` | The events socket. |
| `bus-allow uid\|gid ID\|NAME ROLE[,ROLE]` | Gives roles to a user or group: `read`, `operator`, `auth`, `admin`. |
| `stats-interval SECONDS` | Publishes `stats.tick` events. |

`noirvpnctl` reads the status, connects, disconnects and supplies credentials. `noirvpn-hook` runs a command for each event. See [management.md](management.md).

## Service mode

A client service is a daemon that runs all the time and has no VPN config of its own. A user without root privileges loads a profile with `noirvpnctl`, connects and disconnects. The daemon keeps the privileges for the tunnel, the routes and DNS. The desktop app uses this mode.

The base config has `client-service` and the settings of the service:

```
client-service
verb 3
datapath userspace
bus-control /run/noirvpn/service.control mode 660 group noirvpn
bus-events /run/noirvpn/service.events mode 660 group noirvpn
bus-allow uid 0 admin
bus-allow gid noirvpn operator
```

Add the users to the group `noirvpn` to let them load profiles.

A profile is a client config in one file, with each certificate and key inline (`<ca>`, `<cert>`, `<key>`). Load and use it:

```
noirvpnctl profile check work.ovpn
noirvpnctl profile set work.ovpn --label "Work VPN"
noirvpnctl connect
noirvpnctl disconnect
noirvpnctl profile clear
```

Rules:

- The service keeps the profile in memory only. Load it again after a restart of the service.
- `profile set` and `profile clear` work only in the state `stopped`.
- A profile cannot set service settings (`datapath`, `workers`, `bus-*`, `verb` and others), options that specify a file or a program, or server options.
- `auth-user-pass FILE` and `askpass FILE` are accepted. The service does not open the file; the desktop app reads it for you when you own it and only you can read it (mode 600).
- A profile cannot touch the local networks: a pushed route that is equal to or inside a network of the computer is dropped. Local ports below 1024 and the routing tables 253 and 255 are refused.
- Without `dev`, the device is `noir0`, `noir1` and so on.
- Only the user who loaded the profile, and `admin` users, can connect, disconnect or clear it.
- When a tunnel ends, the service stays up in the state `stopped`, with a reason in `noirvpnctl status`.

## Windows

On Windows, noirvpn is a client only. A server config stops with an error. `datapath dco` and `udco` give a warning and use the userspace data path.

The installer `noirvpn-VERSION-windows-amd64.msi` installs the programs in `C:\Program Files\noirvpn`, installs and starts the service `noirvpn-desktop`, and adds `noirvpn` to the Start menu:

```
msiexec /i noirvpn-0.1.0-windows-amd64.msi
```

The config, the profiles and the logs are in `%ProgramData%\noirvpn`. An uninstall keeps them.

To run in a console, use an elevated prompt: `noirvpn --config C:\vpn\work.ovpn`. Ctrl+C stops the client.

The tunnel adapter is `noirvpn-NAME`, where NAME is the instance name. Routing domains (split DNS) go into one NRPT rule. A DNS server with a port other than 53 is dropped.

### Install the service by hand

The installer creates the service. Without the MSI, or for a second instance, run as an administrator:

```
noirvpn service install
noirvpnctl --name desktop profile set work.ovpn
noirvpnctl --name desktop connect
```

`noirvpn service install` registers `noirvpn-desktop`, which runs as LocalSystem. Give a path to use your own base config, and `--name NAME` for another instance. The default base config lets each user who is logged on load a profile (`bus-allow sid S-1-5-4 operator`). `noirvpn service uninstall` removes the service.

## macOS

On macOS, noirvpn is a client only and uses the userspace data path. It creates its own utun interface. It is not a Network Extension, so it needs no app, entitlement or signature.

- It needs root: `sudo noirvpn --config FILE`.
- It needs OpenSSL from Homebrew (`brew install openssl`).
- `dev tun` lets the system pick a free `utunN`. `dev utunN` asks for that one. Other names are not possible.
- `redirect-gateway` always uses the two half routes of `def1`, because macOS has no route metrics.
- DNS goes into the dynamic store with `scutil`. Check the order of the resolvers with `scutil --dns`.
- Not available: the server, `datapath dco` and `udco`, `user` and `group`, and `noirvpn-hook`.

## Differences from OpenVPN

| Topic | noirvpn |
|---|---|
| Scripts and plugins | `up`, `down`, `route-up`, `plugin` and the like are rejected. Use the bus events. |
| Compression | Removed. |
| Ciphers | AEAD only (`data-ciphers`). No `cipher`, no static key (`secret`). |
| Device | `tun` only. No `tap`, no bridge. |
| Management interface | The control bus replaces `management*`. |
| Log and status files | Standard error only. Use the bus for the status. |
| Private keys | PEM. An encrypted key needs `askpass`. No inline `<askpass>`, no PKCS#11 or PKCS#12. |
| Proxies | HTTP CONNECT only. No `socks-proxy`. |
| Privileges | `user` and `group` keep `CAP_NET_ADMIN`. No `chroot`. |
| Challenge/response | Not supported. |
| `block-ipv6` | Drops IPv6 in both directions and sends no ICMPv6 reply. |
| DNS | Plain DNS only. Each `dhcp-option DOMAIN` is a search domain. |
| `fragment`, `shaper`, `tls-verify` | Rejected. |
| Platforms | Linux; Windows and macOS as a client only. The Windows options of OpenVPN (`allow-nonadmin`, `win-sys`, ...) are rejected. |
| New options | `client-service`, `datapath`, `dco-socket`, `workers`, `pq-mode`, `bus-*`, `stats-interval`, `tls-transport-*`. |

[options.md](options.md) lists every option that noirvpn refuses, with the reason and the replacement.

## Troubleshooting

Run `noirvpn --check-config --config FILE` first. It shows most mistakes without root. For a connection that does not come up, run with `--verb 3`: the client then logs every step.

| Message | Fix |
|---|---|
| `there is no way to verify the server: ...` | Add `ca FILE` or `peer-fingerprint`. |
| `the client has no identity; ...` | Add `cert` and `key`, `auth-user-pass`, or `setenv IV_SSO webauth`. |
| `compress: not supported: ...` | Delete the line (also `comp-lzo`). |
| `key: the key is encrypted; ...` | Add `askpass FILE` or `askpass`. |
| `CAP_NET_ADMIN is needed ...` (exit 3) | Run as root or add the capability. |
| `datapath dco: the kernel has no ovpn module ...` | Load it with `modprobe ovpn`, or use another `datapath`. |
| Exit 7 | Run with `verb 3` and read the `network step` lines. |
