# noirconf

noirconf is a small Python based web service that sets up and runs noirvpn servers.

Features:
- create a server
- add users
- create client profiles for importing into client apps
- change the server options
- and start or stop the daemon.

It only needs Python and the `openssl` command; there is nothing to install.

## Requirements

- Linux with Python 3.9 or later and the `openssl` program.
- The `noirvpn` program, on your `PATH` or given with `--noirvpn`.
- Root. noirconf writes to `/etc/noirvpn/server` and controls services.
- A way to check passwords: PAM (`libpam.so.0`) on Debian and most systems, or `libcrypt`
  and `/etc/shadow` on Alpine when PAM is missing.

## Run it

This server needs to be run as root because of its access to noir's configuration,
which includes certificate and keys, and manage the noir service.

Start it from the source folder:

```
sudo python3 noirconf.py
sudo python3 noirconf.py --noirvpn /usr/local/bin/noirvpn --log /var/log/noirconf.log
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--host` | `127.0.0.1` | Address to listen on. |
| `--port` | `9443` | Port to listen on. |
| `--log FILE` | none | Also write the log to this file. |
| `--etc DIR` | `/etc/noirvpn/server` | The config folder. |
| `--noirvpn PATH` | from `PATH` | The daemon program. |
| `--pam-service NAME` | `login` | The PAM service for the password check. |

On start it will print the address, the SHA-256 fingerprint of its web certificate, and an ssh
hint. Compare the fingerprint with the one in your browser's certificate warning before you
accept it.

You log in with the password of the account that ran `sudo` or `doas`, or `root` when there is
none. As another user, noirconf starts only when `--etc` is outside `/etc` (meant for tests).

### Reach it with an ssh tunnel

noirconf listens on localhost only. From your own computer, run:

```
ssh -L 9443:127.0.0.1:9443 user@server
```

Then open `https://127.0.0.1:9443/`.

### The web certificate

noirconf will generate `appserver.crt` and `appserver.key` in the config folder when they are missing
or about to expire. The certificate is always EC P-256 and uses `localhost`, `127.0.0.1`,
`::1` and the value of `--host`.

## First steps

1. Open the page and log in. With no server yet, you land on the New server page.
2. Keep **Create with Essentials** checked, enter the name, ports, public address and tunnel
   network, and choose the clients and the transport (UDP, TCP, TLS, or TLS with WebSocket).
   noirconf creates the certificates and keys, writes the config, and checks it with
   `noirvpn --check-config`. If the check fails, nothing stays on disk.
3. On the Service page, install the service if asked, and start it.
4. On the Users page, add a user and create a client profile. Send the `.ovpn` file to the
   user. noirconf does not keep the private key, so a lost profile requires creating a new profile.

The Help page inside noirconf explains each of these choices in more detail.

## Where the files live

```
/etc/noirvpn/server/
  appserver.crt, appserver.key   web certificate
  NAME.conf                      daemon config of server NAME
  NAME/
    pki/                         the CA, server.crt, server.key, crl.pem
    tls-crypt.key                control channel key
    accounts.conf                users and keys
    peers                        peers file of the daemon, generated
    noirconf.ini                 settings of noirconf
```

Every `*.conf` file in the folder is a server, except `appserver.*`. Other tools can edit
these files too, and noirconf keeps the lines, comments and blocks that it does not manage.
When a group `noirvpn` exists, the files that the daemon reads belong to it. The CA key stays
readable by root only.

## Security notes

- Anyone who can log in can change the VPN and run the daemon as root. Keep the listener on
  the local address and use an ssh tunnel.
- A session ends after 30 minutes without use. The refresh of the dashboard does not extend
  it. After 5 failed logins in a minute from one address, login is blocked for the rest of
  that minute.
- The session cookie is `HttpOnly; Secure; SameSite=Strict`. Every POST needs the CSRF token
  of the session and an `Origin` that matches the host.
- The page policy is `default-src 'self'`: no inline script and no outside asset. htmx 2.0.4
  is in `static/` with its licence.
- Passwords go to PAM or `crypt()` in memory. Key passphrases go to `openssl` through a pipe
  and never appear in an argument list. The log and the audit lines hold no passwords, keys
  or session tokens.
- Every change writes an audit line with who, what, which server and which user.
- Names and values that come from the daemon are escaped on every page.

## For developers

### Tests

```
python3 -m unittest discover -s noirconf/tests
```

- Tests use temporary folders and never touch `/etc`, `/run` or real services.
- Checks of generated configs need a `noirvpn` that knows `peer-keys-mode either`. Set
  `NOIRVPN=/path/to/noirvpn` to choose one. Without one, those tests are skipped.
- The interop tests use `noirvpnctl`. Set `NOIRVPNCTL=/path/to/noirvpnctl` to choose one.

### The option form

`options.json` comes from `docs/options.md`. The tables at the top of `tools/gen_options.py`
hold the hidden options, the friendly names, the defaults, the accepted values and the
dropdown lists. Options that options.md marks as not applied yet are left out. To make the
file again:

```
python3 noirconf/tools/gen_options.py
```

The Config form writes `dev tun` for a new server and has no `dev`, `bind`, `mlock` or
`dco-socket` field. The switch Run as TLS server writes `proto tls-server`, Use kernel DCO
writes `datapath dco` (a `datapath udco` or `auto` line stays as it is), and `data-ciphers`
is a set of boxes that keeps the order of the existing line. Lines that the form does not
show stay in the file.

### The service manager

The manager is systemd (template unit `noirvpn-server@.service`), OpenRC
(`/etc/init.d/noirvpn-server.NAME`), or a detached process with a pid file in `/run/noirconf`
and a log in `/var/log/noirconf`. After a change to users, noirconf writes the peers file,
kicks the affected sessions (by name, serial and pin, with `halt`) and calls `peers.reload`.

### Create with Essentials

The form takes the name, the listen port, the public address and port, the IPv4 tunnel
network (CIDR from /16 to /30, no host bits) and the clients. OpenVPN compatible offers UDP
or TCP. noirvpn clients only adds TLS and TLS with WebSocket (`tls-transport-ws PATH`, path
`/` plus 1 to 64 characters of `A-Za-z0-9._~/-`, no `..`, default `/noir-NAME`). Loopback and
unspecified public addresses are refused, also in an old `noirconf.ini`, where such a line is
ignored. Profiles get `tls-client` remotes, and `tls-transport-ws PATH` for WebSocket.

### noirconf.ini

```
[server]
key-type = ed25519
clients = openvpn

[external]
remote.1 = vpn.example.com 1194 udp
remote.2 = vpn.example.com 443 tls ws=/noir-server
```

- `key-type` is `ed25519` (default), `ec-p256` or `rsa-3072`. It sets the key of the CA, the
  server certificate and each new client certificate. A change applies to new certificates
  only.
- `clients` is `openvpn` (default) or `noirvpn`. It only decides which reminder the pages
  show.
- An external address is `host port udp|tcp|tls [ws=PATH]`. `ws=` needs `tls`. Older files
  without `clients` or `ws=` still read.

### accounts.conf

One `[username]` section for each user. Names have 1 to 64 characters from
`A-Z a-z 0-9 . _ @ -` and do not start with `-`. Names that differ only by case are the same
user.

| Key | Meaning |
|-----|---------|
| `enabled` | `yes` or `no`. A disabled user gets `disabled` on every line of the peers file. |
| `created` | Time stamp (UTC). |
| `notes` | Free text on one line. |
| `options` | Peers file options for the first active key: `ifconfig-push=`, `ifconfig-ipv6-push=`, `iroute=`, `iroute-ipv6=`. |
| `key.ID.pin` | `sha256:` and the base64 of the SHA-256 of the public key (SubjectPublicKeyInfo). |
| `key.ID.serial` | The certificate serial in hex. Empty for a bare pin. |
| `key.ID.label` | Short text for the key. |
| `key.ID.state` | `active` or `revoked`. A revoked key is `disabled` in the peers file. |
| `key.ID.source` | `ca` (signed by the server CA), `cert` (uploaded certificate) or `pin`. |
| `key.ID.created` | Time stamp (UTC). |

`ID` is `k1`, `k2` and so on.

```
[alice]
enabled = yes
created = 2026-11-26T10:00:00Z
key.k1.pin = sha256:EEdckfvr1RFzY9Di1QZKLSTburVA1g5a1196kqf4Ggw=
key.k1.serial = 6A193F9C3B1D3522
key.k1.label = profile 2026-11-26
key.k1.state = active
key.k1.source = ca
```
