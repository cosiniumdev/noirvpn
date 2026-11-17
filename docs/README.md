# noirvpn documentation

| Document | Content |
|----------|---------|
| [Client](client.md) | Platforms, service mode, identities, data path, post-quantum key exchange, `block-ipv6`, differences from OpenVPN. |
| [Server](server.md) | Pinned keys, password and web sign-in, listeners, data path, control bus, systemd, differences from OpenVPN. |
| [The tls transport](tls-transport.md) | The tunnel inside TLS: options, strict check, HTTP proxies, WebSocket, ClientHello profile, nginx recipes. |
| [Management interface](management.md) | Events, requests, roles, external authentication, `noirvpnctl`, `noirvpn-hook`. |
| [Userspace DCO interface](dco-interface.md) | The socket protocol for implementers of a DCO service. |
| [Option reference](options.md) | Every option and what noirvpn does with it. |

Start with the client or server page. Use the option reference to check an
existing OpenVPN configuration.
