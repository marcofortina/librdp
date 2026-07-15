<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Server API

The server API exposes a small embeddable RDP listener for applications that
need to accept a client connection and drive the protocol state machine through
the public server handle. The API lives in `<librdp/server.h>` and is independent
from viewer backends.

The server object owns the listening socket. Each accepted peer owns its
transport, negotiation state, MCS user/channel state, share identifiers, and
activation lifecycle.

## Lifecycle

```c
librdp_server_config config;
librdp_server *server;
librdp_server_peer *peer;

librdp_server_config_init(&config);
config.bind_address = "127.0.0.1";
config.port = 3390;
config.desktop_width = 1024;
config.desktop_height = 768;

server = librdp_server_new(&config);
librdp_server_listen(server);
peer = librdp_server_accept(server, 1000);

while (peer) {
    librdp_status status = librdp_server_peer_run_once(peer, 50);
    if (status == LIBRDP_STATUS_CLOSED)
        break;
}

librdp_server_peer_free(peer);
librdp_server_free(server);
```

`librdp_server_peer_run_once()` is the only operation that advances a peer. It
processes X.224, MCS/GCC, domain setup, user attach, channel joins, Demand
Active, Confirm Active, and first active-share control PDUs. Applications can
observe peer state with `librdp_server_peer_get_state()`.

## Example Listener

```sh
build/librdp-example-server-listener --bind 127.0.0.1 --port 3390
```

The example is intentionally small: it shows listener setup and peer driving
without introducing an application-specific desktop model. Applications that
embed the server API own policy, graphics production, input handling, channels,
and resource access.

## Threading And Ownership

Server and peer handles are not internally synchronized. Drive each peer from
one owner thread or protect calls with external locking. Configuration strings
are copied during `librdp_server_new()`. Peer handles remain valid until
`librdp_server_peer_free()`.

## Security

Bind addresses, authentication policy, TLS policy, and exposed resources are
application decisions. Do not expose a listener on an untrusted network without
an explicit security policy. Trace output is redacted by default and must not be
used for credentials or raw user payloads.

See also: [API reference](api-reference.md), [Programmer's reference](programmers-reference.md),
and [librdp-server(7)](man/librdp-server.7).
