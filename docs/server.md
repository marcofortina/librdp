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
config.width = 1024;
config.height = 768;

server = librdp_server_new(&config);
librdp_server_listen(server);
if (librdp_server_accept(server, 1000, &peer) != LIBRDP_STATUS_OK)
    peer = NULL;

while (peer) {
    librdp_status status = librdp_server_peer_run_once(peer, 50);
    if (status == LIBRDP_STATUS_CLOSED)
        break;
}

librdp_server_peer_free(peer);
librdp_server_free(server);
```

`librdp_server_peer_run_once()` is the operation that advances a peer. It
processes X.224, MCS/GCC, domain setup, user attach, channel joins, Demand
Active, Confirm Active, active-share control PDUs, input PDUs, refresh requests,
output suppression, and static-channel payload delivery. Applications can
observe peer state with `librdp_server_peer_get_state()`.

## Runtime Surfaces And Channels

After a peer reaches `LIBRDP_SERVER_PEER_ACTIVE`, applications can copy BGRA32
pixels into the peer surface with `librdp_server_peer_surface_blit_bgra32()` and
send dirty rectangles with `librdp_server_peer_surface_present()`. Resize is
handled through `librdp_server_peer_surface_resize()`, which starts a normal
reactivation when the peer is already active. Use
`librdp_server_peer_desktop_width()` and
`librdp_server_peer_desktop_height()` to generate pixels for the desktop size
negotiated with the client.

Input and static-channel callbacks are installed with
`librdp_server_peer_set_input_callback()` and
`librdp_server_peer_set_channel_callback()`. Static channels advertised by the
client can be queried with `librdp_server_peer_static_channel_count()` and
`librdp_server_peer_static_channel_at()`.

Runtime events are installed with `librdp_server_peer_set_event_callback()`.
They report peer state changes, accepted surface updates, static-channel joins,
and redacted error records. Applications that need a durable diagnostic record
can copy `librdp_server_status` with `librdp_server_peer_get_last_status()`.
`librdp_server_peer_close()` closes the peer transport while keeping the handle
valid for final status and metrics queries.

## Example Listener

```sh
build/librdp-example-server-listener --bind 127.0.0.1 --port 3390 --width 1024 --height 768
```

The example accepts one peer, drives activation, sends a generated BGRA desktop
surface, prints input/runtime events, and lists static channels using only
public server APIs.

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
[X11 desktop server](server-x11.md), and
[librdp-server(7)](man/librdp-server.7).
