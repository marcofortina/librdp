<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Cocoa Desktop Server

`librdp-cocoa-server` shares a display or window from the active macOS
graphical session. It uses ScreenCaptureKit for capture, CoreGraphics for
keyboard and pointer injection, NSPasteboard for clipboard exchange, and the
public librdp server API for the RDP connection.

Build the server on macOS 12.3 or newer with:

```sh
cmake -S . -B build-macos -G Ninja \
  -DOpenSSL_DIR="$(brew --prefix openssl@3)/lib/cmake/OpenSSL" \
  -DLIBRDP_BUILD_SERVER=ON
cmake --build build-macos --target librdp-cocoa-server
```

## Capture Sources

The server operates in shadow mode. `display:index` selects a display by its
position in the ScreenCaptureKit display list; `window:id` selects a nonzero
CoreGraphics window identifier.

```sh
librdp-cocoa-server \
  --mode shadow \
  --source display:0 \
  --bind 127.0.0.1 \
  --security tls \
  --tls-cert /etc/librdp/server.crt \
  --tls-key /etc/librdp/server.key \
  --allow-capture
```

Managed login sessions are not exposed because public macOS APIs do not create
an independent WindowServer login session. The selected display or window must
belong to the graphical session running the server.

## Permissions

Capture requires Screen Recording permission. Remote keyboard and pointer
injection additionally require Accessibility permission. The
`--allow-clipboard` and `--allow-drive` options present independent local
consent prompts before those providers are enabled.

`--allow-capture` is mandatory. Input, clipboard, and client-drive access stay
disabled unless their corresponding `--allow-*` option is present. If one
optional permission is denied, the server keeps running without that provider.

`--non-interactive` suppresses permission requests and application consent
dialogs. Screen Recording and Accessibility must already be granted; otherwise
the affected provider remains unavailable. Clipboard and drive access still
require their explicit command-line grants.

Sending `SIGUSR1` revokes capture, input, clipboard, and drive access without
restarting the listener. `SIGINT` and `SIGTERM` stop the server and release
peers and native resources.

## Security

TLS is the default. TLS and NLA require absolute certificate and private-key
paths. NLA also requires an account name and reads its authentication secret
from the environment variable selected by `--password-env`.

```sh
export LIBRDP_SERVER_PASSWORD='account secret'
librdp-cocoa-server \
  --source display:0 \
  --security nla \
  --tls-cert /etc/librdp/server.crt \
  --tls-key /etc/librdp/server.key \
  --user account \
  --domain example \
  --password-env LIBRDP_SERVER_PASSWORD \
  --allow-capture
unset LIBRDP_SERVER_PASSWORD
```

Standard RDP Security is rejected unless both `--security standard` and
`--allow-standard-security` are supplied. It should be limited to isolated
compatibility environments.

## Client Drives

`--allow-drive` requires an absolute `--drive-mount` path and an available
FUSE 3 provider. Client-announced drives are mounted beneath that isolated path
and are always read-only in the Cocoa server. Drive handles and pending
requests are scoped to the peer that announced them and are invalidated on
disconnect.

The server does not expose files from the macOS host to the RDP client through
this option. It presents drives redirected by the connecting client to the
local server application.

See [Server API](server.md), [X11 desktop server](server-x11.md), and
[librdp-cocoa-server(1)](man/librdp-cocoa-server.1).
