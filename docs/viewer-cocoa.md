<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Cocoa Viewer

`librdp-cocoa-viewer` is the native macOS frontend. It uses AppKit for
windowing, rendering, input, cursor presentation, clipboard access, and TLS
certificate prompts, while all protocol work stays behind the public librdp
client APIs.

## Build

```sh
cmake -S . -B build-macos -G Ninja \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_X11_VIEWER=OFF \
  -DLIBRDP_BUILD_COCOA_VIEWER=ON
cmake --build build-macos --parallel
```

The executable is `build-macos/librdp-cocoa-viewer`.

## Basic Connection

```sh
build-macos/librdp-cocoa-viewer --target host --user user --password password --security nla
```

Supported security values are:

- `auto`;
- `rdp`;
- `tls`;
- `nla`.

TLS certificate verification is strict by default. `--tls-prompt-cert` prints
the presented certificate and asks whether to trust it for the current
connection. `--tls-accept-any-cert` accepts the certificate for the current
connection without prompting after printing the same details.
`--accept-tls-certificate` is kept as a compatibility alias for the automatic
accept path.

RemoteApp launches can be requested with `--rail app=<program>`.

Gateway tunneling can be configured with `--gateway <url>`. The gateway mode is
`http-connect` by default; use `--gateway-mode rdg-http` for Microsoft RD
Gateway HTTP transport. Gateway credentials can be supplied separately with
`--gateway-user`, `--gateway-password`, and `--gateway-domain`, or inherited
from the session credentials by default.

## Session Features

The Cocoa viewer accepts the same public session feature switches as the X11
viewer:

- `--drive name=path`;
- `--serial name=path`;
- `--parallel name=path`;
- `--printer name=driver=path`;
- `--audio-output [device=name]`;
- `--audio-input [device=name]`;
- `--video file=path`;
- `--camera device=default|device=id|file=path`;
- `--smartcard [pcsc|source]`;
- `--usb vid:pid|bus:dev`;
- `--pnp`;
- `--webauthn [fido2|mock|provider]`;
- `--webauthn-rp-id id`;
- `--cr2`;
- `--echo`;
- `--telemetry`;
- `--multitransport`.

These switches configure the public librdp settings object. Audio uses
CoreAudio queues. Video output can be written to a file sink. Camera redirection
uses AVFoundation for live devices and keeps a bounded file source for
deterministic capture smoke paths.

## Platform Integration

The viewer uses Cocoa text input for Unicode keyboard events and AppKit mouse
events for movement, buttons, wheels, and extra buttons. Pointer shape updates
from the session are applied through `NSCursor`; the viewer does not infer
cursor shape locally.

Clipboard text, HTML, and PNG payloads are bridged through `NSPasteboard`.
Local pasteboard text changes are advertised through the public clipboard API.

Framebuffer updates are rendered from the public BGRA surface using
CoreGraphics. Resize events are sent through the public session resize path.
