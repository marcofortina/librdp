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

TLS certificate verification is strict by default. `--accept-tls-certificate`
accepts the presented certificate for the current connection after printing
its host, subject, issuer, and SHA-256 fingerprint to stderr.

## Platform Integration

The viewer uses Cocoa text input for Unicode keyboard events and AppKit mouse
events for movement, buttons, wheels, and extra buttons. Pointer shape updates
from the session are applied through `NSCursor`; the viewer does not infer
cursor shape locally.

Clipboard text, HTML, and PNG payloads are bridged through `NSPasteboard`.
Local pasteboard text changes are advertised through the public clipboard API.

Framebuffer updates are rendered from the public BGRA surface using
CoreGraphics. Resize events are sent through the public session resize path.

