<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Viewer

`librdp-viewer` is the native frontend for the public client API. CMake selects
Cocoa on macOS and X11 on Linux, FreeBSD, OpenBSD, NetBSD, and Solaris. Both
frontends use the same session configuration and protocol runtime.

## Build

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON -DLIBRDP_BUILD_VIEWER=ON
cmake --build build -j$(nproc)
```

The executable is `build/librdp-viewer`.

## Basic connection

```sh
build/librdp-viewer --target host --user user --password password --security nla --width 1024 --height 768
```

Supported security values are:

- `auto`;
- `rdp`;
- `tls`;
- `nla`.

`nla` selects the CredSSP-based network-level authentication path. `tls` selects TLS transport security without NLA. `rdp` selects legacy standard security. `auto` lets negotiation select the security path.

TLS certificate verification is strict by default. `--tls-prompt-cert` shows the presented leaf certificate and asks before accepting it for the current connection. `--tls-accept-any-cert` accepts the presented certificate for the current connection without prompting and should be used only when the caller has explicitly chosen that trust policy.

`--gateway` configures an intermediate gateway endpoint. The default `--gateway-mode http-connect` tunnels the target connection through a generic HTTP CONNECT proxy. `--gateway-mode rdg-http` selects Microsoft RD Gateway HTTP transport, establishes the RDG OUT/IN streams, creates the RDG tunnel and channel, then carries the normal RDP connection through that channel. Dedicated gateway credentials can be supplied with `--gateway-user`, `--gateway-password`, and `--gateway-domain`; otherwise the viewer can reuse session credentials. `--gateway-no-session-credentials` disables that reuse, and `--gateway-timeout` sets the gateway connection timeout in milliseconds.

## Options

```text
--target host
--port port
--user name
--password value
--domain name
--width px
--height px
--security auto|rdp|tls|nla
--tls-prompt-cert
--tls-accept-any-cert
--gateway url
--gateway-mode http-connect|rdg-http
--gateway-user name
--gateway-password value
--gateway-domain name
--gateway-timeout ms
--gateway-no-session-credentials
--drive name=path
--serial name=path
--parallel name=path
--printer name=driver=path
--clipboard-file path
--audio-output [device=name]
--audio-input [device=name]
--video file=path
--camera source
--smartcard [pcsc|vsmartcard=path]
--usb vid:pid|bus:dev
--pnp
--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]
--webauthn-rp-id id
--rail app=path
--cr2
--echo
--telemetry
--multitransport
```

`--clipboard-file` is available on X11. Camera sources are
`device=/dev/videoN` on X11 and `device=default`, `device=id`, or `file=path`
on macOS.

## Graphics And Resize

The viewer creates a native window matching the requested desktop size. Resize
requests are sent through the display control path when enabled by the session.
Surface invalidation events are copied into the selected native drawable.

Pointer shape, pointer cache, pointer visibility, and local cursor presentation are driven by pointer events received from the session.

Resize is viewer-driven: native configure events update the requested desktop
layout and the session receives a display-control request. The viewer repaints
from the current surface after local expose events and remote invalidation.

Pointer updates are server-driven. The viewer does not infer local cursor shape
from coordinates or window contents. It applies default, hidden, position, and
shape events from the session and keeps a native cursor cache.

## X11 Integration

Keyboard input is translated through the local X11/XKB stack. The viewer handles focus, keyboard grabs, modifier state, AltGr, dead-key text paths, and remote scancode submission.

Mouse movement, primary buttons, middle button, secondary button, vertical wheel, horizontal wheel, and extra button events are forwarded through the public input API.

When the viewer has focus and the pointer is inside the window, keyboard grab behavior keeps combinations such as Alt+Tab in the remote session where the window manager allows grabs.

On focus loss, the viewer releases remote key state before releasing the local grab. This avoids leaving remote modifiers pressed when the host window manager or compositor changes focus.

For Xwayland, the viewer sets `_XWAYLAND_MAY_GRAB_KEYBOARD` before requesting keyboard grabs.

## Optional backends

- `--audio-output` and `--audio-input` use PipeWire when available.
- `--camera` uses a V4L2 device path.
- `--smartcard` uses PC/SC or a controlled virtual source.
- `--usb` uses libusb selectors.
- `--webauthn` uses libfido2, a hidraw device, or a controlled mock provider.
- `--webauthn-rp-id` adds an RP ID allowlist entry for WebAuthn requests and is required when WebAuthn is enabled.
- `--printer` can route output through the configured printer backend path.
- `--video` can write selected video output to a file path.

Device and media options are safe to combine:

```sh
build/librdp-viewer \
    --target host \
    --security nla \
    --audio-output \
    --audio-input \
    --camera device=/dev/video0 \
    --smartcard pcsc \
    --webauthn fido2 \
    --webauthn-rp-id login.example.com
```

Filesystem, printer, serial, and parallel paths are interpreted on the local host:

```sh
build/librdp-viewer \
    --target host \
    --drive work=/home/user/work \
    --printer printer=Generic=/tmp/print-output \
    --serial COM1=/dev/ttyUSB0 \
    --parallel LPT1=/tmp/lpt-output
```

## macOS Integration

The Cocoa frontend uses AppKit text input for Unicode keyboard events and
AppKit mouse events for movement, buttons, wheels, and extra buttons. Pointer
shape updates are applied through `NSCursor`.

Clipboard text, HTML, and PNG payloads are bridged through `NSPasteboard`.
Framebuffer updates are rendered from the public BGRA surface with
CoreGraphics. Audio uses Core Audio queues, and AVFoundation provides live
camera capture. A bounded file camera source is also available for controlled
input.

## Trace examples

Client and protocol trace:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1 build/librdp-viewer --target host --security nla
```

Full debug trace with bounded hexdumps:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_TRANSPORT=1 LIBRDP_TRACE_PROTOCOL=1 LIBRDP_TRACE_LEVEL=trace LIBRDP_TRACE_HEX_BYTES=96 build/librdp-viewer --target host --security nla
```

Do not place passwords in shell history on shared systems. Prefer controlled test credentials for viewer runs.

Useful event families while debugging the viewer include:

- `x11.keyboard.*` for keyboard translation and grabs;
- `x11.pointer.*` for cursor shape, visibility, and local cursor changes;
- `client.active.framebuffer.*` for surface presentation;
- `client.display_control.*` for resize requests;
- `x11.audio.*`, `x11.camera.*`, `x11.smartcard.*`, `x11.usb.*`, and `x11.webauthn.*` for backend setup.

The Cocoa frontend emits corresponding `cocoa.*` events for native window,
input, media, and permission behavior.
