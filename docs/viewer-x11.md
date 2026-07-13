<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# X11 Viewer

`librdp-x11-viewer` is a minimal X11 frontend used to exercise the public client APIs. It is a debugging and integration tool, not a full desktop product.

## Build

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON -DLIBRDP_BUILD_X11_VIEWER=ON
cmake --build build -j$(nproc)
```

The executable is `build/librdp-x11-viewer`.

## Basic connection

```sh
build/librdp-x11-viewer --target host --user user --password password --security nla --width 1024 --height 768
```

Supported security values are:

- `auto`;
- `rdp`;
- `tls`;
- `nla`.

`nla` selects the CredSSP-based network-level authentication path. `tls` selects TLS transport security without NLA. `rdp` selects legacy standard security. `auto` lets negotiation select the security path.

TLS certificate verification is strict by default. `--tls-prompt-cert` shows the presented leaf certificate and asks before accepting it for the current connection. `--tls-accept-any-cert` accepts the presented certificate for the current connection without prompting and should be used only when the caller has explicitly chosen that trust policy.

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
--drive name=path
--serial name=path
--parallel name=path
--printer name=driver=path
--clipboard-file path
--audio-output [device=name]
--audio-input [device=name]
--video [file=path]
--camera device=/dev/videoN
--smartcard [pcsc|vsmartcard=path]
--usb vid:pid|bus:dev
--pnp
--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]
--rail app=path
--cr2
--echo
--telemetry
--multitransport
```

## Graphics and resize

The viewer creates an X11 window matching the requested desktop size. Resize requests are sent through the display control path when enabled by the session. Surface invalidation events are copied into the X11 drawable.

Pointer shape, pointer cache, pointer visibility, and local cursor presentation are driven by pointer events received from the session.

Resize is viewer-driven: X11 configure events update the requested desktop layout and the session receives a display-control request. The viewer should repaint from the current surface after local expose events and after remote surface invalidation.

Pointer updates are server-driven. The viewer does not infer local cursor shape from coordinates or window contents. It applies default, hidden, position, and shape events from the session and keeps a local X11 cursor cache for the active window.

## Input

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
- `--printer` can route output through the configured printer backend path.
- `--video` can write selected video output to a file path.

Device and media options are safe to combine:

```sh
build/librdp-x11-viewer \
    --target host \
    --security nla \
    --audio-output \
    --audio-input \
    --camera device=/dev/video0 \
    --smartcard pcsc \
    --webauthn fido2
```

Filesystem, printer, serial, and parallel paths are interpreted on the local host:

```sh
build/librdp-x11-viewer \
    --target host \
    --drive work=/home/user/work \
    --printer printer=Generic=/tmp/print-output \
    --serial COM1=/dev/ttyUSB0 \
    --parallel LPT1=/tmp/lpt-output
```

## Trace examples

Client and protocol trace:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1 build/librdp-x11-viewer --target host --security nla
```

Full debug trace with bounded hexdumps:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_TRANSPORT=1 LIBRDP_TRACE_PROTOCOL=1 LIBRDP_TRACE_LEVEL=trace LIBRDP_TRACE_HEX_BYTES=96 build/librdp-x11-viewer --target host --security nla
```

Do not place passwords in shell history on shared systems. Prefer controlled test credentials for viewer runs.

Useful event families while debugging the viewer include:

- `x11.keyboard.*` for keyboard translation and grabs;
- `x11.pointer.*` for cursor shape, visibility, and local cursor changes;
- `client.active.framebuffer.*` for surface presentation;
- `client.display_control.*` for resize requests;
- `x11.audio.*`, `x11.camera.*`, `x11.smartcard.*`, `x11.usb.*`, and `x11.webauthn.*` for backend setup.
