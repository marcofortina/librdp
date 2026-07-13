<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Backends

The core library keeps host-specific work behind public settings and viewer or application backends. Optional system libraries enable richer behavior but are not required for the core build.

This page is the backend map. The operational contract for each backend is in [Backend guide](backend-guide.md).

## Backend matrix

| Feature | Library or provider | Used by |
| --- | --- | --- |
| Audio output | PipeWire | X11 viewer playback backend |
| Audio input | PipeWire | X11 viewer capture backend |
| Camera | V4L2 device path | X11 viewer video capture backend |
| Smartcard | PC/SC or controlled virtual source | Smartcard redirection |
| USB | libusb | USB redirection |
| WebAuthn | libfido2, libcbor, or controlled mock provider | WebAuthn redirection |
| Printer | CUPS or file output path | Printer and XPS paths |
| Filesystem metadata | libacl, libattr, libarchive | Filesystem redirection |
| Video output | file sink selected by settings | Video redirection testing path |
| Keyboard input | XKB through X11/xkbcommon in the viewer | X11 viewer input translation |
| Pointer shape | Xcursor and Xfixes in the viewer | X11 viewer cursor presentation |

## Configuration model

Applications configure backend intent through `librdp_settings`. The library stores the configuration and advertises or activates protocol features as appropriate. Viewer applications still own the host-side device handles and user policy.

Missing optional libraries should produce unavailable backend behavior, not a failed core build.

## Audio

Audio output and audio input are configured through `LIBRDP_FEATURE_AUDIO_OUTPUT`, `LIBRDP_FEATURE_AUDIO_INPUT`, `librdp_settings_set_audio_output_device()`, and `librdp_settings_set_audio_input_device()`.

The X11 viewer uses PipeWire when it is available at build time:

```sh
build/librdp-x11-viewer --target host --audio-output
build/librdp-x11-viewer --target host --audio-input
build/librdp-x11-viewer --target host --audio-output device=pipewire --audio-input device=pipewire
```

PipeWire streams are owned by the viewer backend. The core receives or emits protocol audio events and never owns PipeWire handles.

## Camera and video

Camera capture uses a viewer-owned V4L2 source selected by path:

```sh
build/librdp-x11-viewer --target host --camera device=/dev/video0
```

Video output can be directed to a file sink:

```sh
build/librdp-x11-viewer --target host --video file=/tmp/librdp-video.bin
```

Applications should treat camera frames and video payloads as sensitive user data. Trace events should describe frame metadata and backend state, not dump full frame contents.

## Smartcard

Smartcard redirection can use PC/SC or a controlled virtual source:

```sh
build/librdp-x11-viewer --target host --smartcard pcsc
build/librdp-x11-viewer --target host --smartcard vsmartcard=/path/to/socket
```

PC/SC context and card handles belong to the viewer backend. APDU payload handling belongs to the smartcard channel path and must preserve request ordering.

## USB and PNP

USB devices are selected with either vendor/product or bus/device notation:

```sh
build/librdp-x11-viewer --target host --usb 1234:5678
build/librdp-x11-viewer --target host --usb 001:004
```

PNP device descriptors are configured through public settings and advertised through the device redirection path. The viewer `--pnp` flag enables the feature path for practical runs.

## Filesystem, serial, parallel, and printer

Drive redirection maps a local directory to a remote drive name:

```sh
build/librdp-x11-viewer --target host --drive work=/home/user/work
```

Serial and parallel ports map a remote name to a local path:

```sh
build/librdp-x11-viewer --target host --serial COM1=/dev/ttyUSB0
build/librdp-x11-viewer --target host --parallel LPT1=/tmp/lpt-output
```

Printer configuration uses `name=driver=path`:

```sh
build/librdp-x11-viewer --target host --printer printer=Generic=/tmp/print-output
```

The filesystem path is viewer-owned. The library packet path enforces protocol sizes, file identifiers, and request ordering.

## WebAuthn

WebAuthn redirection can use libfido2 or a controlled mock provider:

```sh
build/librdp-x11-viewer --target host --webauthn fido2
build/librdp-x11-viewer --target host --webauthn fido2=/dev/hidraw0
build/librdp-x11-viewer --target host --webauthn mock
build/librdp-x11-viewer --target host --webauthn mock=/path/to/provider
```

Authenticator handles and user-presence policy belong to the backend. Protocol code must not trace assertion secrets.

## Remote applications, composition, echo, telemetry, and multitransport

The viewer exposes feature flags for channel paths that do not require a complex local device:

```sh
build/librdp-x11-viewer --target host --rail app=/path/to/app
build/librdp-x11-viewer --target host --cr2
build/librdp-x11-viewer --target host --echo
build/librdp-x11-viewer --target host --telemetry
build/librdp-x11-viewer --target host --multitransport
```

`--telemetry` requests telemetry packet support status. The core reports the
feature as parser-only unless an application supplies a privacy-safe runtime
path.

These flags configure the public settings object and route packet behavior through the corresponding channel modules.

## Backend failure reporting

Backends report failures through:

- public API status when configuration fails;
- session events when a runtime protocol path fails;
- client trace events when a host backend cannot open or cannot satisfy a request.

Trace messages should identify the backend, operation, and failure stage without exposing credentials or private payloads.

## Backend development rules

New backends should:

- keep platform-specific headers out of public core headers;
- use CMake feature detection;
- fail closed when a local device cannot be opened safely;
- document ownership and threading;
- provide unit or fuzz coverage for packet-facing logic;
- provide a viewer or controlled test path for exercising the backend.
