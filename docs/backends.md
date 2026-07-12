<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Backends

The core library keeps host-specific work behind public settings and viewer or application backends. Optional system libraries enable richer behavior but are not required for the core build.

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
- provide a viewer or controlled test path for practical validation.
