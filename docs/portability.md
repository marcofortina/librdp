<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Portability

librdp targets Linux, macOS, and FreeBSD. The core library is designed around portable C, explicit platform abstraction, and optional host backends.

## Portability boundary

Core protocol code must remain independent from window systems, audio servers, device APIs, and operating-system-specific UI policy.

Allowed in the core:

- standard C11;
- POSIX-compatible socket and timing abstractions behind `src/platform`;
- OpenSSL, iconv, and optional protocol-support libraries selected by CMake;
- protocol parsers, codecs, state machines, transport framing, and public client APIs.

Not allowed in the core:

- X11, Wayland, Cocoa, AppKit, UIKit, or desktop UI headers;
- PipeWire, V4L2, PC/SC, libusb, FIDO2, or CUPS handles in public headers;
- Linux-only ioctl assumptions outside backend files;
- Windows registry, COM, Win32, or path assumptions;
- host window-manager policy.

## Platform-specific code

Platform-specific behavior belongs in one of these areas:

- `apps/x11/viewer` for the current X11 frontend and its host backends;
- `src/platform` for small reusable OS abstractions needed by the core;
- future platform backend directories that do not leak native handles into public core headers.

When adding platform code, keep the public API stable and expose capability through settings, events, and opaque handles rather than native platform types.

## Linux

Linux provides the richest backend set for the current viewer:

- X11/Xwayland for windowing;
- xkbcommon and XKB for keyboard translation;
- PipeWire for audio input and output;
- V4L2 for camera capture;
- PC/SC for smartcards;
- libusb for USB;
- libfido2 and libcbor for WebAuthn;
- CUPS for printing;
- libacl, libattr, and libarchive for filesystem metadata support.

Linux-only backends must be compiled conditionally and must not be required for the core library.

## Backend portability matrix

| Feature | Linux provider | macOS provider expectation | FreeBSD provider expectation | Public API stability rule |
| --- | --- | --- | --- | --- |
| Window presentation | X11/Xwayland viewer | Native viewer outside core | X11 or native viewer outside core | Keep window handles out of public headers. |
| Keyboard and pointer | X11/XKB/xkbcommon | Native input stack translated to public input structs | X11/XKB or native stack translated to public input structs | Public input structs remain platform-neutral. |
| Audio output/input | PipeWire | Native audio backend outside core | Native or PipeWire-compatible backend outside core | Audio public API carries formats and bytes only. |
| Camera | V4L2 | Native capture backend outside core | V4L2-compatible or native capture backend outside core | Camera device handles remain backend-owned. |
| Clipboard | Viewer integration | Native pasteboard integration outside core | Viewer integration outside core | Clipboard APIs carry copied bytes and borrowed events. |
| Smartcard | PC/SC | PC/SC-compatible provider outside core | PC/SC-compatible provider outside core | Card handles are never public API types. |
| USB | libusb | libusb or native USB backend outside core | libusb backend outside core | USB selectors are settings strings or descriptors. |
| WebAuthn | libfido2/libcbor | platform or libfido2 provider outside core | libfido2 provider outside core | Authenticator handles and assertions remain backend-private. |
| Printer | CUPS or file path | native print backend or file path outside core | CUPS or file path outside core | Printer configuration uses portable settings strings. |
| Filesystem metadata | POSIX, ACL, xattr, archive libs | native metadata adapter outside core | POSIX, ACL, xattr adapters outside core | Remote-visible metadata is normalized by protocol code. |

## macOS

macOS integration should use platform-native frontend code outside the core. A macOS viewer should translate Cocoa input, display, clipboard, audio, device, and security UI into the same public `librdp_settings`, `librdp_session`, `librdp_event`, and `librdp_surface` APIs used by other frontends.

macOS code should not introduce Objective-C or framework headers into public core headers.

macOS-specific implementation should keep Objective-C, CoreFoundation, Security framework, audio, camera, pasteboard, and display objects in a platform viewer or backend layer. Core code should see only public settings, copied bytes, event payloads, and protocol-neutral descriptors.

## FreeBSD

FreeBSD integration should use portable socket, file, USB, PC/SC, and X11 paths where available. Backend detection should be CMake-driven and should fail closed when a provider is unavailable.

FreeBSD-specific behavior belongs behind platform or backend boundaries, not in protocol parsers or public API types.

FreeBSD backend code should avoid Linux-only device assumptions. When an optional provider differs from Linux, the backend should expose the same public behavior and trace failure stage through the same event family.

## Data model rules

Portable code must avoid assumptions about:

- pointer size;
- structure packing;
- integer signedness beyond fixed-width types;
- filesystem path syntax;
- locale encoding;
- socket readiness primitives;
- unaligned memory access;
- host endianess.

Protocol code should use explicit little-endian helpers and bounded stream readers or writers.

## Adding a backend

New backend work should follow this pattern:

1. Add a public setting or feature flag only when the behavior belongs in the stable API.
2. Keep native handles private to the backend implementation.
3. Detect optional libraries through CMake.
4. Provide trace events for setup, shutdown, and failure.
5. Add unit or fuzz coverage for packet-facing logic.
6. Document the backend in [Backends](backends.md).

If a feature cannot be implemented on all target platforms, the API should still fail predictably and document which backend providers can satisfy it.

## Portability review checklist

Before merging platform-specific code:

1. Confirm no native platform type appears in `include/librdp/*.h`.
2. Confirm optional provider detection is CMake-driven.
3. Confirm the core build succeeds without the optional provider.
4. Confirm unavailable providers fail closed with traceable errors.
5. Confirm callbacks and public structs keep the same ownership rules across platforms.
6. Confirm path, locale, endian, and alignment assumptions are explicit.
7. Confirm docs identify the backend provider and trust boundary.
