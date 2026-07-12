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

- `apps/x11-viewer` for the current X11 frontend and its host backends;
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

## macOS

macOS integration should use platform-native frontend code outside the core. A macOS viewer should translate Cocoa input, display, clipboard, audio, device, and security UI into the same public `librdp_settings`, `librdp_session`, `librdp_event`, and `librdp_surface` APIs used by other frontends.

macOS code should not introduce Objective-C or framework headers into public core headers.

## FreeBSD

FreeBSD integration should use portable socket, file, USB, PC/SC, and X11 paths where available. Backend detection should be CMake-driven and should fail closed when a provider is unavailable.

FreeBSD-specific behavior belongs behind platform or backend boundaries, not in protocol parsers or public API types.

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
