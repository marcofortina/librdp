<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# librdp

librdp is a C client library for building RDP viewers and integration tools on Unix-like systems. The core is platform-neutral and exposes public APIs for sessions, settings, events, surfaces, input, clipboard, audio, video, and channels.

## Start here

- [Build](build.md)
- [Build Linux](build-linux.md)
- [Build macOS](build-macos.md)
- [Build FreeBSD](build-freebsd.md)
- [Build OpenBSD](build-openbsd.md)
- [Build NetBSD](build-netbsd.md)
- [Build Solaris](build-solaris.md)
- [API guide](api.md) for the usual session, event, surface, input, and channel flow.
- [Programmer's reference](programmers-reference.md) for application architecture and integration rules.
- [API reference](api-reference.md) for the public header map and object model.
- [Generated API documentation](generated-api.md) for Doxygen per-symbol pages.
- [Examples](examples.md)
- [X11 viewer](viewer-x11.md)
- [Cocoa viewer](viewer-cocoa.md)

## Engineering references

- [Architecture](architecture.md)
- [Lifecycle](lifecycle.md)
- [Protocol support](protocol-support.md)
- [Backends](backends.md)
- [Backend guide](backend-guide.md)
- [Glossary](glossary.md)
- [Portability](portability.md)
- [ABI and versioning](abi-versioning.md)
- [Coding standards](coding-standards.md)
- [Contributing](contributing.md)

## Operations

- [Security](security.md)
- [Tracing](tracing.md)
- [Diagnostics](diagnostics.md)
- [Testing](testing.md)
- [Fuzzing](fuzzing.md)
- [Packaging](packaging.md)

## Manual pages

- [librdp(7)](man/librdp.7)
- [librdp-api(7)](man/librdp-api.7)
- [librdp-tracing(7)](man/librdp-tracing.7)
- [librdp-workspace(7)](man/librdp-workspace.7)
- [librdp-cocoa-viewer(1)](man/librdp-cocoa-viewer.1)
- [librdp-x11-admin(1)](man/librdp-x11-admin.1)
- [librdp-x11-workspace(1)](man/librdp-x11-workspace.1)
- [librdp-x11-viewer(1)](man/librdp-x11-viewer.1)

## Doxygen HTML

The generated Doxygen reference is built from `include/librdp/*.h` and contains the detailed per-symbol API pages.

- [Open generated API documentation](https://marcofortina.github.io/librdp/api/doxygen/html/index.html)

It can also be built locally with:

```sh
cmake --build build --target docs-api
```
