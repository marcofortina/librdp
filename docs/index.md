<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# librdp

librdp is a C client library for building RDP viewers and integration tools on Unix-like systems. The core is platform-neutral and exposes public APIs for sessions, settings, events, surfaces, input, clipboard, audio, video, and channels.

## Start here

- [Build](build.md)
- [API guide](api.md)
- [API reference](api-reference.md)
- [Programmer's reference](programmers-reference.md)
- [Examples](examples.md)
- [X11 viewer](viewer-x11.md)

## Engineering references

- [Architecture](architecture.md)
- [Protocol support](protocol-support.md)
- [Backends](backends.md)
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
- [librdp-x11-viewer(1)](man/librdp-x11-viewer.1)

## Doxygen HTML

The Doxygen API reference is published under `api/doxygen/html/` by the GitHub Pages workflow and can also be built locally with:

```sh
cmake --build build --target docs-api
```
