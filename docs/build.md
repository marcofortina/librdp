<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build

librdp uses CMake to build the C library, unit tests, examples, optional fuzz targets, and the X11 viewer. The core library is portable across Unix-like systems; platform-specific viewer and backend paths are enabled only when their dependencies are present.

## Platform Guides

- [Linux](build-linux.md)
- [macOS](build-macos.md)
- [FreeBSD](build-freebsd.md)
- [OpenBSD](build-openbsd.md)
- [NetBSD](build-netbsd.md)
- [Solaris](build-solaris.md)

## Required Tools

- CMake 3.16 or newer.
- A C11 compiler.
- OpenSSL 3.0 or newer.
- iconv.
- Python 3 for test and documentation guardrails.

## Common CMake Options

- `LIBRDP_BUILD_TESTS=ON|OFF`: build unit tests and repository guardrails.
- `LIBRDP_BUILD_FUZZ=ON|OFF`: build fuzz targets.
- `LIBRDP_BUILD_X11_VIEWER=ON|OFF`: build the X11 viewer.
- `LIBRDP_BUILD_COCOA_VIEWER=ON|OFF`: build the native Cocoa viewer.
- `LIBRDP_BUILD_X11_ADMIN=ON|OFF`: build the X11 administration inventory tool.
- `LIBRDP_BUILD_X11_WORKSPACE=ON|OFF`: build the X11 workspace feed launcher.
- `LIBRDP_BUILD_COCOA_ADMIN=ON|OFF`: build the native Cocoa administration inventory tool.
- `LIBRDP_BUILD_COCOA_WORKSPACE=ON|OFF`: build the native Cocoa workspace feed launcher.
- `LIBRDP_BUILD_EXAMPLES=ON|OFF`: build standalone C examples from `examples/`.
- `LIBRDP_ABI_VERSION=<n>`: shared-library ABI version used as `SOVERSION`.
- `LIBRDP_LIBRARY_TYPE=AUTO|STATIC|SHARED|BOTH`: choose the library artifacts to build. `AUTO` preserves the standard CMake `BUILD_SHARED_LIBS` behavior.
- `LIBRDP_ENABLE_WERROR=ON|OFF`: treat project warnings as errors on supported compilers.
- `LIBRDP_ENABLE_SANITIZERS=ON|OFF`: enable selected compiler sanitizers on project targets.
- `LIBRDP_SANITIZERS=address,undefined`: comma- or semicolon-separated sanitizer selection used when `LIBRDP_ENABLE_SANITIZERS=ON`.

Optional dependency selectors accept `AUTO`, `ON`, or `OFF`. `AUTO` detects the dependency when available, `ON` requires it during configuration, and `OFF` skips discovery and leaves the backend disabled.

- `LIBRDP_WITH_FFMPEG_AVC=AUTO|ON|OFF`: FFmpeg AVC decoder backend.
- `LIBRDP_WITH_OPENH264_AVC=AUTO|ON|OFF`: OpenH264 AVC decoder backend.
- `LIBRDP_WITH_PCSC=AUTO|ON|OFF`: PC/SC smartcard backend.
- `LIBRDP_WITH_LIBUSB=AUTO|ON|OFF`: libusb device backend.
- `LIBRDP_WITH_FIDO2=AUTO|ON|OFF`: FIDO2 authenticator backend.
- `LIBRDP_WITH_CBOR=AUTO|ON|OFF`: CBOR helpers for WebAuthn data.
- `LIBRDP_WITH_CUPS=AUTO|ON|OFF`: CUPS printer backend.
- `LIBRDP_WITH_ACL=AUTO|ON|OFF`: POSIX ACL filesystem metadata backend.
- `LIBRDP_WITH_ATTR=AUTO|ON|OFF`: extended attribute filesystem metadata backend.
- `LIBRDP_WITH_ARCHIVE=AUTO|ON|OFF`: archive-backed print payload support.
- `LIBRDP_WITH_CURL=AUTO|ON|OFF`: HTTP transport backends.
- `LIBRDP_WITH_LIBXML2=AUTO|ON|OFF`: workspace feed XML parsing.
- `LIBRDP_WITH_CAIRO=AUTO|ON|OFF`: Cairo GDI raster backend.
- `LIBRDP_WITH_QUARTZ=AUTO|ON|OFF`: Core Graphics GDI raster backend on macOS.
- `LIBRDP_WITH_PNG=AUTO|ON|OFF`: PNG decoding for compressed GDI+ images.
- `LIBRDP_WITH_PIPEWIRE=AUTO|ON|OFF`: PipeWire audio backend in the X11 viewer.
- `LIBRDP_WITH_JPEG=AUTO|ON|OFF`: JPEG decoding for GDI+ images and X11 camera conversion.
- `LIBRDP_WITH_XSHM=AUTO|ON|OFF`: MIT-SHM presentation path in the X11 viewer.
- `LIBRDP_WITH_XRANDR=AUTO|ON|OFF`: XRandR monitor layout bridge in the X11 viewer.

## Build Directories

Use separate `build-*` directories for different configurations. Build output is ignored by Git and must not be used for source files.
