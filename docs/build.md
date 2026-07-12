<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build

This project uses CMake and builds a C11 library named `librdp`. The core library has a small required dependency set and enables optional protocol backends when their system libraries are available.

## Required tools

- CMake 3.16 or newer.
- A C11 compiler.
- OpenSSL 3.0 or newer.
- iconv.

## Optional libraries

Optional libraries are detected through CMake and `pkg-config` where available:

- FFmpeg libraries: `libavcodec`, `libavutil`, `libswscale`.
- OpenH264: `openh264`.
- PC/SC: `libpcsclite`.
- USB: `libusb-1.0`.
- WebAuthn/FIDO2: `libfido2` and `libcbor`.
- Printing: `cups`.
- Filesystem metadata: `libacl`, `libattr`, `libarchive`.
- X11 viewer: X11, Xcursor, Xfixes, xkbcommon, pthreads.
- X11 viewer audio: PipeWire `libpipewire-0.3`.
- X11 viewer image conversion paths: `libjpeg`.

The build does not require optional libraries unless the feature or viewer path that uses them is enabled.

## CMake options

- `LIBRDP_BUILD_TESTS=ON|OFF`: build unit tests and documentation guardrails.
- `LIBRDP_BUILD_FUZZ=ON|OFF`: build fuzz targets.
- `LIBRDP_BUILD_X11_VIEWER=ON|OFF`: build the X11 viewer.
- `LIBRDP_BUILD_EXAMPLES=ON|OFF`: build standalone C examples from `examples/`.
- `LIBRDP_ABI_VERSION=<n>`: shared-library ABI version used as `SOVERSION`.

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
- `LIBRDP_WITH_PIPEWIRE=AUTO|ON|OFF`: PipeWire audio backend in the X11 viewer.
- `LIBRDP_WITH_JPEG=AUTO|ON|OFF`: JPEG camera conversion backend in the X11 viewer.

## Library and tests

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

## X11 viewer

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON -DLIBRDP_BUILD_X11_VIEWER=ON
cmake --build build -j$(nproc)
```

The viewer executable is `build/librdp-x11-viewer`.

## Fuzz targets

With Clang, CMake links fuzz targets with libFuzzer, AddressSanitizer, and UndefinedBehaviorSanitizer:

```sh
CC=clang cmake -S . -B build-fuzz-clang -DLIBRDP_BUILD_FUZZ=ON
cmake --build build-fuzz-clang -j$(nproc)
```

With non-Clang compilers, fuzz targets use the repository standalone harness and read one input from standard input.

## Generated output

Build output is expected under `build/` or `build-*` directories. These directories are ignored by Git and must not be used for source files.
