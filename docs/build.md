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
