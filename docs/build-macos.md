<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build macOS

macOS builds the portable core, tests, examples, and optional native viewer,
administration, workspace, and shadow-server applications. X11 applications
are not part of the macOS build profile.

## Dependencies

With Homebrew:

```sh
brew update
brew install \
  cmake ninja pkg-config openssl@3 doxygen graphviz \
  ffmpeg openh264 pcsc-lite libusb libfido2 libcbor libarchive
```

## Core And Tests

```sh
cmake -S . -B build-macos -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOpenSSL_DIR="$(brew --prefix openssl@3)/lib/cmake/OpenSSL" \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_PNG=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-macos --parallel
ctest --test-dir build-macos --output-on-failure
```

The viewer, admin, workspace, and server applications use Cocoa and native
macOS frameworks. Building the server does not require Screen Recording or
Accessibility permission; those permissions are evaluated when its
corresponding runtime providers are requested.
