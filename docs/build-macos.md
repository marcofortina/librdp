<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build macOS

macOS builds the portable core, tests, and examples. The X11 viewer is not part of the macOS build profile.

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
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=ON \
  -DLIBRDP_BUILD_X11_VIEWER=OFF \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-macos --parallel
ctest --test-dir build-macos --output-on-failure
```

The disabled options are viewer-specific paths that require the X11 viewer profile.
