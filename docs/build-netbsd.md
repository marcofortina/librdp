<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build NetBSD

NetBSD builds the portable core, tests, and examples in CI. The X11 viewer can be built separately when X11 dependencies are installed.

## Dependencies

```sh
pkg_add \
  cmake ninja-build pkgconf openssl libiconv python312 doxygen graphviz
pkg_add \
  ffmpeg4 openh264 pcsc-lite libusb1 libfido2 libcbor cups libarchive
```

If the Python package installs only `python3.12`, create a local `python3` alias in the build environment.

## Core And Tests

```sh
cmake -S . -B build-netbsd -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/usr/pkg \
  -DCMAKE_PREFIX_PATH=/usr/pkg \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=ON \
  -DLIBRDP_BUILD_VIEWER=OFF \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_PNG=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-netbsd --parallel
ctest --test-dir build-netbsd --output-on-failure
```
