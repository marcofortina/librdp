<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build FreeBSD

FreeBSD builds the portable core, tests, and examples in CI. The X11 viewer can be built separately when X11 dependencies are installed.

## Dependencies

```sh
sudo pkg install -y \
  cmake ninja pkgconf openssl libiconv python3 doxygen graphviz \
  ffmpeg openh264 pcsc-lite libusb libfido2 libcbor cups libarchive
```

## Core And Tests

```sh
cmake -S . -B build-freebsd -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/usr/local \
  -DCMAKE_PREFIX_PATH=/usr/local \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=ON \
  -DLIBRDP_BUILD_X11_VIEWER=OFF \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-freebsd --parallel
ctest --test-dir build-freebsd --output-on-failure
```
