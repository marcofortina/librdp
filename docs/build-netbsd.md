<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build NetBSD

NetBSD CI builds the portable core and all four X11 applications.

## Dependencies

```sh
pkg_add \
  cmake ninja-build pkgconf openssl libiconv python312 doxygen graphviz \
  libXcursor libxkbcommon
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
  -DLIBRDP_BUILD_SERVER=OFF \
  -DLIBRDP_BUILD_ADMIN=OFF \
  -DLIBRDP_BUILD_WORKSPACE=OFF \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_PNG=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-netbsd --parallel
ctest --test-dir build-netbsd --output-on-failure
```

## X11 Applications

```sh
export PKG_CONFIG_PATH="/usr/pkg/lib/pkgconfig:/usr/X11R7/lib/pkgconfig"
cmake -S . -B build-netbsd-apps -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/usr/pkg \
  -DCMAKE_PREFIX_PATH="/usr/pkg;/usr/X11R7" \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_XSHM=ON \
  -DLIBRDP_WITH_XRANDR=ON \
  -DLIBRDP_WITH_PAM=ON
cmake --build build-netbsd-apps --parallel
ctest --test-dir build-netbsd-apps --output-on-failure
```
