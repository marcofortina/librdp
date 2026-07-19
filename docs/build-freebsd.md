<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build FreeBSD

FreeBSD CI builds the portable core and all four X11 applications.

## Dependencies

```sh
sudo pkg install -y \
  cmake ninja pkgconf openssl libiconv python3 doxygen graphviz \
  ffmpeg openh264 pcsc-lite libusb libfido2 libcbor cups libarchive \
  libX11 libXau libXcomposite libXcursor libXdamage libXfixes \
  libXext libXrandr libXtst libxkbcommon xorg-vfbserver
```

## Core And Tests

```sh
cmake -S . -B build-freebsd -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/usr/local \
  -DCMAKE_PREFIX_PATH=/usr/local \
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
cmake --build build-freebsd --parallel
ctest --test-dir build-freebsd --output-on-failure
```

## X11 Applications

```sh
cmake -S . -B build-freebsd-apps -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/usr/local \
  -DCMAKE_PREFIX_PATH=/usr/local \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_XSHM=ON \
  -DLIBRDP_WITH_XRANDR=ON \
  -DLIBRDP_WITH_PAM=ON
cmake --build build-freebsd-apps --parallel
ctest --test-dir build-freebsd-apps --output-on-failure
```
