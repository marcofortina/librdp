<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build Solaris

Solaris is a portability guard for the platform-neutral core. The CI profile builds with optional backends disabled and does not build a viewer.

## Dependencies

With OpenCSW `pkgutil`:

```sh
pkgutil -y -i cmake pkgconfig openssl3 python3
```

The CI profile uses a GCC-based Solaris image and places `/opt/csw/bin` before the system paths.

## Core Portability

```sh
export PATH=/opt/csw/bin:/usr/gnu/bin:/usr/bin:/usr/sbin:${PATH}
cmake -S . -B build-solaris \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/opt/csw \
  -DOPENSSL_ROOT_DIR=/opt/csw \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=OFF \
  -DLIBRDP_BUILD_VIEWER=OFF \
  -DLIBRDP_ENABLE_WERROR=OFF \
  -DLIBRDP_WITH_FFMPEG_AVC=OFF \
  -DLIBRDP_WITH_OPENH264_AVC=OFF \
  -DLIBRDP_WITH_PCSC=OFF \
  -DLIBRDP_WITH_LIBUSB=OFF \
  -DLIBRDP_WITH_FIDO2=OFF \
  -DLIBRDP_WITH_CBOR=OFF \
  -DLIBRDP_WITH_CUPS=OFF \
  -DLIBRDP_WITH_ACL=OFF \
  -DLIBRDP_WITH_ATTR=OFF \
  -DLIBRDP_WITH_ARCHIVE=OFF \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_PNG=OFF \
  -DLIBRDP_WITH_JPEG=OFF \
  -DLIBRDP_WITH_XSHM=OFF \
  -DLIBRDP_WITH_XRANDR=OFF
cmake --build build-solaris --parallel
ctest --test-dir build-solaris -R '^(common|core|protocol|transport)$' --output-on-failure
```
