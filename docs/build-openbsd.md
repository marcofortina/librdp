<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build OpenBSD

OpenBSD CI builds the portable core and all four X11 applications against
Xenocara.

## Dependencies

```sh
doas pkg_add \
  cmake ninja libiconv libxkbcommon doxygen graphviz
pkgconf_package="$(pkg_info -Q pkgconf | head -n 1 || true)"
if [ -z "${pkgconf_package}" ]; then
  pkgconf_package="$(pkg_info -Q pkg-config | head -n 1 || true)"
fi
if [ -n "${pkgconf_package}" ]; then
  doas pkg_add "${pkgconf_package}"
fi
doas pkg_add \
  "$(pkg_info -Q openssl | grep '^openssl-3\\.' | head -n 1)" \
  "$(pkg_info -Q python | grep '^python-3\\.' | tail -n 1)"
doas pkg_add \
  ffmpeg openh264 pcsc-lite libusb1 libfido2 libcbor cups libarchive
```

If the Python package installs only a versioned `python3.x` binary, create a local `python3` alias in the build environment.

## Core And Tests

```sh
openssl_config="$(find /usr/local/lib -path '*/cmake/OpenSSL/OpenSSLConfig.cmake' -print | head -n 1)"
openssl_cmake_dir="${openssl_config%/OpenSSLConfig.cmake}"
openssl_header="$(find /usr/local -path '*/include/eopenssl*/openssl/types.h' -print | head -n 1)"
openssl_include_dir="${openssl_header%/openssl/types.h}"
cmake -S . -B build-openbsd -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON \
  -DOpenSSL_DIR="${openssl_cmake_dir}" \
  -DOPENSSL_INCLUDE_DIR="${openssl_include_dir}" \
  -DLIBRDP_OPENSSL_INCLUDE_DIR="${openssl_include_dir}" \
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
cmake --build build-openbsd --parallel
ctest --test-dir build-openbsd --output-on-failure
```

## X11 Applications

```sh
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/X11R6/lib/pkgconfig"
cmake -S . -B build-openbsd-apps -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON \
  -DOpenSSL_DIR="${openssl_cmake_dir}" \
  -DOPENSSL_INCLUDE_DIR="${openssl_include_dir}" \
  -DLIBRDP_OPENSSL_INCLUDE_DIR="${openssl_include_dir}" \
  -DCMAKE_PREFIX_PATH="/usr/local;/usr/X11R6" \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON \
  -DLIBRDP_WITH_PIPEWIRE=OFF \
  -DLIBRDP_WITH_XSHM=ON \
  -DLIBRDP_WITH_XRANDR=ON \
  -DLIBRDP_WITH_PAM=OFF \
  -DLIBRDP_WITH_BSDAUTH=ON
cmake --build build-openbsd-apps --parallel
ctest --test-dir build-openbsd-apps --output-on-failure
```
