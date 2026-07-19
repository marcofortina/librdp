<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build Linux

Linux is the primary development environment. The full GCC and Clang CI
profiles build all four X11 applications and every required backend.

## Dependencies

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential clang cmake ninja-build pkg-config python3 doxygen graphviz \
  libssl-dev libavcodec-dev libavutil-dev libswscale-dev libopenh264-dev \
  libpcsclite-dev libusb-1.0-0-dev libfido2-dev libcbor-dev libcups2-dev \
  libacl1-dev libattr1-dev libarchive-dev libcurl4-openssl-dev libxml2-dev \
  libcairo2-dev libfuse3-dev libpam0g-dev libpng-dev libjpeg-dev \
  libx11-dev libxau-dev libxcomposite-dev libxcursor-dev libxdamage-dev \
  libxfixes-dev libxext-dev libxrandr-dev libxkbcommon-dev \
  libxkbcommon-x11-dev libxtst-dev libpipewire-0.3-dev xvfb
```

## Core And Tests

```sh
cmake -S . -B build-linux -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_EXAMPLES=ON \
  -DLIBRDP_BUILD_VIEWER=OFF \
  -DLIBRDP_BUILD_SERVER=OFF \
  -DLIBRDP_BUILD_ADMIN=OFF \
  -DLIBRDP_BUILD_WORKSPACE=OFF
cmake --build build-linux --parallel
ctest --test-dir build-linux --output-on-failure
```

## X11 Viewer

```sh
cmake -S . -B build-linux-x11 -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_VIEWER=ON
cmake --build build-linux-x11 --parallel
```

The viewer executable is `build-linux-x11/librdp-viewer`.

## X11 Desktop Server

```sh
cmake -S . -B build-linux-server -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_WITH_FUSE3=ON \
  -DLIBRDP_WITH_PAM=ON
cmake --build build-linux-server --parallel
```

The shadow server, managed-session broker, supervisor, and session agent are
built together. FUSE provides read-only client-drive mounts, and PAM provides
host authentication for managed sessions.

## Fuzz Targets

```sh
CC=clang cmake -S . -B build-linux-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLIBRDP_BUILD_FUZZ=ON \
  -DLIBRDP_BUILD_TESTS=OFF \
  -DLIBRDP_BUILD_VIEWER=OFF
cmake --build build-linux-fuzz --parallel
```
