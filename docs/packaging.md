<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Packaging

This document describes packaging expectations for the library, headers,
native applications, documentation, and generated metadata.

## Package split

Recommended package split:

- runtime library package: shared library and runtime dependency metadata;
- development package: public headers, CMake package files when available, and development dependency metadata;
- application package: `librdp-admin`, `librdp-server`, `librdp-viewer`, and
  `librdp-workspace` with the native runtime dependencies selected at build
  time;
- managed X11 session package: broker, supervisor, session agent, broker
  example configuration, and their manual page;
- documentation package: Markdown documentation, Doxygen output when generated, and man pages.

Distributions may combine these packages, but native application dependencies
should not be pulled in when only the core library is needed.

## CPack artifacts

The install rules are the source of truth for generated packages. A default build can create a compressed archive and, when host tools are present, native DEB or RPM artifacts:

```sh
cmake -S . -B build \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON
cmake --build build -j$(nproc)
cmake --build build --target package
```

Specific generators can be selected explicitly:

```sh
cpack --config build/CPackConfig.cmake -G DEB
cpack --config build/CPackConfig.cmake -G RPM
cpack --config build/CPackConfig.cmake -G TGZ
```

DEB generation requires `dpkg-deb`. RPM generation requires `rpmbuild`. macOS product packages are enabled only on macOS hosts with `productbuild` available.

The generated package installs the library, public headers, CMake package
files, pkg-config metadata, Markdown documentation, man pages, and each native
application selected by its `LIBRDP_BUILD_*` option.

## Homebrew

The repository ships a head-only Homebrew formula under
`packaging/homebrew/librdp.rb`. It builds the portable library, examples, and
all four Cocoa applications while leaving unrelated optional protocol
backends disabled:

```sh
brew install --HEAD packaging/homebrew/librdp.rb
```

Release tarball URL and checksum should be added to the formula only when a signed release artifact exists.

## Build flags

Packagers should build the core library with:

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

Native applications should be selected explicitly when the package provides
them:

```sh
cmake -S . -B build \
  -DLIBRDP_BUILD_TESTS=ON \
  -DLIBRDP_BUILD_ADMIN=ON \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_VIEWER=ON \
  -DLIBRDP_BUILD_WORKSPACE=ON
cmake --build build -j$(nproc)
```

Fuzz targets are developer artifacts and normally should not be shipped in runtime packages.

## Required runtime dependencies

The core runtime needs the libraries selected by the final link, including OpenSSL and iconv.

Optional runtime dependencies depend on enabled features:

- FFmpeg or OpenH264 for AVC codec paths;
- PC/SC for smartcard backends;
- libusb for USB;
- libfido2 and libcbor for WebAuthn;
- CUPS for printer paths;
- libacl, libattr, and libarchive for filesystem metadata paths;
- libcurl and libxml2 for gateway and workspace feed paths;
- X11, Xcursor, Xfixes, xkbcommon, pthreads, PipeWire, and optional image libraries for the X11 viewer.
- X11, XDamage, XComposite, XTest, XFixes, XRandR, Xau, xkbcommon and
  pthreads for the X11 desktop server;
- PAM on systems that use PAM, or BSD Authentication on OpenBSD, for managed
  desktop authentication;
- Xorg with a suitable virtual display driver for managed production sessions;
- FUSE 3 when client-announced drives are mounted into an X11 session.

Package metadata should reflect the build result, not the full optional list.

## Feature dependency matrix

| Package feature | Build-time dependency | Runtime dependency | Package recommendation |
| --- | --- | --- | --- |
| Core client library | C compiler, CMake, OpenSSL, iconv | OpenSSL, iconv | Keep in the runtime library package. |
| Unit and documentation guardrails | Python 3, Doxygen when API docs are checked | none for runtime | Keep in build or development pipelines. |
| Generated API docs | Doxygen, Python 3 | static HTML only | Ship in a documentation package when generated. |
| Fuzz targets | Clang/libFuzzer when available | sanitizer runtime for local developer builds | Do not ship in runtime packages. |
| X11 viewer | X11, Xcursor, Xfixes, xkbcommon, pthreads | same libraries | Ship in the native application package. |
| X11 desktop server | X11, XDamage, XComposite, XTest, XFixes, XRandR, Xau, xkbcommon | same libraries and a local graphical session for shadow mode | Ship in the native application package. |
| Managed X11 sessions | PAM or BSD Authentication, Xorg | host authentication stack, virtual X server, selected desktop | Install the broker and session helpers together. |
| Cocoa applications | AppKit, CoreGraphics, AudioToolbox, AVFoundation, ScreenCaptureKit, ApplicationServices | macOS native frameworks and an active graphical session for viewer or server UI | Build all four applications in the Homebrew formula. |
| PipeWire audio | PipeWire development package | PipeWire user session and runtime libs | Make an optional viewer dependency. |
| Camera | V4L2 headers available through the platform | local video device permissions | Make an optional viewer capability. |
| Smartcard | PC/SC development package | PC/SC service and reader access | Make an optional backend dependency. |
| USB | libusb development package | USB permissions and libusb runtime | Make an optional backend dependency. |
| WebAuthn | libfido2 and libcbor | authenticator access and runtime libs | Make an optional backend dependency. |
| Printer | CUPS development package | print service or file output path | Make an optional backend dependency. |
| Filesystem metadata | libacl, libattr, libarchive | selected metadata libraries | Make metadata fidelity conditional on installed libraries. |

## Filesystem layout

Recommended install layout:

```text
lib*/liblibrdp.so*
include/librdp/*.h
share/doc/librdp/*.md
share/man/man1/librdp-admin.1
share/man/man1/librdp-server.1
share/man/man1/librdp-viewer.1
share/man/man1/librdp-workspace.1
share/man/man8/librdp-session-broker.8
bin/librdp-admin
bin/librdp-server
bin/librdp-viewer
bin/librdp-workspace
sbin/librdp-session-broker
libexec/librdp/librdp-session-supervisor
libexec/librdp/librdp-session-agent
share/librdp/librdp-session-broker.conf.example
```

Development packages should include headers and any build-system metadata needed by downstream applications. Runtime packages should not include internal headers under `src/`.

When install/export support is enabled by downstream packaging, generated CMake and pkg-config metadata should describe only the public include directory and linked runtime libraries. Internal source directories, fuzz harnesses, and viewer-private headers must not be advertised to applications.

## Documentation

Markdown documentation under `docs/` and the application man pages should be
packaged as documentation. Generated Doxygen output may be packaged separately
when generated by the packaging system.

Do not package local build directories, fuzz corpora, sanitizer artifacts, or trace output.

Documentation packages should include:

- Markdown guides under `docs/`;
- man pages under `docs/man/`;
- generated Doxygen HTML when built;
- generated Doxygen tagfile when a downstream package creates one.

Documentation packages should not include private traces, local backend artifacts, device captures, or generated build trees.

## Build SBOM

Generate a CycloneDX 1.5 SBOM from a configured build tree:

```sh
python3 scripts/generate-sbom.py \
  --source-dir . \
  --build-dir build \
  --output build/librdp.cdx.json
python3 scripts/generate-sbom.py --validate build/librdp.cdx.json
```

The result records the four generic application build options, the application
and managed-session artifacts actually produced, selected optional
dependencies, and configured `bin`, `sbin`, and private `libexec` destinations.
`SOURCE_DATE_EPOCH` provides a reproducible metadata timestamp.

## ABI care

Packagers should treat public headers and exported symbols as the compatibility surface. See [ABI and versioning](abi-versioning.md) for source and binary compatibility rules.

When a distribution applies patches, it should avoid changing public API behavior without updating public headers and documentation.
