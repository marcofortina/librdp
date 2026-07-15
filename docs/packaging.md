<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Packaging

This document describes packaging expectations for the library, headers, optional viewer, documentation, and generated metadata.

## Package split

Recommended package split:

- runtime library package: shared library and runtime dependency metadata;
- development package: public headers, CMake package files when available, and development dependency metadata;
- viewer package: `librdp-x11-viewer` and viewer runtime dependencies;
- documentation package: Markdown documentation, Doxygen output when generated, and man pages.

Distributions may combine these packages, but optional viewer dependencies should not force installation of the viewer when only the core library is needed.

## CPack artifacts

The install rules are the source of truth for generated packages. A default build can create a compressed archive and, when host tools are present, native DEB or RPM artifacts:

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON -DLIBRDP_BUILD_X11_VIEWER=ON
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

The generated package installs the library, public headers, CMake package files, pkg-config metadata, Markdown documentation, man pages, and the viewer binary when `LIBRDP_BUILD_X11_VIEWER=ON`.

## Homebrew

The repository ships a head-only Homebrew formula under `packaging/homebrew/librdp.rb`. It builds the portable core library and examples with optional platform backends disabled:

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

The X11 viewer should be built only when the package intentionally provides it:

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON -DLIBRDP_BUILD_X11_VIEWER=ON
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

Package metadata should reflect the build result, not the full optional list.

## Feature dependency matrix

| Package feature | Build-time dependency | Runtime dependency | Package recommendation |
| --- | --- | --- | --- |
| Core client library | C compiler, CMake, OpenSSL, iconv | OpenSSL, iconv | Keep in the runtime library package. |
| Unit and documentation guardrails | Python 3, Doxygen when API docs are checked | none for runtime | Keep in build or development pipelines. |
| Generated API docs | Doxygen, Python 3 | static HTML only | Ship in a documentation package when generated. |
| Fuzz targets | Clang/libFuzzer when available | sanitizer runtime for local developer builds | Do not ship in runtime packages. |
| X11 viewer | X11, Xcursor, Xfixes, xkbcommon, pthreads | same libraries | Ship separately from the core library. |
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
share/man/man1/librdp-x11-viewer.1
bin/librdp-x11-viewer
```

Development packages should include headers and any build-system metadata needed by downstream applications. Runtime packages should not include internal headers under `src/`.

When install/export support is enabled by downstream packaging, generated CMake and pkg-config metadata should describe only the public include directory and linked runtime libraries. Internal source directories, fuzz harnesses, and viewer-private headers must not be advertised to applications.

## Documentation

Markdown documentation under `docs/` and the viewer man page should be packaged as documentation. Generated Doxygen output may be packaged separately when generated by the packaging system.

Do not package local build directories, fuzz corpora, sanitizer artifacts, or trace output.

Documentation packages should include:

- Markdown guides under `docs/`;
- man pages under `docs/man/`;
- generated Doxygen HTML when built;
- generated Doxygen tagfile when a downstream package creates one.

Documentation packages should not include private traces, local backend artifacts, device captures, or generated build trees.

## ABI care

Packagers should treat public headers and exported symbols as the compatibility surface. See [ABI and versioning](abi-versioning.md) for source and binary compatibility rules.

When a distribution applies patches, it should avoid changing public API behavior without updating public headers and documentation.
