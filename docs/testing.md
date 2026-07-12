<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Testing

The test suite combines unit tests, fuzz targets, Doxygen checks, and documentation guardrails. Real target validation is separate from this page and is normally driven through the viewer and trace output.

## Unit tests

Build and run tests with:

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

The `core` test executable covers:

- stream and buffer bounds;
- endian encoding and decoding;
- TPKT, X.224, MCS, GCC, fast-path, slow-path, capabilities, pointer, and licensing parsing;
- settings, sessions, events, surfaces, input, channels, graphics, security, transport, and device behavior;
- codec and rendering edge cases;
- trace configuration and emission.

## Guardrails

CTest runs documentation and source quality guardrails when Python is available:

- `public_api_docs`: validates public API Doxygen coverage.
- `source_comments`: validates comments for non-trivial source functions.
- `internal_header_comments`: validates internal header contract comments.
- `test_fuzz_comments`: validates test and fuzz documentation comments.
- `doxygen_public_headers`: runs Doxygen and fails on warnings when Doxygen is installed.

Run individual guardrails directly from the repository root when narrowing a failure.

## Test policy

Tests should validate behavior, not only successful return codes. For parser and codec tests, include malformed input, boundary lengths, invalid flags, truncated buffers, and oversized counters when relevant.

Tests that introduce fixtures, protocol vectors, certificate material, codec streams, or backend simulations must include comments explaining what bug class the fixture is intended to catch.

## Sanitizers

When using Clang or GCC, configure a separate build directory with the desired sanitizer flags through `CFLAGS` and `LDFLAGS`. Keep sanitizer output outside the source tree.

Example:

```sh
CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=address,undefined" \
cmake -S . -B build-asan -DLIBRDP_BUILD_TESTS=ON
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure
```

## Viewer validation

The X11 viewer is the practical test frontend for public client APIs, input, graphics, resize, pointer updates, clipboard, audio, video, and device options. Viewer usage is documented in [X11 viewer](viewer-x11.md).
