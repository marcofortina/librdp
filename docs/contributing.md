<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing

This document defines the expected workflow for changes to the library, viewer, tests, fuzz targets, and documentation.

## Change shape

Keep changes scoped. A protocol parser fix, a backend feature, a public API addition, and a documentation restructuring should be separate changes unless they are required for one coherent behavior.

Every change should leave the repository buildable and testable.

## Public API changes

Before adding or changing public API under `include/librdp/`:

1. Check whether an existing opaque object or settings feature can carry the behavior.
2. Keep native platform types out of public headers.
3. Document ownership, nullability, threading, errors, security notes, and `@since`.
4. Add unit coverage for the new API.
5. Exercise the API from the X11 viewer or a unit test.
6. Update [API](api.md), [ABI and versioning](abi-versioning.md), and caller-facing examples when behavior changes.

Changing an existing public signature, enum value, struct layout, or documented lifetime rule requires explicit ABI review.

## Protocol and parser changes

Protocol code must treat input bytes as untrusted. Parser changes should include:

- length checks before reads;
- counter and allocation caps;
- malformed input tests or fuzz coverage;
- trace events for meaningful failure stages;
- comments for non-obvious state-machine transitions.

Packet-facing changes should update [Protocol support](protocol-support.md) when they add a new protocol area, module, or fuzz target.

## Backend changes

Backend changes should keep host resources private to the backend implementation. Public API should receive settings and emit events rather than exposing native handles.

For new backend behavior:

1. Add CMake feature detection.
2. Fail closed when the provider is unavailable.
3. Add trace events for probe, open, close, and failure.
4. Add unit or fuzz coverage for protocol-facing packet logic.
5. Update [Backends](backends.md) and [Portability](portability.md).

## Viewer changes

The X11 viewer is an integration frontend for public APIs. Viewer changes should:

- avoid adding protocol logic that belongs in the core;
- keep X11, XKB, PipeWire, V4L2, PC/SC, libusb, and FIDO2 code outside the core;
- update [X11 viewer](viewer-x11.md) when CLI flags or behavior change;
- preserve keyboard grab, pointer shape, resize, and cleanup behavior.

## Test and fuzz changes

Any new parser, decoder, channel dispatcher, backend packet path, or security state machine needs unit or fuzz coverage.

New complex test fixtures and fuzz targets must explain the bug classes they cover. The `test_fuzz_comments` guardrail enforces this for major fixtures and fuzz entrypoints.

## Documentation changes

Documentation changes should be committed with the behavior they describe or in a separate documentation-only change.

Rules:

- every `docs/*.md` file must be linked from `README.md`;
- every required document must have copyright and SPDX header;
- no document should track private planning state;
- local Markdown links must resolve;
- protocol rows must stay synchronized with implementation areas.

## Pre-commit checklist

Run the relevant subset before committing:

```sh
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
scripts/check-docs.py
scripts/check-license-headers.py .
git grep -n -i "forbidden-string-placeholder" -- . ':!build' ':!build-fuzz' ':!build-fuzz-clang'
```

Use the repository-specific forbidden-string check required by the project policy before every commit.
