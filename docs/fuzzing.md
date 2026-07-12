<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Fuzzing

Fuzz targets live under `fuzz/` and use the standard `LLVMFuzzerTestOneInput` entrypoint. Targets are deterministic and do not perform network I/O.

## Build with libFuzzer

Use Clang for libFuzzer, AddressSanitizer, and UndefinedBehaviorSanitizer:

```sh
CC=clang cmake -S . -B build-fuzz-clang -DLIBRDP_BUILD_FUZZ=ON
cmake --build build-fuzz-clang -j$(nproc)
```

Run a target with a corpus directory:

```sh
mkdir -p corpus/x224 artifacts/x224
build-fuzz-clang/fuzz_x224 corpus/x224 -artifact_prefix=artifacts/x224/
```

## Standalone harness

When built without Clang, each fuzz executable links `fuzz/fuzz_main.c` and reads one input from standard input:

```sh
cmake -S . -B build-fuzz -DLIBRDP_BUILD_FUZZ=ON
cmake --build build-fuzz -j$(nproc)
printf '\x03\x00' | build-fuzz/fuzz_tpkt
```

This mode is useful for reproducing minimized inputs without a libFuzzer runtime.

## Naming and structure

Fuzz targets use the `fuzz_<area>` executable name and the `fuzz/<area>_fuzzer.c` source filename. Each target should exercise one parser, decoder, or dispatcher family. Avoid combining unrelated protocols in the same target unless the production code always dispatches them together.

Every target must:

- expose `LLVMFuzzerTestOneInput`;
- avoid network access and host device access;
- initialize only deterministic local state;
- free or reset all per-input allocations;
- document the target and bug classes in the file header and entrypoint comment.

Add new targets through the `add_librdp_fuzzer()` list in `CMakeLists.txt`.

## Target classes

Fuzz coverage includes:

- shared stream, charset, and bulk-compression helpers;
- transport framing;
- X.224, MCS, GCC, TPKT, fast-path, slow-path, capabilities, licensing, and security parsers;
- `credssp` ASN.1, credential transport, and authentication message handling;
- dynamic virtual channels and device channels;
- clipboard, audio, video, camera, smartcard, USB, printer, filesystem, and WebAuthn packets;
- bitmap, NSCodec, ClearCodec, planar, RemoteFX, AVC, graphics pipeline, surface commands, GDI orders, pointer decoding, and `mouse_cursor` packets.

## Bug classes

Each target should focus on one or more of:

- out-of-bounds reads or writes;
- integer overflow and underflow;
- malformed PDU state transitions;
- truncated nested structures;
- oversized counters and allocation pressure;
- decoder edge cases;
- lifetime and cleanup errors;
- inconsistent channel fragmentation.

## Corpus policy

Corpora should contain minimized binary samples and should not contain credentials, private keys, personal files, or target-specific secrets.

Crash artifacts should be minimized before being added to any long-term corpus. A minimized crash should include the target name, sanitizer output, and expected fix area in the associated issue or commit.

Recommended local layout:

```text
corpus/<target>/
artifacts/<target>/
```

These directories are local working data and should stay outside tracked source files unless a minimized vector is intentionally added as a unit-test fixture.

## Reproducing a crash

For libFuzzer builds:

```sh
build-fuzz-clang/fuzz_x224 artifacts/x224/crash-input
```

For standalone builds:

```sh
build-fuzz/fuzz_x224 < artifacts/x224/crash-input
```

After fixing a crash, add a focused unit test when the failure can be represented as a stable protocol or codec vector. Keep the fuzz target broad and deterministic; use unit tests to lock down the exact regression.

## Adding a target

When adding a new fuzz target:

1. Identify the packet-facing entrypoint used by production code.
2. Construct a minimal deterministic state object if the parser requires one.
3. Feed the input through the same parse, decode, or dispatch boundary used by the session or channel.
4. Ignore ordinary parse failures.
5. Treat sanitizer findings, assertions, leaks, and hangs as bugs.
6. Add the target to CMake.
7. Run `scripts/check-test-fuzz-comments.py`.

Do not use fuzz targets to test successful interoperability scenarios. They are for robustness against malformed, truncated, oversized, and inconsistent inputs.
