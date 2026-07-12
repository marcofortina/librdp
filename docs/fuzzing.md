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

## Target classes

Fuzz coverage includes:

- transport framing;
- X.224, MCS, GCC, TPKT, fast-path, slow-path, capabilities, licensing, and security parsers;
- CredSSP ASN.1 and authentication message handling;
- dynamic virtual channels and device channels;
- clipboard, audio, video, camera, smartcard, USB, printer, filesystem, and WebAuthn packets;
- bitmap, NSCodec, ClearCodec, planar, RemoteFX, AVC, graphics pipeline, surface commands, GDI orders, and pointer decoding.

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
