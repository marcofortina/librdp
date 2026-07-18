<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Coding Standards

This project uses C11, explicit ownership, bounded parsing, and small platform boundaries.

## C style

- Prefer clear C over macro-heavy abstractions.
- Use fixed-width integer types for wire values.
- Use `size_t` for memory sizes and buffer lengths.
- Keep functions scoped to one responsibility.
- Avoid hidden global state except for process-level facilities such as trace configuration.
- Keep comments useful: invariants, ownership, trust boundary, state-machine rationale, and non-obvious protocol behavior.

## Error handling

Functions that can fail should return `librdp_status` or a documented boolean/integer result. Avoid ambiguous return values.

Rules:

- validate arguments at API boundaries;
- return early on invalid input;
- leave objects in a coherent state after failure;
- free partially initialized resources on all failure paths;
- do not ignore allocation or transport failures;
- do not collapse distinct caller actions into a generic failure when a public status already exists.

## Ownership

Ownership must be visible from code shape and comments.

- Public settings copy caller strings.
- Sessions own protocol state and clone settings at construction.
- Events expose borrowed payloads valid only for the callback duration.
- Surfaces own pixel memory.
- Backends own native handles.

When a function takes a pointer, make it clear whether it borrows, copies, mutates, or takes ownership.

## Parser rules

Protocol input is untrusted. Parser code must:

- check remaining bytes before every read;
- validate nested lengths against parent lengths;
- cap counters before loops or allocations;
- guard multiplication and addition used for sizes;
- reject invalid enum values unless the protocol says to ignore them;
- avoid partial state commits until validation succeeds.

Use structured stream helpers instead of ad hoc pointer arithmetic when practical.

## Codec and rendering rules

Graphics code must clip before writing to a destination surface. Decoders must validate source bounds, destination bounds, pixel format, stride, and tile dimensions.

Rendering paths should keep surface ownership centralized and avoid retaining temporary decode buffers longer than needed.

## Security rules

Do not add custom cryptographic primitives when a maintained system library provides the required behavior. Use OpenSSL, iconv, and OS-maintained libraries where appropriate.

Do not trace passwords, authentication tokens, private keys, WebAuthn secrets, smartcard PIN-like data, clipboard contents, file contents, audio samples, or video frames.

## Trace rules

Trace events should be stable, lower-case, hierarchical names. Messages should use key-value fields.

Use trace for:

- negotiation state;
- parser failures;
- backend setup and failure;
- transport timing;
- graphics and surface diagnostics.

Do not use trace as a substitute for explicit error handling.

## Platform rules

Keep platform-specific includes out of public headers and core protocol modules. Put native backends behind CMake feature detection and private implementation files.

Core code must not assume a particular host's device APIs, UI frameworks, filesystem extensions, or vendor-native services.

## Tests and fuzzing

Every non-trivial parser, decoder, channel dispatcher, security state machine, and backend packet path should have tests or fuzz coverage.

Malformed input coverage is required for code that reads untrusted bytes.
