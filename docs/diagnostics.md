<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Diagnostics

Diagnostics are based on structured trace, explicit status codes, test guardrails, and reproducible local inputs.

## First checks

When investigating a connection, rendering, input, or backend issue:

1. Rebuild with tests enabled.
2. Run `ctest --test-dir build --output-on-failure`.
3. Enable the smallest trace category that covers the suspected area.
4. Preserve the exact command line without sharing credentials.
5. Keep the trace and any screenshots or local artifacts outside tracked source files.

## Trace categories

Use [Tracing](tracing.md) for the full event format. Practical category selection:

- client lifecycle, input, pointer, surface, channels, and viewer: `LIBRDP_TRACE_CLIENT=1`;
- TCP, TLS, UDP, read/write, timeout, and close behavior: `LIBRDP_TRACE_TRANSPORT=1`;
- handshake, parser, PDU, capability, slow-path, fast-path, channel, and codec behavior: `LIBRDP_TRACE_PROTOCOL=1`.

Use `LIBRDP_TRACE_LEVEL=debug` for control-flow detail and `LIBRDP_TRACE_LEVEL=trace` only when bounded hexdumps are needed.

## Rendering issues

For rendering issues, capture:

- viewer command line without credentials;
- desktop size and resize sequence;
- `LIBRDP_TRACE_CLIENT=1`;
- `LIBRDP_TRACE_PROTOCOL=1`;
- `LIBRDP_TRACE_LEVEL=debug`;
- screenshots of the affected surface area.

Relevant event families include:

- `client.active.framebuffer.*`;
- `client.graphics.*`;
- `rdp.fastpath.*`;
- `rdp.slowpath.*`;
- `rdp.gfx.*`;
- `x11.pointer.*` when cursor rendering is involved.

## Input issues

For keyboard and pointer issues, capture client trace and note the local environment:

- X11 or Xwayland;
- keyboard layout;
- modifier keys involved;
- pointer button or wheel event;
- whether keyboard grab was active.

Relevant event families include:

- `x11.keyboard.*`;
- `client.input.*`;
- `x11.pointer.*`;
- `client.pointer.*`.

## Backend issues

Backend issues should identify the selected local provider and feature flag:

- PipeWire stream for audio;
- V4L2 device path for camera;
- PC/SC or controlled virtual source for smartcard;
- libusb selector for USB;
- FIDO2, hidraw, or mock provider for WebAuthn;
- local directory, file, or printer path for filesystem and printing.

Trace should include backend setup and failure stage, not sensitive payload data.

## Parser or decoder crashes

For parser, channel, codec, or transport crashes:

1. Keep the triggering input as a binary artifact outside the source tree.
2. Reproduce with the closest fuzz target when possible.
3. Minimize the input.
4. Add a unit test when the minimized input represents a stable malformed vector.
5. Keep sensitive data out of any committed vector.

## Sensitive data handling

Do not attach credentials, private keys, authentication tokens, clipboard contents, file contents, audio samples, video frames, smartcard PIN-like data, or WebAuthn assertions to diagnostics reports.

Trace hexdumps are bounded, but bounded does not mean safe for all data classes. Prefer metadata and result codes over payload bytes.
