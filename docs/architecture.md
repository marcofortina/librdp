<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architecture

librdp separates protocol mechanics from viewer and host integration code. The core library is intended to remain usable from X11, macOS, FreeBSD, and future frontends without linking platform UI dependencies into protocol code.

## Layers

- Public client API: `src/client`, `include/librdp`.
- Transport: `src/transport`, `src/platform`.
- Protocol framing and negotiation: `src/protocol`.
- Security and authentication: `src/security`, `src/nla`, `src/licensing`.
- Graphics codecs and rendering: `src/graphics`.
- Input normalization: `src/input`.
- Static and dynamic virtual channels: `src/channels`, `src/clipboard`.
- Shared utilities: `src/common`.
- Viewer and host backend probes: `apps/x11/viewer`.

## Core boundary

The core library must not depend on X11, PipeWire, V4L2, PC/SC user interface policy, or any viewer event loop. It receives settings and returns events, surface updates, and protocol state changes through public APIs.

Viewer applications own:

- local windowing;
- keyboard and pointer translation;
- host device selection;
- audio capture/playback device choice;
- camera source choice;
- clipboard integration;
- reconnect policy;
- user-visible error reporting.

## Protocol boundary

Network input is untrusted. Protocol parsers and decoders validate lengths, counts, flags, and state transitions before updating session state or dispatching events.

Graphics codecs decode into owned temporary buffers or directly into owned surfaces after bounds checks. Channel handlers must not retain borrowed transport buffers beyond the dispatch call unless they explicitly copy data.

## Backend boundary

Host backends are optional and feature-gated. The same public settings may be used by different viewer implementations with different backend providers.

Backends report failures through trace and ordinary API status paths. Missing optional backend libraries must not prevent the core library from building.

## Future server API

The implementation keeps transport, protocol framing, security helpers, codecs, stream utilities, and channel packet code separate from client session orchestration. A future server API should reuse those common pieces and add server-specific lifecycle and policy objects rather than duplicating the core.
