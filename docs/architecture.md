<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architecture

librdp separates protocol mechanics from viewer, server, and host integration code. The core library remains usable from X11, Cocoa/macOS, FreeBSD, and other frontends without linking platform UI dependencies into protocol code.

## Layers

- Public client API: `src/client`, `include/librdp/session.h`, and related public headers.
- Public server API: `src/server`, `include/librdp/server.h`, and server-facing public headers.
- Transport: `src/transport`, `src/platform`.
- Protocol framing and negotiation: `src/protocol`.
- Security and authentication: `src/security`, `src/nla`, `src/licensing`.
- Graphics codecs and rendering: `src/graphics`.
- Input normalization: `src/input`.
- Static and dynamic virtual channels: `src/channels`, `src/clipboard`.
- Shared utilities: `src/common`.
- Viewer, administration, workspace, and host backend applications: `apps/x11`, `apps/cocoa`.

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

Server applications own:

- listen address and peer admission policy;
- certificate and credential policy;
- desktop surface source;
- input, channel, device, and media callbacks;
- peer-visible error handling and disconnect policy.

## Protocol boundary

Network input is untrusted. Protocol parsers and decoders validate lengths, counts, flags, and state transitions before updating session state or dispatching events.

Graphics codecs decode into owned temporary buffers or directly into owned surfaces after bounds checks. Channel handlers must not retain borrowed transport buffers beyond the dispatch call unless they explicitly copy data.

## Backend boundary

Host backends are optional and feature-gated. The same public settings may be used by different viewer implementations with different backend providers.

Backends report failures through trace and ordinary API status paths. Missing optional backend libraries must not prevent the core library from building.

## Server API

The server API reuses the shared transport, protocol framing, security helpers, codecs, stream utilities, and channel packet layers. Server-specific lifecycle, peer state, policy, and callback dispatch stay in `src/server` and are exposed through `include/librdp/server.h`.
