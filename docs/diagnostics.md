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

## Symptom runbook

| Symptom | Enable | Events to inspect | Likely area | First action |
| --- | --- | --- | --- | --- |
| Connection closes during negotiation | `LIBRDP_TRACE_TRANSPORT=1 LIBRDP_TRACE_PROTOCOL=1` | `transport.tcp.*`, `transport.tls.*`, `x224.*`, `mcs.*`, `rdp.client_info.*` | transport, security, capability negotiation | Confirm target, selected security mode, certificate/authentication failure stage, and first protocol error. |
| Authentication succeeds but activation fails | `LIBRDP_TRACE_PROTOCOL=1` | `rdp.activation.*`, `rdp.capability.*`, `rdp.slowpath.*` | activation, capabilities, share state | Compare negotiated capabilities and check whether a malformed or unsupported PDU ended activation. |
| Dirty rectangles do not appear | `LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1` | `client.active.framebuffer.*`, `rdp.fastpath.*`, `rdp.slowpath.*`, `rdp.gfx.*` | graphics dispatch, decoder, surface invalidation | Verify that incoming update rectangles become surface invalidations with matching coordinates and dimensions. |
| Cursor shape is wrong | `LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1` | `client.pointer.*`, `x11.pointer.*`, `rdp.pointer.*` | pointer parser, pointer cache, viewer cursor backend | Confirm cache index, visibility, hotspot, dimensions, and native cursor install result. |
| Keyboard shortcut escapes the viewer | `LIBRDP_TRACE_CLIENT=1` | `x11.keyboard.*`, `client.input.*` | viewer grab, focus, modifier state | Check grab acquisition, focus transition, pressed-key tracking, and release ordering. |
| Mouse buttons or wheel do not work | `LIBRDP_TRACE_CLIENT=1` | `x11.pointer.*`, `client.input.*` | viewer pointer translation, input send path | Confirm native button number, translated public button, coordinates, and send status. |
| Clipboard data is missing | `LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1` | `client.clipboard.*`, `client.channel.*`, `client.drdynvc.*` | clipboard channel, format negotiation, data ownership | Confirm advertised format, requested format, payload length, and whether event data was copied before callback return. |
| Device feature is unavailable | `LIBRDP_TRACE_CLIENT=1` | `client.rdpdr.*`, backend-specific `x11.*` events | settings, backend probe, permission | Check local selector, optional library availability, open/probe result, and device announce. |
| Audio or camera starts then stops | `LIBRDP_TRACE_CLIENT=1` | `client.rdpsnd.*`, `client.audin.*`, `client.video.*`, `client.camera.*` | backend stream, format selection, channel close | Inspect format negotiation, backend open result, sample pacing, and close event. |
| Parser or decoder rejects input | `LIBRDP_TRACE_PROTOCOL=1 LIBRDP_TRACE_LEVEL=debug` | module-specific parser events | malformed PDU, unsupported capability, bounds rejection | Identify the first parser failure and add the minimized input to a unit or fuzz corpus when it is stable. |
| Managed X11 session does not start | broker stderr and `LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1` | `config.*`, `broker.*`, server listener and activation events | policy, host authentication, X server, desktop or session agent | Validate the broker configuration, then inspect the first failed process or protocol stage without recording credentials. |

## Managed X11 sessions

Validate the administrative policy before starting the service:

```sh
librdp-x11-session-broker \
  --config /etc/librdp/x11-session-broker.conf \
  --check-config
```

The broker emits stable `event=config.*` and `event=broker.*` records on
standard error. `config.failed` includes only a line, key and rejection reason;
it never includes the rejected value. A running service should own its Unix
socket and runtime root, and each active session should have a supervisor
control socket below the configured runtime root.

For startup failures, verify in order:

1. ownership and mode of the configuration, certificate and private key;
2. the configured authentication service;
3. availability of Xorg and its virtual display driver;
4. the selected desktop executable;
5. the session agent executable and Xauthority file;
6. the per-session listener and RDP activation trace.

`SIGTERM`, `SIGINT` and `SIGHUP` request an orderly broker shutdown. They do not
reload policy in place.

## Trace-to-component map

| Trace family | Component | Typical files |
| --- | --- | --- |
| `transport.tcp.*`, `transport.tls.*`, `transport.udp.*` | transport | `src/transport/*`, `src/platform/socket.c` |
| `x224.*`, `mcs.*`, `gcc.*` | connection handshake | `src/protocol/x224.c`, `src/protocol/mcs.c`, `src/protocol/gcc.c` |
| `rdp.security.*`, `credssp.*` | security and authentication | `src/security/*`, `src/nla/credssp.c` |
| `rdp.fastpath.*`, `rdp.slowpath.*` | update and input PDU dispatch | `src/protocol/fastpath.c`, `src/protocol/slowpath.c` |
| `client.gfx.*`, `client.gdi.*`, `client.active.framebuffer.*` | graphics decode and presentation | `src/graphics/*`, `src/channels/graphics_pipeline.c` |
| `client.drdynvc.*`, `client.channel.*` | dynamic virtual channels | `src/channels/dynamic_channel.c`, `src/channels/virtual_channel.c` |
| `client.rdpdr.*`, `client.rdpefs.*`, `client.printer.*` | device redirection | `src/channels/device_redirection.c`, device-specific channel files |
| `x11.keyboard.*`, `x11.pointer.*` | X11 viewer input and cursor handling | `apps/viewer/x11_main.c` |

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

Rendering analysis should preserve rectangle order. If a visual artifact appears after move or resize operations, compare:

1. the incoming graphics command rectangle;
2. the decoded source rectangle;
3. the destination surface rectangle;
4. the emitted invalidation rectangle;
5. the viewer repaint rectangle.

The first mismatch identifies whether the issue is parser, decoder, surface, event, or viewer presentation behavior.

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

Backend diagnostics should distinguish:

- configuration failure before session creation;
- local provider missing at build time;
- local provider missing at runtime;
- permission denied by the operating system;
- device busy or detached;
- protocol request unsupported by the backend;
- backend operation timed out;
- backend operation canceled due to disconnect.

These cases should not be collapsed into a generic protocol error.

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
