<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Lifecycle

This document describes application-visible sequencing. It does not replace function-level Doxygen documentation; it shows how the public calls, callbacks, surfaces, channels, and backends fit together.

## Session lifecycle

1. Allocate settings with `librdp_settings_new()`.
2. Configure target, credentials, security mode, desktop size, feature flags, and device selectors.
3. Create a session with `librdp_session_new()`.
4. Install a callback with `librdp_session_set_event_callback()`.
5. Call `librdp_session_connect()`.
6. Drive the session with `librdp_session_run_once()` from one serialized loop.
7. React to state, surface, pointer, channel, clipboard, audio, video, and error events.
8. Send input and feature responses from the same serialized context.
9. Call `librdp_session_disconnect()` during application shutdown or reconnect.
10. Release the session with `librdp_session_free()`.

Callbacks are synchronous. A callback runs from the call that produced it, normally `librdp_session_connect()` or `librdp_session_run_once()`.

## Settings ownership

`librdp_session_new()` clones the settings object. After construction:

- the caller still owns the original settings object;
- modifying the original settings object does not mutate the session;
- strings returned by settings getters remain owned by the settings object;
- credentials copied into settings and the session must not be logged by the application.

Device entries stored in settings express intent. Host device handles remain owned by the viewer or application backend.

## Event lifetime

Every `librdp_event` pointer is borrowed for the duration of the callback. Payload pointers inside the event follow the same rule unless the specific API says otherwise.

Applications must copy data before returning when they need to retain:

- clipboard bytes;
- dynamic channel payloads;
- pointer shape pixels;
- audio samples;
- video capture requests;
- file transfer names or ranges;
- backend request metadata.

Do not call long-running host APIs inside the callback. Queue work to the application loop or backend thread and return.

## Graphics update lifecycle

1. The session receives graphics data from fast-path, slow-path, bitmap, graphics pipeline, RFX, AVC, NSCodec, or GDI paths.
2. The core parser validates packet bounds and decode parameters.
3. The graphics decoder writes into an internal surface or cache.
4. The surface pipeline copies decoded pixels into the session primary surface.
5. The session emits `LIBRDP_EVENT_SURFACE_INVALIDATED` with the dirty rectangle.
6. The viewer reads `librdp_session_get_surface()`.
7. The viewer copies the dirty rectangle to its native window.

The viewer may repaint the full surface after local expose, local resize, reconnect, or damage-history loss. Pixel pointers returned by `librdp_surface_pixels()` remain borrowed and must not be stored across calls that can update or resize the surface.

Useful trace families:

- `rdp.fastpath.*`;
- `rdp.slowpath.*`;
- `client.active.framebuffer.*`;
- `client.gfx.*`;
- `client.gdi.*`.

## Pointer lifecycle

1. The server sends pointer default, hidden, position, cached, or shape updates.
2. Protocol code validates pointer dimensions, hotspot, bitmap length, cache index, and visibility state.
3. The session emits a pointer event.
4. The viewer updates native cursor visibility or installs a native cursor created from server-provided pixels.
5. The viewer keeps pointer cache entries only for the active session and clears them on reconnect, resize reset, or disconnect.

The viewer must not infer cursor shape from local coordinates. Cursor shape is server-driven.

Useful trace families:

- `client.pointer.*`;
- `x11.pointer.*`;
- `client.active.framebuffer.*`.

## Input lifecycle

1. The platform backend receives native keyboard, pointer, touch, or pen input.
2. The backend translates through the operating-system input stack.
3. The viewer fills public input structures from `include/librdp/input.h`.
4. The viewer calls `librdp_session_send_key()`, `librdp_session_send_mouse()`, `librdp_session_send_touch()`, or `librdp_session_send_pen()`.
5. The session routes input through the negotiated input channel or legacy input path.
6. Return status describes the immediate send attempt.

The session does not own native input state. The viewer owns keyboard grabs, modifier release policy, pointer coordinate conversion, and focus handling.

Useful trace families:

- `client.input.*`;
- `x11.keyboard.*`;
- `x11.pointer.*`;
- `client.core_input.*`.

## Clipboard lifecycle

Local-to-remote publication:

1. The application calls `librdp_session_clipboard_set_data()` or `librdp_session_clipboard_set_files()`.
2. The session stores copied metadata or data.
3. The clipboard channel sends a format list when available.
4. The remote side requests data or file ranges.
5. The session replies from stored local data or file metadata.

Remote-to-local request:

1. The session emits a remote format-list event.
2. The application chooses a format and calls `librdp_session_clipboard_request_data()`.
3. The remote side replies.
4. The session emits a clipboard data event.
5. The application copies bytes before returning if it needs them later.

Useful trace families:

- `client.clipboard.*`;
- `client.channel.*`.

## Dynamic channel lifecycle

1. The server or client negotiates dynamic virtual channel support.
2. A channel is created and assigned a `librdp_channel_id`.
3. The session emits an open event for application-owned channels.
4. The application sends bytes with `librdp_session_channel_send()`.
5. Incoming bytes are delivered through channel data events.
6. Either side closes the channel.
7. The application stops using the channel identifier after close.

Internal protocol channels are not exposed as generic application channels. Their data is routed to dedicated modules.

Useful trace families:

- `client.drdynvc.*`;
- `client.channel.*`.

## Device redirection lifecycle

1. Settings define drives, ports, printers, smartcards, USB devices, PNP devices, and related feature flags.
2. The session advertises configured devices during channel setup.
3. The remote side opens a device or submits an I/O request.
4. The device module validates request shape and maps it to a backend operation.
5. The backend completes, fails, or cancels the operation.
6. The device module sends the protocol response.
7. Disconnect closes device mappings and backend handles.

Device handles are authority-bearing resources. Applications should expose only configured local devices and should keep host permission errors separate from parser errors.

Useful trace families:

- `client.rdpdr.*`;
- `client.rdpefs.*`;
- `client.printer.*`;
- `client.smartcard.*`;
- `client.usb.*`;
- `client.pnp.*`.

## Audio, video, and camera lifecycle

Audio output:

1. The server advertises audio formats.
2. The application chooses a compatible local playback format.
3. The session emits audio data events.
4. The backend queues data to the host audio system.

Audio input:

1. The server requests capture open.
2. The backend opens the host capture device.
3. The application replies with `librdp_session_audio_input_open_reply()`.
4. Captured samples are sent with `librdp_session_audio_input_send_data()`.
5. Capture stops when the channel closes or the session disconnects.

Camera:

1. The server requests a capture format.
2. The backend validates local device support.
3. Sample requests are delivered as events.
4. The application sends samples or errors through the video capture API.

Useful trace families:

- `client.rdpsnd.*`;
- `client.audin.*`;
- `client.video.*`;
- `client.camera.*`.

## Resize and display-control lifecycle

1. The local window changes size or monitor layout.
2. The viewer computes a display layout.
3. The viewer calls `librdp_session_resize()` or `librdp_session_set_display_layout()`.
4. If display control is ready, the session sends a layout update.
5. The server acknowledges by sending graphics updates for the new size.
6. The session surface changes only when protocol updates require it.
7. The viewer repaints from the current surface after local expose or remote invalidation.

Applications should not assume that a local resize immediately changes the remote surface. Treat resize as a request and render according to the surface dimensions actually exposed by the session.

Useful trace families:

- `client.display_control.*`;
- `client.active.framebuffer.*`;
- `x11.window.*`.

## Error and teardown lifecycle

Immediate API return values describe the call just made. Asynchronous error events describe session, transport, protocol, channel, or backend failures discovered while driving the session.

Orderly teardown should:

1. stop local device capture and playback;
2. release keyboard grabs and remote pressed-key state;
3. stop sending new channel requests;
4. call `librdp_session_disconnect()`;
5. release backend handles;
6. call `librdp_session_free()`.

After `librdp_session_free()`, all borrowed session objects, event payload pointers, surfaces, and channel identifiers are invalid.
