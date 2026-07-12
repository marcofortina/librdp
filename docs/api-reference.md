<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# API Reference

This document is a hand-written map of the public C API. The function-level reference is produced from Doxygen comments in `include/librdp/*.h`.

## Header map

| Header | Purpose |
| --- | --- |
| `include/librdp/librdp.h` | Convenience umbrella header for all public API families. |
| `include/librdp/error.h` | Stable `librdp_status` error model and status-string helper. |
| `include/librdp/settings.h` | Session configuration, credentials, desktop size, security mode, features, and redirected devices. |
| `include/librdp/session.h` | Session lifecycle, event callback registration, connection loop, resize, display layout, refresh, and input send APIs. |
| `include/librdp/event.h` | Event discriminator and callback payload structures. |
| `include/librdp/surface.h` | BGRA framebuffer surface allocation, resize, blit, metadata, and pixel access. |
| `include/librdp/input.h` | Keyboard, mouse, touch, and pen public event structures and flags. |
| `include/librdp/clipboard.h` | Clipboard format publication, data requests, file publication, and file-content requests. |
| `include/librdp/channel.h` | Application-owned dynamic virtual channel send and close APIs. |
| `include/librdp/audio.h` | Audio format structure and audio input response/send APIs. |
| `include/librdp/video.h` | Video capture media description and sample/error response APIs. |

## Primary objects

`librdp_settings` is the caller-configured input object. It owns copies of strings and device descriptors. A session clones settings during construction.

`librdp_session` is the protocol, transport, channel, cache, and surface owner. It is driven by `librdp_session_connect()` and `librdp_session_run_once()`.

`librdp_surface` is the framebuffer object. A session owns its active surface; applications receive borrowed access through `librdp_session_get_surface()`.

`librdp_event` is a borrowed callback payload. Its active union member is selected by `librdp_event_type`.

## Settings API

Settings functions configure:

- target and port;
- username, password, and domain;
- desktop width and height;
- security mode;
- feature flags;
- drives, serial ports, parallel ports, printers, cameras, smartcards, USB devices, PNP devices, WebAuthn providers, RAIL applications, audio devices, video output, and echo payload.

Settings getters return borrowed pointers owned by the settings object. They become invalid when the setting is changed or the settings object is freed.

## Session API

Session functions cover:

- creation and free;
- event callback registration;
- connect, run-once, disconnect;
- resize and monitor layout;
- surface refresh requests;
- keyboard, mouse, touch, and pen input;
- current state and surface access.

All calls operating on the same session must be serialized by the application.

## Event API

Events include:

- state changes;
- surface invalidation;
- sent input notifications;
- asynchronous errors and disconnect;
- pointer default, hidden, position, and shape updates;
- clipboard formats, data, data requests, and file contents;
- dynamic channel open, data, and close;
- audio output formats, data, and close;
- audio input formats and open requests;
- video capture open, sample requests, and close.

Payload pointers are valid only until the callback returns.

## Surface API

The public surface exposes BGRA32 pixels. Applications can allocate standalone surfaces or access a session-owned surface.

The surface API provides:

- allocation and free;
- resize;
- BGRA blit;
- width, height, stride, and format getters;
- const and mutable pixel access.

Pixel pointers are borrowed from the surface and invalidated by resize or free.

## Input API

Input structures represent:

- scancode and Unicode keyboard events;
- pointer movement, button, and wheel transitions;
- touch contacts and frames;
- pen contacts and frames.

The session send APIs copy input structures during the call. Viewers own native input translation.

## Clipboard API

Clipboard APIs support local format publication, local data publication, file list publication, local clear, remote data requests, remote file size requests, and remote file range requests.

Clipboard bytes can contain sensitive user data. Applications decide which formats and files are exposed.

## Channel API

Application dynamic channels use `librdp_channel_id`. Applications send and close only channels announced through channel events. Internal protocol channels are handled by the library.

## Audio and video APIs

Audio APIs provide response paths for audio input requests. Video APIs provide response paths for video capture requests.

Applications should call these APIs from the same serialized session-driving context that receives the corresponding event.

## Error model

Public functions return `librdp_status` where failure is possible. Asynchronous failures are delivered through `LIBRDP_EVENT_ERROR`.

Use `librdp_status_string()` for stable diagnostic tokens. Do not use status strings as a substitute for branch logic.

## Doxygen reference

Doxygen reads `include/librdp` and this API reference page. HTML output is written to `build/doxygen/html/index.html`; XML output is written to `build/doxygen/xml`.

Build the local HTML reference with:

```sh
cmake --build build --target docs-api
```

The Doxygen guardrail fails on undocumented public API or documentation errors.
