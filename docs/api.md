<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# API

The public API lives under `include/librdp/`. Public handles are opaque where callers do not need protocol internals. Detailed ownership, nullability, error, and threading rules are documented in the headers with Doxygen comments.

## Object model

- `librdp_settings` owns connection settings, credentials, device configuration, and feature flags.
- `librdp_session` owns the client protocol state, transport state, negotiated channels, and the active surface.
- `librdp_surface` owns the framebuffer memory exposed to viewers.
- `librdp_event` is a callback-delivered view of session changes, graphics, pointer updates, clipboard data, channel activity, audio, and video events.

Sessions clone settings at construction time. After `librdp_session_new()`, later mutations to the source settings object do not affect the session.

## Session lifecycle

The typical lifecycle is:

1. Allocate settings with `librdp_settings_new()`.
2. Configure target, credentials, security mode, desktop size, and optional features.
3. Create a session with `librdp_session_new()`.
4. Register an event callback with `librdp_session_set_event_callback()`.
5. Connect with `librdp_session_connect()`.
6. Drive network and protocol processing with `librdp_session_run_once()`.
7. Read the surface with `librdp_session_get_surface()` when surface invalidation events arrive.
8. Send keyboard, mouse, touch, pen, clipboard, audio, video, and channel operations through the session APIs.
9. Disconnect with `librdp_session_disconnect()`.
10. Free the session and settings.

The session object is not internally synchronized. Applications must serialize calls that operate on the same session.

## Events

Callbacks are invoked from the thread that drives the session unless a backend explicitly documents a different thread. Event payloads are borrowed and valid only until the callback returns. Viewers must copy any payload they need after returning, including clipboard bytes, channel data, audio samples, video requests, and pointer pixels.

Surface invalidation events identify dirty desktop rectangles. The surface itself remains owned by the session.

## Input

Keyboard, mouse, touch, and pen APIs accept normalized public structures from `include/librdp/input.h`. The library expects callers to provide RDP-compatible key scancodes and flags. Platform viewers are responsible for translating local input systems into those public structures.

## Graphics surface

The public surface stores pixels in the negotiated format exposed by `librdp_surface_format()`. Pointers returned by `librdp_surface_pixels()` and `librdp_surface_pixels_mut()` are invalidated by resize or free operations.

Viewer code should redraw only the invalidated rectangles when possible, but may refresh the full surface after reconnect, resize, or local window damage.

## Channels and devices

Application-owned dynamic virtual channels are exposed through `librdp_session_channel_send()` and `librdp_session_channel_close()`. Internal protocol channels are handled by the library and are not exposed as generic application channels.

Feature-specific APIs exist for clipboard, audio input, and video capture. Device configuration is supplied through `librdp_settings`.

## Error handling

Public functions return `librdp_status` where failure is possible. Asynchronous errors are delivered through events. Applications should treat transport closure, parser rejection, unsupported negotiated features, and backend failures as recoverable session errors unless the API documents otherwise.
