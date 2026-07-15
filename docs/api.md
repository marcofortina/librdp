<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# API

The public API lives under `include/librdp/`. Public handles are opaque where callers do not need protocol internals. Detailed ownership, nullability, error, and threading rules are documented in the headers with Doxygen comments.

For end-to-end call ordering, see [Lifecycle](lifecycle.md). For standalone source examples, see [Examples](examples.md).

## Object model

- `librdp_settings` owns connection settings, credentials, device configuration, and feature flags.
- `librdp_session` owns the client protocol state, transport state, negotiated channels, and the active surface.
- `librdp_surface` owns the framebuffer memory exposed to viewers.
- `librdp_event` is a callback-delivered view of session changes, graphics, pointer updates, clipboard data, channel activity, audio, and video events.
- `librdp_workspace` owns a workspace feed configuration and parsed published resource list.

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

Minimal setup:

```c
librdp_settings* settings = librdp_settings_new();
if (!settings)
    return 1;

if (librdp_settings_set_target(settings, "host") != LIBRDP_STATUS_OK ||
    librdp_settings_set_username(settings, "user") != LIBRDP_STATUS_OK ||
    librdp_settings_set_password(settings, "password") != LIBRDP_STATUS_OK ||
    librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_NLA) != LIBRDP_STATUS_OK ||
    librdp_settings_set_desktop_size(settings, 1024, 768) != LIBRDP_STATUS_OK)
{
    librdp_settings_free(settings);
    return 1;
}

librdp_session* session = librdp_session_new(settings);
librdp_settings_free(settings);
if (!session)
    return 1;
```

Connection driving:

```c
if (librdp_session_connect(session) != LIBRDP_STATUS_OK)
{
    librdp_session_free(session);
    return 1;
}

while (librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED ||
       librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE)
{
    librdp_status status = librdp_session_run_once(session, 50);
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        break;
}

librdp_session_disconnect(session);
librdp_session_free(session);
```

## Events

Callbacks are invoked from the thread that drives the session unless a backend explicitly documents a different thread. Event payloads are borrowed and valid only until the callback returns. Viewers must copy any payload they need after returning, including clipboard bytes, channel data, audio samples, video requests, and pointer pixels.

Surface invalidation events identify dirty desktop rectangles. The surface itself remains owned by the session.

Callback shape:

```c
static void on_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    (void)user_data;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
        {
            const librdp_surface* surface = librdp_session_get_surface(session);
            const librdp_rect rect = event->data.surface;
            draw_surface_rect(surface, rect.x, rect.y, rect.width, rect.height);
            break;
        }
        case LIBRDP_EVENT_POINTER:
            update_local_cursor(&event->data.pointer);
            break;
        case LIBRDP_EVENT_ERROR:
            record_session_error(event->data.error.status);
            break;
        default:
            break;
    }
}
```

Register the callback before connecting:

```c
librdp_session_set_event_callback(session, on_event, app_state);
```

## Input

Keyboard, mouse, touch, and pen APIs accept normalized public structures from `include/librdp/input.h`. The library expects callers to provide RDP-compatible key scancodes and flags. Platform viewers are responsible for translating local input systems into those public structures.

Keyboard example:

```c
librdp_key_event key = { 0 };
key.scancode = 0x1eu;
key.state = LIBRDP_KEY_PRESSED;
librdp_session_send_key(session, &key);
key.state = LIBRDP_KEY_RELEASED;
librdp_session_send_key(session, &key);
```

Mouse example:

```c
librdp_mouse_event mouse = { 0 };
mouse.x = 400;
mouse.y = 300;
mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;
mouse.state = LIBRDP_MOUSE_PRESSED;
librdp_session_send_mouse(session, &mouse);
mouse.state = LIBRDP_MOUSE_RELEASED;
librdp_session_send_mouse(session, &mouse);
```

Touch and pen frames use bounded contact arrays supplied by the caller. The session reads them during the call and does not retain the caller-owned frame memory.

## Graphics surface

The public surface stores pixels in the negotiated format exposed by `librdp_surface_format()`. Pointers returned by `librdp_surface_pixels()` and `librdp_surface_pixels_mut()` are invalidated by resize or free operations.

Viewer code should redraw only the invalidated rectangles when possible, but may refresh the full surface after reconnect, resize, or local window damage.

Surface access:

```c
const librdp_surface* surface = librdp_session_get_surface(session);
if (surface && librdp_surface_format(surface) == LIBRDP_PIXEL_FORMAT_BGRA32)
{
    const uint8_t* pixels = librdp_surface_pixels(surface);
    size_t stride = librdp_surface_stride(surface);
    present_bgra(pixels,
                 librdp_surface_width(surface),
                 librdp_surface_height(surface),
                 stride);
}
```

The returned pixel pointer is borrowed. Applications must not write through the const pointer and must not keep it after the next session call that can resize or update the surface.

## Channels and devices

Application-owned dynamic virtual channels are exposed through `librdp_session_channel_send()` and `librdp_session_channel_close()`. Internal protocol channels are handled by the library and are not exposed as generic application channels.

Feature-specific APIs exist for clipboard, audio input, and video capture. Device configuration is supplied through `librdp_settings`.

Clipboard publication:

```c
const uint8_t text[] = "hello";
librdp_session_clipboard_set_data(session, 13u, text, sizeof(text) - 1u);
```

Clipboard requests, channel data, audio data, and video capture requests are event-driven. Their event payloads are borrowed; copy bytes before returning from the callback if the application needs to retain them.

Dynamic channel send:

```c
const uint8_t payload[] = { 1u, 2u, 3u };
librdp_session_channel_send(session, channel_id, payload, sizeof(payload));
```

Audio input and video capture APIs are response paths. Applications should only call them after receiving the corresponding request events and after opening the local backend resource.

## Error handling

Public functions return `librdp_status` where failure is possible. Asynchronous errors are delivered through events. Applications should treat transport closure, parser rejection, unsupported negotiated features, and backend failures as recoverable session errors unless the API documents otherwise.

Common handling pattern:

```c
librdp_status status = librdp_session_run_once(session, 50);
if (status == LIBRDP_STATUS_TIMEOUT)
    poll_local_window_events();
else if (status != LIBRDP_STATUS_OK)
    close_session_ui(status);
```

Avoid logging credentials or clipboard contents when reporting errors. Use trace categories for protocol and transport diagnostics.

## Workspace feeds

Workspace APIs are independent from an active RDP session. Applications can fetch an HTTP(S) feed with `librdp_workspace_fetch()` or load XML already obtained by another component with `librdp_workspace_load_xml()`.

```c
librdp_workspace_config config;
librdp_workspace_config_init(&config);
config.feed_url = "https://workspace.example.test/feed";

librdp_workspace* workspace = librdp_workspace_new(&config);
if (workspace && librdp_workspace_fetch(workspace) == LIBRDP_STATUS_OK)
{
    size_t count = librdp_workspace_resource_count(workspace);
    for (size_t i = 0; i < count; i++)
    {
        librdp_workspace_resource resource;
        librdp_workspace_resource_init(&resource);
        if (librdp_workspace_resource_at(workspace, i, &resource) == LIBRDP_STATUS_OK)
            show_resource(resource.title, resource.alias);
    }
}
librdp_workspace_free(workspace);
```

Resource strings are borrowed from the workspace and become invalid after `fetch`, `load_xml`, `clear`, or `free`.
