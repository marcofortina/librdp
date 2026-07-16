<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Examples

These examples show public API usage patterns. They omit application-specific UI, storage, and error presentation code.

The repository also ships standalone examples that are compiled by CMake when `LIBRDP_BUILD_EXAMPLES=ON`:

| Target | Source | Purpose |
| --- | --- | --- |
| `librdp-example-minimal-session` | `examples/minimal_session.c` | Creates settings and a session without opening a network connection. |
| `librdp-example-surface-blit` | `examples/surface_blit.c` | Allocates a public surface and writes a BGRA rectangle. |
| `librdp-example-input-events` | `examples/input_events.c` | Builds keyboard and mouse events and demonstrates state-aware send failures before connection. |
| `librdp-example-event-loop-pollfds` | `examples/event_loop_pollfds.c` | Shows a custom POSIX poll loop around session pollfds, notification, and pending dispatch. |
| `librdp-example-clipboard-data` | `examples/clipboard_data.c` | Advertises text and named HTML clipboard data through the public clipboard API. |
| `librdp-example-dynamic-channels` | `examples/dynamic_channels.c` | Registers a static channel and requests an application-owned dynamic virtual channel. |
| `librdp-example-device-redirection` | `examples/device_redirection.c` | Configures drive, printer, serial, parallel, USB, and PNP device settings and policies. |
| `librdp-example-media-devices` | `examples/media_devices.c` | Configures audio, video, camera, smartcard, and WebAuthn feature backends. |
| `librdp-example-trace-tls-policy` | `examples/trace_tls_policy.c` | Installs a trace callback and TLS certificate policy callback. |
| `librdp-example-workspace-list` | `examples/workspace_list.c` | Loads a workspace feed from HTTP(S) or XML and lists published resources. |
| `librdp-example-server-listener` | `examples/server_listener.c` | Opens a loopback server listener, drives one peer, presents a BGRA desktop, and receives input/channel events through public server APIs. |

## Minimal session

```c
#include <librdp/librdp.h>

static int run_client(const char* host, const char* user, const char* password)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!settings)
        return 1;

    if (librdp_settings_set_target(settings, host) != LIBRDP_STATUS_OK ||
        librdp_settings_set_username(settings, user) != LIBRDP_STATUS_OK ||
        librdp_settings_set_password(settings, password) != LIBRDP_STATUS_OK ||
        librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_NLA) != LIBRDP_STATUS_OK ||
        librdp_settings_set_desktop_size(settings, 1024, 768) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    status = librdp_session_connect(session);
    while (status == LIBRDP_STATUS_OK ||
           status == LIBRDP_STATUS_TIMEOUT ||
           status == LIBRDP_STATUS_AGAIN)
    {
        librdp_session_state state = librdp_session_get_state(session);
        if (state != LIBRDP_SESSION_CONNECTED && state != LIBRDP_SESSION_ACTIVE)
            break;
        status = librdp_session_run_once(session, 50);
    }

    librdp_session_disconnect(session);
    librdp_session_free(session);
    return status == LIBRDP_STATUS_OK ? 0 : 1;
}
```

Do not log the password. The settings object copies it and the session receives a clone during construction.

## Event callback

```c
typedef struct app_state
{
    int disconnected;
    librdp_status last_error;
} app_state;

static void handle_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    app_state* app = (app_state*)user_data;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
        {
            const librdp_surface* surface = librdp_session_get_surface(session);
            const librdp_rect rect = event->data.surface;
            draw_rect(surface, rect.x, rect.y, rect.width, rect.height);
            break;
        }
        case LIBRDP_EVENT_POINTER:
            set_cursor_from_pointer_event(&event->data.pointer);
            break;
        case LIBRDP_EVENT_ERROR:
            app->last_error = event->data.error.status;
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            app->disconnected = 1;
            break;
        default:
            break;
    }
}
```

Event payload pointers are borrowed and expire when the callback returns. Copy channel data, clipboard data, pointer pixels, audio samples, or video requests before returning if they must outlive the callback.

## Surface presentation

```c
static void present_full_surface(const librdp_session* session)
{
    const librdp_surface* surface = librdp_session_get_surface(session);
    const uint8_t* pixels = NULL;

    if (!surface || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return;

    pixels = librdp_surface_pixels(surface);
    if (!pixels)
        return;

    present_bgra32(pixels,
                   librdp_surface_width(surface),
                   librdp_surface_height(surface),
                   librdp_surface_stride(surface));
}
```

The pixel pointer is borrowed. It becomes invalid after resize, session free, or any API call documented to invalidate surface storage.

## Keyboard and mouse

```c
static void send_key_a(librdp_session* session)
{
    librdp_key_event key = { 0 };

    key.scancode = 0x1eu;
    key.state = LIBRDP_KEY_PRESSED;
    librdp_session_send_key(session, &key);

    key.state = LIBRDP_KEY_RELEASED;
    librdp_session_send_key(session, &key);
}

static void click_left(librdp_session* session, uint16_t x, uint16_t y)
{
    librdp_mouse_event mouse = { 0 };

    mouse.x = x;
    mouse.y = y;
    mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;
    mouse.state = LIBRDP_MOUSE_PRESSED;
    librdp_session_send_mouse(session, &mouse);

    mouse.state = LIBRDP_MOUSE_RELEASED;
    librdp_session_send_mouse(session, &mouse);
}
```

Platform viewers should use the local input stack to translate native events into RDP-compatible scancodes, flags, Unicode fallback, and pointer coordinates.

## Clipboard

```c
static void publish_text(librdp_session* session)
{
    static const uint8_t text[] = "hello";
    librdp_session_clipboard_set_data(session, 13u, text, sizeof(text) - 1u);
}

static void request_remote_text(librdp_session* session)
{
    librdp_session_clipboard_request_data(session, 13u);
}
```

Clipboard bytes can contain sensitive user data. Applications decide what formats to publish and when to request remote data.

## Dynamic channel data

```c
static void send_channel_payload(librdp_session* session, librdp_channel_id channel_id)
{
    const uint8_t payload[] = { 0x01u, 0x02u, 0x03u };
    librdp_session_channel_send(session, channel_id, payload, sizeof(payload));
}
```

Applications should send only on channels announced through channel-open events and should stop using a channel identifier after a channel-close event.

## Feature settings

```c
static int configure_devices(librdp_settings* settings)
{
    if (librdp_settings_add_drive(settings, "work", "/home/user/work") != LIBRDP_STATUS_OK)
        return 0;
    if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK)
        return 0;
    if (librdp_settings_set_audio_output_device(settings, "pipewire") != LIBRDP_STATUS_OK)
        return 0;
    if (librdp_settings_add_smartcard(settings, "pcsc") != LIBRDP_STATUS_OK)
        return 0;
    if (librdp_settings_set_webauthn_provider(settings, "fido2") != LIBRDP_STATUS_OK)
        return 0;
    return 1;
}
```

Feature settings express intent. Host handles and user-consent policy belong to the viewer or application backend.
