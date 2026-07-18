/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <librdp/librdp.h>

int main(void)
{
    librdp_server_clipboard_event clipboard_event;
    librdp_settings* settings = librdp_settings_new();

    if (librdp_server_clipboard_event_init(&clipboard_event) !=
            LIBRDP_STATUS_OK ||
        clipboard_event.version != LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION ||
        clipboard_event.size != sizeof(clipboard_event) ||
        librdp_server_peer_set_clipboard_callback(NULL, NULL, NULL) !=
            LIBRDP_STATUS_INVALID_ARGUMENT)
    {
        return 5;
    }
    if (!settings)
        return 1;

    librdp_session* session = librdp_session_new(settings);
    if (!session)
    {
        librdp_settings_free(settings);
        return 2;
    }

    librdp_surface* surface = librdp_surface_new(16u, 16u, LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!surface)
    {
        librdp_session_free(session);
        librdp_settings_free(settings);
        return 3;
    }

    if (librdp_surface_width(surface) != 16u || librdp_surface_height(surface) != 16u)
    {
        librdp_surface_free(surface);
        librdp_session_free(session);
        librdp_settings_free(settings);
        return 4;
    }

    librdp_surface_free(surface);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}
