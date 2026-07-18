/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <librdp/librdp.h>

int main(void)
{
    librdp_server_clipboard_event clipboard_event;
    librdp_server_drive_event drive_event;
    librdp_server_drive_request drive_request;
    librdp_server_drive_request_id drive_request_id = 0u;
    librdp_server_pointer_update pointer_update;
    librdp_clipboard_file_metadata clipboard_file;
    librdp_settings* settings = librdp_settings_new();

    if (librdp_clipboard_file_metadata_init(&clipboard_file) !=
            LIBRDP_STATUS_OK ||
        clipboard_file.version !=
            LIBRDP_CLIPBOARD_FILE_METADATA_VERSION ||
        clipboard_file.size != sizeof(clipboard_file))
    {
        return 8;
    }

    if (librdp_server_pointer_update_init(&pointer_update) !=
            LIBRDP_STATUS_OK ||
        pointer_update.version != LIBRDP_SERVER_POINTER_UPDATE_VERSION ||
        pointer_update.size != sizeof(pointer_update) ||
        librdp_server_peer_send_pointer_update(NULL, &pointer_update) !=
            LIBRDP_STATUS_INVALID_ARGUMENT)
    {
        return 7;
    }
    if (librdp_server_clipboard_event_init(&clipboard_event) !=
            LIBRDP_STATUS_OK ||
        clipboard_event.version != LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION ||
        clipboard_event.size != sizeof(clipboard_event) ||
        librdp_server_peer_set_clipboard_callback(NULL, NULL, NULL) !=
            LIBRDP_STATUS_INVALID_ARGUMENT)
    {
        return 5;
    }
    if (librdp_server_drive_event_init(&drive_event) !=
            LIBRDP_STATUS_OK ||
        librdp_server_drive_request_init(&drive_request) !=
            LIBRDP_STATUS_OK ||
        drive_event.version != LIBRDP_SERVER_DRIVE_EVENT_VERSION ||
        drive_request.version != LIBRDP_SERVER_DRIVE_REQUEST_VERSION ||
        librdp_server_peer_set_drive_callback(NULL, NULL, NULL) !=
            LIBRDP_STATUS_INVALID_ARGUMENT ||
        librdp_server_peer_submit_drive_request(
            NULL,
            &drive_request,
            &drive_request_id) != LIBRDP_STATUS_INVALID_ARGUMENT ||
        librdp_server_peer_cancel_drive_request(NULL, 1u) !=
            LIBRDP_STATUS_INVALID_ARGUMENT)
    {
        return 6;
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
