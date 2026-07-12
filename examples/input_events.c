/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    librdp_key_event key = { 0 };
    librdp_mouse_event mouse = { 0 };
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    librdp_status key_status;
    librdp_status mouse_status;

    if (!settings)
        return 1;

    if (librdp_settings_set_target(settings, "127.0.0.1") != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    key.scancode = 0x1eu;
    key.state = LIBRDP_KEY_PRESSED;

    mouse.x = 400u;
    mouse.y = 300u;
    mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;
    mouse.state = LIBRDP_MOUSE_PRESSED;

    key_status = librdp_session_send_key(session, &key);
    mouse_status = librdp_session_send_mouse(session, &mouse);

    printf("key=%s mouse=%s\n", librdp_status_string(key_status), librdp_status_string(mouse_status));

    librdp_session_free(session);
    return key_status == LIBRDP_STATUS_STATE && mouse_status == LIBRDP_STATUS_STATE ? 0 : 1;
}
