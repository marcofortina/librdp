/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: minimal session construction example.
 * Invariants: settings are completed before session creation and the borrowed
 * surface pointer is not used after the session is freed.
 * Ownership: settings are caller-owned until session creation copies them.
 * Threading: single-threaded setup only.
 * Trust boundary: no network connection is attempted by this example.
 */

#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    const librdp_surface* surface = NULL;

    if (!settings)
        return 1;

    if (librdp_settings_set_target(settings, "127.0.0.1") != LIBRDP_STATUS_OK ||
        librdp_settings_set_username(settings, "user") != LIBRDP_STATUS_OK ||
        librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_NLA) != LIBRDP_STATUS_OK ||
        librdp_settings_set_desktop_size(settings, 1024u, 768u) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    surface = librdp_session_get_surface(session);
    if (!surface)
    {
        librdp_session_free(session);
        return 1;
    }

    printf("state=%d surface=%ux%u stride=%zu\n",
           (int)librdp_session_get_state(session),
           librdp_surface_width(surface),
           librdp_surface_height(surface),
           librdp_surface_stride(surface));

    librdp_session_free(session);
    return 0;
}
