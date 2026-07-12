/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <librdp/librdp.h>

int main(void)
{
    librdp_settings* settings = librdp_settings_new();
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
