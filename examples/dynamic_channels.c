/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: dynamic channel API example.
 * Invariants: a static channel is registered before session creation and the
 * dynamic handle is closed before the session is released.
 * Ownership: settings own copied channel names; session owns channel handles.
 * Threading: single-threaded API exercise.
 * Trust boundary: no remote channel payload is parsed in this example.
 */

#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    librdp_static_channel_info static_info;
    librdp_channel_handle handle = 0;
    librdp_status status;

    if (!settings)
        return 1;

    if (librdp_settings_add_static_channel(settings, "appchan", 0u) != LIBRDP_STATUS_OK ||
        librdp_static_channel_info_init(&static_info) != LIBRDP_STATUS_OK ||
        librdp_settings_static_channel_info(settings, 0u, &static_info) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    status = librdp_session_channel_open(session,
                                         "example-control",
                                         LIBRDP_CHANNEL_PRIORITY_MEDIUM,
                                         &handle);

    printf("static=%s active=%d dynamic_open=%s\n",
           static_info.name,
           static_info.active,
           librdp_status_string(status));

    librdp_session_free(session);
    return status == LIBRDP_STATUS_STATE ? 0 : 1;
}
