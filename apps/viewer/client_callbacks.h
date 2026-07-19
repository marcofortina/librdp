/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared client callback registration.
 * Invariants: callback domains remain independent and are installed together
 * before a session is driven.
 * Ownership: callback functions and user data are borrowed for the session
 * lifetime and remain application-owned.
 * Threading: bindings are configured on the session owner thread before
 * connect; callback execution follows the public session callback contract.
 * Trust boundary: remote event payloads remain borrowed librdp objects and are
 * never retained or interpreted by this registration layer.
 */

#ifndef LIBRDP_APP_CLIENT_CALLBACKS_H
#define LIBRDP_APP_CLIENT_CALLBACKS_H

#include <librdp/librdp.h>

typedef struct client_callbacks
{
    librdp_event_callback event;
    void* event_user_data;
    librdp_event_envelope_callback envelope;
    void* envelope_user_data;
    librdp_domain_event_callback graphics;
    void* graphics_user_data;
    librdp_domain_event_callback pointer;
    void* pointer_user_data;
    librdp_domain_event_callback channel;
    void* channel_user_data;
    librdp_domain_event_callback clipboard;
    void* clipboard_user_data;
    librdp_domain_event_callback audio;
    void* audio_user_data;
    librdp_domain_event_callback video;
    void* video_user_data;
    librdp_graphics_update_callback graphics_update;
    void* graphics_update_user_data;
} client_callbacks;

void client_callbacks_init(client_callbacks* callbacks);
librdp_status client_callbacks_apply(librdp_session* session,
                                     const client_callbacks* callbacks);

#endif
