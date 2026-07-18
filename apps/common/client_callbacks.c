/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared client callback registration implementation.
 * Invariants: every domain callback is applied exactly once from one immutable
 * descriptor before dispatch starts.
 * Ownership: no callback or user-data pointer is copied beyond the storage
 * performed by the public session setters.
 * Threading: callers serialize registration with session dispatch.
 * Trust boundary: this module installs handlers but never observes remote
 * payloads, credentials, pixels, clipboard data, or media samples.
 */

#include "client_callbacks.h"

#include <string.h>

void client_callbacks_init(client_callbacks* callbacks)
{
    if (!callbacks)
        return;
    memset(callbacks, 0, sizeof(*callbacks));
}

librdp_status client_callbacks_apply(librdp_session* session,
                                     const client_callbacks* callbacks)
{
    if (!session || !callbacks)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    librdp_session_set_event_callback(session,
                                      callbacks->event,
                                      callbacks->event_user_data);
    librdp_session_set_event_envelope_callback(session,
                                               callbacks->envelope,
                                               callbacks->envelope_user_data);
    librdp_session_set_graphics_callback(session,
                                         callbacks->graphics,
                                         callbacks->graphics_user_data);
    librdp_session_set_pointer_callback(session,
                                        callbacks->pointer,
                                        callbacks->pointer_user_data);
    librdp_session_set_channel_callback(session,
                                        callbacks->channel,
                                        callbacks->channel_user_data);
    librdp_session_set_clipboard_callback(session,
                                          callbacks->clipboard,
                                          callbacks->clipboard_user_data);
    librdp_session_set_audio_callback(session,
                                      callbacks->audio,
                                      callbacks->audio_user_data);
    librdp_session_set_video_callback(session,
                                      callbacks->video,
                                      callbacks->video_user_data);
    librdp_session_set_graphics_update_callback(session,
                                                callbacks->graphics_update,
                                                callbacks->graphics_update_user_data);
    return LIBRDP_STATUS_OK;
}
