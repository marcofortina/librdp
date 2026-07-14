/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal camera capture redirection contracts.
 * Invariants: capture control and data channels validate stream, media type,
 * sample correlation, and frame bounds before dispatch.
 * Ownership: selected camera media state and capture lifecycle flags are
 * session-owned.
 * Threading: camera channel handlers run on the session owner thread.
 * Trust boundary: camera media samples are sensitive user data and are never
 * traced as payload.
 */

#ifndef RDP_CLIENT_SESSION_CAMERA_H
#define RDP_CLIENT_SESSION_CAMERA_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_session_handle_video_capture_control_message(librdp_session* session,
                                                               uint32_t channel_id,
                                                               const uint8_t* data,
                                                               size_t data_len);
librdp_status rdp_session_handle_video_capture_data_message(librdp_session* session,
                                                            uint32_t channel_id,
                                                            const uint8_t* data,
                                                            size_t data_len);
void rdp_session_video_capture_reset(librdp_session* session);

#endif
