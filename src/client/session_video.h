/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal video and optimized-video contracts.
 * Invariants: stream ids, presentation ids, geometry bindings, timestamps, and
 * queue limits are validated before samples reach callbacks.
 * Ownership: video stream state and sample accounting are session-owned.
 * Threading: video channel dispatch runs on the session owner thread.
 * Trust boundary: video payloads are media data and remain redacted from trace.
 */

#ifndef RDP_CLIENT_SESSION_VIDEO_H
#define RDP_CLIENT_SESSION_VIDEO_H

#include <librdp/session.h>

#include <stddef.h>
#include <stdint.h>

struct rdp_session_dynamic_channel;

librdp_status rdp_session_handle_video_redirection_message(librdp_session* session,
                                                           struct rdp_session_dynamic_channel* channel,
                                                           uint32_t channel_id,
                                                           const uint8_t* data,
                                                           size_t data_len);
librdp_status rdp_session_handle_video_optimized_control_message(librdp_session* session,
                                                                 uint32_t channel_id,
                                                                 const uint8_t* data,
                                                                 size_t data_len);
librdp_status rdp_session_handle_video_optimized_data_message(librdp_session* session,
                                                              struct rdp_session_dynamic_channel* entry,
                                                              uint32_t channel_id,
                                                              const uint8_t* data,
                                                              size_t data_len);
librdp_status rdp_session_handle_geometry_tracking_message(librdp_session* session,
                                                           uint32_t channel_id,
                                                           const uint8_t* data,
                                                           size_t data_len);
void rdp_session_video_redirection_reset(librdp_session* session);
void rdp_session_video_optimized_reset(librdp_session* session);
void rdp_session_geometry_tracking_reset(librdp_session* session);
int rdp_session_geometry_mapping_available(const librdp_session* session,
                                           uint64_t mapping_id);
int rdp_session_video_runtime_active(const librdp_session* session);

#endif
