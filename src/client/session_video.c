/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client video redirection session domain for TSMF and optimized video.
 * Invariants: presentation and stream IDs are tracked before samples are emitted, and media payloads are never dumped in trace.
 * Ownership: stream and presentation slots are session-owned; channel payload buffers are borrowed for dispatch duration only.
 * Threading: called on the session owner thread through the dynamic-channel dispatcher.
 * Trust boundary: server media control PDUs are parsed, bounded, and sequenced before public channel callbacks receive payloads.
 */

#include "client/session_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void rdp_session_geometry_mapping_clear(
    rdp_session_geometry_mapping* mapping);
static rdp_session_geometry_mapping* rdp_session_geometry_mapping_find(
    librdp_session* session,
    uint64_t mapping_id);
static rdp_session_geometry_mapping* rdp_session_geometry_mapping_unused(
    librdp_session* session);

static void rdp_session_video_geometry_counter_add(uint32_t* counter, uint32_t value)
{
    if (!counter)
        return;
    if (value > UINT32_MAX - *counter)
        *counter = UINT32_MAX;
    else
        *counter += value;
}

static void rdp_session_video_geometry_clear(rdp_session_video_geometry* geometry)
{
    if (!geometry)
        return;
    free(geometry->visible_rects);
    memset(geometry, 0, sizeof(*geometry));
}

/*
 * Geometry entries are keyed by presentation and video-window identifiers.
 * Keeping both identifiers prevents one presentation from overwriting another
 * when the server reuses a window number.
 */
static rdp_session_video_geometry* rdp_session_video_geometry_find(
    librdp_session* session,
    const uint8_t presentation_id[16],
    uint64_t video_window_id)
{
    uint32_t i = 0;

    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_GEOMETRIES; i++)
    {
        rdp_session_video_geometry* geometry = &session->video_geometries[i];

        if (geometry->active &&
            geometry->video_window_id == video_window_id &&
            memcmp(geometry->presentation_id, presentation_id, 16u) == 0)
            return geometry;
    }
    return NULL;
}

static rdp_session_video_geometry* rdp_session_video_geometry_unused(librdp_session* session)
{
    uint32_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_GEOMETRIES; i++)
    {
        if (!session->video_geometries[i].active)
            return &session->video_geometries[i];
    }
    return NULL;
}

/*
 * Visible rectangles arrive in desktop coordinates. This routine validates
 * every rectangle and stores only its intersection with the associated video
 * window, so decoder or compositor backends never receive out-of-window
 * regions.
 */
static librdp_status rdp_session_video_geometry_clip_rects(
    const rdp_video_redirection_geometry_update* update,
    const rdp_video_redirection_geometry_info* info,
    rdp_video_redirection_rect** visible_rects,
    uint32_t* visible_rect_count,
    uint32_t* clipped_count)
{
    rdp_video_redirection_rect* rects = NULL;
    uint32_t input_count = 0;
    uint32_t output_count = 0;
    uint32_t clipped = 0;
    uint32_t window_right = 0;
    uint32_t window_bottom = 0;
    uint32_t i = 0;

    if (!update || !info || !visible_rects || !visible_rect_count || !clipped_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *visible_rects = NULL;
    *visible_rect_count = 0;
    *clipped_count = 0;
    if (update->visible_rect_len == 0)
        return LIBRDP_STATUS_OK;
    if ((info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_VISRGN) == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    input_count = update->visible_rect_len / 16u;
    rects = (rdp_video_redirection_rect*)calloc(input_count, sizeof(*rects));
    if (!rects)
        return LIBRDP_STATUS_NO_MEMORY;
    window_right = info->left + info->width;
    window_bottom = info->top + info->height;
    for (i = 0; i < input_count; i++)
    {
        rdp_video_redirection_rect rect;
        rdp_video_redirection_rect clipped_rect;
        librdp_status status =
            rdp_video_redirection_parse_rect(update->visible_rect + ((size_t)i * 16u),
                                             16u,
                                             &rect);

        if (status != LIBRDP_STATUS_OK)
        {
            free(rects);
            return status;
        }
        clipped_rect.top = rect.top > info->top ? rect.top : info->top;
        clipped_rect.left = rect.left > info->left ? rect.left : info->left;
        clipped_rect.bottom = rect.bottom < window_bottom ? rect.bottom : window_bottom;
        clipped_rect.right = rect.right < window_right ? rect.right : window_right;
        if (clipped_rect.top >= clipped_rect.bottom ||
            clipped_rect.left >= clipped_rect.right)
        {
            clipped++;
            continue;
        }
        if (rect.top != clipped_rect.top ||
            rect.left != clipped_rect.left ||
            rect.bottom != clipped_rect.bottom ||
            rect.right != clipped_rect.right)
            clipped++;
        rects[output_count++] = clipped_rect;
    }
    if (output_count == 0)
    {
        free(rects);
        rects = NULL;
    }
    *visible_rects = rects;
    *visible_rect_count = output_count;
    *clipped_count = clipped;
    return LIBRDP_STATUS_OK;
}

static void rdp_session_video_geometry_update_streams(
    librdp_session* session,
    const uint8_t presentation_id[16],
    const rdp_video_redirection_geometry_info* info,
    uint8_t removed)
{
    uint32_t i = 0;

    if (!session || !presentation_id || !info)
        return;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        rdp_session_video_stream* stream = &session->video_streams[i];

        if (!stream->active ||
            memcmp(stream->presentation_id, presentation_id, 16u) != 0)
            continue;
        if (removed && stream->video_window_id == info->video_window_id)
        {
            stream->video_window_id = 0;
            stream->width = 0;
            stream->height = 0;
        }
        else if (!removed)
        {
            stream->video_window_id = info->video_window_id;
            stream->width = info->width;
            stream->height = info->height;
        }
    }
}

/*
 * Apply one geometry update atomically. Malformed rectangles cannot partially
 * replace an existing region, while late updates for a removed region are
 * counted and ignored without recreating stale state.
 */
static librdp_status rdp_session_video_geometry_apply(
    librdp_session* session,
    const rdp_video_redirection_geometry_update* update,
    const rdp_video_redirection_geometry_info* info,
    const char** action)
{
    rdp_session_video_geometry* geometry = NULL;
    rdp_video_redirection_rect* visible_rects = NULL;
    uint32_t visible_rect_count = 0;
    uint32_t clipped_count = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t created = 0;

    if (!session || !update || !info || !action)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *action = "update";
    if ((info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_DELETED) != 0)
    {
        if (update->visible_rect_len != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        geometry = rdp_session_video_geometry_find(session,
                                                   update->presentation_id,
                                                   info->video_window_id);
        if (!geometry)
        {
            rdp_session_video_geometry_counter_add(&session->video_geometry_stale_count, 1u);
            rdp_session_video_geometry_counter_add(&session->video_geometry_update_count, 1u);
            *action = "stale";
            return LIBRDP_STATUS_OK;
        }
        rdp_session_video_geometry_update_streams(session,
                                                  update->presentation_id,
                                                  info,
                                                  1u);
        rdp_session_video_geometry_clear(geometry);
        if (session->video_geometry_active_count > 0)
            session->video_geometry_active_count--;
        rdp_session_video_geometry_counter_add(&session->video_geometry_update_count, 1u);
        *action = "delete";
        return LIBRDP_STATUS_OK;
    }

    status = rdp_session_video_geometry_clip_rects(update,
                                                   info,
                                                   &visible_rects,
                                                   &visible_rect_count,
                                                   &clipped_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    geometry = rdp_session_video_geometry_find(session,
                                               update->presentation_id,
                                               info->video_window_id);
    if (!geometry && (info->window_state & RDP_VIDEO_REDIRECTION_WINDOW_NEW) == 0)
    {
        free(visible_rects);
        rdp_session_video_geometry_counter_add(&session->video_geometry_stale_count, 1u);
        rdp_session_video_geometry_counter_add(&session->video_geometry_update_count, 1u);
        rdp_session_video_geometry_counter_add(&session->video_geometry_clipped_count,
                                               clipped_count);
        *action = "stale";
        return LIBRDP_STATUS_OK;
    }
    if (!geometry)
    {
        geometry = rdp_session_video_geometry_unused(session);
        if (!geometry)
        {
            free(visible_rects);
            return rdp_session_limit_rejected(session);
        }
        created = 1u;
    }
    free(geometry->visible_rects);
    memset(geometry, 0, sizeof(*geometry));
    geometry->active = 1u;
    memcpy(geometry->presentation_id, update->presentation_id, 16u);
    geometry->video_window_id = info->video_window_id;
    geometry->last_message_id = update->header.message_id;
    geometry->info = *info;
    geometry->visible_rect_count = visible_rect_count;
    geometry->visible_rects = visible_rects;
    if (created)
        rdp_session_video_geometry_counter_add(&session->video_geometry_active_count, 1u);
    rdp_session_video_geometry_counter_add(&session->video_geometry_update_count, 1u);
    rdp_session_video_geometry_counter_add(&session->video_geometry_clipped_count,
                                           clipped_count);
    rdp_session_video_geometry_update_streams(session,
                                              update->presentation_id,
                                              info,
                                              0u);
    *action = created ? "new" : "update";
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_session_video_geometry_remove_presentation(
    librdp_session* session,
    const uint8_t presentation_id[16])
{
    uint32_t removed = 0;
    uint32_t i = 0;

    if (!session || !presentation_id)
        return 0;
    for (i = 0; i < RDP_SESSION_VIDEO_GEOMETRIES; i++)
    {
        rdp_session_video_geometry* geometry = &session->video_geometries[i];

        if (!geometry->active ||
            memcmp(geometry->presentation_id, presentation_id, 16u) != 0)
            continue;
        rdp_session_video_geometry_clear(geometry);
        removed++;
    }
    if (removed >= session->video_geometry_active_count)
        session->video_geometry_active_count = 0;
    else
        session->video_geometry_active_count -= removed;
    return removed;
}

void rdp_session_video_redirection_reset(librdp_session* session)
{
    uint32_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_VIDEO_GEOMETRIES; i++)
        rdp_session_video_geometry_clear(&session->video_geometries[i]);
    session->video_redirection_channel_id = 0;
    session->video_redirection_channel_id_bytes = 0;
    session->video_redirection_ready = 0;
    session->video_redirection_capabilities_sent = 0;
    session->video_redirection_rim_sent = 0;
    session->video_geometry_update_count = 0;
    session->video_geometry_active_count = 0;
    session->video_geometry_stale_count = 0;
    session->video_geometry_clipped_count = 0;
    memset(session->video_streams, 0, sizeof(session->video_streams));
}

void rdp_session_video_optimized_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_optimized_control_channel_id = 0;
    session->video_optimized_control_channel_id_bytes = 0;
    session->video_optimized_control_ready = 0;
    session->video_optimized_data_channel_id = 0;
    session->video_optimized_data_channel_id_bytes = 0;
    memset(session->video_optimized_presentations, 0, sizeof(session->video_optimized_presentations));
}

void rdp_session_geometry_tracking_reset(librdp_session* session)
{
    if (!session)
        return;
    for (uint32_t i = 0; i < RDP_SESSION_GEOMETRY_MAPPINGS; i++)
        rdp_session_geometry_mapping_clear(&session->geometry_mappings[i]);
    session->geometry_tracking_channel_id = 0;
    session->geometry_tracking_channel_id_bytes = 0;
    session->geometry_tracking_update_count = 0;
    session->geometry_tracking_active_count = 0;
    session->geometry_tracking_stale_count = 0;
}

/*
 * Commit a complete mapped geometry only after every rectangle has been
 * validated and copied. Clear for an unknown mapping is intentionally ignored
 * while still contributing to stale-message diagnostics.
 */
librdp_status rdp_session_handle_geometry_tracking_message(
    librdp_session* session,
    uint32_t channel_id,
    const uint8_t* data,
    size_t data_len)
{
    rdp_geometry_tracking_packet packet;
    rdp_session_geometry_mapping* mapping = NULL;
    rdp_session_geometry_mapping next;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t created = 0;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&packet, 0, sizeof(packet));
    status = rdp_geometry_tracking_parse(data, data_len, &packet);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.geometry.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }

    mapping = rdp_session_geometry_mapping_find(session, packet.mapping_id);
    rdp_session_video_geometry_counter_add(
        &session->geometry_tracking_update_count,
        1u);
    if (packet.update_type == RDP_GEOMETRY_TRACKING_CLEAR)
    {
        if (!mapping)
        {
            rdp_session_video_geometry_counter_add(
                &session->geometry_tracking_stale_count,
                1u);
            rdp_trace_event_level(
                RDP_TRACE_CLIENT,
                RDP_TRACE_LEVEL_DEBUG,
                "client.geometry.clear",
                "dvc_channel_id=%u mapping_id=%llu action=ignored active=%u stale=%u",
                channel_id,
                (unsigned long long)packet.mapping_id,
                session->geometry_tracking_active_count,
                session->geometry_tracking_stale_count);
            return LIBRDP_STATUS_OK;
        }
        rdp_session_geometry_mapping_clear(mapping);
        if (session->geometry_tracking_active_count > 0)
            session->geometry_tracking_active_count--;
        rdp_trace_event(
            RDP_TRACE_CLIENT,
            "client.geometry.clear",
            "dvc_channel_id=%u mapping_id=%llu action=removed active=%u stale=%u",
            channel_id,
            (unsigned long long)packet.mapping_id,
            session->geometry_tracking_active_count,
            session->geometry_tracking_stale_count);
        return LIBRDP_STATUS_OK;
    }
    if (packet.geometry_buffer_len >
            session->limits.dynamic_channel_message_bytes ||
        packet.rect_count >
            session->limits.dynamic_channel_message_bytes /
                sizeof(rdp_geometry_tracking_rect))
        return rdp_session_limit_rejected(session);

    memset(&next, 0, sizeof(next));
    if (packet.rect_count > 0)
    {
        next.rects = (rdp_geometry_tracking_rect*)calloc(
            packet.rect_count,
            sizeof(*next.rects));
        if (!next.rects)
            return LIBRDP_STATUS_NO_MEMORY;
        for (uint32_t i = 0; i < packet.rect_count; i++)
        {
            status = rdp_geometry_tracking_get_rect(&packet,
                                                    i,
                                                    &next.rects[i]);
            if (status != LIBRDP_STATUS_OK)
            {
                free(next.rects);
                return status;
            }
        }
    }
    if (!mapping)
    {
        mapping = rdp_session_geometry_mapping_unused(session);
        if (!mapping)
        {
            free(next.rects);
            return rdp_session_limit_rejected(session);
        }
        created = 1u;
    }
    next.active = 1u;
    next.mapping_id = packet.mapping_id;
    next.top_level_id = packet.top_level_id;
    next.local_bounds = packet.local_bounds;
    next.top_level_bounds = packet.top_level_bounds;
    next.region_bounds = packet.region_bounds;
    next.rect_count = packet.rect_count;
    rdp_session_geometry_mapping_clear(mapping);
    *mapping = next;
    if (created)
    {
        rdp_session_video_geometry_counter_add(
            &session->geometry_tracking_active_count,
            1u);
    }
    rdp_trace_event(
        RDP_TRACE_CLIENT,
        "client.geometry.update",
        "dvc_channel_id=%u mapping_id=%llu action=%s top_level_id=%llu left=%d top=%d right=%d bottom=%d rects=%u active=%u",
        channel_id,
        (unsigned long long)packet.mapping_id,
        created ? "created" : "updated",
        (unsigned long long)packet.top_level_id,
        packet.local_bounds.left,
        packet.local_bounds.top,
        packet.local_bounds.right,
        packet.local_bounds.bottom,
        packet.rect_count,
        session->geometry_tracking_active_count);
    return LIBRDP_STATUS_OK;
}

static rdp_session_video_optimized_presentation* rdp_session_video_optimized_find(librdp_session* session,
                                                                                  uint8_t presentation_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (session->video_optimized_presentations[i].active &&
            session->video_optimized_presentations[i].presentation_id == presentation_id)
            return &session->video_optimized_presentations[i];
    }
    return NULL;
}

static rdp_session_video_optimized_presentation* rdp_session_video_optimized_upsert(librdp_session* session,
                                                                                    uint8_t presentation_id)
{
    size_t i = 0;
    rdp_session_video_optimized_presentation* entry = rdp_session_video_optimized_find(session, presentation_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (!session->video_optimized_presentations[i].active)
        {
            memset(&session->video_optimized_presentations[i], 0, sizeof(session->video_optimized_presentations[i]));
            session->video_optimized_presentations[i].active = 1;
            session->video_optimized_presentations[i].presentation_id = presentation_id;
            return &session->video_optimized_presentations[i];
        }
    }
    return NULL;
}

typedef enum rdp_session_video_sequence
{
    RDP_SESSION_VIDEO_SEQUENCE_VALID = 0,
    RDP_SESSION_VIDEO_SEQUENCE_GAP = 1,
    RDP_SESSION_VIDEO_SEQUENCE_INVALID = 2
} rdp_session_video_sequence;

static rdp_session_video_sequence rdp_session_video_optimized_sample_sequence(
    const rdp_session_video_optimized_presentation* presentation,
    const rdp_video_optimized_video_data* video)
{
    uint32_t expected_sample = 0;

    if (!presentation || !video)
        return RDP_SESSION_VIDEO_SEQUENCE_INVALID;
    if (!presentation->sequence_initialized)
    {
        return (presentation->sample_count > 0 ||
                video->sample_number == 1u) &&
                       video->current_packet_index == 1u ?
                   RDP_SESSION_VIDEO_SEQUENCE_VALID :
                   RDP_SESSION_VIDEO_SEQUENCE_INVALID;
    }
    if (video->sample_number == presentation->last_sample_number)
    {
        if (video->packets_in_sample != presentation->last_packets_in_sample ||
            video->current_packet_index <= presentation->last_packet_index)
            return RDP_SESSION_VIDEO_SEQUENCE_INVALID;
        return video->current_packet_index ==
                       (uint16_t)(presentation->last_packet_index + 1u) ?
                   RDP_SESSION_VIDEO_SEQUENCE_VALID :
                   RDP_SESSION_VIDEO_SEQUENCE_GAP;
    }
    expected_sample = presentation->last_sample_number == UINT32_MAX ?
                          1u :
                          presentation->last_sample_number + 1u;
    if (video->sample_number == expected_sample)
    {
        return presentation->last_packet_index ==
                           presentation->last_packets_in_sample &&
                       video->current_packet_index == 1u ?
                   RDP_SESSION_VIDEO_SEQUENCE_VALID :
                   RDP_SESSION_VIDEO_SEQUENCE_GAP;
    }
    if (video->sample_number > expected_sample &&
        video->current_packet_index == 1u)
        return RDP_SESSION_VIDEO_SEQUENCE_GAP;
    return RDP_SESSION_VIDEO_SEQUENCE_INVALID;
}

static void rdp_session_video_optimized_remove(librdp_session* session, uint8_t presentation_id)
{
    rdp_session_video_optimized_presentation* entry = rdp_session_video_optimized_find(session, presentation_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static void rdp_session_video_optimized_sequence_reset(
    rdp_session_video_optimized_presentation* presentation)
{
    if (!presentation)
        return;
    presentation->recovery_notified = 0;
    presentation->sequence_initialized = 0;
    presentation->last_timestamp = 0;
    presentation->last_duration = 0;
    presentation->last_sample_number = 0;
    presentation->last_packet_index = 0;
    presentation->last_packets_in_sample = 0;
    presentation->last_flags = 0;
}

static void rdp_session_geometry_mapping_clear(
    rdp_session_geometry_mapping* mapping)
{
    if (!mapping)
        return;
    free(mapping->rects);
    memset(mapping, 0, sizeof(*mapping));
}

static rdp_session_geometry_mapping* rdp_session_geometry_mapping_find(
    librdp_session* session,
    uint64_t mapping_id)
{
    if (!session)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_GEOMETRY_MAPPINGS; i++)
    {
        if (session->geometry_mappings[i].active &&
            session->geometry_mappings[i].mapping_id == mapping_id)
            return &session->geometry_mappings[i];
    }
    return NULL;
}

int rdp_session_geometry_mapping_available(const librdp_session* session,
                                           uint64_t mapping_id)
{
    if (!session)
        return 0;
    for (uint32_t i = 0; i < RDP_SESSION_GEOMETRY_MAPPINGS; i++)
    {
        if (session->geometry_mappings[i].active &&
            session->geometry_mappings[i].mapping_id == mapping_id)
            return 1;
    }
    return 0;
}

static rdp_session_geometry_mapping* rdp_session_geometry_mapping_unused(
    librdp_session* session)
{
    uint32_t limit = 0;

    if (!session)
        return NULL;
    limit = session->limits.surface_count;
    if (limit > RDP_SESSION_GEOMETRY_MAPPINGS)
        limit = RDP_SESSION_GEOMETRY_MAPPINGS;
    for (uint32_t i = 0; i < limit; i++)
    {
        if (!session->geometry_mappings[i].active)
            return &session->geometry_mappings[i];
    }
    return NULL;
}

static rdp_session_video_stream* rdp_session_video_stream_find(librdp_session* session,
                                                               const uint8_t presentation_id[16],
                                                               uint32_t stream_id)
{
    uint32_t i = 0;

    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active &&
            session->video_streams[i].stream_id == stream_id &&
            memcmp(session->video_streams[i].presentation_id, presentation_id, 16u) == 0)
            return &session->video_streams[i];
    }
    return NULL;
}

static rdp_session_video_stream* rdp_session_video_stream_upsert(librdp_session* session,
                                                                 const uint8_t presentation_id[16],
                                                                 uint32_t stream_id)
{
    uint32_t i = 0;
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        return entry;
    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (!session->video_streams[i].active)
        {
            memset(&session->video_streams[i], 0, sizeof(session->video_streams[i]));
            session->video_streams[i].active = 1;
            session->video_streams[i].stream_id = stream_id;
            memcpy(session->video_streams[i].presentation_id, presentation_id, 16u);
            return &session->video_streams[i];
        }
    }
    return NULL;
}

static void rdp_session_video_stream_remove(librdp_session* session,
                                            const uint8_t presentation_id[16],
                                            uint32_t stream_id)
{
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static uint32_t rdp_session_video_presentation_update(librdp_session* session,
                                                      const uint8_t presentation_id[16],
                                                      uint8_t set_paused,
                                                      uint8_t paused,
                                                      uint8_t increment_preroll,
                                                      uint32_t rate_bits)
{
    uint32_t i = 0;
    uint32_t matched = 0;

    if (!session || !presentation_id)
        return 0;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        rdp_session_video_stream* entry = &session->video_streams[i];

        if (!entry->active || memcmp(entry->presentation_id, presentation_id, 16u) != 0)
            continue;
        if (set_paused)
            entry->paused = paused;
        if (increment_preroll)
            entry->preroll_count++;
        if (rate_bits != UINT32_MAX)
            entry->playback_rate_bits = rate_bits;
        matched++;
    }
    return matched;
}

static uint32_t rdp_session_video_presentation_remove(librdp_session* session,
                                                      const uint8_t presentation_id[16])
{
    uint32_t i = 0;
    uint32_t removed = 0;

    if (!session || !presentation_id)
        return 0;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active &&
            memcmp(session->video_streams[i].presentation_id, presentation_id, 16u) == 0)
        {
            memset(&session->video_streams[i], 0, sizeof(session->video_streams[i]));
            removed++;
        }
    }
    return removed;
}

static void rdp_session_write_u32_bytes(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

static librdp_status rdp_session_send_video_redirection_packet(librdp_session* session,
                                                               const rdp_buffer* payload,
                                                               const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->video_redirection_channel_id == 0 || session->video_redirection_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->video_redirection_channel_id,
                                                 session->video_redirection_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capabilities(librdp_session* session, uint32_t message_id)
{
    uint8_t protocol[4];
    uint8_t platform[4];
    uint8_t audio[4];
    rdp_video_redirection_capability caps[3];
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2, protocol);
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PLATFORM_OTHER, platform);
    rdp_session_write_u32_bytes(
        rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_AUDIO_OUTPUT) ?
            RDP_VIDEO_REDIRECTION_AUDIO_SUPPORTED :
            RDP_VIDEO_REDIRECTION_AUDIO_NO_DEVICE,
        audio);
    memset(caps, 0, sizeof(caps));
    caps[0].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION;
    caps[0].length = sizeof(protocol);
    caps[0].data = protocol;
    caps[0].data_len = sizeof(protocol);
    caps[1].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM;
    caps[1].length = sizeof(platform);
    caps[1].data = platform;
    caps[1].data_len = sizeof(platform);
    caps[2].type = RDP_VIDEO_REDIRECTION_CAPABILITY_AUDIO_SUPPORT;
    caps[2].length = sizeof(audio);
    caps[2].data = audio;
    caps[2].data_len = sizeof(audio);
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_exchange_capabilities_response(&response,
                                                                        message_id,
                                                                        caps,
                                                                        3u,
                                                                        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.capabilities.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_capabilities_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.response",
                        "dvc_channel_id=%u message_id=%u audio=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        audio[0]);
    }
    return status;
}

static librdp_status rdp_session_send_video_rim(librdp_session* session, uint32_t message_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_rim_capability_response(
        &response,
        message_id,
        RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01,
        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.rim.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_rim_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.rim.response",
                        "dvc_channel_id=%u message_id=%u",
                        session->video_redirection_channel_id,
                        message_id);
    }
    return status;
}

static librdp_status rdp_session_send_video_format_support(librdp_session* session,
                                                           uint32_t message_id,
                                                           uint32_t platform_cookie,
                                                           uint32_t supported)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || supported > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_check_format_support_response(&response,
                                                                       message_id,
                                                                       supported,
                                                                       platform_cookie,
                                                                       RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.format.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.format.response",
                        "dvc_channel_id=%u message_id=%u platform=%u supported=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        platform_cookie,
                        supported);
    return status;
}

static librdp_status rdp_session_send_video_topology(librdp_session* session,
                                                     uint32_t message_id,
                                                     uint32_t ready)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || ready > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_set_topology_response(&response,
                                                               message_id,
                                                               ready,
                                                               RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.topology.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.topology.response",
                        "dvc_channel_id=%u message_id=%u ready=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        ready);
    return status;
}

static librdp_status rdp_session_send_video_event(librdp_session* session,
                                                  uint32_t message_id,
                                                  uint32_t stream_id,
                                                  uint32_t event_id,
                                                  const char* event_name)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_client_event(&response, message_id, stream_id, event_id, NULL, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, event_name);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event_name,
                        "dvc_channel_id=%u message_id=%u stream_id=%u event_id=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        event_id);
    return status;
}

static librdp_status rdp_session_send_video_sample_ack(librdp_session* session,
                                                       uint32_t message_id,
                                                       uint32_t stream_id,
                                                       uint64_t duration,
                                                       uint64_t data_len)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_playback_ack(&response,
                                                      message_id,
                                                      stream_id,
                                                      duration,
                                                      data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, "client.tsmf.sample.ack");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.sample.ack",
                        "dvc_channel_id=%u message_id=%u stream_id=%u duration=%llu data_len=%llu",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        (unsigned long long)duration,
                        (unsigned long long)data_len);
    return status;
}

static librdp_status rdp_session_send_video_optimized_control(librdp_session* session,
                                                              const rdp_buffer* payload,
                                                              const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->video_optimized_control_channel_id == 0 ||
        session->video_optimized_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->video_optimized_control_channel_id,
                                                 session->video_optimized_control_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_optimized_presentation_response(librdp_session* session,
                                                                           uint8_t presentation_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_optimized_write_presentation_response(&response, presentation_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_optimized_control(session,
                                                          &response,
                                                          "client.video_optimized.presentation.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.presentation.response",
                        "dvc_channel_id=%u presentation_id=%u",
                        session->video_optimized_control_channel_id,
                        presentation_id);
    return status;
}

/*
 * Report packet loss or reordering once per recovery interval. The protocol
 * reserves this notification for transport discontinuities so geometry and
 * local resource-policy failures must not pass through this path.
 */
static librdp_status rdp_session_send_video_optimized_recovery(
    librdp_session* session,
    rdp_session_video_optimized_presentation* presentation,
    const char* reason)
{
    rdp_buffer notification;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !presentation || !reason)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (presentation->recovery_notified)
        return LIBRDP_STATUS_OK;

    rdp_buffer_init(&notification);
    status = rdp_video_optimized_write_client_notification(
        &notification,
        presentation->presentation_id,
        RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR,
        NULL,
        0);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_session_send_video_optimized_control(
            session,
            &notification,
            "client.video_optimized.recovery");
    }
    if (status == LIBRDP_STATUS_OK)
    {
        presentation->recovery_notified = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.recovery",
                        "presentation_id=%u reason=%s",
                        presentation->presentation_id,
                        reason);
    }
    rdp_buffer_free(&notification);
    return status;
}

/*
 * Handle video-optimized remoting control traffic. Presentation identifiers,
 * format negotiation, and stream state are validated before media payload
 * callbacks are enabled.
 */
librdp_status rdp_session_handle_video_optimized_control_message(librdp_session* session,
                                                                        uint32_t channel_id,
                                                                        const uint8_t* data,
                                                                        size_t data_len)
{
    rdp_video_optimized_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.control.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.control",
                          "dvc_channel_id=%u packet_type=%u payload_len=%u enabled=%u",
                          channel_id,
                          header.packet_type,
                          (unsigned)header.payload_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));

    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST)
    {
        rdp_video_optimized_presentation_request request;

        status = rdp_video_optimized_parse_presentation_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (request.command == RDP_VIDEO_OPTIMIZED_COMMAND_START)
        {
            rdp_session_video_optimized_presentation* entry = NULL;

            if (rdp_session_video_optimized_find(session,
                                                 request.presentation_id))
            {
                rdp_trace_event_level(
                    RDP_TRACE_CLIENT,
                    RDP_TRACE_LEVEL_DEBUG,
                    "client.video_optimized.presentation.ignored",
                    "dvc_channel_id=%u presentation_id=%u reason=duplicate_start",
                    channel_id,
                    request.presentation_id);
                return LIBRDP_STATUS_OK;
            }
            if (!rdp_session_geometry_mapping_available(
                    session,
                    request.geometry_mapping_id))
            {
                rdp_trace_event(
                    RDP_TRACE_CLIENT,
                    "client.video_optimized.presentation.ignored",
                    "dvc_channel_id=%u presentation_id=%u reason=geometry_unavailable mapping_id=%llu",
                    channel_id,
                    request.presentation_id,
                    (unsigned long long)request.geometry_mapping_id);
                return LIBRDP_STATUS_OK;
            }
            entry = rdp_session_video_optimized_upsert(session,
                                                       request.presentation_id);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->frame_rate = request.frame_rate;
            entry->average_bitrate_kbps = request.average_bitrate_kbps;
            entry->source_width = request.source_width;
            entry->source_height = request.source_height;
            entry->scaled_width = request.scaled_width;
            entry->scaled_height = request.scaled_height;
            entry->timestamp_offset = request.timestamp_offset;
            entry->geometry_mapping_id = request.geometry_mapping_id;
            status = rdp_session_send_video_optimized_presentation_response(session, request.presentation_id);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.video_optimized.presentation.start",
                                "dvc_channel_id=%u presentation_id=%u source_width=%u source_height=%u scaled_width=%u scaled_height=%u frame_rate=%u bitrate_kbps=%u extra_len=%u",
                                channel_id,
                                request.presentation_id,
                                request.source_width,
                                request.source_height,
                                request.scaled_width,
                                request.scaled_height,
                                request.frame_rate,
                                request.average_bitrate_kbps,
                                request.extra_len);
            return status;
        }
        if (!rdp_session_video_optimized_find(session,
                                              request.presentation_id))
        {
            rdp_trace_event_level(
                RDP_TRACE_CLIENT,
                RDP_TRACE_LEVEL_DEBUG,
                "client.video_optimized.presentation.ignored",
                "dvc_channel_id=%u presentation_id=%u reason=unknown_stop",
                channel_id,
                request.presentation_id);
            return LIBRDP_STATUS_OK;
        }
        rdp_session_video_optimized_remove(session, request.presentation_id);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.presentation.stop",
                        "dvc_channel_id=%u presentation_id=%u",
                        channel_id,
                        request.presentation_id);
        return LIBRDP_STATUS_OK;
    }
    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION)
    {
        rdp_video_optimized_client_notification notification;

        status = rdp_video_optimized_parse_client_notification(data, data_len, &notification);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE)
        {
            rdp_video_optimized_framerate_override framerate;

            status = rdp_video_optimized_parse_framerate_override(notification.data,
                                                                 notification.data_len,
                                                                 &framerate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.framerate",
                            "dvc_channel_id=%u presentation_id=%u flags=%u desired_frame_rate=%u",
                            channel_id,
                            notification.presentation_id,
                            framerate.flags,
                            framerate.desired_frame_rate);
        }
        else
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.network_error",
                            "dvc_channel_id=%u presentation_id=%u",
                            channel_id,
                            notification.presentation_id);
        }
        return LIBRDP_STATUS_OK;
    }
    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE)
    {
        rdp_video_optimized_presentation_response response;

        status = rdp_video_optimized_parse_presentation_response(data, data_len, &response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.presentation.response.recv",
                        "dvc_channel_id=%u presentation_id=%u",
                        channel_id,
                        response.presentation_id);
        return LIBRDP_STATUS_OK;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.control.skipped",
                          "dvc_channel_id=%u packet_type=%u payload_len=%u",
                          channel_id,
                          header.packet_type,
                          (unsigned)header.payload_len);
    return LIBRDP_STATUS_OK;
}

/*
 * Validate one optimized-video fragment against presentation state, media
 * limits, geometry availability and monotonic timestamps before exposing it
 * to the application. Missing geometry drops a valid but unusable sample,
 * while packet loss or reordering requests an intra frame for recovery.
 */
librdp_status rdp_session_handle_video_optimized_data_message(librdp_session* session,
                                                              rdp_session_dynamic_channel* entry,
                                                              uint32_t channel_id,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_video_optimized_video_data video;
    rdp_session_video_optimized_presentation* presentation = NULL;
    rdp_session_video_sequence sequence = RDP_SESSION_VIDEO_SEQUENCE_VALID;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !entry || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_parse_video_data(data, data_len, &video);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.data.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }

    presentation = rdp_session_video_optimized_find(session, video.presentation_id);
    if (!presentation)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.rejected",
                        "dvc_channel_id=%u presentation_id=%u reason=unknown_presentation sample_number=%u",
                        channel_id,
                        video.presentation_id,
                        video.sample_number);
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_session_geometry_mapping_available(
            session,
            presentation->geometry_mapping_id))
    {
        rdp_trace_event_level(
            RDP_TRACE_CLIENT,
            RDP_TRACE_LEVEL_DEBUG,
            "client.video_optimized.sample.ignored",
            "dvc_channel_id=%u presentation_id=%u reason=geometry_unavailable mapping_id=%llu sample_number=%u packet=%u",
            channel_id,
            video.presentation_id,
            (unsigned long long)presentation->geometry_mapping_id,
            video.sample_number,
            video.current_packet_index);
        return LIBRDP_STATUS_OK;
    }
    if (video.sample_len > session->limits.frame_bytes)
    {
        rdp_session_metric_add(&session->metrics.limits_rejected, 1);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.rejected",
                        "dvc_channel_id=%u presentation_id=%u reason=frame_limit sample_len=%u limit=%u",
                        channel_id,
                        video.presentation_id,
                        video.sample_len,
                        session->limits.frame_bytes);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (presentation->recovery_notified)
    {
        if ((video.flags & RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME) == 0 ||
            video.current_packet_index != 1u)
        {
            rdp_trace_event_level(
                RDP_TRACE_CLIENT,
                RDP_TRACE_LEVEL_DEBUG,
                "client.video_optimized.sample.ignored",
                "dvc_channel_id=%u presentation_id=%u reason=awaiting_keyframe sample_number=%u packet=%u",
                channel_id,
                video.presentation_id,
                video.sample_number,
                video.current_packet_index);
            return LIBRDP_STATUS_OK;
        }
        rdp_session_video_optimized_sequence_reset(presentation);
    }
    sequence = rdp_session_video_optimized_sample_sequence(presentation,
                                                           &video);
    if (sequence != RDP_SESSION_VIDEO_SEQUENCE_VALID)
    {
        status = rdp_session_send_video_optimized_recovery(
            session,
            presentation,
            sequence == RDP_SESSION_VIDEO_SEQUENCE_GAP ?
                "packet_gap" :
                "packet_order");
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.ignored",
                        "dvc_channel_id=%u presentation_id=%u reason=%s sample_number=%u packet=%u last_sample_number=%u last_packet=%u",
                        channel_id,
                        video.presentation_id,
                        sequence == RDP_SESSION_VIDEO_SEQUENCE_GAP ?
                            "packet_gap" :
                            "packet_order",
                        video.sample_number,
                        video.current_packet_index,
                        presentation->last_sample_number,
                        presentation->last_packet_index);
        if ((video.flags & RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME) == 0 ||
            video.current_packet_index != 1u)
            return LIBRDP_STATUS_OK;
        rdp_session_video_optimized_sequence_reset(presentation);
    }
    if ((video.flags & RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS) != 0 &&
        presentation->sequence_initialized &&
        video.timestamp < presentation->last_timestamp)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.rejected",
                        "dvc_channel_id=%u presentation_id=%u reason=timestamp sample_number=%u timestamp=%llu last_timestamp=%llu",
                        channel_id,
                        video.presentation_id,
                        video.sample_number,
                        (unsigned long long)video.timestamp,
                        (unsigned long long)presentation->last_timestamp);
        status = rdp_session_send_video_optimized_recovery(session,
                                                           presentation,
                                                           "timestamp_order");
        return status;
    }
    presentation->sample_count++;
    presentation->sample_bytes += video.sample_len;
    presentation->sequence_initialized = 1u;
    presentation->last_timestamp = video.timestamp;
    presentation->last_duration = video.duration;
    presentation->last_sample_number = video.sample_number;
    presentation->last_packet_index = video.current_packet_index;
    presentation->last_packets_in_sample = video.packets_in_sample;
    presentation->last_flags = video.flags;
    if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO) && video.sample_len > 0)
        rdp_session_emit_channel_data(session, entry, video.sample, video.sample_len);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.sample",
                          "dvc_channel_id=%u presentation_id=%u sample_number=%u packet=%u packets=%u flags=%u sample_len=%u samples=%llu bytes=%llu emitted=%u",
                          channel_id,
                          video.presentation_id,
                          video.sample_number,
                          video.current_packet_index,
                          video.packets_in_sample,
                          video.flags,
                          video.sample_len,
                          (unsigned long long)presentation->sample_count,
                          (unsigned long long)presentation->sample_bytes,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
    return LIBRDP_STATUS_OK;
}

/*
 * TSMF control and data messages can use either the full channel header or a
 * compact channel-specific header. Parse both forms here and keep presentation
 * bookkeeping synchronized with application data events.
 */
librdp_status rdp_session_handle_video_redirection_message(librdp_session* session,
                                                                  rdp_session_dynamic_channel* channel,
                                                                  uint32_t channel_id,
                                                                  const uint8_t* data,
                                                                  size_t data_len)
{
    rdp_video_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_parse_header(data, data_len, 1, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        status = rdp_video_redirection_parse_header(data, data_len, 0, &header);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.pdu.invalid",
                            "dvc_channel_id=%u payload_len=%u status=%s",
                            channel_id,
                            (unsigned)data_len,
                            librdp_status_string(status));
            return status;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.tsmf.pdu",
                          "dvc_channel_id=%u interface_id=%u stream_mask=%u message_id=%u function_id=%u payload_len=%u video_enabled=%u geometry_enabled=%u",
                          channel_id,
                          header.interface_id,
                          header.stream_id_mask,
                          header.message_id,
                          header.has_function_id ? header.function_id : 0u,
                          (unsigned)header.payload_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO),
                          rdp_session_feature_ready_for_negotiation(session,
                                                                    LIBRDP_FEATURE_GEOMETRY_TRACKING));
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST)
    {
        rdp_video_redirection_rim_capability request;

        status = rdp_video_redirection_parse_rim_capability_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_send_video_rim(session, request.header.message_id);
    }
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ)
    {
        rdp_video_redirection_capability_message request;

        status = rdp_video_redirection_parse_exchange_capabilities_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->video_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.request",
                        "dvc_channel_id=%u message_id=%u count=%u",
                        channel_id,
                        request.header.message_id,
                        request.capabilities.count);
        return rdp_session_send_video_capabilities(session, request.header.message_id);
    }
    if (!header.has_function_id || header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT)
        return LIBRDP_STATUS_OK;

    switch (header.function_id)
    {
        case RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ:
        {
            rdp_video_redirection_format_support_request request;
            uint32_t supported =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO);

            status = rdp_video_redirection_parse_check_format_support_request(data, data_len, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.format.request",
                            "dvc_channel_id=%u message_id=%u platform=%u media_types=%u media_len=%u supported=%u",
                            channel_id,
                            request.header.message_id,
                            request.platform_cookie,
                            request.media_type_count,
                            (unsigned)request.media_types_len,
                            supported);
            return rdp_session_send_video_format_support(session,
                                                         request.header.message_id,
                                                         request.platform_cookie,
                                                         supported);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS:
        {
            rdp_video_redirection_stream params;

            status = rdp_video_redirection_parse_set_channel_params(data, data_len, &params);
            if (status != LIBRDP_STATUS_OK)
                return status;
            (void)rdp_session_video_stream_upsert(session, params.presentation_id, params.stream_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.channel_params",
                            "dvc_channel_id=%u message_id=%u stream_id=%u",
                            channel_id,
                            params.header.message_id,
                            params.stream_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION:
        {
            rdp_video_redirection_presentation presentation;

            status = rdp_video_redirection_parse_new_presentation(data, data_len, &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.presentation",
                            "dvc_channel_id=%u message_id=%u platform=%u",
                            channel_id,
                            presentation.header.message_id,
                            presentation.platform_cookie);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t ready =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO);

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.topology.request",
                            "dvc_channel_id=%u message_id=%u ready=%u",
                            channel_id,
                            presentation.header.message_id,
                            ready);
            return rdp_session_send_video_topology(session, presentation.header.message_id, ready);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SHUTDOWN_PRESENTATION_REQ:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t removed = 0;
            uint32_t geometries_removed = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            removed = rdp_session_video_presentation_remove(session, presentation.presentation_id);
            geometries_removed =
                rdp_session_video_geometry_remove_presentation(session,
                                                               presentation.presentation_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.presentation.shutdown",
                            "dvc_channel_id=%u message_id=%u streams_removed=%u geometries_removed=%u",
                            channel_id,
                            presentation.header.message_id,
                            removed,
                            geometries_removed);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM:
        {
            rdp_video_redirection_stream stream;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_add_stream(data, data_len, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_upsert(session, stream.presentation_id, stream.stream_id);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.add",
                            "dvc_channel_id=%u message_id=%u stream_id=%u media_len=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id,
                            stream.data_len);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE:
        {
            rdp_video_redirection_stream stream;
            rdp_video_redirection_data_sample sample;
            rdp_session_video_stream* entry = NULL;
            uint64_t duration = 0;

            status = rdp_video_redirection_parse_sample_message(data, data_len, &stream);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_video_redirection_parse_data_sample(stream.data, stream.data_len, &sample);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, stream.presentation_id, stream.stream_id);
            if (!entry)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.tsmf.sample.rejected",
                                "dvc_channel_id=%u message_id=%u stream_id=%u reason=unknown_stream",
                                channel_id,
                                stream.header.message_id,
                                stream.stream_id);
                return LIBRDP_STATUS_STATE;
            }
            if (entry->sample_count > 0 && sample.sample_start_time <= entry->last_sample_start)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.tsmf.sample.rejected",
                                "dvc_channel_id=%u message_id=%u stream_id=%u reason=sequence sample_start=%llu last_sample_start=%llu",
                                channel_id,
                                stream.header.message_id,
                                stream.stream_id,
                                (unsigned long long)sample.sample_start_time,
                                (unsigned long long)entry->last_sample_start);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (sample.data_len > session->limits.frame_bytes)
            {
                rdp_session_metric_add(&session->metrics.limits_rejected, 1);
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.tsmf.sample.rejected",
                                "dvc_channel_id=%u message_id=%u stream_id=%u reason=frame_limit sample_len=%u limit=%u",
                                channel_id,
                                stream.header.message_id,
                                stream.stream_id,
                                sample.data_len,
                                session->limits.frame_bytes);
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            }
            duration = sample.sample_end_time - sample.sample_start_time;
            entry->sample_count++;
            entry->sample_bytes += sample.data_len;
            entry->last_sample_start = sample.sample_start_time;
            entry->last_sample_end = sample.sample_end_time;
            if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO) &&
                sample.data_len > 0)
                rdp_session_emit_channel_data(session, channel, sample.data, sample.data_len);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.sample",
                                  "dvc_channel_id=%u message_id=%u stream_id=%u sample_len=%u samples=%llu bytes=%llu flags=%u emitted=%u",
                                  channel_id,
                                  stream.header.message_id,
                                  stream.stream_id,
                                  sample.data_len,
                                  (unsigned long long)entry->sample_count,
                                  (unsigned long long)entry->sample_bytes,
                                  sample.sample_flags,
                                  rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
            return rdp_session_send_video_sample_ack(session,
                                                     stream.header.message_id,
                                                     stream.stream_id,
                                                     duration,
                                                     sample.data_len);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED:
        {
            rdp_video_redirection_playback_started started;

            status = rdp_video_redirection_parse_playback_started(data, data_len, &started);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.started",
                            "dvc_channel_id=%u message_id=%u offset=%llu seek=%u",
                            channel_id,
                            started.header.message_id,
                            (unsigned long long)started.playback_start_offset,
                            started.is_seek);
            return rdp_session_send_video_event(session,
                                                started.header.message_id,
                                                0,
                                                RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                "client.tsmf.playback.start_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_PAUSED:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RESTARTED:
        {
            rdp_video_redirection_presentation presentation;
            uint8_t paused =
                header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_PAUSED ? 1u : 0u;
            uint32_t matched = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            matched = rdp_session_video_presentation_update(session,
                                                            presentation.presentation_id,
                                                            1,
                                                            paused,
                                                            0,
                                                            UINT32_MAX);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            paused ? "client.tsmf.playback.paused" :
                                     "client.tsmf.playback.restarted",
                            "dvc_channel_id=%u message_id=%u streams=%u",
                            channel_id,
                            presentation.header.message_id,
                            matched);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH:
        {
            rdp_video_redirection_stream stream;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, stream.presentation_id, stream.stream_id);
            if (entry)
                entry->flush_count++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.flush",
                            "dvc_channel_id=%u message_id=%u stream_id=%u flushes=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id,
                            entry ? entry->flush_count : 0u);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STOPPED:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM:
        {
            rdp_video_redirection_stream stream;
            uint32_t event_id = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM ?
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM :
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_STOP_COMPLETED;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_session_video_stream_remove(session, stream.presentation_id, stream.stream_id);
            return rdp_session_send_video_event(session,
                                                stream.header.message_id,
                                                stream.stream_id,
                                                event_id,
                                                event_id == RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM ?
                                                    "client.tsmf.playback.end_of_stream" :
                                                    "client.tsmf.playback.stop_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW:
        {
            rdp_video_redirection_window window;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_set_video_window(data, data_len, &window);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, window.presentation_id, 0);
            if (entry)
                entry->video_window_id = window.video_window_id;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.window",
                            "dvc_channel_id=%u message_id=%u video_window_id=%llu parent_window_id=%llu",
                            channel_id,
                            window.header.message_id,
                            (unsigned long long)window.video_window_id,
                            (unsigned long long)window.parent_window_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_REMOVE_STREAM:
        {
            rdp_video_redirection_stream stream;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_session_video_stream_remove(session, stream.presentation_id, stream.stream_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.remove",
                            "dvc_channel_id=%u message_id=%u stream_id=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_SOURCE_VIDEO_RECT:
        {
            rdp_video_redirection_source_video_rect rect;

            status = rdp_video_redirection_parse_source_video_rect(data, data_len, &rect);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.source_rect",
                            "dvc_channel_id=%u message_id=%u left=%u top=%u right=%u bottom=%u",
                            channel_id,
                            rect.header.message_id,
                            rect.left_bits,
                            rect.top_bits,
                            rect.right_bits,
                            rect.bottom_bits);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_ALLOCATOR:
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.allocator",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)header.payload_len);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_NOTIFY_PREROLL:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t matched = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            matched = rdp_session_video_presentation_update(session,
                                                            presentation.presentation_id,
                                                            1,
                                                            1,
                                                            1,
                                                            UINT32_MAX);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.preroll",
                            "dvc_channel_id=%u message_id=%u streams=%u",
                            channel_id,
                            presentation.header.message_id,
                            matched);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO:
        {
            rdp_video_redirection_geometry_update update;
            rdp_video_redirection_geometry_info info;
            rdp_session_video_geometry* stored = NULL;
            const char* action = NULL;

            status = rdp_video_redirection_parse_geometry_update(data, data_len, &update);
            if (status != LIBRDP_STATUS_OK)
                return status;
            memset(&info, 0, sizeof(info));
            if (update.geometry_len == 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_video_redirection_parse_geometry_info(update.geometry,
                                                               update.geometry_len,
                                                               &info);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_video_geometry_apply(session, &update, &info, &action);
            if (status != LIBRDP_STATUS_OK)
                return status;
            stored = rdp_session_video_geometry_find(session,
                                                     update.presentation_id,
                                                     info.video_window_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.geometry",
                            "dvc_channel_id=%u message_id=%u action=%s window_id=%llu geometry_len=%u visible_len=%u visible_rects=%u window_state=%u left=%u top=%u width=%u height=%u active=%u clipped=%u stale=%u",
                            channel_id,
                            update.header.message_id,
                            action,
                            (unsigned long long)info.video_window_id,
                            update.geometry_len,
                            update.visible_rect_len,
                            stored ? stored->visible_rect_count : 0u,
                            info.window_state,
                            info.left,
                            info.top,
                            info.width,
                            info.height,
                            session->video_geometry_active_count,
                            session->video_geometry_clipped_count,
                            session->video_geometry_stale_count);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED:
        {
            rdp_video_redirection_playback_rate rate;

            status = rdp_video_redirection_parse_playback_rate(data, data_len, &rate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            (void)rdp_session_video_presentation_update(session,
                                                        rate.presentation_id,
                                                        0,
                                                        0,
                                                        0,
                                                        rate.rate_bits);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.rate",
                            "dvc_channel_id=%u message_id=%u rate_bits=%u",
                            channel_id,
                            rate.header.message_id,
                            rate.rate_bits);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME:
        {
            rdp_video_redirection_volume volume;

            status = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME ?
                         rdp_video_redirection_parse_stream_volume(data, data_len, &volume) :
                         rdp_video_redirection_parse_channel_volume(data, data_len, &volume);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.volume",
                            "dvc_channel_id=%u message_id=%u function_id=%u value=%u second=%u",
                            channel_id,
                            volume.header.message_id,
                            header.function_id,
                            volume.value,
                            volume.second_value);
            break;
        }
        default:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.pdu.skipped",
                                  "dvc_channel_id=%u message_id=%u function_id=%u payload_len=%u",
                                  channel_id,
                                  header.message_id,
                                  header.function_id,
                                  (unsigned)header.payload_len);
            break;
    }
    return LIBRDP_STATUS_OK;
}

int rdp_session_video_runtime_active(const librdp_session* session)
{
    if (!session)
        return 0;
    for (uint32_t i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active)
            return 1;
    }
    for (uint32_t i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (session->video_optimized_presentations[i].active)
            return 1;
    }
    return 0;
}
