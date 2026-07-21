/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session dynamic/static channel tables and public channel APIs.
 * Invariants: channel handles carry slot generations and fragmented payloads complete before callbacks fire.
 * Ownership: channel fragments and decompressor state are session-owned; callback payloads are borrowed.
 * Threading: public APIs enforce the session owner-thread contract before channel table mutation.
 * Trust boundary: remote channel IDs, names, fragments, and close PDUs are validated before dispatch.
 */

#include "client/session_internal.h"
#include "common/trace.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

int rdp_session_dynamic_channel_is_internal(const rdp_session_dynamic_channel* entry);

static rdp_session_multiparty_participant* rdp_session_multiparty_find_participant(
    librdp_session* session,
    uint32_t participant_id)
{
    uint32_t i = 0u;

    if (!session)
        return NULL;
    for (i = 0u; i < RDP_SESSION_MULTIPARTY_PARTICIPANT_LIMIT; i++)
    {
        rdp_session_multiparty_participant* participant =
            &session->multiparty_participants[i];

        if (participant->active &&
            participant->participant_id == participant_id)
            return participant;
    }
    return NULL;
}

static rdp_session_multiparty_participant* rdp_session_multiparty_find_free_participant(
    librdp_session* session)
{
    uint32_t i = 0u;

    if (!session)
        return NULL;
    for (i = 0u; i < RDP_SESSION_MULTIPARTY_PARTICIPANT_LIMIT; i++)
    {
        if (!session->multiparty_participants[i].active)
            return &session->multiparty_participants[i];
    }
    return NULL;
}

void rdp_session_multiparty_reset(librdp_session* session)
{
    if (!session)
        return;
    session->multiparty_channel_id = 0u;
    session->multiparty_joined = 0u;
    session->multiparty_participant_count = 0u;
    session->multiparty_participant_joins = 0u;
    session->multiparty_participant_updates = 0u;
    session->multiparty_participant_leaves = 0u;
    session->multiparty_participant_duplicates = 0u;
    session->multiparty_participant_stale = 0u;
    memset(session->multiparty_participants,
           0,
           sizeof(session->multiparty_participants));
}

/*
 * Apply participant lifecycle messages without retaining friendly names from
 * the remote peer. The fixed table bounds resource use, while duplicate and
 * stale messages remain observable in trace without destabilizing the channel.
 */
static librdp_status rdp_session_multiparty_apply_message(
    librdp_session* session,
    const rdp_multiparty_message* message)
{
    rdp_session_multiparty_participant* participant = NULL;

    if (!session || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (message->type)
    {
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED:
        {
            const rdp_multiparty_participant_created* created =
                &message->body.participant_created;

            participant = rdp_session_multiparty_find_participant(
                session,
                created->participant_id);
            if (participant)
            {
                if (participant->group_id == created->group_id &&
                    participant->share_flags == created->flags)
                {
                    session->multiparty_participant_duplicates++;
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.multiparty.participant.duplicate",
                                    "participant_id=%u group_id=%u",
                                    created->participant_id,
                                    created->group_id);
                    return LIBRDP_STATUS_OK;
                }
                participant->group_id = created->group_id;
                participant->share_flags = created->flags;
                session->multiparty_participant_updates++;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.multiparty.participant.update",
                                "participant_id=%u group_id=%u share_flags=%u",
                                created->participant_id,
                                created->group_id,
                                created->flags);
                return LIBRDP_STATUS_OK;
            }
            participant =
                rdp_session_multiparty_find_free_participant(session);
            if (!participant)
                return rdp_session_limit_rejected(session);
            participant->participant_id = created->participant_id;
            participant->group_id = created->group_id;
            participant->share_flags = created->flags;
            participant->active = 1u;
            session->multiparty_participant_count++;
            session->multiparty_participant_joins++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.multiparty.participant.join",
                            "participant_id=%u group_id=%u share_flags=%u",
                            created->participant_id,
                            created->group_id,
                            created->flags);
            return LIBRDP_STATUS_OK;
        }
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED:
        {
            const rdp_multiparty_control_change* change =
                &message->body.control_change;

            participant = rdp_session_multiparty_find_participant(
                session,
                change->participant_id);
            if (!participant)
            {
                session->multiparty_participant_stale++;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.multiparty.participant.stale",
                                "participant_id=%u type=control_change",
                                change->participant_id);
                return LIBRDP_STATUS_OK;
            }
            participant->control_flags = change->flags;
            session->multiparty_participant_updates++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.multiparty.participant.update",
                            "participant_id=%u control_flags=%u",
                            change->participant_id,
                            change->flags);
            return LIBRDP_STATUS_OK;
        }
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED:
        {
            const rdp_multiparty_participant_removed* removed =
                &message->body.participant_removed;

            participant = rdp_session_multiparty_find_participant(
                session,
                removed->participant_id);
            if (!participant)
            {
                session->multiparty_participant_stale++;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.multiparty.participant.stale",
                                "participant_id=%u type=remove",
                                removed->participant_id);
                return LIBRDP_STATUS_OK;
            }
            memset(participant, 0, sizeof(*participant));
            if (session->multiparty_participant_count > 0u)
                session->multiparty_participant_count--;
            session->multiparty_participant_leaves++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.multiparty.participant.leave",
                            "participant_id=%u disconnect_type=%u disconnect_code=%u",
                            removed->participant_id,
                            removed->disconnect_type,
                            removed->disconnect_code);
            return LIBRDP_STATUS_OK;
        }
        default:
            return LIBRDP_STATUS_OK;
    }
}

/*
 * Parse and apply a complete Multiparty message before exposing its borrowed
 * wire payload through the generic channel callback.
 */
static librdp_status rdp_session_multiparty_dispatch(
    librdp_session* session,
    uint16_t channel_id,
    const uint8_t* data,
    size_t data_len)
{
    rdp_multiparty_message message;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_multiparty_parse_message(data, data_len, &message);
    if (status != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_session_multiparty_apply_message(session, &message);
    if (status != LIBRDP_STATUS_OK)
        return status;
    session->multiparty_joined = 1u;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.multiparty.pdu",
                    "channel_id=%u type=%u payload_len=%u",
                    channel_id,
                    message.type,
                    (unsigned)data_len);
    return LIBRDP_STATUS_OK;
}

rdp_session_dynamic_channel* rdp_session_dynamic_channel_find(librdp_session* session, uint32_t channel_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (session->dynamic_channels[i].active && session->dynamic_channels[i].channel_id == channel_id)
            return &session->dynamic_channels[i];
    }
    return NULL;
}

static rdp_session_dynamic_channel* rdp_session_dynamic_channel_find_any(librdp_session* session, uint32_t channel_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        if ((session->dynamic_channels[i].active || session->dynamic_channels[i].opening) &&
            session->dynamic_channels[i].channel_id == channel_id)
            return &session->dynamic_channels[i];
    }
    return NULL;
}

rdp_session_dynamic_channel* rdp_session_dynamic_channel_find_opening(librdp_session* session,
                                                                             uint32_t channel_id)
{
    rdp_session_dynamic_channel* entry = rdp_session_dynamic_channel_find_any(session, channel_id);

    return entry && entry->opening && entry->client_initiated ? entry : NULL;
}

static librdp_channel_handle rdp_session_dynamic_channel_handle(librdp_session* session,
                                                                const rdp_session_dynamic_channel* entry)
{
    size_t slot = 0;

    if (!session || !entry || entry < session->dynamic_channels ||
        entry >= session->dynamic_channels + RDP_SESSION_MAX_DYNAMIC_CHANNELS || entry->generation == 0)
        return 0;
    slot = (size_t)(entry - session->dynamic_channels);
    return (((uint64_t)slot + 1u) << 32) | (uint64_t)entry->generation;
}

static rdp_session_dynamic_channel* rdp_session_dynamic_channel_from_handle(librdp_session* session,
                                                                            librdp_channel_handle handle)
{
    size_t slot = 0;
    uint32_t generation = 0;
    rdp_session_dynamic_channel* entry = NULL;

    if (!session || handle == 0)
        return NULL;
    slot = (size_t)((handle >> 32) & 0xffffffffu);
    generation = (uint32_t)(handle & 0xffffffffu);
    if (slot == 0 || slot > RDP_SESSION_MAX_DYNAMIC_CHANNELS || generation == 0)
        return NULL;
    entry = &session->dynamic_channels[slot - 1u];
    if ((!entry->active && !entry->opening) || entry->generation != generation)
        return NULL;
    return entry;
}

static librdp_status rdp_session_dynamic_channel_copy_info(librdp_session* session,
                                                           const rdp_session_dynamic_channel* entry,
                                                           librdp_channel_info* info)
{
    size_t name_len = 0;

    if (!session || !entry || !info || info->version != LIBRDP_CHANNEL_INFO_VERSION ||
        info->size < offsetof(librdp_channel_info, name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (info->size >= offsetof(librdp_channel_info, handle) + sizeof(info->handle))
        info->handle = rdp_session_dynamic_channel_handle(session, entry);
    if (info->size >= offsetof(librdp_channel_info, channel_id) + sizeof(info->channel_id))
        info->channel_id = entry->channel_id;
    if (info->size >= offsetof(librdp_channel_info, priority) + sizeof(info->priority))
        info->priority = (librdp_channel_priority)entry->priority;
    if (info->size >= offsetof(librdp_channel_info, active) + sizeof(info->active))
        info->active = entry->active ? 1 : 0;
    if (info->size >= offsetof(librdp_channel_info, application_owned) + sizeof(info->application_owned))
        info->application_owned = rdp_session_dynamic_channel_is_internal(entry) ? 0 : 1;
    name_len = strlen(entry->name);
    if (name_len > LIBRDP_CHANNEL_NAME_MAX)
        name_len = LIBRDP_CHANNEL_NAME_MAX;
    if (info->size >= offsetof(librdp_channel_info, name_len) + sizeof(info->name_len))
        info->name_len = name_len;
    if (info->size >= offsetof(librdp_channel_info, name) + 1u)
    {
        size_t available = info->size - offsetof(librdp_channel_info, name);
        size_t copy_len = name_len;

        if (copy_len >= available)
            copy_len = available - 1u;
        memcpy(info->name, entry->name, copy_len);
        info->name[copy_len] = '\0';
    }
    return LIBRDP_STATUS_OK;
}

static int rdp_session_dynamic_channel_name_public_valid(const char* name, size_t* name_len)
{
    size_t i = 0;

    if (!name)
        return 0;
    while (name[i] != '\0')
    {
        unsigned char ch = (unsigned char)name[i];

        if (i >= LIBRDP_CHANNEL_NAME_MAX || ch < 0x21u || ch > 0x7eu)
            return 0;
        i++;
    }
    if (i == 0)
        return 0;
    if (name_len)
        *name_len = i;
    return 1;
}

static rdp_session_dynamic_channel* rdp_session_dynamic_channel_free_slot(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < session->limits.dynamic_channel_count; i++)
    {
        if (!session->dynamic_channels[i].active && !session->dynamic_channels[i].opening)
            return &session->dynamic_channels[i];
    }
    return NULL;
}

static librdp_status rdp_session_dynamic_channel_allocate_id(librdp_session* session, uint32_t* channel_id)
{
    uint32_t candidate = 0;
    size_t attempts = 0;

    if (!session || !channel_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    candidate = session->next_dynamic_channel_id == 0 ? 1u : session->next_dynamic_channel_id;
    for (attempts = 0; attempts <= RDP_SESSION_MAX_DYNAMIC_CHANNELS; attempts++)
    {
        if (candidate == 0)
            candidate = 1;
        if (!rdp_session_dynamic_channel_find_any(session, candidate))
        {
            *channel_id = candidate;
            session->next_dynamic_channel_id = candidate + 1u;
            if (session->next_dynamic_channel_id == 0)
                session->next_dynamic_channel_id = 1;
            return LIBRDP_STATUS_OK;
        }
        candidate++;
    }
    return rdp_session_limit_rejected(session);
}

void rdp_session_dynamic_channel_clear_entry(rdp_session_dynamic_channel* entry)
{
    uint32_t generation = 0;

    if (!entry)
        return;
    generation = entry->generation + 1u;
    if (generation == 0)
        generation = 1;
    rdp_buffer_free(&entry->fragment);
    rdp_graphics_decompressor_free(&entry->decompressor);
    memset(entry, 0, sizeof(*entry));
    entry->generation = generation;
}

librdp_status rdp_session_dynamic_channel_add(librdp_session* session,
                                                     const rdp_dynamic_channel_create_request* request)
{
    size_t i = 0;
    size_t name_len = 0;
    rdp_session_dynamic_channel* entry = NULL;

    if (!session || !request || !request->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    entry = rdp_session_dynamic_channel_find_any(session, request->channel_id);
    if (entry)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.create.failed",
                        "channel_id=%u reason=duplicate",
                        request->channel_id);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    for (i = 0; i < session->limits.dynamic_channel_count; i++)
    {
        if (!session->dynamic_channels[i].active && !session->dynamic_channels[i].opening)
        {
            entry = &session->dynamic_channels[i];
            break;
        }
    }
    if (!entry)
        return rdp_session_limit_rejected(session);

    rdp_session_dynamic_channel_clear_entry(entry);
    rdp_graphics_decompressor_init(&entry->decompressor);
    entry->channel_id = request->channel_id;
    entry->channel_id_bytes = request->channel_id_bytes;
    entry->priority = request->priority <= 2u ? request->priority : 0;
    entry->active = 1;
    name_len = request->name_len < RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u ?
                   request->name_len :
                   RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u;
    memcpy(entry->name, request->name, name_len);
    entry->name[name_len] = '\0';
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_dynamic_channel_add_opening(librdp_session* session,
                                                             uint32_t channel_id,
                                                             uint8_t channel_id_bytes,
                                                             librdp_channel_priority priority,
                                                             const char* name,
                                                             size_t name_len,
                                                             librdp_channel_handle* handle)
{
    rdp_session_dynamic_channel* entry = NULL;

    if (!session || !name || name_len == 0 || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_session_dynamic_channel_find_any(session, channel_id))
        return LIBRDP_STATUS_STATE;
    entry = rdp_session_dynamic_channel_free_slot(session);
    if (!entry)
        return rdp_session_limit_rejected(session);

    rdp_session_dynamic_channel_clear_entry(entry);
    rdp_graphics_decompressor_init(&entry->decompressor);
    entry->channel_id = channel_id;
    entry->channel_id_bytes = channel_id_bytes;
    entry->priority = (uint8_t)priority;
    entry->opening = 1;
    entry->client_initiated = 1;
    if (name_len >= sizeof(entry->name))
        name_len = sizeof(entry->name) - 1u;
    memcpy(entry->name, name, name_len);
    entry->name[name_len] = '\0';
    *handle = rdp_session_dynamic_channel_handle(session, entry);
    return *handle != 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_STATE;
}

static int rdp_session_dynamic_channel_is_internal_name(const char* name)
{
    if (!name)
        return 0;
    return strcmp(name, RDP_SESSION_ECHO_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_DISPLAY_CONTROL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_CORE_INPUT_NAME) == 0 ||
           strcmp(name, RDP_SESSION_INPUT_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_GRAPHICS_PIPELINE_NAME) == 0 ||
           strcmp(name, RDP_SESSION_MOUSE_CURSOR_NAME) == 0 ||
           strcmp(name, RDP_SESSION_AUTH_REDIRECTION_NAME) == 0 ||
           strcmp(name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_TELEMETRY_DVC_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_COMPOSITED_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_GEOMETRY_TRACKING_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) == 0 ||
           strcmp(name, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL) == 0 ||
           strcmp(name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_VIDEO_CAPTURE_CHANNEL_NAME) == 0 ||
           strcmp(name, RDP_AUDIO_INPUT_CHANNEL_NAME) == 0;
}

int rdp_session_dynamic_channel_is_internal(const rdp_session_dynamic_channel* entry)
{
    return entry && rdp_session_dynamic_channel_is_internal_name(entry->name);
}

static int rdp_session_dynamic_channel_request_name_equals(const rdp_dynamic_channel_create_request* request,
                                                           const char* name)
{
    size_t name_len = 0;

    if (!request || !request->name || !name)
        return 0;
    name_len = strlen(name);
    return request->name_len == name_len && memcmp(request->name, name, name_len) == 0;
}

static int rdp_session_dynamic_channel_optional_feature(const rdp_dynamic_channel_create_request* request,
                                                        librdp_feature* feature)
{
    if (!request || !feature)
        return 0;
    if (rdp_session_dynamic_channel_request_name_equals(request, RDP_SESSION_ECHO_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_ECHO;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_SESSION_WEBAUTHN_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_WEBAUTHN;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_USB;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_SESSION_DISPLAY_CONTROL_NAME))
        *feature = LIBRDP_FEATURE_DISPLAY_CONTROL;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_COMPOSITED_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_CR2;
    else if (rdp_session_dynamic_channel_request_name_equals(
                 request,
                 RDP_GEOMETRY_TRACKING_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_GEOMETRY_TRACKING;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) ||
             rdp_session_dynamic_channel_request_name_equals(request, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) ||
             rdp_session_dynamic_channel_request_name_equals(request, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL))
        *feature = LIBRDP_FEATURE_VIDEO;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) ||
             rdp_session_dynamic_channel_request_name_equals(request, RDP_VIDEO_CAPTURE_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_CAMERA;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_AUDIO_INPUT_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_AUDIO_INPUT;
    else if (rdp_session_dynamic_channel_request_name_equals(request, RDP_TELEMETRY_DVC_CHANNEL_NAME))
        *feature = LIBRDP_FEATURE_TELEMETRY;
    else
        return 0;
    return 1;
}

static int rdp_session_dynamic_channel_requires_credssp(const rdp_dynamic_channel_create_request* request)
{
    return rdp_session_dynamic_channel_request_name_equals(request, RDP_SESSION_AUTH_REDIRECTION_NAME);
}

uint32_t rdp_session_dynamic_channel_create_status(librdp_session* session,
                                                          const rdp_dynamic_channel_create_request* request)
{
    librdp_feature feature = (librdp_feature)0;
    librdp_feature_status feature_status;

    if (rdp_session_dynamic_channel_requires_credssp(request) &&
        (!session || !session->credssp_security_ready))
        return RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    if (!rdp_session_dynamic_channel_optional_feature(request, &feature))
        return RDP_DYNAMIC_CHANNEL_STATUS_OK;
    memset(&feature_status, 0, sizeof(feature_status));
    if (librdp_settings_get_feature_status(session ? session->settings : NULL,
                                           feature,
                                           &feature_status) != LIBRDP_STATUS_OK)
        return RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    if (!feature_status.requested || !feature_status.backend_ready)
        return RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    return RDP_DYNAMIC_CHANNEL_STATUS_OK;
}

static rdp_session_dynamic_channel* rdp_session_echo_channel_entry(const librdp_session* session)
{
    if (!session)
        return NULL;
    if (!librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_ECHO))
        return NULL;
    for (uint32_t i = 0; i < session->limits.dynamic_channel_count; i++)
    {
        if (session->dynamic_channels[i].active &&
            strcmp(session->dynamic_channels[i].name, RDP_SESSION_ECHO_CHANNEL_NAME) == 0)
            return &((librdp_session*)session)->dynamic_channels[i];
    }
    return NULL;
}

int rdp_session_echo_channel_active(const librdp_session* session)
{
    return rdp_session_echo_channel_entry(session) != NULL;
}

uint64_t rdp_session_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

void rdp_session_echo_clear_pending(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->echo_pending_payload);
    rdp_buffer_init(&session->echo_pending_payload);
    session->echo_pending = 0;
    session->echo_pending_sequence = 0;
    session->echo_pending_sent_ns = 0;
    session->echo_pending_timeout_ms = 0;
    session->echo_stats.pending_sequence = 0;
    session->echo_stats.pending_payload_len = 0;
}

void rdp_session_echo_emit_result(librdp_session* session,
                                         uint64_t sequence,
                                         const uint8_t* data,
                                         size_t data_len,
                                         uint64_t rtt_us,
                                         int ok,
                                         int timed_out)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_ECHO_RESULT;
    event.data.echo_result.sequence = sequence;
    event.data.echo_result.rtt_us = rtt_us;
    event.data.echo_result.data = data;
    event.data.echo_result.data_len = data_len;
    event.data.echo_result.ok = ok ? 1 : 0;
    event.data.echo_result.timed_out = timed_out ? 1 : 0;
    rdp_session_emit(session, &event);
}

void rdp_session_echo_record_rtt(librdp_session* session, uint64_t rtt_us)
{
    uint64_t previous = 0;

    if (!session)
        return;
    previous = session->echo_stats.last_rtt_us;
    session->echo_stats.last_rtt_us = rtt_us;
    if (session->echo_stats.min_rtt_us == 0 || rtt_us < session->echo_stats.min_rtt_us)
        session->echo_stats.min_rtt_us = rtt_us;
    if (rtt_us > session->echo_stats.max_rtt_us)
        session->echo_stats.max_rtt_us = rtt_us;
    if (previous != 0)
        session->echo_stats.jitter_us = previous > rtt_us ? previous - rtt_us : rtt_us - previous;
}

int rdp_session_echo_pending_expired(const librdp_session* session, uint64_t now_ns, uint64_t* elapsed_us)
{
    uint64_t elapsed_ns = 0;
    uint64_t timeout_ns = 0;

    if (elapsed_us)
        *elapsed_us = 0;
    if (!session || !session->echo_pending || session->echo_pending_timeout_ms == 0 ||
        session->echo_pending_sent_ns == 0 || now_ns < session->echo_pending_sent_ns)
        return 0;
    elapsed_ns = now_ns - session->echo_pending_sent_ns;
    if (elapsed_us)
        *elapsed_us = elapsed_ns / 1000u;
    timeout_ns = (uint64_t)session->echo_pending_timeout_ms * 1000000ull;
    return elapsed_ns >= timeout_ns;
}

void rdp_session_echo_check_timeout(librdp_session* session)
{
    uint64_t elapsed_us = 0;

    if (!session || !session->echo_pending)
        return;
    if (!rdp_session_echo_pending_expired(session, rdp_session_monotonic_ns(), &elapsed_us))
        return;
    rdp_session_metric_add(&session->echo_stats.timeouts, 1);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.echo.timeout",
                    "sequence=%llu payload_len=%u timeout_ms=%u elapsed_us=%llu",
                    (unsigned long long)session->echo_pending_sequence,
                    (unsigned)session->echo_pending_payload.length,
                    session->echo_pending_timeout_ms,
                    (unsigned long long)elapsed_us);
    rdp_session_echo_emit_result(session,
                                 session->echo_pending_sequence,
                                 session->echo_pending_payload.data,
                                 session->echo_pending_payload.length,
                                 0,
                                 0,
                                 1);
    rdp_session_echo_clear_pending(session);
}

int rdp_session_echo_next_timeout_ms(const librdp_session* session)
{
    uint64_t now_ns = 0;
    uint64_t elapsed_ns = 0;
    uint64_t timeout_ns = 0;
    uint64_t remaining_ns = 0;

    if (!session || !session->echo_pending || session->echo_pending_timeout_ms == 0 ||
        session->echo_pending_sent_ns == 0)
        return -1;
    now_ns = rdp_session_monotonic_ns();
    if (now_ns <= session->echo_pending_sent_ns)
        return (int)session->echo_pending_timeout_ms;
    elapsed_ns = now_ns - session->echo_pending_sent_ns;
    timeout_ns = (uint64_t)session->echo_pending_timeout_ms * 1000000ull;
    if (elapsed_ns >= timeout_ns)
        return 0;
    remaining_ns = timeout_ns - elapsed_ns;
    return (int)((remaining_ns + 999999ull) / 1000000ull);
}

void rdp_session_emit_channel_open_data(librdp_session* session,
                                               librdp_channel_id channel_id,
                                               const char* name)
{
    librdp_event event;

    if (!session || !name)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_OPEN;
    event.data.channel_open.channel_id = channel_id;
    event.data.channel_open.name = name;
    event.data.channel_open.name_len = strlen(name);
    rdp_session_emit(session, &event);
}

void rdp_session_emit_channel_payload(librdp_session* session,
                                             librdp_channel_id channel_id,
                                             const char* name,
                                             const uint8_t* data,
                                             size_t data_len)
{
    librdp_event event;

    if (!session || !name || (!data && data_len > 0))
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_DATA;
    event.data.channel_data.channel_id = channel_id;
    event.data.channel_data.name = name;
    event.data.channel_data.name_len = strlen(name);
    event.data.channel_data.data = data;
    event.data.channel_data.data_len = data_len;
    rdp_session_emit(session, &event);
}

void rdp_session_emit_channel_close_data(librdp_session* session,
                                                librdp_channel_id channel_id,
                                                const char* name)
{
    librdp_event event;

    if (!session || !name)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_CHANNEL_CLOSE;
    event.data.channel_close.channel_id = channel_id;
    event.data.channel_close.name = name;
    event.data.channel_close.name_len = strlen(name);
    rdp_session_emit(session, &event);
}

void rdp_session_emit_channel_open(librdp_session* session, const rdp_session_dynamic_channel* entry)
{
    if (entry)
        rdp_session_emit_channel_open_data(session, entry->channel_id, entry->name);
}

void rdp_session_emit_channel_data(librdp_session* session,
                                          const rdp_session_dynamic_channel* entry,
                                          const uint8_t* data,
                                          size_t data_len)
{
    if (entry)
        rdp_session_emit_channel_payload(session, entry->channel_id, entry->name, data, data_len);
}

void rdp_session_emit_channel_close(librdp_session* session, const rdp_session_dynamic_channel* entry)
{
    if (entry)
        rdp_session_emit_channel_close_data(session, entry->channel_id, entry->name);
}

void rdp_session_dynamic_channels_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
        rdp_session_dynamic_channel_clear_entry(&session->dynamic_channels[i]);
}

static void rdp_session_static_channel_clear_entry(rdp_session_static_channel* entry)
{
    if (!entry)
        return;
    rdp_buffer_free(&entry->fragment);
    memset(entry, 0, sizeof(*entry));
}

void rdp_session_static_channels_clear(librdp_session* session)
{
    uint32_t i = 0;

    if (!session)
        return;
    for (i = 0; i < LIBRDP_SETTINGS_MAX_STATIC_CHANNELS; i++)
        rdp_session_static_channel_clear_entry(&session->static_channels[i]);
    session->static_channel_count = 0;
}

/*
 * Discard incomplete channel payloads at an activation boundary while
 * preserving negotiated channel identities, generations and open handles.
 */
void rdp_session_channels_reset_activation_fragments(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        rdp_session_dynamic_channel* entry = &session->dynamic_channels[i];

        if (!entry->active && !entry->opening)
            continue;
        entry->fragmenting = 0u;
        entry->fragment_expected = 0u;
        entry->fragment.length = 0u;
        rdp_graphics_decompressor_reset(&entry->decompressor);
    }
    for (i = 0; i < session->static_channel_count; i++)
    {
        rdp_session_static_channel* entry = &session->static_channels[i];

        if (!entry->active)
            continue;
        entry->fragmenting = 0u;
        entry->fragment_expected = 0u;
        entry->fragment.length = 0u;
    }
}

rdp_session_static_channel* rdp_session_static_channel_find_by_id(librdp_session* session,
                                                                         uint16_t channel_id)
{
    uint32_t i = 0;

    if (!session || channel_id == 0)
        return NULL;
    for (i = 0; i < session->static_channel_count; i++)
    {
        if (session->static_channels[i].active && session->static_channels[i].channel_id == channel_id)
            return &session->static_channels[i];
    }
    return NULL;
}

static rdp_session_static_channel* rdp_session_static_channel_find_by_name(librdp_session* session,
                                                                           const char* name)
{
    uint32_t i = 0;

    if (!session || !name)
        return NULL;
    for (i = 0; i < session->static_channel_count; i++)
    {
        if (session->static_channels[i].active && strcmp(session->static_channels[i].name, name) == 0)
            return &session->static_channels[i];
    }
    return NULL;
}

static librdp_status rdp_session_static_channel_copy_info(const rdp_session_static_channel* entry,
                                                          librdp_static_channel_info* info)
{
    size_t name_len = 0;

    if (!entry || !info || info->version != LIBRDP_STATIC_CHANNEL_INFO_VERSION ||
        info->size < offsetof(librdp_static_channel_info, name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    name_len = strlen(entry->name);
    if (info->size >= offsetof(librdp_static_channel_info, channel_id) + sizeof(info->channel_id))
        info->channel_id = entry->channel_id;
    if (info->size >= offsetof(librdp_static_channel_info, flags) + sizeof(info->flags))
        info->flags = entry->flags;
    if (info->size >= offsetof(librdp_static_channel_info, active) + sizeof(info->active))
        info->active = entry->active ? 1 : 0;
    if (info->size >= offsetof(librdp_static_channel_info, name_len) + sizeof(info->name_len))
        info->name_len = name_len;
    if (info->size >= offsetof(librdp_static_channel_info, name) + 1u)
    {
        size_t available = info->size - offsetof(librdp_static_channel_info, name);
        size_t copy_len = name_len;

        if (copy_len >= available)
            copy_len = available - 1u;
        memcpy(info->name, entry->name, copy_len);
        info->name[copy_len] = '\0';
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_static_channel_configure(librdp_session* session,
                                                          uint32_t index,
                                                          const char* name,
                                                          uint32_t flags,
                                                          uint16_t channel_id)
{
    rdp_session_static_channel* entry = NULL;

    if (!session || !name || index >= LIBRDP_SETTINGS_MAX_STATIC_CHANNELS || channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    entry = &session->static_channels[index];
    rdp_session_static_channel_clear_entry(entry);
    entry->channel_id = channel_id;
    entry->flags = flags;
    entry->active = 1;
    memcpy(entry->name, name, strlen(name) + 1u);
    if (session->static_channel_count <= index)
        session->static_channel_count = index + 1u;
    return LIBRDP_STATUS_OK;
}

/*
 * Reassembles static virtual channel fragments and validates protocol-owned
 * static channels before publishing application data. Fragment state is kept on
 * the channel entry, and any malformed or oversized fragment discards the partial
 * buffer so the next PDU starts from a known boundary.
 */
librdp_status rdp_session_handle_static_channel(librdp_session* session,
                                                       rdp_session_static_channel* entry,
                                                       const rdp_virtual_channel_packet* packet)
{
    uint32_t fragment_flags = 0;

    if (!session || !entry || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet->length > session->limits.channel_buffer_bytes)
        return rdp_session_limit_rejected(session);

    fragment_flags = packet->flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
    if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
    {
        entry->fragmenting = 0;
        entry->fragment_expected = 0;
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
        if (strcmp(entry->name, RDP_MULTIPARTY_CHANNEL_NAME) == 0)
        {
            librdp_status status = rdp_session_multiparty_dispatch(
                session,
                entry->channel_id,
                packet->payload,
                packet->payload_len);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_session_emit_channel_payload(session,
                                         entry->channel_id,
                                         entry->name,
                                         packet->payload,
                                         packet->payload_len);
        return LIBRDP_STATUS_OK;
    }

    if ((packet->flags & RDP_VIRTUAL_CHANNEL_FLAG_FIRST) != 0)
    {
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
        entry->fragmenting = 1;
        entry->fragment_expected = packet->length;
    }
    else if (!entry->fragmenting)
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    if (packet->payload_len > (size_t)entry->fragment_expected ||
        entry->fragment.length > (size_t)entry->fragment_expected - packet->payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_buffer_append(&entry->fragment, packet->payload, packet->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;

    if ((packet->flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
    {
        if (entry->fragment.length != (size_t)entry->fragment_expected)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (strcmp(entry->name, RDP_MULTIPARTY_CHANNEL_NAME) == 0)
        {
            librdp_status status = rdp_session_multiparty_dispatch(
                session,
                entry->channel_id,
                entry->fragment.data,
                entry->fragment.length);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_session_emit_channel_payload(session,
                                         entry->channel_id,
                                         entry->name,
                                         entry->fragment.data,
                                         entry->fragment.length);
        entry->fragmenting = 0;
        entry->fragment_expected = 0;
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
    }
    return LIBRDP_STATUS_OK;
}


static librdp_status rdp_session_require_user_channel(librdp_session* session,
                                                      librdp_channel_id channel_id,
                                                      rdp_session_dynamic_channel** entry)
{
    rdp_session_dynamic_channel* found = NULL;

    if (!session || channel_id == 0 || !entry)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_STATE;
    found = rdp_session_dynamic_channel_find(session, channel_id);
    if (!found || !found->active)
        return LIBRDP_STATUS_STATE;
    if (rdp_session_dynamic_channel_is_internal(found))
        return LIBRDP_STATUS_UNSUPPORTED;
    *entry = found;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_channel_info_init(librdp_channel_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_CHANNEL_INFO_VERSION;
    info->size = sizeof(*info);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_channel_send_options_init(librdp_channel_send_options* options)
{
    if (!options)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(options, 0, sizeof(*options));
    options->version = LIBRDP_CHANNEL_SEND_OPTIONS_VERSION;
    options->size = sizeof(*options);
    options->priority = LIBRDP_CHANNEL_PRIORITY_LOW;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_channel_open(librdp_session* session,
                                          const char* name,
                                          librdp_channel_priority priority,
                                          librdp_channel_handle* handle)
{
    rdp_buffer create;
    rdp_session_dynamic_channel* entry = NULL;
    uint32_t channel_id = 0;
    uint8_t channel_id_bytes = 0;
    size_t name_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *handle = 0;
    if (!session || !rdp_session_dynamic_channel_name_public_valid(name, &name_len) ||
        priority > LIBRDP_CHANNEL_PRIORITY_REALTIME || rdp_session_dynamic_channel_is_internal_name(name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.open.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_STATE;

    status = rdp_session_dynamic_channel_allocate_id(session, &channel_id);
    if (status == LIBRDP_STATUS_OK)
    {
        channel_id_bytes = rdp_dynamic_channel_select_channel_id_bytes(channel_id);
        status = rdp_session_dynamic_channel_add_opening(session,
                                                         channel_id,
                                                         channel_id_bytes,
                                                         priority,
                                                         name,
                                                         name_len,
                                                         handle);
    }

    rdp_buffer_init(&create);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_create_request(&create,
                                                          channel_id,
                                                          channel_id_bytes,
                                                          (uint8_t)priority,
                                                          name,
                                                          name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_channel_pdu(session,
                                               session->dynamic_channel_id,
                                               &create,
                                               "client.drdynvc.open.start");
    rdp_buffer_free(&create);
    if (status != LIBRDP_STATUS_OK)
    {
        entry = rdp_session_dynamic_channel_find_opening(session, channel_id);
        if (entry)
            rdp_session_dynamic_channel_clear_entry(entry);
        *handle = 0;
        return status;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.drdynvc.open.start",
                    "dvc_channel_id=%u name=%s priority=%u",
                    channel_id,
                    name,
                    (unsigned)priority);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_channel_list(librdp_session* session,
                                          librdp_channel_info* infos,
                                          size_t capacity,
                                          size_t* count)
{
    size_t i = 0;
    size_t written = 0;
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !count || (!infos && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.list.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        rdp_session_dynamic_channel* entry = &session->dynamic_channels[i];

        if (!entry->active)
            continue;
        if (infos && written < capacity)
        {
            status = rdp_session_dynamic_channel_copy_info(session, entry, &infos[written]);
            if (status != LIBRDP_STATUS_OK)
                return status;
            written++;
        }
        total++;
    }
    *count = total;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_channel_handle_for_id(librdp_session* session,
                                                   librdp_channel_id channel_id,
                                                   librdp_channel_handle* handle)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || channel_id == 0 || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.handle.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    entry = rdp_session_dynamic_channel_find(session, channel_id);
    if (!entry || !entry->active)
        return LIBRDP_STATUS_STATE;
    *handle = rdp_session_dynamic_channel_handle(session, entry);
    return *handle != 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_STATE;
}

librdp_status librdp_session_channel_get_info(librdp_session* session,
                                              librdp_channel_handle handle,
                                              librdp_channel_info* info)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.info.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    entry = rdp_session_dynamic_channel_from_handle(session, handle);
    if (!entry)
        return LIBRDP_STATUS_STATE;
    return rdp_session_dynamic_channel_copy_info(session, entry, info);
}

librdp_status librdp_session_channel_send_ex(librdp_session* session,
                                             const librdp_channel_send_options* options,
                                             const void* data,
                                             size_t data_len)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !options || (!data && data_len > 0) ||
        options->version != LIBRDP_CHANNEL_SEND_OPTIONS_VERSION ||
        options->size < offsetof(librdp_channel_send_options, priority) + sizeof(options->priority) ||
        options->priority > LIBRDP_CHANNEL_PRIORITY_REALTIME)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.send_ex.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.dynamic_channel_message_bytes)
        return rdp_session_limit_rejected(session);
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_STATE;
    entry = rdp_session_dynamic_channel_from_handle(session, options->handle);
    if (!entry)
        return LIBRDP_STATUS_STATE;
    if (!entry->active)
        return LIBRDP_STATUS_STATE;
    if (rdp_session_dynamic_channel_is_internal(entry))
        return LIBRDP_STATUS_UNSUPPORTED;
    status = rdp_session_send_dynamic_channel_data_priority(session,
                                                            entry->channel_id,
                                                            entry->channel_id_bytes,
                                                            (uint8_t)options->priority,
                                                            data,
                                                            data_len,
                                                            "client.drdynvc.channel_send");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.channel_send",
                        "dvc_channel_id=%u name=%s priority=%u payload_len=%u",
                        entry->channel_id,
                        entry->name,
                        (unsigned)options->priority,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_channel_close_handle(librdp_session* session, librdp_channel_handle handle)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || handle == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.close_handle.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_STATE;
    entry = rdp_session_dynamic_channel_from_handle(session, handle);
    if (!entry)
        return LIBRDP_STATUS_STATE;
    if (!entry->active)
        return LIBRDP_STATUS_STATE;
    if (rdp_session_dynamic_channel_is_internal(entry))
        return LIBRDP_STATUS_UNSUPPORTED;
    return librdp_session_channel_close(session, entry->channel_id);
}

librdp_status librdp_session_static_channel_list(librdp_session* session,
                                                 librdp_static_channel_info* infos,
                                                 size_t capacity,
                                                 size_t* count)
{
    uint32_t i = 0;
    size_t written = 0;
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !count || (!infos && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.static_list.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < session->static_channel_count; i++)
    {
        rdp_session_static_channel* entry = &session->static_channels[i];

        if (!entry->active)
            continue;
        if (infos && written < capacity)
        {
            status = rdp_session_static_channel_copy_info(entry, &infos[written]);
            if (status != LIBRDP_STATUS_OK)
                return status;
            written++;
        }
        total++;
    }
    *count = total;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_static_channel_send(librdp_session* session,
                                                 const char* name,
                                                 const void* data,
                                                 size_t data_len)
{
    rdp_session_static_channel* entry = NULL;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !name || name[0] == '\0' || strlen(name) > LIBRDP_STATIC_CHANNEL_NAME_MAX ||
        (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.static_send.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.channel_buffer_bytes)
        return rdp_session_limit_rejected(session);
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    entry = rdp_session_static_channel_find_by_name(session, name);
    if (!entry)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append(&payload, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_channel_pdu(session,
                                               entry->channel_id,
                                               &payload,
                                               "client.channel.static_send");
    rdp_buffer_free(&payload);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.channel.static_send",
                        "name=%s channel_id=%u payload_len=%u",
                        entry->name,
                        entry->channel_id,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_channel_send(librdp_session* session,
                                          librdp_channel_id channel_id,
                                          const void* data,
                                          size_t data_len)
{
    rdp_session_dynamic_channel* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.channel.send.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.dynamic_channel_message_bytes)
        return rdp_session_limit_rejected(session);
    status = rdp_session_require_user_channel(session, channel_id, &entry);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_send_dynamic_channel_data(session,
                                                   entry->channel_id,
                                                   entry->channel_id_bytes,
                                                   data,
                                                   data_len,
                                                   "client.drdynvc.channel_send");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.channel_send",
                        "dvc_channel_id=%u name=%s payload_len=%u",
                        entry->channel_id,
                        entry->name,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_channel_close(librdp_session* session, librdp_channel_id channel_id)
{
    rdp_session_dynamic_channel* entry = NULL;
    rdp_buffer close_pdu;
    librdp_status status = rdp_session_require_owner(session, "client.channel.close.owner");

    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_require_user_channel(session, channel_id, &entry);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&close_pdu);
    status = rdp_dynamic_channel_write_close(&close_pdu, entry->channel_id, entry->channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_channel_pdu(session,
                                               session->dynamic_channel_id,
                                               &close_pdu,
                                               "client.drdynvc.channel_close");
    rdp_buffer_free(&close_pdu);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.channel_close",
                        "dvc_channel_id=%u name=%s",
                        entry->channel_id,
                        entry->name);
        rdp_session_dynamic_channel_clear_entry(entry);
    }
    return status;
}


librdp_status librdp_session_echo_send(librdp_session* session,
                                       const void* data,
                                       size_t data_len,
                                       uint32_t timeout_ms,
                                       uint64_t* sequence)
{
    rdp_session_dynamic_channel* entry = NULL;
    rdp_buffer request;
    rdp_buffer pending;
    uint64_t next_sequence = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || data_len > RDP_ECHO_CHANNEL_MAX_PAYLOAD ||
        timeout_ms == 0 || timeout_ms > RDP_SESSION_ECHO_MAX_TIMEOUT_MS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.echo.send.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->echo_pending)
        return LIBRDP_STATUS_STATE;
    entry = rdp_session_echo_channel_entry(session);
    if (!entry)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_buffer_init(&request);
    rdp_buffer_init(&pending);
    status = rdp_buffer_append(&pending, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_echo_channel_write_request(&request, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       entry->channel_id,
                                                       entry->channel_id_bytes,
                                                       request.data,
                                                       request.length,
                                                       "client.echo.ping");
    if (status == LIBRDP_STATUS_OK)
    {
        next_sequence = session->echo_next_sequence + 1u;
        if (next_sequence == 0)
            next_sequence = 1u;
        session->echo_next_sequence = next_sequence;
        session->echo_pending_payload = pending;
        rdp_buffer_init(&pending);
        session->echo_pending = 1;
        session->echo_pending_sequence = next_sequence;
        session->echo_pending_sent_ns = rdp_session_monotonic_ns();
        session->echo_pending_timeout_ms = timeout_ms;
        session->echo_stats.last_sequence = next_sequence;
        session->echo_stats.pending_sequence = next_sequence;
        session->echo_stats.pending_payload_len = data_len;
        rdp_session_metric_add(&session->echo_stats.pings_sent, 1);
        rdp_session_metric_add(&session->echo_stats.bytes_sent, data_len);
        if (sequence)
            *sequence = next_sequence;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.echo.ping",
                        "dvc_channel_id=%u sequence=%llu payload_len=%u timeout_ms=%u",
                        entry->channel_id,
                        (unsigned long long)next_sequence,
                        (unsigned)data_len,
                        timeout_ms);
    }
    rdp_buffer_free(&pending);
    rdp_buffer_free(&request);
    return status;
}

librdp_status librdp_session_get_echo_stats(const librdp_session* session, librdp_echo_stats* stats)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !stats || stats->version != LIBRDP_ECHO_STATS_VERSION ||
        stats->size < sizeof(*stats))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner_const(session, "client.echo.stats.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    *stats = session->echo_stats;
    stats->version = LIBRDP_ECHO_STATS_VERSION;
    stats->size = (uint32_t)sizeof(*stats);
    return LIBRDP_STATUS_OK;
}

const librdp_error* librdp_session_last_error(const librdp_session* session)
{
    return session ? &session->last_error : NULL;
}
