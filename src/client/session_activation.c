/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client activation and slow-path session status domain.
 * Invariants: ACTIVE state is visible only after Demand Active, Confirm Active, finalization, and channel handshakes succeed.
 * Ownership: activation buffers are stack-owned; persistent share, pointer, and clipboard state remain owned by the session.
 * Threading: callers must run on the session owner thread because activation changes lifecycle and callback-observable state.
 * Trust boundary: Demand Active, Font Map, Set Error Info, and Save Session Info are untrusted slow-path server data.
 */

#include "client/session_internal.h"
#include "protocol/slowpath.h"

#include <stdint.h>
#include <string.h>

static librdp_status rdp_session_send_activation_finalization(librdp_session* session, uint32_t share_id)
{
    rdp_buffer sync;
    rdp_buffer cooperate;
    rdp_buffer request;
    rdp_buffer persistent_keys;
    rdp_buffer font_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&sync);
    rdp_buffer_init(&cooperate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&persistent_keys);
    rdp_buffer_init(&font_list);

    status = rdp_slowpath_write_client_synchronize(&sync, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &sync, "rdp.activation.client_synchronize");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_synchronize", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&cooperate, share_id, session->mcs_user_id, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &cooperate, "rdp.activation.client_control_cooperate");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_cooperate", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&request, share_id, session->mcs_user_id, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &request, "rdp.activation.client_control_request");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_request", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_persistent_key_list(&persistent_keys, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &persistent_keys, "rdp.activation.client_persistent_key_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_persistent_key_list", "share_id=%u entries=0", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_font_list(&font_list, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &font_list, "rdp.activation.client_font_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_font_list", "share_id=%u", share_id);

    rdp_buffer_free(&font_list);
    rdp_buffer_free(&persistent_keys);
    rdp_buffer_free(&request);
    rdp_buffer_free(&cooperate);
    rdp_buffer_free(&sync);
    return status;
}

static librdp_status rdp_session_send_active_output_request(librdp_session* session)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!session || !session->surface || session->share_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    if (width == 0 || height == 0 || width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (session->server_suppress_output_supported)
        status = librdp_session_set_output_suppressed(session, 0);
    if (status == LIBRDP_STATUS_OK &&
        session->server_refresh_rect_supported)
        status = librdp_session_refresh(session, 0, 0, width, height);
    return status;
}

/*
 * Reset state whose lifetime is bounded by one activation epoch. Static and
 * dynamic channel identities survive, but incomplete fragments cannot cross
 * the boundary into the next epoch.
 */
static librdp_status rdp_session_reset_activation_epoch(librdp_session* session)
{
    uint32_t width = 0u;
    uint32_t height = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !session->surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    rdp_session_graphics_dirty_reset(session);
    rdp_session_fastpath_fragment_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_graphics_decompressor_reset(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_reset(&session->bulk_decompressor);
    session->slowpath_decompressed.length = 0u;
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_nscodec_context_reset(&session->surface_nscodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_gdi_gdiplus_reset(session);
    rdp_session_gdi_window_state_reset(session);
    rdp_session_palette_reset(session);
    rdp_gdi_render_state_init(&session->gdi_render);
    session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    session->gdi_drawing_to_offscreen = 0u;
    session->composited_connection_open = 0u;
    session->composited_connection_id = 0u;
    session->composited_open_channel_id = 0u;
    rdp_composited_render_tree_reset(&session->composited_tree);
    rdp_session_pointer_cache_clear(session);
    rdp_session_channels_reset_activation_fragments(session);

    session->clipboard_fragmenting = 0u;
    session->clipboard_fragment_expected = 0u;
    session->clipboard_fragment.length = 0u;
    session->audio_output_fragmenting = 0u;
    session->audio_output_fragment_expected = 0u;
    session->audio_output_fragment.length = 0u;
    session->audio_output_pending_wave = 0u;
    session->audio_output_pending_data.length = 0u;
    session->device_redirection_fragmenting = 0u;
    session->device_redirection_fragment_expected = 0u;
    session->device_redirection_fragment.length = 0u;
    session->pnp_redirection_fragmenting = 0u;
    session->pnp_redirection_fragment_expected = 0u;
    session->pnp_redirection_fragment.length = 0u;
    session->remote_programs_fragmenting = 0u;
    session->remote_programs_fragment_expected = 0u;
    session->remote_programs_fragment.length = 0u;
    session->server_refresh_rect_supported = 0u;
    session->server_suppress_output_supported = 0u;
    session->output_suppressed = 0u;
    session->output_suppression_known = 0u;

    status = librdp_surface_resize(session->surface, width, height);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.activation.reset",
                        "width=%u height=%u static_channels=%u",
                        width,
                        height,
                        session->static_channel_count);
    return status;
}

/*
 * Begin a fresh activation epoch without closing the transport or negotiated
 * virtual channels.
 */
librdp_status rdp_session_handle_deactivate_all(librdp_session* session,
                                                const uint8_t* payload,
                                                size_t payload_len)
{
    rdp_slowpath_deactivate_all deactivate;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!payload && payload_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_ACTIVE || session->share_id == 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_slowpath_parse_deactivate_all(payload,
                                               payload_len,
                                               &deactivate);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (deactivate.has_share_id && deactivate.share_id != session->share_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_session_reset_activation_epoch(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    session->reactivating = 1u;
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_ACTIVATING);
    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);
    status = rdp_session_activation_deadline_start(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_pointer_emit_default(session);
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.deactivate_all",
                    "share_id=%u descriptor_len=%u",
                    session->share_id,
                    deactivate.source_descriptor_len);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_trace_slowpath_data_pdu(librdp_session* session, const rdp_slowpath_data_pdu* data_pdu)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
    {
        rdp_slowpath_font_map font_map;

        status = rdp_slowpath_parse_font_map(data_pdu->payload, data_pdu->payload_len, &font_map);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.activation.font_map",
                            "entries=%u total_entries=%u flags=%u entry_size=%u",
                            font_map.number_entries,
                            font_map.total_entries,
                            font_map.map_flags,
                            font_map.entry_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_active_output_request(session);
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
    {
        uint32_t error_info = 0;

        status = rdp_slowpath_parse_set_error_info(data_pdu->payload, data_pdu->payload_len, &error_info);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.set_error_info", "error_info=%u", error_info);
            if (error_info != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
    {
        rdp_slowpath_save_session_info info;

        status = rdp_slowpath_parse_save_session_info(data_pdu->payload, data_pdu->payload_len, &info);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.save_session_info",
                            "info_type=%u data_len=%u",
                            info.info_type,
                            (unsigned)info.data_len);
    }

    return status;
}
/*
 * Demand Active commits the negotiated share state, resets pointer visibility,
 * sends Confirm Active and finalization PDUs, then exposes ACTIVE state only
 * after optional static-channel handshakes have completed.
 */
librdp_status rdp_session_handle_demand_active(librdp_session* session, const uint8_t* payload, size_t payload_len)
{
    rdp_slowpath_demand_active demand;
    const rdp_capability_set* general_set = NULL;
    const rdp_capability_set* bitmap_set = NULL;
    rdp_capability_general general;
    rdp_capability_bitmap bitmap;
    rdp_buffer confirm;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0u;
    uint32_t height = 0u;
    int dimensions_changed = 0;
    int was_reactivating = 0;

    if (!session || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&confirm);
    was_reactivating = session->reactivating != 0u;
    status = rdp_slowpath_parse_demand_active(payload, payload_len, &demand);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.activation.demand_active",
                        "share_id=%u capabilities=%u",
                        demand.share_id,
                        demand.capabilities.count);
    if (status == LIBRDP_STATUS_OK)
    {
        width = librdp_surface_width(session->surface);
        height = librdp_surface_height(session->surface);
        memset(&general, 0, sizeof(general));
        general_set = rdp_capabilities_find(&demand.capabilities,
                                            RDP_CAPABILITY_TYPE_GENERAL);
        if (general_set)
            status = rdp_capability_parse_general(general_set, &general);
        bitmap_set = rdp_capabilities_find(&demand.capabilities,
                                           RDP_CAPABILITY_TYPE_BITMAP);
        if (status == LIBRDP_STATUS_OK && bitmap_set)
        {
            status = rdp_capability_parse_bitmap(bitmap_set, &bitmap);
            if (status == LIBRDP_STATUS_OK)
            {
                width = bitmap.desktop_width;
                height = bitmap.desktop_height;
                if (width < LIBRDP_DESKTOP_MIN_DIMENSION ||
                    height < LIBRDP_DESKTOP_MIN_DIMENSION ||
                    width > LIBRDP_DESKTOP_MAX_DIMENSION ||
                    height > LIBRDP_DESKTOP_MAX_DIMENSION)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else if (width > session->limits.surface_max_dimension ||
                         height > session->limits.surface_max_dimension)
                    status = rdp_session_limit_rejected(session);
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        session->share_id = demand.share_id;
        session->server_refresh_rect_supported =
            general.refresh_rect_support != 0u;
        session->server_suppress_output_supported =
            general.suppress_output_support != 0u;
        session->output_suppressed = 0u;
        session->output_suppression_known = 0u;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        dimensions_changed =
            width != librdp_surface_width(session->surface) ||
            height != librdp_surface_height(session->surface);
        if (dimensions_changed)
            status = librdp_surface_resize(session->surface, width, height);
    }
    if (status == LIBRDP_STATUS_OK && dimensions_changed)
    {
        librdp_rect rect;

        memset(&rect, 0, sizeof(rect));
        rect.width = width;
        rect.height = height;
        rdp_session_emit_graphics_update(session,
                                         LIBRDP_GRAPHICS_UPDATE_DESKTOP_RESIZE,
                                         0u,
                                         0u,
                                         &rect,
                                         LIBRDP_PIXEL_FORMAT_BGRA32,
                                         NULL,
                                         0u);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_pointer_cache_clear(session);
        rdp_session_pointer_emit_default(session);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_confirm_active(&confirm,
                                                   demand.share_id,
                                                   session->mcs_user_id,
                                                   (uint16_t)width,
                                                   (uint16_t)height,
                                                   "librdp");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &confirm, "rdp.activation.confirm_active");
    rdp_buffer_free(&confirm);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.confirm_active", "share_id=%u", demand.share_id);
    status = rdp_session_send_activation_finalization(session, demand.share_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!was_reactivating && session->clipboard_channel_id != 0)
    {
        status = rdp_session_send_clipboard_handshake(session);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    session->reactivating = 0u;
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_ACTIVE);
    rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_set_output_suppressed(
    librdp_session* session,
    int suppressed)
{
    rdp_buffer request;
    rdp_trace_session_scope trace_scope;
    uint32_t width = 0u;
    uint32_t height = 0u;
    uint8_t next = suppressed ? 1u : 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(
        session,
        "client.output_suppression.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_ACTIVE ||
        session->share_id == 0u)
        return LIBRDP_STATUS_STATE;
    if (!session->server_suppress_output_supported)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (session->output_suppression_known &&
        session->output_suppressed == next)
        return LIBRDP_STATUS_OK;
    if (!next)
    {
        if (!session->surface)
            return LIBRDP_STATUS_STATE;
        width = librdp_surface_width(session->surface);
        height = librdp_surface_height(session->surface);
        if (width == 0u || height == 0u ||
            width > 0xffffu || height > 0xffffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    rdp_session_trace_scope_begin(session, &trace_scope);
    rdp_buffer_init(&request);
    status = rdp_slowpath_write_client_suppress_output(
        &request,
        session->share_id,
        session->mcs_user_id,
        next ? 0 : 1,
        0u,
        0u,
        (uint16_t)width,
        (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(
            session,
            &request,
            next ? "rdp.output.suppress" :
                   "rdp.output.resume");
    rdp_buffer_free(&request);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_trace_scope_end(session, &trace_scope);
        return status;
    }

    session->output_suppressed = next;
    session->output_suppression_known = 1u;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    next ? "client.active.output.suppressed" :
                           "client.active.output.resumed",
                    "width=%u height=%u",
                    width,
                    height);
    rdp_session_trace_scope_end(session, &trace_scope);
    return LIBRDP_STATUS_OK;
}
