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
    rdp_buffer suppress;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!session || !session->surface || session->share_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    if (width == 0 || height == 0 || width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&suppress);
    status = rdp_slowpath_write_client_suppress_output(&suppress,
                                                       session->share_id,
                                                       session->mcs_user_id,
                                                       1,
                                                       0,
                                                       0,
                                                       (uint16_t)width,
                                                       (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &suppress, "rdp.activation.client_suppress_output");
    rdp_buffer_free(&suppress);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.client_suppress_output",
                    "share_id=%u width=%u height=%u",
                    session->share_id,
                    width,
                    height);
    return librdp_session_refresh(session, 0, 0, width, height);
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
    rdp_buffer confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&confirm);
    status = rdp_slowpath_parse_demand_active(payload, payload_len, &demand);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.activation.demand_active",
                        "share_id=%u capabilities=%u",
                        demand.share_id,
                        demand.capabilities.count);
    if (status == LIBRDP_STATUS_OK)
        session->share_id = demand.share_id;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_pointer_cache_clear(session);
        rdp_session_pointer_emit_default(session);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_confirm_active(&confirm,
                                                   demand.share_id,
                                                   session->mcs_user_id,
                                                   (uint16_t)librdp_surface_width(session->surface),
                                                   (uint16_t)librdp_surface_height(session->surface),
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
    if (session->clipboard_channel_id != 0)
    {
        status = rdp_session_send_clipboard_handshake(session);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_ACTIVE);
    rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);
    return LIBRDP_STATUS_OK;
}
