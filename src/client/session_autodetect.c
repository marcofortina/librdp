/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client network characteristics auto-detection runtime.
 * Invariants: requests are accepted only on the negotiated message channel,
 * one bandwidth measurement owns the timer at a time, and responses preserve
 * the request sequence number.
 * Ownership: the session owns all measurement state and temporary response
 * buffers remain local to dispatch.
 * Threading: dispatch and accounting are serialized by the session owner.
 * Trust boundary: parsed measurements may influence diagnostics but never
 * allocate according to an unchecked remote length.
 */

#include "client/session_autodetect.h"

#include "client/session_internal.h"
#include "client/session_protocol_io.h"
#include "client/session_runtime.h"
#include "common/trace.h"
#include "protocol/network_autodetect.h"
#include "security/security.h"

#include <limits.h>
#include <string.h>

static void rdp_session_autodetect_add_bytes(librdp_session* session,
                                             size_t payload_len)
{
    uint64_t bytes = 0u;

    if (!session || !session->autodetect_measurement_active ||
        payload_len == 0u)
        return;
    bytes = (uint64_t)payload_len;
    if (UINT64_MAX - session->autodetect_measurement_bytes < bytes)
        session->autodetect_measurement_bytes = UINT64_MAX;
    else
        session->autodetect_measurement_bytes += bytes;
}

void rdp_session_autodetect_reset(librdp_session* session)
{
    if (!session)
        return;
    session->autodetect_measurement_active = 0u;
    session->autodetect_measurement_sequence = 0u;
    session->autodetect_measurement_type = 0u;
    session->autodetect_measurement_start_ns = 0u;
    session->autodetect_measurement_bytes = 0u;
    rdp_session_autodetect_reset_metrics(session);
}

/* Clear observable counters and latest result gauges without stopping a measurement. */
void rdp_session_autodetect_reset_metrics(librdp_session* session)
{
    if (!session)
        return;
    session->autodetect_base_rtt_ms = 0u;
    session->autodetect_average_rtt_ms = 0u;
    session->autodetect_bandwidth_kbps = 0u;
    session->autodetect_requests_received = 0u;
    session->autodetect_responses_sent = 0u;
    session->autodetect_result_reports = 0u;
}

void rdp_session_autodetect_account_bytes(librdp_session* session,
                                          size_t payload_len)
{
    if (!session || !session->autodetect_measurement_active ||
        session->autodetect_measurement_type !=
            RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS)
        return;
    rdp_session_autodetect_add_bytes(session, payload_len);
}

static uint32_t rdp_session_autodetect_elapsed_ms(
    const librdp_session* session)
{
    uint64_t now_ns = rdp_session_monotonic_ns();
    uint64_t elapsed_ms = 0u;

    if (!session || session->autodetect_measurement_start_ns == 0u ||
        now_ns <= session->autodetect_measurement_start_ns)
        return 0u;
    elapsed_ms = (now_ns - session->autodetect_measurement_start_ns) /
                 1000000u;
    return elapsed_ms > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed_ms;
}

static uint32_t rdp_session_autodetect_byte_count(
    const librdp_session* session)
{
    if (!session)
        return 0u;
    return session->autodetect_measurement_bytes > UINT32_MAX ?
               UINT32_MAX :
               (uint32_t)session->autodetect_measurement_bytes;
}

static librdp_status rdp_session_autodetect_send_rtt_response(
    librdp_session* session,
    uint16_t sequence_number)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&response);
    status = rdp_network_autodetect_write_rtt_response(&response,
                                                       sequence_number);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_message_channel_pdu(
            session,
            RDP_SEC_AUTODETECT_RSP,
            &response,
            "rdp.autodetect.rtt.response");
    if (status == LIBRDP_STATUS_OK)
        rdp_session_metric_add(&session->autodetect_responses_sent, 1u);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_autodetect_send_bandwidth_results(
    librdp_session* session,
    const rdp_network_autodetect_pdu* request)
{
    rdp_buffer response;
    uint16_t response_type =
        RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONTINUOUS;
    uint32_t elapsed_ms = 0u;
    uint32_t byte_count = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (request->message_type ==
        RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME)
        response_type =
            RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONNECT_TIME;
    elapsed_ms = rdp_session_autodetect_elapsed_ms(session);
    byte_count = rdp_session_autodetect_byte_count(session);
    rdp_buffer_init(&response);
    status = rdp_network_autodetect_write_bandwidth_results(
        &response,
        request->sequence_number,
        response_type,
        elapsed_ms,
        byte_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_message_channel_pdu(
            session,
            RDP_SEC_AUTODETECT_RSP,
            &response,
            "rdp.autodetect.bandwidth.response");
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_metric_add(&session->autodetect_responses_sent, 1u);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.autodetect.bandwidth.response",
                        "sequence=%u elapsed_ms=%u byte_count=%u",
                        request->sequence_number,
                        elapsed_ms,
                        byte_count);
    }
    rdp_buffer_free(&response);
    return status;
}

/*
 * Process one verified server request and emit only the response mandated by
 * its type. Tunnel-only forms are rejected on the primary message channel so
 * transport state cannot be mixed across TCP and side channels.
 */
librdp_status rdp_session_handle_autodetect_message(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len)
{
    rdp_network_autodetect_pdu request;
    uint16_t routing_flags = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload || session->message_channel_id == 0u ||
        !session->message_channel_joined)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    routing_flags = (uint16_t)(security_flags &
                               (RDP_SEC_AUTODETECT_REQ |
                                RDP_SEC_AUTODETECT_RSP));
    if (routing_flags != RDP_SEC_AUTODETECT_REQ)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_network_autodetect_parse(payload, payload_len, &request);
    if (status != LIBRDP_STATUS_OK ||
        request.header_type != RDP_NETWORK_AUTODETECT_REQUEST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_session_metric_add(&session->autodetect_requests_received, 1u);
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.autodetect.request",
                    "sequence=%u type=%u payload_len=%u",
                    request.sequence_number,
                    request.message_type,
                    (unsigned)request.payload_len);

    if (request.message_type ==
            RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONTINUOUS ||
        request.message_type ==
            RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONNECT_TIME)
        return rdp_session_autodetect_send_rtt_response(
            session,
            request.sequence_number);

    if (request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_START_TUNNEL ||
        request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_TUNNEL)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS ||
        request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME)
    {
        if (session->autodetect_measurement_active)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        session->autodetect_measurement_active = 1u;
        session->autodetect_measurement_sequence = request.sequence_number;
        session->autodetect_measurement_type = request.message_type;
        session->autodetect_measurement_start_ns =
            rdp_session_monotonic_ns();
        session->autodetect_measurement_bytes = 0u;
        return LIBRDP_STATUS_OK;
    }

    if (request.message_type ==
        RDP_NETWORK_AUTODETECT_BANDWIDTH_PAYLOAD)
    {
        if (!session->autodetect_measurement_active ||
            session->autodetect_measurement_sequence !=
                request.sequence_number ||
            session->autodetect_measurement_type !=
                RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_session_autodetect_add_bytes(session, request.payload_len);
        return LIBRDP_STATUS_OK;
    }

    if (request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME ||
        request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONTINUOUS)
    {
        if (!session->autodetect_measurement_active ||
            session->autodetect_measurement_sequence !=
                request.sequence_number ||
            (session->autodetect_measurement_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME &&
                 request.message_type !=
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME) ||
            (session->autodetect_measurement_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS &&
                 request.message_type !=
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONTINUOUS))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (request.message_type ==
            RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME)
            rdp_session_autodetect_add_bytes(session, request.payload_len);
        status = rdp_session_autodetect_send_bandwidth_results(session,
                                                               &request);
        session->autodetect_measurement_active = 0u;
        session->autodetect_measurement_sequence = 0u;
        session->autodetect_measurement_type = 0u;
        session->autodetect_measurement_start_ns = 0u;
        session->autodetect_measurement_bytes = 0u;
        return status;
    }

    if (request.message_type == RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT ||
        request.message_type ==
            RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH ||
        request.message_type == RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL)
    {
        if (request.message_type !=
            RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH)
            session->autodetect_base_rtt_ms = request.base_rtt_ms;
        if (request.message_type !=
            RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT)
            session->autodetect_bandwidth_kbps = request.bandwidth_kbps;
        session->autodetect_average_rtt_ms = request.average_rtt_ms;
        rdp_session_metric_add(&session->autodetect_result_reports, 1u);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.autodetect.network.result",
                        "sequence=%u base_rtt_ms=%u bandwidth_kbps=%u average_rtt_ms=%u",
                        request.sequence_number,
                        session->autodetect_base_rtt_ms,
                        session->autodetect_bandwidth_kbps,
                        session->autodetect_average_rtt_ms);
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

/* Initialize caller-owned metadata for a complete public metrics snapshot. */
librdp_status librdp_network_autodetect_metrics_init(
    librdp_network_autodetect_metrics* metrics)
{
    if (!metrics)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = LIBRDP_NETWORK_AUTODETECT_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
    return LIBRDP_STATUS_OK;
}

/* Copy one owner-thread-consistent view of counters and latest server results. */
librdp_status librdp_session_get_network_autodetect_metrics(
    const librdp_session* session,
    librdp_network_autodetect_metrics* metrics)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !metrics ||
        metrics->version != LIBRDP_NETWORK_AUTODETECT_METRICS_VERSION ||
        metrics->size < sizeof(*metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner_const(
        session,
        "client.autodetect.metrics.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    metrics->requests_received = session->autodetect_requests_received;
    metrics->responses_sent = session->autodetect_responses_sent;
    metrics->result_reports = session->autodetect_result_reports;
    metrics->base_rtt_ms = session->autodetect_base_rtt_ms;
    metrics->average_rtt_ms = session->autodetect_average_rtt_ms;
    metrics->bandwidth_kbps = session->autodetect_bandwidth_kbps;
    return LIBRDP_STATUS_OK;
}
