/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server-side Message Channel auto-detect orchestration.
 * Invariants: the security header is mandatory under every transport mode,
 * Standard Security responses are authenticated before parsing, and stale
 * sequence numbers cannot complete a newer probe.
 * Ownership: temporary plaintext and wire buffers are local to each call.
 * Threading: the server peer dispatch thread owns all state transitions.
 * Trust boundary: Message Channel bytes are remote input and are committed
 * only after security, direction, record type, and sequence validation.
 */

#include "server/server_autodetect.h"

#include "server/server_security.h"

#include "common/buffer.h"
#include "common/trace.h"
#include "protocol/mcs.h"
#include "protocol/network_autodetect.h"
#include "security/security.h"

#include <limits.h>
#include <time.h>

static uint64_t rdp_server_autodetect_monotonic_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
}

void rdp_server_autodetect_reset(librdp_server_peer* peer)
{
    if (!peer)
        return;
    peer->autodetect_next_sequence = 1u;
    peer->autodetect_pending_sequence = 0u;
    peer->autodetect_pending_rtt = 0u;
    peer->autodetect_pending_started_ns = 0u;
    peer->autodetect_base_rtt_us = 0u;
    peer->autodetect_average_rtt_us = 0u;
    peer->autodetect_requests_sent = 0u;
    peer->autodetect_responses_received = 0u;
}

static librdp_status rdp_server_autodetect_send(
    librdp_server_peer* peer,
    uint16_t security_flags,
    const rdp_buffer* body)
{
    rdp_buffer secured;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !body || peer->message_channel_id == 0u ||
        !peer->message_channel_joined)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    if (peer->standard_security_ready)
    {
        status = rdp_security_write_encrypted_pdu(
            &secured,
            &peer->standard_security,
            security_flags,
            body->data,
            body->length);
    }
    else
    {
        status = rdp_security_write_header(&secured, security_flags);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&secured, body->data, body->length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_mcs_write_send_data_indication(
            &mcs,
            peer->user_id,
            peer->message_channel_id,
            secured.data,
            secured.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    return status;
}

librdp_status rdp_server_autodetect_start(librdp_server_peer* peer)
{
    rdp_buffer request;
    uint16_t sequence_number = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE ||
        peer->message_channel_id == 0u || !peer->message_channel_joined)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (peer->autodetect_pending_rtt)
        return LIBRDP_STATUS_STATE;
    sequence_number = peer->autodetect_next_sequence++;
    if (peer->autodetect_next_sequence == 0u)
        peer->autodetect_next_sequence = 1u;
    rdp_buffer_init(&request);
    status = rdp_network_autodetect_write_rtt_request(&request,
                                                       sequence_number,
                                                       0);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_autodetect_send(peer,
                                            RDP_SEC_AUTODETECT_REQ,
                                            &request);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        peer->autodetect_pending_sequence = sequence_number;
        peer->autodetect_pending_started_ns =
            rdp_server_autodetect_monotonic_ns();
        peer->autodetect_pending_rtt = 1u;
        peer->autodetect_requests_sent++;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.autodetect.rtt.request",
                        "sequence=%u",
                        sequence_number);
    }
    rdp_buffer_free(&request);
    return status;
}

static librdp_status rdp_server_autodetect_unwrap(
    librdp_server_peer* peer,
    const uint8_t* payload,
    size_t payload_len,
    rdp_buffer* body,
    uint16_t* security_flags)
{
    rdp_standard_security_context* security = NULL;
    uint16_t allowed_flags = RDP_SEC_AUTODETECT_RSP;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !payload || !body || !security_flags)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->standard_security_ready)
    {
        security = &peer->standard_security;
        allowed_flags = (uint16_t)(allowed_flags | RDP_SEC_ENCRYPT |
                                   RDP_SEC_SECURE_CHECKSUM);
    }
    status = rdp_security_unwrap_pdu(security,
                                     payload,
                                     payload_len,
                                     body,
                                     security_flags);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status != LIBRDP_STATUS_OK ||
        (*security_flags & RDP_SEC_AUTODETECT_RSP) == 0u ||
        (*security_flags & (uint16_t)~allowed_flags) != 0u ||
        (peer->standard_security_ready &&
         (*security_flags & RDP_SEC_ENCRYPT) == 0u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_autodetect_handle(librdp_server_peer* peer,
                                           const uint8_t* payload,
                                           size_t payload_len)
{
    rdp_network_autodetect_pdu response;
    rdp_buffer body;
    uint16_t security_flags = 0u;
    uint64_t now_ns = 0u;
    uint64_t elapsed_us = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !payload || peer->message_channel_id == 0u ||
        !peer->message_channel_joined)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_server_autodetect_unwrap(peer,
                                          payload,
                                          payload_len,
                                          &body,
                                          &security_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_network_autodetect_parse(body.data,
                                              body.length,
                                              &response);
    if (status == LIBRDP_STATUS_OK &&
        (response.header_type != RDP_NETWORK_AUTODETECT_RESPONSE ||
         response.message_type != RDP_NETWORK_AUTODETECT_RTT_RESPONSE ||
         !peer->autodetect_pending_rtt ||
         response.sequence_number != peer->autodetect_pending_sequence))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        now_ns = rdp_server_autodetect_monotonic_ns();
        if (now_ns >= peer->autodetect_pending_started_ns)
            elapsed_us = (now_ns - peer->autodetect_pending_started_ns) /
                         1000u;
        if (elapsed_us > UINT32_MAX)
            elapsed_us = UINT32_MAX;
        peer->autodetect_average_rtt_us = (uint32_t)elapsed_us;
        if (peer->autodetect_base_rtt_us == 0u ||
            peer->autodetect_base_rtt_us > elapsed_us)
            peer->autodetect_base_rtt_us = (uint32_t)elapsed_us;
        peer->autodetect_pending_rtt = 0u;
        peer->autodetect_pending_sequence = 0u;
        peer->autodetect_pending_started_ns = 0u;
        peer->autodetect_responses_received++;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.autodetect.rtt.response",
                        "sequence=%u rtt_us=%u",
                        response.sequence_number,
                        peer->autodetect_average_rtt_us);
    }
    rdp_buffer_free(&body);
    return status;
}
