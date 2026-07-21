/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client RDPEUDP and UDP2 side-transport runtime.
 * Invariants: packet validation and response allocation complete before
 * receive-window state or success metrics are committed.
 * Ownership: callers own datagrams and response buffers; the session owns only
 * sequence state and aggregate counters.
 * Threading: public entry points require the serialized session owner thread.
 * Trust boundary: decrypted side-transport records remain untrusted and their
 * payload bytes are never written to trace.
 */

#include "client/session_internal.h"

#include "common/trace.h"
#include "client/session_protocol_io.h"
#include "protocol/gcc.h"
#include "security/security.h"
#include "transport/multitransport.h"
#include "transport/udp_transport.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <string.h>

#define RDP_SESSION_MULTITRANSPORT_DEFAULT_TIMEOUT_MS 10000u

static int rdp_session_multitransport_slot_index(
    librdp_multitransport_protocol protocol)
{
    if (protocol == LIBRDP_MULTITRANSPORT_UDP_RELIABLE)
        return 0;
    if (protocol == LIBRDP_MULTITRANSPORT_UDP_LOSSY)
        return 1;
    return -1;
}

static uint64_t rdp_session_multitransport_next_token(
    librdp_session* session)
{
    if (!session)
        return 0u;
    session->multitransport_next_request_token++;
    if (session->multitransport_next_request_token == 0u)
        session->multitransport_next_request_token = 1u;
    return session->multitransport_next_request_token;
}

static void rdp_session_multitransport_release_slot(
    librdp_session* session,
    rdp_session_multitransport_slot* slot,
    int established)
{
    librdp_multitransport_request request;
    librdp_multitransport_release_callback release = NULL;
    void* user_data = NULL;

    if (!session || !slot || slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_EMPTY)
        return;
    request = slot->request;
    if (session->multitransport_provider_set)
    {
        release = session->multitransport_provider.release;
        user_data = session->multitransport_provider.user_data;
    }
    OPENSSL_cleanse(slot, sizeof(*slot));
    if (release)
        release(session, &request, established, user_data);
    OPENSSL_cleanse(&request, sizeof(request));
}

static librdp_status rdp_session_multitransport_send_response(
    librdp_session* session,
    uint32_t request_id,
    uint32_t hresult)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&response);
    status = rdp_multitransport_write_initiate_response(&response,
                                                        request_id,
                                                        hresult);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_message_channel_pdu(
            session,
            RDP_SEC_TRANSPORT_RSP,
            &response,
            "rdp.multitransport.response");
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.multitransport.response",
                        "request_id=%u hresult=%u",
                        request_id,
                        hresult);
    }
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_multitransport_finish_slot(
    librdp_session* session,
    rdp_session_multitransport_slot* slot,
    librdp_status result)
{
    const int accepted = result == LIBRDP_STATUS_OK;
    const uint32_t hresult = accepted ?
                                 RDP_MULTITRANSPORT_HRESULT_OK :
                                 RDP_MULTITRANSPORT_HRESULT_ABORT;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !slot || slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_EMPTY)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_multitransport_send_response(session,
                                                      slot->request.request_id,
                                                      hresult);
    if (status == LIBRDP_STATUS_OK && accepted)
    {
        slot->state = RDP_SESSION_MULTITRANSPORT_SLOT_READY;
        slot->deadline_ns = 0u;
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.multitransport.ready",
                        "request_id=%u protocol=%u request_token=%llu",
                        slot->request.request_id,
                        (unsigned)slot->request.protocol,
                        (unsigned long long)slot->request.request_token);
        return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK &&
        session->multitransport_provider_set)
    {
        rdp_session_set_last_error(
            session,
            result,
            0,
            LIBRDP_ERROR_COMPONENT_BACKEND,
            "client.multitransport.provider",
            result == LIBRDP_STATUS_TIMEOUT ?
                "multitransport provider timed out" :
                "multitransport provider rejected side transport");
    }
    rdp_session_multitransport_release_slot(session, slot, accepted);
    return status;
}

static int rdp_session_multitransport_request_matches(
    const rdp_session_multitransport_slot* slot,
    const rdp_multitransport_initiate_request* request)
{
    if (!slot || !request || slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_EMPTY)
        return 0;
    return slot->request.request_id == request->request_id &&
           (uint16_t)slot->request.protocol == request->requested_protocol &&
           CRYPTO_memcmp(slot->request.security_cookie,
                         request->security_cookie,
                         RDP_MULTITRANSPORT_COOKIE_LENGTH) == 0;
}

static librdp_status rdp_session_multitransport_require(
    librdp_session* session,
    librdp_feature feature,
    const char* phase)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_session_require_owner(session, phase);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_session_feature_ready_for_negotiation(session, feature) ||
        !session->multitransport_negotiated)
        return LIBRDP_STATUS_UNSUPPORTED;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_multitransport_copy_response(
    const rdp_buffer* response_packet,
    void* response,
    size_t response_capacity,
    size_t* response_len)
{
    if (!response_packet || !response_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (response_packet->length > response_capacity)
    {
        *response_len = response_packet->length;
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (response_packet->length > 0)
        memcpy(response, response_packet->data, response_packet->length);
    *response_len = response_packet->length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_udp_write_ack_vector(
    rdp_buffer* response,
    uint32_t source_ack,
    uint16_t receive_window,
    uint32_t pending_gap)
{
    rdp_udp_fec_header header;
    uint8_t vector[RDP_UDP_ACK_VECTOR_ENCODED_MAX_SIZE];
    uint16_t vector_size = 0;
    uint32_t remaining = pending_gap;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!response || pending_gap > RDP_UDP_MAX_REPORTABLE_GAP)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&header, 0, sizeof(header));
    memset(vector, 0, sizeof(vector));
    header.source_ack = source_ack;
    header.receive_window_size = receive_window == 0 ? 1u : receive_window;
    header.flags = RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SACK_OPTION;
    while (remaining > 0 && vector_size < (uint16_t)sizeof(vector))
    {
        uint8_t run = remaining > RDP_UDP_ACK_VECTOR_MAX_RUN ?
                          RDP_UDP_ACK_VECTOR_MAX_RUN :
                          (uint8_t)remaining;

        vector[vector_size] =
            (uint8_t)((RDP_UDP_ACK_VECTOR_STATE_PENDING << 6) |
                      (uint8_t)(run - 1u));
        remaining -= run;
        vector_size++;
    }
    if (remaining != 0 || vector_size >= (uint16_t)sizeof(vector))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    vector[vector_size++] = 0;
    status = rdp_udp_write_fec_header(response, &header);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_ack_vector(response, vector, vector_size);
    return status;
}

void rdp_session_multitransport_reset(librdp_session* session,
                                      int reset_metrics)
{
    size_t index = 0u;

    if (!session)
        return;
    for (index = 0u; index < RDP_SESSION_MULTITRANSPORT_SLOT_COUNT; index++)
    {
        rdp_session_multitransport_slot* slot =
            &session->multitransport_slots[index];
        const int established =
            slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_READY;

        rdp_session_multitransport_release_slot(session,
                                                slot,
                                                established);
    }
    session->multitransport_negotiated = 0;
    session->multitransport_flags = 0;
    session->multitransport_udp_active = 0;
    session->multitransport_udp2_active = 0;
    session->multitransport_soft_sync_count = 0;
    session->multitransport_udp_reliable_selected = 0;
    session->multitransport_udp_lossy_selected = 0;
    memset(session->multitransport_udp_window_started,
           0,
           sizeof(session->multitransport_udp_window_started));
    memset(session->multitransport_udp_fallback_tcp,
           0,
           sizeof(session->multitransport_udp_fallback_tcp));
    memset(session->multitransport_udp_receive_window,
           0,
           sizeof(session->multitransport_udp_receive_window));
    memset(session->multitransport_udp_next_receive_sequence,
           0,
           sizeof(session->multitransport_udp_next_receive_sequence));
    memset(session->multitransport_udp_last_receive_sequence,
           0,
           sizeof(session->multitransport_udp_last_receive_sequence));
    session->multitransport_udp2_window_started = 0;
    session->multitransport_udp2_fallback_tcp = 0;
    session->multitransport_udp2_log_window_size = 0;
    session->multitransport_udp2_next_receive_sequence = 0;
    session->multitransport_udp2_last_receive_sequence = 0;
    session->multitransport_udp2_last_peer_ack_sequence = 0;
    session->multitransport_bootstrap_required = 0u;
    if (reset_metrics)
        (void)librdp_multitransport_metrics_init(
            &session->multitransport_metrics);
}

/*
 * Route the primary Message Channel bootstrap request to the application
 * provider. A provider may finish synchronously or retain the opaque token for
 * owner-thread completion; absent or failed providers produce the wire-defined
 * E_ABORT response without weakening the primary TCP connection.
 */
librdp_status rdp_session_handle_multitransport_message(
    librdp_session* session,
    uint16_t security_flags,
    const uint8_t* payload,
    size_t payload_len)
{
    rdp_multitransport_initiate_request request;
    rdp_session_multitransport_slot* slot = NULL;
    librdp_multitransport_request provider_request;
    librdp_status provider_status = LIBRDP_STATUS_UNSUPPORTED;
    int slot_index = -1;
    uint32_t required_flag = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload || session->message_channel_id == 0u ||
        !session->message_channel_joined)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((security_flags & (RDP_SEC_TRANSPORT_REQ | RDP_SEC_TRANSPORT_RSP)) !=
        RDP_SEC_TRANSPORT_REQ)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_multitransport_parse_initiate_request(payload,
                                                       payload_len,
                                                       &request);
    if (status != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    required_flag = request.requested_protocol ==
                            RDP_MULTITRANSPORT_PROTOCOL_UDP_RELIABLE ?
                        RDP_GCC_MULTITRANSPORT_UDP_FECR :
                        RDP_GCC_MULTITRANSPORT_UDP_FECL;
    if (!session->multitransport_negotiated ||
        (session->multitransport_flags & required_flag) == 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    slot_index = rdp_session_multitransport_slot_index(
        (librdp_multitransport_protocol)request.requested_protocol);
    if (slot_index < 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    slot = &session->multitransport_slots[(size_t)slot_index];
    session->multitransport_bootstrap_required = 1u;
    if (slot->state != RDP_SESSION_MULTITRANSPORT_SLOT_EMPTY)
    {
        if (rdp_session_multitransport_request_matches(slot, &request))
        {
            if (slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_READY)
                return rdp_session_multitransport_send_response(
                    session,
                    request.request_id,
                    RDP_MULTITRANSPORT_HRESULT_OK);
            return LIBRDP_STATUS_OK;
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.multitransport.request.rejected",
                        "request_id=%u protocol=%u reason=slot_busy",
                        request.request_id,
                        request.requested_protocol);
        return rdp_session_multitransport_send_response(
            session,
            request.request_id,
            RDP_MULTITRANSPORT_HRESULT_ABORT);
    }

    memset(&provider_request, 0, sizeof(provider_request));
    provider_request.version = LIBRDP_MULTITRANSPORT_REQUEST_VERSION;
    provider_request.size = (uint32_t)sizeof(provider_request);
    provider_request.request_token =
        rdp_session_multitransport_next_token(session);
    provider_request.request_id = request.request_id;
    provider_request.protocol =
        (librdp_multitransport_protocol)request.requested_protocol;
    memcpy(provider_request.security_cookie,
           request.security_cookie,
           sizeof(provider_request.security_cookie));
    slot->state = RDP_SESSION_MULTITRANSPORT_SLOT_STARTING;
    slot->request = provider_request;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.multitransport.request",
                    "request_id=%u protocol=%u provider=%s request_token=%llu",
                    request.request_id,
                    request.requested_protocol,
                    session->multitransport_provider_set ? "configured" :
                                                          "unavailable",
                    (unsigned long long)provider_request.request_token);
    if (session->multitransport_provider_set)
    {
        provider_status = session->multitransport_provider.start(
            session,
            &provider_request,
            session->multitransport_provider.user_data);
    }
    OPENSSL_cleanse(&provider_request, sizeof(provider_request));
    if (provider_status == LIBRDP_STATUS_AGAIN)
    {
        const uint64_t now_ns = rdp_session_monotonic_ns();
        const uint64_t timeout_ns =
            (uint64_t)session->multitransport_provider.timeout_ms * 1000000u;

        slot->state = RDP_SESSION_MULTITRANSPORT_SLOT_PENDING;
        slot->deadline_ns = now_ns > UINT64_MAX - timeout_ns ?
                                UINT64_MAX :
                                now_ns + timeout_ns;
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.multitransport.pending",
                        "request_id=%u protocol=%u request_token=%llu timeout_ms=%u",
                        slot->request.request_id,
                        (unsigned)slot->request.protocol,
                        (unsigned long long)slot->request.request_token,
                        session->multitransport_provider.timeout_ms);
        return LIBRDP_STATUS_OK;
    }
    status = rdp_session_multitransport_finish_slot(session,
                                                    slot,
                                                    provider_status);
    return status;
}

librdp_status librdp_multitransport_metrics_init(
    librdp_multitransport_metrics* metrics)
{
    if (!metrics)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = LIBRDP_MULTITRANSPORT_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_multitransport_provider_init(
    librdp_multitransport_provider* provider)
{
    if (!provider)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(provider, 0, sizeof(*provider));
    provider->version = LIBRDP_MULTITRANSPORT_PROVIDER_VERSION;
    provider->size = (uint32_t)sizeof(*provider);
    provider->timeout_ms = RDP_SESSION_MULTITRANSPORT_DEFAULT_TIMEOUT_MS;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_set_multitransport_provider(
    librdp_session* session,
    const librdp_multitransport_provider* provider)
{
    size_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_session_require_owner(
        session,
        "client.multitransport.provider.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (index = 0u; index < RDP_SESSION_MULTITRANSPORT_SLOT_COUNT; index++)
    {
        if (session->multitransport_slots[index].state !=
            RDP_SESSION_MULTITRANSPORT_SLOT_EMPTY)
            return LIBRDP_STATUS_STATE;
    }
    if (!provider)
    {
        OPENSSL_cleanse(&session->multitransport_provider,
                        sizeof(session->multitransport_provider));
        session->multitransport_provider_set = 0u;
        return LIBRDP_STATUS_OK;
    }
    if (provider->version != LIBRDP_MULTITRANSPORT_PROVIDER_VERSION ||
        provider->size < sizeof(*provider) || !provider->start ||
        !provider->release ||
        provider->timeout_ms == 0u ||
        provider->timeout_ms >
            LIBRDP_MULTITRANSPORT_PROVIDER_MAX_TIMEOUT_MS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    session->multitransport_provider = *provider;
    session->multitransport_provider_set = 1u;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_complete_multitransport_request(
    librdp_session* session,
    uint64_t request_token,
    librdp_status result)
{
    size_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (request_token == 0u || result == LIBRDP_STATUS_AGAIN)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(
        session,
        "client.multitransport.complete.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (index = 0u; index < RDP_SESSION_MULTITRANSPORT_SLOT_COUNT; index++)
    {
        rdp_session_multitransport_slot* slot =
            &session->multitransport_slots[index];

        if (slot->state == RDP_SESSION_MULTITRANSPORT_SLOT_PENDING &&
            slot->request.request_token == request_token)
            return rdp_session_multitransport_finish_slot(session,
                                                          slot,
                                                          result);
    }
    return LIBRDP_STATUS_STATE;
}

int rdp_session_multitransport_next_timeout_ms(
    const librdp_session* session)
{
    uint64_t now_ns = 0u;
    uint64_t minimum_ns = UINT64_MAX;
    uint64_t timeout_ms = 0u;
    size_t index = 0u;

    if (!session)
        return -1;
    now_ns = rdp_session_monotonic_ns();
    for (index = 0u; index < RDP_SESSION_MULTITRANSPORT_SLOT_COUNT; index++)
    {
        const rdp_session_multitransport_slot* slot =
            &session->multitransport_slots[index];

        if (slot->state != RDP_SESSION_MULTITRANSPORT_SLOT_PENDING)
            continue;
        if (slot->deadline_ns <= now_ns)
            return 0;
        if (slot->deadline_ns - now_ns < minimum_ns)
            minimum_ns = slot->deadline_ns - now_ns;
    }
    if (minimum_ns == UINT64_MAX)
        return -1;
    timeout_ms = minimum_ns / 1000000u;
    if (minimum_ns % 1000000u != 0u)
        timeout_ms++;
    if (timeout_ms > (uint64_t)INT_MAX)
        return INT_MAX;
    return (int)timeout_ms;
}

librdp_status rdp_session_multitransport_check_timeout(
    librdp_session* session)
{
    uint64_t now_ns = 0u;
    size_t index = 0u;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    now_ns = rdp_session_monotonic_ns();
    for (index = 0u; index < RDP_SESSION_MULTITRANSPORT_SLOT_COUNT; index++)
    {
        rdp_session_multitransport_slot* slot =
            &session->multitransport_slots[index];
        librdp_status status = LIBRDP_STATUS_OK;

        if (slot->state != RDP_SESSION_MULTITRANSPORT_SLOT_PENDING ||
            slot->deadline_ns > now_ns)
            continue;
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.multitransport.timeout",
                        "request_id=%u protocol=%u request_token=%llu",
                        slot->request.request_id,
                        (unsigned)slot->request.protocol,
                        (unsigned long long)slot->request.request_token);
        status = rdp_session_multitransport_finish_slot(session,
                                                        slot,
                                                        LIBRDP_STATUS_TIMEOUT);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_get_multitransport_metrics(
    const librdp_session* session,
    librdp_multitransport_metrics* metrics)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !metrics ||
        metrics->version != LIBRDP_MULTITRANSPORT_METRICS_VERSION ||
        metrics->size < sizeof(*metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner_const(
        session,
        "client.multitransport.metrics.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    *metrics = session->multitransport_metrics;
    return LIBRDP_STATUS_OK;
}

/*
 * Validate a caller-supplied decrypted RDPEUDP record and advance the receive
 * window selected by reliable. Response sizing is transactional: sequence
 * state and success counters commit only after the complete ACK vector fits.
 * A reliable gap beyond the advertised window permanently selects TCP
 * fallback for that tunnel until reconnect; payload bytes never enter trace.
 */
librdp_status librdp_session_process_udp_datagram(librdp_session* session,
                                                  int reliable,
                                                  const void* datagram,
                                                  size_t datagram_len,
                                                  void* response,
                                                  size_t response_capacity,
                                                  size_t* response_len)
{
    const uint8_t* bytes = (const uint8_t*)datagram;
    rdp_udp_fec_header header;
    rdp_udp_payload_prefix prefix;
    rdp_udp_source_payload_header source;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_syn_data syn;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_buffer response_packet;
    uint8_t next_window_started = 0;
    uint8_t next_fallback_tcp = 0;
    uint16_t next_receive_window = 0;
    uint32_t next_receive_sequence = 0;
    uint32_t next_last_receive_sequence = 0;
    uint64_t metric_ack_vector_in = 0;
    uint64_t metric_pending_from_peer = 0;
    uint64_t metric_pending = 0;
    uint64_t metric_dropped = 0;
    uint64_t metric_reordered = 0;
    uint64_t metric_tcp_fallback = 0;
    size_t mode = reliable ? 1u : 0u;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    status = rdp_session_multitransport_require(
        session,
        LIBRDP_FEATURE_UDP_TRANSPORT,
        "client.udp.datagram.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((reliable && !session->multitransport_udp_reliable_selected) ||
        (!reliable && !session->multitransport_udp_lossy_selected))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (session->multitransport_bootstrap_required)
    {
        const size_t slot_index = reliable ? 0u : 1u;

        if (session->multitransport_slots[slot_index].state !=
            RDP_SESSION_MULTITRANSPORT_SLOT_READY)
            return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (session->multitransport_udp_fallback_tcp[mode])
        return LIBRDP_STATUS_UNSUPPORTED;

    memset(&header, 0, sizeof(header));
    memset(&prefix, 0, sizeof(prefix));
    memset(&source, 0, sizeof(source));
    memset(&ack_vector, 0, sizeof(ack_vector));
    memset(&syn, 0, sizeof(syn));
    memset(&syn_ex, 0, sizeof(syn_ex));
    memset(&ack_of_ack, 0, sizeof(ack_of_ack));
    rdp_buffer_init(&response_packet);
    next_window_started =
        session->multitransport_udp_window_started[mode];
    next_fallback_tcp = session->multitransport_udp_fallback_tcp[mode];
    next_receive_window =
        session->multitransport_udp_receive_window[mode];
    next_receive_sequence =
        session->multitransport_udp_next_receive_sequence[mode];
    next_last_receive_sequence =
        session->multitransport_udp_last_receive_sequence[mode];

    status = rdp_udp_parse_fec_header(datagram, datagram_len, &header);
    if (status == LIBRDP_STATUS_OK)
        offset = 8u;
    if (status == LIBRDP_STATUS_OK)
    {
        uint16_t known_payload_flags =
            RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_SYNLOSSY |
            RDP_UDP_FLAG_SYNEX | RDP_UDP_FLAG_ACK_OF_ACKS |
            RDP_UDP_FLAG_SACK_OPTION | RDP_UDP_FLAG_DATA;
        uint16_t payload_flags =
            (uint16_t)(header.flags & known_payload_flags);

        if ((payload_flags & RDP_UDP_FLAG_DATA) != 0 &&
            (payload_flags & ~(RDP_UDP_FLAG_DATA | RDP_UDP_FLAG_FEC)) != 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else if ((payload_flags & RDP_UDP_FLAG_SYNEX) != 0 &&
                 payload_flags != RDP_UDP_FLAG_SYNEX)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else if ((payload_flags & RDP_UDP_FLAG_SACK_OPTION) != 0 &&
                 payload_flags != RDP_UDP_FLAG_SACK_OPTION)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK &&
        (header.flags & (RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_SYNLOSSY)) != 0)
    {
        if (datagram_len - offset != 8u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_udp_parse_syn_data(bytes + offset,
                                            datagram_len - offset,
                                            &syn);
    }
    else if (status == LIBRDP_STATUS_OK &&
             (header.flags & RDP_UDP_FLAG_SYNEX) != 0)
    {
        status = rdp_udp_parse_syn_data_ex(bytes + offset,
                                           datagram_len - offset,
                                           &syn_ex);
    }
    else if (status == LIBRDP_STATUS_OK &&
             (header.flags & RDP_UDP_FLAG_ACK_OF_ACKS) != 0)
    {
        if (datagram_len - offset != 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_udp_parse_ack_of_ack_vector(
                bytes + offset,
                datagram_len - offset,
                &ack_of_ack);
    }
    else if (status == LIBRDP_STATUS_OK &&
             (header.flags & RDP_UDP_FLAG_SACK_OPTION) != 0)
    {
        uint32_t received = 0;
        uint32_t pending = 0;

        status = rdp_udp_parse_ack_vector(bytes + offset,
                                          datagram_len - offset,
                                          &ack_vector);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_ack_vector_count(&ack_vector,
                                              &received,
                                              &pending);
        if (status == LIBRDP_STATUS_OK)
        {
            metric_ack_vector_in++;
            metric_pending_from_peer += pending;
        }
    }
    else if (status == LIBRDP_STATUS_OK &&
             (header.flags & RDP_UDP_FLAG_DATA) != 0)
    {
        uint32_t sequence = 0;
        uint32_t expected = next_receive_sequence;
        uint32_t distance = 0;
        uint16_t window =
            header.receive_window_size == 0 ?
                1u :
                header.receive_window_size;

        if (datagram_len - offset < 10u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_parse_payload_prefix(
                bytes + offset,
                datagram_len - offset,
                &prefix);
        if (status == LIBRDP_STATUS_OK &&
            (prefix.payload_size < 8u ||
             (size_t)prefix.payload_size > datagram_len - offset - 2u))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_parse_source_payload_header(
                bytes + offset + 2u,
                prefix.payload_size,
                &source);
        if (status == LIBRDP_STATUS_OK)
        {
            sequence = source.coded_sequence;
            distance =
                next_window_started ? sequence - expected : 0;
            next_receive_window = window;
            if (!next_window_started)
            {
                next_window_started = 1;
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
            }
            else if (distance == 0)
            {
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
            }
            else if (distance >= 0x80000000u)
            {
                metric_reordered++;
                if (!reliable)
                    metric_dropped++;
            }
            else if (!reliable)
            {
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
                metric_dropped += distance;
            }
            else if (distance <= window &&
                     distance <= RDP_UDP_MAX_REPORTABLE_GAP)
            {
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
                metric_pending += distance;
            }
            else
            {
                next_fallback_tcp = 1;
                metric_tcp_fallback++;
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_udp_write_ack_vector(
                &response_packet,
                sequence,
                window,
                reliable ? (uint32_t)metric_pending : 0u);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_multitransport_copy_response(
            &response_packet,
            response,
            response_capacity,
            response_len);
    if (status == LIBRDP_STATUS_OK)
    {
        librdp_multitransport_metrics* metrics =
            &session->multitransport_metrics;

        session->multitransport_udp_window_started[mode] =
            next_window_started;
        session->multitransport_udp_fallback_tcp[mode] =
            next_fallback_tcp;
        session->multitransport_udp_receive_window[mode] =
            next_receive_window;
        session->multitransport_udp_next_receive_sequence[mode] =
            next_receive_sequence;
        session->multitransport_udp_last_receive_sequence[mode] =
            next_last_receive_sequence;
        session->multitransport_udp_active = 1;
        rdp_session_metric_add(&session->metrics.pdu_in, 1u);
        rdp_session_metric_add(&metrics->udp_datagrams_in, 1u);
        rdp_session_metric_add(&metrics->udp_bytes_in,
                               (uint64_t)datagram_len);
        rdp_session_metric_add(&metrics->udp_ack_vector_in,
                               metric_ack_vector_in);
        rdp_session_metric_add(&metrics->udp_pending_packets,
                               metric_pending_from_peer + metric_pending);
        rdp_session_metric_add(&metrics->udp_dropped_packets,
                               metric_dropped);
        rdp_session_metric_add(&metrics->udp_reordered_packets,
                               metric_reordered);
        if (response_packet.length > 0)
        {
            rdp_session_metric_add(&session->metrics.pdu_out, 1u);
            rdp_session_metric_add(&metrics->udp_datagrams_out, 1u);
            rdp_session_metric_add(&metrics->udp_bytes_out,
                                   (uint64_t)response_packet.length);
            rdp_session_metric_add(&metrics->udp_ack_vector_out, 1u);
        }
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.udp.datagram",
                        "mode=%s wire_len=%u response_len=%u pending=%llu dropped=%llu reordered=%llu",
                        reliable ? "reliable" : "lossy",
                        (unsigned)datagram_len,
                        (unsigned)response_packet.length,
                        (unsigned long long)metric_pending,
                        (unsigned long long)metric_dropped,
                        (unsigned long long)metric_reordered);
    }
    else if (metric_tcp_fallback > 0)
    {
        session->multitransport_udp_fallback_tcp[mode] =
            next_fallback_tcp;
        rdp_session_metric_add(
            &session->multitransport_metrics.udp_tcp_fallbacks,
            metric_tcp_fallback);
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.udp.fallback",
                        "mode=%s reason=receive_window",
                        reliable ? "reliable" : "lossy");
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_session_set_last_error(session,
                                   status,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   "client.udp.datagram",
                                   "RDPEUDP datagram processing failed");
    rdp_buffer_free(&response_packet);
    return status;
}

/*
 * Decode one caller-owned UDP2 record, account peer ACK/loss information, and
 * emit an ACK or bounded loss vector for DATA. Window state is copied locally
 * and committed only after the response has been copied, allowing a safe retry
 * after LIMIT_EXCEEDED. Out-of-window forward jumps latch TCP fallback until
 * reconnect, while stale packets are acknowledged and counted as reordered.
 */
librdp_status librdp_session_process_udp2_datagram(librdp_session* session,
                                                   const void* datagram,
                                                   size_t datagram_len,
                                                   void* response,
                                                   size_t response_capacity,
                                                   size_t* response_len)
{
    rdp_buffer packet_bytes;
    rdp_buffer response_packet;
    rdp_buffer response_wire;
    rdp_udp2_prefix prefix;
    rdp_udp2_packet packet;
    rdp_udp2_packet_kind kind = RDP_UDP2_PACKET_KIND_CONTROL;
    uint8_t response_is_ack = 0;
    uint8_t response_is_ack_vector = 0;
    uint8_t next_window_started = 0;
    uint8_t next_fallback_tcp = 0;
    uint8_t next_log_window_size = 0;
    uint16_t next_receive_sequence = 0;
    uint16_t next_last_receive_sequence = 0;
    uint16_t next_last_peer_ack_sequence = 0;
    uint64_t metric_ack_in = 0;
    uint64_t metric_ack_vector_in = 0;
    uint64_t metric_ack_vector_lost = 0;
    uint64_t metric_lost = 0;
    uint64_t metric_reordered = 0;
    uint64_t metric_tcp_fallback = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    status = rdp_session_multitransport_require(
        session,
        LIBRDP_FEATURE_UDP2_TRANSPORT,
        "client.udp2.datagram.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->multitransport_bootstrap_required &&
        session->multitransport_slots[0].state !=
            RDP_SESSION_MULTITRANSPORT_SLOT_READY &&
        session->multitransport_slots[1].state !=
            RDP_SESSION_MULTITRANSPORT_SLOT_READY)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (session->multitransport_udp2_fallback_tcp)
        return LIBRDP_STATUS_UNSUPPORTED;

    next_window_started = session->multitransport_udp2_window_started;
    next_fallback_tcp = session->multitransport_udp2_fallback_tcp;
    next_log_window_size = session->multitransport_udp2_log_window_size;
    next_receive_sequence =
        session->multitransport_udp2_next_receive_sequence;
    next_last_receive_sequence =
        session->multitransport_udp2_last_receive_sequence;
    next_last_peer_ack_sequence =
        session->multitransport_udp2_last_peer_ack_sequence;
    rdp_buffer_init(&packet_bytes);
    rdp_buffer_init(&response_packet);
    rdp_buffer_init(&response_wire);
    memset(&prefix, 0, sizeof(prefix));
    memset(&packet, 0, sizeof(packet));

    status = rdp_udp2_unwrap_packet(&packet_bytes,
                                    datagram,
                                    datagram_len,
                                    &prefix);
    if (status == LIBRDP_STATUS_OK &&
        prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_parse_packet(packet_bytes.data,
                                       packet_bytes.length,
                                       &packet);
    if (status == LIBRDP_STATUS_OK &&
        prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_classify_packet(&packet, &kind);
    if (status == LIBRDP_STATUS_OK &&
        prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
    {
        if (packet.has_ack)
        {
            next_last_peer_ack_sequence = packet.ack.sequence_number;
            metric_ack_in++;
        }
        if (packet.has_ack_vector)
        {
            uint32_t received = 0;
            uint32_t lost = 0;

            status = rdp_udp2_ack_vector_count(&packet.ack_vector,
                                               &received,
                                               &lost);
            if (status == LIBRDP_STATUS_OK)
            {
                metric_ack_vector_in++;
                metric_ack_vector_lost += lost;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK &&
        (kind == RDP_UDP2_PACKET_KIND_DATA ||
         kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK))
    {
        uint16_t sequence = packet.data_sequence_number;
        uint16_t expected = next_receive_sequence;
        uint16_t distance =
            next_window_started ? (uint16_t)(sequence - expected) : 0u;
        uint32_t window = UINT32_C(1) << packet.header.log_window_size;

        next_log_window_size = packet.header.log_window_size;
        if (!next_window_started)
        {
            next_window_started = 1;
            next_receive_sequence = (uint16_t)(sequence + 1u);
            next_last_receive_sequence = sequence;
        }
        else if (distance == 0)
        {
            next_receive_sequence = (uint16_t)(sequence + 1u);
            next_last_receive_sequence = sequence;
        }
        else if (distance < 0x8000u && distance <= window &&
                 distance <= RDP_UDP2_MAX_REPORTABLE_GAP)
        {
            uint8_t coded_ack_vector[
                RDP_UDP2_ACK_VECTOR_ENCODED_MAX_SIZE];
            uint16_t remaining = distance;
            uint8_t count = 0;

            memset(coded_ack_vector, 0, sizeof(coded_ack_vector));
            while (remaining > 0 &&
                   count < (uint8_t)sizeof(coded_ack_vector))
            {
                uint8_t run =
                    remaining > RDP_UDP2_ACK_VECTOR_MAX_RUN ?
                        RDP_UDP2_ACK_VECTOR_MAX_RUN :
                        (uint8_t)remaining;

                coded_ack_vector[count++] =
                    (uint8_t)(0x80u | (uint8_t)(run - 1u));
                remaining = (uint16_t)(remaining - run);
            }
            if (remaining != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            if (status == LIBRDP_STATUS_OK)
                status = rdp_udp2_write_ack_vector_packet(
                    &response_packet,
                    packet.header.log_window_size,
                    expected,
                    0,
                    0,
                    0,
                    coded_ack_vector,
                    count);
            if (status == LIBRDP_STATUS_OK)
            {
                next_receive_sequence = (uint16_t)(sequence + 1u);
                next_last_receive_sequence = sequence;
                metric_lost += distance;
                response_is_ack_vector = 1;
            }
        }
        else if (distance < 0x8000u)
        {
            next_fallback_tcp = 1;
            metric_tcp_fallback++;
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else
        {
            metric_reordered++;
        }
        if (status == LIBRDP_STATUS_OK && response_packet.length == 0)
        {
            status = rdp_udp2_write_ack_packet(
                &response_packet,
                packet.header.log_window_size,
                packet.data_sequence_number,
                0,
                0,
                NULL,
                0,
                0);
            if (status == LIBRDP_STATUS_OK)
                response_is_ack = 1;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp2_wrap_packet(
                &response_wire,
                response_packet.data,
                response_packet.length,
                RDP_UDP2_PACKET_TYPE_DATA);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_multitransport_copy_response(
            &response_wire,
            response,
            response_capacity,
            response_len);
    if (status == LIBRDP_STATUS_OK)
    {
        librdp_multitransport_metrics* metrics =
            &session->multitransport_metrics;

        session->multitransport_udp2_window_started =
            next_window_started;
        session->multitransport_udp2_fallback_tcp = next_fallback_tcp;
        session->multitransport_udp2_log_window_size =
            next_log_window_size;
        session->multitransport_udp2_next_receive_sequence =
            next_receive_sequence;
        session->multitransport_udp2_last_receive_sequence =
            next_last_receive_sequence;
        session->multitransport_udp2_last_peer_ack_sequence =
            next_last_peer_ack_sequence;
        session->multitransport_udp2_active = 1;
        rdp_session_metric_add(&session->metrics.pdu_in, 1u);
        rdp_session_metric_add(&metrics->udp2_datagrams_in, 1u);
        rdp_session_metric_add(&metrics->udp2_bytes_in,
                               (uint64_t)datagram_len);
        rdp_session_metric_add(&metrics->udp2_ack_in, metric_ack_in);
        rdp_session_metric_add(&metrics->udp2_ack_vector_in,
                               metric_ack_vector_in);
        rdp_session_metric_add(
            &metrics->udp2_lost_packets,
            metric_ack_vector_lost + metric_lost);
        rdp_session_metric_add(&metrics->udp2_reordered_packets,
                               metric_reordered);
        if (response_wire.length > 0)
        {
            rdp_session_metric_add(&session->metrics.pdu_out, 1u);
            rdp_session_metric_add(&metrics->udp2_datagrams_out, 1u);
            rdp_session_metric_add(&metrics->udp2_bytes_out,
                                   (uint64_t)response_wire.length);
            if (response_is_ack)
                rdp_session_metric_add(&metrics->udp2_ack_out, 1u);
            if (response_is_ack_vector)
                rdp_session_metric_add(
                    &metrics->udp2_ack_vector_out,
                    1u);
        }
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.udp2.datagram",
                        "wire_len=%u response_len=%u kind=%u lost=%llu reordered=%llu",
                        (unsigned)datagram_len,
                        (unsigned)response_wire.length,
                        (unsigned)kind,
                        (unsigned long long)metric_lost,
                        (unsigned long long)metric_reordered);
    }
    else if (metric_tcp_fallback > 0)
    {
        session->multitransport_udp2_fallback_tcp = next_fallback_tcp;
        rdp_session_metric_add(
            &session->multitransport_metrics.udp2_tcp_fallbacks,
            metric_tcp_fallback);
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.udp2.fallback",
                        "reason=receive_window");
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_session_set_last_error(session,
                                   status,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   "client.udp2.datagram",
                                   "UDP2 datagram processing failed");

    rdp_buffer_free(&response_wire);
    rdp_buffer_free(&response_packet);
    rdp_buffer_free(&packet_bytes);
    return status;
}
