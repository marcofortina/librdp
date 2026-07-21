/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client channel tests.
 * Coverage: static channels, DVC, clipboard, display, echo, and WebAuthn.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

#include "client/session_autodetect.h"
#include "client/session_message_channel.h"
#include "protocol/network_autodetect.h"
#include "protocol/session_selection.h"
#include "transport/multitransport.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

typedef struct dvc_boundary_capture
{
    event_counter events;
    size_t message_count;
    int valid;
} dvc_boundary_capture;

typedef struct unknown_channel_capture
{
    uint32_t static_open;
    uint32_t static_data;
    uint32_t dynamic_open;
    uint32_t dynamic_data;
    uint32_t dynamic_close;
    int valid;
} unknown_channel_capture;

typedef struct multitransport_provider_capture
{
    librdp_status next_status;
    librdp_multitransport_request request;
    int side_fds[2][2];
    uint8_t bound_cookie[2][LIBRDP_MULTITRANSPORT_COOKIE_SIZE];
    uint32_t starts;
    uint32_t releases;
    uint32_t established_releases;
    uint8_t bound[2];
    int valid;
} multitransport_provider_capture;

static librdp_status build_test_udp_data(rdp_buffer* datagram,
                                         uint32_t sequence,
                                         uint16_t receive_window,
                                         const void* data,
                                         size_t data_len);

static int multitransport_capture_index(
    librdp_multitransport_protocol protocol)
{
    if (protocol == LIBRDP_MULTITRANSPORT_UDP_RELIABLE)
        return 0;
    if (protocol == LIBRDP_MULTITRANSPORT_UDP_LOSSY)
        return 1;
    return -1;
}

/*
 * Model the application-owned side transport with a datagram socket pair and
 * retain the server cookie that a native provider binds to its TLS/DTLS
 * context. No descriptor or security material crosses into the core.
 */
static librdp_status establish_test_side_transport(
    multitransport_provider_capture* capture,
    const librdp_multitransport_request* request)
{
    int index = 0;

    if (!capture || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    index = multitransport_capture_index(request->protocol);
    if (index < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capture->bound[index] || capture->side_fds[index][0] >= 0 ||
        capture->side_fds[index][1] >= 0)
        return LIBRDP_STATUS_STATE;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, capture->side_fds[index]) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    memcpy(capture->bound_cookie[index],
           request->security_cookie,
           sizeof(capture->bound_cookie[index]));
    capture->bound[index] = 1u;
    return LIBRDP_STATUS_OK;
}

/*
 * Capture the request and establish a provider-owned transport for immediate
 * completions. Pending completions are established by the test before they
 * are reported to the core.
 */
static librdp_status on_multitransport_start(
    librdp_session* session,
    const librdp_multitransport_request* request,
    void* user_data)
{
    multitransport_provider_capture* capture =
        (multitransport_provider_capture*)user_data;

    (void)session;
    if (!capture || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    capture->request = *request;
    capture->starts++;
    if (capture->next_status == LIBRDP_STATUS_OK)
        return establish_test_side_transport(capture, request);
    return capture->next_status;
}

/* Close provider resources and verify the cookie retained for security binding. */
static void on_multitransport_release(
    librdp_session* session,
    const librdp_multitransport_request* request,
    int established,
    void* user_data)
{
    multitransport_provider_capture* capture =
        (multitransport_provider_capture*)user_data;
    int index = 0;

    (void)session;
    if (!capture || !request)
        return;
    index = multitransport_capture_index(request->protocol);
    if (index < 0)
    {
        capture->valid = 0;
        return;
    }
    capture->releases++;
    if (established)
    {
        capture->established_releases++;
        if (!capture->bound[index] ||
            CRYPTO_memcmp(capture->bound_cookie[index],
                          request->security_cookie,
                          sizeof(capture->bound_cookie[index])) != 0)
            capture->valid = 0;
    }
    else if (capture->bound[index])
    {
        capture->valid = 0;
    }
    if (capture->side_fds[index][0] >= 0)
        close(capture->side_fds[index][0]);
    if (capture->side_fds[index][1] >= 0)
        close(capture->side_fds[index][1]);
    capture->side_fds[index][0] = -1;
    capture->side_fds[index][1] = -1;
    OPENSSL_cleanse(capture->bound_cookie[index],
                    sizeof(capture->bound_cookie[index]));
    capture->bound[index] = 0u;
}

/* Decode one complete client Message Channel response and validate correlation. */
static int expect_multitransport_response(rdp_transport* peer_transport,
                                          uint32_t request_id,
                                          uint32_t hresult)
{
    rdp_buffer packet;
    rdp_buffer plaintext;
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    rdp_multitransport_initiate_response response;
    const uint8_t* x224_payload = NULL;
    size_t x224_payload_len = 0u;
    uint16_t security_flags = 0u;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&plaintext);
    memset(&tpkt, 0, sizeof(tpkt));
    memset(&indication, 0, sizeof(indication));
    memset(&response, 0, sizeof(response));
    CHECK(rdp_transport_read_tpkt_timeout(peer_transport,
                                          &packet,
                                          1000) == LIBRDP_STATUS_OK);
    CHECK(rdp_tpkt_parse(packet.data, packet.length, &tpkt) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_x224_parse_data(tpkt.payload,
                              tpkt.payload_len,
                              &x224_payload,
                              &x224_payload_len) == LIBRDP_STATUS_OK);
    CHECK(rdp_mcs_parse_send_data_request(x224_payload,
                                          x224_payload_len,
                                          &indication) == LIBRDP_STATUS_OK);
    CHECK(rdp_security_unwrap_pdu(NULL,
                                  indication.payload,
                                  indication.payload_len,
                                  &plaintext,
                                  &security_flags) == LIBRDP_STATUS_OK);
    CHECK(security_flags == RDP_SEC_TRANSPORT_RSP);
    CHECK(rdp_multitransport_parse_initiate_response(
              plaintext.data,
              plaintext.length,
              &response) == LIBRDP_STATUS_OK);
    CHECK(response.request_id == request_id && response.hresult == hresult);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&packet);
    return 0;
}

/*
 * Drive the client Auto Detect state machine without transport I/O. Invalid
 * duplicate starts, mismatched sequences, incompatible stop types, and
 * response routing must not mutate the active measurement or result fields.
 */
int test_network_autodetect_client_state(void)
{
    librdp_session session;
    rdp_buffer packet;

    memset(&session, 0, sizeof(session));
    session.message_channel_id = 1006u;
    session.message_channel_joined = 1u;
    rdp_session_autodetect_reset(&session);
    rdp_buffer_init(&packet);

    CHECK(rdp_network_autodetect_write_bandwidth_start(
              &packet,
              10u,
              RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session.autodetect_measurement_active == 1u &&
          session.autodetect_measurement_sequence == 10u &&
          session.autodetect_measurement_type ==
              RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_PROTOCOL_ERROR);

    packet.length = 0u;
    CHECK(rdp_network_autodetect_write_bandwidth_payload(&packet,
                                                          10u,
                                                          "measure",
                                                          7u) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.length = 0u;
    CHECK(rdp_network_autodetect_write_bandwidth_stop(
              &packet,
              10u,
              RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME,
              NULL,
              0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_session_autodetect_reset(&session);
    packet.length = 0u;
    CHECK(rdp_network_autodetect_write_bandwidth_start(
              &packet,
              20u,
              RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    packet.length = 0u;
    CHECK(rdp_network_autodetect_write_bandwidth_payload(&packet,
                                                          21u,
                                                          "sample",
                                                          6u) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.data[2] = 20u;
    packet.data[3] = 0u;
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session.autodetect_measurement_bytes == 6u);

    packet.length = 0u;
    CHECK(rdp_network_autodetect_write_network_result(
              &packet,
              30u,
              RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL,
              11u,
              22000u,
              17u) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_RSP,
              packet.data,
              packet.length) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length) == LIBRDP_STATUS_OK);
    CHECK(session.autodetect_base_rtt_ms == 11u &&
          session.autodetect_bandwidth_kbps == 22000u &&
          session.autodetect_average_rtt_ms == 17u);

    CHECK(rdp_session_handle_autodetect_message(
              &session,
              RDP_SEC_AUTODETECT_REQ,
              packet.data,
              packet.length - 1u) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&packet);
    return 0;
}

/*
 * Exercise a real local Message Channel write after a server multitransport
 * bootstrap request. The client must return the matching failure response,
 * preserve TCP ownership, and leave every UDP runtime inactive.
 */
int test_multitransport_message_channel_fallback(void)
{
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
    int sockets[2] = {-1, -1};
    librdp_session session;
    rdp_transport peer_transport;
    rdp_buffer request;
    rdp_buffer packet;
    rdp_buffer plaintext;
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    rdp_multitransport_initiate_response response;
    const uint8_t* x224_payload = NULL;
    size_t x224_payload_len = 0u;
    uint16_t security_flags = 0u;
    size_t i = 0u;

    memset(&session, 0, sizeof(session));
    memset(&tpkt, 0, sizeof(tpkt));
    memset(&indication, 0, sizeof(indication));
    memset(&response, 0, sizeof(response));
    for (i = 0u; i < sizeof(cookie); i++)
        cookie[i] = (uint8_t)(0xa0u + i);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    rdp_transport_init(&session.transport);
    rdp_transport_init(&peer_transport);
    rdp_transport_attach_fd(&session.transport, sockets[0], 1);
    sockets[0] = -1;
    rdp_transport_attach_fd(&peer_transport, sockets[1], 1);
    sockets[1] = -1;
    session.mcs_user_id = 1003u;
    session.message_channel_id = 1006u;
    session.message_channel_joined = 1u;
    session.multitransport_negotiated = 1u;
    session.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR;
    rdp_buffer_init(&request);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&plaintext);

    CHECK(rdp_multitransport_write_initiate_request(
              &request,
              4u,
              RDP_MULTITRANSPORT_PROTOCOL_UDP_RELIABLE,
              cookie) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_message_channel(
              &session,
              RDP_SEC_TRANSPORT_REQ,
              request.data,
              request.length) == LIBRDP_STATUS_OK);
    CHECK(session.multitransport_udp_active == 0u &&
          session.multitransport_udp2_active == 0u);
    CHECK(rdp_transport_read_tpkt_timeout(&peer_transport,
                                          &packet,
                                          1000) == LIBRDP_STATUS_OK);
    CHECK(rdp_tpkt_parse(packet.data, packet.length, &tpkt) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_x224_parse_data(tpkt.payload,
                              tpkt.payload_len,
                              &x224_payload,
                              &x224_payload_len) == LIBRDP_STATUS_OK);
    CHECK(rdp_mcs_parse_send_data_request(x224_payload,
                                          x224_payload_len,
                                          &indication) == LIBRDP_STATUS_OK);
    CHECK(indication.initiator == session.mcs_user_id &&
          indication.channel_id == session.message_channel_id);
    CHECK(rdp_security_unwrap_pdu(NULL,
                                  indication.payload,
                                  indication.payload_len,
                                  &plaintext,
                                  &security_flags) == LIBRDP_STATUS_OK);
    CHECK(security_flags == RDP_SEC_TRANSPORT_RSP);
    CHECK(rdp_multitransport_parse_initiate_response(
              plaintext.data,
              plaintext.length,
              &response) == LIBRDP_STATUS_OK);
    CHECK(response.request_id == 4u &&
          response.hresult == RDP_MULTITRANSPORT_HRESULT_ABORT);

    request.data[6] = 1u;
    CHECK(rdp_session_handle_message_channel(
              &session,
              RDP_SEC_TRANSPORT_REQ,
              request.data,
              request.length) == LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[6] = 0u;
    CHECK(rdp_session_handle_message_channel(
              &session,
              (uint16_t)(RDP_SEC_TRANSPORT_REQ | RDP_SEC_AUTODETECT_REQ),
              request.data,
              request.length) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&request);
    rdp_transport_close(&peer_transport);
    rdp_transport_close(&session.transport);
    return 0;
}

/*
 * Exercise the public application-provider boundary for side-transport
 * bootstrap. Synchronous, asynchronous, rejected, expired, duplicate, and
 * reconnect-stale requests must produce exactly one correlated wire response
 * and release provider resources with the correct establishment state.
 */
int test_multitransport_provider_lifecycle(void)
{
    static const uint8_t side_payload[] = {'s', 'i', 'd', 'e'};
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
    uint8_t side_wire[256];
    uint8_t side_response[256];
    int sockets[2] = {-1, -1};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_multitransport_provider provider;
    multitransport_provider_capture capture;
    rdp_transport peer_transport;
    rdp_buffer request;
    struct timespec pause_time;
    uint64_t pending_token = 0u;
    size_t side_response_len = 0u;
    ssize_t side_wire_len = 0;
    size_t index = 0u;
    rdp_buffer side_datagram;

    memset(&provider, 0, sizeof(provider));
    memset(&capture, 0, sizeof(capture));
    memset(&pause_time, 0, sizeof(pause_time));
    memset(side_wire, 0, sizeof(side_wire));
    memset(side_response, 0, sizeof(side_response));
    capture.valid = 1;
    capture.side_fds[0][0] = -1;
    capture.side_fds[0][1] = -1;
    capture.side_fds[1][0] = -1;
    capture.side_fds[1][1] = -1;
    rdp_buffer_init(&side_datagram);
    for (index = 0u; index < sizeof(cookie); index++)
        cookie[index] = (uint8_t)(0x50u + index);
    CHECK(librdp_multitransport_provider_init(NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_multitransport_provider_init(&provider) ==
          LIBRDP_STATUS_OK);
    CHECK(provider.version == LIBRDP_MULTITRANSPORT_PROVIDER_VERSION &&
          provider.size == sizeof(provider) && provider.timeout_ms > 0u);
    provider.start = on_multitransport_start;
    provider.release = on_multitransport_release;
    provider.user_data = &capture;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_enable_feature(
              settings,
              LIBRDP_FEATURE_MULTITRANSPORT,
              1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(
              settings,
              LIBRDP_FEATURE_UDP_TRANSPORT,
              1) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    provider.release = NULL;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    provider.release = on_multitransport_release;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_OK);
    provider.version++;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    provider.version = LIBRDP_MULTITRANSPORT_PROVIDER_VERSION;
    provider.timeout_ms = 0u;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    provider.timeout_ms = 100u;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_OK);

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    rdp_transport_attach_fd(&session->transport, sockets[0], 1);
    sockets[0] = -1;
    rdp_transport_init(&peer_transport);
    rdp_transport_attach_fd(&peer_transport, sockets[1], 1);
    sockets[1] = -1;
    session->mcs_user_id = 1003u;
    session->message_channel_id = 1006u;
    session->message_channel_joined = 1u;
    session->multitransport_negotiated = 1u;
    session->multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                    RDP_GCC_MULTITRANSPORT_UDP_FECL;
    rdp_buffer_init(&request);

    capture.next_status = LIBRDP_STATUS_OK;
    CHECK(rdp_multitransport_write_initiate_request(
              &request,
              20u,
              RDP_MULTITRANSPORT_PROTOCOL_UDP_RELIABLE,
              cookie) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_message_channel(session,
                                              RDP_SEC_TRANSPORT_REQ,
                                              request.data,
                                              request.length) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.starts == 1u &&
          capture.request.protocol == LIBRDP_MULTITRANSPORT_UDP_RELIABLE &&
          capture.request.request_token != 0u &&
          CRYPTO_memcmp(capture.request.security_cookie,
                        cookie,
                        sizeof(cookie)) == 0);
    CHECK(expect_multitransport_response(
              &peer_transport,
              20u,
              RDP_MULTITRANSPORT_HRESULT_OK) == 0);
    CHECK(session->multitransport_slots[0].state ==
          RDP_SESSION_MULTITRANSPORT_SLOT_READY);
    CHECK(capture.bound[0] && capture.side_fds[0][0] >= 0 &&
          capture.side_fds[0][1] >= 0);
    CHECK(build_test_udp_data(&side_datagram,
                              1u,
                              4u,
                              side_payload,
                              sizeof(side_payload)) == LIBRDP_STATUS_OK);
    CHECK(send(capture.side_fds[0][0],
               side_datagram.data,
               side_datagram.length,
               0) == (ssize_t)side_datagram.length);
    side_wire_len = recv(capture.side_fds[0][1],
                         side_wire,
                         sizeof(side_wire),
                         0);
    CHECK(side_wire_len == (ssize_t)side_datagram.length);
    session->state = LIBRDP_SESSION_ACTIVE;
    session->multitransport_udp_reliable_selected = 1u;
    CHECK(librdp_session_process_udp_datagram(
              session,
              1,
              side_wire,
              (size_t)side_wire_len,
              side_response,
              sizeof(side_response),
              &side_response_len) == LIBRDP_STATUS_OK);
    CHECK(side_response_len > 0u);
    session->state = LIBRDP_SESSION_IDLE;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_STATE);
    CHECK(rdp_session_handle_message_channel(session,
                                              RDP_SEC_TRANSPORT_REQ,
                                              request.data,
                                              request.length) ==
          LIBRDP_STATUS_OK);
    CHECK(capture.starts == 1u);
    CHECK(expect_multitransport_response(
              &peer_transport,
              20u,
              RDP_MULTITRANSPORT_HRESULT_OK) == 0);
    rdp_session_multitransport_reset(session, 0);
    CHECK(capture.releases == 1u && capture.established_releases == 1u);

    session->multitransport_negotiated = 1u;
    session->multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                    RDP_GCC_MULTITRANSPORT_UDP_FECL;
    request.length = 0u;
    capture.next_status = LIBRDP_STATUS_AGAIN;
    CHECK(rdp_multitransport_write_initiate_request(
              &request,
              21u,
              RDP_MULTITRANSPORT_PROTOCOL_UDP_LOSSY,
              cookie) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_message_channel(session,
                                              RDP_SEC_TRANSPORT_REQ,
                                              request.data,
                                              request.length) ==
          LIBRDP_STATUS_OK);
    pending_token = capture.request.request_token;
    CHECK(session->multitransport_slots[1].state ==
          RDP_SESSION_MULTITRANSPORT_SLOT_PENDING);
    CHECK(librdp_session_complete_multitransport_request(
              session,
              pending_token + 1u,
              LIBRDP_STATUS_OK) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_complete_multitransport_request(
              session,
              pending_token,
              LIBRDP_STATUS_AGAIN) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(establish_test_side_transport(&capture, &capture.request) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_complete_multitransport_request(
              session,
              pending_token,
              LIBRDP_STATUS_OK) == LIBRDP_STATUS_OK);
    CHECK(expect_multitransport_response(
              &peer_transport,
              21u,
              RDP_MULTITRANSPORT_HRESULT_OK) == 0);
    CHECK(librdp_session_complete_multitransport_request(
              session,
              pending_token,
              LIBRDP_STATUS_OK) == LIBRDP_STATUS_STATE);
    rdp_session_multitransport_reset(session, 0);
    CHECK(capture.releases == 2u && capture.established_releases == 2u);

    provider.timeout_ms = 1u;
    CHECK(librdp_session_set_multitransport_provider(session, &provider) ==
          LIBRDP_STATUS_OK);
    session->multitransport_negotiated = 1u;
    session->multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR;
    request.length = 0u;
    CHECK(rdp_multitransport_write_initiate_request(
              &request,
              22u,
              RDP_MULTITRANSPORT_PROTOCOL_UDP_RELIABLE,
              cookie) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_message_channel(session,
                                              RDP_SEC_TRANSPORT_REQ,
                                              request.data,
                                              request.length) ==
          LIBRDP_STATUS_OK);
    pending_token = capture.request.request_token;
    pause_time.tv_nsec = 5000000l;
    CHECK(nanosleep(&pause_time, NULL) == 0);
    CHECK(rdp_session_multitransport_next_timeout_ms(session) == 0);
    CHECK(rdp_session_multitransport_check_timeout(session) ==
          LIBRDP_STATUS_OK);
    CHECK(expect_multitransport_response(
              &peer_transport,
              22u,
              RDP_MULTITRANSPORT_HRESULT_ABORT) == 0);
    CHECK(capture.releases == 3u && capture.established_releases == 2u);
    CHECK(librdp_session_complete_multitransport_request(
              session,
              pending_token,
              LIBRDP_STATUS_OK) == LIBRDP_STATUS_STATE);

    capture.next_status = LIBRDP_STATUS_UNSUPPORTED;
    session->multitransport_negotiated = 1u;
    session->multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR;
    request.length = 0u;
    CHECK(rdp_multitransport_write_initiate_request(
              &request,
              23u,
              RDP_MULTITRANSPORT_PROTOCOL_UDP_RELIABLE,
              cookie) == LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_message_channel(session,
                                              RDP_SEC_TRANSPORT_REQ,
                                              request.data,
                                              request.length) ==
          LIBRDP_STATUS_OK);
    CHECK(expect_multitransport_response(
              &peer_transport,
              23u,
              RDP_MULTITRANSPORT_HRESULT_ABORT) == 0);
    CHECK(capture.releases == 4u && capture.established_releases == 2u);
    CHECK(capture.valid);
    CHECK(capture.side_fds[0][0] < 0 && capture.side_fds[0][1] < 0 &&
          capture.side_fds[1][0] < 0 && capture.side_fds[1][1] < 0);
    CHECK(librdp_session_set_multitransport_provider(session, NULL) ==
          LIBRDP_STATUS_OK);

    OPENSSL_cleanse(&capture.request, sizeof(capture.request));
    rdp_buffer_free(&side_datagram);
    rdp_buffer_free(&request);
    rdp_transport_close(&peer_transport);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Separate application-owned static and dynamic traffic by the public channel
 * name. Exact payload checks ensure neither path exposes partial reassembly.
 */
static void on_unknown_channel_event(librdp_session* session,
                                     const librdp_event* event,
                                     void* user_data)
{
    unknown_channel_capture* capture =
        (unknown_channel_capture*)user_data;
    const char* name = NULL;
    size_t name_len = 0u;

    (void)session;
    if (!capture || !event)
        return;
    switch (event->type)
    {
        case LIBRDP_EVENT_CHANNEL_OPEN:
            name = event->data.channel_open.name;
            name_len = event->data.channel_open.name_len;
            if (name_len == 7u && name &&
                memcmp(name, "UNKSTAT", 7u) == 0)
            {
                capture->static_open++;
            }
            else if (name_len == 6u && name &&
                     memcmp(name, "APPDVC", 6u) == 0)
            {
                capture->dynamic_open++;
            }
            else
            {
                capture->valid = 0;
            }
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            name = event->data.channel_data.name;
            name_len = event->data.channel_data.name_len;
            if (name_len == 7u && name &&
                memcmp(name, "UNKSTAT", 7u) == 0)
            {
                capture->static_data++;
                if (event->data.channel_data.data_len != 8u ||
                    !event->data.channel_data.data ||
                    memcmp(event->data.channel_data.data,
                           "statchan",
                           8u) != 0)
                {
                    capture->valid = 0;
                }
            }
            else if (name_len == 6u && name &&
                     memcmp(name, "APPDVC", 6u) == 0)
            {
                capture->dynamic_data++;
                if (event->data.channel_data.data_len != 8u ||
                    !event->data.channel_data.data ||
                    memcmp(event->data.channel_data.data,
                           "abcdefgh",
                           8u) != 0)
                {
                    capture->valid = 0;
                }
            }
            else
            {
                capture->valid = 0;
            }
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            name = event->data.channel_close.name;
            name_len = event->data.channel_close.name_len;
            if (name_len == 6u && name &&
                memcmp(name, "APPDVC", 6u) == 0)
            {
                capture->dynamic_close++;
            }
            else
            {
                capture->valid = 0;
            }
            break;
        default:
            break;
    }
}

/*
 * Validate reassembled application payloads while preserving the shared event
 * counters used to observe channel create and close ordering.
 */
static void on_dvc_boundary_event(librdp_session* session,
                                  const librdp_event* event,
                                  void* user_data)
{
    dvc_boundary_capture* capture = (dvc_boundary_capture*)user_data;

    if (!capture)
        return;
    on_event(session, event, &capture->events);
    if (!event || event->type != LIBRDP_EVENT_CHANNEL_DATA)
        return;
    if (capture->message_count >= CORE_TEST_DVC_BOUNDARY_COUNT ||
        event->data.channel_data.channel_id != 7u ||
        event->data.channel_data.data_len !=
            core_test_dvc_boundary_sizes[capture->message_count])
    {
        capture->valid = 0;
        capture->message_count++;
        return;
    }
    for (size_t i = 0; i < event->data.channel_data.data_len; i++)
    {
        if (!event->data.channel_data.data ||
            event->data.channel_data.data[i] !=
                core_test_dvc_boundary_byte(capture->message_count, i))
        {
            capture->valid = 0;
            break;
        }
    }
    capture->message_count++;
}

/*
 * Coverage: validates static channel registration, activation-time channel
 * metadata, fragmented channel delivery, and deterministic fixture shutdown.
 * Bug classes: invalid channel names, clone ownership, stale channel state,
 * partial static-channel payloads, and peer teardown races after local close.
 */
int test_static_channels(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_session* session = NULL;
    librdp_static_channel_info info;
    librdp_static_channel_info infos[2];
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t count = 0;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    CHECK(librdp_static_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_static_channel_info_init(&info) == LIBRDP_STATUS_OK);
    CHECK(info.version == LIBRDP_STATIC_CHANNEL_INFO_VERSION);
    CHECK(info.size == sizeof(info));

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_add_static_channel(NULL,
                                             "STAT",
                                             LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "12345678", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "drdynvc", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_static_channel(settings, "STAT", 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_static_channel(settings, "stat", 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_count(NULL) == 0);
    CHECK(librdp_settings_static_channel_count(settings) == 1);
    CHECK(librdp_settings_static_channel_info(NULL, 0, &info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_info(settings, 1, &info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_static_channel_info(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_static_channel_info_init(&info) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_static_channel_info(settings, 0, &info) == LIBRDP_STATUS_OK);
    CHECK(info.channel_id == 0);
    CHECK(info.flags == LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS);
    CHECK(info.active == 0);
    CHECK(info.name_len == 4 && strcmp(info.name, "STAT") == 0);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(librdp_settings_static_channel_count(copy) == 1);
    librdp_settings_free(copy);
    copy = NULL;

    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_ex(&test_port, &server_pid, 0, 0, 1, 0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_static_channel_list(NULL, NULL, 0, &count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_list(session, NULL, 1, &count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_list(session, NULL, 0, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 0);
    CHECK(librdp_session_static_channel_send(session, "STAT", "pong", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(counter.last_channel_id == 1006);
    CHECK(librdp_session_static_channel_list(session, NULL, 0, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 1);
    CHECK(librdp_static_channel_info_init(&infos[0]) == LIBRDP_STATUS_OK);
    CHECK(librdp_static_channel_info_init(&infos[1]) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_static_channel_list(session, infos, 2, &count) == LIBRDP_STATUS_OK);
    CHECK(count == 1);
    CHECK(infos[0].channel_id == 1006);
    CHECK(infos[0].active == 1);
    CHECK(infos[0].flags == LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS);
    CHECK(infos[0].name_len == 4 && strcmp(infos[0].name, "STAT") == 0);
    CHECK(librdp_session_static_channel_send(session, NULL, "pong", 4) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_send(session, "STAT", NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_static_channel_send(session, "NOPE", "pong", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_static_channel_send(session, "STAT", "pong", 4) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 1);
    CHECK(counter.last_channel_id == 1006);
    CHECK(counter.last_channel_data_len == 8);
    CHECK(memcmp(counter.last_channel_data, "statchan", 8) == 0);
    for (i = 0; i < 4u; i++)
        (void)librdp_session_run_once(session, 100);
    librdp_session_free(session);
    session = NULL;
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: validates clipboard request correlation. A server may deliver
 * syntactically valid response PDUs after a local cancel or without a matching
 * request; those bytes must not become public clipboard events with zeroed
 * metadata.
 */
int test_clipboard_unmatched_responses(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_add_static_channel(settings, "STAT", 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       1,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       0,
                                       CLIPBOARD_SCENARIO_UNMATCHED_RESPONSES));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 10u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.clipboard_data == 0);
    CHECK(counter.clipboard_file_contents == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates dynamic-channel state rejects duplicate server-created
 * channel identifiers before overwriting the existing table entry. It catches
 * handle lifetime corruption and parser/state-machine drift.
 */
int test_dynamic_channel_duplicate_create(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DUPLICATE_CREATE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that closing a dynamic virtual channel while reassembly
 * is pending drops the partial payload, emits close, and does not expose stale
 * channel handles or data events.
 */
int test_dynamic_channel_close_pending_fragment(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t channel_count = 99u;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_CLOSE_PENDING_FRAGMENT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (size_t i = 0; i < 7u && counter.channel_close == 0; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);
    CHECK(counter.channel_close == 1);
    CHECK(counter.last_channel_id == 7);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: rejects zero-length DVC continuation fragments while a message is
 * pending. It catches stalled reassembly that would keep channel state alive
 * without advancing toward the declared message length.
 */
int test_dynamic_channel_empty_continuation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_EMPTY_CONTINUATION,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: rejects a new DVC DATA_FIRST while a previous fragmented message
 * is incomplete. It prevents out-of-order traffic from silently replacing the
 * pending payload and corrupting channel message boundaries.
 */
int test_dynamic_channel_nested_data_first(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NESTED_DATA_FIRST,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

static int run_dynamic_channel_protocol_error_scenario(int scenario)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       scenario,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 7u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 1);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: compressed DVC fragments must make forward progress after
 * decompression. It catches zero-output bulk segments that would otherwise
 * leave a fragmented message pending forever.
 */
int test_dynamic_channel_empty_compressed_fragments(void)
{
    if (run_dynamic_channel_protocol_error_scenario(DVC_SCENARIO_EMPTY_COMPRESSED_FIRST) != 0)
        return 1;
    return run_dynamic_channel_protocol_error_scenario(DVC_SCENARIO_EMPTY_COMPRESSED_CONTINUATION);
}

/*
 * Build a decrypted RDPEUDP DATA record with one source payload. The fixture
 * controls sequence and receive-window values while preserving the production
 * writer layout used by the transport parser.
 */
static librdp_status build_test_udp_data(rdp_buffer* datagram,
                                         uint32_t sequence,
                                         uint16_t receive_window,
                                         const void* data,
                                         size_t data_len)
{
    rdp_udp_fec_header header;
    rdp_udp_source_payload_header source;
    size_t payload_size = 8u + data_len;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!datagram || (!data && data_len > 0) ||
        payload_size > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    datagram->length = 0;
    memset(&header, 0, sizeof(header));
    memset(&source, 0, sizeof(source));
    header.source_ack = sequence;
    header.receive_window_size = receive_window;
    header.flags = RDP_UDP_FLAG_DATA;
    source.coded_sequence = sequence;
    source.source_start = sequence;
    status = rdp_udp_write_fec_header(datagram, &header);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_payload_prefix(
            datagram,
            (uint16_t)payload_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_source_payload_header(datagram, &source);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(datagram, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        datagram->length = 0;
    return status;
}

/*
 * Build a framed UDP2 DATA datagram for receive-window tests. Both buffers are
 * reusable and remain owned by the test.
 */
static librdp_status build_test_udp2_data(rdp_buffer* packet,
                                          rdp_buffer* wire,
                                          uint16_t sequence,
                                          const void* data,
                                          size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    packet->length = 0;
    wire->length = 0;
    status = rdp_udp2_write_data_packet(packet,
                                        4u,
                                        sequence,
                                        data,
                                        data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp2_wrap_packet(wire,
                                      packet->data,
                                      packet->length,
                                      RDP_UDP2_PACKET_TYPE_DATA);
    if (status != LIBRDP_STATUS_OK)
    {
        packet->length = 0;
        wire->length = 0;
    }
    return status;
}

/*
 * Coverage: validates that a DVC soft-sync tunnel request selects UDP only
 * when multitransport and UDP are explicitly requested. Independent reliable,
 * lossy, and UDP2 windows catch non-atomic retries, sequence wrap mistakes,
 * loss/reorder accounting, stale state after reconnect, and oversized gaps
 * that must force a bounded TCP fallback.
 */
int test_dynamic_channel_soft_sync_runtime(void)
{
    static const uint8_t payload[] = {'u', 'd', 'p'};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_multitransport_metrics metrics;
    rdp_buffer udp_datagram;
    rdp_buffer udp2_packet;
    rdp_buffer udp2_wire;
    rdp_udp_fec_header udp_response_header;
    rdp_udp_ack_vector udp_ack_vector;
    uint8_t response[256];
    size_t response_len = 0;
    uint32_t received = 0;
    uint32_t pending = 0;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    rdp_buffer_init(&udp_datagram);
    rdp_buffer_init(&udp2_packet);
    rdp_buffer_init(&udp2_wire);
    memset(&metrics, 0, sizeof(metrics));
    memset(&udp_response_header, 0, sizeof(udp_response_header));
    memset(&udp_ack_vector, 0, sizeof(udp_ack_vector));
    memset(response, 0, sizeof(response));
    CHECK(librdp_multitransport_metrics_init(NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_multitransport_metrics_init(&metrics) ==
          LIBRDP_STATUS_OK);
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_UDP_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_UDP2_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       2,
                                       DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_MULTITRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_UDP_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    CHECK(build_test_udp_data(&udp_datagram,
                              10u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              1u,
                                              &response_len) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(response_len > 1u);
    CHECK(librdp_session_get_multitransport_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.soft_syncs == 1u && metrics.udp_datagrams_in == 0u);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(response_len > 8u);

    CHECK(build_test_udp_data(&udp_datagram,
                              12u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_udp_parse_fec_header(response,
                                   response_len,
                                   &udp_response_header) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_udp_parse_ack_vector(response + 8u,
                                  response_len - 8u,
                                  &udp_ack_vector) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_udp_ack_vector_count(&udp_ack_vector,
                                   &received,
                                   &pending) ==
          LIBRDP_STATUS_OK);
    CHECK(received == 1u && pending == 1u);

    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(build_test_udp_data(&udp_datagram,
                              11u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);

    CHECK(build_test_udp_data(&udp_datagram,
                              30u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              0,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(build_test_udp_data(&udp_datagram,
                              33u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              0,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(build_test_udp_data(&udp_datagram,
                              32u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              0,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);

    CHECK(build_test_udp_data(&udp_datagram,
                              100u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_UNSUPPORTED);

    CHECK(build_test_udp2_data(&udp2_packet,
                               &udp2_wire,
                               7u,
                               payload,
                               sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               1u,
                                               &response_len) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(response_len > 1u);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(response_len > 0);
    CHECK(build_test_udp2_data(&udp2_packet,
                               &udp2_wire,
                               9u,
                               payload,
                               sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(build_test_udp2_data(&udp2_packet,
                               &udp2_wire,
                               8u,
                               payload,
                               sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(build_test_udp2_data(&udp2_packet,
                               &udp2_wire,
                               1000u,
                               payload,
                               sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_UNSUPPORTED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_UDP2_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    CHECK(librdp_multitransport_metrics_init(&metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_multitransport_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.soft_syncs == 1u);
    CHECK(metrics.udp_datagrams_in == 7u &&
          metrics.udp_datagrams_out == 7u);
    CHECK(metrics.udp_pending_packets == 1u);
    CHECK(metrics.udp_dropped_packets == 3u);
    CHECK(metrics.udp_reordered_packets == 3u);
    CHECK(metrics.udp_tcp_fallbacks == 1u);
    CHECK(metrics.udp2_datagrams_in == 3u &&
          metrics.udp2_datagrams_out == 3u);
    CHECK(metrics.udp2_ack_out == 2u &&
          metrics.udp2_ack_vector_out == 1u);
    CHECK(metrics.udp2_lost_packets == 1u);
    CHECK(metrics.udp2_reordered_packets == 1u);
    CHECK(metrics.udp2_tcp_fallbacks == 1u);

    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               response,
                                               sizeof(response),
                                               &response_len) ==
          LIBRDP_STATUS_STATE);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    status = LIBRDP_STATUS_OK;
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_multitransport_metrics_init(&metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_multitransport_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.soft_syncs == 1u && metrics.udp_datagrams_in == 0u &&
          metrics.udp2_datagrams_in == 0u);
    CHECK(build_test_udp_data(&udp_datagram,
                              500u,
                              4u,
                              payload,
                              sizeof(payload)) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp_datagram(session,
                                              1,
                                              udp_datagram.data,
                                              udp_datagram.length,
                                              response,
                                              sizeof(response),
                                              &response_len) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_multitransport_metrics_init(&metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_multitransport_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.soft_syncs == 0u && metrics.udp_datagrams_in == 0u &&
          metrics.udp2_datagrams_in == 0u);

    rdp_buffer_free(&udp_datagram);
    rdp_buffer_free(&udp2_wire);
    rdp_buffer_free(&udp2_packet);
    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates the MS-RDPEECO client behavior on an internal ECHO DVC.
 * The mock server sends an echo request and verifies that the client core,
 * not the viewer callback, returns the identical payload without exposing the
 * internal request as an application channel event.
 */
int test_echo_channel_auto_response(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_echo_stats echo_stats;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_ECHO_VALIDATE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK; i++)
    {
        status = librdp_session_run_once(session, 1000);
        if (status == LIBRDP_STATUS_OK)
        {
            CHECK(librdp_session_get_feature_status(session,
                                                    LIBRDP_FEATURE_ECHO,
                                                    &feature_status) == LIBRDP_STATUS_OK);
            if (feature_status.active)
                saw_active = 1;
            if (saw_active && !feature_status.active)
                break;
        }
    }
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(saw_active);
    CHECK(counter.channel_open == 0);
    CHECK(counter.channel_data == 0);
    CHECK(counter.channel_close == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.requests_received == 2);
    CHECK(echo_stats.responses_sent == 2);
    CHECK(echo_stats.pings_sent == 0);
    CHECK(echo_stats.ping_responses == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates client-originated Echo diagnostics without changing the
 * wire payload. The mock server repeats the first response, then applies a
 * different delay to a second response. The client emits one result per local
 * ping, treats the repeated payload as a server request, and records both RTT
 * samples and their jitter without exposing the internal DVC.
 */
int test_echo_channel_client_ping(void)
{
    static const uint8_t first_ping[] = {'p', 'i', 'n', 'g'};
    static const uint8_t second_ping[] = {'p', 'o', 'n', 'g'};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_echo_stats echo_stats;
    event_counter counter;
    uint16_t test_port = 0;
    uint64_t first_sequence = 0;
    uint64_t second_sequence = 0;
    uint64_t first_rtt_us = 0;
    uint64_t second_rtt_us = 0;
    uint64_t expected_jitter_us = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_ECHO_PING,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_echo_stats_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.pings_sent == 0 && echo_stats.pending_sequence == 0);
    CHECK(librdp_session_echo_send(session,
                                   first_ping,
                                   sizeof(first_ping),
                                   1000,
                                   &first_sequence) ==
          LIBRDP_STATUS_UNSUPPORTED);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && !saw_active; i++)
    {
        status = librdp_session_run_once(session, 1000);
        if (status == LIBRDP_STATUS_OK)
        {
            CHECK(librdp_session_get_feature_status(session,
                                                    LIBRDP_FEATURE_ECHO,
                                                    &feature_status) == LIBRDP_STATUS_OK);
            saw_active = feature_status.active ? 1 : 0;
        }
    }
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(saw_active);
    CHECK(librdp_session_echo_send(session,
                                   first_ping,
                                   sizeof(first_ping),
                                   1000,
                                   &first_sequence) ==
          LIBRDP_STATUS_OK);
    CHECK(first_sequence != 0);
    CHECK(librdp_session_echo_send(session,
                                   first_ping,
                                   sizeof(first_ping),
                                   1000,
                                   NULL) ==
          LIBRDP_STATUS_STATE);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && counter.echo_result == 0; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 1);
    CHECK(counter.echo_ok == 1 && counter.echo_timed_out == 0);
    CHECK(counter.echo_sequence == first_sequence);
    CHECK(counter.echo_rtt_us > 0);
    first_rtt_us = counter.echo_rtt_us;
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 1);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.requests_received == 1);
    CHECK(echo_stats.responses_sent == 1);
    CHECK(echo_stats.pings_sent == 1);
    CHECK(echo_stats.ping_responses == 1);

    CHECK(librdp_session_echo_send(session,
                                   second_ping,
                                   sizeof(second_ping),
                                   1000,
                                   &second_sequence) ==
          LIBRDP_STATUS_OK);
    CHECK(second_sequence == first_sequence + 1u);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && counter.echo_result < 2; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 2);
    CHECK(counter.echo_ok == 1 && counter.echo_timed_out == 0);
    CHECK(counter.echo_sequence == second_sequence);
    CHECK(counter.echo_rtt_us > 0);
    second_rtt_us = counter.echo_rtt_us;
    expected_jitter_us = first_rtt_us > second_rtt_us
                             ? first_rtt_us - second_rtt_us
                             : second_rtt_us - first_rtt_us;
    CHECK(expected_jitter_us > 0);
    CHECK(counter.channel_open == 0);
    CHECK(counter.channel_data == 0);
    CHECK(counter.channel_close == 0);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.pings_sent == 2);
    CHECK(echo_stats.ping_responses == 2);
    CHECK(echo_stats.requests_received == 1);
    CHECK(echo_stats.responses_sent == 1);
    CHECK(echo_stats.pending_sequence == 0);
    CHECK(echo_stats.pending_payload_len == 0);
    CHECK(echo_stats.last_sequence == second_sequence);
    CHECK(echo_stats.last_rtt_us == second_rtt_us);
    CHECK(echo_stats.min_rtt_us ==
          (first_rtt_us < second_rtt_us ? first_rtt_us : second_rtt_us));
    CHECK(echo_stats.max_rtt_us ==
          (first_rtt_us > second_rtt_us ? first_rtt_us : second_rtt_us));
    CHECK(echo_stats.jitter_us == expected_jitter_us);
    CHECK(echo_stats.bytes_sent >= sizeof(first_ping) + sizeof(second_ping));
    CHECK(echo_stats.bytes_received >= sizeof(first_ping) + sizeof(second_ping));
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(!feature_status.negotiated && !feature_status.active);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: verifies that a client-originated Echo diagnostic cannot remain
 * pending indefinitely when the server consumes the request but never replies.
 * The test also locks down the public payload limit path before the send code
 * copies user memory into the pending request buffer.
 */
int test_echo_channel_client_timeout(void)
{
    static const uint8_t ping[] = {'t', 'i', 'm', 'e'};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_echo_stats echo_stats;
    event_counter counter;
    uint16_t test_port = 0;
    uint64_t sequence = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_ECHO_TIMEOUT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && !saw_active; i++)
    {
        status = librdp_session_run_once(session, 1000);
        if (status == LIBRDP_STATUS_OK)
        {
            CHECK(librdp_session_get_feature_status(session,
                                                    LIBRDP_FEATURE_ECHO,
                                                    &feature_status) == LIBRDP_STATUS_OK);
            saw_active = feature_status.active ? 1 : 0;
        }
    }
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(saw_active);
    CHECK(librdp_session_echo_send(session,
                                   ping,
                                   (size_t)RDP_ECHO_CHANNEL_MAX_PAYLOAD + 1u,
                                   1000,
                                   NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_echo_send(session, ping, sizeof(ping), 20, &sequence) ==
          LIBRDP_STATUS_OK);
    CHECK(sequence != 0);
    for (i = 0; i < 16u && status == LIBRDP_STATUS_OK && counter.echo_result == 0; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 1);
    CHECK(counter.echo_ok == 0 && counter.echo_timed_out == 1);
    CHECK(counter.echo_sequence == sequence);
    CHECK(counter.echo_rtt_us == 0);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.pings_sent == 1);
    CHECK(echo_stats.ping_responses == 0);
    CHECK(echo_stats.timeouts == 1);
    CHECK(echo_stats.pending_sequence == 0);
    CHECK(echo_stats.pending_payload_len == 0);
    CHECK(echo_stats.last_sequence == sequence);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: verifies that a delayed Echo response is correlated with the
 * original request but still reported as timed out. This catches races where a
 * late diagnostic reply could resurrect a cleared request or skew RTT metrics.
 */
int test_echo_channel_client_late_response(void)
{
    static const uint8_t ping[] = {'l', 'a', 't', 'e'};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_echo_stats echo_stats;
    event_counter counter;
    uint16_t test_port = 0;
    uint64_t sequence = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_ECHO_LATE_RESPONSE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && !saw_active; i++)
    {
        status = librdp_session_run_once(session, 1000);
        if (status == LIBRDP_STATUS_OK)
        {
            CHECK(librdp_session_get_feature_status(session,
                                                    LIBRDP_FEATURE_ECHO,
                                                    &feature_status) == LIBRDP_STATUS_OK);
            saw_active = feature_status.active ? 1 : 0;
        }
    }
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(saw_active);
    CHECK(librdp_session_echo_send(session, ping, sizeof(ping), 50, &sequence) ==
          LIBRDP_STATUS_OK);
    CHECK(sequence != 0);
    test_sleep_ms(500u);
    for (i = 0; i < 16u && status == LIBRDP_STATUS_OK && counter.echo_result == 0; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 1);
    CHECK(counter.echo_ok == 0 && counter.echo_timed_out == 1);
    CHECK(counter.echo_sequence == sequence);
    CHECK(counter.echo_rtt_us == 0);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.pings_sent == 1);
    CHECK(echo_stats.ping_responses == 0);
    CHECK(echo_stats.timeouts == 0);
    CHECK(echo_stats.late_responses == 1);
    CHECK(echo_stats.pending_sequence == 0);
    CHECK(echo_stats.pending_payload_len == 0);
    CHECK(echo_stats.last_sequence == sequence);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that Display Control capability rejection of a pending
 * local monitor layout does not fail the RDP session. It catches resize paths
 * that treat server capability limits as fatal protocol errors.
 */
int test_display_control_caps_reject_pending_layout(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_display_monitor monitors[2];
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(monitors, 0, sizeof(monitors));
    monitors[0].flags = LIBRDP_DISPLAY_MONITOR_PRIMARY;
    monitors[0].width = 800;
    monitors[0].height = 600;
    monitors[0].physical_width = 210;
    monitors[0].physical_height = 158;
    monitors[0].desktop_scale_factor = 100;
    monitors[0].device_scale_factor = 100;
    monitors[1].left = 800;
    monitors[1].width = 640;
    monitors[1].height = 480;
    monitors[1].physical_width = 169;
    monitors[1].physical_height = 127;
    monitors[1].desktop_scale_factor = 100;
    monitors[1].device_scale_factor = 100;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_CAPS_REJECT_LAYOUT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_set_display_layout(session, monitors, 2) == LIBRDP_STATUS_OK);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that Display Control remains opt-in. A server-created
 * display-control DVC is rejected when the application did not call resize,
 * set_display_layout, or enable the public feature explicitly.
 */
int test_display_control_dvc_rejects_unrequested_feature(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int server_done = 0;
    struct timespec poll_delay;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_CREATE_REJECT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && !server_done; i++)
    {
        librdp_status run_status = librdp_session_run_once(session, 1000);
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
        {
            server_done = 1;
            break;
        }
        CHECK(run_status == LIBRDP_STATUS_OK || run_status == LIBRDP_STATUS_TIMEOUT ||
              run_status == LIBRDP_STATUS_CLOSED || run_status == LIBRDP_STATUS_STATE);
    }
    poll_delay.tv_sec = 0;
    poll_delay.tv_nsec = 100000000;
    for (i = 0; i < 20u && !server_done; i++)
    {
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
        else
            (void)nanosleep(&poll_delay, NULL);
    }
    CHECK(server_done);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DISPLAY_CONTROL,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(!feature_status.requested);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates the positive display-control path. A pending two-monitor
 * layout is sent after server capabilities arrive, and a later public resize
 * sends an immediate single-monitor layout while channel metrics advance.
 */
int test_display_control_accept_pending_and_resize(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_display_monitor monitors[2];
    librdp_metrics before_resize;
    librdp_metrics after_resize;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(monitors, 0, sizeof(monitors));
    monitors[0].flags = LIBRDP_DISPLAY_MONITOR_PRIMARY;
    monitors[0].width = 800;
    monitors[0].height = 600;
    monitors[0].physical_width = 210;
    monitors[0].physical_height = 158;
    monitors[0].desktop_scale_factor = 100;
    monitors[0].device_scale_factor = 100;
    monitors[1].left = 800;
    monitors[1].width = 640;
    monitors[1].height = 480;
    monitors[1].physical_width = 169;
    monitors[1].physical_height = 127;
    monitors[1].desktop_scale_factor = 100;
    monitors[1].device_scale_factor = 100;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_ACCEPT_LAYOUT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_set_display_layout(session, monitors, 2) == LIBRDP_STATUS_OK);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 6u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&before_resize) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &before_resize) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_resize(session, 1024, 768) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&after_resize) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after_resize) == LIBRDP_STATUS_OK);
    CHECK(after_resize.channel_out == before_resize.channel_out + 1u);
    CHECK(after_resize.channel_bytes_out == before_resize.channel_bytes_out + 58u);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

static int display_control_surface_matches_stage(
    const librdp_surface* surface,
    const core_test_display_resize_stage* stage)
{
    uint8_t actual_digest[EVP_MAX_MD_SIZE];
    uint8_t expected_digest[EVP_MAX_MD_SIZE];
    uint8_t* expected = NULL;
    const uint8_t* actual = NULL;
    size_t stride = 0u;
    size_t expected_size = 0u;
    size_t x = 0u;
    size_t y = 0u;
    unsigned int actual_digest_len = 0u;
    unsigned int expected_digest_len = 0u;
    int matches = 0;

    if (!surface || !stage ||
        librdp_surface_width(surface) != stage->width ||
        librdp_surface_height(surface) != stage->height)
        return 0;
    actual = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    if (!actual || stride < (size_t)stage->width * 4u ||
        stage->height > SIZE_MAX / stride)
        return 0;
    expected_size = stride * (size_t)stage->height;
    expected = (uint8_t*)calloc(1u, expected_size);
    if (!expected)
        return 0;
    for (y = 0u; y < stage->height; y++)
    {
        uint8_t* row = expected + y * stride;

        for (x = 0u; x < stage->width; x++)
        {
            row[x * 4u] = (uint8_t)stage->color;
            row[x * 4u + 1u] = (uint8_t)(stage->color >> 8u);
            row[x * 4u + 2u] = (uint8_t)(stage->color >> 16u);
            row[x * 4u + 3u] = 0xffu;
        }
    }
    if (EVP_Digest(actual,
                   expected_size,
                   actual_digest,
                   &actual_digest_len,
                   EVP_sha256(),
                   NULL) == 1 &&
        EVP_Digest(expected,
                   expected_size,
                   expected_digest,
                   &expected_digest_len,
                   EVP_sha256(),
                   NULL) == 1 &&
        actual_digest_len == expected_digest_len &&
        actual_digest_len != 0u &&
        CRYPTO_memcmp(actual_digest, expected_digest, actual_digest_len) == 0)
    {
        matches = 1;
    }
    free(expected);
    return matches;
}

/*
 * Coverage: drives grow, shrink, maximize-like, restore, and odd-sized Display
 * Control layouts through real reactivation epochs. Each stable frame must
 * replace every framebuffer byte, preventing stale geometry from passing on
 * callback counts alone.
 */
int test_display_control_resize_frame_stability(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_metrics metrics;
    graphics_update_capture graphics;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t stage_index = 0u;

    memset(&graphics, 0, sizeof(graphics));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 640u, 480u) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_RESIZE_STRESS,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_graphics_update_callback(session, on_graphics_update, &graphics);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_resize(session,
                                core_test_display_resize_stages[0].requested_width,
                                core_test_display_resize_stages[0].requested_height) == LIBRDP_STATUS_OK);

    for (stage_index = 0u;
         stage_index < CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT;
         stage_index++)
    {
        const core_test_display_resize_stage* stage =
            &core_test_display_resize_stages[stage_index];
        size_t attempt = 0u;
        int stable = 0;

        for (attempt = 0u; attempt < 24u && !stable; attempt++)
        {
            librdp_status status = librdp_session_run_once(session, 1000);

            CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
            stable = graphics.desktop_resize >= (int)(stage_index + 1u) &&
                     graphics.frame_end >= (int)(stage_index + 1u) &&
                     display_control_surface_matches_stage(
                         librdp_session_get_surface(session),
                         stage);
        }
        CHECK(stable);
        if (stage_index + 1u < CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT)
        {
            const core_test_display_resize_stage* next =
                &core_test_display_resize_stages[stage_index + 1u];

            CHECK(librdp_session_resize(session,
                                        next->requested_width,
                                        next->requested_height) == LIBRDP_STATUS_OK);
        }
    }

    CHECK(graphics.desktop_resize == (int)CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(graphics.frame_begin >= (int)CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(graphics.frame_end >= (int)CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(graphics.pixel_rect >= (int)CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(graphics.borrowed_pixels >= (int)CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(graphics.invalid == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DISPLAY_CONTROL,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.frames >= CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(metrics.surface_updates >= CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(metrics.channel_out >= CORE_TEST_DISPLAY_RESIZE_STAGE_COUNT);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: verifies every public monitor field reaches the Display Control
 * wire format unchanged for both multi-monitor and single-monitor layouts.
 */
static int test_display_control_monitor_fields(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    librdp_metrics before_layout;
    librdp_metrics after_layout;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t attempt = 0u;
    int first_layout_sent = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_LAYOUT_FIELDS,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&before_layout) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &before_layout) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_display_layout(session,
                                            core_test_display_layout_multi,
                                            2u) == LIBRDP_STATUS_OK);

    for (attempt = 0u; attempt < 8u && !first_layout_sent; attempt++)
    {
        librdp_status status = librdp_session_run_once(session, 1000);

        CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        CHECK(librdp_metrics_init(&after_layout) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_metrics(session, &after_layout) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_DISPLAY_CONTROL,
                                                &feature_status) == LIBRDP_STATUS_OK);
        first_layout_sent =
            feature_status.active &&
            after_layout.channel_out >= before_layout.channel_out + 2u;
    }
    CHECK(first_layout_sent);
    before_layout = after_layout;
    CHECK(librdp_session_set_display_layout(session,
                                            core_test_display_layout_single,
                                            1u) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&after_layout) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after_layout) == LIBRDP_STATUS_OK);
    CHECK(after_layout.channel_out == before_layout.channel_out + 1u);
    CHECK(feature_status.requested && feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: keeps an otherwise active server connection open without creating
 * Display Control. The public feature query must distinguish a pending request
 * from a negotiated runtime instead of reporting a false active capability.
 */
static int test_display_control_unavailable(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t attempt = 0u;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DISPLAY_CONTROL_UNAVAILABLE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_display_layout(session,
                                            core_test_display_layout_multi,
                                            2u) == LIBRDP_STATUS_OK);
    for (attempt = 0u; attempt < 5u; attempt++)
    {
        librdp_status status = librdp_session_run_once(session, 100);

        CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
    }
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DISPLAY_CONTROL,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

int test_display_control_monitor_fields_and_unavailable(void)
{
    if (test_display_control_monitor_fields() != 0)
        return 1;
    return test_display_control_unavailable();
}

/*
 * Coverage: validates that dynamic channel data cannot arrive before the
 * channel create handshake. It catches out-of-order DVC sequencing that would
 * otherwise hide malformed server traffic and lose channel metrics.
 */
int test_dynamic_channel_data_before_create(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_DATA_BEFORE_CREATE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 5u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(counter.channel_open == 0);
    CHECK(counter.channel_data == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: sends a large application DVC payload through the public handle
 * API and has the loopback peer verify DATA_FIRST/DATA framing, continuation
 * priority, payload order, close sequencing, and channel metrics.
 */
int test_dynamic_channel_public_fragment_send(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    librdp_channel_handle handle = 0;
    librdp_channel_send_options options;
    librdp_metrics before;
    librdp_metrics after_send;
    librdp_metrics after_close;
    uint8_t* payload = NULL;
    const size_t payload_len = 3600u;
    const size_t channel_id_bytes = 1u;
    size_t first_header = 0;
    size_t data_header = 0;
    size_t first_payload = 0;
    size_t continuation_payload = 0;
    size_t continuation_count = 0;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_CLIENT_FRAGMENT_SEND,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    payload = (uint8_t*)malloc(payload_len);
    CHECK(payload != NULL);
    for (i = 0; i < payload_len; i++)
        payload[i] = (uint8_t)(i & 0xffu);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && counter.channel_open == 0; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(counter.last_channel_id == 7);
    CHECK(librdp_session_channel_handle_for_id(session, 7, &handle) == LIBRDP_STATUS_OK);
    CHECK(handle != 0);
    CHECK(librdp_channel_send_options_init(&options) == LIBRDP_STATUS_OK);
    options.handle = handle;
    options.priority = LIBRDP_CHANNEL_PRIORITY_HIGH;
    CHECK(librdp_metrics_init(&before) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &before) == LIBRDP_STATUS_OK);

    CHECK(librdp_session_channel_send_ex(session, &options, payload, payload_len) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&after_send) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after_send) == LIBRDP_STATUS_OK);

    first_header = rdp_dynamic_channel_data_first_pdu_header_size((uint8_t)channel_id_bytes,
                                                                  (uint32_t)payload_len);
    data_header = rdp_dynamic_channel_data_pdu_header_size((uint8_t)channel_id_bytes);
    first_payload = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - first_header;
    continuation_payload = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - data_header;
    continuation_count = (payload_len - first_payload + continuation_payload - 1u) / continuation_payload;
    CHECK(after_send.channel_out == before.channel_out + 1u + continuation_count);
    CHECK(after_send.channel_bytes_out == before.channel_bytes_out + payload_len + first_header +
                                               (continuation_count * data_header));

    CHECK(librdp_session_channel_close_handle(session, handle) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&after_close) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after_close) == LIBRDP_STATUS_OK);
    CHECK(after_close.channel_out == after_send.channel_out + 1u);
    CHECK(after_close.channel_bytes_out == after_send.channel_bytes_out + data_header);
    CHECK(librdp_session_channel_list(session, NULL, 0, &i) == LIBRDP_STATUS_OK);
    CHECK(i == 0);

    free(payload);
    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: opens an application-owned DVC at every public priority, checks
 * provisional and active handle state, sends a wire-verified payload, closes
 * the handle and confirms immediate stale-handle invalidation.
 */
int test_dynamic_channel_public_open_priorities(void)
{
    static const char* const channel_names[] = {
        "prio.low",
        "prio.medium",
        "prio.high",
        "prio.realtime"
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_CLIENT_OPEN_PRIORITIES,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (size_t attempt = 0;
         attempt < 8u && librdp_session_get_state(session) != LIBRDP_SESSION_ACTIVE;
         attempt++)
    {
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    }
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);

    for (librdp_channel_priority priority = LIBRDP_CHANNEL_PRIORITY_LOW;
         priority <= LIBRDP_CHANNEL_PRIORITY_REALTIME;
         priority = (librdp_channel_priority)(priority + 1))
    {
        const uint8_t payload[] = {0xa5u, 0x5au, (uint8_t)priority, 0xc3u};
        librdp_channel_handle handle = 0;
        librdp_channel_info info;
        librdp_channel_send_options options;
        size_t channel_count = 0;
        int expected_open_count = counter.channel_open + 1;

        CHECK(librdp_session_channel_open(session,
                                          channel_names[priority],
                                          priority,
                                          &handle) == LIBRDP_STATUS_OK);
        CHECK(handle != 0);
        CHECK(librdp_channel_info_init(&info) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_channel_get_info(session, handle, &info) == LIBRDP_STATUS_OK);
        CHECK(!info.active);
        CHECK(info.application_owned);
        CHECK(info.priority == priority);
        CHECK(info.name_len == strlen(channel_names[priority]));
        CHECK(strcmp(info.name, channel_names[priority]) == 0);

        for (size_t attempt = 0; attempt < 8u && counter.channel_open < expected_open_count; attempt++)
            CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        CHECK(counter.channel_open == expected_open_count);
        CHECK(librdp_channel_info_init(&info) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_channel_get_info(session, handle, &info) == LIBRDP_STATUS_OK);
        CHECK(info.active);
        CHECK(info.application_owned);
        CHECK(info.priority == priority);
        CHECK(info.name_len == strlen(channel_names[priority]));
        CHECK(strcmp(info.name, channel_names[priority]) == 0);
        CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
        CHECK(channel_count == 1u);

        CHECK(librdp_channel_send_options_init(&options) == LIBRDP_STATUS_OK);
        options.handle = handle;
        options.priority = priority;
        CHECK(librdp_session_channel_send_ex(session,
                                             &options,
                                             payload,
                                             sizeof(payload)) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_channel_close_handle(session, handle) == LIBRDP_STATUS_OK);
        CHECK(librdp_channel_info_init(&info) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_channel_get_info(session, handle, &info) == LIBRDP_STATUS_STATE);
        CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
        CHECK(channel_count == 0u);
    }

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: exchanges logical DVC messages at each framing boundary in both
 * directions. The peer verifies DATA versus DATA_FIRST/DATA transitions while
 * the callback proves that inbound fragments are delivered once and atomically.
 */
int test_dynamic_channel_fragment_boundaries(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    dvc_boundary_capture capture;
    librdp_channel_handle handle = 0;
    librdp_channel_send_options options;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&capture, 0, sizeof(capture));
    capture.valid = 1;
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_FRAGMENT_BOUNDARIES,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_dvc_boundary_event, &capture);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (size_t attempt = 0; attempt < 8u && capture.events.channel_open == 0; attempt++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(capture.events.channel_open == 1);
    CHECK(capture.events.last_channel_id == 7u);
    CHECK(librdp_session_channel_handle_for_id(session, 7u, &handle) == LIBRDP_STATUS_OK);
    CHECK(handle != 0);
    CHECK(librdp_channel_send_options_init(&options) == LIBRDP_STATUS_OK);
    options.handle = handle;
    options.priority = LIBRDP_CHANNEL_PRIORITY_MEDIUM;

    for (size_t message_index = 0;
         message_index < CORE_TEST_DVC_BOUNDARY_COUNT;
         message_index++)
    {
        const size_t payload_len = core_test_dvc_boundary_sizes[message_index];
        uint8_t* payload = NULL;

        for (size_t attempt = 0;
             attempt < 128u && capture.message_count <= message_index;
             attempt++)
        {
            CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        }
        CHECK(capture.message_count == message_index + 1u);
        CHECK(capture.valid);
        if (payload_len > 0)
        {
            payload = (uint8_t*)malloc(payload_len);
            CHECK(payload != NULL);
            for (size_t i = 0; i < payload_len; i++)
                payload[i] = core_test_dvc_boundary_byte(message_index, i);
        }
        CHECK(librdp_session_channel_send_ex(session,
                                             &options,
                                             payload,
                                             payload_len) == LIBRDP_STATUS_OK);
        free(payload);
    }

    for (size_t attempt = 0; attempt < 8u && capture.events.channel_close == 0; attempt++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(capture.valid);
    CHECK(capture.message_count == CORE_TEST_DVC_BOUNDARY_COUNT);
    CHECK(capture.events.channel_data == (int)CORE_TEST_DVC_BOUNDARY_COUNT);
    CHECK(capture.events.channel_close == 1);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: drives unknown application-owned static and dynamic channels at
 * configured payload and channel-count limits. It catches accidental routing
 * into protocol runtimes, unbounded tables, partial callback payloads, and
 * stale channel state after disconnect.
 */
int test_unknown_channels_bounded(void)
{
    static const librdp_feature features[] = {
        LIBRDP_FEATURE_AUDIO_OUTPUT,
        LIBRDP_FEATURE_AUDIO_INPUT,
        LIBRDP_FEATURE_VIDEO,
        LIBRDP_FEATURE_CAMERA,
        LIBRDP_FEATURE_SMARTCARD,
        LIBRDP_FEATURE_USB,
        LIBRDP_FEATURE_PNP,
        LIBRDP_FEATURE_WEBAUTHN,
        LIBRDP_FEATURE_RAIL,
        LIBRDP_FEATURE_CR2,
        LIBRDP_FEATURE_ECHO,
        LIBRDP_FEATURE_TELEMETRY,
        LIBRDP_FEATURE_MULTITRANSPORT,
        LIBRDP_FEATURE_DESKTOP_COMPOSITION,
        LIBRDP_FEATURE_DISPLAY_CONTROL,
        LIBRDP_FEATURE_UDP_TRANSPORT,
        LIBRDP_FEATURE_UDP2_TRANSPORT,
        LIBRDP_FEATURE_GEOMETRY_TRACKING,
        LIBRDP_FEATURE_MULTIPARTY
    };
    static const uint8_t oversized_payload[9] = {0};
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_limits limits;
    librdp_metrics before;
    librdp_metrics after;
    librdp_feature_status feature_status;
    librdp_channel_handle dynamic_handle = 0u;
    unknown_channel_capture capture;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t dynamic_count = 0u;
    size_t static_count = 0u;

    memset(&capture, 0, sizeof(capture));
    capture.valid = 1;
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.channel_buffer_bytes = 8u;
    limits.dynamic_channel_count = 1u;
    limits.dynamic_channel_message_bytes = 8u;
    CHECK(librdp_settings_set_limits(settings, &limits) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_static_channel(
              settings,
              "UNKSTAT",
              LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(
              settings,
              LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_ex(&test_port,
                                    &server_pid,
                                    0,
                                    0,
                                    1,
                                    0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session,
                                      on_unknown_channel_event,
                                      &capture);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(capture.static_open == 1u);
    CHECK(librdp_session_static_channel_list(
              session,
              NULL,
              0u,
              &static_count) == LIBRDP_STATUS_OK);
    CHECK(static_count == 1u);
    for (size_t attempt = 0u;
         attempt < 16u && capture.dynamic_open == 0u;
         attempt++)
    {
        CHECK(librdp_session_run_once(session, 1000) ==
              LIBRDP_STATUS_OK);
    }
    CHECK(capture.dynamic_open == 1u);
    CHECK(librdp_session_channel_list(
              session,
              NULL,
              0u,
              &dynamic_count) == LIBRDP_STATUS_OK);
    CHECK(dynamic_count == 1u);
    CHECK(librdp_session_channel_handle_for_id(
              session,
              7u,
              &dynamic_handle) == LIBRDP_STATUS_OK);
    CHECK(dynamic_handle != 0u);
    CHECK(librdp_metrics_init(&before) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &before) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_static_channel_send(
              session,
              "UNKSTAT",
              oversized_payload,
              sizeof(oversized_payload)) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_session_channel_send(
              session,
              7u,
              oversized_payload,
              sizeof(oversized_payload)) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_metrics_init(&after) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after) == LIBRDP_STATUS_OK);
    CHECK(after.limits_rejected == before.limits_rejected + 2u);

    for (size_t attempt = 0u;
         attempt < 16u &&
         (capture.static_data == 0u ||
          capture.dynamic_data == 0u ||
          capture.dynamic_close == 0u);
         attempt++)
    {
        CHECK(librdp_session_run_once(session, 1000) ==
              LIBRDP_STATUS_OK);
    }
    CHECK(capture.valid);
    CHECK(capture.static_open == 1u);
    CHECK(capture.static_data == 1u);
    CHECK(capture.dynamic_open == 1u);
    CHECK(capture.dynamic_data == 1u);
    CHECK(capture.dynamic_close == 1u);
    CHECK(librdp_session_channel_list(
              session,
              NULL,
              0u,
              &dynamic_count) == LIBRDP_STATUS_OK);
    CHECK(dynamic_count == 0u);
    for (size_t i = 0u;
         i < sizeof(features) / sizeof(features[0]);
         i++)
    {
        CHECK(librdp_session_get_feature_status(
                  session,
                  features[i],
                  &feature_status) == LIBRDP_STATUS_OK);
        CHECK(!feature_status.requested);
        CHECK(!feature_status.negotiated);
        CHECK(!feature_status.active);
        CHECK(feature_status.reason ==
              LIBRDP_FEATURE_REASON_NOT_REQUESTED);
    }

    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_list(
              session,
              NULL,
              0u,
              &dynamic_count) == LIBRDP_STATUS_OK);
    CHECK(dynamic_count == 0u);
    CHECK(librdp_session_static_channel_list(
              session,
              NULL,
              0u,
              &static_count) == LIBRDP_STATUS_OK);
    CHECK(static_count == 0u);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: WebAuthn is an internal DVC and must drive the public feature
 * status from its own channel lifecycle, not from auth-redirection state or
 * public application-channel events.
 */
int test_webauthn_feature_status_channel_lifecycle(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int saw_active = 0;

    memset(&counter, 0, sizeof(counter));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/librdp-webauthn-test.cbor") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "example.test") == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_WEBAUTHN_CREATE_CLOSE,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_WEBAUTHN,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);

    for (i = 0; i < 8u && !saw_active; i++)
    {
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_WEBAUTHN,
                                                &feature_status) == LIBRDP_STATUS_OK);
        if (feature_status.active)
            saw_active = 1;
    }
    CHECK(saw_active);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(counter.channel_open == 0);

    for (; i < 10u && feature_status.negotiated; i++)
    {
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_WEBAUTHN,
                                                &feature_status) == LIBRDP_STATUS_OK);
    }
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(counter.channel_close == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that optional DVC runtime channels are not accepted just
 * because the server requests them. It catches false feature activation when the
 * application did not request WebAuthn or provide a backend/provider.
 */
int test_webauthn_dvc_rejects_unrequested_feature(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int server_done = 0;
    struct timespec poll_delay;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_WEBAUTHN_CREATE_REJECT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && !server_done; i++)
    {
        librdp_status run_status = librdp_session_run_once(session, 1000);
        pid_t waited = 0;

        waited = waitpid(server_pid, &child_status, WNOHANG);
        CHECK(waited >= 0);
        if (waited == server_pid)
        {
            server_done = 1;
            break;
        }
        CHECK(run_status == LIBRDP_STATUS_OK || run_status == LIBRDP_STATUS_TIMEOUT ||
              run_status == LIBRDP_STATUS_CLOSED || run_status == LIBRDP_STATUS_STATE);
    }
    poll_delay.tv_sec = 0;
    poll_delay.tv_nsec = 100000000;
    for (i = 0; i < 20u && !server_done; i++)
    {
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
        else
            (void)nanosleep(&poll_delay, NULL);
    }
    CHECK(server_done);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_WEBAUTHN,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(!feature_status.requested);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: WebAuthn RP ID allowlists must be enforced before mock or native
 * providers receive authenticator requests. The loopback peer sends a blocked
 * RP ID and verifies that the client returns an operation-denied CTAP status.
 */
int test_webauthn_rp_id_allowlist_denies_unmatched_request(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int server_done = 0;
    struct timespec poll_delay;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "allowed.example") == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_WEBAUTHN_RP_ID_DENIED,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && !server_done; i++)
    {
        librdp_status run_status = librdp_session_run_once(session, 1000);
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
        {
            server_done = 1;
            break;
        }
        CHECK(run_status == LIBRDP_STATUS_OK || run_status == LIBRDP_STATUS_TIMEOUT ||
              run_status == LIBRDP_STATUS_CLOSED || run_status == LIBRDP_STATUS_STATE);
    }
    poll_delay.tv_sec = 0;
    poll_delay.tv_nsec = 100000000;
    for (i = 0; i < 20u && !server_done; i++)
    {
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
        else
            (void)nanosleep(&poll_delay, NULL);
    }
    CHECK(server_done);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: a controlled mock authenticator completes the WebAuthn DVC
 * discovery, registration, assertion, cancellation and credential-list
 * sequence. Synthetic canaries make trace redaction externally verifiable
 * without using a physical authenticator or user data.
 */
int test_webauthn_mock_runtime_sequence(void)
{
    static const uint8_t authenticator_canary[] =
        CORE_TEST_WEBAUTHN_AUTHENTICATOR_CANARY;
    uint8_t mock_response[5u + sizeof(authenticator_canary) - 1u];
    char mock_path[] = "/tmp/librdp-webauthn-smoke-XXXXXX";
    char provider[sizeof(mock_path) + 5u];
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    FILE* mock_file = NULL;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int mock_fd = -1;
    int child_status = 0;
    int server_done = 0;
    int saw_active = 0;
    struct timespec poll_delay;
    size_t i = 0u;

    CHECK(sizeof(authenticator_canary) - 1u <= UINT8_MAX);
    mock_response[0] = 0u;
    mock_response[1] = 0xa1u;
    mock_response[2] = 0x01u;
    mock_response[3] = 0x58u;
    mock_response[4] = (uint8_t)(sizeof(authenticator_canary) - 1u);
    memcpy(mock_response + 5u,
           authenticator_canary,
           sizeof(authenticator_canary) - 1u);

    mock_fd = mkstemp(mock_path);
    CHECK(mock_fd >= 0);
    mock_file = fdopen(mock_fd, "wb");
    CHECK(mock_file != NULL);
    CHECK(fwrite(mock_response, 1u, sizeof(mock_response), mock_file) ==
          sizeof(mock_response));
    CHECK(fclose(mock_file) == 0);
    mock_file = NULL;
    CHECK(snprintf(provider, sizeof(provider), "mock=%s", mock_path) > 0);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings,
                                            LIBRDP_SECURITY_STANDARD) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings,
                                         LIBRDP_FEATURE_WEBAUTHN,
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, provider) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "example.test") ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_WEBAUTHN_MOCK_RUNTIME,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0u; i < 40u && !server_done; i++)
    {
        librdp_status run_status = librdp_session_run_once(session, 1000);
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(run_status == LIBRDP_STATUS_OK ||
              run_status == LIBRDP_STATUS_TIMEOUT ||
              run_status == LIBRDP_STATUS_CLOSED ||
              run_status == LIBRDP_STATUS_STATE);
        CHECK(librdp_session_get_feature_status(session,
                                                LIBRDP_FEATURE_WEBAUTHN,
                                                &feature_status) ==
              LIBRDP_STATUS_OK);
        if (feature_status.negotiated && feature_status.active)
            saw_active = 1;
        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
    }
    poll_delay.tv_sec = 0;
    poll_delay.tv_nsec = 100000000L;
    for (i = 0u; i < 20u && !server_done; i++)
    {
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
        else
            (void)nanosleep(&poll_delay, NULL);
    }
    CHECK(server_done);
    CHECK(saw_active);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(unlink(mock_path) == 0);
    return 0;
}

/*
 * Coverage: authentication redirection carries sensitive credential material
 * and is valid only after CredSSP security is established. A server-created
 * AuthRedirection DVC in a standard-security session must be rejected before a
 * channel entry or public event can appear.
 */
int test_auth_redirection_dvc_requires_credssp(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
    int server_done = 0;
    struct timespec poll_delay;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_AUTH_REDIRECTION_CREATE_REJECT,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && !server_done; i++)
    {
        librdp_status run_status = librdp_session_run_once(session, 1000);
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
        {
            server_done = 1;
            break;
        }
        CHECK(run_status == LIBRDP_STATUS_OK || run_status == LIBRDP_STATUS_TIMEOUT ||
              run_status == LIBRDP_STATUS_CLOSED || run_status == LIBRDP_STATUS_STATE);
    }
    poll_delay.tv_sec = 0;
    poll_delay.tv_nsec = 100000000;
    for (i = 0; i < 20u && !server_done; i++)
    {
        pid_t waited = waitpid(server_pid, &child_status, WNOHANG);

        CHECK(waited >= 0);
        if (waited == server_pid)
            server_done = 1;
        else
            (void)nanosleep(&poll_delay, NULL);
    }
    CHECK(server_done);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: stages server-directed targets, routing tokens, credential
 * overrides, informational responses, malformed address lists, and the finite
 * redirect bound without opening a network connection.
 * Bug classes: partial state commit, stale sensitive fields, malformed
 * UTF-16LE, redirect loops, and missing limit accounting.
 */
int test_server_redirection_state(void)
{
    static const uint8_t routing_token[] = {
        'r', 'o', 'u', 't', 'e', '=', 'a', '\r', '\n'
    };
    static const uint8_t username_utf16[] = {
        'u', 0, 's', 0, 'e', 0, 'r', 0, 0, 0
    };
    static const uint8_t password_utf16[] = {
        's', 0, 'e', 0, 'c', 0, 'r', 0, 'e', 0, 't', 0, 0, 0
    };
    static const uint8_t domain_utf16[] = {
        'T', 0, 'E', 0, 'S', 0, 'T', 0, 0, 0
    };
    static const uint8_t malformed_addresses[] = {
        1, 0, 0, 0,
        6, 0, 0, 0,
        '1', 0, '2', 0, 0, 1
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_server_redirection_packet packet;
    rdp_server_redirection_packet informational;
    rdp_server_redirection_packet malformed;
    librdp_metrics metrics;
    size_t routing_len = 0u;
    const uint8_t* routing = NULL;
    int reconnect = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "redirect.test") ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    memset(&informational, 0, sizeof(informational));
    informational.redirection_flags =
        RDP_SERVER_REDIRECTION_LB_NO_REDIRECT;
    informational.session_id = 7u;
    reconnect = 1;
    CHECK(rdp_session_redirection_stage(session,
                                        &informational,
                                        &reconnect) ==
          LIBRDP_STATUS_OK);
    CHECK(reconnect == 0);
    CHECK(rdp_session_redirection_active(session) == 0u);

    memset(&packet, 0, sizeof(packet));
    packet.session_id = 0x10203040u;
    packet.redirection_flags =
        RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO |
        RDP_SERVER_REDIRECTION_LB_USERNAME |
        RDP_SERVER_REDIRECTION_LB_PASSWORD |
        RDP_SERVER_REDIRECTION_LB_DOMAIN;
    packet.load_balance_info.data = routing_token;
    packet.load_balance_info.length = (uint32_t)sizeof(routing_token);
    packet.username.data = username_utf16;
    packet.username.length = (uint32_t)sizeof(username_utf16);
    packet.password.data = password_utf16;
    packet.password.length = (uint32_t)sizeof(password_utf16);
    packet.domain.data = domain_utf16;
    packet.domain.length = (uint32_t)sizeof(domain_utf16);
    CHECK(rdp_session_redirection_stage(session, &packet, &reconnect) ==
          LIBRDP_STATUS_OK);
    CHECK(reconnect == 1);
    CHECK(rdp_session_redirection_active(session) == 1u);
    CHECK(strcmp(rdp_session_redirection_target(session),
                 "redirect.test") == 0);
    routing = (const uint8_t*)rdp_session_redirection_routing_data(
        session,
        &routing_len);
    CHECK(routing_len == sizeof(routing_token));
    CHECK(routing != NULL &&
          memcmp(routing, routing_token, sizeof(routing_token)) == 0);
    CHECK(rdp_session_redirection_session_id(session) == 0x10203040u);
    CHECK(session->redirection.credentials.username != NULL &&
          strcmp(session->redirection.credentials.username, "user") == 0);
    CHECK(session->redirection.credentials.password != NULL &&
          strcmp(session->redirection.credentials.password, "secret") == 0);
    CHECK(session->redirection.credentials.domain != NULL &&
          strcmp(session->redirection.credentials.domain, "TEST") == 0);

    memset(&malformed, 0, sizeof(malformed));
    malformed.redirection_flags =
        RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES;
    malformed.target_net_addresses.data = malformed_addresses;
    malformed.target_net_addresses.length =
        (uint32_t)sizeof(malformed_addresses);
    reconnect = 0;
    CHECK(rdp_session_redirection_stage(session, &malformed, &reconnect) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(reconnect == 0);
    CHECK(strcmp(rdp_session_redirection_target(session),
                 "redirect.test") == 0);
    CHECK(rdp_session_redirection_session_id(session) == 0x10203040u);

    for (unsigned int hop = 1u; hop < 8u; hop++)
    {
        CHECK(rdp_session_redirection_stage(session, &packet, &reconnect) ==
              LIBRDP_STATUS_OK);
        CHECK(reconnect == 1);
    }
    CHECK(session->redirection.hop_count == 8u);
    CHECK(rdp_session_redirection_stage(session, &packet, &reconnect) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(reconnect == 0);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 1u);

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}
