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
 * Coverage: validates that a DVC soft-sync tunnel request selects UDP only
 * when multitransport and UDP are explicitly requested. It also exercises the
 * app-owned UDP2 datagram path so feature status reflects real runtime wiring,
 * not packet helpers alone.
 */
int test_dynamic_channel_soft_sync_runtime(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    rdp_buffer udp2_packet;
    rdp_buffer udp2_wire;
    uint8_t udp2_response[64];
    size_t udp2_response_len = 0;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    rdp_buffer_init(&udp2_packet);
    rdp_buffer_init(&udp2_wire);
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
                                       1,
                                       DVC_SCENARIO_SOFT_SYNC_TUNNEL_REQUEST,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 4u && status == LIBRDP_STATUS_OK; i++)
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

    CHECK(rdp_udp2_write_data_packet(&udp2_packet, 4u, 7u, "abc", 3u) == LIBRDP_STATUS_OK);
    CHECK(rdp_udp2_wrap_packet(&udp2_wire,
                               udp2_packet.data,
                               udp2_packet.length,
                               RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_process_udp2_datagram(session,
                                               udp2_wire.data,
                                               udp2_wire.length,
                                               udp2_response,
                                               sizeof(udp2_response),
                                               &udp2_response_len) == LIBRDP_STATUS_OK);
    CHECK(udp2_response_len > 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_UDP2_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

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

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates client-originated Echo diagnostics without changing the
 * wire payload. The mock server echoes the payload byte-for-byte; the client
 * correlates it with the pending request, emits a result event, and updates
 * public Echo statistics instead of exposing the internal DVC as an app channel.
 */
int test_echo_channel_client_ping(void)
{
    static const uint8_t ping[] = {'p', 'i', 'n', 'g'};
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
    CHECK(librdp_session_echo_send(session, ping, sizeof(ping), 1000, &sequence) ==
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
    CHECK(librdp_session_echo_send(session, ping, sizeof(ping), 1000, &sequence) ==
          LIBRDP_STATUS_OK);
    CHECK(sequence != 0);
    CHECK(librdp_session_echo_send(session, ping, sizeof(ping), 1000, NULL) ==
          LIBRDP_STATUS_STATE);
    for (i = 0; i < 8u && status == LIBRDP_STATUS_OK && counter.echo_result == 0; i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(counter.echo_result == 1);
    CHECK(counter.echo_ok == 1 && counter.echo_timed_out == 0);
    CHECK(counter.echo_sequence == sequence);
    CHECK(counter.echo_rtt_us > 0);
    CHECK(counter.channel_open == 0);
    CHECK(counter.channel_data == 0);
    CHECK(counter.channel_close == 0);
    CHECK(librdp_echo_stats_init(&echo_stats) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_echo_stats(session, &echo_stats) == LIBRDP_STATUS_OK);
    CHECK(echo_stats.pings_sent == 1);
    CHECK(echo_stats.ping_responses == 1);
    CHECK(echo_stats.pending_sequence == 0);
    CHECK(echo_stats.pending_payload_len == 0);
    CHECK(echo_stats.last_sequence == sequence);
    CHECK(echo_stats.last_rtt_us > 0);
    CHECK(echo_stats.min_rtt_us > 0);
    CHECK(echo_stats.max_rtt_us >= echo_stats.min_rtt_us);
    CHECK(echo_stats.bytes_sent >= sizeof(ping));
    CHECK(echo_stats.bytes_received >= sizeof(ping));

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
