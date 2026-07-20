/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client licensing tests.
 * Coverage: pre-activation licensing state transitions.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

typedef struct licensing_trace_capture
{
    unsigned request;
    unsigned client_request;
    unsigned challenge;
    unsigned challenge_response;
    unsigned new_or_upgrade;
    unsigned error_alert;
    unsigned failed;
} licensing_trace_capture;

static void on_licensing_trace(librdp_session* session,
                               const librdp_trace_record* record,
                               void* user_data)
{
    licensing_trace_capture* capture = (licensing_trace_capture*)user_data;

    (void)session;
    if (!record || !record->event || !record->message || !capture)
        return;
    if (strcmp(record->event, "rdp.licensing.request") == 0)
        capture->request++;
    else if (strcmp(record->event, "rdp.licensing.new_license_request") == 0)
        capture->client_request++;
    else if (strcmp(record->event, "rdp.licensing.platform_challenge") == 0)
        capture->challenge++;
    else if (strcmp(record->event, "rdp.licensing.platform_challenge_response") == 0)
        capture->challenge_response++;
    else if (strcmp(record->event, "rdp.licensing.new_or_upgrade") == 0)
        capture->new_or_upgrade++;
    else if (strcmp(record->event, "rdp.licensing.error_alert") == 0)
        capture->error_alert++;
    else if (strcmp(record->event, "rdp.licensing.failed") == 0)
        capture->failed++;
}

static int configure_licensing_trace(librdp_session* session,
                                     licensing_trace_capture* capture,
                                     const char* trace_id)
{
    librdp_trace_policy policy;

    if (!session || !capture || !trace_id ||
        librdp_trace_policy_init(&policy) != LIBRDP_STATUS_OK)
        return 0;
    policy.categories = LIBRDP_TRACE_CATEGORY_PROTOCOL;
    policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    policy.callback = on_licensing_trace;
    policy.callback_user_data = capture;
    policy.trace_id = trace_id;
    return librdp_session_set_trace_policy(session, &policy) == LIBRDP_STATUS_OK;
}

static int drive_licensing_activation(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return 0;
    for (i = 0; i < 12u &&
                librdp_session_get_state(session) != LIBRDP_SESSION_ACTIVE;
         i++)
    {
        if (librdp_session_run_once(session, 1000) != LIBRDP_STATUS_OK)
            return 0;
    }
    return librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE;
}

static int drain_licensing_updates(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return 0;
    for (i = 0; i < 6u; i++)
    {
        if (librdp_session_run_once(session, 1000) != LIBRDP_STATUS_OK)
            return 0;
    }
    return 1;
}

/*
 * Coverage: validates that terminal licensing PDUs can appear before Demand
 * Active without being misclassified as malformed slow-path share traffic. It
 * catches licensing/lifecycle ordering regressions while keeping the fixture
 * deterministic and credential-free.
 */
int test_licensing_new_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

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
                                       DVC_SCENARIO_NORMAL,
                                       1,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that the server-side STATUS_VALID_CLIENT error alert is
 * a successful terminal licensing message, not a fatal handshake failure. This
 * catches Standard Security interop regressions before the Demand Active PDU.
 */
int test_licensing_valid_client_alert_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

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
                                       DVC_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_VALID_CLIENT_ALERT,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that a legacy License Request produces a client new
 * license request, accepts a valid-client alert, and continues activation.
 */
int test_licensing_request_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;

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
                                       DVC_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_REQUEST,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: performs a complete request, RSA premaster exchange, platform
 * challenge/response and terminal license sequence over loopback. The peer
 * verifies both encrypted response blobs and the licensing MAC.
 */
int test_licensing_challenge_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    licensing_trace_capture trace;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&trace, 0, sizeof(trace));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_CHALLENGE,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(configure_licensing_trace(session, &trace, "license-challenge"));

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(drive_licensing_activation(session));
    CHECK(drain_licensing_updates(session));
    CHECK(trace.request == 1);
    CHECK(trace.client_request == 1);
    CHECK(trace.challenge == 1);
    CHECK(trace.challenge_response == 1);
    CHECK(trace.new_or_upgrade == 1);
    CHECK(trace.error_alert == 0);
    CHECK(trace.failed == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: repeats the licensing request path after a public reconnect and
 * verifies that transient licensing state and keys are rebuilt per connection.
 */
int test_licensing_reconnect(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_reconnect_policy policy;
    librdp_metrics metrics;
    licensing_trace_capture trace;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&trace, 0, sizeof(trace));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       2,
                                       DVC_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_REQUEST,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(configure_licensing_trace(session, &trace, "license-reconnect"));

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(drive_licensing_activation(session));
    CHECK(drain_licensing_updates(session));
    CHECK(librdp_reconnect_policy_init(&policy) == LIBRDP_STATUS_OK);
    policy.max_attempts = 1;
    policy.initial_delay_ms = 0;
    policy.max_delay_ms = 0;
    CHECK(librdp_session_reconnect(session, &policy) == LIBRDP_STATUS_OK);
    CHECK(drive_licensing_activation(session));
    CHECK(drain_licensing_updates(session));
    CHECK(trace.request == 2);
    CHECK(trace.client_request == 2);
    CHECK(trace.failed == 0);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.reconnects == 1);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: sends a terminal server licensing rejection and verifies precise
 * protocol attribution, trace correlation and terminal client state.
 */
int test_licensing_error_alert(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_error_info error;
    licensing_trace_capture trace;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&trace, 0, sizeof(trace));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       0,
                                       0,
                                       1,
                                       DVC_SCENARIO_NORMAL,
                                       LICENSE_SCENARIO_ERROR_ALERT,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(configure_licensing_trace(session, &trace, "license-rejected"));

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(trace.error_alert == 1);
    CHECK(trace.failed == 1);
    CHECK(librdp_error_info_init(&error) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error) ==
          LIBRDP_STATUS_OK);
    CHECK(error.status == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(error.os_errno == 0);
    CHECK(error.component == LIBRDP_ERROR_COMPONENT_PROTOCOL);
    CHECK(error.phase != NULL &&
          strcmp(error.phase, "rdp.licensing.error_alert") == 0);
    CHECK(error.message != NULL && strstr(error.message, "licensing") != NULL);
    CHECK(error.trace_id != NULL &&
          strcmp(error.trace_id, "license-rejected") == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}
