/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client feature tests.
 * Coverage: requested, built, backend, negotiated, and active state.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

static int core_test_feature_reason_is_current(const librdp_feature_status* status)
{
    return status &&
           status->reason >= LIBRDP_FEATURE_REASON_NONE &&
           status->reason <= LIBRDP_FEATURE_REASON_NOT_ACTIVE;
}

/*
 * Coverage: drives optional feature runtimes through the session dispatcher
 * instead of accepting settings-level readiness. It catches regressions where a
 * protocol can be parsed but no channel, order, or transport path makes it
 * negotiated and active.
 */
static int run_optional_feature_runtime_scenario(librdp_feature feature,
                                                 int extra_static_channel,
                                                 int dynamic_channel_scenario,
                                                 int gdi_scenario)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status feature_status;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    int active = 0;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, feature, 1) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_full(&test_port,
                                      &server_pid,
                                      0,
                                      0,
                                      extra_static_channel,
                                      0,
                                      1,
                                      dynamic_channel_scenario,
                                      gdi_scenario,
                                      0,
                                      CLIPBOARD_SCENARIO_NONE,
                                      HANDSHAKE_SCENARIO_NORMAL));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u && !active; i++)
    {
        status = librdp_session_run_once(session, 1000);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_CLOSED)
            break;
        CHECK(librdp_session_get_feature_status(session, feature, &feature_status) == LIBRDP_STATUS_OK);
        active = feature_status.active != 0;
    }
    CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_CLOSED);
    CHECK(librdp_session_get_feature_status(session, feature, &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.negotiated && feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    for (i = 0; i < 4u && status == LIBRDP_STATUS_OK; i++)
    {
        status = librdp_session_run_once(session, 100);
        CHECK(status == LIBRDP_STATUS_OK ||
              status == LIBRDP_STATUS_TIMEOUT ||
              status == LIBRDP_STATUS_CLOSED);
    }

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

int test_optional_feature_runtime_paths(void)
{
    CHECK(run_optional_feature_runtime_scenario(LIBRDP_FEATURE_TELEMETRY,
                                                0,
                                                DVC_SCENARIO_TELEMETRY_RUNTIME,
                                                GDI_SCENARIO_NORMAL) == 0);
    CHECK(run_optional_feature_runtime_scenario(LIBRDP_FEATURE_MULTIPARTY,
                                                1,
                                                DVC_SCENARIO_MULTIPARTY_RUNTIME,
                                                GDI_SCENARIO_NORMAL) == 0);
    CHECK(run_optional_feature_runtime_scenario(LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                                0,
                                                DVC_SCENARIO_NORMAL,
                                                GDI_SCENARIO_DESKTOP_COMPOSITION) == 0);
    CHECK(run_optional_feature_runtime_scenario(LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                                0,
                                                DVC_SCENARIO_GEOMETRY_TRACKING_RUNTIME,
                                                GDI_SCENARIO_NORMAL) == 0);
    return 0;
}

/*
 * Coverage: ensures feature bits with runtime implementations are backend
 * ready in settings but remain not-negotiated on a fresh session. It catches
 * accidental active status without a channel, transport, or activated session.
 */
int test_feature_runtime_gates(void)
{
    static const librdp_feature runtime_features[] = {
        LIBRDP_FEATURE_TELEMETRY,
        LIBRDP_FEATURE_MULTITRANSPORT,
        LIBRDP_FEATURE_DESKTOP_COMPOSITION,
        LIBRDP_FEATURE_UDP_TRANSPORT,
        LIBRDP_FEATURE_UDP2_TRANSPORT,
        LIBRDP_FEATURE_GEOMETRY_TRACKING,
        LIBRDP_FEATURE_MULTIPARTY
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status status;

    settings = librdp_settings_new();
    CHECK(settings != NULL);

    for (size_t i = 0; i < sizeof(runtime_features) / sizeof(runtime_features[0]); i++)
    {
        CHECK(librdp_settings_enable_feature(settings, runtime_features[i], 1) == LIBRDP_STATUS_OK);
        CHECK(librdp_settings_get_feature_status(settings, runtime_features[i], &status) ==
              LIBRDP_STATUS_OK);
        CHECK(status.feature == runtime_features[i]);
        CHECK(status.requested && status.built);
        CHECK(status.backend_ready && !status.negotiated && !status.active);
        CHECK(status.reason == LIBRDP_FEATURE_REASON_NONE);
    }

    session = librdp_session_new(settings);
    CHECK(session != NULL);

    for (size_t i = 0; i < sizeof(runtime_features) / sizeof(runtime_features[0]); i++)
    {
        CHECK(librdp_session_get_feature_status(session, runtime_features[i], &status) ==
              LIBRDP_STATUS_OK);
        CHECK(status.feature == runtime_features[i]);
        CHECK(status.requested && status.built);
        CHECK(status.backend_ready && !status.negotiated && !status.active);
        CHECK(status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    }

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: locks public feature-status reason values to the active contract.
 * Bug class: catches stale readiness categories leaking from settings or a
 * fresh client session after all known feature bits are queried.
 */
int test_client_feature_status_reason_contract(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_feature_status status;

    settings = librdp_settings_new();
    CHECK(settings != NULL);

    for (size_t i = 0; i < sizeof(core_test_all_features) / sizeof(core_test_all_features[0]); i++)
    {
        CHECK(librdp_settings_get_feature_status(settings, core_test_all_features[i], &status) ==
              LIBRDP_STATUS_OK);
        CHECK(status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
        CHECK(core_test_feature_reason_is_current(&status));
        CHECK(librdp_settings_enable_feature(settings, core_test_all_features[i], 1) ==
              LIBRDP_STATUS_OK);
        CHECK(librdp_settings_get_feature_status(settings, core_test_all_features[i], &status) ==
              LIBRDP_STATUS_OK);
        CHECK(core_test_feature_reason_is_current(&status));
    }

    session = librdp_session_new(settings);
    CHECK(session != NULL);
    for (size_t i = 0; i < sizeof(core_test_all_features) / sizeof(core_test_all_features[0]); i++)
    {
        CHECK(librdp_session_get_feature_status(session, core_test_all_features[i], &status) ==
              LIBRDP_STATUS_OK);
        CHECK(core_test_feature_reason_is_current(&status));
    }

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}
