/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server feature and provider readiness tests.
 * Coverage: requested/built/provider/negotiated reason-state drift.
 * Bug classes: malformed input, invalid state, bounds, and ownership regressions.
 * Determinism: fixtures use synthetic data and loopback transports only.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

/*
 * Coverage: verifies that side transport features are built and backend-ready
 * only when the server has a real runtime path, while still remaining inactive
 * until a peer negotiates and uses the transport.
 */
int test_server_transport_feature_gates(void)
{
    librdp_server_config config;
    librdp_feature_status feature_status;
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);

    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_UDP2_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_UDP2_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.feature == LIBRDP_FEATURE_UDP2_TRANSPORT);
    SCHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    SCHECK(!feature_status.negotiated && !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);

    librdp_server_free(server);
    return 0;
}

/*
 * Coverage: locks the server feature model to runtime-backed features and keeps
 * application-backed extensions unavailable at listener scope until a peer has
 * callbacks installed.
 */
int test_server_public_feature_backend_readiness(void)
{
    static const librdp_feature application_features[] = {
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
        LIBRDP_FEATURE_DESKTOP_COMPOSITION,
        LIBRDP_FEATURE_DISPLAY_CONTROL,
        LIBRDP_FEATURE_GEOMETRY_TRACKING,
        LIBRDP_FEATURE_MULTIPARTY
    };
    static const librdp_feature internal_features[] = {
        LIBRDP_FEATURE_MULTITRANSPORT,
        LIBRDP_FEATURE_UDP_TRANSPORT,
        LIBRDP_FEATURE_UDP2_TRANSPORT
    };
    librdp_server_config config;
    librdp_feature_status feature_status;
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    for (size_t i = 0; i < sizeof(application_features) / sizeof(application_features[0]); i++)
    {
        SCHECK(librdp_server_enable_feature(server, application_features[i], 1) == LIBRDP_STATUS_OK);
        SCHECK(librdp_server_get_feature_status(server, application_features[i], &feature_status) ==
               LIBRDP_STATUS_OK);
        SCHECK(feature_status.feature == application_features[i]);
        SCHECK(feature_status.requested);
        SCHECK(feature_status.built);
        SCHECK(!feature_status.backend_ready);
        SCHECK(!feature_status.negotiated);
        SCHECK(!feature_status.active);
        SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
        SCHECK(librdp_server_enable_feature_provider(server, application_features[i], 1) ==
               LIBRDP_STATUS_OK);
        SCHECK(librdp_server_get_feature_status(server, application_features[i], &feature_status) ==
               LIBRDP_STATUS_OK);
        SCHECK(feature_status.feature == application_features[i]);
        SCHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
        SCHECK(!feature_status.negotiated && !feature_status.active);
        SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
        SCHECK(librdp_server_enable_feature_provider(server, application_features[i], 0) ==
               LIBRDP_STATUS_OK);
    }
    for (size_t i = 0; i < sizeof(internal_features) / sizeof(internal_features[0]); i++)
    {
        SCHECK(librdp_server_enable_feature(server, internal_features[i], 1) == LIBRDP_STATUS_OK);
        SCHECK(librdp_server_enable_feature_provider(server, internal_features[i], 1) ==
               LIBRDP_STATUS_UNSUPPORTED);
        SCHECK(librdp_server_get_feature_status(server, internal_features[i], &feature_status) ==
               LIBRDP_STATUS_OK);
        SCHECK(feature_status.feature == internal_features[i]);
        SCHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
        SCHECK(!feature_status.negotiated && !feature_status.active);
        SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    }
    librdp_server_free(server);
    return 0;
}

/*
 * Coverage: validates that listener-scope feature readiness reports only the
 * public reason values that are part of the active API contract.
 * Bug class: catches stale readiness categories when new server features are
 * wired into the listener before peer negotiation.
 */
int test_server_feature_status_reason_contract(void)
{
    librdp_server_config config;
    librdp_feature_status feature_status;
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);

    for (size_t i = 0; i < sizeof(server_test_all_features) / sizeof(server_test_all_features[0]); i++)
    {
        SCHECK(librdp_server_get_feature_status(server, server_test_all_features[i], &feature_status) ==
               LIBRDP_STATUS_OK);
        SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
        SCHECK(server_test_feature_reason_is_current(&feature_status));
        SCHECK(librdp_server_enable_feature(server, server_test_all_features[i], 1) ==
               LIBRDP_STATUS_OK);
        SCHECK(librdp_server_get_feature_status(server, server_test_all_features[i], &feature_status) ==
               LIBRDP_STATUS_OK);
        SCHECK(server_test_feature_reason_is_current(&feature_status));
    }

    librdp_server_free(server);
    return 0;
}
