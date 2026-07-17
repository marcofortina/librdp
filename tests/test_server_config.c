/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server configuration and listener ownership tests.
 * Coverage: ABI metadata, invalid configuration, and copied string lifetime.
 * Bug classes: malformed input, invalid state, bounds, and ownership regressions.
 * Determinism: fixtures use synthetic data and loopback transports only.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

int test_server_config_defaults(void)
{
    librdp_server_config config;
    librdp_server_input_event input_event;
    librdp_server_static_channel_info channel_info;
    librdp_server_extension_event extension_event;
    librdp_server_event server_event;
    librdp_server_status server_status;
    librdp_server_metrics metrics;
    librdp_server_extension_state extension_state;
    librdp_server_credentials_request credentials_request;

    SCHECK(librdp_server_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    SCHECK(config.version == LIBRDP_SERVER_CONFIG_VERSION);
    SCHECK(config.size == sizeof(config));
    SCHECK(config.bind_address == NULL);
    SCHECK(config.port == 0);
    SCHECK(config.backlog == 4);
    SCHECK(config.max_peers == 16);
    SCHECK(config.width == 1024);
    SCHECK(config.height == 768);
    SCHECK(config.server_name == NULL);
    SCHECK(config.security_mode == LIBRDP_SECURITY_STANDARD);
    SCHECK(config.tls_certificate_path == NULL);
    SCHECK(config.tls_private_key_path == NULL);
    SCHECK(config.nla_domain == NULL);
    SCHECK(config.nla_username == NULL);
    SCHECK(config.nla_password == NULL);
    SCHECK(librdp_server_input_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_input_event_init(&input_event) == LIBRDP_STATUS_OK);
    SCHECK(input_event.version == LIBRDP_SERVER_INPUT_EVENT_VERSION);
    SCHECK(input_event.size == sizeof(input_event));
    SCHECK(librdp_server_static_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_static_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    SCHECK(channel_info.version == LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION);
    SCHECK(channel_info.size == sizeof(channel_info));
    SCHECK(librdp_server_extension_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_extension_event_init(&extension_event) == LIBRDP_STATUS_OK);
    SCHECK(extension_event.version == LIBRDP_SERVER_EXTENSION_EVENT_VERSION);
    SCHECK(extension_event.size == sizeof(extension_event));
    SCHECK(extension_event.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_event_init(&server_event) == LIBRDP_STATUS_OK);
    SCHECK(server_event.version == LIBRDP_SERVER_EVENT_VERSION);
    SCHECK(server_event.size == sizeof(server_event));
    SCHECK(server_event.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_credentials_request_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_credentials_request_init(&credentials_request) == LIBRDP_STATUS_OK);
    SCHECK(credentials_request.version == LIBRDP_SERVER_CREDENTIALS_REQUEST_VERSION);
    SCHECK(credentials_request.size == sizeof(credentials_request));
    SCHECK(librdp_server_status_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.version == LIBRDP_SERVER_STATUS_VERSION);
    SCHECK(server_status.size == sizeof(server_status));
    SCHECK(server_status.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_metrics_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    SCHECK(metrics.version == LIBRDP_SERVER_METRICS_VERSION);
    SCHECK(metrics.size == sizeof(metrics));
    SCHECK(librdp_server_extension_state_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.version == LIBRDP_SERVER_EXTENSION_STATE_VERSION);
    SCHECK(extension_state.size == sizeof(extension_state));
    SCHECK(extension_state.last_status == LIBRDP_STATUS_OK);
    return 0;
}

/*
 * Fixture: exercises public server construction guardrails with malformed ABI
 * metadata, TLS file combinations, feature readiness, and lifecycle cleanup.
 * Bug class: rejects configuration drift, ownership mistakes, and backend-ready
 * claims before a valid runtime provider exists.
 */
int test_server_new_validates_metadata(void)
{
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_feature_status feature_status;
    int extension_enabled = 0;
    char cert_path[128];
    char key_path[128];
    char cert_path_b[128];
    char key_path_b[128];
    char nla_password[32];
    char nla_username[32];

    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));
    memset(cert_path_b, 0, sizeof(cert_path_b));
    memset(key_path_b, 0, sizeof(key_path_b));
    test_server_fill_secret(nla_password, sizeof(nla_password), 307u);
    test_server_fill_secret(nla_username, sizeof(nla_username), 311u);

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.version = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.size = 1;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 1024;
    config.height = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 9000;
    config.height = 9000;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.backlog = 129;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = (librdp_security_mode)99;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = "server.pem";
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = "server.pem";
    config.tls_private_key_path = "server.key";
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(test_server_make_tls_files(cert_path_b, sizeof(cert_path_b), key_path_b, sizeof(key_path_b)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path_b;
    SCHECK(librdp_server_new(&config) == NULL);
    config.tls_private_key_path = key_path;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    librdp_server_free(server);
    server = NULL;
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.security_mode = LIBRDP_SECURITY_NLA;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    librdp_server_free(server);
    server = NULL;
    config.nla_username = nla_username;
    SCHECK(librdp_server_new(&config) == NULL);
    config.nla_password = nla_password;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    librdp_server_free(server);
    server = NULL;
    unlink(cert_path);
    unlink(key_path);
    unlink(cert_path_b);
    unlink(key_path_b);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_get_feature_status(NULL,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_feature_status(server,
                                            (librdp_feature)(LIBRDP_FEATURE_ECHO | LIBRDP_FEATURE_VIDEO),
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(!feature_status.requested && feature_status.built && !feature_status.backend_ready &&
           !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready &&
           !feature_status.negotiated && !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_enable_feature_provider(server, LIBRDP_FEATURE_UDP2_TRANSPORT, 1) ==
           LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(librdp_server_enable_feature_provider(server, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.built && feature_status.backend_ready &&
           !feature_status.negotiated && !feature_status.active);
    SCHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_enable_feature_provider(server, LIBRDP_FEATURE_ECHO, 0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_extension_provider_status(NULL,
                                                       LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                       &extension_enabled) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_extension_provider_status(server,
                                                       LIBRDP_SERVER_EXTENSION_UNKNOWN,
                                                       &extension_enabled) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_get_extension_provider_status(server,
                                                       LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                       NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_enable_extension_provider(NULL,
                                                   LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                   1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_UNKNOWN,
                                                   1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_extension_provider_status(server,
                                                       LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                       &extension_enabled) == LIBRDP_STATUS_OK);
    SCHECK(extension_enabled);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                   0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_extension_provider_status(server,
                                                       LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                       &extension_enabled) == LIBRDP_STATUS_OK);
    SCHECK(!extension_enabled);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_GEOMETRY_TRACKING, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING,
                                                   0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_GEOMETRY_TRACKING, 0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 0) == LIBRDP_STATUS_OK);
    librdp_server_free(server);
    librdp_server_free(NULL);
    return 0;
}

int test_server_new_copies_strings(void)
{
    librdp_server_config config;
    char bind_address[16] = "127.0.0.1";
    char server_name[16] = "test";
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = bind_address;
    config.server_name = server_name;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    memset(bind_address, 'x', sizeof(bind_address) - 1u);
    bind_address[sizeof(bind_address) - 1u] = '\0';
    memset(server_name, 'y', sizeof(server_name) - 1u);
    server_name[sizeof(server_name) - 1u] = '\0';
    librdp_server_free(server);
    return 0;
}
