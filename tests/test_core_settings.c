/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: settings and session tests.
 * Coverage: settings ownership, lifecycle, reconnect, metrics, and errors.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

/*
 * Coverage: exercises public settings, surface, input, callback, clipboard,
 * channel, audio, video, and session lifecycle APIs together to catch
 * ownership and state regressions.
 */
int test_settings_surface_input_session(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_surface* surface = NULL;
    librdp_session* session = NULL;
    librdp_client* client = NULL;
    librdp_client_config client_config;
    const librdp_surface* session_surface = NULL;
    librdp_surface_mapping surface_map;
    librdp_surface_mapping surface_map2;
    uint8_t pixels[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    };
    const uint8_t* out = NULL;
    uint16_t flags = 0;
    librdp_key_event key = {
        .scancode = 30,
        .state = LIBRDP_KEY_PRESSED,
        .flags = 0,
        .unicode = 0
    };
    librdp_mouse_event mouse = {10, 11, LIBRDP_MOUSE_BUTTON_LEFT, LIBRDP_MOUSE_PRESSED};
    librdp_display_monitor display_monitors[2];
    librdp_touch_contact touch_contact;
    librdp_touch_frame touch_frame;
    librdp_pen_contact pen_contact;
    librdp_pen_frame pen_frame;
    librdp_feature_status feature_status;
    librdp_tls_policy tls_policy;
    librdp_tls_policy tls_policy_out;
    librdp_gateway_config gateway_config;
    librdp_gateway_config gateway_config_out;
    const struct
    {
        librdp_status status;
        const char* name;
    } status_cases[] = {
        {LIBRDP_STATUS_OK, "ok"},
        {LIBRDP_STATUS_INVALID_ARGUMENT, "invalid_argument"},
        {LIBRDP_STATUS_NO_MEMORY, "no_memory"},
        {LIBRDP_STATUS_IO_ERROR, "io_error"},
        {LIBRDP_STATUS_PROTOCOL_ERROR, "protocol_error"},
        {LIBRDP_STATUS_UNSUPPORTED, "unsupported"},
        {LIBRDP_STATUS_TIMEOUT, "timeout"},
        {LIBRDP_STATUS_CLOSED, "closed"},
        {LIBRDP_STATUS_AGAIN, "again"},
        {LIBRDP_STATUS_STATE, "state"},
        {LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED, "tls_certificate_rejected"},
        {LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH, "tls_hostname_mismatch"},
        {LIBRDP_STATUS_TLS_HANDSHAKE_FAILED, "tls_handshake_failed"},
        {LIBRDP_STATUS_SECURITY_DOWNGRADE, "security_downgrade"},
        {LIBRDP_STATUS_LIMIT_EXCEEDED, "limit_exceeded"},
        {LIBRDP_STATUS_CANCELLED, "cancelled"}
    };
    librdp_credentials credentials;
    librdp_error_info error_info;
    const librdp_error* session_error = NULL;
    librdp_drive_policy drive_policy;
    librdp_drive_policy drive_policy_out;
    librdp_usb_policy usb_policy;
    librdp_usb_policy usb_policy_out;
    librdp_usb_selector_mode usb_selector_mode = LIBRDP_USB_SELECTOR_VID_PID;
    uint32_t usb_selector_first = 0;
    uint32_t usb_selector_second = 0;
    librdp_limits limits;
    librdp_limits limits_out;
    librdp_metrics metrics;
    librdp_event_envelope envelope;
    librdp_trace_policy trace_policy;
    librdp_channel_info channel_info;
    librdp_channel_info channel_infos[2];
    librdp_channel_send_options channel_send_options;
    librdp_channel_handle channel_handle = 0;
    librdp_channel_handle client_channel_handle = 0;
    trace_capture trace;
    event_envelope_capture envelope_capture;
    domain_event_capture domain_capture;
    graphics_update_capture graphics_capture;
    secure_string_capture secure_capture;
    credentials_provider_capture credentials_capture;
    cancel_thread_capture cancel_capture;
    owner_thread_capture owner_capture;
    pthread_t cancel_thread;
    pthread_t owner_thread;
    char trace_file_path[] = "/tmp/librdp-trace-XXXXXX";
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    int trace_fd = -1;
    int next_timeout = 0;
    struct pollfd session_pfds[3];
    size_t session_pfd_count = 0;
    size_t channel_count = 0;
    char bulk_domain[32];
    char bulk_password[32];
    char bulk_username[32];
    char gateway_domain[32];
    char gateway_password[32];
    char gateway_username[32];
    char settings_domain[32];
    char settings_password_a[32];
    char settings_password_b[32];
    char settings_username[32];

    memset(&counter, 0, sizeof(counter));
    memset(&envelope_capture, 0, sizeof(envelope_capture));
    memset(&domain_capture, 0, sizeof(domain_capture));
    memset(&graphics_capture, 0, sizeof(graphics_capture));
    memset(&trace, 0, sizeof(trace));
    memset(&secure_capture, 0, sizeof(secure_capture));
    memset(&credentials_capture, 0, sizeof(credentials_capture));
    memset(&cancel_capture, 0, sizeof(cancel_capture));
    memset(&owner_capture, 0, sizeof(owner_capture));
    test_core_fill_secret(bulk_domain, sizeof(bulk_domain), 103u);
    test_core_fill_secret(bulk_password, sizeof(bulk_password), 107u);
    test_core_fill_secret(bulk_username, sizeof(bulk_username), 109u);
    test_core_fill_secret(gateway_domain, sizeof(gateway_domain), 113u);
    test_core_fill_secret(gateway_password, sizeof(gateway_password), 127u);
    test_core_fill_secret(gateway_username, sizeof(gateway_username), 131u);
    test_core_fill_secret(settings_domain, sizeof(settings_domain), 137u);
    test_core_fill_secret(settings_password_a, sizeof(settings_password_a), 139u);
    test_core_fill_secret(settings_password_b, sizeof(settings_password_b), 149u);
    test_core_fill_secret(settings_username, sizeof(settings_username), 151u);

    for (size_t i = 0; i < sizeof(status_cases) / sizeof(status_cases[0]); i++)
    {
        CHECK(strcmp(librdp_status_name(status_cases[i].status), status_cases[i].name) == 0);
        CHECK(strcmp(librdp_status_string(status_cases[i].status), status_cases[i].name) == 0);
        CHECK(librdp_status_description(status_cases[i].status) != NULL);
        CHECK(librdp_status_description(status_cases[i].status)[0] != '\0');
    }
    CHECK(strcmp(librdp_status_name((librdp_status)-1000), "unknown") == 0);
    CHECK(strcmp(librdp_status_string((librdp_status)-1000), "unknown") == 0);
    CHECK(strcmp(librdp_status_description((librdp_status)-1000), "Unknown status code.") == 0);
    CHECK(librdp_error_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.version == LIBRDP_ERROR_INFO_VERSION);
    CHECK(error_info.status == LIBRDP_STATUS_OK);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
    CHECK(librdp_error_copy_info(NULL, &error_info) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(strcmp(librdp_error_component_name(LIBRDP_ERROR_COMPONENT_CLIENT), "client") == 0);
    CHECK(strcmp(librdp_error_component_name(LIBRDP_ERROR_COMPONENT_TRANSPORT), "transport") == 0);
    CHECK(strcmp(librdp_error_component_name((librdp_error_component)1000), "unknown") == 0);
    CHECK(librdp_event_envelope_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_event_envelope_init(&envelope) == LIBRDP_STATUS_OK);
    CHECK(envelope.version == LIBRDP_EVENT_ENVELOPE_VERSION);
    CHECK(envelope.size == sizeof(envelope));
    CHECK(librdp_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.version == LIBRDP_CHANNEL_INFO_VERSION);
    CHECK(channel_info.size == sizeof(channel_info));
    CHECK(librdp_channel_send_options_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_channel_send_options_init(&channel_send_options) == LIBRDP_STATUS_OK);
    CHECK(channel_send_options.version == LIBRDP_CHANNEL_SEND_OPTIONS_VERSION);
    CHECK(channel_send_options.size == sizeof(channel_send_options));
    CHECK(channel_send_options.priority == LIBRDP_CHANNEL_PRIORITY_LOW);
    CHECK(librdp_client_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_config_init(&client_config) == LIBRDP_STATUS_OK);
    CHECK(client_config.version == LIBRDP_CLIENT_CONFIG_VERSION);
    CHECK(client_config.port == 3389);
    CHECK(client_config.width == 1024);
    CHECK(client_config.height == 768);
    CHECK(client_config.security == LIBRDP_SECURITY_AUTO);
    CHECK(librdp_client_new(NULL) == NULL);
    client = librdp_client_new(&client_config);
    CHECK(client != NULL);
    CHECK(librdp_client_settings(NULL) == NULL);
    CHECK(librdp_client_session(NULL) == NULL);
    CHECK(librdp_client_settings(client) != NULL);
    CHECK(librdp_client_session(client) != NULL);
    CHECK(librdp_client_state(NULL) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_client_lifecycle(NULL) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_client_state(client) == LIBRDP_SESSION_IDLE);
    CHECK(librdp_client_lifecycle(client) == LIBRDP_LIFECYCLE_NEW);
    CHECK(librdp_settings_enable_feature(librdp_client_settings(client),
                                         LIBRDP_FEATURE_DISPLAY_CONTROL,
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(librdp_client_session(client),
                                            LIBRDP_FEATURE_DISPLAY_CONTROL,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(librdp_client_dispatch(client, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_get_pollfds(NULL, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_get_pollfds(client, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_notify_poll(NULL, session_pfds, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_notify_poll(client, session_pfds, 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_dispatch_pending(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_dispatch_pending(client) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_get_next_timeout(NULL, &next_timeout) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_get_next_timeout(client, &next_timeout) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_cancel(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_reconnect(NULL, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_client_reconnect(client, NULL) == LIBRDP_STATUS_STATE);
    CHECK(librdp_settings_set_desktop_size(librdp_client_settings(client), 800, 600) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_client_connect(client) == LIBRDP_STATUS_INVALID_ARGUMENT);
    session_surface = librdp_session_get_surface(librdp_client_session(client));
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 800);
    CHECK(librdp_surface_height(session_surface) == 600);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(librdp_client_session(client)), &error_info) ==
          LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
    CHECK(librdp_client_state(client) == LIBRDP_SESSION_IDLE);
    CHECK(librdp_client_reconnect(client, NULL) == LIBRDP_STATUS_STATE);
    CHECK(librdp_client_disconnect(client) == LIBRDP_STATUS_OK);
    librdp_client_free(client);
    client = NULL;
    client_config.target = "127.0.0.1";
    client_config.username = settings_username;
    client_config.password = settings_password_b;
    client_config.width = 800;
    client_config.height = 600;
    client_config.security = LIBRDP_SECURITY_STANDARD;
    client = librdp_client_new(&client_config);
    CHECK(client != NULL);
    CHECK(strcmp(librdp_settings_target(librdp_client_settings(client)), "127.0.0.1") == 0);
    CHECK(librdp_settings_width(librdp_client_settings(client)) == 800);
    CHECK(librdp_settings_height(librdp_client_settings(client)) == 600);
    librdp_client_free(client);
    client = NULL;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_limits_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    CHECK(limits.version == LIBRDP_LIMITS_VERSION);
    CHECK(limits.size == sizeof(limits));
    CHECK(limits.dynamic_channel_message_bytes == 64u * 1024u * 1024u);
    CHECK(librdp_settings_get_limits(NULL, &limits_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_limits(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_limits(settings, &limits_out) == LIBRDP_STATUS_OK);
    CHECK(limits_out.surface_max_dimension == 8192u);
    limits_out.surface_max_dimension = 512u;
    CHECK(librdp_settings_set_limits(settings, &limits_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    limits_out.surface_max_dimension = 1024u;
    CHECK(librdp_settings_set_limits(settings, &limits_out) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 1200, 768) == LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_settings_set_limits(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_tls_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(NULL, &tls_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.version == LIBRDP_TLS_POLICY_VERSION);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_STRICT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(tls_policy_out.pinned_sha256 == NULL);
    CHECK(tls_policy_out.certificate_callback == NULL);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.pinned_sha256 =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(strcmp(tls_policy_out.pinned_sha256,
                 "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899") == 0);
    tls_policy.mode = LIBRDP_TLS_POLICY_TOFU;
    tls_policy.pinned_sha256 = NULL;
    tls_policy.certificate_callback = NULL;
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_trace_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    CHECK(trace_policy.version == LIBRDP_TRACE_POLICY_VERSION);
    CHECK(trace_policy.categories == LIBRDP_TRACE_CATEGORY_ALL);
    CHECK(trace_policy.level == LIBRDP_TRACE_LEVEL_INFO);
    CHECK(trace_policy.sink == LIBRDP_TRACE_SINK_STDERR);
    tls_policy.certificate_callback = core_tls_certificate_callback;
    tls_policy.certificate_callback_user_data = &counter;
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_TOFU);
    CHECK(tls_policy_out.certificate_callback == core_tls_certificate_callback);
    CHECK(tls_policy_out.certificate_callback_user_data == &counter);
    CHECK(librdp_settings_set_tls_policy(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_tls_policy(settings, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_STRICT);
    CHECK(tls_policy_out.use_system_store == 1);
    CHECK(tls_policy_out.pinned_sha256 == NULL);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.pinned_sha256 = "not-a-sha256";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_gateway_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_gateway_config_init(&gateway_config) == LIBRDP_STATUS_OK);
    CHECK(gateway_config.version == LIBRDP_GATEWAY_CONFIG_VERSION);
    CHECK(gateway_config.mode == LIBRDP_GATEWAY_DISABLED);
    CHECK(gateway_config.timeout_ms == 15000u);
    CHECK(gateway_config.use_session_credentials == 1);
    CHECK(librdp_settings_get_gateway_config(NULL, &gateway_config_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_gateway_config(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_gateway_config(settings, &gateway_config_out) == LIBRDP_STATUS_OK);
    CHECK(gateway_config_out.mode == LIBRDP_GATEWAY_DISABLED);
    gateway_config.mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    gateway_config.url = "https://gateway.example.com/rdp";
    gateway_config.username = gateway_username;
    gateway_config.password = gateway_password;
    gateway_config.domain = gateway_domain;
    gateway_config.timeout_ms = 30000u;
    gateway_config.use_session_credentials = 0;
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_gateway_config(settings, &gateway_config_out) == LIBRDP_STATUS_OK);
    CHECK(gateway_config_out.mode == LIBRDP_GATEWAY_HTTP_CONNECT);
    CHECK(strcmp(gateway_config_out.url, "https://gateway.example.com/rdp") == 0);
    CHECK(strcmp(gateway_config_out.username, gateway_username) == 0);
    CHECK(strcmp(gateway_config_out.password, gateway_password) == 0);
    CHECK(strcmp(gateway_config_out.domain, gateway_domain) == 0);
    CHECK(gateway_config_out.timeout_ms == 30000u);
    CHECK(gateway_config_out.use_session_credentials == 0);
    gateway_config.url = "ftp://gateway.example.com";
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_INVALID_ARGUMENT);
    gateway_config.url = "https://gateway.example.com/rdp";
    gateway_config.timeout_ms = 600001u;
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_INVALID_ARGUMENT);
    gateway_config.timeout_ms = 30000u;
    gateway_config.mode = LIBRDP_GATEWAY_RDG_HTTP;
    gateway_config.url = "http://gateway.example.com/rdg";
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_INVALID_ARGUMENT);
    gateway_config.url = "https://gateway.example.com/rdg";
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_gateway_config(settings, &gateway_config_out) == LIBRDP_STATUS_OK);
    CHECK(gateway_config_out.mode == LIBRDP_GATEWAY_RDG_HTTP);
    CHECK(strcmp(gateway_config_out.url, "https://gateway.example.com/rdg") == 0);
    gateway_config.mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    gateway_config.url = "https://gateway.example.com/rdp";
    CHECK(librdp_settings_set_gateway_config(settings, &gateway_config) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_port(settings) == 3389);
    CHECK(librdp_settings_width(settings) == 1024);
    CHECK(librdp_settings_height(settings) == 768);
    {
        librdp_session* no_target_session = librdp_session_new(settings);

        CHECK(no_target_session != NULL);
        CHECK(librdp_session_connect(no_target_session) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        CHECK(librdp_error_copy_info(librdp_session_last_error(no_target_session), &error_info) ==
              LIBRDP_STATUS_OK);
        CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
        CHECK(error_info.os_errno == 0);
        CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.connect.validate") == 0);
        CHECK(error_info.message != NULL && strstr(error_info.message, "target") != NULL);
        librdp_session_clear_last_error(no_target_session);
        CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        CHECK(librdp_error_copy_info(librdp_session_last_error(no_target_session), &error_info) ==
              LIBRDP_STATUS_OK);
        CHECK(error_info.status == LIBRDP_STATUS_OK);
        CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
        librdp_session_free(no_target_session);
        librdp_session_clear_last_error(NULL);
    }
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_username(settings, settings_username) == LIBRDP_STATUS_OK);
    rdp_settings_secure_string_observer_for_tests(on_secure_string_cleanse, &secure_capture);
    CHECK(librdp_settings_set_password(settings, settings_password_a) == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 0);
    CHECK(librdp_settings_set_password(settings, settings_password_b) == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 1);
    CHECK(secure_capture.failed == 0);
    CHECK(secure_capture.last_length == strlen(settings_password_a) + 1u);
    CHECK(librdp_settings_set_password(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(secure_capture.calls == 2);
    CHECK(secure_capture.failed == 0);
    CHECK(secure_capture.last_length == strlen(settings_password_b) + 1u);
    CHECK(librdp_credentials_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_credentials_init(&credentials) == LIBRDP_STATUS_OK);
    CHECK(credentials.version == LIBRDP_CREDENTIALS_VERSION);
    CHECK(credentials.size == sizeof(credentials));
    CHECK(librdp_credentials_set(NULL, bulk_username, bulk_password, bulk_domain) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_credentials_set(&credentials, bulk_username, bulk_password, bulk_domain) ==
          LIBRDP_STATUS_OK);
    CHECK(strcmp(credentials.username, bulk_username) == 0);
    CHECK(strcmp(credentials.password, bulk_password) == 0);
    CHECK(strcmp(credentials.domain, bulk_domain) == 0);
    CHECK(librdp_settings_set_credentials(NULL, &credentials) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_credentials(settings, &credentials) == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_username(settings), bulk_username) == 0);
    CHECK(strcmp(rdp_settings_password_internal(settings), bulk_password) == 0);
    CHECK(strcmp(librdp_settings_domain(settings), bulk_domain) == 0);
    CHECK(librdp_settings_set_credentials(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_username(settings) == NULL);
    CHECK(rdp_settings_password_internal(settings) == NULL);
    CHECK(librdp_settings_domain(settings) == NULL);
    librdp_credentials_clear(&credentials);
    CHECK(credentials.username == NULL);
    CHECK(credentials.password == NULL);
    CHECK(credentials.domain == NULL);
    CHECK(secure_capture.failed == 0);
    CHECK(librdp_settings_set_username(settings, settings_username) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_password(settings, settings_password_a) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_domain(settings, settings_domain) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 3390) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_TLS) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_drive_count(settings) == 0);
    CHECK(librdp_settings_add_drive(settings, "C:", "/tmp") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_drive_count(settings) == 1);
    CHECK(strcmp(librdp_settings_drive_name(settings, 0), "C:") == 0);
    CHECK(strcmp(librdp_settings_drive_path(settings, 0), "/tmp") == 0);
    CHECK(librdp_settings_drive_name(settings, 1) == NULL);
    CHECK(librdp_settings_drive_path(settings, 1) == NULL);
    CHECK(librdp_drive_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_drive_policy_init(&drive_policy) == LIBRDP_STATUS_OK);
    CHECK(drive_policy.version == LIBRDP_DRIVE_POLICY_VERSION);
    CHECK(drive_policy.size == sizeof(drive_policy));
    CHECK(drive_policy.read_only == 1);
    CHECK(drive_policy.deny_device_files == 1);
    CHECK(drive_policy.deny_symlink_escape == 1);
    CHECK(drive_policy.deny_dotfiles == 1);
    CHECK(drive_policy.max_open_handles > 0);
    CHECK(librdp_settings_get_drive_policy(NULL, 0, &drive_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 1, &drive_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_drive_policy(settings, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 1);
    drive_policy.read_only = 0;
    drive_policy.max_file_size = 65536u;
    drive_policy.max_open_handles = 2u;
    CHECK(librdp_settings_set_drive_policy(NULL, 0, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_drive_policy(settings, 1, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_drive_policy(settings, 0, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    drive_policy.version = 0;
    CHECK(librdp_settings_set_drive_policy(settings, 0, &drive_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_drive_policy_init(&drive_policy) == LIBRDP_STATUS_OK);
    drive_policy.read_only = 0;
    drive_policy.max_file_size = 65536u;
    drive_policy.max_open_handles = 2u;
    CHECK(librdp_settings_set_drive_policy(settings, 0, &drive_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_drive_policy(settings, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 0);
    CHECK(drive_policy_out.max_file_size == 65536u);
    CHECK(drive_policy_out.max_open_handles == 2u);
    librdp_usb_policy_init(NULL);
    librdp_usb_policy_init(&usb_policy);
    CHECK(usb_policy.version == LIBRDP_USB_POLICY_VERSION);
    CHECK(usb_policy.size == sizeof(usb_policy));
    CHECK(usb_policy.require_explicit_consent == 1);
    CHECK(usb_policy.allow_hid == 0);
    CHECK(usb_policy.allow_mass_storage == 0);
    CHECK(usb_policy.max_transfer_ms > 0);
    CHECK(librdp_settings_get_usb_policy(NULL, &usb_policy_out) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_usb_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_usb_policy(settings, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 0);
    CHECK(usb_policy_out.allow_mass_storage == 0);
    CHECK(librdp_settings_set_usb_policy(NULL, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_usb_policy(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    usb_policy.version = 0;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_usb_policy_init(&usb_policy);
    usb_policy.max_transfer_ms = 60001u;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    librdp_usb_policy_init(&usb_policy);
    usb_policy.require_explicit_consent = 1;
    usb_policy.allow_hid = 1;
    usb_policy.allow_mass_storage = 1;
    usb_policy.max_transfer_ms = 0;
    CHECK(librdp_settings_set_usb_policy(settings, &usb_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_usb_policy(settings, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 1);
    CHECK(usb_policy_out.allow_mass_storage == 1);
    CHECK(usb_policy_out.max_transfer_ms > 0);
    CHECK(librdp_usb_selector_parse(NULL,
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_usb_selector_parse("",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_usb_selector_parse("vid:pid=1234:5678",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_OK);
    CHECK(usb_selector_mode == LIBRDP_USB_SELECTOR_VID_PID);
    CHECK(usb_selector_first == 0x1234u);
    CHECK(usb_selector_second == 0x5678u);
    CHECK(librdp_usb_selector_parse("bus:dev=1:4",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_OK);
    CHECK(usb_selector_mode == LIBRDP_USB_SELECTOR_BUS_DEV);
    CHECK(usb_selector_first == 1u);
    CHECK(usb_selector_second == 4u);
    CHECK(librdp_usb_selector_parse("1:4",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_OK);
    CHECK(usb_selector_mode == LIBRDP_USB_SELECTOR_BUS_DEV);
    CHECK(librdp_usb_selector_parse("1234:5678",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_OK);
    CHECK(usb_selector_mode == LIBRDP_USB_SELECTOR_VID_PID);
    CHECK(usb_selector_first == 0x1234u);
    CHECK(usb_selector_second == 0x5678u);
    CHECK(librdp_usb_selector_parse("12ab:34cd",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_OK);
    CHECK(usb_selector_mode == LIBRDP_USB_SELECTOR_VID_PID);
    CHECK(usb_selector_first == 0x12abu);
    CHECK(usb_selector_second == 0x34cdu);
    CHECK(librdp_usb_selector_parse("bus:dev=256:1",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_usb_selector_parse("1:2:3",
                                    &usb_selector_mode,
                                    &usb_selector_first,
                                    &usb_selector_second) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_serial_port_count(settings) == 0);
    CHECK(librdp_settings_add_serial_port(settings, "COM1:", "/dev/ttyS0") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_serial_port_count(settings) == 1);
    CHECK(strcmp(librdp_settings_serial_port_name(settings, 0), "COM1:") == 0);
    CHECK(strcmp(librdp_settings_serial_port_path(settings, 0), "/dev/ttyS0") == 0);
    CHECK(librdp_settings_serial_port_name(settings, 1) == NULL);
    CHECK(librdp_settings_serial_port_path(settings, 1) == NULL);
    CHECK(librdp_settings_parallel_port_count(settings) == 0);
    CHECK(librdp_settings_add_parallel_port(settings, "LPT1:", "/tmp/lpt1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_parallel_port_count(settings) == 1);
    CHECK(strcmp(librdp_settings_parallel_port_name(settings, 0), "LPT1:") == 0);
    CHECK(strcmp(librdp_settings_parallel_port_path(settings, 0), "/tmp/lpt1") == 0);
    CHECK(librdp_settings_parallel_port_name(settings, 1) == NULL);
    CHECK(librdp_settings_parallel_port_path(settings, 1) == NULL);
    CHECK(librdp_settings_printer_count(settings) == 0);
    CHECK(librdp_settings_add_printer(settings, "Print", "Generic", "/tmp") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_printer_count(settings) == 1);
    CHECK(strcmp(librdp_settings_printer_name(settings, 0), "Print") == 0);
    CHECK(strcmp(librdp_settings_printer_driver(settings, 0), "Generic") == 0);
    CHECK(strcmp(librdp_settings_printer_output_path(settings, 0), "/tmp") == 0);
    CHECK(librdp_settings_printer_name(settings, 1) == NULL);
    CHECK(librdp_settings_printer_driver(settings, 1) == NULL);
    CHECK(librdp_settings_printer_output_path(settings, 1) == NULL);
    CHECK(librdp_settings_get_feature_status(NULL,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)0,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)0x80000000u,
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.feature == LIBRDP_FEATURE_AUDIO_OUTPUT);
    CHECK(!feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_REQUESTED);
    CHECK(!librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_enable_feature(settings,
                                         (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                         LIBRDP_FEATURE_VIDEO),
                                         1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_feature_enabled(settings,
                                          (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                          LIBRDP_FEATURE_VIDEO)));
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DESKTOP_COMPOSITION, 1) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_UDP_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_UDP2_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_GEOMETRY_TRACKING, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTIPARTY, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_PNP,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_RAIL,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_VIDEO,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_CAMERA,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_WEBAUTHN,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             (librdp_feature)(LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                             LIBRDP_FEATURE_VIDEO),
                                             &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 0) == LIBRDP_STATUS_OK);
    CHECK(!librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(librdp_settings_set_audio_output_device(settings, "pipewire") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_AUDIO_OUTPUT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_audio_input_device(settings, "pipewire") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_video_output_path(settings, "/tmp/video.bin") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_camera(settings, "device=/dev/video0") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_smartcard(settings, "pcsc") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_usb_device(settings, "vid:pid=1234:5678") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\TEST_DEVICE",
                                         "LIBRDP\\PNP\\TEST",
                                         "Host test device",
                                         LIBRDP_PNP_DEVICE_CAP_REMOVABLE |
                                             LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/auth.json") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_rail_app(settings, "notepad.exe") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_echo_payload(settings, "probe") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_audio_output_device(settings), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(settings), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_video_output_path(settings), "/tmp/video.bin") == 0);
    CHECK(librdp_settings_camera_count(settings) == 1);
    CHECK(strcmp(librdp_settings_camera_source(settings, 0), "device=/dev/video0") == 0);
    CHECK(librdp_settings_camera_source(settings, 1) == NULL);
    CHECK(librdp_settings_smartcard_count(settings) == 1);
    CHECK(strcmp(librdp_settings_smartcard_source(settings, 0), "pcsc") == 0);
    CHECK(librdp_settings_smartcard_source(settings, 1) == NULL);
    CHECK(librdp_settings_usb_device_count(settings) == 1);
    CHECK(strcmp(librdp_settings_usb_device_selector(settings, 0), "vid:pid=1234:5678") == 0);
    CHECK(librdp_settings_usb_device_selector(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_count(settings) == 1);
    CHECK(strcmp(librdp_settings_pnp_device_hardware_id(settings, 0), "LIBRDP\\PNP\\TEST_DEVICE") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_compatibility_id(settings, 0), "LIBRDP\\PNP\\TEST") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_description(settings, 0), "Host test device") == 0);
    CHECK(librdp_settings_pnp_device_caps(settings, 0) ==
          (LIBRDP_PNP_DEVICE_CAP_REMOVABLE | LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK));
    CHECK(librdp_settings_pnp_device_hardware_id(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_compatibility_id(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_description(settings, 1) == NULL);
    CHECK(librdp_settings_pnp_device_caps(settings, 1) == 0);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "mock=/tmp/auth.json") == 0);
    CHECK(librdp_settings_webauthn_rp_id_count(settings) == 0);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_WEBAUTHN,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && !feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "example.com") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_webauthn_rp_id(settings, "login.example.com") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_webauthn_rp_id_count(settings) == 2);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(settings, 0), "example.com") == 0);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(settings, 1), "login.example.com") == 0);
    CHECK(librdp_settings_webauthn_rp_id(settings, 2) == NULL);
    CHECK(librdp_settings_rail_app_count(settings) == 1);
    CHECK(strcmp(librdp_settings_rail_app(settings, 0), "notepad.exe") == 0);
    CHECK(librdp_settings_rail_app(settings, 1) == NULL);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_PNP,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_RAIL,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_VIDEO,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_CAMERA,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_WEBAUTHN,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(strcmp(librdp_settings_echo_payload(settings), "probe") == 0);
    CHECK(librdp_settings_set_port(settings, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_desktop_size(settings, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_security_mode(settings, (librdp_security_mode)99) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "BAD/NAME", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_drive(settings, "D:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "", "/dev/ttyS1") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "BAD/COM", "/dev/ttyS1") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_serial_port(settings, "COM2:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "", "/tmp/lpt2") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "BAD/LPT", "/tmp/lpt2") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_parallel_port(settings, "LPT2:", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "", "Generic", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "Print", "", "/tmp") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_printer(settings, "Print", "Generic", "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings, (librdp_feature)0, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_enable_feature(settings,
                                         (librdp_feature)0x80000000u,
                                         1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(!librdp_settings_feature_enabled(settings, (librdp_feature)0x80000000u));
    CHECK(!librdp_settings_feature_enabled(settings,
                                           (librdp_feature)(LIBRDP_FEATURE_AUDIO_INPUT |
                                                           0x80000000u)));
    CHECK(librdp_settings_set_audio_output_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_audio_input_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_video_output_path(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_camera(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_smartcard(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_usb_device(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_usb_device(settings, "vid:pid=") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_usb_device(settings, "bus:dev=1:ffff") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_usb_device(settings, "bad") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "",
                                         "LIBRDP\\PNP\\BAD",
                                         "bad",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "",
                                         "bad",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "LIBRDP\\PNP\\BAD",
                                         "",
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_add_pnp_device(settings,
                                         "LIBRDP\\PNP\\BAD",
                                         "LIBRDP\\PNP\\BAD",
                                         "bad",
                                         0x80000000u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_webauthn_provider(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_webauthn_provider(settings, "fido2") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "fido2") == 0);
    CHECK(librdp_settings_set_webauthn_provider(settings, "fido2=/dev/hidraw0") == LIBRDP_STATUS_OK);
    CHECK(strcmp(librdp_settings_webauthn_provider(settings), "fido2=/dev/hidraw0") == 0);
    CHECK(librdp_settings_set_webauthn_provider(settings, "mock=/tmp/auth.json") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_rail_app(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_echo_payload(settings, "") == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_TELEMETRY,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_MULTITRANSPORT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_UDP_TRANSPORT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_UDP2_TRANSPORT,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_MULTIPARTY,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_settings_get_feature_status(settings,
                                             LIBRDP_FEATURE_DISPLAY_CONTROL,
                                             &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    CHECK(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
    tls_policy.use_system_store = 0;
    tls_policy.pinned_sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    CHECK(librdp_settings_set_tls_policy(settings, &tls_policy) == LIBRDP_STATUS_OK);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(strcmp(librdp_settings_target(copy), "127.0.0.1") == 0);
    CHECK(strcmp(librdp_settings_username(copy), settings_username) == 0);
    CHECK(strcmp(librdp_settings_domain(copy), settings_domain) == 0);
    CHECK(librdp_settings_security_mode(copy) == LIBRDP_SECURITY_TLS);
    CHECK(librdp_settings_get_gateway_config(copy, &gateway_config_out) == LIBRDP_STATUS_OK);
    CHECK(gateway_config_out.mode == LIBRDP_GATEWAY_HTTP_CONNECT);
    CHECK(strcmp(gateway_config_out.url, "https://gateway.example.com/rdp") == 0);
    CHECK(strcmp(gateway_config_out.username, gateway_username) == 0);
    CHECK(strcmp(gateway_config_out.password, gateway_password) == 0);
    CHECK(strcmp(gateway_config_out.domain, gateway_domain) == 0);
    CHECK(gateway_config_out.timeout_ms == 30000u);
    CHECK(gateway_config_out.use_session_credentials == 0);
    CHECK(librdp_settings_get_tls_policy(copy, &tls_policy_out) == LIBRDP_STATUS_OK);
    CHECK(tls_policy_out.mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT);
    CHECK(tls_policy_out.use_system_store == 0);
    CHECK(strcmp(tls_policy_out.pinned_sha256,
                 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") == 0);
    CHECK(librdp_settings_drive_count(copy) == 1);
    CHECK(strcmp(librdp_settings_drive_name(copy, 0), "C:") == 0);
    CHECK(strcmp(librdp_settings_drive_path(copy, 0), "/tmp") == 0);
    CHECK(librdp_settings_get_drive_policy(copy, 0, &drive_policy_out) == LIBRDP_STATUS_OK);
    CHECK(drive_policy_out.read_only == 0);
    CHECK(drive_policy_out.max_file_size == 65536u);
    CHECK(drive_policy_out.max_open_handles == 2u);
    CHECK(librdp_settings_get_usb_policy(copy, &usb_policy_out) == LIBRDP_STATUS_OK);
    CHECK(usb_policy_out.require_explicit_consent == 1);
    CHECK(usb_policy_out.allow_hid == 1);
    CHECK(usb_policy_out.allow_mass_storage == 1);
    CHECK(librdp_settings_serial_port_count(copy) == 1);
    CHECK(strcmp(librdp_settings_serial_port_name(copy, 0), "COM1:") == 0);
    CHECK(strcmp(librdp_settings_serial_port_path(copy, 0), "/dev/ttyS0") == 0);
    CHECK(librdp_settings_parallel_port_count(copy) == 1);
    CHECK(strcmp(librdp_settings_parallel_port_name(copy, 0), "LPT1:") == 0);
    CHECK(strcmp(librdp_settings_parallel_port_path(copy, 0), "/tmp/lpt1") == 0);
    CHECK(librdp_settings_printer_count(copy) == 1);
    CHECK(strcmp(librdp_settings_printer_name(copy, 0), "Print") == 0);
    CHECK(strcmp(librdp_settings_printer_driver(copy, 0), "Generic") == 0);
    CHECK(strcmp(librdp_settings_printer_output_path(copy, 0), "/tmp") == 0);
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_AUDIO_INPUT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_CAMERA));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_TELEMETRY));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_MULTITRANSPORT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_DESKTOP_COMPOSITION));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_DISPLAY_CONTROL));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_UDP_TRANSPORT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_UDP2_TRANSPORT));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_GEOMETRY_TRACKING));
    CHECK(librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_MULTIPARTY));
    CHECK(!librdp_settings_feature_enabled(copy, LIBRDP_FEATURE_AUDIO_OUTPUT));
    CHECK(strcmp(librdp_settings_audio_output_device(copy), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_audio_input_device(copy), "pipewire") == 0);
    CHECK(strcmp(librdp_settings_video_output_path(copy), "/tmp/video.bin") == 0);
    CHECK(strcmp(librdp_settings_camera_source(copy, 0), "device=/dev/video0") == 0);
    CHECK(strcmp(librdp_settings_smartcard_source(copy, 0), "pcsc") == 0);
    CHECK(strcmp(librdp_settings_usb_device_selector(copy, 0), "vid:pid=1234:5678") == 0);
    CHECK(librdp_settings_pnp_device_count(copy) == 1);
    CHECK(strcmp(librdp_settings_pnp_device_hardware_id(copy, 0), "LIBRDP\\PNP\\TEST_DEVICE") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_compatibility_id(copy, 0), "LIBRDP\\PNP\\TEST") == 0);
    CHECK(strcmp(librdp_settings_pnp_device_description(copy, 0), "Host test device") == 0);
    CHECK(librdp_settings_pnp_device_caps(copy, 0) ==
          (LIBRDP_PNP_DEVICE_CAP_REMOVABLE | LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK));
    CHECK(strcmp(librdp_settings_webauthn_provider(copy), "mock=/tmp/auth.json") == 0);
    CHECK(librdp_settings_webauthn_rp_id_count(copy) == 2);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(copy, 0), "example.com") == 0);
    CHECK(strcmp(librdp_settings_webauthn_rp_id(copy, 1), "login.example.com") == 0);
    CHECK(strcmp(librdp_settings_rail_app(copy, 0), "notepad.exe") == 0);
    CHECK(strcmp(librdp_settings_echo_payload(copy), "probe") == 0);
    CHECK(librdp_settings_set_gateway_config(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_get_gateway_config(settings, &gateway_config_out) == LIBRDP_STATUS_OK);
    CHECK(gateway_config_out.mode == LIBRDP_GATEWAY_DISABLED);

    surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);
    CHECK(librdp_surface_format(surface) == LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(librdp_surface_stride(surface) == 16);
    CHECK(librdp_surface_blit_bgra32(surface, 1, 1, 2, 2, pixels, 8) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_blit_bgra32(surface, 3, 3, 2, 2, pixels, 8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    out = librdp_surface_pixels(surface);
    CHECK(out[((size_t)1 * 16) + 4] == 1);
    CHECK(librdp_surface_mapping_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_mapping_init(&surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.version == LIBRDP_SURFACE_MAPPING_VERSION);
    CHECK(librdp_surface_map(NULL, LIBRDP_SURFACE_ACCESS_READ, &surface_map) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_map(surface, (librdp_surface_access)99, &surface_map) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.pixels == librdp_surface_pixels(surface));
    CHECK(surface_map.writable_pixels == NULL);
    CHECK(surface_map.width == 4 && surface_map.height == 4 && surface_map.stride == 16);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_blit_bgra32(surface, 0, 0, 1, 1, pixels, 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_mapping_init(&surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_unmap(surface, &surface_map2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_unmap(surface, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.pixels == NULL);
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(surface_map.writable_pixels != NULL);
    surface_map.writable_pixels[0] = 0xaau;
    CHECK(librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_READ, &surface_map2) == LIBRDP_STATUS_STATE);
    CHECK(librdp_surface_unmap(surface, &surface_map) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_pixels(surface)[0] == 0xaau);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_width(surface) == 2);
    CHECK(librdp_surface_pixels_mut(surface) != NULL);
    librdp_surface_free(surface);

    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0);
    key.flags = LIBRDP_KEY_FLAG_EXTENDED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x0100u);
    key.flags = 0;
    key.state = LIBRDP_KEY_RELEASED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x8000u);
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x9000u);
    mouse.state = LIBRDP_MOUSE_RELEASED;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x1000u);
    mouse.state = LIBRDP_MOUSE_MOVED;
    mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0800u);
    mouse.state = LIBRDP_MOUSE_PRESSED;
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_DOWN;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0388u);
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_LEFT;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0588u);
    mouse.button = LIBRDP_MOUSE_BUTTON_X1;
    CHECK(rdp_input_mouse_uses_extended(&mouse));
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x8001u);
    mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;

    memset(display_monitors, 0, sizeof(display_monitors));
    display_monitors[0].flags = LIBRDP_DISPLAY_MONITOR_PRIMARY;
    display_monitors[0].width = 800;
    display_monitors[0].height = 600;
    display_monitors[0].physical_width = 210;
    display_monitors[0].physical_height = 158;
    display_monitors[0].desktop_scale_factor = 100;
    display_monitors[0].device_scale_factor = 100;
    display_monitors[1].left = 800;
    display_monitors[1].width = 640;
    display_monitors[1].height = 480;
    display_monitors[1].physical_width = 169;
    display_monitors[1].physical_height = 127;
    display_monitors[1].desktop_scale_factor = 100;
    display_monitors[1].device_scale_factor = 100;
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    session_error = librdp_session_last_error(session);
    CHECK(session_error != NULL);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(session_error, &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_OK);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_NONE);
    CHECK(error_info.phase == NULL);
    CHECK(librdp_session_last_error(NULL) == NULL);
    CHECK(librdp_session_get_lifecycle(NULL) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_NEW);
    CHECK(librdp_metrics_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.version == LIBRDP_METRICS_VERSION);
    CHECK(metrics.size == sizeof(metrics));
    CHECK(librdp_session_get_metrics(NULL, &metrics) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_metrics(session, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    metrics.size = 0;
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 0);
    CHECK(librdp_session_reset_metrics(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_trace_policy(NULL, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = NULL;
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.callback = on_trace;
    trace_policy.callback_user_data = &trace;
    trace_policy.categories = 0x80000000u;
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 32;
    trace_policy.session_id = "session-1";
    trace_policy.connection_id = "connection-1";
    trace_policy.trace_id = "trace-1";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_set_trace_policy(session, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_feature_status(NULL,
                                            LIBRDP_FEATURE_TELEMETRY,
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_feature_status(session,
                                            (librdp_feature)(LIBRDP_FEATURE_AUDIO_INPUT |
                                                            LIBRDP_FEATURE_VIDEO),
                                            &feature_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_AUDIO_INPUT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_TELEMETRY,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_MULTITRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_UDP_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_UDP2_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_MULTIPARTY,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_DISPLAY_CONTROL,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.built && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_set_display_layout(NULL, display_monitors, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, NULL, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, display_monitors, 0) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session,
                                            display_monitors,
                                            LIBRDP_DISPLAY_MAX_MONITORS + 1u) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_set_display_layout(session, display_monitors, 2) == LIBRDP_STATUS_OK);
    display_monitors[1].left = 700;
    CHECK(librdp_session_set_display_layout(session, display_monitors, 2) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    CHECK(librdp_session_refresh(session, 0, 0, 1, 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_set_data(session,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            "t\0e\0x\0t\0\0",
                                            10) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_named_data(session,
                                                  LIBRDP_CLIPBOARD_FORMAT_HTML,
                                                  LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
                                                  "<p>x</p>",
                                                  8) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_named_data(NULL,
                                                  LIBRDP_CLIPBOARD_FORMAT_HTML,
                                                  LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
                                                  "<p>x</p>",
                                                  8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_set_named_data(session,
                                                  0,
                                                  LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
                                                  "<p>x</p>",
                                                  8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_set_named_data(session,
                                                  LIBRDP_CLIPBOARD_FORMAT_HTML,
                                                  NULL,
                                                  "<p>x</p>",
                                                  8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_set_named_data(session,
                                                  LIBRDP_CLIPBOARD_FORMAT_HTML,
                                                  "",
                                                  "<p>x</p>",
                                                  8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    {
        char path[] = "/tmp/librdp-clip-XXXXXX";
        int fd = mkstemp(path);
        librdp_clipboard_file file;

        CHECK(fd >= 0);
        CHECK(write(fd, "abcdef", 6) == 6);
        CHECK(close(fd) == 0);
        memset(&file, 0, sizeof(file));
        file.path = path;
        file.name = "clip.txt";
        CHECK(librdp_session_clipboard_set_files(session, &file, 1) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_clipboard_set_files(NULL, &file, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_session_clipboard_set_files(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(librdp_session_clipboard_set_files(session, &file, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
        CHECK(unlink(path) == 0);
        CHECK(librdp_session_clipboard_set_files(session, &file, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    CHECK(librdp_session_clipboard_request_data(session,
                                                LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_size(session, 1, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_range(session, 2, 0, 4, 16) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_clipboard_request_file_size(NULL, 1, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_file_size(session, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_file_range(session, 2, 0, 0, 0) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_clear(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_clipboard_set_data(NULL,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            "x",
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_set_data(session, 0, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_clipboard_request_data(session, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(NULL, 1, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 0, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_send(session, 1, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_close(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_close(session, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_close(session, 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_open_reply(NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_open_reply(session, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_send_data(NULL, "x", 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_data(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_data(session, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_audio_input_send_format_change(NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_audio_input_send_format_change(session, 0) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_video_capture_send_sample(NULL, 0, "x", 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_sample(session, 0, NULL, 1) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_sample(session, 0, "x", 1) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_video_capture_send_error(NULL,
                                                  0,
                                                  LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_video_capture_send_error(session,
                                                  0,
                                                  LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED) ==
          LIBRDP_STATUS_STATE);
    memset(&touch_contact, 0, sizeof(touch_contact));
    touch_contact.contact_id = 1;
    touch_contact.x = 100;
    touch_contact.y = 120;
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    touch_frame.contact_count = 1;
    touch_frame.frame_offset = 0;
    touch_frame.contacts = &touch_contact;
    CHECK(librdp_session_send_touch(NULL, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_STATE);
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN;
    CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    touch_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    {
        librdp_touch_contact duplicate_touch[2];

        duplicate_touch[0] = touch_contact;
        duplicate_touch[1] = touch_contact;
        touch_frame.contacts = duplicate_touch;
        touch_frame.contact_count = 2;
        CHECK(librdp_session_send_touch(session, 1, &touch_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        touch_frame.contacts = &touch_contact;
        touch_frame.contact_count = 1;
    }
    memset(&pen_contact, 0, sizeof(pen_contact));
    pen_contact.device_id = 1;
    pen_contact.fields_present = LIBRDP_PEN_PRESSURE_PRESENT;
    pen_contact.x = 100;
    pen_contact.y = 120;
    pen_contact.contact_flags = LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE | LIBRDP_CONTACT_INCONTACT;
    pen_contact.pressure = 512;
    pen_frame.contact_count = 1;
    pen_frame.frame_offset = 0;
    pen_frame.contacts = &pen_contact;
    CHECK(librdp_session_send_pen(NULL, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_STATE);
    pen_contact.pressure = 1025u;
    CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    pen_contact.pressure = 512u;
    {
        librdp_pen_contact duplicate_pen[2];

        duplicate_pen[0] = pen_contact;
        duplicate_pen[1] = pen_contact;
        pen_frame.contacts = duplicate_pen;
        pen_frame.contact_count = 2;
        CHECK(librdp_session_send_pen(session, 1, &pen_frame, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
        pen_frame.contacts = &pen_contact;
        pen_frame.contact_count = 1;
    }
    CHECK(librdp_session_dismiss_touch(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_dismiss_touch(session, 1) == LIBRDP_STATUS_STATE);
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_limits_init(&limits) == LIBRDP_STATUS_OK);
    limits.dynamic_channel_message_bytes = 4;
    CHECK(librdp_settings_set_limits(settings, &limits) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_clipboard_set_data(session, LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT, "abcdef", 6) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 1);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 0);
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_settings_set_limits(settings, NULL) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTIPARTY, 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_credentials_provider(settings,
                                                   on_credentials_provider,
                                                   &credentials_capture) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_ex(&test_port, &server_pid, 0, 0, 0, 1));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    librdp_session_free(session);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_graphics_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_pointer_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_channel_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_clipboard_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_audio_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_video_callback(NULL, on_domain_event, &domain_capture);
    librdp_session_set_graphics_update_callback(NULL, on_graphics_update, &graphics_capture);
    librdp_session_set_event_callback(session, on_event, &counter);
    librdp_session_set_event_envelope_callback(session, on_event_envelope, &envelope_capture);
    librdp_session_set_graphics_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_pointer_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_channel_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_clipboard_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_audio_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_video_callback(session, on_domain_event, &domain_capture);
    librdp_session_set_graphics_update_callback(session, on_graphics_update, &graphics_capture);
    memset(&trace, 0, sizeof(trace));
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = on_trace;
    trace_policy.callback_user_data = &trace;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 32;
    trace_policy.session_id = "session-1";
    trace_policy.connection_id = "connection-1";
    trace_policy.trace_id = "trace-1";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(credentials_capture.calls == 1);
    CHECK(secure_capture.failed == 0);
    CHECK(trace.count > 0);
    CHECK(trace.last_sequence == trace.count);
    CHECK(trace.saw_connect_start);
    CHECK(trace.saw_protocol);
    CHECK(trace.saw_ids);
    CHECK(trace.saw_line);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    CHECK(counter.states == 2);
    CHECK(envelope_capture.invalid == 0);
    CHECK(envelope_capture.state == 2);
    CHECK(counter.surfaces == 1);
    CHECK(envelope_capture.surface == 1);
    CHECK(counter.pointer >= 1);
    CHECK(domain_capture.invalid == 0);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(domain_capture.pointer == counter.pointer);
    CHECK(domain_capture.channel == 0);
    CHECK(domain_capture.clipboard == 0);
    CHECK(domain_capture.audio == 0);
    CHECK(domain_capture.video == 0);
    CHECK(domain_capture.reentrant_metrics == domain_capture.graphics + domain_capture.pointer);
    CHECK(graphics_capture.invalid == 0);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    CHECK(graphics_capture.desktop_resize == 0);
    CHECK(graphics_capture.surface_create == 0);
    CHECK(graphics_capture.surface_destroy == 0);
    CHECK(librdp_session_channel_list(session, NULL, 1, &channel_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    owner_capture.session = session;
    owner_capture.status = LIBRDP_STATUS_OK;
    CHECK(pthread_create(&owner_thread, NULL, owner_thread_main, &owner_capture) == 0);
    CHECK(pthread_join(owner_thread, NULL) == 0);
    CHECK(owner_capture.status == LIBRDP_STATUS_STATE);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_STATE);
    CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.refresh.owner") == 0);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_session_get_pollfds(NULL, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_pollfds(session, NULL, 0, &session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(session_pfd_count == 2);
    CHECK(librdp_session_get_pollfds(session, session_pfds, 0, &session_pfd_count) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_pollfds(session, session_pfds, 2, &session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(session_pfd_count == 2);
    CHECK(session_pfds[0].fd >= 0);
    CHECK(session_pfds[1].fd >= 0);
    CHECK((session_pfds[0].events & POLLIN) != 0);
    CHECK((session_pfds[1].events & POLLIN) != 0);
    CHECK(librdp_session_get_next_timeout(session, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_get_next_timeout(session, &next_timeout) == LIBRDP_STATUS_OK);
    CHECK(next_timeout == -1);
    CHECK(librdp_session_notify_poll(session, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    session_pfds[0].revents = 0;
    CHECK(librdp_session_notify_poll(session, session_pfds, session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_dispatch_pending(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    {
        int poll_rc = 0;

        do
        {
            poll_rc = poll(session_pfds, (nfds_t)session_pfd_count, 1000);
        } while (poll_rc < 0 && errno == EINTR);
        CHECK(poll_rc > 0);
    }
    CHECK(librdp_session_notify_poll(session, session_pfds, session_pfd_count) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_next_timeout(session, &next_timeout) == LIBRDP_STATUS_OK);
    CHECK(next_timeout == 0);
    CHECK(librdp_session_dispatch_pending(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 2);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    out = librdp_surface_pixels(session_surface);
    CHECK(out[0] == 9 && out[1] == 10 && out[2] == 11 && out[3] == 12);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 8);
    CHECK(domain_capture.graphics == counter.surfaces);
    CHECK(graphics_capture.pixel_rect == counter.surfaces);
    CHECK(graphics_capture.borrowed_pixels == graphics_capture.pixel_rect);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    out = librdp_surface_pixels(session_surface);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)2 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)3 * librdp_surface_stride(session_surface)) + ((size_t)8 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 0u] == 0x44u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 1u] == 0x55u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 2u] == 0x66u);
    CHECK(out[((size_t)4 * librdp_surface_stride(session_surface)) + ((size_t)12 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 0u] == 0x31u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 1u] == 0x32u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 2u] == 0x33u);
    CHECK(out[((size_t)6 * librdp_surface_stride(session_surface)) + ((size_t)16 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)32 * 4u) + 0u] == 0x12u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)32 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)32 * 4u) + 2u] == 0x32u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)32 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)33 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)33 * 4u) + 1u] == 0x21u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)33 * 4u) + 2u] == 0x31u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)33 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)36 * 4u) + 0u] == 0x12u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)36 * 4u) + 1u] == 0x22u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)36 * 4u) + 2u] == 0x32u);
    CHECK(out[((size_t)8 * librdp_surface_stride(session_surface)) + ((size_t)36 * 4u) + 3u] == 0xffu);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)37 * 4u) + 0u] == 0x11u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)37 * 4u) + 1u] == 0x21u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)37 * 4u) + 2u] == 0x31u);
    CHECK(out[((size_t)9 * librdp_surface_stride(session_surface)) + ((size_t)37 * 4u) + 3u] == 0xffu);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 1);
    CHECK(domain_capture.channel == 1);
    CHECK(librdp_session_channel_handle_for_id(session, 7, &channel_handle) == LIBRDP_STATUS_OK);
    CHECK(channel_handle != 0);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.handle == channel_handle);
    CHECK(channel_info.channel_id == 7);
    CHECK(channel_info.priority == LIBRDP_CHANNEL_PRIORITY_MEDIUM);
    CHECK(channel_info.active == 1);
    CHECK(channel_info.application_owned == 1);
    CHECK(channel_info.name_len == 6 && strcmp(channel_info.name, "APPDVC") == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_channel_info_init(&channel_infos[0]) == LIBRDP_STATUS_OK);
    CHECK(librdp_channel_info_init(&channel_infos[1]) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_list(session, channel_infos, 2, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 1);
    CHECK(channel_infos[0].handle == channel_handle);
    CHECK(librdp_channel_send_options_init(&channel_send_options) == LIBRDP_STATUS_OK);
    channel_send_options.handle = channel_handle;
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_REALTIME;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_OK);
    channel_send_options.priority = (librdp_channel_priority)4;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_LOW;
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_data == 1);
    CHECK(domain_capture.channel == 2);
    CHECK(counter.last_channel_id == 7);
    CHECK(counter.last_channel_data_len == 8);
    CHECK(memcmp(counter.last_channel_data, "abcdefgh", 8) == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_close == 1);
    CHECK(domain_capture.channel == 3);
    CHECK(librdp_session_channel_get_info(session, channel_handle, &channel_info) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_close_handle(session, channel_handle) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    CHECK(librdp_session_get_feature_status(session,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    CHECK(feature_status.requested && feature_status.backend_ready);
    CHECK(!feature_status.negotiated && !feature_status.active);
    CHECK(feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    CHECK(librdp_session_channel_open(NULL,
                                      "APPCHAN",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      NULL,
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "APPCHAN",
                                      (librdp_channel_priority)4,
                                      &client_channel_handle) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_channel_open(session,
                                      "APPCHAN",
                                      LIBRDP_CHANNEL_PRIORITY_REALTIME,
                                      &client_channel_handle) == LIBRDP_STATUS_OK);
    CHECK(client_channel_handle != 0);
    CHECK(librdp_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, client_channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.handle == client_channel_handle);
    CHECK(channel_info.channel_id == 1);
    CHECK(channel_info.priority == LIBRDP_CHANNEL_PRIORITY_REALTIME);
    CHECK(channel_info.active == 0);
    CHECK(channel_info.application_owned == 1);
    CHECK(channel_info.name_len == 7 && strcmp(channel_info.name, "APPCHAN") == 0);
    channel_send_options.handle = client_channel_handle;
    channel_send_options.priority = LIBRDP_CHANNEL_PRIORITY_LOW;
    CHECK(librdp_session_channel_send_ex(session, &channel_send_options, "ping", 4) == LIBRDP_STATUS_STATE);
    CHECK(librdp_session_channel_list(session, NULL, 0, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 0);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.channel_open == 2);
    CHECK(domain_capture.channel == 4);
    CHECK(counter.last_channel_id == 1);
    CHECK(librdp_session_channel_get_info(session, client_channel_handle, &channel_info) == LIBRDP_STATUS_OK);
    CHECK(channel_info.active == 1);
    CHECK(librdp_session_channel_list(session, channel_infos, 2, &channel_count) == LIBRDP_STATUS_OK);
    CHECK(channel_count == 1);
    CHECK(channel_infos[0].handle == client_channel_handle);
    CHECK(librdp_session_refresh(session, 0, 0, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_refresh(session, 0, 0, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    key.state = LIBRDP_KEY_PRESSED;
    CHECK(librdp_session_send_key(session, &key) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_send_mouse(session, &mouse) == LIBRDP_STATUS_OK);
    CHECK(trace.last_sequence == trace.count);
    CHECK(counter.keys == 1);
    CHECK(counter.mouse == 1);
    CHECK(librdp_session_resize(session, 80, 60) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 8);
    CHECK(counter.pointer >= 1);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_surface_height(session_surface) == 48);
    trace_fd = mkstemp(trace_file_path);
    CHECK(trace_fd >= 0);
    CHECK(close(trace_fd) == 0);
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.sink = LIBRDP_TRACE_SINK_FILE;
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_CLIENT;
    trace_policy.level = LIBRDP_TRACE_LEVEL_DEBUG;
    trace_policy.file_path = trace_file_path;
    trace_policy.trace_id = "file-trace";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_DISCONNECTED);
    CHECK(counter.disconnected == 1);
    CHECK(envelope_capture.disconnected == 1);
    {
        char file_trace[1024];
        int fd = open(trace_file_path, O_RDONLY);
        ssize_t got = 0;

        CHECK(fd >= 0);
        got = read(fd, file_trace, sizeof(file_trace) - 1u);
        CHECK(got > 0);
        file_trace[(size_t)got] = '\0';
        CHECK(close(fd) == 0);
        CHECK(strstr(file_trace, "client.disconnect.start") != NULL);
        CHECK(strstr(file_trace, "trace_id=file-trace") != NULL);
    }
    librdp_session_free(session);
    session = NULL;
    CHECK(librdp_settings_set_credentials_provider(settings, NULL, NULL) == LIBRDP_STATUS_OK);
    CHECK(unlink(trace_file_path) == 0);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    credentials_capture.fail = 1;
    CHECK(librdp_settings_set_credentials_provider(settings,
                                                   on_credentials_provider,
                                                   &credentials_capture) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_CLIENT);
    CHECK(error_info.phase != NULL && strcmp(error_info.phase, "client.credentials") == 0);
    CHECK(error_info.message != NULL && strstr(error_info.message, "provider") != NULL);
    CHECK(credentials_capture.password[0] != '\0');
    CHECK(error_info.message == NULL || strstr(error_info.message, credentials_capture.password) == NULL);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(credentials_capture.calls == 2);
    librdp_session_free(session);
    session = NULL;
    credentials_capture.fail = 0;
    CHECK(librdp_settings_set_credentials_provider(settings, NULL, NULL) == LIBRDP_STATUS_OK);

    memset(&counter, 0, sizeof(counter));
    server_pid = -1;
    child_status = 0;
    CHECK(start_handshake_server(&test_port, &server_pid, 0, 0x1234u));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    if (test_standard_security_available())
    {
        memset(&counter, 0, sizeof(counter));
        server_pid = -1;
        child_status = 0;
        CHECK(start_handshake_server(&test_port, &server_pid, 1, 0));
        CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
        session = librdp_session_new(settings);
        CHECK(session != NULL);
        librdp_session_set_event_callback(session, on_event, &counter);
        CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
        CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
        CHECK(counter.states == 2);
        cancel_capture.session = session;
        cancel_capture.delay_ms = 50;
        cancel_capture.status = LIBRDP_STATUS_AGAIN;
        CHECK(pthread_create(&cancel_thread, NULL, cancel_thread_main, &cancel_capture) == 0);
        CHECK(librdp_session_run_once(session, 5000) == LIBRDP_STATUS_CANCELLED);
        CHECK(pthread_join(cancel_thread, NULL) == 0);
        CHECK(cancel_capture.status == LIBRDP_STATUS_OK);
        CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CANCELLED);
        CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_DISCONNECTED);
        CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
        CHECK(error_info.status == LIBRDP_STATUS_CANCELLED);
        librdp_session_free(session);
        session = NULL;
        if (server_pid > 0)
        {
            CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
            CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
        }
    }

    librdp_settings_free(copy);
    librdp_settings_free(settings);
    CHECK(secure_capture.calls >= 3);
    CHECK(secure_capture.failed == 0);
    rdp_settings_secure_string_observer_for_tests(NULL, NULL);
    return 0;
}

int test_reconnect_policy(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_reconnect_policy policy;
    librdp_reconnect_policy bad_policy;
    librdp_metrics metrics;
    librdp_error_info error_info;
    uint16_t closed_port = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    CHECK(librdp_reconnect_policy_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_reconnect_policy_init(&policy) == LIBRDP_STATUS_OK);
    CHECK(policy.version == LIBRDP_RECONNECT_POLICY_VERSION);
    CHECK(policy.size == sizeof(policy));
    CHECK(policy.max_attempts == 1);
    CHECK(policy.initial_delay_ms == 0);
    CHECK(policy.max_delay_ms == 0);
    CHECK(reserve_closed_loopback_port(&closed_port));

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, closed_port) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_reconnect(NULL, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_session_reconnect(session, NULL) == LIBRDP_STATUS_STATE);

    status = librdp_session_connect(session);
    CHECK(status != LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);

    bad_policy = policy;
    bad_policy.version = 0;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.size = offsetof(librdp_reconnect_policy, max_delay_ms);
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.max_attempts = 0;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);
    bad_policy = policy;
    bad_policy.max_attempts = 65;
    CHECK(librdp_session_reconnect(session, &bad_policy) == LIBRDP_STATUS_INVALID_ARGUMENT);

    policy.max_attempts = 2;
    policy.initial_delay_ms = 0;
    policy.max_delay_ms = 0;
    status = librdp_session_reconnect(session, &policy);
    CHECK(status != LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.reconnects == 1);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status != LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: interrupts a connect blocked while waiting for the first server
 * handshake packet. It catches wakeups that only affect active dispatch and
 * cross-thread socket teardown that bypasses owner-thread cleanup.
 */
int test_connect_cancellation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    cancel_thread_capture cancel_capture;
    pthread_t cancel_thread;
    struct timespec started;
    struct timespec finished;
    uint64_t elapsed_ms = 0;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&cancel_capture, 0, sizeof(cancel_capture));
    CHECK(start_stalling_handshake_server(&test_port, &server_pid));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    cancel_capture.session = session;
    cancel_capture.delay_ms = 50;
    cancel_capture.status = LIBRDP_STATUS_AGAIN;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    CHECK(pthread_create(&cancel_thread, NULL, cancel_thread_main, &cancel_capture) == 0);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_CANCELLED);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &finished) == 0);
    CHECK(pthread_join(cancel_thread, NULL) == 0);
    elapsed_ms = ((uint64_t)(finished.tv_sec - started.tv_sec) * 1000u) +
                 ((uint64_t)(finished.tv_nsec >= started.tv_nsec ?
                                 finished.tv_nsec - started.tv_nsec :
                                 1000000000L + finished.tv_nsec - started.tv_nsec) /
                  1000000u);
    if (finished.tv_nsec < started.tv_nsec)
        elapsed_ms -= 1000u;
    CHECK(elapsed_ms < 1000u);
    CHECK(cancel_capture.status == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CANCELLED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_DISCONNECTED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: verifies that a peer withholding its first X.224 response reaches
 * the transport deadline, records the exact failure boundary, and closes the
 * connection without relying on peer EOF.
 */
int test_connect_timeout(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    CHECK(start_stalling_handshake_server(&test_port, &server_pid));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.trace_id = "connect-timeout";
    CHECK(librdp_session_set_trace_policy(session, &trace_policy) == LIBRDP_STATUS_OK);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_TIMEOUT);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_FAILED);
    CHECK(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error_info) == LIBRDP_STATUS_OK);
    CHECK(error_info.status == LIBRDP_STATUS_TIMEOUT);
    CHECK(error_info.os_errno == 0);
    CHECK(error_info.component == LIBRDP_ERROR_COMPONENT_TRANSPORT);
    CHECK(error_info.phase != NULL && strcmp(error_info.phase, "x224.negotiation.read") == 0);
    CHECK(error_info.trace_id != NULL && strcmp(error_info.trace_id, "connect-timeout") == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates reconnect success against a deterministic loopback peer
 * that accepts two handshakes on the same listener. It catches stale state,
 * missed activation transitions, and reconnect metrics drift without requiring
 * an external desktop endpoint.
 */
int test_reconnect_success(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_reconnect_policy policy;
    librdp_channel_handle stale_handle = 0;
    librdp_channel_info stale_info;
    librdp_metrics metrics;
    librdp_metrics before_loss;
    librdp_metrics after_loss;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    size_t i = 0;
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
                                       2,
                                       DVC_SCENARIO_NORMAL,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_open(session,
                                      "smoke.reconnect",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &stale_handle) == LIBRDP_STATUS_OK);
    CHECK(stale_handle != 0);
    CHECK(librdp_metrics_init(&before_loss) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &before_loss) == LIBRDP_STATUS_OK);
    for (i = 0;
         i < 8u && librdp_session_get_state(session) != LIBRDP_SESSION_CLOSED &&
         librdp_session_get_state(session) != LIBRDP_SESSION_FAILED;
         i++)
        status = librdp_session_run_once(session, 1000);
    CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_IO_ERROR ||
          status == LIBRDP_STATUS_CLOSED);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CLOSED ||
          librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_metrics_init(&after_loss) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &after_loss) == LIBRDP_STATUS_OK);
    CHECK(after_loss.transport_bytes_read >= before_loss.transport_bytes_read);
    CHECK(after_loss.transport_bytes_written >= before_loss.transport_bytes_written);
    CHECK(after_loss.pdu_in >= before_loss.pdu_in);
    CHECK(after_loss.pdu_out >= before_loss.pdu_out);
    CHECK(after_loss.channel_in >= before_loss.channel_in);
    CHECK(after_loss.channel_out >= before_loss.channel_out);
    if (librdp_session_get_state(session) == LIBRDP_SESSION_FAILED)
        CHECK(after_loss.errors > before_loss.errors);

    CHECK(librdp_reconnect_policy_init(&policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_reconnect(session, &policy) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVE);
    for (i = 0; i < 6u; i++)
        CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_channel_info_init(&stale_info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, stale_handle, &stale_info) == LIBRDP_STATUS_STATE);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.reconnects == 1);
    CHECK(metrics.transport_bytes_read >= after_loss.transport_bytes_read);
    CHECK(metrics.transport_bytes_written >= after_loss.transport_bytes_written);
    CHECK(metrics.pdu_in >= after_loss.pdu_in);
    CHECK(metrics.pdu_out >= after_loss.pdu_out);
    CHECK(metrics.surface_updates > 0);
    CHECK(metrics.channel_in > 0);
    CHECK(metrics.channel_out > 0);
    CHECK(librdp_session_reset_metrics(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.transport_bytes_read == 0);
    CHECK(metrics.transport_bytes_written == 0);
    CHECK(metrics.pdu_in == 0);
    CHECK(metrics.pdu_out == 0);
    CHECK(metrics.frames == 0);
    CHECK(metrics.surface_updates == 0);
    CHECK(metrics.channel_in == 0);
    CHECK(metrics.channel_out == 0);
    CHECK(metrics.channel_bytes_in == 0);
    CHECK(metrics.channel_bytes_out == 0);
    CHECK(metrics.errors == 0);
    CHECK(metrics.reconnects == 0);
    CHECK(metrics.limits_rejected == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}
