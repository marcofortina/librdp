/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public server API tests.
 * Coverage: versioned server config defaults, invalid metadata rejection, and
 * ownership of copied listener configuration.
 * Bug classes: ABI metadata drift, invalid size/version acceptance, bounds
 * mistakes, and cleanup of partially copied strings.
 * Determinism: runtime coverage binds only to loopback on an ephemeral port
 * and exchanges one synthetic connection request.
 */

#include <librdp/librdp.h>

#include "common/buffer.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/desktop_composition.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/pnp_redirection.h"
#include "channels/remote_programs.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCHECK(condition)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(condition))                                                                                             \
        {                                                                                                             \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition);                              \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

static int test_server_make_tls_files(char* cert_path,
                                      size_t cert_path_len,
                                      char* key_path,
                                      size_t key_path_len);
static void test_server_fill_secret(char* output, size_t output_len, uint32_t seed);

static const librdp_feature server_test_all_features[] = {
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

static int server_test_feature_reason_is_current(const librdp_feature_status* status)
{
    return status &&
           status->reason >= LIBRDP_FEATURE_REASON_NONE &&
           status->reason <= LIBRDP_FEATURE_REASON_NOT_ACTIVE;
}

static int test_server_config_defaults(void)
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
static int test_server_new_validates_metadata(void)
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

/*
 * Coverage: verifies that side transport features are built and backend-ready
 * only when the server has a real runtime path, while still remaining inactive
 * until a peer negotiates and uses the transport.
 */
static int test_server_transport_feature_gates(void)
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
static int test_server_public_feature_backend_readiness(void)
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
static int test_server_feature_status_reason_contract(void)
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

static int test_server_new_copies_strings(void)
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

static int test_server_connect_loopback(uint16_t port)
{
    struct sockaddr_in address;
    int fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr*)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int test_server_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int test_server_write_temp_path(char* output, size_t output_len, const char* suffix)
{
    int fd = -1;

    if (!output || output_len < 32 || !suffix)
        return -1;
    if (snprintf(output, output_len, "/tmp/librdp-server-test-%ld-%s-XXXXXX", (long)getpid(), suffix) >=
        (int)output_len)
        return -1;
    fd = mkstemp(output);
    return fd;
}

static int test_server_copy_file(const char* source_path, const char* target_path)
{
    uint8_t buffer[4096];
    FILE* source = NULL;
    FILE* target = NULL;
    size_t count = 0;
    int ok = 0;

    source = fopen(source_path, "rb");
    if (!source)
        return 0;
    target = fopen(target_path, "wb");
    if (!target)
    {
        fclose(source);
        return 0;
    }
    do
    {
        count = fread(buffer, 1u, sizeof(buffer), source);
        if (count > 0u && fwrite(buffer, 1u, count, target) != count)
            break;
        if (ferror(source))
            break;
    } while (count > 0u);
    ok = count == 0u && !ferror(source) && fflush(target) == 0;
    fclose(target);
    fclose(source);
    return ok;
}

static int test_server_make_tls_files(char* cert_path,
                                      size_t cert_path_len,
                                      char* key_path,
                                      size_t key_path_len)
{
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    X509_NAME* name = NULL;
    FILE* file = NULL;
    int cert_fd = -1;
    int key_fd = -1;
    int ok = 0;

    do
    {
        cert_fd = test_server_write_temp_path(cert_path, cert_path_len, "cert");
        key_fd = test_server_write_temp_path(key_path, key_path_len, "key");
        if (cert_fd < 0 || key_fd < 0)
            break;
        key = EVP_RSA_gen(2048);
        cert = X509_new();
        if (!key || !cert)
            break;
        if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
            X509_set_version(cert, 2) != 1 ||
            X509_set_pubkey(cert, key) != 1 ||
            !X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
            !X509_gmtime_adj(X509_get_notAfter(cert), 3600))
            break;
        name = X509_get_subject_name(cert);
        if (!name ||
            X509_NAME_add_entry_by_txt(name,
                                       "CN",
                                       MBSTRING_ASC,
                                       (const unsigned char*)"librdp-server-test",
                                       -1,
                                       -1,
                                       0) != 1 ||
            X509_set_issuer_name(cert, name) != 1 ||
            X509_sign(cert, key, EVP_sha256()) <= 0)
            break;
        file = fdopen(cert_fd, "w");
        if (!file)
            break;
        cert_fd = -1;
        if (PEM_write_X509(file, cert) != 1 || fclose(file) != 0)
        {
            file = NULL;
            break;
        }
        file = NULL;
        file = fdopen(key_fd, "w");
        if (!file)
            break;
        key_fd = -1;
        if (PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) != 1 || fclose(file) != 0)
        {
            file = NULL;
            break;
        }
        file = NULL;
        ok = 1;
    } while (0);
    if (file)
        fclose(file);
    if (cert_fd >= 0)
        close(cert_fd);
    if (key_fd >= 0)
        close(key_fd);
    X509_free(cert);
    EVP_PKEY_free(key);
    if (!ok)
    {
        if (cert_path)
            unlink(cert_path);
        if (key_path)
            unlink(key_path);
        ERR_clear_error();
    }
    return ok;
}

static int test_server_read_response(int fd, uint8_t* response, size_t response_len)
{
    struct pollfd pfd;
    ssize_t count = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    count = recv(fd, response, response_len, 0);
    return count > 0 ? (int)count : 0;
}

static int test_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, 0);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int test_server_tls_write_all(SSL* tls, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!tls || (!data && length > 0))
        return 0;
    while (offset < length)
    {
        int chunk = (length - offset) > (size_t)INT32_MAX ? INT32_MAX : (int)(length - offset);
        int written = SSL_write(tls, data + offset, chunk);

        if (written <= 0)
        {
            int error = SSL_get_error(tls, written);
            struct pollfd poll_fd;

            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return 0;
            memset(&poll_fd, 0, sizeof(poll_fd));
            poll_fd.fd = SSL_get_fd(tls);
            poll_fd.events = error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (poll_fd.fd < 0 || poll(&poll_fd, 1, 1000) <= 0)
                return 0;
            continue;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int test_server_tls_read_exact(SSL* tls, uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!tls || (!data && length > 0))
        return 0;
    while (offset < length)
    {
        size_t remaining = length - offset;
        int chunk = remaining > (size_t)INT32_MAX ? INT32_MAX : (int)remaining;
        int read_len = SSL_read(tls, data + offset, chunk);

        if (read_len <= 0)
        {
            int error = SSL_get_error(tls, read_len);
            struct pollfd poll_fd;

            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return 0;
            memset(&poll_fd, 0, sizeof(poll_fd));
            poll_fd.fd = SSL_get_fd(tls);
            poll_fd.events = error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (poll_fd.fd < 0 || poll(&poll_fd, 1, 1000) <= 0)
                return 0;
            continue;
        }
        offset += (size_t)read_len;
    }
    return 1;
}

static int test_server_tls_read_tpkt(SSL* tls, uint8_t* data, size_t capacity)
{
    uint16_t length = 0;

    if (!tls || !data || capacity < 4u)
        return 0;
    if (!test_server_tls_read_exact(tls, data, 4u))
        return 0;
    length = (uint16_t)(((uint32_t)data[2] << 8) | (uint32_t)data[3]);
    if (length < 4u || length > capacity)
        return 0;
    if (!test_server_tls_read_exact(tls, data + 4u, (size_t)length - 4u))
        return 0;
    return (int)length;
}

static int test_server_wait_peer_state(librdp_server_peer* peer, librdp_server_peer_state state)
{
    if (!peer)
        return 0;
    for (int attempt = 0; attempt < 100; attempt++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (librdp_server_peer_get_state(peer) == state)
            return 1;
        status = librdp_server_peer_run_once(peer, 10);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
            return 0;
    }
    return librdp_server_peer_get_state(peer) == state;
}

static int test_server_tls_read_credssp(SSL* tls, rdp_buffer* packet)
{
    uint8_t header[6];
    size_t header_len = 2u;
    size_t payload_len = 0;
    size_t total = 0;

    if (!tls || !packet)
        return 0;
    if (!test_server_tls_read_exact(tls, header, 2))
        return 0;
    if (header[0] != 0x30u)
        return 0;
    if ((header[1] & 0x80u) == 0)
        payload_len = header[1];
    else
    {
        size_t length_len = header[1] & 0x7fu;

        if (length_len == 0 || length_len > 4u)
            return 0;
        if (!test_server_tls_read_exact(tls, header + 2u, length_len))
            return 0;
        header_len += length_len;
        for (size_t i = 0; i < length_len; i++)
            payload_len = (payload_len << 8) | header[2u + i];
    }
    total = header_len + payload_len;
    if (total > 1048576u || rdp_buffer_append(packet, header, header_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_buffer_reserve(packet, total) != LIBRDP_STATUS_OK)
        return 0;
    if (!test_server_tls_read_exact(tls,
                                    packet->data + packet->length,
                                    total - packet->length))
        return 0;
    packet->length = total;
    return 1;
}

static int test_server_tls_public_key(SSL* tls, rdp_buffer* public_key)
{
    X509* certificate = NULL;
    EVP_PKEY* key = NULL;
    unsigned char* cursor = NULL;
    int encoded_len = 0;
    int written = 0;

    if (!tls || !public_key)
        return 0;
    certificate = SSL_get1_peer_certificate(tls);
    if (!certificate)
        return 0;
    key = X509_get_pubkey(certificate);
    X509_free(certificate);
    if (!key)
        return 0;
    encoded_len = i2d_PublicKey(key, NULL);
    if (encoded_len > 0 && rdp_buffer_reserve(public_key, (size_t)encoded_len) == LIBRDP_STATUS_OK)
    {
        cursor = public_key->data;
        written = i2d_PublicKey(key, &cursor);
        if (written == encoded_len)
            public_key->length = (size_t)written;
    }
    EVP_PKEY_free(key);
    return public_key->length > 0;
}

static void test_server_fill_secret(char* output, size_t output_len, uint32_t seed)
{
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    if (!output || output_len == 0)
        return;
    for (size_t i = 0; i + 1u < output_len; i++)
        output[i] = alphabet[(seed + (uint32_t)(i * 13u)) % (sizeof(alphabet) - 1u)];
    output[output_len - 1u] = '\0';
}

typedef struct test_server_nla_provider_context
{
    const char* domain;
    const char* username;
    const char* password;
    const char* workstation;
    uint32_t calls;
    uint32_t last_version;
    uint32_t last_failed_attempts;
    uint8_t last_public_key_bound;
    int reject;
} test_server_nla_provider_context;

enum
{
    TEST_SERVER_NLA_BAD_TS_VERSION = 1u << 0,
    TEST_SERVER_NLA_PROVIDER_REJECT = 1u << 1,
    TEST_SERVER_NLA_WRONG_PASSWORD = 1u << 2,
    TEST_SERVER_NLA_TAMPER_PUBLIC_KEY = 1u << 3,
    TEST_SERVER_NLA_TRUNCATED_CREDENTIALS = 1u << 4,
    TEST_SERVER_NLA_COMBINED_PUBLIC_KEY = 1u << 5
};

static librdp_status test_server_nla_provider(librdp_server_peer* peer,
                                              const librdp_server_credentials_request* request,
                                              librdp_credentials* credentials,
                                              void* user_data)
{
    test_server_nla_provider_context* context = (test_server_nla_provider_context*)user_data;

    if (!peer || !request || !credentials || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->calls++;
    context->last_version = request->ts_request_version;
    context->last_failed_attempts = request->failed_attempts;
    context->last_public_key_bound = request->public_key_bound;
    if (request->version != LIBRDP_SERVER_CREDENTIALS_REQUEST_VERSION ||
        request->size < sizeof(*request) ||
        !request->username ||
        strcmp(request->username, context->username) != 0 ||
        !request->domain ||
        strcmp(request->domain, context->domain) != 0 ||
        !request->workstation ||
        strcmp(request->workstation, context->workstation) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->reject)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return librdp_credentials_set(credentials,
                                  context->username,
                                  context->password,
                                  context->domain);
}

typedef struct test_server_runtime_context
{
    uint32_t input_count;
    uint32_t synchronize_count;
    uint32_t control_count;
    uint32_t font_list_count;
    uint32_t key_count;
    uint32_t channel_count;
    uint32_t dynamic_open_count;
    uint32_t dynamic_data_count;
    uint32_t dynamic_close_count;
    uint32_t dynamic_accept_count;
    uint32_t dynamic_reject_count;
    uint32_t extension_count;
    uint32_t state_event_count;
    uint32_t error_event_count;
    uint32_t surface_event_count;
    uint32_t channel_joined_event_count;
    librdp_server_peer_state last_old_state;
    librdp_server_peer_state last_new_state;
    librdp_status last_error_status;
    librdp_server_extension_family last_extension_family;
    librdp_feature last_extension_feature;
    uint32_t last_extension_message_type;
    uint32_t last_extension_flags;
    uint16_t last_channel_id;
    uint32_t last_dynamic_channel_id;
    uint32_t accepted_dynamic_channel_id;
    uint32_t rejected_dynamic_channel_id;
    uint8_t channel_payload[16];
    size_t channel_payload_len;
} test_server_runtime_context;

static void test_server_input_callback(librdp_server_peer* peer,
                                       const librdp_server_input_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->input_count++;
    if (event->type == LIBRDP_SERVER_INPUT_SYNCHRONIZE)
        context->synchronize_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_CONTROL)
        context->control_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_FONT_LIST)
        context->font_list_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
        context->key_count++;
}

static void test_server_channel_callback(librdp_server_peer* peer,
                                         const librdp_server_channel_event* event,
                                         void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;
    size_t copy_len = 0;

    (void)peer;
    if (!context || !event)
        return;
    context->channel_count++;
    context->last_channel_id = event->channel_id;
    context->last_dynamic_channel_id = event->dynamic_channel_id;
    if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN)
        context->dynamic_open_count++;
    else if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA)
        context->dynamic_data_count++;
    else if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE)
        context->dynamic_close_count++;
    copy_len = event->data_len > sizeof(context->channel_payload) ? sizeof(context->channel_payload) : event->data_len;
    if (copy_len > 0)
        memcpy(context->channel_payload, event->data, copy_len);
    context->channel_payload_len = copy_len;
}

static int test_server_dynamic_channel_accept_callback(librdp_server_peer* peer,
                                                       uint32_t dynamic_channel_id,
                                                       uint8_t priority,
                                                       const char* name,
                                                       size_t name_len,
                                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;
    int accepted = 1;

    (void)peer;
    (void)priority;
    if (name && name_len == 6u && memcmp(name, "DENIED", 6u) == 0)
        accepted = 0;
    if (context)
    {
        if (accepted)
        {
            context->dynamic_accept_count++;
            context->accepted_dynamic_channel_id = dynamic_channel_id;
        }
        else
        {
            context->dynamic_reject_count++;
            context->rejected_dynamic_channel_id = dynamic_channel_id;
        }
    }
    return accepted;
}

static void test_server_extension_callback(librdp_server_peer* peer,
                                           const librdp_server_extension_event* event,
                                           void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->extension_count++;
    context->last_extension_family = event->family;
    context->last_extension_feature = event->feature;
    context->last_extension_message_type = event->message_type;
    context->last_extension_flags = event->flags;
    context->last_channel_id = event->channel_id;
    context->last_dynamic_channel_id = event->dynamic_channel_id;
}

static void test_server_event_callback(librdp_server_peer* peer,
                                       const librdp_server_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    if (event->type == LIBRDP_SERVER_EVENT_STATE_CHANGED)
    {
        context->state_event_count++;
        context->last_old_state = event->old_state;
        context->last_new_state = event->new_state;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_ERROR)
    {
        context->error_event_count++;
        context->last_error_status = event->status;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_SURFACE)
    {
        context->surface_event_count++;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_CHANNEL_JOINED)
    {
        context->channel_joined_event_count++;
        context->last_channel_id = event->channel_id;
    }
}

static int test_server_build_client_mcs_connect_initial(rdp_buffer* tpkt)
{
    static const rdp_gcc_channel_definition extra_channels[8] = {
        {{'t', 'e', 's', 't', 'v', 'c', 0, 0}, 0xc0800000u},
        {{'c', 'l', 'i', 'p', 'r', 'd', 'r', 0}, 0xc0a00000u},
        {{'e', 'n', 'c', 'o', 'm', 's', 'p', 0}, 0xc0a00000u},
        {{'T', 'S', 'M', 'F', 0, 0, 0, 0}, 0xc0a00000u},
        {{'r', 'd', 'p', 'd', 'r', 0, 0, 0}, 0xc0a00000u},
        {{'P', 'N', 'P', 'D', 'R', 0, 0, 0}, 0xc0a00000u},
        {{'r', 'd', 'p', 's', 'n', 'd', 0, 0}, 0xc0a00000u},
        {{'r', 'a', 'i', 'l', 0, 0, 0, 0}, 0xc0a00000u}
    };
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs_initial;
    rdp_buffer x224_data;
    rdp_gcc_client_config config;
    int ok = 0;

    if (!tpkt)
        return 0;
    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&x224_data);
    memset(&config, 0, sizeof(config));
    config.desktop_width = 800;
    config.desktop_height = 600;
    config.requested_protocols = RDP_X224_PROTOCOL_STANDARD;
    config.client_name = "server-test";
    config.enable_dynamic_channels = 1;
    config.enable_multitransport = 1;
    config.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                  RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                  RDP_GCC_MULTITRANSPORT_UDP_PREFERRED;
    config.extra_channels = extra_channels;
    config.extra_channel_count = 8;
    if (rdp_gcc_write_client_data_blocks(&gcc_blocks, &config) == LIBRDP_STATUS_OK &&
        rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length) ==
            LIBRDP_STATUS_OK &&
        rdp_mcs_write_connect_initial(&mcs_initial, gcc_request.data, gcc_request.length) ==
            LIBRDP_STATUS_OK &&
        rdp_x224_wrap_data(&x224_data, mcs_initial.data, mcs_initial.length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&x224_data);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    return ok;
}

static int test_server_send_client_mcs_connect_initial(int fd)
{
    rdp_buffer tpkt;
    int ok = 0;

    rdp_buffer_init(&tpkt);
    if (test_server_build_client_mcs_connect_initial(&tpkt))
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    return ok;
}

static int test_server_send_mcs_pdu(int fd, const rdp_buffer* mcs_pdu)
{
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    int ok = 0;

    if (!mcs_pdu)
        return 0;
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    if (rdp_x224_wrap_data(&x224_data, mcs_pdu->data, mcs_pdu->length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    return ok;
}

static int test_server_append_mcs_tpkt(rdp_buffer* output, const rdp_buffer* mcs_pdu)
{
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    int ok = 0;

    if (!output || !mcs_pdu)
        return 0;
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    if (rdp_x224_wrap_data(&x224_data, mcs_pdu->data, mcs_pdu->length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(output, tpkt.data, tpkt.length) == LIBRDP_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    return ok;
}

static int test_server_send_channel_join(int fd, uint16_t user_id, uint16_t channel_id)
{
    rdp_buffer pdu;
    int ok = 0;

    rdp_buffer_init(&pdu);
    if (rdp_mcs_write_channel_join_request(&pdu, user_id, channel_id) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

static int test_server_send_confirm_active(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer confirm;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&confirm);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_slowpath_write_confirm_active(&confirm, share_id, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, 800, 600, "test") ==
            LIBRDP_STATUS_OK &&
        rdp_security_write_header(&security_payload, 0) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(&security_payload, confirm.data, confirm.length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&confirm);
    return ok;
}

static int test_server_send_slowpath(int fd, uint16_t user_id, const rdp_buffer* slowpath)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!slowpath)
        return 0;
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_security_write_header(&security_payload, 0) == LIBRDP_STATUS_OK &&
        rdp_buffer_append(&security_payload, slowpath->data, slowpath->length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return ok;
}

typedef enum test_server_security_tamper
{
    TEST_SERVER_SECURITY_TAMPER_NONE,
    TEST_SERVER_SECURITY_TAMPER_SIGNATURE,
    TEST_SERVER_SECURITY_TAMPER_CIPHERTEXT,
} test_server_security_tamper;

static int test_server_send_encrypted_slowpath(int fd,
                                               uint16_t user_id,
                                               rdp_standard_security_context* security,
                                               const rdp_buffer* slowpath,
                                               test_server_security_tamper tamper)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!security || !slowpath)
        return 0;
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_security_write_encrypted_pdu(&security_payload,
                                         security,
                                         0,
                                         slowpath->data,
                                         slowpath->length) == LIBRDP_STATUS_OK)
    {
        if (tamper == TEST_SERVER_SECURITY_TAMPER_SIGNATURE && security_payload.length > 4u)
            security_payload.data[4] ^= 0x80u;
        else if (tamper == TEST_SERVER_SECURITY_TAMPER_CIPHERTEXT && security_payload.length > 12u)
            security_payload.data[security_payload.length - 1u] ^= 0x01u;
        if (rdp_security_write_send_data_request(&send_data,
                                                 user_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 security_payload.data,
                                                 security_payload.length) == LIBRDP_STATUS_OK)
            ok = test_server_send_mcs_pdu(fd, &send_data);
    }
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return ok;
}

static int test_server_send_encrypted_channel_payload(int fd,
                                                      uint16_t user_id,
                                                      uint16_t channel_id,
                                                      rdp_standard_security_context* security,
                                                      const rdp_buffer* payload)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    int ok = 0;

    if (!security || !payload)
        return 0;
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (rdp_security_write_encrypted_pdu(&security_payload,
                                         security,
                                         0,
                                         payload->data,
                                         payload->length) == LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             channel_id,
                                             security_payload.data,
                                             security_payload.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return ok;
}

static int test_server_send_client_synchronize(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_synchronize(&slowpath,
                                              share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_control(int fd, uint32_t share_id, uint16_t user_id, uint16_t action)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_control(&slowpath,
                                          share_id,
                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                          action) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_font_list(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_font_list(&slowpath,
                                            share_id,
                                            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_keyboard_input(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_keyboard_input(&slowpath,
                                                 share_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 0,
                                                 30) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_sync_input(int fd, uint32_t share_id, uint16_t user_id)
{
    static const uint8_t payload[16] = {
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_data_pdu(&slowpath,
                                    share_id,
                                    (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                    RDP_SLOWPATH_DATA_PDU_INPUT,
                                    payload,
                                    sizeof(payload)) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_static_channel_data(int fd, uint16_t user_id, uint16_t channel_id)
{
    static const uint8_t payload[] = {1, 2, 3, 4};
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data, user_id, channel_id, payload, sizeof(payload)) ==
        LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_send_channel_payload(int fd, uint16_t user_id, uint16_t channel_id, const rdp_buffer* payload)
{
    rdp_buffer send_data;
    int ok = 0;

    if (!payload)
        return 0;
    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             channel_id,
                                             payload->data,
                                             payload->length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_read_tpkt_x224_data(int fd, uint8_t* buffer, size_t buffer_len, rdp_tpkt* tpkt)
{
    struct pollfd pfd;
    size_t total = 0;
    size_t offset = 0;

    if (!buffer || buffer_len < 4 || !tpkt)
        return 0;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    while (offset < 4u)
    {
        ssize_t count = recv(fd, buffer + offset, 4u - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    total = ((size_t)buffer[2] << 8) | buffer[3];
    if (total < 4u || total > buffer_len)
        return 0;
    while (offset < total)
    {
        ssize_t count = recv(fd, buffer + offset, total - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return rdp_tpkt_parse(buffer, total, tpkt) == LIBRDP_STATUS_OK;
}

static int test_server_read_encrypted_mcs_payload(int fd,
                                                  uint8_t* response,
                                                  size_t response_len,
                                                  rdp_standard_security_context* security,
                                                  rdp_buffer* plaintext)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    uint16_t flags = 0;

    if (!security || !plaintext)
        return 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK ||
        rdp_security_unwrap_pdu(security,
                                indication.payload,
                                indication.payload_len,
                                plaintext,
                                &flags) != LIBRDP_STATUS_OK ||
        (flags & RDP_SEC_ENCRYPT) == 0)
        return 0;
    return 1;
}

static int test_server_read_encrypted_slowpath_data_pdu(int fd,
                                                        uint8_t* response,
                                                        size_t response_len,
                                                        rdp_standard_security_context* security,
                                                        rdp_buffer* plaintext,
                                                        rdp_slowpath_data_pdu* data_pdu)
{
    int ok = 0;

    if (!plaintext)
        return 0;
    plaintext->length = 0;
    if (test_server_read_encrypted_mcs_payload(fd, response, response_len, security, plaintext) &&
        rdp_slowpath_parse_data_pdu(plaintext->data, plaintext->length, data_pdu) == LIBRDP_STATUS_OK)
        ok = 1;
    return ok;
}

static int test_server_read_encrypted_static_channel_data(int fd,
                                                          uint8_t* response,
                                                          size_t response_len,
                                                          rdp_standard_security_context* security,
                                                          rdp_buffer* plaintext,
                                                          uint16_t* channel_id,
                                                          const uint8_t** data,
                                                          size_t* data_len)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    uint16_t flags = 0;

    if (!security || !plaintext || !channel_id || !data || !data_len)
        return 0;
    plaintext->length = 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK ||
        rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK ||
        rdp_security_unwrap_pdu(security,
                                indication.payload,
                                indication.payload_len,
                                plaintext,
                                &flags) != LIBRDP_STATUS_OK ||
        (flags & RDP_SEC_ENCRYPT) == 0)
        return 0;
    *channel_id = indication.channel_id;
    *data = plaintext->data;
    *data_len = plaintext->length;
    return 1;
}

static int test_server_open_client_dynamic_channel(int fd,
                                                   librdp_server_peer* peer,
                                                   uint16_t user_id,
                                                   uint16_t static_channel_id,
                                                   uint32_t dynamic_channel_id,
                                                   const char* name,
                                                   uint8_t priority,
                                                   rdp_standard_security_context* security,
                                                   rdp_buffer* plaintext,
                                                   uint8_t* response,
                                                   size_t response_len)
{
    rdp_buffer dvc_packet;
    rdp_dynamic_channel_create_response create_response;
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    uint16_t response_channel_id = 0;
    int ok = 0;

    rdp_buffer_init(&dvc_packet);
    if (name &&
        rdp_dynamic_channel_write_create_request(&dvc_packet,
                                                 dynamic_channel_id,
                                                 1,
                                                 priority,
                                                 name,
                                                 strlen(name)) == LIBRDP_STATUS_OK &&
        test_server_send_channel_payload(fd, user_id, static_channel_id, &dvc_packet) &&
        librdp_server_peer_run_once(peer, 1000) == LIBRDP_STATUS_OK &&
        test_server_read_encrypted_static_channel_data(fd,
                                                       response,
                                                       response_len,
                                                       security,
                                                       plaintext,
                                                       &response_channel_id,
                                                       &dvc_payload,
                                                       &dvc_payload_len) &&
        response_channel_id == static_channel_id &&
        rdp_dynamic_channel_parse_create_response(dvc_payload,
                                                  dvc_payload_len,
                                                  &create_response) == LIBRDP_STATUS_OK &&
        create_response.channel_id == dynamic_channel_id &&
        create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
        ok = 1;
    rdp_buffer_free(&dvc_packet);
    return ok;
}

static int test_server_read_encrypted_dynamic_channel_payload(int fd,
                                                              uint8_t* response,
                                                              size_t response_len,
                                                              rdp_standard_security_context* security,
                                                              rdp_buffer* plaintext,
                                                              uint16_t static_channel_id,
                                                              uint32_t dynamic_channel_id,
                                                              rdp_dynamic_channel_data_pdu* data_response)
{
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    uint16_t response_channel_id = 0;

    if (!data_response)
        return 0;
    if (!test_server_read_encrypted_static_channel_data(fd,
                                                        response,
                                                        response_len,
                                                        security,
                                                        plaintext,
                                                        &response_channel_id,
                                                        &dvc_payload,
                                                        &dvc_payload_len) ||
        response_channel_id != static_channel_id)
        return 0;
    if (rdp_dynamic_channel_parse_data(dvc_payload, dvc_payload_len, data_response) != LIBRDP_STATUS_OK)
        return 0;
    return data_response->channel_id == dynamic_channel_id;
}

static int test_server_loopback_negotiation_failure(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    uint8_t response[64];
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.port = 0;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_accept(server, 0, &peer) == LIBRDP_STATUS_STATE);
    SCHECK(peer == NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_STATE);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    SCHECK(librdp_server_accept(server, 1, &peer) == LIBRDP_STATUS_TIMEOUT);
    SCHECK(peer == NULL);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    status = librdp_server_accept(server, 1000, &peer);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(send(client_fd, request, sizeof(request), 0) == (ssize_t)sizeof(request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 19);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x13);
    SCHECK(response[4] == 0x0e && response[5] == 0xd0);
    SCHECK(response[11] == 0x03 && response[13] == 0x08 && response[15] == 0x02);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    SCHECK(librdp_server_local_port(server) == 0);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

/*
 * Fixture: drives X.224 TLS negotiation and a local OpenSSL client/server
 * handshake before sending MCS over the encrypted stream. It catches security
 * downgrade regressions, missing certificate/key setup, TLS state lifetime
 * errors, and accidental raw-socket reads after the transport switches to TLS.
 */
static int test_server_loopback_tls_handshake(void)
{
    uint8_t response[65536];
    rdp_buffer request;
    rdp_buffer x224_request;
    rdp_buffer mcs_initial;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    SSL_CTX* client_context = NULL;
    SSL* client_tls = NULL;
    char cert_path[128];
    char key_path[128];
    int client_fd = -1;
    int response_len = 0;
    int tls_ready = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&x224_request);
    rdp_buffer_init(&mcs_initial);
    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));
    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_TLS) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_TLS_HANDSHAKING);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present);
    SCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_TLS);
    client_context = SSL_CTX_new(TLS_client_method());
    SCHECK(client_context != NULL);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, NULL);
    client_tls = SSL_new(client_context);
    SCHECK(client_tls != NULL);
    SCHECK(SSL_set_fd(client_tls, client_fd) == 1);
    for (int attempt = 0; attempt < 100 && !tls_ready; attempt++)
    {
        int rc = SSL_connect(client_tls);

        if (rc == 1)
            tls_ready = 1;
        else
        {
            int error = SSL_get_error(client_tls, rc);

            SCHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        }
        status = librdp_server_peer_run_once(peer, 0);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(test_server_wait_peer_state(peer, LIBRDP_SERVER_PEER_X224_CONFIRMED));
    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_tls_read_tpkt(client_tls, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);
    SSL_free(client_tls);
    SSL_CTX_free(client_context);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    unlink(cert_path);
    unlink(key_path);
    return 0;
}

/*
 * Fixture: negotiates X.224 TLS, then verifies that server-side TLS material
 * validation rejects a certificate/private-key mismatch before handshake bytes
 * are accepted. This catches collapsed TLS setup errors that would make
 * diagnostics unusable for embedders.
 */
static int test_server_loopback_tls_mismatched_key(void)
{
    uint8_t response[65536];
    rdp_buffer request;
    rdp_buffer x224_request;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    librdp_server_status server_status;
    char cert_path_a[128];
    char key_path_a[128];
    char cert_path_b[128];
    char key_path_b[128];
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&x224_request);
    memset(cert_path_a, 0, sizeof(cert_path_a));
    memset(key_path_a, 0, sizeof(key_path_a));
    memset(cert_path_b, 0, sizeof(cert_path_b));
    memset(key_path_b, 0, sizeof(key_path_b));
    SCHECK(test_server_make_tls_files(cert_path_a, sizeof(cert_path_a), key_path_a, sizeof(key_path_a)));
    SCHECK(test_server_make_tls_files(cert_path_b, sizeof(cert_path_b), key_path_b, sizeof(key_path_b)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_TLS;
    config.tls_certificate_path = cert_path_a;
    config.tls_private_key_path = key_path_a;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(test_server_copy_file(key_path_b, key_path_a));
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_TLS) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present && confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_TLS);
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED);
    SCHECK(strcmp(server_status.phase, "server.transport.tls.accept") == 0);
    SCHECK(strstr(server_status.message, "do not match") != NULL);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    unlink(cert_path_a);
    unlink(key_path_a);
    unlink(cert_path_b);
    unlink(key_path_b);
    return 0;
}

/*
 * Fixture: performs the complete server-side NLA exchange over a loopback TLS
 * transport, then sends one MCS Connect-Initial. It catches NLA negotiation
 * downgrades, NTLMv2 verification failures, public-key binding sequence bugs,
 * and accidental attempts to parse CredSSP as TPKT.
 */
static int test_server_loopback_nla_handshake_variant(uint32_t flags)
{
    uint8_t response[65536];
    uint8_t client_nonce[32];
    rdp_buffer request;
    rdp_buffer reply;
    rdp_buffer x224_request;
    rdp_buffer mcs_initial;
    rdp_buffer ntlm_negotiate;
    rdp_buffer spnego_negotiate;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_authenticate;
    rdp_buffer tls_public_key;
    rdp_buffer pub_key_auth;
    rdp_buffer auth_info;
    rdp_tpkt tpkt;
    rdp_x224_connection_confirm confirm;
    rdp_credssp_ts_request ts_response;
    rdp_credssp_ts_request pub_key_response;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_authenticate_result auth_result;
    rdp_ntlm_security_context ntlm_security;
    SSL_CTX* client_context = NULL;
    SSL* client_tls = NULL;
    const uint8_t* ntlm_token = NULL;
    size_t ntlm_token_len = 0;
    char cert_path[128];
    char key_path[128];
    int client_fd = -1;
    int response_len = 0;
    int tls_ready = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    test_server_nla_provider_context provider_context;
    char domain[32];
    char username[32];
    char password[32];
    char wrong_password[32];
    const char* workstation = "unit-rdp";
    const char* authenticate_password = NULL;
    uint32_t ts_request_version = 6;
    size_t final_auth_info_len = 0;
    uint16_t port = 0;

    rdp_buffer_init(&request);
    rdp_buffer_init(&reply);
    rdp_buffer_init(&x224_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&tls_public_key);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&auth_info);
    memset(&auth_result, 0, sizeof(auth_result));
    memset(&ntlm_security, 0, sizeof(ntlm_security));
    test_server_fill_secret(domain, sizeof(domain), 317u);
    test_server_fill_secret(username, sizeof(username), 331u);
    test_server_fill_secret(password, sizeof(password), 337u);
    test_server_fill_secret(wrong_password, sizeof(wrong_password), 341u);
    authenticate_password = (flags & TEST_SERVER_NLA_WRONG_PASSWORD) ? wrong_password : password;
    ts_request_version = (flags & TEST_SERVER_NLA_BAD_TS_VERSION) ? 5u : 6u;
    memset(&provider_context, 0, sizeof(provider_context));
    provider_context.domain = domain;
    provider_context.username = username;
    provider_context.password = password;
    provider_context.workstation = workstation;
    provider_context.reject = (flags & TEST_SERVER_NLA_PROVIDER_REJECT) != 0;
    for (size_t i = 0; i < sizeof(client_nonce); i++)
        client_nonce[i] = (uint8_t)i;
    memset(cert_path, 0, sizeof(cert_path));
    memset(key_path, 0, sizeof(key_path));

    SCHECK(test_server_make_tls_files(cert_path, sizeof(cert_path), key_path, sizeof(key_path)));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_NLA;
    config.tls_certificate_path = cert_path;
    config.tls_private_key_path = key_path;
    config.server_name = "unit-server";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_set_credentials_provider(server,
                                                  test_server_nla_provider,
                                                  &provider_context) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(test_server_set_nonblocking(client_fd));
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);

    SCHECK(rdp_x224_build_connection_request(&x224_request, NULL, RDP_X224_PROTOCOL_NLA) == LIBRDP_STATUS_OK);
    SCHECK(rdp_tpkt_write(&request, x224_request.data, x224_request.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_TLS_HANDSHAKING);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(rdp_x224_parse_connection_confirm(tpkt.payload, tpkt.payload_len, &confirm) == LIBRDP_STATUS_OK);
    SCHECK(confirm.negotiation.present);
    SCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_NLA);

    client_context = SSL_CTX_new(TLS_client_method());
    SCHECK(client_context != NULL);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, NULL);
    client_tls = SSL_new(client_context);
    SCHECK(client_tls != NULL);
    SCHECK(SSL_set_fd(client_tls, client_fd) == 1);
    for (int attempt = 0; attempt < 100 && !tls_ready; attempt++)
    {
        int rc = SSL_connect(client_tls);

        if (rc == 1)
            tls_ready = 1;
        else
        {
            int error = SSL_get_error(client_tls, rc);

            SCHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        }
        status = librdp_server_peer_run_once(peer, 0);
        SCHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
        if (librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING && tls_ready)
            break;
    }
    SCHECK(tls_ready);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING);
    SCHECK(test_server_tls_public_key(client_tls, &tls_public_key));

    request.length = 0;
    SCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, workstation, domain) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        ts_request_version,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & TEST_SERVER_NLA_BAD_TS_VERSION)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_read_credssp(client_tls, &reply));
    SCHECK(rdp_credssp_parse_ts_request(reply.data, reply.length, &ts_response) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_extract_ntlm_challenge(ts_response.nego_token,
                                              ts_response.nego_token_len,
                                              &ntlm_token,
                                              &ntlm_token_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_token, ntlm_token_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);

    SCHECK(rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                               &ntlm_challenge,
                                               username,
                                               authenticate_password,
                                               domain,
                                               workstation,
                                               0,
                                               NULL,
                                               NULL,
                                               &auth_result) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                      ntlm_authenticate.data,
                                                      ntlm_authenticate.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &auth_result) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                               client_nonce,
                                               sizeof(client_nonce),
                                               tls_public_key.data,
                                               tls_public_key.length,
                                               &pub_key_auth) == LIBRDP_STATUS_OK);
    if ((flags & TEST_SERVER_NLA_TAMPER_PUBLIC_KEY) && pub_key_auth.length > 0)
        pub_key_auth.data[pub_key_auth.length - 1u] ^= 0x40u;
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        ts_response.version,
                                        spnego_authenticate.data,
                                        spnego_authenticate.length,
                                        NULL,
                                        0,
                                        (flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) ? pub_key_auth.data : NULL,
                                        (flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) ? pub_key_auth.length : 0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    reply.length = 0;
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & (TEST_SERVER_NLA_PROVIDER_REJECT | TEST_SERVER_NLA_WRONG_PASSWORD))
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    if ((flags & TEST_SERVER_NLA_COMBINED_PUBLIC_KEY) == 0)
    {
        request.length = 0;
        SCHECK(rdp_credssp_write_ts_request(&request,
                                            ts_response.version,
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                            pub_key_auth.data,
                                            pub_key_auth.length,
                                            client_nonce,
                                            sizeof(client_nonce)) == LIBRDP_STATUS_OK);
        SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
        reply.length = 0;
        status = librdp_server_peer_run_once(peer, 1000);
    }
    if (flags & TEST_SERVER_NLA_TAMPER_PUBLIC_KEY)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_read_credssp(client_tls, &reply));
    SCHECK(rdp_credssp_parse_ts_request(reply.data, reply.length, &pub_key_response) == LIBRDP_STATUS_OK);
    SCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                              client_nonce,
                                              sizeof(client_nonce),
                                              tls_public_key.data,
                                              tls_public_key.length,
                                              pub_key_response.pub_key_auth,
                                              pub_key_response.pub_key_auth_len) == LIBRDP_STATUS_OK);

    SCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                    domain,
                                                    username,
                                                      password,
                                                      &auth_info) == LIBRDP_STATUS_OK);
    final_auth_info_len = auth_info.length;
    if (flags & TEST_SERVER_NLA_TRUNCATED_CREDENTIALS)
    {
        SCHECK(final_auth_info_len > 0);
        final_auth_info_len--;
    }
    request.length = 0;
    SCHECK(rdp_credssp_write_ts_request(&request,
                                        pub_key_response.version,
                                        NULL,
                                        0,
                                        auth_info.data,
                                        final_auth_info_len,
                                        NULL,
                                        0,
                                        client_nonce,
                                        sizeof(client_nonce)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_tls_write_all(client_tls, request.data, request.length));
    status = librdp_server_peer_run_once(peer, 1000);
    if (flags & TEST_SERVER_NLA_TRUNCATED_CREDENTIALS)
    {
        SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
        goto cleanup;
    }
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    SCHECK(provider_context.calls == 1);
    SCHECK(provider_context.last_version == 6);
    SCHECK(provider_context.last_failed_attempts == 0);
    SCHECK(provider_context.last_public_key_bound == 0);

    SCHECK(test_server_build_client_mcs_connect_initial(&mcs_initial));
    SCHECK(test_server_tls_write_all(client_tls, mcs_initial.data, mcs_initial.length));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    response_len = test_server_tls_read_tpkt(client_tls, response, sizeof(response));
    SCHECK(response_len > 0);
    SCHECK(rdp_tpkt_parse(response, (size_t)response_len, &tpkt) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);

cleanup:
    if (client_tls)
        SSL_free(client_tls);
    if (client_context)
        SSL_CTX_free(client_context);
    OPENSSL_cleanse(&ntlm_security, sizeof(ntlm_security));
    OPENSSL_cleanse(&auth_result, sizeof(auth_result));
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&tls_public_key);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_negotiate);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&x224_request);
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    librdp_server_peer_free(peer);
    if (server)
        librdp_server_close(server);
    librdp_server_free(server);
    if (client_fd >= 0)
        close(client_fd);
    unlink(cert_path);
    unlink(key_path);
    return 0;
}

static int test_server_loopback_nla_handshake(void)
{
    return test_server_loopback_nla_handshake_variant(0);
}

static int test_server_loopback_nla_combined_public_key(void)
{
    return test_server_loopback_nla_handshake_variant(TEST_SERVER_NLA_COMBINED_PUBLIC_KEY);
}

static int test_server_loopback_nla_reject_vectors(void)
{
    const uint32_t vectors[] = {
        TEST_SERVER_NLA_BAD_TS_VERSION,
        TEST_SERVER_NLA_PROVIDER_REJECT,
        TEST_SERVER_NLA_WRONG_PASSWORD,
        TEST_SERVER_NLA_TAMPER_PUBLIC_KEY,
        TEST_SERVER_NLA_TRUNCATED_CREDENTIALS,
    };

    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
    {
        if (test_server_loopback_nla_handshake_variant(vectors[i]) != 0)
            return 1;
    }
    return 0;
}

/*
 * Fixture: validates Standard Security signing and encryption with paired
 * client/server contexts without opening a socket.
 * Bug class: detects accepted signature tampering, ciphertext tampering,
 * secure-checksum sequence drift, and missing encrypt/decrypt counter updates.
 */
static int test_server_standard_security_tamper_vectors(void)
{
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    static const uint8_t payload[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    rdp_standard_security_context sender;
    rdp_standard_security_context receiver;
    rdp_buffer wire;
    rdp_buffer plaintext;
    uint16_t flags = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    for (size_t i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(0x10u + i);
        server_random[i] = (uint8_t)(0x80u + i);
    }

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_OK &&
           (flags & RDP_SEC_ENCRYPT) != 0 &&
           sender.encrypt_count == 1 &&
           receiver.decrypt_count == 1 &&
           plaintext.length == sizeof(payload) &&
           memcmp(plaintext.data, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    wire.data[4] ^= 0x40u;
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_encrypted_pdu(&wire, &sender, 0, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    wire.data[wire.length - 1u] ^= 0x01u;
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);

    memset(&sender, 0, sizeof(sender));
    memset(&receiver, 0, sizeof(receiver));
    rdp_buffer_init(&wire);
    rdp_buffer_init(&plaintext);
    SCHECK(rdp_security_standard_client_init(&sender,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_server_init(&receiver,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    sender.encrypt_count = 1;
    SCHECK(rdp_security_write_encrypted_pdu(&wire,
                                            &sender,
                                            (uint16_t)RDP_SEC_SECURE_CHECKSUM,
                                            payload,
                                            sizeof(payload)) == LIBRDP_STATUS_OK);
    status = rdp_security_unwrap_pdu(&receiver, wire.data, wire.length, &plaintext, &flags);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR && plaintext.length == 0);
    rdp_buffer_free(&plaintext);
    rdp_buffer_free(&wire);
    rdp_security_standard_clear(&sender);
    rdp_security_standard_clear(&receiver);
    OPENSSL_cleanse(client_random, sizeof(client_random));
    OPENSSL_cleanse(server_random, sizeof(server_random));
    return 0;
}

/*
 * Drives one in-process client/server pair through the server activation path.
 * The sequence catches truncated or misordered X.224/MCS/GCC wrapping,
 * channel-join accounting, Demand Active framing, and Confirm Active state
 * transition regressions without requiring a real desktop server.
 */
static int test_server_loopback_standard_activation_sequence(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t response[65536];
    rdp_tpkt tpkt;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_mcs_channel_join_confirm join_confirm;
    rdp_mcs_send_data_indication license_indication;
    rdp_license_error_alert license_alert;
    rdp_security_public_key server_public_key;
    rdp_standard_security_context client_security;
    rdp_dynamic_channel_capabilities dvc_caps;
    rdp_dynamic_channel_header dvc_header;
    rdp_dynamic_channel_create_request dvc_create_request;
    rdp_dynamic_channel_create_response dvc_create_response;
    rdp_dynamic_channel_data_pdu dvc_data_response;
    rdp_dynamic_channel_data_first_pdu dvc_data_first;
    rdp_dynamic_channel_close_pdu dvc_close;
    rdp_dynamic_channel_soft_sync_response soft_sync_response;
    rdp_clipboard_packet clipboard_packet;
    rdp_clipboard_capabilities clipboard_capabilities;
    rdp_clipboard_format_list clipboard_format_list;
    rdp_clipboard_format_entry clipboard_format_entry;
    rdp_clipboard_format_data_request clipboard_format_data_request;
    rdp_clipboard_format_data_response clipboard_format_data_response;
    rdp_clipboard_file_contents_request clipboard_file_contents_request;
    rdp_clipboard_file_contents_response clipboard_file_contents_response;
    rdp_clipboard_lock clipboard_lock;
    librdp_server_clipboard_state clipboard_state;
    rdp_echo_channel_pdu echo_response;
    rdp_display_control_monitor display_monitors[1];
    uint32_t display_monitor_count = 0;
    uint32_t clipboard_format_count = 0;
    rdp_graphics_header graphics_header;
    rdp_graphics_create_surface graphics_create;
    rdp_graphics_delete_surface graphics_delete;
    rdp_graphics_reset graphics_reset;
    rdp_graphics_start_frame graphics_start;
    rdp_graphics_end_frame graphics_end;
    rdp_graphics_wire_to_surface_1 graphics_wire;
    rdp_core_input_header core_input_header;
    rdp_input_channel_header input_channel_header;
    rdp_input_channel_sc_ready input_ready;
    rdp_mouse_cursor_header mouse_cursor_header;
    rdp_telemetry_pdu telemetry_pdu;
    rdp_multiparty_header multiparty_header;
    rdp_pnp_redirection_version pnp_version;
    rdp_pnp_redirection_info_header pnp_info;
    rdp_pnp_redirection_io_version pnp_io_version;
    rdp_pnp_redirection_create_request pnp_create;
    rdp_pnp_redirection_read_request pnp_read;
    rdp_pnp_redirection_write_request pnp_write;
    rdp_pnp_redirection_control_request pnp_control;
    rdp_pnp_redirection_cancel_request pnp_cancel;
    librdp_server_usb_device_capabilities usb_caps;
    rdp_usb_redirection_header usb_header;
    rdp_usb_redirection_add_device usb_device;
    rdp_usb_redirection_retract_device usb_retract;
    rdp_usb_redirection_io_completion usb_io_completion;
    rdp_usb_redirection_urb_completion usb_urb_completion;
    rdp_video_redirection_geometry_info geometry_info;
    rdp_video_redirection_geometry_update geometry_update;
    rdp_video_redirection_rect geometry_rect;
    rdp_video_redirection_capability_message video_caps;
    rdp_video_redirection_stream video_sample;
    rdp_video_optimized_video_data optimized_video;
    rdp_audio_output_header audio_output_header;
    rdp_audio_output_formats audio_output_formats;
    rdp_audio_output_wave2 audio_output_wave2;
    rdp_audio_input_formats audio_input_formats;
    rdp_audio_input_open audio_input_open;
    rdp_video_capture_device_notification camera_device;
    rdp_video_capture_media_list camera_media_list;
    rdp_video_capture_sample camera_sample;
    librdp_video_capture_media camera_media;
    rdp_webauthn_response webauthn_response;
    rdp_remote_programs_handshake_ex rail_handshake;
    rdp_remote_programs_exec_result rail_exec_result;
    rdp_remote_programs_windowmove rail_windowmove;
    rdp_composited_control cr2_control;
    rdp_composited_version_reply cr2_version_reply;
    rdp_composited_window_node_create cr2_window_node;
    rdp_auth_redirection_response auth_response;
    rdp_pointer_update pointer_update;
    rdp_desktop_composition_toggle composition_toggle;
    rdp_desktop_composition_lsurface composition_lsurface;
    rdp_gdi_altsec_order_header altsec_order;
    rdp_device_redirection_device_announce device_announce;
    rdp_device_redirection_device_announce provider_devices[4];
    rdp_device_redirection_device_reply device_reply;
    rdp_device_redirection_io_completion device_completion;
    rdp_gdi_orders_update gdi_update;
    rdp_gdi_order_list gdi_orders;
    rdp_udp_fec_header udp_header;
    rdp_udp_source_payload_header udp_source;
    rdp_udp_ack_vector udp_ack_vector;
    rdp_udp2_prefix udp2_prefix;
    rdp_udp2_packet udp2_packet;
    rdp_udp2_packet_kind udp2_kind = RDP_UDP2_PACKET_KIND_CONTROL;
    uint32_t udp2_ack_received = 0;
    uint32_t udp2_ack_lost = 0;
    librdp_server_dynamic_channel_info dynamic_info;
    rdp_buffer license_payload;
    rdp_buffer security_payload;
    rdp_buffer security_data;
    rdp_buffer encrypted_client_random;
    rdp_buffer demand_plaintext;
    rdp_buffer slowpath_plaintext;
    rdp_buffer channel_plaintext;
    rdp_buffer dvc_packet;
    rdp_buffer graphics_payload;
    rdp_buffer geometry_payload;
    rdp_buffer geometry_rect_payload;
    rdp_buffer udp_wire;
    rdp_buffer udp2_payload;
    rdp_buffer udp2_wire;
    rdp_buffer udp2_unwrapped;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_bitmap_update bitmap_update;
    librdp_server_static_channel_info static_info;
    librdp_server_metrics server_metrics;
    librdp_server_status server_status;
    librdp_server_extension_state extension_state;
    librdp_feature_status feature_status;
    test_server_runtime_context runtime_context;
    test_server_runtime_context device_family_context;
    librdp_server_clipboard_format clipboard_formats[1];
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    const uint8_t* static_payload = NULL;
    size_t static_payload_len = 0;
    const uint8_t* dvc_payload = NULL;
    size_t dvc_payload_len = 0;
    size_t udp_response_len = 0;
    size_t udp2_response_len = 0;
    size_t dynamic_fragmented_len = 0;
    int client_fd = -1;
    int response_len = 0;
    int extension_enabled = 0;
    size_t poll_count = 0;
    struct pollfd pollfds[2];
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;
    uint16_t dynamic_static_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t static_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 2u);
    uint16_t clipboard_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 3u);
    uint16_t multiparty_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 4u);
    uint16_t video_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 5u);
    uint16_t device_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 6u);
    uint16_t pnp_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 7u);
    uint16_t audio_output_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 8u);
    uint16_t rail_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 9u);
    uint16_t response_channel_id = 0;
    uint16_t security_flags = 0;
    uint32_t extension_count_before_echo = 0;
    uint32_t channel_count_before_static = 0;
    uint32_t extension_count_before_static = 0;
    uint32_t error_count_before_udp2 = 0;
    uint32_t error_count_before_dvc_limit = 0;
    uint32_t error_count_before_surface = 0;
    uint32_t dynamic_close_count_before_peer_close = 0;
    uint32_t dynamic_count_before_peer_close = 0;
    uint32_t graphics_frame_id = 0;
    uint32_t graphics_pending_frames = 0;
    uint32_t graphics_frame_limit = 0;
    uint32_t graphics_last_ack_frame_id = 0;
    uint16_t graphics_cap_count = 0;
    uint32_t graphics_cap_version = 0;
    uint32_t graphics_cap_flags = 0;
    uint64_t limits_before_dvc_limit = 0;
    librdp_server_extension_family provider_families[4] = {
        LIBRDP_SERVER_EXTENSION_PRINTER,
        LIBRDP_SERVER_EXTENSION_SERIAL_PORT,
        LIBRDP_SERVER_EXTENSION_PARALLEL_PORT,
        LIBRDP_SERVER_EXTENSION_SMARTCARD
    };
    size_t dvc_oversize_len = ((size_t)64u * 1024u * 1024u) + 1u;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    static const uint8_t clipboard_name_utf16[] = {'T', 0, 'e', 0, 'x', 0, 't', 0};
    static const uint8_t usb_instance_utf16[] = {'U', 0, 'S', 0, 'B', 0, 0, 0};
    static const uint8_t usb_ids_utf16[] = {'I', 0, 'D', 0, 0, 0, 0, 0};
    static const uint8_t usb_container_utf16[] = {'{', 0, '1', 0, '}', 0, 0, 0};
    static const uint8_t rail_app_utf16[] = {'a', 0, 'p', 0, 'p', 0, 0, 0};
    static const uint8_t camera_name_utf16[] = {'C', 0, 'a', 0, 'm', 0, 0, 0};
    librdp_audio_format public_pcm;
    uint32_t audio_input_version = 0;
    uint32_t cr2_versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
    uint32_t clipboard_clip_data_id = 0x8899aabbu;
    uint8_t presentation_id[16] = {
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t pixels[4u * 4u * 4u];
    uint8_t large_pixels[800u * 11u * 4u];
    uint8_t dynamic_large_payload[2000];
    uint8_t udp_response[256];
    uint8_t udp2_response[64];

    memset(&server_public_key, 0, sizeof(server_public_key));
    memset(&client_security, 0, sizeof(client_security));
    memset(&device_announce, 0, sizeof(device_announce));
    memset(provider_devices, 0, sizeof(provider_devices));
    memset(&public_pcm, 0, sizeof(public_pcm));
    memset(&camera_media, 0, sizeof(camera_media));
    public_pcm.format_tag = LIBRDP_AUDIO_FORMAT_PCM;
    public_pcm.channels = 2;
    public_pcm.samples_per_sec = 44100;
    public_pcm.avg_bytes_per_sec = 176400;
    public_pcm.block_align = 4;
    public_pcm.bits_per_sample = 16;
    rdp_buffer_init(&license_payload);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&security_data);
    rdp_buffer_init(&encrypted_client_random);
    rdp_buffer_init(&demand_plaintext);
    rdp_buffer_init(&slowpath_plaintext);
    rdp_buffer_init(&channel_plaintext);
    rdp_buffer_init(&dvc_packet);
    rdp_buffer_init(&graphics_payload);
    rdp_buffer_init(&geometry_payload);
    rdp_buffer_init(&geometry_rect_payload);
    rdp_buffer_init(&udp_wire);
    rdp_buffer_init(&udp2_payload);
    rdp_buffer_init(&udp2_wire);
    rdp_buffer_init(&udp2_unwrapped);
    memset(&runtime_context, 0, sizeof(runtime_context));
    memset(&device_family_context, 0, sizeof(device_family_context));
    memset(clipboard_formats, 0, sizeof(clipboard_formats));
    SCHECK(librdp_server_clipboard_state_init(&clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    clipboard_formats[0].format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    clipboard_formats[0].name = clipboard_name_utf16;
    clipboard_formats[0].name_len = sizeof(clipboard_name_utf16);
    memset(pixels, 0, sizeof(pixels));
    for (size_t pixel_index = 0; pixel_index < sizeof(pixels); pixel_index++)
        pixels[pixel_index] = (uint8_t)pixel_index;
    memset(large_pixels, 0x5a, sizeof(large_pixels));
    memset(dynamic_large_payload, 0x6b, sizeof(dynamic_large_payload));
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.server_name = "unit-server";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_TELEMETRY, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_MULTIPARTY, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_DESKTOP_COMPOSITION, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_GEOMETRY_TRACKING, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_PNP, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_USB, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_AUDIO_INPUT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_VIDEO, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_CAMERA, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_RAIL, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_CR2, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_MULTITRANSPORT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_UDP_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_UDP2_TRANSPORT, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_ECHO,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_TELEMETRY,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_MULTIPARTY,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_PNP,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_USB,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_AUDIO_INPUT,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_VIDEO,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CAMERA,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_WEBAUTHN,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_RAIL,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CR2,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION,
                                                   1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_get_extension_provider_status(server,
                                                       LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                       &extension_enabled) == LIBRDP_STATUS_OK);
    SCHECK(extension_enabled);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_MULTITRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_UDP_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_get_feature_status(server,
                                            LIBRDP_FEATURE_UDP2_TRANSPORT,
                                            &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_enable_feature(server, LIBRDP_FEATURE_VIDEO, 1) == LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_enable_extension_provider(server,
                                                   LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                   0) == LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_get_pollfds(server, NULL, 0, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1);
    SCHECK(librdp_server_get_pollfds(server, pollfds, 1, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1 && pollfds[0].fd >= 0 && (pollfds[0].events & POLLIN));
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    for (size_t i = 0; i < sizeof(server_test_all_features) / sizeof(server_test_all_features[0]); i++)
    {
        SCHECK(librdp_server_peer_get_feature_status(peer,
                                                     server_test_all_features[i],
                                                     &feature_status) == LIBRDP_STATUS_OK);
        SCHECK(server_test_feature_reason_is_current(&feature_status));
    }
    SCHECK(librdp_server_peer_get_extension_provider_status(NULL,
                                                            LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                            &extension_enabled) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_get_extension_provider_status(peer,
                                                            LIBRDP_SERVER_EXTENSION_UNKNOWN,
                                                            &extension_enabled) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_get_extension_provider_status(peer,
                                                            LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                            NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_get_extension_provider_status(peer,
                                                            LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                            &extension_enabled) ==
           LIBRDP_STATUS_OK);
    SCHECK(extension_enabled);
    SCHECK(librdp_server_peer_enable_extension_provider(NULL,
                                                        LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                        1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_enable_extension_provider(peer,
                                                        LIBRDP_SERVER_EXTENSION_UNKNOWN,
                                                        1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_enable_extension_provider(peer,
                                                        LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING,
                                                        0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_peer_enable_extension_provider(peer,
                                                        LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING,
                                                        1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.backend_ready &&
           feature_status.reason == LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE);
    SCHECK(librdp_server_peer_set_input_callback(peer, test_server_input_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_channel_callback(peer, test_server_channel_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_dynamic_channel_accept_callback(NULL,
                                                                  test_server_dynamic_channel_accept_callback,
                                                                  &runtime_context) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_dynamic_channel_accept_callback(peer,
                                                                  test_server_dynamic_channel_accept_callback,
                                                                  &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_extension_callback(NULL,
                                                     test_server_extension_callback,
                                                     &runtime_context) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_extension_callback(peer, test_server_extension_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_extension_family_callback(NULL,
                                                            LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION,
                                                            test_server_extension_callback,
                                                            &device_family_context) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_extension_family_callback(peer,
                                                            LIBRDP_SERVER_EXTENSION_UNKNOWN,
                                                            test_server_extension_callback,
                                                            &device_family_context) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_extension_family_callback(peer,
                                                            LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION,
                                                            test_server_extension_callback,
                                                            &device_family_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_event_callback(NULL,
                                                 test_server_event_callback,
                                                 &runtime_context) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_event_callback(peer, test_server_event_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_enable_feature_provider(NULL,
                                                      LIBRDP_FEATURE_ECHO,
                                                      1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_enable_feature_provider(peer,
                                                      LIBRDP_FEATURE_UDP_TRANSPORT,
                                                      1) == LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(librdp_server_peer_enable_feature_provider(peer,
                                                      (librdp_feature)(LIBRDP_FEATURE_ECHO |
                                                                       LIBRDP_FEATURE_TELEMETRY |
                                                                       LIBRDP_FEATURE_MULTIPARTY |
                                                                       LIBRDP_FEATURE_DESKTOP_COMPOSITION |
                                                                       LIBRDP_FEATURE_GEOMETRY_TRACKING |
                                                                       LIBRDP_FEATURE_AUDIO_OUTPUT |
                                                                       LIBRDP_FEATURE_AUDIO_INPUT |
                                                                       LIBRDP_FEATURE_VIDEO |
                                                                       LIBRDP_FEATURE_CAMERA |
                                                                       LIBRDP_FEATURE_WEBAUTHN |
                                                                       LIBRDP_FEATURE_RAIL |
                                                                       LIBRDP_FEATURE_CR2),
                                                      1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_enable_extension_provider(peer,
                                                        LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR,
                                                        1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_enable_extension_provider(peer,
                                                        LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION,
                                                        1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(NULL, &server_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_get_last_status(peer, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    server_status.version = 0;
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    SCHECK(librdp_server_peer_get_pollfds(peer, NULL, 0, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1);
    SCHECK(librdp_server_peer_get_pollfds(peer, pollfds, 1, &poll_count) == LIBRDP_STATUS_OK);
    SCHECK(poll_count == 1 && pollfds[0].fd >= 0 && (pollfds[0].events & POLLIN));
    SCHECK(test_server_send_all(client_fd, request, sizeof(request)));
    SCHECK(poll(pollfds, 1, 1000) == 1);
    SCHECK(librdp_server_peer_notify_poll(peer, pollfds, 1) == LIBRDP_STATUS_OK);
    status = librdp_server_peer_dispatch_pending(peer);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    SCHECK(runtime_context.state_event_count >= 2);
    SCHECK(runtime_context.last_new_state == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 11);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x0b);
    SCHECK(response[4] == 0x06 && response[5] == 0xd0);
    SCHECK(test_server_send_client_mcs_connect_initial(client_fd));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_connect_response(x224_data, x224_data_len, &mcs_response) == LIBRDP_STATUS_OK);
    SCHECK(mcs_response.result == 0);
    SCHECK(rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                    mcs_response.user_data_len,
                                                    &gcc_response) == LIBRDP_STATUS_OK);
    SCHECK(gcc_response.result == 0);
    SCHECK(rdp_gcc_parse_server_data_blocks(gcc_response.user_data,
                                            gcc_response.user_data_len,
                                            &server_data) == LIBRDP_STATUS_OK);
    SCHECK(server_data.has_core && server_data.has_security && server_data.has_network);
    SCHECK(server_data.has_multitransport);
    SCHECK((server_data.multitransport_flags &
            (RDP_GCC_MULTITRANSPORT_UDP_FECR |
             RDP_GCC_MULTITRANSPORT_UDP_FECL |
             RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP)) ==
           (RDP_GCC_MULTITRANSPORT_UDP_FECR |
            RDP_GCC_MULTITRANSPORT_UDP_FECL |
            RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP));
    SCHECK(server_data.encryption_method == RDP_SECURITY_METHOD_128BIT);
    SCHECK(server_data.encryption_level == 3);
    SCHECK(server_data.server_random_len == RDP_SECURITY_CLIENT_RANDOM_LEN);
    SCHECK(server_data.server_certificate_len > 64u);
    SCHECK(server_data.mcs_channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    SCHECK(librdp_server_peer_desktop_width(peer) == 800);
    SCHECK(librdp_server_peer_desktop_height(peer) == 600);
    SCHECK(librdp_server_peer_static_channel_count(peer) == 9);
    SCHECK(librdp_server_static_channel_info_init(&static_info) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == dynamic_static_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "drdynvc") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 1, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == static_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "testvc") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 2, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == clipboard_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "cliprdr") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 3, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == multiparty_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "encomsp") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 4, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == video_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 5, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == device_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, RDP_DEVICE_REDIRECTION_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 6, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == pnp_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, RDP_PNP_REDIRECTION_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 7, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == audio_output_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, RDP_AUDIO_OUTPUT_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 8, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == rail_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, RDP_REMOTE_PROGRAMS_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 9, &static_info) == LIBRDP_STATUS_INVALID_ARGUMENT);

    {
        rdp_buffer coalesced;
        rdp_buffer erect;
        rdp_buffer attach;

        rdp_buffer_init(&coalesced);
        rdp_buffer_init(&erect);
        rdp_buffer_init(&attach);
        SCHECK(rdp_mcs_write_erect_domain_request(&erect) == LIBRDP_STATUS_OK);
        SCHECK(rdp_mcs_write_attach_user_request(&attach) == LIBRDP_STATUS_OK);
        SCHECK(test_server_append_mcs_tpkt(&coalesced, &erect));
        SCHECK(test_server_append_mcs_tpkt(&coalesced, &attach));
        SCHECK(test_server_send_all(client_fd, coalesced.data, coalesced.length));
        rdp_buffer_free(&attach);
        rdp_buffer_free(&erect);
        rdp_buffer_free(&coalesced);
    }
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_DOMAIN_READY);

    status = librdp_server_peer_run_once(peer, 0);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_USER_ATTACHED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_attach_user_confirm(x224_data, x224_data_len, &attach_confirm) == LIBRDP_STATUS_OK);
    SCHECK(attach_confirm.result == 0 && attach_confirm.user_id == RDP_MCS_BASE_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == attach_confirm.user_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, RDP_MCS_GLOBAL_CHANNEL_ID));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, dynamic_static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == dynamic_static_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 2);
    SCHECK(runtime_context.last_channel_id == static_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == static_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, clipboard_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 3);
    SCHECK(runtime_context.last_channel_id == clipboard_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == clipboard_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, multiparty_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 4);
    SCHECK(runtime_context.last_channel_id == multiparty_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == multiparty_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, video_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 5);
    SCHECK(runtime_context.last_channel_id == video_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == video_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, device_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 6);
    SCHECK(runtime_context.last_channel_id == device_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == device_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, pnp_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 7);
    SCHECK(runtime_context.last_channel_id == pnp_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == pnp_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, audio_output_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(runtime_context.channel_joined_event_count == 8);
    SCHECK(runtime_context.last_channel_id == audio_output_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == audio_output_channel_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, rail_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_LICENSING);
    SCHECK(runtime_context.channel_joined_event_count == 9);
    SCHECK(runtime_context.last_channel_id == rail_channel_id);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == rail_channel_id);

    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 1, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 2, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 3, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 4, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 5, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 6, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 7, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 8, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &license_indication) == LIBRDP_STATUS_OK);
    SCHECK(license_indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    SCHECK(rdp_security_unwrap_pdu(NULL,
                                   license_indication.payload,
                                   license_indication.payload_len,
                                   &license_payload,
                                   &security_flags) == LIBRDP_STATUS_OK);
    SCHECK(security_flags == (RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    SCHECK(rdp_license_parse_error_alert(license_payload.data,
                                         license_payload.length,
                                         &license_alert) == LIBRDP_STATUS_OK);
    SCHECK(rdp_license_error_alert_is_terminal_success(&license_alert));
    SCHECK(rdp_security_parse_server_certificate(server_data.server_certificate,
                                                 server_data.server_certificate_len,
                                                 &server_public_key) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_encrypt_client_random(&server_public_key, client_random, &encrypted_client_random) ==
           LIBRDP_STATUS_OK);
    SCHECK(rdp_security_standard_client_init(&client_security,
                                             server_data.encryption_method,
                                             client_random,
                                             server_data.server_random) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_exchange_pdu(&security_payload,
                                           encrypted_client_random.data,
                                           encrypted_client_random.length) == LIBRDP_STATUS_OK);
    SCHECK(rdp_security_write_send_data_request(&security_data,
                                                attach_confirm.user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                security_payload.data,
                                                security_payload.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_mcs_pdu(client_fd, &security_data));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_LICENSING);
    security_payload.length = 0;
    security_data.length = 0;
    {
        rdp_client_info info;
        char info_password[32];
        char info_username[32];

        memset(&info, 0, sizeof(info));
        test_server_fill_secret(info_username, sizeof(info_username), 347u);
        test_server_fill_secret(info_password, sizeof(info_password), 353u);
        info.username = info_username;
        info.password = info_password;
        SCHECK(rdp_security_write_encrypted_client_info_pdu(&security_payload, &client_security, &info) ==
               LIBRDP_STATUS_OK);
    }
    SCHECK(rdp_security_write_send_data_request(&security_data,
                                                attach_confirm.user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                security_payload.data,
                                                security_payload.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_mcs_pdu(client_fd, &security_data));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_encrypted_mcs_payload(client_fd,
                                                  response,
                                                  sizeof(response),
                                                  &client_security,
                                                  &demand_plaintext));
    SCHECK(rdp_slowpath_parse_demand_active(demand_plaintext.data,
                                            demand_plaintext.length,
                                            &demand) == LIBRDP_STATUS_OK);
    SCHECK(demand.share_id == 0x00010001u);
    SCHECK(demand.capabilities.count == 11);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BRUSH) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_SOUND) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_CONTROL) == NULL);
    SCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_ACTIVATION) == NULL);

    SCHECK(test_server_send_confirm_active(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 4);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 2);

    SCHECK(test_server_send_client_synchronize(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 4));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 1));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_font_list(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE);
    SCHECK(runtime_context.control_count == 2);
    SCHECK(runtime_context.font_list_count == 1);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP &&
           data_pdu.payload_len == 8);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_DESKTOP_COMPOSITION,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_send_desktop_composition_start(peer) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_gdi_parse_slow_orders_update_payload(data_pdu.payload,
                                                    data_pdu.payload_len,
                                                    &gdi_update) == LIBRDP_STATUS_OK);
    SCHECK(gdi_update.number_orders == 1);
    SCHECK(rdp_gdi_parse_order_list(gdi_update.order_data,
                                    gdi_update.order_data_len,
                                    gdi_update.number_orders,
                                    RDP_GDI_ORDER_DSTBLT,
                                    &gdi_orders) == LIBRDP_STATUS_OK);
    SCHECK(gdi_orders.count == 1 &&
           gdi_orders.orders[0].kind == RDP_GDI_ORDER_KIND_ALTSEC &&
           gdi_orders.orders[0].order_type == RDP_GDI_ALTSEC_COMPDESK_FIRST);
    SCHECK(librdp_server_peer_send_desktop_composition_toggle(
               peer,
               RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_gdi_parse_slow_orders_update_payload(data_pdu.payload,
                                                    data_pdu.payload_len,
                                                    &gdi_update) == LIBRDP_STATUS_OK);
    SCHECK(gdi_update.number_orders == 1);
    SCHECK(rdp_gdi_parse_altsec_order(gdi_update.order_data,
                                      gdi_update.order_data_len,
                                      &altsec_order) == LIBRDP_STATUS_OK);
    SCHECK(altsec_order.order_type == RDP_GDI_ALTSEC_COMPDESK_FIRST);
    SCHECK(rdp_desktop_composition_parse_toggle(altsec_order.payload,
                                                altsec_order.payload_len,
                                                &composition_toggle) == LIBRDP_STATUS_OK);
    SCHECK(composition_toggle.event_type == RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON);
    SCHECK(librdp_server_peer_send_desktop_composition_lsurface(
               peer,
               1,
               RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION,
               0x1122334455667788u,
               640,
               480,
               0x0102030405060708u,
               0x8877665544332211u) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_gdi_parse_slow_orders_update_payload(data_pdu.payload,
                                                    data_pdu.payload_len,
                                                    &gdi_update) == LIBRDP_STATUS_OK);
    SCHECK(gdi_update.number_orders == 1);
    SCHECK(rdp_gdi_parse_altsec_order(gdi_update.order_data,
                                      gdi_update.order_data_len,
                                      &altsec_order) == LIBRDP_STATUS_OK);
    SCHECK(altsec_order.order_type == RDP_GDI_ALTSEC_COMPDESK_FIRST);
    SCHECK(rdp_desktop_composition_parse_lsurface(altsec_order.payload,
                                                  altsec_order.payload_len,
                                                  &composition_lsurface) == LIBRDP_STATUS_OK);
    SCHECK(composition_lsurface.create == 1 &&
           composition_lsurface.width == 640 &&
           composition_lsurface.height == 480);
    device_announce.device_type = RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
    device_announce.device_id = 0x44440001u;
    memcpy(device_announce.preferred_dos_name, "DRIVE", 5u);
    dvc_packet.length = 0;
    SCHECK(rdp_device_redirection_write_device_list_announce(&dvc_packet,
                                                             &device_announce,
                                                             1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            device_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.last_extension_family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION);
    SCHECK(runtime_context.last_extension_message_type ==
           RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE);
    SCHECK(device_family_context.extension_count == 1);
    SCHECK(device_family_context.last_extension_family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION);
    SCHECK(device_family_context.last_extension_message_type ==
           RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.negotiated && extension_state.active && extension_state.open &&
           extension_state.static_channel_id == device_channel_id &&
           extension_state.open_count == 1);
    SCHECK(librdp_server_peer_send_device_reply(peer,
                                                device_channel_id,
                                                LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                                                device_announce.device_id,
                                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == device_channel_id);
    SCHECK(rdp_device_redirection_parse_device_reply(static_payload,
                                                     static_payload_len,
                                                     &device_reply) == LIBRDP_STATUS_OK);
    SCHECK(device_reply.device_id == device_announce.device_id &&
           device_reply.result_code == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    SCHECK(librdp_server_peer_send_device_io_completion(peer,
                                                        device_channel_id,
                                                        LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                                                        device_announce.device_id,
                                                        0x44u,
                                                        RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                        "fs",
                                                        2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == device_channel_id);
    SCHECK(rdp_device_redirection_parse_io_completion(static_payload,
                                                      static_payload_len,
                                                      &device_completion) == LIBRDP_STATUS_OK);
    SCHECK(device_completion.device_id == device_announce.device_id &&
           device_completion.completion_id == 0x44u &&
           device_completion.payload_len == 2 &&
           memcmp(device_completion.payload, "fs", 2) == 0);
    provider_devices[0].device_type = RDP_DEVICE_REDIRECTION_TYPE_PRINTER;
    provider_devices[0].device_id = 0x44440002u;
    memcpy(provider_devices[0].preferred_dos_name, "PRN", 4u);
    provider_devices[1].device_type = RDP_DEVICE_REDIRECTION_TYPE_SERIAL;
    provider_devices[1].device_id = 0x44440003u;
    memcpy(provider_devices[1].preferred_dos_name, "COM1", 5u);
    provider_devices[2].device_type = RDP_DEVICE_REDIRECTION_TYPE_PARALLEL;
    provider_devices[2].device_id = 0x44440004u;
    memcpy(provider_devices[2].preferred_dos_name, "LPT1", 5u);
    provider_devices[3].device_type = RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD;
    provider_devices[3].device_id = 0x44440005u;
    memcpy(provider_devices[3].preferred_dos_name, "SCARD", 6u);
    dvc_packet.length = 0;
    SCHECK(rdp_device_redirection_write_device_list_announce(&dvc_packet,
                                                             provider_devices,
                                                             4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            device_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    for (uint32_t provider_index = 0; provider_index < 4u; provider_index++)
    {
        SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
        SCHECK(librdp_server_peer_get_extension_state(peer,
                                                      provider_families[provider_index],
                                                      &extension_state) == LIBRDP_STATUS_OK);
        SCHECK(extension_state.negotiated && extension_state.active && extension_state.open &&
               extension_state.static_channel_id == device_channel_id);
        SCHECK(librdp_server_peer_send_device_reply(peer,
                                                    device_channel_id,
                                                    provider_families[provider_index],
                                                    provider_devices[provider_index].device_id,
                                                    RDP_DEVICE_REDIRECTION_STATUS_SUCCESS) ==
               LIBRDP_STATUS_OK);
        SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              &response_channel_id,
                                                              &static_payload,
                                                              &static_payload_len));
        SCHECK(response_channel_id == device_channel_id);
        SCHECK(rdp_device_redirection_parse_device_reply(static_payload,
                                                         static_payload_len,
                                                         &device_reply) == LIBRDP_STATUS_OK);
        SCHECK(device_reply.device_id == provider_devices[provider_index].device_id &&
               device_reply.result_code == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    }
    dvc_packet.length = 0;
    SCHECK(rdp_device_redirection_write_io_completion(&dvc_packet,
                                                      device_announce.device_id,
                                                      0x55u,
                                                      RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                      NULL,
                                                      0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            device_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.last_extension_family == LIBRDP_SERVER_EXTENSION_FILESYSTEM);
    SCHECK(runtime_context.last_extension_message_type ==
           RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.rx_messages == 1 &&
           extension_state.last_message_type == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION);
    {
        uint32_t remove_ids[1] = {device_announce.device_id};

        dvc_packet.length = 0;
        SCHECK(rdp_device_redirection_write_device_remove(&dvc_packet,
                                                          remove_ids,
                                                          1) == LIBRDP_STATUS_OK);
        SCHECK(test_server_send_channel_payload(client_fd,
                                                attach_confirm.user_id,
                                                device_channel_id,
                                                &dvc_packet));
        status = librdp_server_peer_run_once(peer, 1000);
        SCHECK(status == LIBRDP_STATUS_OK);
        SCHECK(runtime_context.last_extension_family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION);
        SCHECK(runtime_context.last_extension_message_type ==
               RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE);
        SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
        SCHECK(librdp_server_peer_get_extension_state(peer,
                                                      LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                                                      &extension_state) == LIBRDP_STATUS_OK);
        SCHECK(!extension_state.open && !extension_state.active && extension_state.close_count == 1);
    }
    dvc_packet.length = 0;
    SCHECK(rdp_device_redirection_write_io_completion(&dvc_packet,
                                                      device_announce.device_id,
                                                      0x56u,
                                                      RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                      NULL,
                                                      0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            device_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.last_extension_family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION);
    SCHECK(librdp_server_peer_open_dynamic_channel(peer, 8, 0, RDP_ECHO_CHANNEL_NAME) ==
           LIBRDP_STATUS_STATE);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_capabilities_response(&dvc_packet, 3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_capabilities(dvc_payload, dvc_payload_len, &dvc_caps) == LIBRDP_STATUS_OK);
    SCHECK(dvc_caps.version == 3);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.negotiated &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);
    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_create_request(&dvc_packet, 6, 1, 0, "DENIED", 6) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_create_response(dvc_payload,
                                                     dvc_payload_len,
                                                     &dvc_create_response) == LIBRDP_STATUS_OK);
    SCHECK(dvc_create_response.channel_id == 6 &&
           dvc_create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED);
    SCHECK(runtime_context.dynamic_reject_count == 1 &&
           runtime_context.rejected_dynamic_channel_id == 6);
    SCHECK(runtime_context.dynamic_open_count == 0);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(librdp_server_peer_open_dynamic_channel(NULL, 8, 0, RDP_ECHO_CHANNEL_NAME) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_open_dynamic_channel(peer, 8, 4, RDP_ECHO_CHANNEL_NAME) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_open_dynamic_channel(peer, 8, 0, "BAD NAME") ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_open_dynamic_channel(peer, 8, 0, RDP_ECHO_CHANNEL_NAME) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.pending_open && extension_state.pending_requests == 1 &&
           extension_state.dynamic_channel_id == 8);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_create_request(dvc_payload,
                                                    dvc_payload_len,
                                                    &dvc_create_request) == LIBRDP_STATUS_OK);
    SCHECK(dvc_create_request.channel_id == 8 &&
           dvc_create_request.priority == 0 &&
           dvc_create_request.name_len == sizeof(RDP_ECHO_CHANNEL_NAME) - 1u &&
           memcmp(dvc_create_request.name,
                  RDP_ECHO_CHANNEL_NAME,
                  sizeof(RDP_ECHO_CHANNEL_NAME) - 1u) == 0);
    SCHECK(librdp_server_peer_open_dynamic_channel(peer, 8, 0, RDP_ECHO_CHANNEL_NAME) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_create_response(&dvc_packet,
                                                     8,
                                                     dvc_create_request.channel_id_bytes,
                                                     RDP_DYNAMIC_CHANNEL_STATUS_OK) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_open_count == 1);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 1);
    SCHECK(librdp_server_peer_dynamic_channel_at(peer, 0, &dynamic_info) == LIBRDP_STATUS_OK);
    SCHECK(dynamic_info.channel_id == 8 && dynamic_info.open &&
           strcmp(dynamic_info.name, RDP_ECHO_CHANNEL_NAME) == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.open && !extension_state.pending_open &&
           extension_state.pending_requests == 0 &&
           extension_state.dynamic_channel_id == 8 &&
           extension_state.open_count == 1);
    dvc_packet.length = 0;
    extension_count_before_echo = runtime_context.extension_count;
    SCHECK(rdp_dynamic_channel_write_data(&dvc_packet, 8, 1, "echo", 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_data_count == 1);
    SCHECK(runtime_context.extension_count == extension_count_before_echo + 1u);
    SCHECK(runtime_context.last_extension_family == LIBRDP_SERVER_EXTENSION_ECHO);
    SCHECK(runtime_context.last_extension_feature == LIBRDP_FEATURE_ECHO);
    SCHECK(runtime_context.last_extension_message_type == 1);
    SCHECK(runtime_context.last_channel_id == dynamic_static_channel_id);
    SCHECK(runtime_context.last_dynamic_channel_id == 8);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.rx_messages == 1 && extension_state.rx_bytes == 4 &&
           extension_state.last_message_type == 1);
    SCHECK(librdp_server_peer_send_echo_response(peer, 8, "reply", 5) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    8,
                                                    &dvc_data_response));
    SCHECK(dvc_data_response.data_len == 5);
    SCHECK(rdp_echo_channel_parse_response(dvc_data_response.data,
                                           dvc_data_response.data_len,
                                           &echo_response) == LIBRDP_STATUS_OK);
    SCHECK(echo_response.payload_len == 5 && memcmp(echo_response.payload, "reply", 5) == 0);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.tx_messages == 1 && extension_state.tx_bytes == 5);
    SCHECK(librdp_server_peer_cancel_extension(peer, LIBRDP_SERVER_EXTENSION_ECHO) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.cancelled && extension_state.pending_requests == 0);
    SCHECK(librdp_server_peer_record_extension_timeout(peer,
                                                       LIBRDP_SERVER_EXTENSION_ECHO) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_extension_state_init(&extension_state) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_state(peer,
                                                  LIBRDP_SERVER_EXTENSION_ECHO,
                                                  &extension_state) == LIBRDP_STATUS_OK);
    SCHECK(extension_state.timeout_count == 1 &&
           extension_state.last_status == LIBRDP_STATUS_TIMEOUT);
    dvc_packet.length = 0;
    SCHECK(rdp_echo_channel_write_response(&dvc_packet, "generic", 7) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_send_dynamic_extension_data(peer,
                                                          LIBRDP_SERVER_EXTENSION_ECHO,
                                                          8,
                                                          dvc_packet.data,
                                                          dvc_packet.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    8,
                                                    &dvc_data_response));
    SCHECK(rdp_echo_channel_parse_response(dvc_data_response.data,
                                           dvc_data_response.data_len,
                                           &echo_response) == LIBRDP_STATUS_OK);
    SCHECK(echo_response.payload_len == 7 && memcmp(echo_response.payload, "generic", 7) == 0);
    SCHECK(librdp_server_peer_send_dynamic_extension_data(peer,
                                                          LIBRDP_SERVER_EXTENSION_GRAPHICS,
                                                          8,
                                                          dvc_packet.data,
                                                          dvc_packet.length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_close_dynamic_channel(peer, 8) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_close(dvc_payload, dvc_payload_len, &dvc_close) == LIBRDP_STATUS_OK);
    SCHECK(dvc_close.channel_id == 8);
    SCHECK(runtime_context.dynamic_close_count == 1);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_close(&dvc_packet, 8, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_close_count == 1);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_ECHO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && !feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NOT_NEGOTIATED);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_create_request(&dvc_packet, 7, 1, 2, "APPDVC", 6) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_create_response(dvc_payload,
                                                     dvc_payload_len,
                                                     &dvc_create_response) == LIBRDP_STATUS_OK);
    SCHECK(dvc_create_response.channel_id == 7 &&
           dvc_create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK);
    SCHECK(runtime_context.dynamic_open_count == 2);
    SCHECK(runtime_context.dynamic_accept_count == 1 &&
           runtime_context.accepted_dynamic_channel_id == 7);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 1);
    SCHECK(librdp_server_dynamic_channel_info_init(&dynamic_info) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_at(peer, 0, &dynamic_info) == LIBRDP_STATUS_OK);
    SCHECK(dynamic_info.channel_id == 7 && dynamic_info.open &&
           dynamic_info.priority == 2 &&
           strcmp(dynamic_info.name, "APPDVC") == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_MULTITRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated &&
           !feature_status.active && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_ACTIVE);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_UDP_TRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated &&
           !feature_status.active && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_ACTIVE);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_UDP2_TRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated &&
           !feature_status.active && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_ACTIVE);

    dvc_packet.length = 0;
    SCHECK(rdp_buffer_append_u8(&dvc_packet,
                                (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST << 4)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u8(&dvc_packet, 0) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u32_le(&dvc_packet, 18u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u16_le(&dvc_packet,
                                    RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                                        RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u16_le(&dvc_packet, 1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u32_le(&dvc_packet, RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u16_le(&dvc_packet, 1u) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append_u32_le(&dvc_packet, 7u) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_soft_sync_response(dvc_payload,
                                                       dvc_payload_len,
                                                       &soft_sync_response) == LIBRDP_STATUS_OK);
    SCHECK(soft_sync_response.tunnel_count == 1);
    {
        uint32_t tunnel_type = 0;

        SCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&soft_sync_response,
                                                                 0,
                                                                 &tunnel_type) == LIBRDP_STATUS_OK);
        SCHECK(tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE);
    }
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_MULTITRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_UDP_TRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_UDP2_TRANSPORT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated &&
           !feature_status.active && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_ACTIVE);

    memset(&udp_header, 0, sizeof(udp_header));
    memset(&udp_source, 0, sizeof(udp_source));
    udp_header.receive_window_size = 16u;
    udp_header.flags = RDP_UDP_FLAG_DATA;
    udp_source.coded_sequence = 0x100u;
    udp_source.source_start = 0x100u;
    SCHECK(rdp_udp_write_fec_header(&udp_wire, &udp_header) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_payload_prefix(&udp_wire,
                                        (uint16_t)(8u + sizeof("udp") - 1u)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_source_payload_header(&udp_wire, &udp_source) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append(&udp_wire, "udp", sizeof("udp") - 1u) == LIBRDP_STATUS_OK);
    udp_response_len = 0;
    SCHECK(librdp_server_peer_process_udp_datagram(peer,
                                                   udp_wire.data,
                                                   udp_wire.length,
                                                   udp_response,
                                                   1,
                                                   &udp_response_len) ==
           LIBRDP_STATUS_LIMIT_EXCEEDED);
    SCHECK(udp_response_len > 8u);
    udp_response_len = 0;
    SCHECK(librdp_server_peer_process_udp_datagram(peer,
                                                   udp_wire.data,
                                                   udp_wire.length,
                                                   udp_response,
                                                   sizeof(udp_response),
                                                   &udp_response_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_parse_fec_header(udp_response, udp_response_len, &udp_header) == LIBRDP_STATUS_OK);
    SCHECK((udp_header.flags & (RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SACK_OPTION)) ==
           (RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SACK_OPTION));
    SCHECK(rdp_udp_parse_ack_vector(udp_response + 8u,
                                    udp_response_len - 8u,
                                    &udp_ack_vector) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_ack_vector_count(&udp_ack_vector,
                                    &udp2_ack_received,
                                    &udp2_ack_lost) == LIBRDP_STATUS_OK);
    SCHECK(udp2_ack_received == 1 && udp2_ack_lost == 0);
    udp_wire.length = 0;
    memset(&udp_header, 0, sizeof(udp_header));
    memset(&udp_source, 0, sizeof(udp_source));
    udp_header.receive_window_size = 16u;
    udp_header.flags = RDP_UDP_FLAG_DATA;
    udp_source.coded_sequence = 0x102u;
    udp_source.source_start = 0x102u;
    SCHECK(rdp_udp_write_fec_header(&udp_wire, &udp_header) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_payload_prefix(&udp_wire,
                                        (uint16_t)(8u + sizeof("udp") - 1u)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_source_payload_header(&udp_wire, &udp_source) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append(&udp_wire, "udp", sizeof("udp") - 1u) == LIBRDP_STATUS_OK);
    udp_response_len = 0;
    SCHECK(librdp_server_peer_process_udp_datagram(peer,
                                                   udp_wire.data,
                                                   udp_wire.length,
                                                   udp_response,
                                                   sizeof(udp_response),
                                                   &udp_response_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_parse_ack_vector(udp_response + 8u,
                                    udp_response_len - 8u,
                                    &udp_ack_vector) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_ack_vector_count(&udp_ack_vector,
                                    &udp2_ack_received,
                                    &udp2_ack_lost) == LIBRDP_STATUS_OK);
    SCHECK(udp2_ack_received == 1 && udp2_ack_lost == 1);
    udp_wire.length = 0;
    memset(&udp_header, 0, sizeof(udp_header));
    memset(&udp_source, 0, sizeof(udp_source));
    udp_header.receive_window_size = 16u;
    udp_header.flags = RDP_UDP_FLAG_DATA;
    udp_source.coded_sequence = 0x130u;
    udp_source.source_start = 0x130u;
    SCHECK(rdp_udp_write_fec_header(&udp_wire, &udp_header) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_payload_prefix(&udp_wire,
                                        (uint16_t)(8u + sizeof("udp") - 1u)) == LIBRDP_STATUS_OK);
    SCHECK(rdp_udp_write_source_payload_header(&udp_wire, &udp_source) == LIBRDP_STATUS_OK);
    SCHECK(rdp_buffer_append(&udp_wire, "udp", sizeof("udp") - 1u) == LIBRDP_STATUS_OK);
    error_count_before_udp2 = runtime_context.error_event_count;
    udp_response_len = 0;
    SCHECK(librdp_server_peer_process_udp_datagram(peer,
                                                   udp_wire.data,
                                                   udp_wire.length,
                                                   udp_response,
                                                   sizeof(udp_response),
                                                   &udp_response_len) == LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(udp_response_len == 0);
    SCHECK(runtime_context.error_event_count == error_count_before_udp2 + 1u);

    {
        static const uint8_t udp2_data[] = {0x51u, 0x52u, 0x53u, 0x54u};

        SCHECK(rdp_udp2_write_data_packet(&udp2_payload,
                                          4,
                                          0x3210u,
                                          udp2_data,
                                          sizeof(udp2_data)) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_wrap_packet(&udp2_wire,
                                    udp2_payload.data,
                                    udp2_payload.length,
                                    RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
        error_count_before_udp2 = runtime_context.error_event_count;
        udp2_response_len = 0;
        SCHECK(librdp_server_peer_process_udp2_datagram(peer,
                                                        udp2_wire.data,
                                                        udp2_wire.length,
                                                        udp2_response,
                                                        1,
                                                        &udp2_response_len) ==
               LIBRDP_STATUS_LIMIT_EXCEEDED);
        SCHECK(udp2_response_len > 1);
        SCHECK(runtime_context.error_event_count == error_count_before_udp2 + 1u);
        SCHECK(runtime_context.last_error_status == LIBRDP_STATUS_LIMIT_EXCEEDED);
        SCHECK(librdp_server_peer_get_feature_status(peer,
                                                     LIBRDP_FEATURE_UDP2_TRANSPORT,
                                                     &feature_status) == LIBRDP_STATUS_OK);
        SCHECK(feature_status.requested && feature_status.negotiated &&
               !feature_status.active && feature_status.reason == LIBRDP_FEATURE_REASON_NOT_ACTIVE);
        udp2_response_len = 0;
        SCHECK(librdp_server_peer_process_udp2_datagram(peer,
                                                        udp2_wire.data,
                                                        udp2_wire.length,
                                                        udp2_response,
                                                        sizeof(udp2_response),
                                                        &udp2_response_len) == LIBRDP_STATUS_OK);
        SCHECK(udp2_response_len > 0);
        SCHECK(rdp_udp2_unwrap_packet(&udp2_unwrapped,
                                      udp2_response,
                                      udp2_response_len,
                                      &udp2_prefix) == LIBRDP_STATUS_OK);
        SCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA);
        SCHECK(rdp_udp2_parse_packet(udp2_unwrapped.data,
                                     udp2_unwrapped.length,
                                     &udp2_packet) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
        SCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK);
        SCHECK(udp2_packet.has_ack && udp2_packet.ack.sequence_number == 0x3210u);
        udp2_payload.length = 0;
        udp2_wire.length = 0;
        udp2_unwrapped.length = 0;
        SCHECK(rdp_udp2_write_data_packet(&udp2_payload,
                                          4,
                                          0x3212u,
                                          udp2_data,
                                          sizeof(udp2_data)) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_wrap_packet(&udp2_wire,
                                    udp2_payload.data,
                                    udp2_payload.length,
                                    RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
        udp2_response_len = 0;
        SCHECK(librdp_server_peer_process_udp2_datagram(peer,
                                                        udp2_wire.data,
                                                        udp2_wire.length,
                                                        udp2_response,
                                                        sizeof(udp2_response),
                                                        &udp2_response_len) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_unwrap_packet(&udp2_unwrapped,
                                      udp2_response,
                                      udp2_response_len,
                                      &udp2_prefix) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_parse_packet(udp2_unwrapped.data,
                                     udp2_unwrapped.length,
                                     &udp2_packet) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
        SCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK_VECTOR);
        SCHECK(udp2_packet.has_ack_vector && udp2_packet.ack_vector.base_sequence_number == 0x3211u);
        SCHECK(rdp_udp2_ack_vector_count(&udp2_packet.ack_vector,
                                         &udp2_ack_received,
                                         &udp2_ack_lost) == LIBRDP_STATUS_OK);
        SCHECK(udp2_ack_received == 0 && udp2_ack_lost == 1);
        udp2_payload.length = 0;
        udp2_wire.length = 0;
        udp2_unwrapped.length = 0;
        SCHECK(rdp_udp2_write_data_packet(&udp2_payload,
                                          4,
                                          0x3212u,
                                          udp2_data,
                                          sizeof(udp2_data)) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_wrap_packet(&udp2_wire,
                                    udp2_payload.data,
                                    udp2_payload.length,
                                    RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
        udp2_response_len = 0;
        SCHECK(librdp_server_peer_process_udp2_datagram(peer,
                                                        udp2_wire.data,
                                                        udp2_wire.length,
                                                        udp2_response,
                                                        sizeof(udp2_response),
                                                        &udp2_response_len) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_unwrap_packet(&udp2_unwrapped,
                                      udp2_response,
                                      udp2_response_len,
                                      &udp2_prefix) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_parse_packet(udp2_unwrapped.data,
                                     udp2_unwrapped.length,
                                     &udp2_packet) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
        SCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK);
        udp2_payload.length = 0;
        udp2_wire.length = 0;
        SCHECK(rdp_udp2_write_data_packet(&udp2_payload,
                                          4,
                                          0x3234u,
                                          udp2_data,
                                          sizeof(udp2_data)) == LIBRDP_STATUS_OK);
        SCHECK(rdp_udp2_wrap_packet(&udp2_wire,
                                    udp2_payload.data,
                                    udp2_payload.length,
                                    RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
        error_count_before_udp2 = runtime_context.error_event_count;
        udp2_response_len = 0;
        SCHECK(librdp_server_peer_process_udp2_datagram(peer,
                                                        udp2_wire.data,
                                                        udp2_wire.length,
                                                        udp2_response,
                                                        sizeof(udp2_response),
                                                        &udp2_response_len) == LIBRDP_STATUS_PROTOCOL_ERROR);
        SCHECK(udp2_response_len == 0);
        SCHECK(runtime_context.error_event_count == error_count_before_udp2 + 1u);
        SCHECK(librdp_server_peer_get_feature_status(peer,
                                                     LIBRDP_FEATURE_UDP2_TRANSPORT,
                                                     &feature_status) == LIBRDP_STATUS_OK);
        SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
               feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    }

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_data(&dvc_packet, 7, 1, "ping", 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_data_count == 2);
    SCHECK(runtime_context.last_dynamic_channel_id == 7);
    SCHECK(runtime_context.channel_payload_len == 4 &&
           memcmp(runtime_context.channel_payload, "ping", 4) == 0);
    SCHECK(librdp_server_metrics_init(&server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    limits_before_dvc_limit = server_metrics.limits_rejected;
    error_count_before_dvc_limit = runtime_context.error_event_count;
    SCHECK(librdp_server_peer_send_dynamic_channel_data(peer,
                                                        7,
                                                        dynamic_large_payload,
                                                        dvc_oversize_len) ==
           LIBRDP_STATUS_LIMIT_EXCEEDED);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(server_metrics.limits_rejected == limits_before_dvc_limit + 1u);
    SCHECK(runtime_context.error_event_count == error_count_before_dvc_limit + 1u);
    SCHECK(runtime_context.last_error_status == LIBRDP_STATUS_LIMIT_EXCEEDED);

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_data_first_ex(&dvc_packet,
                                                   7,
                                                   1,
                                                   2,
                                                   10,
                                                   "frag",
                                                   4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_data_count == 2);
    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_data_ex(&dvc_packet, 7, 1, 2, "mented", 6) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_data_count == 3);
    SCHECK(runtime_context.channel_payload_len == 10 &&
           memcmp(runtime_context.channel_payload, "fragmented", 10) == 0);

    SCHECK(librdp_server_peer_send_dynamic_channel_data(peer, 7, "pong", 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_header(dvc_payload, dvc_payload_len, &dvc_header) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA && dvc_header.priority == 2);
    SCHECK(rdp_dynamic_channel_parse_data(dvc_payload, dvc_payload_len, &dvc_data_response) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_data_response.channel_id == 7 &&
           dvc_data_response.data_len == 4 &&
           memcmp(dvc_data_response.data, "pong", 4) == 0);

    SCHECK(librdp_server_peer_send_dynamic_channel_data(peer,
                                                        7,
                                                        dynamic_large_payload,
                                                        sizeof(dynamic_large_payload)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_header(dvc_payload, dvc_payload_len, &dvc_header) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST);
    SCHECK(rdp_dynamic_channel_parse_data_first(dvc_payload, dvc_payload_len, &dvc_data_first) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_data_first.channel_id == 7 &&
           dvc_data_first.total_length == sizeof(dynamic_large_payload) &&
           dvc_data_first.data_len > 0);
    dynamic_fragmented_len = dvc_data_first.data_len;
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &dvc_payload,
                                                          &dvc_payload_len));
    SCHECK(response_channel_id == dynamic_static_channel_id);
    SCHECK(rdp_dynamic_channel_parse_header(dvc_payload, dvc_payload_len, &dvc_header) ==
           LIBRDP_STATUS_OK);
    SCHECK(dvc_header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA && dvc_header.priority == 2);
    SCHECK(rdp_dynamic_channel_parse_data(dvc_payload, dvc_payload_len, &dvc_data_response) ==
           LIBRDP_STATUS_OK);
    dynamic_fragmented_len += dvc_data_response.data_len;
    SCHECK(dvc_data_response.channel_id == 7 &&
           dynamic_fragmented_len == sizeof(dynamic_large_payload));

    dvc_packet.length = 0;
    SCHECK(rdp_dynamic_channel_write_close(&dvc_packet, 7, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.dynamic_close_count == 2);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(librdp_server_peer_dynamic_channel_at(peer, 0, &dynamic_info) == LIBRDP_STATUS_INVALID_ARGUMENT);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   9,
                                                   RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_graphics_default_caps(peer, 9) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_header(dvc_data_response.data,
                                     dvc_data_response.data_len,
                                     &graphics_header) == LIBRDP_STATUS_OK);
    SCHECK(graphics_header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE);
    SCHECK(graphics_header.pdu_length == 34);
    graphics_cap_count = (uint16_t)((uint32_t)dvc_data_response.data[8] |
                                    ((uint32_t)dvc_data_response.data[9] << 8u));
    graphics_cap_version = (uint32_t)dvc_data_response.data[22] |
                           ((uint32_t)dvc_data_response.data[23] << 8) |
                           ((uint32_t)dvc_data_response.data[24] << 16) |
                           ((uint32_t)dvc_data_response.data[25] << 24);
    graphics_cap_flags = (uint32_t)dvc_data_response.data[30] |
                         ((uint32_t)dvc_data_response.data[31] << 8) |
                         ((uint32_t)dvc_data_response.data[32] << 16) |
                         ((uint32_t)dvc_data_response.data[33] << 24);
    SCHECK(graphics_cap_count == 2 &&
           graphics_cap_version == RDP_GRAPHICS_CAPVERSION_10 &&
           (graphics_cap_flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    SCHECK(librdp_server_peer_send_graphics_create_surface(peer,
                                                           9,
                                                           1,
                                                           64,
                                                           32,
                                                           RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_create_surface(dvc_data_response.data,
                                             dvc_data_response.data_len,
                                             &graphics_create) == LIBRDP_STATUS_OK);
    SCHECK(graphics_create.surface_id == 1 &&
           graphics_create.width == 64 &&
           graphics_create.height == 32);
    SCHECK(librdp_server_peer_send_graphics_bitmap_bgra32(peer,
                                                          9,
                                                          1,
                                                          2,
                                                          3,
                                                          2,
                                                          2,
                                                          16,
                                                          pixels) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_wire_to_surface_1(dvc_data_response.data,
                                                dvc_data_response.data_len,
                                                &graphics_wire) == LIBRDP_STATUS_OK);
    SCHECK(graphics_wire.surface_id == 1 &&
           graphics_wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED &&
           graphics_wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
           graphics_wire.dest_rect.left == 2 &&
           graphics_wire.dest_rect.top == 3 &&
           graphics_wire.dest_rect.right == 4 &&
           graphics_wire.dest_rect.bottom == 5 &&
           graphics_wire.bitmap_data_length == 16 &&
           graphics_wire.bitmap_data[0] == pixels[0] &&
           graphics_wire.bitmap_data[7] == pixels[7] &&
           graphics_wire.bitmap_data[8] == pixels[16] &&
           graphics_wire.bitmap_data[15] == pixels[23]);
    SCHECK(librdp_server_peer_send_graphics_bitmap_bgra32(peer,
                                                          9,
                                                          1,
                                                          0,
                                                          0,
                                                          2,
                                                          2,
                                                          4,
                                                          pixels) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_graphics_delete_surface(peer, 9, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_delete_surface(dvc_data_response.data,
                                             dvc_data_response.data_len,
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    SCHECK(graphics_delete.surface_id == 1);
    SCHECK(librdp_server_peer_send_graphics_reset(peer, 9, 800, 600) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_reset(dvc_data_response.data,
                                    dvc_data_response.data_len,
                                    &graphics_reset) == LIBRDP_STATUS_OK);
    SCHECK(graphics_reset.width == 800 && graphics_reset.height == 600);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(peer, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_graphics_frame_state(peer,
                                                       &graphics_pending_frames,
                                                       &graphics_frame_limit,
                                                       &graphics_last_ack_frame_id) == LIBRDP_STATUS_OK);
    SCHECK(graphics_pending_frames == 0 && graphics_frame_limit == 1 && graphics_last_ack_frame_id == 0);
    SCHECK(librdp_server_peer_send_graphics_start_frame(peer, 9, 1234, &graphics_frame_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(graphics_frame_id == 1);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_start_frame(dvc_data_response.data,
                                          dvc_data_response.data_len,
                                          &graphics_start) == LIBRDP_STATUS_OK);
    SCHECK(graphics_start.timestamp == 1234 && graphics_start.frame_id == graphics_frame_id);
    SCHECK(librdp_server_peer_send_graphics_end_frame(peer, 9, graphics_frame_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_end_frame(dvc_data_response.data,
                                        dvc_data_response.data_len,
                                        &graphics_end) == LIBRDP_STATUS_OK);
    SCHECK(graphics_end.frame_id == graphics_frame_id);
    SCHECK(librdp_server_peer_get_graphics_frame_state(peer,
                                                       &graphics_pending_frames,
                                                       &graphics_frame_limit,
                                                       &graphics_last_ack_frame_id) == LIBRDP_STATUS_OK);
    SCHECK(graphics_pending_frames == 1 && graphics_frame_limit == 1 && graphics_last_ack_frame_id == 0);
    SCHECK(librdp_server_peer_send_graphics_start_frame(peer, 9, 2234, &graphics_frame_id) ==
           LIBRDP_STATUS_LIMIT_EXCEEDED);
    SCHECK(graphics_frame_id == 0);
    graphics_payload.length = 0;
    dvc_packet.length = 0;
    SCHECK(rdp_graphics_write_frame_ack(&graphics_payload, 0, 1, 1) == LIBRDP_STATUS_OK);
    SCHECK(rdp_dynamic_channel_write_data(&dvc_packet,
                                          9,
                                          1,
                                          graphics_payload.data,
                                          graphics_payload.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_channel_payload(client_fd,
                                            attach_confirm.user_id,
                                            dynamic_static_channel_id,
                                            &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_graphics_frame_state(peer,
                                                       &graphics_pending_frames,
                                                       &graphics_frame_limit,
                                                       &graphics_last_ack_frame_id) == LIBRDP_STATUS_OK);
    SCHECK(graphics_pending_frames == 0 && graphics_frame_limit == 1 && graphics_last_ack_frame_id == 1);
    SCHECK(librdp_server_peer_send_graphics_start_frame(peer, 9, 2234, &graphics_frame_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(graphics_frame_id == 2);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_start_frame(dvc_data_response.data,
                                          dvc_data_response.data_len,
                                          &graphics_start) == LIBRDP_STATUS_OK);
    SCHECK(graphics_start.timestamp == 2234 && graphics_start.frame_id == graphics_frame_id);
    SCHECK(librdp_server_peer_send_graphics_end_frame(peer, 9, graphics_frame_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    9,
                                                    &dvc_data_response));
    SCHECK(rdp_graphics_parse_end_frame(dvc_data_response.data,
                                        dvc_data_response.data_len,
                                        &graphics_end) == LIBRDP_STATUS_OK);
    SCHECK(graphics_end.frame_id == graphics_frame_id);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   10,
                                                   RDP_DISPLAY_CONTROL_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_display_single_monitor_layout(peer, 10, 1024, 768) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    10,
                                                    &dvc_data_response));
    SCHECK(rdp_display_control_parse_monitor_layout(dvc_data_response.data,
                                                    dvc_data_response.data_len,
                                                    display_monitors,
                                                    1,
                                                    &display_monitor_count) == LIBRDP_STATUS_OK);
    SCHECK(display_monitor_count == 1 &&
           display_monitors[0].width == 1024 &&
           display_monitors[0].height == 768);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   11,
                                                   RDP_CORE_INPUT_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_core_input_init(peer, 11) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    11,
                                                    &dvc_data_response));
    SCHECK(rdp_core_input_parse_header(dvc_data_response.data,
                                       dvc_data_response.data_len,
                                       &core_input_header) == LIBRDP_STATUS_OK);
    SCHECK(core_input_header.pdu_type == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   12,
                                                   RDP_INPUT_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_touch_ready(peer,
                                               12,
                                               RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                               RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                                               1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    12,
                                                    &dvc_data_response));
    SCHECK(rdp_input_channel_parse_header(dvc_data_response.data,
                                          dvc_data_response.data_len,
                                          &input_channel_header) == LIBRDP_STATUS_OK);
    SCHECK(input_channel_header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY);
    SCHECK(rdp_input_channel_parse_sc_ready(dvc_data_response.data,
                                            dvc_data_response.data_len,
                                            &input_ready) == LIBRDP_STATUS_OK);
    SCHECK(input_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_ready.has_supported_features);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   13,
                                                   RDP_MOUSE_CURSOR_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_mouse_cursor_caps(peer, 13) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    13,
                                                    &dvc_data_response));
    SCHECK(rdp_mouse_cursor_parse_header(dvc_data_response.data,
                                         dvc_data_response.data_len,
                                         &mouse_cursor_header) == LIBRDP_STATUS_OK);
    SCHECK(mouse_cursor_header.pdu_type == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE);
    SCHECK(librdp_server_peer_send_mouse_cursor_update(peer,
                                                       13,
                                                       RDP_POINTER_UPDATE_KIND_POSITION,
                                                       0,
                                                       320,
                                                       240,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              13,
                                                              &dvc_data_response));
    SCHECK(rdp_mouse_cursor_parse_update(dvc_data_response.data,
                                         dvc_data_response.data_len,
                                         &pointer_update) == LIBRDP_STATUS_OK);
    SCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 320 &&
           pointer_update.y == 240);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   14,
                                                   RDP_TELEMETRY_DVC_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_telemetry_metrics(peer, 14, 1, 2, 3, 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    14,
                                                    &dvc_data_response));
    SCHECK(rdp_telemetry_parse_pdu(dvc_data_response.data,
                                   dvc_data_response.data_len,
                                   &telemetry_pdu) == LIBRDP_STATUS_OK);
    SCHECK(telemetry_pdu.prompt_for_credentials_ms == 1 &&
           telemetry_pdu.first_graphics_received_ms == 4);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_TELEMETRY,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   15,
                                                   RDP_USB_REDIRECTION_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_usb_device_capabilities_init(&usb_caps) == LIBRDP_STATUS_OK);
    usb_caps.device_is_high_speed = 1u;
    SCHECK(librdp_server_peer_send_usb_capability_response(peer,
                                                           15,
                                                           0x20u,
                                                           RDP_USB_REDIRECTION_CAPABILITY_VERSION_01,
                                                           0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    15,
                                                    &dvc_data_response));
    SCHECK(rdp_usb_redirection_parse_header(dvc_data_response.data,
                                            dvc_data_response.data_len,
                                            0,
                                            &usb_header) == LIBRDP_STATUS_OK);
    SCHECK(usb_header.interface_id == RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES &&
           usb_header.message_id == 0x20u &&
           usb_header.payload_len == 8u &&
           usb_header.payload[0] == RDP_USB_REDIRECTION_CAPABILITY_VERSION_01 &&
           usb_header.payload[4] == 0);
    SCHECK(librdp_server_peer_send_usb_add_device(peer,
                                                  15,
                                                  0x21u,
                                                  0x77u,
                                                  usb_instance_utf16,
                                                  (uint32_t)sizeof(usb_instance_utf16),
                                                  usb_ids_utf16,
                                                  (uint32_t)sizeof(usb_ids_utf16),
                                                  usb_ids_utf16,
                                                  (uint32_t)sizeof(usb_ids_utf16),
                                                  usb_container_utf16,
                                                  (uint32_t)sizeof(usb_container_utf16),
                                                  &usb_caps) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    15,
                                                    &dvc_data_response));
    SCHECK(rdp_usb_redirection_parse_add_device(dvc_data_response.data,
                                                dvc_data_response.data_len,
                                                &usb_device) == LIBRDP_STATUS_OK);
    SCHECK(usb_device.usb_device == 0x77u &&
           usb_device.capabilities.hcd_capabilities == usb_caps.hcd_capabilities &&
           usb_device.capabilities.device_is_high_speed == 1u);
    SCHECK(librdp_server_peer_send_usb_io_control_completion(peer,
                                                             15,
                                                             9,
                                                             0x22u,
                                                             0x1234u,
                                                             RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS,
                                                             2,
                                                             "ok",
                                                             2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    15,
                                                    &dvc_data_response));
    SCHECK(rdp_usb_redirection_parse_io_control_completion(dvc_data_response.data,
                                                           dvc_data_response.data_len,
                                                           &usb_io_completion) == LIBRDP_STATUS_OK);
    SCHECK(usb_io_completion.request_id == 0x1234u &&
           usb_io_completion.information == 2 &&
           usb_io_completion.output_buffer_len == 2 &&
           memcmp(usb_io_completion.output_buffer, "ok", 2) == 0);
    SCHECK(librdp_server_peer_send_usb_urb_completion(peer,
                                                      15,
                                                      9,
                                                      0x23u,
                                                      0x1235u,
                                                      "urb",
                                                      3,
                                                      RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS,
                                                      "xy",
                                                      2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    15,
                                                    &dvc_data_response));
    SCHECK(rdp_usb_redirection_parse_urb_completion(dvc_data_response.data,
                                                    dvc_data_response.data_len,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                    &usb_urb_completion) == LIBRDP_STATUS_OK);
    SCHECK(usb_urb_completion.request_id == 0x1235u &&
           usb_urb_completion.cb_ts_urb_result == 3 &&
           memcmp(usb_urb_completion.ts_urb_result, "urb", 3) == 0 &&
           usb_urb_completion.output_buffer_len == 2 &&
           memcmp(usb_urb_completion.output_buffer, "xy", 2) == 0);
    SCHECK(librdp_server_peer_send_usb_retract_device(peer,
                                                      15,
                                                      RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                      0x24u,
                                                      RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                    15,
                                                    &dvc_data_response));
    SCHECK(rdp_usb_redirection_parse_retract_device(dvc_data_response.data,
                                                    dvc_data_response.data_len,
                                                    &usb_retract) == LIBRDP_STATUS_OK);
    SCHECK(usb_retract.reason == RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_USB,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   16,
                                                   RDP_AUDIO_INPUT_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_audio_input_version(peer,
                                                       16,
                                                       RDP_AUDIO_INPUT_VERSION_2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              16,
                                                              &dvc_data_response));
    SCHECK(rdp_audio_input_parse_version(dvc_data_response.data,
                                         dvc_data_response.data_len,
                                         &audio_input_version) == LIBRDP_STATUS_OK);
    SCHECK(audio_input_version == RDP_AUDIO_INPUT_VERSION_2);
    SCHECK(librdp_server_peer_send_audio_input_formats(peer, 16, &public_pcm, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              16,
                                                              &dvc_data_response));
    SCHECK(rdp_audio_input_parse_formats(dvc_data_response.data,
                                         dvc_data_response.data_len,
                                         &audio_input_formats) == LIBRDP_STATUS_OK);
    SCHECK(audio_input_formats.format_count == 1);
    SCHECK(librdp_server_peer_send_audio_input_open(peer,
                                                    16,
                                                    2,
                                                    0,
                                                    &public_pcm) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              16,
                                                              &dvc_data_response));
    SCHECK(rdp_audio_input_parse_open(dvc_data_response.data,
                                      dvc_data_response.data_len,
                                      &audio_input_open) == LIBRDP_STATUS_OK);
    SCHECK(audio_input_open.frames_per_packet == 2 &&
           audio_input_open.initial_format == 0 &&
           audio_input_open.format.samples_per_sec == public_pcm.samples_per_sec);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_AUDIO_INPUT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   17,
                                                   RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   18,
                                                   RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_camera_device_added(peer,
                                                       17,
                                                       RDP_VIDEO_CAPTURE_VERSION_1,
                                                       camera_name_utf16,
                                                       sizeof(camera_name_utf16) - 2u,
                                                       RDP_VIDEO_CAPTURE_CHANNEL_NAME) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              17,
                                                              &dvc_data_response));
    SCHECK(rdp_video_capture_parse_device_added(dvc_data_response.data,
                                                dvc_data_response.data_len,
                                                &camera_device) == LIBRDP_STATUS_OK);
    SCHECK(camera_device.header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_ADDED &&
           camera_device.device_name_len == sizeof(camera_name_utf16) - 2u);
    camera_media.format = LIBRDP_VIDEO_CAPTURE_MEDIA_RGB32;
    camera_media.width = 640;
    camera_media.height = 480;
    camera_media.frame_rate_numerator = 30;
    camera_media.frame_rate_denominator = 1;
    camera_media.pixel_aspect_ratio_numerator = 1;
    camera_media.pixel_aspect_ratio_denominator = 1;
    SCHECK(librdp_server_peer_send_camera_media_list(peer,
                                                     18,
                                                     RDP_VIDEO_CAPTURE_VERSION_1,
                                                     RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE,
                                                     &camera_media,
                                                     1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              18,
                                                              &dvc_data_response));
    SCHECK(rdp_video_capture_parse_media_list(dvc_data_response.data,
                                              dvc_data_response.data_len,
                                              RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE,
                                              &camera_media_list) == LIBRDP_STATUS_OK);
    SCHECK(camera_media_list.count == 1 &&
           camera_media_list.media[0].width == 640 &&
           camera_media_list.media[0].format == RDP_VIDEO_CAPTURE_MEDIA_RGB32);
    SCHECK(librdp_server_peer_send_camera_sample(peer,
                                                 18,
                                                 RDP_VIDEO_CAPTURE_VERSION_1,
                                                 0,
                                                 "cam",
                                                 3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              18,
                                                              &dvc_data_response));
    SCHECK(rdp_video_capture_parse_sample(dvc_data_response.data,
                                          dvc_data_response.data_len,
                                          &camera_sample) == LIBRDP_STATUS_OK);
    SCHECK(camera_sample.stream_index == 0 &&
           camera_sample.sample_len == 3 &&
           memcmp(camera_sample.sample, "cam", 3) == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_CAMERA,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   19,
                                                   RDP_WEBAUTHN_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_webauthn_response(peer,
                                                     19,
                                                     0,
                                                     "ok",
                                                     2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              19,
                                                              &dvc_data_response));
    SCHECK(rdp_webauthn_parse_response(dvc_data_response.data,
                                       dvc_data_response.data_len,
                                       &webauthn_response) == LIBRDP_STATUS_OK);
    SCHECK(webauthn_response.hresult == 0 &&
           webauthn_response.payload_len == 2 &&
           memcmp(webauthn_response.payload, "ok", 2) == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_WEBAUTHN,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   20,
                                                   RDP_COMPOSITED_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_cr2_version_reply(peer, 20, cr2_versions, 1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              20,
                                                              &dvc_data_response));
    SCHECK(rdp_composited_parse_control(dvc_data_response.data,
                                        dvc_data_response.data_len,
                                        &cr2_control) == LIBRDP_STATUS_OK);
    SCHECK(cr2_control.control_code == RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION);
    SCHECK(rdp_composited_parse_version_reply(cr2_control.payload,
                                              cr2_control.payload_len,
                                              &cr2_version_reply) == LIBRDP_STATUS_OK);
    SCHECK(rdp_composited_version_reply_has(&cr2_version_reply, RDP_COMPOSITED_PROTOCOL_VERSION));
    SCHECK(librdp_server_peer_send_cr2_window_node_create(peer,
                                                          20,
                                                          0x12u,
                                                          0x1111222233334444u,
                                                          0x5555666677778888u,
                                                          1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              20,
                                                              &dvc_data_response));
    SCHECK(rdp_composited_parse_window_node_create(dvc_data_response.data,
                                                   dvc_data_response.data_len,
                                                   &cr2_window_node) == LIBRDP_STATUS_OK);
    SCHECK(cr2_window_node.target_resource == 0x12u &&
           cr2_window_node.caching_mode == 1);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_CR2,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   21,
                                                   RDP_VIDEO_OPTIMIZED_DATA_CHANNEL,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_video_optimized_data(peer,
                                                       21,
                                                       1,
                                                        RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS |
                                                            RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
                                                       100,
                                                       33,
                                                        1,
                                                       1,
                                                        7,
                                                        "vid",
                                                        3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              21,
                                                              &dvc_data_response));
    SCHECK(rdp_video_optimized_parse_video_data(dvc_data_response.data,
                                                dvc_data_response.data_len,
                                                &optimized_video) == LIBRDP_STATUS_OK);
    SCHECK(optimized_video.presentation_id == 1 &&
           optimized_video.sample_number == 7 &&
           optimized_video.sample_len == 3 &&
           memcmp(optimized_video.sample, "vid", 3) == 0);

    SCHECK(test_server_open_client_dynamic_channel(client_fd,
                                                   peer,
                                                   attach_confirm.user_id,
                                                   dynamic_static_channel_id,
                                                   22,
                                                   RDP_AUTH_REDIRECTION_CHANNEL_NAME,
                                                   0,
                                                   &client_security,
                                                   &channel_plaintext,
                                                   response,
                                                   sizeof(response)));
    SCHECK(librdp_server_peer_send_auth_redirection_response(
               peer,
               22,
               RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION,
               0,
               NULL,
               0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_dynamic_channel_payload(client_fd,
                                                              response,
                                                              sizeof(response),
                                                              &client_security,
                                                              &channel_plaintext,
                                                              dynamic_static_channel_id,
                                                              22,
                                                              &dvc_data_response));
    SCHECK(rdp_auth_redirection_parse_response(dvc_data_response.data,
                                               dvc_data_response.data_len,
                                               &auth_response) == LIBRDP_STATUS_OK);
    SCHECK(auth_response.call_id == RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION &&
           auth_response.status == 0 &&
           auth_response.payload_len == 0);

    SCHECK(librdp_server_peer_send_clipboard_monitor_ready(peer, clipboard_channel_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_packet.type == RDP_CLIPBOARD_CB_MONITOR_READY && clipboard_packet.length == 0);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.monitor_ready_sent && !clipboard_state.monitor_ready_received);
    SCHECK(librdp_server_peer_send_clipboard_capabilities(peer,
                                                          clipboard_channel_id,
                                                          RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_capabilities(&clipboard_packet, &clipboard_capabilities) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_capabilities.has_general &&
           clipboard_capabilities.general.general_flags == RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.capabilities_sent && !clipboard_state.capabilities_received);
    SCHECK(librdp_server_peer_send_clipboard_format_list(peer,
                                                         clipboard_channel_id,
                                                         clipboard_formats,
                                                         1,
                                                         1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_format_list(&clipboard_packet, &clipboard_format_list) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_format_list_entry_count(&clipboard_format_list, 1, &clipboard_format_count) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard_format_count == 1);
    SCHECK(rdp_clipboard_format_list_get_entry(&clipboard_format_list,
                                               1,
                                               0,
                                               &clipboard_format_entry) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_format_entry.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.formats_sent &&
           !clipboard_state.formats_accepted &&
           clipboard_state.format_count == 1);
    SCHECK(librdp_server_peer_send_clipboard_format_list_response(peer, clipboard_channel_id, 1) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_packet.type == RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE &&
           (clipboard_packet.flags & RDP_CLIPBOARD_CB_RESPONSE_OK) != 0);
    SCHECK(librdp_server_peer_send_clipboard_format_data_request(peer,
                                                                 clipboard_channel_id,
                                                                 RDP_CLIPBOARD_FORMAT_UNICODETEXT) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_format_data_request(&clipboard_packet, &clipboard_format_data_request) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard_format_data_request.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.pending_format_request &&
           clipboard_state.pending_format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    SCHECK(librdp_server_peer_cancel_clipboard_requests(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(!clipboard_state.pending_format_request && clipboard_state.pending_format_id == 0);
    SCHECK(librdp_server_peer_send_clipboard_format_data_response(peer,
                                                                  clipboard_channel_id,
                                                                  1,
                                                                  "abc",
                                                                  3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_format_data_response(&clipboard_packet, &clipboard_format_data_response) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard_format_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           clipboard_format_data_response.data_len == 3 &&
           memcmp(clipboard_format_data_response.data, "abc", 3) == 0);
    SCHECK(librdp_server_peer_send_clipboard_file_contents_request(peer,
                                                                   clipboard_channel_id,
                                                                   0x11223344u,
                                                                   2,
                                                                   RDP_CLIPBOARD_FILECONTENTS_RANGE,
                                                                   5,
                                                                   7,
                                                                   &clipboard_clip_data_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_file_contents_request(&clipboard_packet, &clipboard_file_contents_request) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard_file_contents_request.stream_id == 0x11223344u &&
           clipboard_file_contents_request.lindex == 2 &&
           clipboard_file_contents_request.flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
           clipboard_file_contents_request.position == 5 &&
           clipboard_file_contents_request.requested == 7 &&
           clipboard_file_contents_request.has_clip_data_id &&
           clipboard_file_contents_request.clip_data_id == clipboard_clip_data_id);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.pending_file_request &&
           clipboard_state.pending_file_stream_id == 0x11223344u);
    SCHECK(librdp_server_peer_send_clipboard_file_contents_response(peer,
                                                                    clipboard_channel_id,
                                                                    1,
                                                                    0x11223344u,
                                                                    "file",
                                                                    4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_file_contents_response(&clipboard_packet, &clipboard_file_contents_response) ==
           LIBRDP_STATUS_OK);
    SCHECK(clipboard_file_contents_response.stream_id == 0x11223344u &&
           clipboard_file_contents_response.data_len == 4 &&
           memcmp(clipboard_file_contents_response.data, "file", 4) == 0);
    SCHECK(librdp_server_peer_cancel_clipboard_requests(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(!clipboard_state.pending_file_request && clipboard_state.pending_file_stream_id == 0);
    SCHECK(librdp_server_peer_send_clipboard_lock(peer, clipboard_channel_id, clipboard_clip_data_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_lock(&clipboard_packet, &clipboard_lock) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_lock.clip_data_id == clipboard_clip_data_id);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.locked && clipboard_state.locked_clip_data_id == clipboard_clip_data_id);
    SCHECK(librdp_server_peer_send_clipboard_unlock(peer, clipboard_channel_id, clipboard_clip_data_id) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(rdp_clipboard_parse_unlock(&clipboard_packet, &clipboard_lock) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_lock.clip_data_id == clipboard_clip_data_id);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(!clipboard_state.locked && clipboard_state.locked_clip_data_id == 0);
    dvc_packet.length = 0;
    SCHECK(rdp_clipboard_write_monitor_ready(&dvc_packet) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_send_static_extension_data(peer,
                                                         LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                                                         clipboard_channel_id,
                                                         dvc_packet.data,
                                                         dvc_packet.length) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == clipboard_channel_id);
    SCHECK(rdp_clipboard_parse_packet(static_payload, static_payload_len, &clipboard_packet) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_packet.type == RDP_CLIPBOARD_CB_MONITOR_READY);
    SCHECK(test_server_send_encrypted_channel_payload(client_fd,
                                                      attach_confirm.user_id,
                                                      clipboard_channel_id,
                                                      &client_security,
                                                      &dvc_packet));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_clipboard_state(peer, &clipboard_state) == LIBRDP_STATUS_OK);
    SCHECK(clipboard_state.monitor_ready_received);
    SCHECK(librdp_server_peer_send_static_extension_data(peer,
                                                         LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION,
                                                         clipboard_channel_id,
                                                         dvc_packet.data,
                                                         dvc_packet.length) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_pnp_version(peer,
                                               pnp_channel_id,
                                               1,
                                               0,
                                               RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_version(static_payload,
                                             static_payload_len,
                                             &pnp_version) == LIBRDP_STATUS_OK);
    SCHECK(pnp_version.major_version == 1 &&
           pnp_version.capabilities == RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    SCHECK(librdp_server_peer_send_pnp_authenticated(peer, pnp_channel_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_authenticated(static_payload,
                                                   static_payload_len,
                                                   &pnp_info) == LIBRDP_STATUS_OK);
    SCHECK(pnp_info.packet_id == RDP_PNP_REDIRECTION_INFO_SERVER_LOGON);
    SCHECK(librdp_server_peer_send_pnp_capabilities_request(peer,
                                                            pnp_channel_id,
                                                            1,
                                                            RDP_PNP_REDIRECTION_IO_VERSION_6) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_capabilities_request(static_payload,
                                                          static_payload_len,
                                                          &pnp_io_version) == LIBRDP_STATUS_OK);
    SCHECK(pnp_io_version.header.request_id == 1 &&
           pnp_io_version.version == RDP_PNP_REDIRECTION_IO_VERSION_6);
    SCHECK(librdp_server_peer_send_pnp_create_request(peer,
                                                      pnp_channel_id,
                                                      2,
                                                      0x8888u,
                                                      0x80000000u,
                                                      1,
                                                      3,
                                                      0x80u) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_create_request(static_payload,
                                                    static_payload_len,
                                                    &pnp_create) == LIBRDP_STATUS_OK);
    SCHECK(pnp_create.header.request_id == 2 && pnp_create.device_id == 0x8888u);
    SCHECK(librdp_server_peer_send_pnp_read_request(peer,
                                                    pnp_channel_id,
                                                    3,
                                                    16,
                                                    0,
                                                    4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_read_request(static_payload,
                                                  static_payload_len,
                                                  &pnp_read) == LIBRDP_STATUS_OK);
    SCHECK(pnp_read.header.request_id == 3 && pnp_read.bytes_to_read == 16);
    SCHECK(librdp_server_peer_send_pnp_write_request(peer,
                                                     pnp_channel_id,
                                                     4,
                                                     0,
                                                     8,
                                                     "pn",
                                                     2) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_write_request(static_payload,
                                                   static_payload_len,
                                                   &pnp_write) == LIBRDP_STATUS_OK);
    SCHECK(pnp_write.header.request_id == 4 &&
           pnp_write.bytes_to_write == 2 &&
           memcmp(pnp_write.data, "pn", 2) == 0);
    SCHECK(librdp_server_peer_send_pnp_control_request(peer,
                                                       pnp_channel_id,
                                                       5,
                                                       0x1020u,
                                                       "in",
                                                       2,
                                                       4,
                                                       "out",
                                                       3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_control_request(static_payload,
                                                     static_payload_len,
                                                     &pnp_control) == LIBRDP_STATUS_OK);
    SCHECK(pnp_control.header.request_id == 5 &&
           pnp_control.input_len == 2 &&
           pnp_control.output_len == 4 &&
           pnp_control.actual_output_len == 3);
    SCHECK(librdp_server_peer_send_pnp_cancel_request(peer,
                                                      pnp_channel_id,
                                                      6,
                                                      5) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == pnp_channel_id);
    SCHECK(rdp_pnp_redirection_parse_cancel_request(static_payload,
                                                    static_payload_len,
                                                    &pnp_cancel) == LIBRDP_STATUS_OK);
    SCHECK(pnp_cancel.header.request_id == 6 && pnp_cancel.id_to_cancel == 5);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_PNP,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    public_pcm.format_tag = LIBRDP_AUDIO_FORMAT_PCM;
    public_pcm.channels = 2;
    public_pcm.samples_per_sec = 44100;
    public_pcm.avg_bytes_per_sec = 176400;
    public_pcm.block_align = 4;
    public_pcm.bits_per_sample = 16;
    SCHECK(librdp_server_peer_send_audio_output_formats(peer,
                                                        audio_output_channel_id,
                                                        RDP_AUDIO_OUTPUT_CAP_ALIVE,
                                                        0x00010001u,
                                                        0,
                                                        0,
                                                        0,
                                                        2,
                                                        &public_pcm,
                                                        1) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == audio_output_channel_id);
    SCHECK(rdp_audio_output_parse_formats(static_payload,
                                          static_payload_len,
                                          &audio_output_formats) == LIBRDP_STATUS_OK);
    SCHECK(audio_output_formats.flags == RDP_AUDIO_OUTPUT_CAP_ALIVE &&
           audio_output_formats.format_count == 1 &&
           audio_output_formats.version == 2);
    SCHECK(librdp_server_peer_send_audio_output_wave2(peer,
                                                      audio_output_channel_id,
                                                      7,
                                                      0,
                                                      3,
                                                      1234,
                                                      "pcm",
                                                      3) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == audio_output_channel_id);
    SCHECK(rdp_audio_output_parse_wave2(static_payload,
                                        static_payload_len,
                                        &audio_output_wave2) == LIBRDP_STATUS_OK);
    SCHECK(audio_output_wave2.timestamp == 7 &&
           audio_output_wave2.block_no == 3 &&
           audio_output_wave2.data_len == 3 &&
           memcmp(audio_output_wave2.data, "pcm", 3) == 0);
    SCHECK(librdp_server_peer_send_audio_output_close(peer,
                                                      audio_output_channel_id) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == audio_output_channel_id);
    SCHECK(rdp_audio_output_parse_header(static_payload,
                                         static_payload_len,
                                         &audio_output_header) == LIBRDP_STATUS_OK);
    SCHECK(audio_output_header.msg_type == RDP_AUDIO_OUTPUT_CLOSE);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_AUDIO_OUTPUT,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_send_rail_handshake_ex(
               peer,
               rail_channel_id,
               26000,
               RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == rail_channel_id);
    SCHECK(rdp_remote_programs_parse_handshake_ex(static_payload,
                                                  static_payload_len,
                                                  &rail_handshake) == LIBRDP_STATUS_OK);
    SCHECK(rail_handshake.build_number == 26000 &&
           rail_handshake.flags == RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF);
    SCHECK(librdp_server_peer_send_rail_exec_result(peer,
                                                    rail_channel_id,
                                                    RDP_REMOTE_PROGRAMS_EXEC_FLAG_FILE,
                                                    RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK,
                                                    0,
                                                    rail_app_utf16,
                                                    (uint16_t)sizeof(rail_app_utf16)) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == rail_channel_id);
    SCHECK(rdp_remote_programs_parse_exec_result(static_payload,
                                                 static_payload_len,
                                                 &rail_exec_result) == LIBRDP_STATUS_OK);
    SCHECK(rail_exec_result.exec_result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK &&
           rail_exec_result.exe_or_file_len == sizeof(rail_app_utf16));
    SCHECK(librdp_server_peer_send_rail_windowmove(peer,
                                                   rail_channel_id,
                                                   0x1111u,
                                                   10,
                                                   20,
                                                   300,
                                                   400) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == rail_channel_id);
    SCHECK(rdp_remote_programs_parse_windowmove(static_payload,
                                                static_payload_len,
                                                &rail_windowmove) == LIBRDP_STATUS_OK);
    SCHECK(rail_windowmove.window_id == 0x1111u &&
           rail_windowmove.right == 300 &&
           rail_windowmove.bottom == 400);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_RAIL,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_send_multiparty_filter_state(peer,
                                                           multiparty_channel_id,
                                                           RDP_MULTIPARTY_FILTER_ENABLED) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == multiparty_channel_id);
    SCHECK(rdp_multiparty_parse_header(static_payload,
                                       static_payload_len,
                                       &multiparty_header) == LIBRDP_STATUS_OK);
    SCHECK(multiparty_header.type == RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_MULTIPARTY,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_send_video_capability_response(peer,
                                                             video_channel_id,
                                                             0x40u,
                                                             0) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == video_channel_id);
    SCHECK(rdp_video_redirection_parse_exchange_capabilities_response(static_payload,
                                                                      static_payload_len,
                                                                      &video_caps) == LIBRDP_STATUS_OK);
    SCHECK(video_caps.header.message_id == 0x40u &&
           video_caps.result == 0);
    SCHECK(librdp_server_peer_send_video_sample(peer,
                                                video_channel_id,
                                                0x41u,
                                                presentation_id,
                                                2,
                                                "tsmf",
                                                4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == video_channel_id);
    SCHECK(rdp_video_redirection_parse_sample_message(static_payload,
                                                      static_payload_len,
                                                      &video_sample) == LIBRDP_STATUS_OK);
    SCHECK(video_sample.header.message_id == 0x41u &&
           video_sample.stream_id == 2 &&
           video_sample.data_len == 4 &&
           memcmp(video_sample.data, "tsmf", 4) == 0);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_VIDEO,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    memset(&geometry_info, 0, sizeof(geometry_info));
    geometry_info.video_window_id = 0x1122334455667788u;
    geometry_info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW | RDP_VIDEO_REDIRECTION_WINDOW_VISRGN;
    geometry_info.width = 640;
    geometry_info.height = 480;
    geometry_info.left = 10;
    geometry_info.top = 20;
    geometry_info.client_left = 12;
    geometry_info.client_top = 22;
    SCHECK(rdp_video_redirection_write_geometry_info(&geometry_payload, &geometry_info) == LIBRDP_STATUS_OK);
    SCHECK(rdp_video_redirection_write_rect(&geometry_rect_payload, 20, 10, 500, 650) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_send_video_geometry_update(peer,
                                                         video_channel_id,
                                                         42,
                                                         presentation_id,
                                                         geometry_payload.data,
                                                         (uint32_t)geometry_payload.length,
                                                         geometry_rect_payload.data,
                                                         (uint32_t)geometry_rect_payload.length) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == video_channel_id);
    SCHECK(rdp_video_redirection_parse_geometry_update(static_payload,
                                                       static_payload_len,
                                                       &geometry_update) == LIBRDP_STATUS_OK);
    SCHECK(geometry_update.header.message_id == 42 &&
           memcmp(geometry_update.presentation_id, presentation_id, sizeof(presentation_id)) == 0);
    memset(&geometry_info, 0, sizeof(geometry_info));
    SCHECK(rdp_video_redirection_parse_geometry_info(geometry_update.geometry,
                                                     geometry_update.geometry_len,
                                                     &geometry_info) == LIBRDP_STATUS_OK);
    SCHECK(geometry_info.video_window_id == 0x1122334455667788u &&
           geometry_info.width == 640 &&
           geometry_info.client_top == 22);
    SCHECK(rdp_video_redirection_parse_rect(geometry_update.visible_rect,
                                            geometry_update.visible_rect_len,
                                            &geometry_rect) == LIBRDP_STATUS_OK);
    SCHECK(geometry_rect.top == 20 && geometry_rect.left == 10 &&
           geometry_rect.bottom == 500 && geometry_rect.right == 650);
    SCHECK(librdp_server_peer_get_feature_status(peer,
                                                 LIBRDP_FEATURE_GEOMETRY_TRACKING,
                                                 &feature_status) == LIBRDP_STATUS_OK);
    SCHECK(feature_status.requested && feature_status.negotiated && feature_status.active &&
           feature_status.reason == LIBRDP_FEATURE_REASON_NONE);
    SCHECK(librdp_server_peer_send_video_geometry_update(peer,
                                                         static_channel_id,
                                                         43,
                                                         presentation_id,
                                                         geometry_payload.data,
                                                         (uint32_t)geometry_payload.length,
                                                         NULL,
                                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_clipboard_monitor_ready(peer, static_channel_id) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_graphics_default_caps(peer, 99) == LIBRDP_STATUS_INVALID_ARGUMENT);

    SCHECK(librdp_server_peer_surface_blit_bgra32(peer, 0, 0, 4, 4, 16, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_present(peer, 0, 0, 4, 4) == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.surface_event_count == 1);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 4 &&
           bitmap_update.rects[0].height == 4 &&
           bitmap_update.rects[0].bits_per_pixel == 32);
    SCHECK(librdp_server_peer_surface_blit_bgra32(peer, 0, 0, 800, 11, 800u * 4u, large_pixels) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_present(peer, 0, 0, 800, 11) == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.surface_event_count == 2);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 800 &&
           bitmap_update.rects[0].height == 10);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd, response, sizeof(response), &client_security, &slowpath_plaintext, &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 800 &&
           bitmap_update.rects[0].height == 1);
    SCHECK(librdp_server_peer_surface_resize(peer, 4, 4) == LIBRDP_STATUS_OK);
    demand_plaintext.length = 0;
    SCHECK(test_server_read_encrypted_mcs_payload(client_fd,
                                                  response,
                                                  sizeof(response),
                                                  &client_security,
                                                  &demand_plaintext));
    SCHECK(rdp_slowpath_parse_demand_active(demand_plaintext.data,
                                            demand_plaintext.length,
                                            &demand) == LIBRDP_STATUS_OK);
    SCHECK(demand.share_id == 0x00010001u);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_send_confirm_active(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL);
    SCHECK(test_server_send_client_synchronize(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 4));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 1));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_font_list(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP);
    SCHECK(test_server_read_encrypted_slowpath_data_pdu(client_fd,
                                                        response,
                                                        sizeof(response),
                                                        &client_security,
                                                        &slowpath_plaintext,
                                                        &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(runtime_context.surface_event_count == 4);

    SCHECK(test_server_send_keyboard_input(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.key_count == 1);
    SCHECK(test_server_send_sync_input(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.synchronize_count >= 1u);

    channel_count_before_static = runtime_context.channel_count;
    extension_count_before_static = runtime_context.extension_count;
    SCHECK(test_server_send_static_channel_data(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.channel_count == channel_count_before_static + 1u);
    SCHECK(runtime_context.extension_count == extension_count_before_static);
    SCHECK(runtime_context.last_channel_id == static_channel_id);
    SCHECK(runtime_context.channel_payload_len == 4 &&
           runtime_context.channel_payload[0] == 1 &&
           runtime_context.channel_payload[3] == 4);
    SCHECK(librdp_server_peer_send_channel_data(peer, static_channel_id, pixels, 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_encrypted_static_channel_data(client_fd,
                                                          response,
                                                          sizeof(response),
                                                          &client_security,
                                                          &channel_plaintext,
                                                          &response_channel_id,
                                                          &static_payload,
                                                          &static_payload_len));
    SCHECK(response_channel_id == static_channel_id &&
           static_payload_len == 4 &&
           static_payload[0] == pixels[0] &&
           static_payload[3] == pixels[3]);
    error_count_before_surface = runtime_context.error_event_count;
    SCHECK(librdp_server_peer_surface_present(peer, 900, 0, 1, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(runtime_context.error_event_count == error_count_before_surface + 1u);
    SCHECK(runtime_context.last_error_status == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_status_init(&server_status) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_last_status(peer, &server_status) == LIBRDP_STATUS_OK);
    SCHECK(server_status.status == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(strcmp(server_status.phase, "server.surface.present") == 0);
    SCHECK(librdp_server_metrics_init(&server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(server_metrics.bytes_read > 0 && server_metrics.bytes_written > 0);
    SCHECK(server_metrics.pdu_in > 0 && server_metrics.pdu_out > 0);
    SCHECK(server_metrics.input_events == runtime_context.input_count);
    SCHECK(server_metrics.static_channel_in == 7 && server_metrics.static_channel_out >= 2);
    SCHECK(server_metrics.static_channel_bytes_in > 4 && server_metrics.static_channel_bytes_out >= 4);
    SCHECK(server_metrics.dynamic_channel_in == 4);
    SCHECK(server_metrics.dynamic_channel_out == 35);
    SCHECK(server_metrics.dynamic_channel_bytes_in == 38 && server_metrics.dynamic_channel_bytes_out > 64);
    SCHECK(server_metrics.udp_datagrams_in == 2);
    SCHECK(server_metrics.udp_datagrams_out == 2);
    SCHECK(server_metrics.udp_ack_vector_out == 2);
    SCHECK(server_metrics.udp_pending_packets == 1);
    SCHECK(server_metrics.udp_tcp_fallbacks == 1);
    SCHECK(server_metrics.udp2_datagrams_in == 3);
    SCHECK(server_metrics.udp2_datagrams_out == 3);
    SCHECK(server_metrics.udp2_ack_out == 2);
    SCHECK(server_metrics.udp2_ack_vector_out == 1);
    SCHECK(server_metrics.udp2_lost_packets == 1);
    SCHECK(server_metrics.udp2_reordered_packets == 1);
    SCHECK(server_metrics.udp2_tcp_fallbacks == 1);
    SCHECK(server_metrics.surface_updates == 3);
    SCHECK(librdp_server_peer_reset_metrics(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_metrics_init(&server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(peer, &server_metrics) == LIBRDP_STATUS_OK);
    SCHECK(server_metrics.bytes_read == 0 && server_metrics.bytes_written == 0);
    dynamic_count_before_peer_close = librdp_server_peer_dynamic_channel_count(peer);
    dynamic_close_count_before_peer_close = runtime_context.dynamic_close_count;
    SCHECK(dynamic_count_before_peer_close > 0);
    dvc_packet.length = 0;
    SCHECK(rdp_slowpath_write_client_synchronize(&dvc_packet,
                                                 demand.share_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_encrypted_slowpath(client_fd,
                                               attach_confirm.user_id,
                                               &client_security,
                                               &dvc_packet,
                                               TEST_SERVER_SECURITY_TAMPER_SIGNATURE));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_FAILED);
    SCHECK(librdp_server_peer_close(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_close(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_count(peer) == 0);
    SCHECK(runtime_context.dynamic_close_count ==
           dynamic_close_count_before_peer_close + dynamic_count_before_peer_close);
    SCHECK(librdp_server_peer_close(peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED);
    memset(client_random, 0, sizeof(client_random));
    rdp_security_standard_clear(&client_security);
    rdp_security_public_key_clear(&server_public_key);
    rdp_buffer_free(&encrypted_client_random);
    rdp_buffer_free(&demand_plaintext);
    rdp_buffer_free(&slowpath_plaintext);
    rdp_buffer_free(&channel_plaintext);
    rdp_buffer_free(&geometry_rect_payload);
    rdp_buffer_free(&geometry_payload);
    rdp_buffer_free(&graphics_payload);
    rdp_buffer_free(&udp_wire);
    rdp_buffer_free(&udp2_unwrapped);
    rdp_buffer_free(&udp2_wire);
    rdp_buffer_free(&udp2_payload);
    rdp_buffer_free(&dvc_packet);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&license_payload);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

int main(void)
{
    if (test_server_config_defaults() != 0)
        return 1;
    if (test_server_new_validates_metadata() != 0)
        return 1;
    if (test_server_transport_feature_gates() != 0)
        return 1;
    if (test_server_public_feature_backend_readiness() != 0)
        return 1;
    if (test_server_feature_status_reason_contract() != 0)
        return 1;
    if (test_server_new_copies_strings() != 0)
        return 1;
    if (test_server_loopback_negotiation_failure() != 0)
        return 1;
    if (test_server_loopback_tls_handshake() != 0)
        return 1;
    if (test_server_loopback_tls_mismatched_key() != 0)
        return 1;
    if (test_server_loopback_nla_handshake() != 0)
        return 1;
    if (test_server_loopback_nla_combined_public_key() != 0)
        return 1;
    if (test_server_loopback_nla_reject_vectors() != 0)
        return 1;
    if (test_server_standard_security_tamper_vectors() != 0)
        return 1;
    if (test_server_loopback_standard_activation_sequence() != 0)
        return 1;
    return 0;
}
