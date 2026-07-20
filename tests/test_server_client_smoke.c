/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application desktop-server loopback smoke tests.
 * Coverage: Standard, TLS, and NLA activation through the shared server host
 * with synthetic capture, input, clipboard, drive, and permission providers.
 * Bug classes: security-profile drift, provider negotiation gaps, stalled
 * activation, missing graphics delivery, dropped input, and drive lifecycle.
 * Determinism: all transport stays on loopback, credentials and certificates
 * are ephemeral, and native providers use bounded in-memory state.
 */

#include "client_runtime.h"
#include "client/session_redirection.h"
#include "server_host.h"
#include "server_platform.h"
#include "test_http_proxy.h"
#include "test_rdg_gateway.h"
#include "test_server_support.h"

#include "channels/graphics_pipeline.h"
#include "graphics/bitmap.h"
#include "graphics/planar.h"
#include "protocol/fastpath.h"
#include "protocol/session_selection.h"
#include "server/server_internal.h"
#include "server/server_security.h"

#include <librdp/librdp.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SMOKE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_CAPTURE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_CAPTURE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_PIXEL_BYTES (SMOKE_CAPTURE_WIDTH * SMOKE_CAPTURE_HEIGHT * 4u)
#define SMOKE_PUMP_LIMIT 500u
#define SMOKE_LIFECYCLE_CAPACITY 32u
#define SMOKE_TRACE_RECENT_CAPACITY 32u
#define SMOKE_TRACE_RECENT_LINE 256u
#define SMOKE_LIFECYCLE_STRESS_CYCLES 24u
#define SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES 4u
#define SMOKE_LIFECYCLE_STRESS_RSS_ALLOWANCE (32u * 1024u * 1024u)
#define SMOKE_DESCRIPTOR_SCAN_LIMIT 1048576L
#define SMOKE_SHA256_BYTES 32u

#if defined(__SANITIZE_ADDRESS__)
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 1
#else
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 0
#endif
#else
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 0
#endif

typedef struct smoke_nla_identity
{
    const char* username;
    const char* password;
    const char* domain;
} smoke_nla_identity;

static const smoke_nla_identity smoke_nla_default_identity = {
    "smoke-user-731",
    "smoke-secret-739",
    "SMOKE-DOMAIN-733",
};
static const smoke_nla_identity smoke_nla_no_domain_identity = {
    "smoke-user-743",
    "smoke-secret-751",
    NULL,
};
static const smoke_nla_identity smoke_nla_empty_domain_identity = {
    "smoke-user-757",
    "smoke-secret-761",
    "",
};
static const smoke_nla_identity smoke_nla_upn_identity = {
    "smoke.user.769@example.test",
    "smoke-secret-773",
    NULL,
};
static const smoke_nla_identity smoke_nla_utf8_identity = {
    "smoke-us\xc3\xa9r-787",
    "smoke-secret-797",
    "D\xc3\x96M\xc3\x84IN-809",
};
static const smoke_nla_identity smoke_gateway_identity = {
    "gateway-user-811",
    "gateway-secret-821",
    "GATEWAY-DOMAIN-823",
};
static const smoke_nla_identity smoke_gateway_reject_identity = {
    "gateway-reject-user-827",
    "gateway-reject-secret-829",
    "GATEWAY-REJECT-DOMAIN-839",
};
static const uint8_t smoke_frame_sha256[SMOKE_SHA256_BYTES] = {
    0x91, 0x43, 0x12, 0xa9, 0x79, 0x81, 0xea, 0x05,
    0x7b, 0xc0, 0x70, 0x89, 0xd2, 0x35, 0x85, 0x90,
    0xa7, 0x9d, 0x05, 0xcc, 0x05, 0xb9, 0x07, 0x3d,
    0x7a, 0x63, 0x59, 0x09, 0xb9, 0xfc, 0x7b, 0xec,
};
static const uint8_t smoke_alternate_frame_sha256[SMOKE_SHA256_BYTES] = {
    0xac, 0x72, 0x02, 0xe7, 0xf6, 0x7f, 0x6a, 0x48,
    0x98, 0x87, 0xb6, 0xca, 0x2e, 0x2e, 0x55, 0x19,
    0x40, 0x42, 0xc0, 0x0e, 0x14, 0xe6, 0xa9, 0x77,
    0x96, 0x55, 0x26, 0xbc, 0x9e, 0x7f, 0xfd, 0xf5,
};
static const uint8_t smoke_fastpath_bitmap_sha256[SMOKE_SHA256_BYTES] = {
    0xbe, 0x9b, 0x92, 0xcb, 0xbe, 0xa1, 0xde, 0x7b,
    0xac, 0xb2, 0x82, 0x48, 0xc0, 0x1d, 0x22, 0xa1,
    0x66, 0xbe, 0x42, 0x44, 0x59, 0xd9, 0x83, 0xc5,
    0x82, 0x6a, 0x54, 0x7c, 0x8f, 0x9d, 0xed, 0x98,
};

typedef struct smoke_platform
{
    server_platform_capture_sink capture_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_drive_sink drive_sink;
    server_platform_permission_sink permission_sink;
    atomic_uint capture_requests;
    atomic_uint capture_variant;
    atomic_uint key_events;
    atomic_uint mouse_events;
    atomic_uint clipboard_offers;
    atomic_uint drive_presentations;
    atomic_uint releases;
    atomic_uint refresh_requests;
    atomic_uint output_suppressions;
    atomic_uint output_resumptions;
    char drive_name[64];
    uint8_t pixels[SMOKE_PIXEL_BYTES];
    uint8_t alternate_pixels[SMOKE_PIXEL_BYTES];
} smoke_platform;

typedef struct smoke_host
{
    server_host* host;
    pthread_t thread;
    atomic_uint port;
    librdp_status status;
} smoke_host;

typedef struct smoke_nla_stall
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint authenticating;
    librdp_status status;
} smoke_nla_stall;

typedef enum smoke_integrity_tamper
{
    SMOKE_INTEGRITY_SLOWPATH_MAC = 1,
    SMOKE_INTEGRITY_FASTPATH_MAC = 2,
    SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT = 3
} smoke_integrity_tamper;

typedef enum smoke_gateway_credentials
{
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT = 0,
    SMOKE_GATEWAY_CREDENTIALS_SESSION = 1,
    SMOKE_GATEWAY_CREDENTIALS_NONE = 2
} smoke_gateway_credentials;

typedef struct smoke_gateway_profile
{
    librdp_gateway_mode mode;
    smoke_gateway_credentials credentials;
    test_http_proxy_behavior proxy_behavior;
    int reject_credentials;
    int trust_certificate;
    uint32_t timeout_ms;
    librdp_status expected_status;
    librdp_status expected_fixture_status;
    test_rdg_stream drop_stream;
} smoke_gateway_profile;

static const smoke_gateway_profile smoke_gateway_http_explicit = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_session = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_SESSION,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_no_credentials = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_NONE,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_AUTHENTICATION_FAILED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg_drop_out = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_OUT,
};
static const smoke_gateway_profile smoke_gateway_rdg_drop_in = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_IN,
};
static const smoke_gateway_profile smoke_gateway_http_auth_failure = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    1,
    1,
    5000u,
    LIBRDP_STATUS_AUTHENTICATION_FAILED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_timeout = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_STALL,
    0,
    1,
    100u,
    LIBRDP_STATUS_TIMEOUT,
    LIBRDP_STATUS_TIMEOUT,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_malformed = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_MALFORMED_RESPONSE,
    0,
    1,
    5000u,
    LIBRDP_STATUS_IO_ERROR,
    LIBRDP_STATUS_PROTOCOL_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_refused = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_REFUSE,
    0,
    1,
    5000u,
    LIBRDP_STATUS_IO_ERROR,
    LIBRDP_STATUS_CLOSED,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg_untrusted = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    0,
    5000u,
    LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};

typedef struct smoke_integrity_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint packet_sent;
    atomic_uint client_closed;
    smoke_integrity_tamper tamper;
    librdp_status status;
} smoke_integrity_peer;

typedef struct smoke_fastpath_bitmap_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint packet_sent;
    atomic_uint client_closed;
    librdp_status status;
} smoke_fastpath_bitmap_peer;

typedef struct smoke_graphics_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint caps_advertised;
    atomic_uint frame_acknowledged;
    atomic_uint frame_sent;
    atomic_uint client_closed;
    librdp_status status;
} smoke_graphics_peer;

typedef struct smoke_redirection_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint connections;
    atomic_uint redirects;
    atomic_uint route_verified;
    int enhanced;
    int loop;
    librdp_status status;
} smoke_redirection_peer;

typedef enum smoke_security_peer_mode
{
    SMOKE_SECURITY_PEER_DOWNGRADE = 1,
    SMOKE_SECURITY_PEER_TLS_CERTIFICATE = 2,
    SMOKE_SECURITY_PEER_TLS_INVALID = 3
} smoke_security_peer_mode;

typedef struct smoke_security_peer
{
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    smoke_security_peer_mode mode;
    const char* certificate_path;
    const char* private_key_path;
    librdp_status status;
} smoke_security_peer;

typedef struct smoke_client_events
{
    unsigned int state_events;
    unsigned int surface_events;
    unsigned int error_events;
    int active;
    int active_seen;
} smoke_client_events;

typedef struct smoke_nla_provider
{
    librdp_status status;
    unsigned int calls;
} smoke_nla_provider;

typedef struct smoke_trace_capture
{
    unsigned int records;
    unsigned int connect_starts;
    unsigned int connect_completions;
    unsigned int client_connect_successes;
    unsigned int client_connect_failures;
    unsigned int client_connect_cancellations;
    unsigned int credssp_failures;
    unsigned int slowpath_integrity_failures;
    unsigned int fastpath_integrity_failures;
    unsigned int integrity_failures;
    unsigned int security_downgrades;
    unsigned int tls_connect_failures;
    unsigned int tls_verify_failures;
    unsigned int gateway_connect_starts;
    unsigned int gateway_connect_completions;
    unsigned int rdg_connect_starts;
    unsigned int rdg_connect_completions;
    unsigned int rdg_handshakes;
    unsigned int rdg_tunnels;
    unsigned int rdg_authentications;
    unsigned int rdg_channels;
    unsigned int redirections;
    unsigned int redirection_reconnects;
    unsigned int redirection_loops;
    unsigned int slowpath_bitmap_updates;
    unsigned int fastpath_bitmap_updates;
    unsigned int graphics_caps_confirms;
    unsigned int graphics_surface_creates;
    unsigned int graphics_surface_maps;
    unsigned int graphics_planar_updates;
    unsigned int graphics_uncompressed_updates;
    unsigned int graphics_frame_starts;
    unsigned int graphics_frame_ends;
    unsigned int graphics_frame_acks;
    unsigned int graphics_surface_deletes;
    unsigned int refresh_requests;
    unsigned int output_suppressions;
    unsigned int output_resumptions;
    unsigned int cancel_requests;
    int cancel_phase;
    librdp_status cancel_status;
    librdp_session_lifecycle lifecycle[SMOKE_LIFECYCLE_CAPACITY];
    size_t lifecycle_count;
    char recent[SMOKE_TRACE_RECENT_CAPACITY]
               [SMOKE_TRACE_RECENT_LINE];
    size_t recent_count;
    size_t recent_next;
    int lifecycle_overflow;
    int leaked;
    int address_matched;
    const smoke_nla_identity* identity;
    const smoke_nla_identity* gateway_identity;
    const char* target;
    uint16_t port;
} smoke_trace_capture;

static int smoke_check(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_server_client_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expression)                                                                           \
    do                                                                                              \
    {                                                                                               \
        if (smoke_check((expression), #expression, __LINE__) != 0)                                 \
            return 1;                                                                               \
    } while (0)

#define REQUIRE(expression)                                                                         \
    do                                                                                              \
    {                                                                                               \
        if (smoke_check((expression), #expression, __LINE__) != 0)                                 \
        {                                                                                           \
            result = 1;                                                                             \
            goto cleanup;                                                                           \
        }                                                                                           \
    } while (0)

static uint64_t smoke_now_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return (uint64_t)value.tv_sec * 1000000000u + (uint64_t)value.tv_nsec;
}

/*
 * Hash a complete presented surface with the mandatory crypto backend. Fixed
 * digests detect row-order, stride, tiling, and partial-update regressions
 * without retaining image artifacts.
 */
static int smoke_frame_matches_sha256(
    const uint8_t* pixels,
    size_t pixels_len,
    const uint8_t expected[SMOKE_SHA256_BYTES])
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;

    if (!pixels || !expected ||
        EVP_Digest(pixels,
                   pixels_len,
                   digest,
                   &digest_len,
                   EVP_sha256(),
                   NULL) != 1)
        return 0;
    return digest_len == SMOKE_SHA256_BYTES &&
           CRYPTO_memcmp(digest,
                         expected,
                         SMOKE_SHA256_BYTES) == 0;
}

static librdp_status smoke_nla_credentials_provider(
    librdp_server_peer* peer,
    const librdp_server_credentials_request* request,
    librdp_credentials* credentials,
    void* user_data)
{
    smoke_nla_provider* provider = (smoke_nla_provider*)user_data;

    if (!peer || !request || !credentials || !provider)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    provider->calls++;
    return provider->status;
}

static void smoke_trace_callback(librdp_session* session,
                                 const librdp_trace_record* record,
                                 void* user_data)
{
    smoke_trace_capture* capture = (smoke_trace_capture*)user_data;
    char expected_address[320] = {0};

    (void)session;
    if (!capture || !record || !record->line)
        return;
    if (getenv("LIBRDP_SMOKE_TRACE_OUTPUT"))
        fprintf(stderr, "%s\n", record->line);
    (void)snprintf(
        capture->recent[capture->recent_next],
        sizeof(capture->recent[capture->recent_next]),
        "%s",
        record->line);
    capture->recent_next =
        (capture->recent_next + 1u) %
        SMOKE_TRACE_RECENT_CAPACITY;
    if (capture->recent_count <
        SMOKE_TRACE_RECENT_CAPACITY)
        capture->recent_count++;
    capture->records++;
    if (record->event &&
        strcmp(record->event, "transport.tcp.connect.start") == 0)
    {
        capture->connect_starts++;
        if (capture->target && record->message &&
            snprintf(expected_address,
                     sizeof(expected_address),
                     "host=%s port=%u",
                     capture->target,
                     (unsigned int)capture->port) > 0 &&
            strcmp(record->message, expected_address) == 0)
            capture->address_matched = 1;
    }
    else if (record->event &&
             strcmp(record->event, "transport.tcp.connect.done") == 0)
        capture->connect_completions++;
    else if (record->event &&
             strcmp(record->event, "client.connect.done") == 0)
        capture->client_connect_successes++;
    else if (record->event &&
             strcmp(record->event, "client.connect.failed") == 0)
        capture->client_connect_failures++;
    else if (record->event &&
             strcmp(record->event, "client.connect.cancelled") == 0)
        capture->client_connect_cancellations++;
    else if (record->event &&
             strcmp(record->event, "credssp.nla.failed") == 0)
        capture->credssp_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.security.signature.mismatch") == 0)
        capture->slowpath_integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.fastpath.signature.mismatch") == 0)
        capture->fastpath_integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.security.integrity.failed") == 0)
        capture->integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "x224.negotiation.downgrade") == 0)
        capture->security_downgrades++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.tls.connect.failed") == 0)
        capture->tls_connect_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.tls.verify.failed") == 0)
        capture->tls_verify_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.connect.start") == 0)
        capture->gateway_connect_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.connect.done") == 0)
        capture->gateway_connect_completions++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.connect.start") == 0)
        capture->rdg_connect_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.connect.done") == 0)
        capture->rdg_connect_completions++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.handshake.done") == 0)
        capture->rdg_handshakes++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.tunnel.done") == 0)
        capture->rdg_tunnels++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.auth.done") == 0)
        capture->rdg_authentications++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.channel.done") == 0)
        capture->rdg_channels++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.received") == 0)
        capture->redirections++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.reconnect.done") == 0)
        capture->redirection_reconnects++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.loop_rejected") == 0)
        capture->redirection_loops++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.slowpath.bitmap_update") == 0)
        capture->slowpath_bitmap_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.fastpath.bitmap_update") == 0)
        capture->fastpath_bitmap_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.caps_confirm") == 0)
        capture->graphics_caps_confirms++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.create") == 0)
        capture->graphics_surface_creates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.map_output") == 0)
        capture->graphics_surface_maps++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.wire_to_surface") == 0 &&
             record->message &&
             strstr(record->message, "codec_id=10 ") != NULL)
        capture->graphics_planar_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.wire_to_surface") == 0 &&
             record->message &&
             strstr(record->message, "codec_id=0 ") != NULL)
        capture->graphics_uncompressed_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame.start") == 0)
        capture->graphics_frame_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame.end") == 0)
        capture->graphics_frame_ends++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame_ack") == 0)
        capture->graphics_frame_acks++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.delete") == 0)
        capture->graphics_surface_deletes++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.refresh_rect") == 0)
        capture->refresh_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.output.suppressed") == 0)
        capture->output_suppressions++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.output.resumed") == 0)
        capture->output_resumptions++;
    else if (record->event &&
             strcmp(record->event, "client.lifecycle") == 0 &&
             record->message)
    {
        unsigned long phase = 0ul;
        char* end = NULL;

        errno = 0;
        if (strncmp(record->message, "phase=", 6u) == 0)
        {
            phase = strtoul(record->message + 6u, &end, 10);
            if (errno == 0 && end && *end == '\0' &&
                phase <= (unsigned long)LIBRDP_LIFECYCLE_FAILED)
            {
                if (capture->lifecycle_count <
                    SMOKE_LIFECYCLE_CAPACITY)
                {
                    capture->lifecycle[capture->lifecycle_count++] =
                        (librdp_session_lifecycle)phase;
                }
                else
                    capture->lifecycle_overflow = 1;
                if (capture->cancel_phase == (int)phase &&
                    capture->cancel_requests == 0u)
                {
                    capture->cancel_requests++;
                    capture->cancel_status =
                        librdp_session_cancel(session);
                }
            }
        }
    }
    {
        const smoke_nla_identity* identities[2] = {
            capture->identity,
            capture->gateway_identity
        };
        size_t index = 0u;

        for (index = 0u; index < 2u; index++)
        {
            const smoke_nla_identity* identity = identities[index];

            if (!identity)
                continue;
            if ((identity->username &&
                 strstr(record->line, identity->username)) ||
                (identity->password &&
                 strstr(record->line, identity->password)) ||
                (identity->domain && identity->domain[0] != '\0' &&
                 strstr(record->line, identity->domain)))
                capture->leaked = 1;
        }
    }
}

/*
 * Validate the complete lifecycle observed through the per-session trace.
 * Negotiation and authentication may alternate while Standard Security or NLA
 * exchanges are in progress, but terminal and transport phases remain strict.
 */
static int smoke_validate_lifecycle(
    const smoke_trace_capture* capture,
    librdp_security_mode security)
{
    size_t index = 0u;
    size_t connecting_index = SIZE_MAX;
    size_t tls_index = SIZE_MAX;
    size_t authenticating_index = SIZE_MAX;
    size_t activating_index = SIZE_MAX;
    size_t active_index = SIZE_MAX;
    size_t disconnecting_index = SIZE_MAX;
    size_t disconnected_index = SIZE_MAX;
    unsigned int connecting_count = 0u;
    unsigned int tls_count = 0u;
    unsigned int activating_count = 0u;
    unsigned int active_count = 0u;
    unsigned int disconnecting_count = 0u;
    unsigned int disconnected_count = 0u;

    if (!capture || capture->lifecycle_overflow ||
        capture->lifecycle_count < 7u ||
        capture->lifecycle[0] != LIBRDP_LIFECYCLE_NEW)
        return 0;
    for (index = 1u; index < capture->lifecycle_count; index++)
    {
        librdp_session_lifecycle phase = capture->lifecycle[index];

        if (phase == capture->lifecycle[index - 1u] ||
            phase == LIBRDP_LIFECYCLE_FAILED ||
            phase == LIBRDP_LIFECYCLE_RECONNECTING)
            return 0;
        switch (phase)
        {
            case LIBRDP_LIFECYCLE_RESOLVING:
                if (connecting_index != SIZE_MAX)
                    return 0;
                break;
            case LIBRDP_LIFECYCLE_CONNECTING:
                connecting_count++;
                connecting_index = index;
                break;
            case LIBRDP_LIFECYCLE_TLS_HANDSHAKE:
                tls_count++;
                tls_index = index;
                break;
            case LIBRDP_LIFECYCLE_AUTHENTICATING:
                if (authenticating_index == SIZE_MAX)
                    authenticating_index = index;
                break;
            case LIBRDP_LIFECYCLE_NEGOTIATING:
                break;
            case LIBRDP_LIFECYCLE_ACTIVATING:
                activating_count++;
                activating_index = index;
                break;
            case LIBRDP_LIFECYCLE_ACTIVE:
                active_count++;
                active_index = index;
                break;
            case LIBRDP_LIFECYCLE_DISCONNECTING:
                disconnecting_count++;
                disconnecting_index = index;
                break;
            case LIBRDP_LIFECYCLE_DISCONNECTED:
                disconnected_count++;
                disconnected_index = index;
                break;
            default:
                return 0;
        }
    }
    if (connecting_count != 1u || activating_count != 1u ||
        active_count != 1u || disconnecting_count != 1u ||
        disconnected_count != 1u ||
        authenticating_index == SIZE_MAX ||
        !(connecting_index < authenticating_index &&
          authenticating_index < activating_index &&
          activating_index < active_index &&
          active_index < disconnecting_index &&
          disconnecting_index < disconnected_index) ||
        disconnected_index + 1u != capture->lifecycle_count)
        return 0;
    if (security == LIBRDP_SECURITY_STANDARD)
        return tls_count == 0u;
    return tls_count == 1u && connecting_index < tls_index &&
           tls_index < authenticating_index;
}

static librdp_status smoke_capture_start(
    void* context,
    const server_platform_capture_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->frame || !sink->lost)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->capture_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_capture_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->capture_sink, 0, sizeof(platform->capture_sink));
}

/*
 * Emit a complete deterministic frame synchronously. The host copies the
 * pixels before this callback returns, so no provider buffer escapes.
 */
static librdp_status smoke_capture_request(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;
    server_platform_frame frame;
    unsigned int sequence = 0u;
    unsigned int variant = 0u;

    if (!platform || !platform->capture_sink.frame)
        return LIBRDP_STATUS_STATE;
    sequence = atomic_fetch_add_explicit(&platform->capture_requests,
                                         1u,
                                         memory_order_relaxed) +
               1u;
    memset(&frame, 0, sizeof(frame));
    frame.width = SMOKE_CAPTURE_WIDTH;
    frame.height = SMOKE_CAPTURE_HEIGHT;
    frame.stride = SMOKE_CAPTURE_WIDTH * 4u;
    variant = atomic_load_explicit(&platform->capture_variant,
                                   memory_order_acquire);
    frame.pixels = variant ? platform->alternate_pixels :
                             platform->pixels;
    frame.pixels_len = sizeof(platform->pixels);
    frame.sequence = sequence;
    frame.timestamp_ns = smoke_now_ns();
    platform->capture_sink.frame(&frame,
                                 platform->capture_sink.user_data);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_input_inject(
    void* context,
    const librdp_server_input_event* event)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY ||
        event->type == LIBRDP_SERVER_INPUT_UNICODE_KEY)
    {
        atomic_fetch_add_explicit(&platform->key_events,
                                  1u,
                                  memory_order_relaxed);
    }
    else if (event->type == LIBRDP_SERVER_INPUT_MOUSE ||
             event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE)
    {
        atomic_fetch_add_explicit(&platform->mouse_events,
                                  1u,
                                  memory_order_relaxed);
    }
    return LIBRDP_STATUS_OK;
}

static void smoke_input_release(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
    {
        atomic_fetch_add_explicit(&platform->releases,
                                  1u,
                                  memory_order_relaxed);
    }
}

static librdp_status smoke_clipboard_start(
    void* context,
    const server_platform_clipboard_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->formats || !sink->data ||
        !sink->request || !sink->file_request || !sink->cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->clipboard_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_clipboard_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->clipboard_sink, 0, sizeof(platform->clipboard_sink));
}

static librdp_status smoke_clipboard_publish(
    void* context,
    const server_platform_clipboard_offer* offer)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !offer ||
        (offer->format_count > 0u && !offer->formats))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_fetch_add_explicit(&platform->clipboard_offers,
                              1u,
                              memory_order_relaxed);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_clipboard_request_data(void* context,
                                                  uint64_t request_id,
                                                  uint32_t format_id)
{
    return context && request_id != 0u && format_id != 0u
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status smoke_clipboard_request_file(
    void* context,
    const server_platform_clipboard_file_request* request)
{
    return context && request && request->request_id != 0u
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status smoke_clipboard_write(
    void* context,
    const server_platform_clipboard_data* data)
{
    return context && data &&
                   (data->data_len == 0u || data->data != NULL)
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void smoke_clipboard_cancel(void* context,
                                   uint32_t peer_id,
                                   uint32_t generation)
{
    (void)context;
    (void)peer_id;
    (void)generation;
}

static void smoke_clipboard_release(void* context, uint64_t generation)
{
    (void)context;
    (void)generation;
}

static librdp_status smoke_drive_start(
    void* context,
    const server_platform_drive_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->request || !sink->cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->drive_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_drive_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->drive_sink, 0, sizeof(platform->drive_sink));
}

static librdp_status smoke_drive_present(
    void* context,
    const server_platform_drive_volume* volume)
{
    smoke_platform* platform = (smoke_platform*)context;
    int length = 0;

    if (!platform || !volume || !volume->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    length = snprintf(platform->drive_name,
                      sizeof(platform->drive_name),
                      "%s",
                      volume->name);
    if (length < 0 || (size_t)length >= sizeof(platform->drive_name))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    atomic_fetch_add_explicit(&platform->drive_presentations,
                              1u,
                              memory_order_release);
    return LIBRDP_STATUS_OK;
}

static void smoke_drive_remove(void* context,
                               uint32_t peer_id,
                               uint32_t generation,
                               uint32_t device_id)
{
    (void)context;
    (void)peer_id;
    (void)generation;
    (void)device_id;
}

static void smoke_drive_remove_peer(void* context,
                                    uint32_t peer_id,
                                    uint32_t generation)
{
    (void)context;
    (void)peer_id;
    (void)generation;
}

static librdp_status smoke_drive_complete(
    void* context,
    const server_platform_drive_completion* completion)
{
    return context && completion
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status smoke_permission_start(
    void* context,
    const server_platform_permission_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->changed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->permission_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_permission_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->permission_sink, 0, sizeof(platform->permission_sink));
}

static librdp_status smoke_permission_query(
    void* context,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    if (!context || !state ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = SERVER_PLATFORM_PERMISSION_GRANTED;
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_permission_change(
    void* context,
    server_platform_permission_kind kind)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (platform->permission_sink.changed)
    {
        platform->permission_sink.changed(
            kind,
            SERVER_PLATFORM_PERMISSION_GRANTED,
            platform->permission_sink.user_data);
    }
    return LIBRDP_STATUS_OK;
}

static const server_platform_capture_vtable smoke_capture_vtable = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    smoke_capture_start,
    smoke_capture_stop,
    smoke_capture_request,
    NULL,
};

static const server_platform_input_vtable smoke_input_vtable = {
    SERVER_PLATFORM_INPUT_VERSION,
    sizeof(server_platform_input_vtable),
    smoke_input_inject,
    smoke_input_release,
};

static const server_platform_clipboard_vtable smoke_clipboard_vtable = {
    SERVER_PLATFORM_CLIPBOARD_VERSION,
    sizeof(server_platform_clipboard_vtable),
    smoke_clipboard_start,
    smoke_clipboard_stop,
    smoke_clipboard_publish,
    smoke_clipboard_request_data,
    smoke_clipboard_request_file,
    smoke_clipboard_write,
    smoke_clipboard_cancel,
    smoke_clipboard_release,
    NULL,
};

static const server_platform_drive_vtable smoke_drive_vtable = {
    SERVER_PLATFORM_DRIVE_VERSION,
    sizeof(server_platform_drive_vtable),
    smoke_drive_start,
    smoke_drive_stop,
    smoke_drive_present,
    smoke_drive_remove,
    smoke_drive_remove_peer,
    smoke_drive_complete,
    NULL,
};

static const server_platform_permission_vtable smoke_permission_vtable = {
    SERVER_PLATFORM_PERMISSION_VERSION,
    sizeof(server_platform_permission_vtable),
    smoke_permission_start,
    smoke_permission_stop,
    smoke_permission_query,
    smoke_permission_change,
    smoke_permission_change,
    NULL,
};

static void smoke_platform_init(smoke_platform* platform,
                                server_host_config* config)
{
    size_t pixel = 0u;

    memset(platform, 0, sizeof(*platform));
    for (pixel = 0u; pixel < SMOKE_PIXEL_BYTES; pixel += 4u)
    {
        platform->pixels[pixel] = (uint8_t)(pixel / 4u);
        platform->pixels[pixel + 1u] = 0x5au;
        platform->pixels[pixel + 2u] = 0xc3u;
        platform->pixels[pixel + 3u] = 0xffu;
        platform->alternate_pixels[pixel] =
            (uint8_t)(0xf0u ^ (uint8_t)(pixel / 4u));
        platform->alternate_pixels[pixel + 1u] = 0xa5u;
        platform->alternate_pixels[pixel + 2u] = 0x3cu;
        platform->alternate_pixels[pixel + 3u] = 0xffu;
    }
    atomic_init(&platform->capture_requests, 0u);
    atomic_init(&platform->capture_variant, 0u);
    atomic_init(&platform->key_events, 0u);
    atomic_init(&platform->mouse_events, 0u);
    atomic_init(&platform->clipboard_offers, 0u);
    atomic_init(&platform->drive_presentations, 0u);
    atomic_init(&platform->releases, 0u);
    atomic_init(&platform->refresh_requests, 0u);
    atomic_init(&platform->output_suppressions, 0u);
    atomic_init(&platform->output_resumptions, 0u);
    config->platform.capture.vtable = &smoke_capture_vtable;
    config->platform.capture.context = platform;
    config->platform.input.vtable = &smoke_input_vtable;
    config->platform.input.context = platform;
    config->platform.clipboard.vtable = &smoke_clipboard_vtable;
    config->platform.clipboard.context = platform;
    config->platform.drive.vtable = &smoke_drive_vtable;
    config->platform.drive.context = platform;
    config->platform.permission.vtable = &smoke_permission_vtable;
    config->platform.permission.context = platform;
    config->drive.enabled = 1;
    config->drive.read_only = 1;
}

static void smoke_host_trace_callback(
    const server_host_trace_event* event,
    void* user_data)
{
    smoke_platform* platform = (smoke_platform*)user_data;

    if (!platform || !event)
        return;
    if (event->type == SERVER_HOST_TRACE_REFRESH_REQUEST)
    {
        atomic_fetch_add_explicit(&platform->refresh_requests,
                                  1u,
                                  memory_order_release);
    }
    else if (event->type ==
             SERVER_HOST_TRACE_OUTPUT_SUPPRESSION)
    {
        atomic_uint* counter =
            event->value ?
                &platform->output_suppressions :
                &platform->output_resumptions;

        atomic_fetch_add_explicit(counter,
                                  1u,
                                  memory_order_release);
    }
}

/*
 * Own all host operations on one thread. Cross-thread cancellation is the
 * only host method invoked by the client side of the fixture.
 */
static void* smoke_host_main(void* user_data)
{
    smoke_host* fixture = (smoke_host*)user_data;

    if (!fixture)
        return NULL;
    fixture->status = server_host_start(fixture->host);
    if (fixture->status != LIBRDP_STATUS_OK)
        return NULL;
    atomic_store_explicit(&fixture->port,
                          server_host_local_port(fixture->host),
                          memory_order_release);
    for (;;)
    {
        librdp_status status = server_host_run_once(fixture->host, 20);

        if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status == LIBRDP_STATUS_CANCELLED)
        {
            fixture->status = LIBRDP_STATUS_OK;
            break;
        }
        fixture->status = status;
        break;
    }
    if (server_host_get_state(fixture->host) != SERVER_HOST_STOPPED)
        (void)server_host_stop(fixture->host);
    return NULL;
}

/*
 * Read one bounded X.224 request from a raw loopback peer. Polling keeps the
 * fixture cancellable when a client fails before reaching negotiation.
 */
static int smoke_security_peer_read_exact(smoke_security_peer* fixture,
                                          int fd,
                                          uint8_t* data,
                                          size_t length)
{
    uint64_t deadline_ns = smoke_now_ns() + 5000000000ULL;
    size_t offset = 0u;

    while (offset < length &&
           atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u)
    {
        struct pollfd pfd;
        ssize_t count = 0;
        int ready = 0;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        do
        {
            ready = poll(&pfd, 1u, 50);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0 || smoke_now_ns() >= deadline_ns)
            return 0;
        if (ready == 0)
            continue;
        count = recv(fd, data + offset, length - offset, 0);
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return offset == length;
}

static int smoke_security_peer_read_x224(smoke_security_peer* fixture,
                                         int fd)
{
    uint8_t header[4];
    uint8_t body[4092];
    size_t packet_length = 0u;

    if (!smoke_security_peer_read_exact(fixture,
                                        fd,
                                        header,
                                        sizeof(header)) ||
        header[0] != 3u)
        return 0;
    packet_length = ((size_t)header[2] << 8u) | (size_t)header[3];
    if (packet_length < sizeof(header) ||
        packet_length > sizeof(header) + sizeof(body))
        return 0;
    return smoke_security_peer_read_exact(fixture,
                                          fd,
                                          body,
                                          packet_length - sizeof(header));
}

/*
 * Present a deterministic X.224 security boundary without running later RDP
 * phases. Certificate modes perform a real server-side TLS handshake, while
 * the invalid mode deliberately returns non-TLS bytes after selecting TLS.
 */
static void* smoke_security_peer_main(void* user_data)
{
    static const uint8_t invalid_tls[] = {
        'N', 'O', 'T', '-', 'T', 'L', 'S', '\r', '\n'
    };
    smoke_security_peer* fixture = (smoke_security_peer*)user_data;
    struct sockaddr_in address;
    struct timeval timeout = {5, 0};
    socklen_t address_len = (socklen_t)sizeof(address);
    SSL_CTX* tls_context = NULL;
    SSL* tls = NULL;
    sigset_t blocked_signals;
    int listener = -1;
    int client = -1;
    int ok = 0;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_IO_ERROR;
    if (sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGPIPE) != 0 ||
        pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL) != 0)
        return NULL;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        goto cleanup;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener,
             (const struct sockaddr*)&address,
             (socklen_t)sizeof(address)) != 0 ||
        getsockname(listener,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(listener, 1) != 0)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          (unsigned int)ntohs(address.sin_port),
                          memory_order_release);
    while (atomic_load_explicit(&fixture->stop,
                                memory_order_acquire) == 0u)
    {
        struct pollfd pfd;
        int ready = 0;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = listener;
        pfd.events = POLLIN;
        do
        {
            ready = poll(&pfd, 1u, 50);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0)
            goto cleanup;
        if (ready == 0)
            continue;
        client = accept(listener, NULL, NULL);
        if (client < 0 && errno == EINTR)
            continue;
        if (client < 0)
            goto cleanup;
        break;
    }
    if (client < 0 ||
        setsockopt(client,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        setsockopt(client,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        !smoke_security_peer_read_x224(fixture, client))
        goto cleanup;
    {
        uint8_t response[] = {
            0x03u, 0x00u, 0x00u, 0x13u,
            0x0eu, 0xd0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x02u, 0x00u, 0x08u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u
        };

        if (fixture->mode != SMOKE_SECURITY_PEER_DOWNGRADE)
            response[15] = 0x01u;
        if (!test_server_send_all(client, response, sizeof(response)))
            goto cleanup;
    }
    if (fixture->mode == SMOKE_SECURITY_PEER_TLS_INVALID)
    {
        if (!test_server_send_all(client,
                                  invalid_tls,
                                  sizeof(invalid_tls)))
            goto cleanup;
    }
    else if (fixture->mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE)
    {
        int tls_result = 0;

        if (!fixture->certificate_path || !fixture->private_key_path)
            goto cleanup;
        tls_context = SSL_CTX_new(TLS_server_method());
        if (!tls_context ||
            SSL_CTX_use_certificate_chain_file(
                tls_context,
                fixture->certificate_path) != 1 ||
            SSL_CTX_use_PrivateKey_file(tls_context,
                                        fixture->private_key_path,
                                        SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(tls_context) != 1)
            goto cleanup;
        tls = SSL_new(tls_context);
        if (!tls || SSL_set_fd(tls, client) != 1)
            goto cleanup;
        tls_result = SSL_accept(tls);
        if (tls_result != 1)
            ERR_clear_error();
    }
    ok = 1;

cleanup:
    SSL_free(tls);
    SSL_CTX_free(tls_context);
    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);
    fixture->status = ok ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
    return NULL;
}

/*
 * Complete X.224 and TLS through the public server API, then stop dispatching
 * as soon as CredSSP authentication begins. The client can therefore exercise
 * its own bounded CredSSP read without a synthetic TLS implementation.
 */
static void* smoke_nla_stall_main(void* user_data)
{
    smoke_nla_stall* fixture = (smoke_nla_stall*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_NO_MEMORY;
    server = librdp_server_new(&fixture->config);
    if (!server)
        return NULL;
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
           !peer)
    {
        fixture->status = librdp_server_accept(server, 20, &peer);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
           peer)
    {
        if (librdp_server_peer_get_state(peer) ==
            LIBRDP_SERVER_PEER_NLA_AUTHENTICATING)
        {
            atomic_store_explicit(&fixture->authenticating,
                                  1u,
                                  memory_order_release);
            break;
        }
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u)
    {
        struct timespec delay = {0, 10000000L};

        (void)nanosleep(&delay, NULL);
    }
    fixture->status = LIBRDP_STATUS_OK;

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static librdp_status smoke_send_all(int fd,
                                    const uint8_t* data,
                                    size_t length)
{
    size_t offset = 0u;
#ifdef MSG_NOSIGNAL
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#endif

    if (fd < 0 || (!data && length > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (offset < length)
    {
        ssize_t written = send(fd,
                               data + offset,
                               length - offset,
                               send_flags);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd descriptor = {fd, POLLOUT, 0};
            int ready = poll(&descriptor, 1, 1000);

            if (ready > 0 &&
                (descriptor.revents & POLLOUT) != 0)
                continue;
            return ready == 0 ? LIBRDP_STATUS_TIMEOUT
                              : LIBRDP_STATUS_IO_ERROR;
        }
        return (written < 0 &&
                (errno == EPIPE || errno == ECONNRESET))
                   ? LIBRDP_STATUS_CLOSED
                   : LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_integrity_send_slowpath(
    librdp_server_peer* peer,
    smoke_integrity_tamper tamper)
{
    rdp_buffer slowpath;
    rdp_buffer secured;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !peer->standard_security_ready)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&slowpath);
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    status = rdp_slowpath_write_server_synchronize(
        &slowpath,
        peer->share_id,
        (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
        peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_encrypted_pdu(
            &secured,
            &peer->standard_security,
            0u,
            slowpath.data,
            slowpath.length);
    if (status == LIBRDP_STATUS_OK && secured.length <= 12u)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        if (tamper == SMOKE_INTEGRITY_SLOWPATH_MAC)
            secured.data[4] ^= 0x80u;
        else if (tamper == SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT)
            secured.data[secured.length - 1u] ^= 0x01u;
        else
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(
            &mcs,
            peer->user_id,
            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
            secured.data,
            secured.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    rdp_buffer_free(&slowpath);
    return status;
}

/*
 * Wrap one server-to-client fast-path update with the active Standard
 * Security context. Integrity fixtures may corrupt the completed signature;
 * functional fixtures send the exact authenticated packet.
 */
static librdp_status smoke_standard_send_fastpath(
    librdp_server_peer* peer,
    const uint8_t* updates,
    size_t updates_len,
    int corrupt_signature)
{
    rdp_buffer encrypted;
    rdp_buffer wire;
    uint8_t signature[8] = {0};
    size_t signature_offset = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !peer->standard_security_ready)
        return LIBRDP_STATUS_STATE;
    if (!updates && updates_len > 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&wire);
    status = rdp_security_mac_signature(
        &peer->standard_security,
        updates,
        updates_len,
        signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&encrypted,
                                   updates,
                                   updates_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_encrypt_payload(
            &peer->standard_security,
            encrypted.data,
            encrypted.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_header(
            &wire,
            RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
            RDP_FASTPATH_OUTPUT_ENCRYPTED,
            sizeof(signature) + encrypted.length);
    signature_offset = wire.length;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&wire,
                                   signature,
                                   sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&wire,
                                   encrypted.data,
                                   encrypted.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (corrupt_signature)
            wire.data[signature_offset] ^= 0x40u;
        status = smoke_send_all(peer->fd,
                                wire.data,
                                wire.length);
    }
    OPENSSL_cleanse(signature, sizeof(signature));
    rdp_buffer_free(&wire);
    rdp_buffer_free(&encrypted);
    return status;
}

static librdp_status smoke_integrity_send_fastpath(
    librdp_server_peer* peer)
{
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&update);
    status = rdp_fastpath_write_update(
        &update,
        RDP_FASTPATH_UPDATE_SYNCHRONIZE,
        RDP_FASTPATH_FRAGMENT_SINGLE,
        0u,
        0u,
        NULL,
        0u);
    if (status == LIBRDP_STATUS_OK)
        status = smoke_standard_send_fastpath(peer,
                                              update.data,
                                              update.length,
                                              1);
    rdp_buffer_free(&update);
    return status;
}

/*
 * Send one authenticated fast-path bitmap update containing both raw
 * bottom-up pixels and RLE pixels. The rectangles are disjoint so the final
 * whole-surface digest proves that each decoder reached the normalized
 * framebuffer.
 */
static librdp_status smoke_fastpath_bitmap_send(
    librdp_server_peer* peer)
{
    static const uint8_t raw_pixels[] = {
        0x90u, 0x80u, 0x70u, 0xffu,
        0x60u, 0x50u, 0x40u, 0xffu,
        0x30u, 0x20u, 0x10u, 0xffu,
        0xc0u, 0xb0u, 0xa0u, 0xffu,
    };
    static const uint8_t rle_pixels[] = {
        0xfdu, 0xfeu, 0xfeu, 0xfdu,
    };
    rdp_bitmap_rect rects[2];
    rdp_buffer bitmap;
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(rects, 0, sizeof(rects));
    rects[0].dest_left = 3u;
    rects[0].dest_top = 5u;
    rects[0].dest_right = 4u;
    rects[0].dest_bottom = 6u;
    rects[0].width = 2u;
    rects[0].height = 2u;
    rects[0].bits_per_pixel = 32u;
    rects[0].data = raw_pixels;
    rects[0].data_len = (uint32_t)sizeof(raw_pixels);
    rects[1].dest_left = 9u;
    rects[1].dest_top = 7u;
    rects[1].dest_right = 10u;
    rects[1].dest_bottom = 8u;
    rects[1].width = 2u;
    rects[1].height = 2u;
    rects[1].bits_per_pixel = 32u;
    rects[1].flags = RDP_BITMAP_FLAG_COMPRESSED |
                     RDP_BITMAP_FLAG_NO_COMPRESSION_HEADER;
    rects[1].data = rle_pixels;
    rects[1].data_len = (uint32_t)sizeof(rle_pixels);

    rdp_buffer_init(&bitmap);
    rdp_buffer_init(&update);
    status = rdp_bitmap_write_fastpath_update(
        &bitmap,
        rects,
        (uint16_t)(sizeof(rects) / sizeof(rects[0])));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_update(
            &update,
            RDP_FASTPATH_UPDATE_BITMAP,
            RDP_FASTPATH_FRAGMENT_SINGLE,
            0u,
            0u,
            bitmap.data,
            bitmap.length);
    if (status == LIBRDP_STATUS_OK)
        status = smoke_standard_send_fastpath(peer,
                                              update.data,
                                              update.length,
                                              0);
    rdp_buffer_free(&update);
    rdp_buffer_free(&bitmap);
    return status;
}

static int smoke_integrity_wait_for_client_close(int fd)
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < 100u; attempt++)
    {
        struct pollfd descriptor = {
            fd,
            (short)(POLLIN | POLLHUP),
            0
        };
        uint8_t discard[256];
        int ready = poll(&descriptor, 1, 50);

        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        if ((descriptor.revents &
             (POLLERR | POLLNVAL)) != 0)
            return 1;
        if ((descriptor.revents &
             (POLLIN | POLLHUP)) != 0)
        {
            ssize_t received = recv(fd,
                                    discard,
                                    sizeof(discard),
                                    0);

            if (received == 0)
                return 1;
            if (received < 0 &&
                (errno == ECONNRESET || errno == ENOTCONN))
                return 1;
            if (received < 0 &&
                errno != EINTR &&
                errno != EAGAIN &&
                errno != EWOULDBLOCK)
                return 0;
        }
    }
    return 0;
}

/*
 * Accept one loopback peer and drive the public server lifecycle until
 * activation. Callers retain ownership of the server and returned peer.
 */
static librdp_status smoke_server_accept_active(
    librdp_server* server,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!server || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u; attempt < 500u && !*peer; attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!*peer)
        return LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        if (librdp_server_peer_get_state(*peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(*peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return librdp_server_peer_get_state(*peer) ==
                   LIBRDP_SERVER_PEER_ACTIVE
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_TIMEOUT;
}

/*
 * Complete a real Standard Security activation, inject exactly one corrupted
 * encrypted packet, and retain the peer until the client closes its socket.
 * Each fixture instance owns one connection so cipher counters cannot leak
 * between tamper variants.
 */
static void* smoke_integrity_peer_main(void* user_data)
{
    smoke_integrity_peer* fixture =
        (smoke_integrity_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    if (fixture->tamper == SMOKE_INTEGRITY_FASTPATH_MAC)
        fixture->status = smoke_integrity_send_fastpath(peer);
    else
        fixture->status = smoke_integrity_send_slowpath(
            peer,
            fixture->tamper);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->packet_sent,
                          1u,
                          memory_order_release);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    atomic_store_explicit(&fixture->client_closed,
                          1u,
                          memory_order_release);
    fixture->status = LIBRDP_STATUS_OK;

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

/*
 * Host the deterministic fast-path bitmap fixture until the client has
 * verified the framebuffer and closed the transport.
 */
static void* smoke_fastpath_bitmap_peer_main(void* user_data)
{
    smoke_fastpath_bitmap_peer* fixture =
        (smoke_fastpath_bitmap_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = smoke_fastpath_bitmap_send(peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->packet_sent,
                          1u,
                          memory_order_release);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    atomic_store_explicit(&fixture->client_closed,
                          1u,
                          memory_order_release);
    fixture->status = LIBRDP_STATUS_OK;

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static void smoke_graphics_channel_event(
    librdp_server_peer* peer,
    const librdp_server_channel_event* event,
    void* user_data)
{
    smoke_graphics_peer* fixture =
        (smoke_graphics_peer*)user_data;
    rdp_graphics_header header;

    (void)peer;
    if (!fixture || !event ||
        event->type != LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA ||
        event->dynamic_channel_id != 17u ||
        !event->data)
        return;
    if (rdp_graphics_parse_header(event->data,
                                  event->data_len,
                                  &header) != LIBRDP_STATUS_OK ||
        header.pdu_length != event->data_len)
        return;
    if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE)
    {
        atomic_store_explicit(&fixture->caps_advertised,
                              1u,
                              memory_order_release);
    }
    else if (header.cmd_id ==
             RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE)
    {
        atomic_store_explicit(&fixture->frame_acknowledged,
                              1u,
                              memory_order_release);
    }
}

static librdp_status smoke_graphics_send_command(
    librdp_server_peer* peer,
    uint32_t channel_id,
    const rdp_buffer* command)
{
    rdp_buffer segmented;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !command)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&segmented);
    status = rdp_graphics_write_segmented_uncompressed(
        &segmented,
        command->data,
        command->length);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_dynamic_channel_data(
            peer,
            channel_id,
            segmented.data,
            segmented.length);
    }
    rdp_buffer_free(&segmented);
    return status;
}

/*
 * Exercise the complete public client/server RDPGFX path with deterministic
 * Planar and uncompressed updates. The callback confirms that the client
 * advertises capabilities and acknowledges the rendered frame.
 */
static void* smoke_graphics_peer_main(void* user_data)
{
    static const uint8_t planar_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA,
        0x10u, 0x20u,
        0x30u, 0x40u,
        0x50u, 0x60u
    };
    static const uint8_t uncompressed_pixels[] = {
        0x70u, 0x80u, 0x90u, 0x01u,
        0xa0u, 0xb0u, 0xc0u, 0x02u
    };
    const rdp_graphics_rect16 planar_rect = {
        0u, 0u, 2u, 1u
    };
    smoke_graphics_peer* fixture =
        (smoke_graphics_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    rdp_buffer command;
    uint32_t frame_id = 0u;
    uint32_t pending_frames = 0u;
    uint32_t last_ack_frame_id = 0u;
    unsigned int attempt = 0u;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    rdp_buffer_init(&command);
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = librdp_server_peer_set_channel_callback(
        peer,
        smoke_graphics_channel_event,
        fixture);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        fixture->status = librdp_server_peer_open_dynamic_channel(
            peer,
            17u,
            0u,
            RDP_GRAPHICS_PIPELINE_CHANNEL_NAME);
        if (fixture->status == LIBRDP_STATUS_OK)
            break;
        if (fixture->status != LIBRDP_STATUS_STATE)
            goto cleanup;
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
    }
    if (attempt == SMOKE_PUMP_LIMIT)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    for (attempt = 0u;
         attempt < SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(&fixture->caps_advertised,
                              memory_order_acquire) == 0u;
         attempt++)
    {
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
    }
    if (atomic_load_explicit(&fixture->caps_advertised,
                             memory_order_acquire) == 0u)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    fixture->status =
        librdp_server_peer_send_graphics_default_caps(peer, 17u);
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status = librdp_server_peer_send_graphics_reset(
            peer,
            17u,
            SMOKE_WIDTH + 1u,
            SMOKE_HEIGHT + 1u);
    }
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status =
            librdp_server_peer_send_graphics_create_surface(
                peer,
                17u,
                1u,
                4u,
                2u,
                RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    }
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status = rdp_graphics_write_map_surface_to_output(
            &command,
            1u,
            0u,
            0u);
    }
    if (fixture->status == LIBRDP_STATUS_OK)
        fixture->status = smoke_graphics_send_command(peer, 17u, &command);
    command.length = 0u;
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status =
            librdp_server_peer_send_graphics_start_frame(
                peer,
                17u,
                1000u,
                &frame_id);
    }
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status = rdp_graphics_write_wire_to_surface_1(
            &command,
            1u,
            RDP_GRAPHICS_CODECID_PLANAR,
            RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
            &planar_rect,
            planar_no_alpha,
            (uint32_t)sizeof(planar_no_alpha));
    }
    if (fixture->status == LIBRDP_STATUS_OK)
        fixture->status = smoke_graphics_send_command(peer, 17u, &command);
    command.length = 0u;
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status =
            librdp_server_peer_send_graphics_bitmap_bgra32(
                peer,
                17u,
                1u,
                2u,
                0u,
                2u,
                1u,
                8u,
                uncompressed_pixels);
    }
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        fixture->status = librdp_server_peer_send_graphics_end_frame(
            peer,
            17u,
            frame_id);
    }
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
        fixture->status =
            librdp_server_peer_get_graphics_frame_state(
                peer,
                &pending_frames,
                NULL,
                &last_ack_frame_id);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        if (pending_frames == 0u &&
            last_ack_frame_id == frame_id &&
            atomic_load_explicit(&fixture->frame_acknowledged,
                                 memory_order_acquire) != 0u)
            break;
    }
    if (attempt == SMOKE_PUMP_LIMIT)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    fixture->status =
        librdp_server_peer_send_graphics_delete_surface(
            peer,
            17u,
            1u);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->frame_sent,
                          1u,
                          memory_order_release);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    atomic_store_explicit(&fixture->client_closed,
                          1u,
                          memory_order_release);
    fixture->status = LIBRDP_STATUS_OK;

cleanup:
    rdp_buffer_free(&command);
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static const uint8_t smoke_redirection_routing_token[] = {
    'r', 'o', 'u', 't', 'e', '=', 's', 'm', 'o', 'k', 'e', '\r', '\n'
};

/*
 * Send the same typed redirection through the security envelope selected by
 * the peer. Standard Security uses SEC_REDIRECTION_PKT; TLS uses the enhanced
 * Share Control PDU because the transport already supplies confidentiality.
 */
static librdp_status smoke_redirection_send(librdp_server_peer* peer,
                                            int enhanced)
{
    rdp_server_redirection_packet redirection;
    rdp_buffer packet;
    rdp_buffer secured;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&redirection, 0, sizeof(redirection));
    redirection.session_id = 0x10203040u;
    redirection.redirection_flags =
        RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO;
    redirection.load_balance_info.data =
        smoke_redirection_routing_token;
    redirection.load_balance_info.length =
        (uint32_t)sizeof(smoke_redirection_routing_token);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    if (enhanced)
    {
        status = rdp_server_redirection_write_enhanced(
            &packet,
            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
            &redirection,
            1,
            1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &packet);
    }
    else
    {
        if (!peer->standard_security_ready)
            status = LIBRDP_STATUS_STATE;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_redirection_write_packet(
                &packet,
                &redirection,
                1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_encrypted_pdu(
                &secured,
                &peer->standard_security,
                RDP_SEC_REDIRECTION_PKT,
                packet.data,
                packet.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_mcs_write_send_data_indication(
                &mcs,
                peer->user_id,
                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                secured.data,
                secured.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_mcs_pdu(peer, &mcs);
    }
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status smoke_redirection_accept_active(
    smoke_redirection_peer* fixture,
    librdp_server* server,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!fixture || !server || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u;
         attempt < 500u &&
         atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
         !*peer;
         attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status != LIBRDP_STATUS_TIMEOUT)
            break;
    }
    if (!*peer)
        return status;
    for (attempt = 0u;
         attempt < 500u &&
         atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u;
         attempt++)
    {
        if (librdp_server_peer_get_state(*peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(*peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static int smoke_redirection_route_matches(
    const librdp_server_peer* peer)
{
    uint32_t required_cluster_flags =
        RDP_GCC_CLUSTER_REDIRECTION_SUPPORTED |
        RDP_GCC_CLUSTER_REDIRECTED_SESSION_ID_VALID;

    return peer &&
           peer->x224_routing_data.length ==
               sizeof(smoke_redirection_routing_token) &&
           memcmp(peer->x224_routing_data.data,
                  smoke_redirection_routing_token,
                  sizeof(smoke_redirection_routing_token)) == 0 &&
           (peer->client_cluster_flags & required_cluster_flags) ==
               required_cluster_flags &&
           peer->redirected_session_id == 0x10203040u;
}

static librdp_status smoke_redirection_wait_for_client_close(
    smoke_redirection_peer* fixture,
    librdp_server_peer* peer)
{
    unsigned int attempt = 0u;

    if (!fixture || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u;
         attempt < 500u &&
         atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u;
         attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);

        if (status == LIBRDP_STATUS_CLOSED ||
            status == LIBRDP_STATUS_IO_ERROR ||
            librdp_server_peer_get_state(peer) ==
                LIBRDP_SERVER_PEER_CLOSED)
            return LIBRDP_STATUS_OK;
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

/*
 * Accept successive loopback peers so the client reconnect happens while its
 * dispatch call is blocked in the connection state machine. The final peer is
 * held open until the client verifies success or rejects the bounded loop.
 */
static void* smoke_redirection_peer_main(void* user_data)
{
    smoke_redirection_peer* fixture =
        (smoke_redirection_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    unsigned int connection = 0u;
    unsigned int final_connection =
        RDP_SESSION_MAX_SERVER_REDIRECTS;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_NO_MEMORY;
    server = librdp_server_new(&fixture->config);
    if (!server)
        return NULL;
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    if (!fixture->loop)
        final_connection = 1u;
    for (connection = 0u; connection <= final_connection; connection++)
    {
        fixture->status = smoke_redirection_accept_active(
            fixture,
            server,
            &peer);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        atomic_fetch_add_explicit(&fixture->connections,
                                  1u,
                                  memory_order_release);
        if (connection > 0u)
        {
            if (!smoke_redirection_route_matches(peer))
            {
                fixture->status = LIBRDP_STATUS_PROTOCOL_ERROR;
                goto cleanup;
            }
            atomic_store_explicit(&fixture->route_verified,
                                  1u,
                                  memory_order_release);
        }
        if (!fixture->loop && connection == final_connection)
            break;
        fixture->status = smoke_redirection_send(
            peer,
            fixture->enhanced);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        atomic_fetch_add_explicit(&fixture->redirects,
                                  1u,
                                  memory_order_release);
        fixture->status = smoke_redirection_wait_for_client_close(
            fixture,
            peer);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
        peer = NULL;
    }
    fixture->status = LIBRDP_STATUS_OK;
    while (atomic_load_explicit(&fixture->stop,
                                memory_order_acquire) == 0u)
    {
        struct timespec delay = {0, 10000000L};

        (void)nanosleep(&delay, NULL);
    }

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static void smoke_client_event(librdp_session* session,
                               const librdp_event* event,
                               void* user_data)
{
    smoke_client_events* events = (smoke_client_events*)user_data;

    (void)session;
    if (!events || !event)
        return;
    if (event->type == LIBRDP_EVENT_STATE_CHANGED)
    {
        events->state_events++;
        events->active =
            event->data.state.new_state == LIBRDP_SESSION_ACTIVE;
        if (events->active)
            events->active_seen = 1;
    }
    else if (event->type == LIBRDP_EVENT_SURFACE_INVALIDATED)
        events->surface_events++;
    else if (event->type == LIBRDP_EVENT_ERROR)
        events->error_events++;
}

static librdp_status smoke_client_pump(client_runtime* runtime)
{
    struct pollfd* fds = NULL;
    size_t count = 0u;
    int timeout_ms = 20;
    int ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    status = client_runtime_prepare_poll(runtime,
                                         NULL,
                                         0u,
                                         20,
                                         &fds,
                                         &count,
                                         &timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    do
    {
        ready = poll(fds, (nfds_t)count, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0)
        return LIBRDP_STATUS_IO_ERROR;
    return client_runtime_dispatch_poll(runtime, 16u);
}

static int smoke_wait_for_port(const atomic_uint* source, uint16_t* port)
{
    unsigned int attempt = 0u;
    struct timespec delay = {0, 10000000L};

    if (!source || !port)
        return 0;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        unsigned int value = atomic_load_explicit(source,
                                                  memory_order_acquire);

        if (value > 0u && value <= UINT16_MAX)
        {
            *port = (uint16_t)value;
            return 1;
        }
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static int smoke_wait_for_counter(const atomic_uint* source,
                                  unsigned int expected)
{
    unsigned int attempt = 0u;
    struct timespec delay = {0, 1000000L};

    if (!source)
        return 0;
    for (attempt = 0u; attempt < 1000u; attempt++)
    {
        if (atomic_load_explicit(source,
                                 memory_order_acquire) >=
            expected)
            return 1;
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static int smoke_make_drive(char* directory,
                            size_t directory_size,
                            char* marker,
                            size_t marker_size)
{
    int fd = -1;
    int length = 0;
    static const char content[] = "temporary client drive\n";

    if (!directory || directory_size < 32u || !marker || marker_size < 48u)
        return 0;
    length = snprintf(directory,
                      directory_size,
                      "/tmp/librdp-drive-smoke-%ld-XXXXXX",
                      (long)getpid());
    if (length < 0 || (size_t)length >= directory_size || !mkdtemp(directory))
        return 0;
    length = snprintf(marker, marker_size, "%s/marker.txt", directory);
    if (length < 0 || (size_t)length >= marker_size)
    {
        (void)rmdir(directory);
        directory[0] = '\0';
        return 0;
    }
    fd = open(marker, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        (void)rmdir(directory);
        directory[0] = '\0';
        return 0;
    }
    if (write(fd, content, sizeof(content) - 1u) !=
        (ssize_t)(sizeof(content) - 1u))
    {
        (void)close(fd);
        (void)unlink(marker);
        (void)rmdir(directory);
        directory[0] = '\0';
        marker[0] = '\0';
        return 0;
    }
    if (close(fd) != 0)
    {
        (void)unlink(marker);
        (void)rmdir(directory);
        directory[0] = '\0';
        marker[0] = '\0';
        return 0;
    }
    return 1;
}

static int smoke_configure_security(server_host_config* host_config,
                                    librdp_settings* settings,
                                    librdp_security_mode security,
                                    const char* cert_path,
                                    const char* key_path,
                                    const smoke_nla_identity* identity)
{
    librdp_tls_policy tls_policy;

    host_config->server.security_mode = security;
    if (librdp_settings_set_security_mode(settings, security) !=
        LIBRDP_STATUS_OK)
        return 0;
    if (security == LIBRDP_SECURITY_STANDARD)
        return 1;
    host_config->server.tls_certificate_path = cert_path;
    host_config->server.tls_private_key_path = key_path;
    if (librdp_tls_policy_init(&tls_policy) != LIBRDP_STATUS_OK)
        return 0;
    tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
    tls_policy.use_system_store = 0;
    if (librdp_settings_set_tls_policy(settings, &tls_policy) !=
        LIBRDP_STATUS_OK)
        return 0;
    if (security != LIBRDP_SECURITY_NLA)
        return 1;
    if (!identity || !identity->username || !identity->password)
        return 0;
    host_config->server.nla_username = identity->username;
    host_config->server.nla_password = identity->password;
    host_config->server.nla_domain = identity->domain;
    if (librdp_settings_set_username(settings, identity->username) !=
            LIBRDP_STATUS_OK ||
        librdp_settings_set_password(settings, identity->password) !=
            LIBRDP_STATUS_OK)
        return 0;
    return !identity->domain ||
           librdp_settings_set_domain(settings, identity->domain) ==
               LIBRDP_STATUS_OK;
}

/*
 * Complete one security profile through the public client API and application
 * server host. Every provider must cross a real protocol boundary before the
 * fixture accepts the run.
 */
static int smoke_run_profile(librdp_security_mode security,
                             librdp_status expected_connect_status,
                             const smoke_nla_identity* identity,
                             const char* bind_address,
                             const char* target,
                             const smoke_gateway_profile* gateway_profile,
                             int exercise_output_control,
                             int cancel_phase)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char gateway_cert_path[128] = {0};
    char gateway_key_path[128] = {0};
    char drive_directory[128] = {0};
    char drive_marker[160] = {0};
    char gateway_url[128] = {0};
    char* saved_curl_ca_bundle = NULL;
    static const uint8_t clipboard_data[] = {'s', 'm', 'o', 'k', 'e'};
    smoke_platform platform;
    smoke_host host_fixture;
    smoke_client_events events;
    smoke_nla_provider nla_provider;
    smoke_trace_capture trace_capture;
    test_http_proxy proxy;
    test_http_proxy_config proxy_config;
    test_rdg_gateway rdg_gateway;
    test_rdg_gateway_config rdg_config;
    server_host_config host_config;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_gateway_config gateway_config;
    client_runtime runtime;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    librdp_key_event key;
    librdp_mouse_event mouse;
    librdp_status connect_status = LIBRDP_STATUS_OK;
    librdp_status terminal_status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    uint16_t default_port = 0u;
    unsigned int cycle = 0u;
    unsigned int capture_before_refresh = 0u;
    unsigned int refresh_requests_before = 0u;
    unsigned int output_suppressions_before = 0u;
    unsigned int output_resumptions_before = 0u;
    unsigned int surface_events_before_resume = 0u;
    uint8_t initial_pixel[4] = {0};
    int clipboard_sent = 0;
    int curl_environment_changed = 0;
    int input_sent = 0;
    int proxy_started = 0;
    int rdg_started = 0;
    int output_control_stage = 0;
    int thread_started = 0;
    int result = 1;
    const librdp_gateway_mode gateway_mode =
        gateway_profile
            ? gateway_profile->mode
            : LIBRDP_GATEWAY_DISABLED;
    const smoke_gateway_credentials gateway_credentials =
        gateway_profile
            ? gateway_profile->credentials
            : SMOKE_GATEWAY_CREDENTIALS_EXPLICIT;
    const librdp_status expected_gateway_status =
        gateway_profile
            ? gateway_profile->expected_status
            : LIBRDP_STATUS_OK;

    memset(&host_fixture, 0, sizeof(host_fixture));
    memset(&events, 0, sizeof(events));
    memset(&nla_provider, 0, sizeof(nla_provider));
    memset(&trace_capture, 0, sizeof(trace_capture));
    memset(&proxy, 0, sizeof(proxy));
    memset(&proxy_config, 0, sizeof(proxy_config));
    memset(&rdg_gateway, 0, sizeof(rdg_gateway));
    memset(&rdg_config, 0, sizeof(rdg_config));
    trace_capture.identity = identity;
    trace_capture.cancel_phase = cancel_phase;
    trace_capture.cancel_status = LIBRDP_STATUS_AGAIN;
    trace_capture.gateway_identity =
        gateway_mode != LIBRDP_GATEWAY_DISABLED
            ? (gateway_credentials ==
                       SMOKE_GATEWAY_CREDENTIALS_SESSION
                   ? identity
                   : &smoke_gateway_identity)
            : NULL;
    memset(&runtime, 0, sizeof(runtime));
    memset(&key, 0, sizeof(key));
    memset(&mouse, 0, sizeof(mouse));
    REQUIRE(bind_address != NULL);
    REQUIRE(target != NULL);
    atomic_init(&host_fixture.port, 0u);
    host_fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(smoke_make_drive(drive_directory,
                             sizeof(drive_directory),
                             drive_marker,
                             sizeof(drive_marker)));
    if (security != LIBRDP_SECURITY_STANDARD)
    {
        REQUIRE(test_server_make_tls_files(cert_path,
                                           sizeof(cert_path),
                                           key_path,
                                           sizeof(key_path)));
    }

    server_host_config_init(&host_config);
    host_config.server.bind_address = bind_address;
    host_config.server.width = SMOKE_CAPTURE_WIDTH;
    host_config.server.height = SMOKE_CAPTURE_HEIGHT;
    host_config.max_peers = 1u;
    host_config.dirty.frame_interval_ns = 0u;
    smoke_platform_init(&platform, &host_config);
    host_config.trace_callback = smoke_host_trace_callback;
    host_config.trace_user_data = &platform;

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    default_port = librdp_settings_port(settings);
    REQUIRE(librdp_settings_set_target(settings, target) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_add_drive(settings,
                                      "SMOKE",
                                      drive_directory) ==
            LIBRDP_STATUS_OK);
    REQUIRE(smoke_configure_security(&host_config,
                                     settings,
                                     security,
                                     cert_path,
                                     key_path,
                                     identity));
    REQUIRE(gateway_mode == LIBRDP_GATEWAY_DISABLED ||
            expected_connect_status == LIBRDP_STATUS_OK);
    if (expected_connect_status != LIBRDP_STATUS_OK)
    {
        REQUIRE(security == LIBRDP_SECURITY_NLA);
        nla_provider.status = expected_connect_status;
        host_config.credentials_provider = smoke_nla_credentials_provider;
        host_config.credentials_provider_user_data = &nla_provider;
    }
    host_fixture.host = server_host_new(&host_config);
    REQUIRE(host_fixture.host != NULL);
    REQUIRE(pthread_create(&host_fixture.thread,
                           NULL,
                           smoke_host_main,
                           &host_fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&host_fixture.port, &port));
    REQUIRE(port != default_port);
    REQUIRE(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);
    if (gateway_mode != LIBRDP_GATEWAY_DISABLED)
    {
        int written = 0;

        if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
        {
            const smoke_nla_identity* proxy_identity =
                gateway_profile->reject_credentials
                    ? &smoke_gateway_reject_identity
                    : gateway_credentials ==
                              SMOKE_GATEWAY_CREDENTIALS_SESSION
                    ? identity
                    : &smoke_gateway_identity;
            const smoke_nla_identity* forbidden_identity =
                gateway_credentials ==
                        SMOKE_GATEWAY_CREDENTIALS_SESSION
                    ? &smoke_gateway_identity
                    : identity;

            proxy_config.target_host = target;
            proxy_config.target_port = port;
            proxy_config.gateway_username =
                proxy_identity->username;
            proxy_config.gateway_password =
                proxy_identity->password;
            proxy_config.gateway_domain =
                proxy_identity->domain;
            proxy_config.forbidden_username =
                forbidden_identity->username;
            proxy_config.forbidden_password =
                forbidden_identity->password;
            proxy_config.forbidden_domain =
                forbidden_identity->domain;
            proxy_config.behavior =
                gateway_profile->proxy_behavior;
            REQUIRE(test_http_proxy_start(&proxy, &proxy_config));
            proxy_started = 1;
            written = snprintf(gateway_url,
                               sizeof(gateway_url),
                               "http://127.0.0.1:%u",
                               (unsigned int)proxy.port);
        }
        else
        {
            const char* current_curl_ca_bundle =
                getenv("CURL_CA_BUNDLE");

            REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
            REQUIRE(test_server_make_tls_files_for_host(
                gateway_cert_path,
                sizeof(gateway_cert_path),
                gateway_key_path,
                sizeof(gateway_key_path),
                "localhost"));
            rdg_config.target_host = target;
            rdg_config.target_port = port;
            rdg_config.certificate_path = gateway_cert_path;
            rdg_config.private_key_path = gateway_key_path;
            REQUIRE(test_rdg_gateway_start(&rdg_gateway,
                                           &rdg_config));
            rdg_started = 1;
            written = snprintf(
                gateway_url,
                sizeof(gateway_url),
                "https://localhost:%u/remoteDesktopGateway/",
                (unsigned int)rdg_gateway.port);
            if (current_curl_ca_bundle)
            {
                saved_curl_ca_bundle =
                    strdup(current_curl_ca_bundle);
                REQUIRE(saved_curl_ca_bundle != NULL);
            }
            if (gateway_profile->trust_certificate)
            {
                REQUIRE(setenv("CURL_CA_BUNDLE",
                               gateway_cert_path,
                               1) == 0);
            }
            else
                REQUIRE(unsetenv("CURL_CA_BUNDLE") == 0);
            curl_environment_changed = 1;
        }
        REQUIRE(written > 0 &&
                (size_t)written < sizeof(gateway_url));
        REQUIRE(librdp_gateway_config_init(&gateway_config) ==
                LIBRDP_STATUS_OK);
        gateway_config.mode = gateway_mode;
        gateway_config.url = gateway_url;
        if (gateway_credentials ==
            SMOKE_GATEWAY_CREDENTIALS_EXPLICIT)
        {
            gateway_config.username =
                smoke_gateway_identity.username;
            gateway_config.password =
                smoke_gateway_identity.password;
            gateway_config.domain =
                smoke_gateway_identity.domain;
        }
        gateway_config.use_session_credentials =
            gateway_credentials ==
            SMOKE_GATEWAY_CREDENTIALS_SESSION;
        gateway_config.timeout_ms =
            gateway_profile->timeout_ms;
        REQUIRE(librdp_settings_set_gateway_config(
                    settings,
                    &gateway_config) == LIBRDP_STATUS_OK);
    }
    trace_capture.target = target;
    trace_capture.port = port;

    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    trace_capture.lifecycle[trace_capture.lifecycle_count++] =
        librdp_session_get_lifecycle(session);
    librdp_session_set_event_callback(session, smoke_client_event, &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 96u;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "server-client-smoke";
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);
    client_runtime_init(&runtime, session);
    connect_status = client_runtime_connect(&runtime);
    if (gateway_mode != LIBRDP_GATEWAY_DISABLED &&
        connect_status !=
            (expected_gateway_status != LIBRDP_STATUS_OK
                 ? expected_gateway_status
                 : expected_connect_status))
    {
        const librdp_error* connect_error =
            librdp_session_last_error(session);
        librdp_error_info connect_error_info;
        const char* phase = "none";

        if (connect_error &&
            librdp_error_info_init(&connect_error_info) ==
                LIBRDP_STATUS_OK &&
            librdp_error_copy_info(connect_error,
                                   &connect_error_info) ==
                LIBRDP_STATUS_OK &&
            connect_error_info.phase)
            phase = connect_error_info.phase;
        fprintf(stderr,
                "gateway smoke mode=%u connect=%s phase=%s http_proxy=%s rdg=%s authenticated=%u forwarded=%u leak=%u\n",
                (unsigned int)gateway_mode,
                librdp_status_name(connect_status),
                phase,
                librdp_status_name(proxy.status),
                librdp_status_name(rdg_gateway.status),
                atomic_load_explicit(&proxy.authenticated,
                                     memory_order_acquire),
                atomic_load_explicit(&proxy.forwarded,
                                     memory_order_acquire),
                atomic_load_explicit(&proxy.credential_leak,
                                     memory_order_acquire));
    }
    if (expected_gateway_status != LIBRDP_STATUS_OK)
    {
        const librdp_error* error = NULL;

        REQUIRE(connect_status == expected_gateway_status);
        REQUIRE(nla_provider.calls == 0u);
        REQUIRE(trace_capture.records > 0u);
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.leaked == 0);
        if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
        {
            REQUIRE(trace_capture.gateway_connect_starts ==
                    1u);
            REQUIRE(trace_capture.gateway_connect_completions ==
                    0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.requests,
                        memory_order_acquire) > 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.authenticated,
                        memory_order_acquire) == 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.forwarded,
                        memory_order_acquire) == 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.credential_leak,
                        memory_order_acquire) == 0u);
        }
        else
        {
            REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
            REQUIRE(trace_capture.gateway_connect_starts ==
                    0u);
            REQUIRE(trace_capture.gateway_connect_completions ==
                    0u);
            REQUIRE(trace_capture.rdg_connect_starts == 1u);
            REQUIRE(trace_capture.rdg_connect_completions ==
                    0u);
        }
        error = librdp_session_last_error(session);
        REQUIRE(error != NULL);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(error, &error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == expected_gateway_status);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_TRANSPORT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase,
                       "transport.gateway.connect") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        if (proxy_started)
        {
            test_http_proxy_cancel(&proxy);
            REQUIRE(test_http_proxy_join_status(
                &proxy,
                gateway_profile->expected_fixture_status));
            proxy_started = 0;
            test_http_proxy_clear(&proxy);
        }
        if (rdg_started)
        {
            test_rdg_gateway_cancel(&rdg_gateway);
            REQUIRE(test_rdg_gateway_join_status(
                &rdg_gateway,
                gateway_profile->expected_fixture_status));
            rdg_started = 0;
            test_rdg_gateway_clear(&rdg_gateway);
        }
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    if (cancel_phase >= 0)
    {
        terminal_status = connect_status;
        if (terminal_status == LIBRDP_STATUS_OK)
        {
            for (cycle = 0u;
                 cycle < 4u &&
                 terminal_status == LIBRDP_STATUS_OK;
                 cycle++)
            {
                terminal_status = smoke_client_pump(&runtime);
            }
        }
        REQUIRE(terminal_status == LIBRDP_STATUS_CANCELLED);
        REQUIRE(trace_capture.cancel_requests == 1u);
        REQUIRE(trace_capture.cancel_status == LIBRDP_STATUS_OK);
        REQUIRE(trace_capture.client_connect_successes == 0u);
        REQUIRE(trace_capture.client_connect_failures == 0u);
        REQUIRE(trace_capture.client_connect_cancellations == 1u);
        REQUIRE(trace_capture.credssp_failures == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_CANCELLED);
        REQUIRE(librdp_session_get_lifecycle(session) ==
                LIBRDP_LIFECYCLE_DISCONNECTED);
        REQUIRE(!events.active);
        REQUIRE(events.error_events == 0u);
        REQUIRE(trace_capture.leaked == 0);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == LIBRDP_STATUS_CANCELLED);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_CLIENT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase, "client.cancel") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    if (expected_connect_status != LIBRDP_STATUS_OK)
    {
        const librdp_error* error = NULL;

        REQUIRE(connect_status == expected_connect_status);
        REQUIRE(nla_provider.calls == 1u);
        REQUIRE(trace_capture.records > 0u);
        REQUIRE(trace_capture.connect_starts == 1u);
        REQUIRE(trace_capture.connect_completions == 1u);
        REQUIRE(trace_capture.address_matched);
        REQUIRE(trace_capture.leaked == 0);
        error = librdp_session_last_error(session);
        REQUIRE(error != NULL);
        REQUIRE(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(error, &error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == expected_connect_status);
        REQUIRE(error_info.os_errno == 0);
        REQUIRE(error_info.component == LIBRDP_ERROR_COMPONENT_CREDSSP);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase, "credssp.nla.authenticate") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        (void)server_host_cancel(host_fixture.host);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    REQUIRE(connect_status == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        const librdp_surface* surface = NULL;
        int desktop_ready = 0;
        librdp_status status = smoke_client_pump(&runtime);

        if (status != LIBRDP_STATUS_OK)
        {
            librdp_error_info pump_error_info;
            const librdp_error* pump_error =
                librdp_session_last_error(session);
            const char* pump_phase = "none";
            librdp_status pump_error_status =
                LIBRDP_STATUS_OK;
            size_t trace_index = 0u;

            if (pump_error &&
                librdp_error_info_init(&pump_error_info) ==
                    LIBRDP_STATUS_OK &&
                librdp_error_copy_info(pump_error,
                                       &pump_error_info) ==
                    LIBRDP_STATUS_OK)
            {
                pump_error_status = pump_error_info.status;
                if (pump_error_info.phase)
                    pump_phase = pump_error_info.phase;
            }
            fprintf(stderr,
                    "client pump failed status=%s error=%s phase=%s host=%s rdg=%s out=%u in=%u channel=%u sent=%u received=%u\n",
                    librdp_status_name(status),
                    librdp_status_name(pump_error_status),
                    pump_phase,
                    librdp_status_name(host_fixture.status),
                    librdp_status_name(rdg_gateway.status),
                    atomic_load_explicit(&rdg_gateway.out_stream,
                                         memory_order_acquire),
                    atomic_load_explicit(&rdg_gateway.in_stream,
                                         memory_order_acquire),
                    atomic_load_explicit(&rdg_gateway.channel,
                                         memory_order_acquire),
                    atomic_load_explicit(
                        &rdg_gateway.downstream_sent,
                        memory_order_acquire),
                    atomic_load_explicit(
                        &rdg_gateway.downstream_received,
                        memory_order_acquire));
            for (trace_index = 0u;
                 trace_index < trace_capture.recent_count;
                 trace_index++)
            {
                size_t slot =
                    (trace_capture.recent_next +
                     SMOKE_TRACE_RECENT_CAPACITY -
                     trace_capture.recent_count +
                     trace_index) %
                    SMOKE_TRACE_RECENT_CAPACITY;

                fprintf(stderr,
                        "recent trace: %s\n",
                        trace_capture.recent[slot]);
            }
        }
        REQUIRE(status == LIBRDP_STATUS_OK);
        surface = librdp_session_get_surface(session);
        desktop_ready =
            events.active && surface &&
            librdp_surface_width(surface) == SMOKE_WIDTH &&
            librdp_surface_height(surface) == SMOKE_HEIGHT;
        if (desktop_ready && !clipboard_sent)
        {
            status = librdp_session_clipboard_set_data(
                session,
                LIBRDP_CLIPBOARD_FORMAT_TEXT,
                clipboard_data,
                sizeof(clipboard_data));
            if (status == LIBRDP_STATUS_OK)
                clipboard_sent = 1;
            else
                REQUIRE(status == LIBRDP_STATUS_STATE);
        }
        if (desktop_ready && !input_sent)
        {
            key.scancode = 0x1eu;
            key.state = LIBRDP_KEY_PRESSED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            key.state = LIBRDP_KEY_RELEASED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            mouse.x = 7u;
            mouse.y = 9u;
            mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
            mouse.state = LIBRDP_MOUSE_MOVED;
            REQUIRE(librdp_session_send_mouse(session, &mouse) ==
                    LIBRDP_STATUS_OK);
            input_sent = 1;
        }
        if (exercise_output_control &&
            output_control_stage == 0 &&
            desktop_ready && events.surface_events > 0u &&
            clipboard_sent && input_sent &&
            atomic_load_explicit(&platform.clipboard_offers,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            REQUIRE(pixels != NULL);
            memcpy(initial_pixel, pixels, sizeof(initial_pixel));
            refresh_requests_before =
                atomic_load_explicit(&platform.refresh_requests,
                                     memory_order_acquire);
            output_suppressions_before =
                atomic_load_explicit(
                    &platform.output_suppressions,
                    memory_order_acquire);
            output_resumptions_before =
                atomic_load_explicit(
                    &platform.output_resumptions,
                    memory_order_acquire);
            capture_before_refresh =
                atomic_load_explicit(&platform.capture_requests,
                                     memory_order_acquire);
            atomic_store_explicit(&platform.capture_variant,
                                  1u,
                                  memory_order_release);
            REQUIRE(librdp_session_set_output_suppressed(
                        session,
                        1) == LIBRDP_STATUS_OK);
            REQUIRE(librdp_session_refresh(session,
                                           1u,
                                           2u,
                                           7u,
                                           5u) ==
                    LIBRDP_STATUS_OK);
            output_control_stage = 1;
        }
        else if (exercise_output_control &&
                 output_control_stage == 1 &&
                 atomic_load_explicit(
                     &platform.output_suppressions,
                     memory_order_acquire) >
                     output_suppressions_before &&
                 atomic_load_explicit(
                     &platform.refresh_requests,
                     memory_order_acquire) >
                     refresh_requests_before &&
                 atomic_load_explicit(
                     &platform.capture_requests,
                     memory_order_acquire) >
                     capture_before_refresh)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            REQUIRE(pixels != NULL);
            REQUIRE(memcmp(pixels,
                           initial_pixel,
                           sizeof(initial_pixel)) == 0);
            surface_events_before_resume = events.surface_events;
            REQUIRE(librdp_session_set_output_suppressed(
                        session,
                        0) == LIBRDP_STATUS_OK);
            output_control_stage = 2;
        }
        else if (exercise_output_control &&
                 output_control_stage == 2 &&
                 atomic_load_explicit(
                     &platform.output_resumptions,
                     memory_order_acquire) >
                     output_resumptions_before)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            if (pixels &&
                smoke_frame_matches_sha256(
                    pixels,
                    (size_t)librdp_surface_stride(surface) *
                        librdp_surface_height(surface),
                    smoke_alternate_frame_sha256) &&
                events.surface_events >
                    surface_events_before_resume)
            {
                output_control_stage = 3;
            }
        }
        if (desktop_ready && events.surface_events > 0u &&
            clipboard_sent &&
            atomic_load_explicit(&platform.clipboard_offers,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.key_events,
                                 memory_order_acquire) >= 2u &&
            atomic_load_explicit(&platform.mouse_events,
                                 memory_order_acquire) >= 1u &&
            (!exercise_output_control ||
             output_control_stage == 3))
            break;
    }
    if (cycle >= SMOKE_PUMP_LIMIT && exercise_output_control)
    {
        fprintf(stderr,
                "output control timeout stage=%d capture=%u refresh=%u suppress=%u resume=%u surface=%u clipboard=%u drive=%u keys=%u mouse=%u\n",
                output_control_stage,
                atomic_load_explicit(&platform.capture_requests,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.refresh_requests,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.output_suppressions,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.output_resumptions,
                                     memory_order_acquire),
                events.surface_events,
                atomic_load_explicit(&platform.clipboard_offers,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.drive_presentations,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.key_events,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.mouse_events,
                                     memory_order_acquire));
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.surface_events > 0u);
    REQUIRE(events.error_events == 0u);
    REQUIRE(trace_capture.records > 0u);
    if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
    {
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.gateway_connect_starts == 1u);
        REQUIRE(trace_capture.gateway_connect_completions == 1u);
        REQUIRE(atomic_load_explicit(&proxy.authenticated,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&proxy.forwarded,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&proxy.credential_leak,
                                     memory_order_acquire) == 0u);
    }
    else if (gateway_mode == LIBRDP_GATEWAY_RDG_HTTP)
    {
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.gateway_connect_starts == 0u);
        REQUIRE(trace_capture.gateway_connect_completions == 0u);
        REQUIRE(trace_capture.rdg_connect_starts == 1u);
        REQUIRE(trace_capture.rdg_connect_completions == 1u);
        REQUIRE(trace_capture.rdg_handshakes == 1u);
        REQUIRE(trace_capture.rdg_tunnels == 1u);
        REQUIRE(trace_capture.rdg_authentications == 1u);
        REQUIRE(trace_capture.rdg_channels == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.out_stream,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.in_stream,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.handshake,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.tunnel,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.authorized,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.channel,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.downstream_sent,
                    memory_order_acquire) > 0u);
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.downstream_received,
                    memory_order_acquire) > 0u);
    }
    else
    {
        REQUIRE(trace_capture.connect_starts == 1u);
        REQUIRE(trace_capture.connect_completions == 1u);
        REQUIRE(trace_capture.address_matched);
    }
    REQUIRE(trace_capture.leaked == 0);
    REQUIRE(librdp_surface_width(librdp_session_get_surface(session)) ==
            SMOKE_WIDTH);
    REQUIRE(librdp_surface_height(librdp_session_get_surface(session)) ==
            SMOKE_HEIGHT);
    REQUIRE(librdp_surface_stride(librdp_session_get_surface(session)) ==
            SMOKE_WIDTH * 4u);
    REQUIRE(trace_capture.slowpath_bitmap_updates > 0u);
    REQUIRE(smoke_frame_matches_sha256(
        librdp_surface_pixels(librdp_session_get_surface(session)),
        (size_t)librdp_surface_stride(
            librdp_session_get_surface(session)) *
            librdp_surface_height(
                librdp_session_get_surface(session)),
        exercise_output_control
            ? smoke_alternate_frame_sha256
            : smoke_frame_sha256));
    REQUIRE(clipboard_sent);
    REQUIRE(input_sent);
    REQUIRE(atomic_load_explicit(&platform.capture_requests,
                                 memory_order_acquire) > 0u);
    REQUIRE(atomic_load_explicit(&platform.clipboard_offers,
                                 memory_order_acquire) > 0u);
    REQUIRE(atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u);
    REQUIRE(atomic_load_explicit(&platform.key_events,
                                 memory_order_acquire) >= 2u);
    REQUIRE(atomic_load_explicit(&platform.mouse_events,
                                 memory_order_acquire) >= 1u);
    if (exercise_output_control)
    {
        REQUIRE(output_control_stage == 3);
        REQUIRE(atomic_load_explicit(
                    &platform.refresh_requests,
                    memory_order_acquire) >
                refresh_requests_before);
        REQUIRE(atomic_load_explicit(
                    &platform.output_suppressions,
                    memory_order_acquire) >
                output_suppressions_before);
        REQUIRE(atomic_load_explicit(
                    &platform.output_resumptions,
                    memory_order_acquire) >
                output_resumptions_before);
        REQUIRE(trace_capture.output_suppressions >= 1u);
        REQUIRE(trace_capture.output_resumptions >= 2u);
        REQUIRE(trace_capture.refresh_requests >= 2u);
    }
    if (gateway_profile &&
        gateway_profile->drop_stream != TEST_RDG_STREAM_NONE)
    {
        REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
        REQUIRE(rdg_started);
        REQUIRE(test_rdg_gateway_drop_stream(
            &rdg_gateway,
            gateway_profile->drop_stream));
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.dropped,
                    memory_order_acquire) ==
                (unsigned int)gateway_profile->drop_stream);
        if (gateway_profile->drop_stream == TEST_RDG_STREAM_IN)
        {
            mouse.x++;
            terminal_status =
                librdp_session_send_mouse(session, &mouse);
            REQUIRE(terminal_status == LIBRDP_STATUS_OK ||
                    terminal_status == LIBRDP_STATUS_IO_ERROR ||
                    terminal_status == LIBRDP_STATUS_CLOSED);
        }
        terminal_status = LIBRDP_STATUS_OK;
        for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
        {
            terminal_status = smoke_client_pump(&runtime);
            if (terminal_status != LIBRDP_STATUS_OK ||
                librdp_session_get_state(session) !=
                    LIBRDP_SESSION_ACTIVE)
                break;
        }
        REQUIRE(cycle < SMOKE_PUMP_LIMIT);
        REQUIRE(terminal_status == LIBRDP_STATUS_IO_ERROR ||
                terminal_status == LIBRDP_STATUS_CLOSED);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_FAILED);
        REQUIRE(librdp_session_get_lifecycle(session) ==
                LIBRDP_LIFECYCLE_FAILED);
        REQUIRE(!events.active);
        REQUIRE(events.active_seen);
        REQUIRE(events.error_events == 1u);
        REQUIRE(trace_capture.leaked == 0);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == terminal_status);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_TRANSPORT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase,
                       "client.dispatch") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        REQUIRE(client_runtime_disconnect(&runtime) ==
                LIBRDP_STATUS_OK);
        test_rdg_gateway_cancel(&rdg_gateway);
        {
            int gateway_joined =
                test_rdg_gateway_join_status(
                    &rdg_gateway,
                    gateway_profile->expected_fixture_status);

            if (!gateway_joined)
                fprintf(stderr,
                        "RDG fixture join failed actual=%s expected=%s dropped=%u\n",
                        librdp_status_name(rdg_gateway.status),
                        librdp_status_name(
                            gateway_profile
                                ->expected_fixture_status),
                        atomic_load_explicit(
                            &rdg_gateway.dropped,
                            memory_order_acquire));
            REQUIRE(gateway_joined);
        }
        rdg_started = 0;
        test_rdg_gateway_clear(&rdg_gateway);
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        REQUIRE(atomic_load_explicit(&platform.releases,
                                     memory_order_acquire) > 0u);
        result = 0;
        goto cleanup;
    }
    REQUIRE(client_runtime_disconnect(&runtime) == LIBRDP_STATUS_OK);
    REQUIRE(smoke_validate_lifecycle(&trace_capture, security));
    if (proxy_started)
    {
        test_http_proxy_cancel(&proxy);
        REQUIRE(test_http_proxy_join(&proxy));
        proxy_started = 0;
        test_http_proxy_clear(&proxy);
    }
    if (rdg_started)
    {
        REQUIRE(test_rdg_gateway_join(&rdg_gateway));
        rdg_started = 0;
        REQUIRE(atomic_load_explicit(&rdg_gateway.closed,
                                     memory_order_acquire) ==
                1u);
        test_rdg_gateway_clear(&rdg_gateway);
    }
    REQUIRE(server_host_cancel(host_fixture.host) == LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(strcmp(platform.drive_name, "SMOKE") == 0);
    REQUIRE(atomic_load_explicit(&platform.releases,
                                 memory_order_acquire) > 0u);
    result = 0;

cleanup:
    if (proxy_started)
        test_http_proxy_clear(&proxy);
    if (rdg_started)
        test_rdg_gateway_clear(&rdg_gateway);
    if (thread_started)
    {
        (void)server_host_cancel(host_fixture.host);
        (void)pthread_join(host_fixture.thread, NULL);
    }
    client_runtime_clear(&runtime);
    librdp_session_free(session);
    librdp_settings_free(settings);
    server_host_free(host_fixture.host);
    if (drive_marker[0] != '\0')
        (void)unlink(drive_marker);
    if (drive_directory[0] != '\0')
        (void)rmdir(drive_directory);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    if (gateway_cert_path[0] != '\0')
        (void)unlink(gateway_cert_path);
    if (gateway_key_path[0] != '\0')
        (void)unlink(gateway_key_path);
    if (curl_environment_changed)
    {
        if (saved_curl_ca_bundle)
            (void)setenv("CURL_CA_BUNDLE",
                         saved_curl_ca_bundle,
                         1);
        else
            (void)unsetenv("CURL_CA_BUNDLE");
    }
    free(saved_curl_ca_bundle);
    return result;
}

/*
 * Verify that each pre-authentication security boundary preserves its exact
 * public status, component, phase, native error, and per-session trace ID.
 */
static int smoke_run_security_error(smoke_security_peer_mode peer_mode,
                                    librdp_status expected_status,
                                    int trust_test_certificate,
                                    int use_wrong_pin)
{
    static const char wrong_pin[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char* saved_cert_file = NULL;
    const char* current_cert_file = NULL;
    smoke_security_peer fixture;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_tls_policy tls_policy;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    uint16_t port = 0u;
    int cert_environment_changed = 0;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    fixture.mode = peer_mode;
    fixture.status = LIBRDP_STATUS_AGAIN;
    if (peer_mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE)
    {
        REQUIRE(test_server_make_tls_files(cert_path,
                                           sizeof(cert_path),
                                           key_path,
                                           sizeof(key_path)));
        fixture.certificate_path = cert_path;
        fixture.private_key_path = key_path;
    }
    if (trust_test_certificate)
    {
        current_cert_file = getenv("SSL_CERT_FILE");
        if (current_cert_file)
        {
            saved_cert_file = strdup(current_cert_file);
            REQUIRE(saved_cert_file != NULL);
        }
        REQUIRE(setenv("SSL_CERT_FILE", cert_path, 1) == 0);
        cert_environment_changed = 1;
    }
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_security_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                    ? LIBRDP_SECURITY_AUTO
                    : LIBRDP_SECURITY_TLS) ==
            LIBRDP_STATUS_OK);
    if (peer_mode != SMOKE_SECURITY_PEER_DOWNGRADE)
    {
        REQUIRE(librdp_tls_policy_init(&tls_policy) ==
                LIBRDP_STATUS_OK);
        if (use_wrong_pin)
        {
            tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
            tls_policy.use_system_store = 0;
            tls_policy.pinned_sha256 = wrong_pin;
        }
        else
        {
            tls_policy.mode =
                peer_mode == SMOKE_SECURITY_PEER_TLS_INVALID
                    ? LIBRDP_TLS_POLICY_INSECURE_LAB
                    : LIBRDP_TLS_POLICY_STRICT;
            tls_policy.use_system_store =
                peer_mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE ? 1 : 0;
        }
        REQUIRE(librdp_settings_set_tls_policy(settings, &tls_policy) ==
                LIBRDP_STATUS_OK);
    }
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "security-boundary";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);

    REQUIRE(librdp_session_connect(session) == expected_status);
    REQUIRE(librdp_session_get_state(session) ==
            LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_session_get_lifecycle(session) ==
            LIBRDP_LIFECYCLE_FAILED);
    REQUIRE(trace_capture.records > 0u);
    REQUIRE(trace_capture.connect_starts == 1u);
    REQUIRE(trace_capture.connect_completions == 1u);
    REQUIRE(trace_capture.address_matched);
    REQUIRE(trace_capture.leaked == 0);
    if (peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE)
    {
        REQUIRE(trace_capture.security_downgrades == 1u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(trace_capture.tls_verify_failures == 0u);
    }
    else if (use_wrong_pin)
    {
        REQUIRE(trace_capture.security_downgrades == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(trace_capture.tls_verify_failures == 1u);
    }
    else
    {
        REQUIRE(trace_capture.security_downgrades == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 1u);
        REQUIRE(trace_capture.tls_verify_failures == 0u);
    }
    REQUIRE(librdp_error_info_init(&error_info) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(librdp_session_last_error(session),
                                   &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == expected_status);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component ==
            (peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                 ? LIBRDP_ERROR_COMPONENT_PROTOCOL
                 : LIBRDP_ERROR_COMPONENT_TLS));
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                       ? "x224.negotiation.policy"
                       : "transport.tls.handshake") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id,
                   "security-boundary") == 0);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
    {
        (void)pthread_join(fixture.thread, NULL);
        if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
            result = 1;
    }
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_environment_changed)
    {
        if (saved_cert_file)
            (void)setenv("SSL_CERT_FILE", saved_cert_file, 1);
        else
            (void)unsetenv("SSL_CERT_FILE");
    }
    free(saved_cert_file);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

/*
 * Exercise server-directed reconnects over both wire envelopes and prove that
 * routing data plus the redirected session ID survive into the next X.224/GCC
 * handshake. Loop mode accepts the protocol maximum and rejects the next hop.
 */
static int smoke_run_redirection(int enhanced, int loop)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    smoke_redirection_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_tls_policy tls_policy;
    librdp_metrics metrics;
    librdp_error_info error_info;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.connections, 0u);
    atomic_init(&fixture.redirects, 0u);
    atomic_init(&fixture.route_verified, 0u);
    fixture.enhanced = enhanced;
    fixture.loop = loop;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode =
        enhanced ? LIBRDP_SECURITY_TLS : LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    fixture.config.max_peers =
        RDP_SESSION_MAX_SERVER_REDIRECTS + 2u;
    if (enhanced)
    {
        REQUIRE(test_server_make_tls_files_for_host(
            cert_path,
            sizeof(cert_path),
            key_path,
            sizeof(key_path),
            "127.0.0.1"));
        fixture.config.tls_certificate_path = cert_path;
        fixture.config.tls_private_key_path = key_path;
    }
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_redirection_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                enhanced ? LIBRDP_SECURITY_TLS :
                           LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    if (enhanced)
    {
        REQUIRE(librdp_tls_policy_init(&tls_policy) ==
                LIBRDP_STATUS_OK);
        tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
        tls_policy.use_system_store = 0;
        REQUIRE(librdp_settings_set_tls_policy(settings,
                                               &tls_policy) ==
                LIBRDP_STATUS_OK);
    }
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id =
        loop ? "redirection-loop" :
               enhanced ? "redirection-tls" :
                          "redirection-standard";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);

    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        if (loop && status == LIBRDP_STATUS_LIMIT_EXCEEDED)
            break;
        REQUIRE(status == LIBRDP_STATUS_OK ||
                status == LIBRDP_STATUS_TIMEOUT);
        if (!loop &&
            atomic_load_explicit(&fixture.route_verified,
                                 memory_order_acquire) == 1u &&
            librdp_session_get_state(session) ==
                LIBRDP_SESSION_ACTIVE)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_get_metrics(session, &metrics) ==
            LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.route_verified,
                                 memory_order_acquire) == 1u);
    REQUIRE(trace_capture.leaked == 0);
    if (loop)
    {
        REQUIRE(status == LIBRDP_STATUS_LIMIT_EXCEEDED);
        REQUIRE(smoke_wait_for_counter(
            &fixture.redirects,
            RDP_SESSION_MAX_SERVER_REDIRECTS + 1u));
        REQUIRE(atomic_load_explicit(&fixture.connections,
                                     memory_order_acquire) ==
                RDP_SESSION_MAX_SERVER_REDIRECTS + 1u);
        REQUIRE(atomic_load_explicit(&fixture.redirects,
                                     memory_order_acquire) ==
                RDP_SESSION_MAX_SERVER_REDIRECTS + 1u);
        REQUIRE(metrics.reconnects ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(metrics.limits_rejected == 1u);
        REQUIRE(trace_capture.redirections ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(trace_capture.redirection_reconnects ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(trace_capture.redirection_loops == 1u);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == LIBRDP_STATUS_LIMIT_EXCEEDED);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_PROTOCOL);
        REQUIRE(error_info.phase != NULL &&
                strcmp(error_info.phase,
                       "client.redirection.loop") == 0);
    }
    else
    {
        REQUIRE(status == LIBRDP_STATUS_OK ||
                status == LIBRDP_STATUS_TIMEOUT);
        REQUIRE(atomic_load_explicit(&fixture.connections,
                                     memory_order_acquire) == 2u);
        REQUIRE(atomic_load_explicit(&fixture.redirects,
                                     memory_order_acquire) == 1u);
        REQUIRE(metrics.reconnects == 1u);
        REQUIRE(metrics.limits_rejected == 0u);
        REQUIRE(trace_capture.redirections == 1u);
        REQUIRE(trace_capture.redirection_reconnects == 1u);
        REQUIRE(trace_capture.redirection_loops == 0u);
        REQUIRE(trace_capture.connect_starts == 2u);
        REQUIRE(trace_capture.connect_completions == 2u);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_ACTIVE);
        REQUIRE(events.active);
        REQUIRE(events.error_events == 0u);
    }
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
    {
        (void)pthread_join(fixture.thread, NULL);
        if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
            result = 1;
    }
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

typedef struct smoke_resource_snapshot
{
    size_t descriptor_count;
    size_t thread_count;
    uint64_t resident_bytes;
    int thread_count_available;
    int resident_bytes_available;
} smoke_resource_snapshot;

/*
 * Prefer procfs for constant-time descriptor accounting, then fall back to a
 * bounded POSIX descriptor scan on systems without procfs.
 */
static int smoke_count_descriptors(size_t* count)
{
    DIR* directory = NULL;
    struct dirent* entry = NULL;
    size_t total = 0u;
    long descriptor_limit = 0;
    int descriptor = 0;

    if (!count)
        return 0;
    directory = opendir("/proc/self/fd");
    if (directory)
    {
        while ((entry = readdir(directory)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0)
                total++;
        }
        (void)closedir(directory);
        if (total == 0u)
            return 0;
        *count = total - 1u;
        return 1;
    }

    descriptor_limit = sysconf(_SC_OPEN_MAX);
    if (descriptor_limit <= 0)
        return 0;
    if (descriptor_limit > SMOKE_DESCRIPTOR_SCAN_LIMIT)
        descriptor_limit = SMOKE_DESCRIPTOR_SCAN_LIMIT;
    for (descriptor = 0;
         (long)descriptor < descriptor_limit;
         descriptor++)
    {
        errno = 0;
        if (fcntl(descriptor, F_GETFD) >= 0 || errno != EBADF)
            total++;
    }
    *count = total;
    return 1;
}

/*
 * Procfs provides current thread and resident-memory observations on Linux.
 * Other supported systems still receive portable descriptor checks and run
 * this same loop under leak sanitizers in their configured test jobs.
 */
static void smoke_read_optional_process_resources(
    smoke_resource_snapshot* snapshot)
{
    DIR* directory = NULL;
    struct dirent* entry = NULL;
#if !SMOKE_ADDRESS_SANITIZER_ACTIVE
    FILE* statm = NULL;
    unsigned long long virtual_pages = 0u;
    unsigned long long resident_pages = 0u;
    long page_size = 0;
#endif

    directory = opendir("/proc/self/task");
    if (directory)
    {
        while ((entry = readdir(directory)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0)
                snapshot->thread_count++;
        }
        (void)closedir(directory);
        snapshot->thread_count_available = 1;
    }

#if !SMOKE_ADDRESS_SANITIZER_ACTIVE
    statm = fopen("/proc/self/statm", "r");
    if (!statm)
        return;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0 &&
        fscanf(statm,
               "%llu %llu",
               &virtual_pages,
               &resident_pages) == 2 &&
        resident_pages <= UINT64_MAX / (uint64_t)page_size)
    {
        snapshot->resident_bytes =
            (uint64_t)resident_pages * (uint64_t)page_size;
        snapshot->resident_bytes_available = 1;
    }
    (void)virtual_pages;
    (void)fclose(statm);
#endif
}

static int smoke_take_resource_snapshot(smoke_resource_snapshot* snapshot)
{
    if (!snapshot)
        return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    if (!smoke_count_descriptors(&snapshot->descriptor_count))
        return 0;
    smoke_read_optional_process_resources(snapshot);
    return 1;
}

/*
 * Alternate all client security paths, tear every fixture down completely,
 * and periodically include a protocol-driven reconnect. Exact descriptor and
 * thread baselines catch leaked transports or workers; bounded resident growth
 * complements the allocator-level sanitizer run.
 */
static int smoke_run_lifecycle_stress(void)
{
    smoke_resource_snapshot baseline;
    smoke_resource_snapshot current;
    uint64_t resident_floor = 0u;
    unsigned int cycle = 0u;

    CHECK(smoke_take_resource_snapshot(&baseline));
    for (cycle = 0u;
         cycle < SMOKE_LIFECYCLE_STRESS_CYCLES;
         cycle++)
    {
        librdp_security_mode security = LIBRDP_SECURITY_STANDARD;
        const smoke_nla_identity* identity = NULL;

        if (cycle % 3u == 1u)
            security = LIBRDP_SECURITY_TLS;
        else if (cycle % 3u == 2u)
        {
            security = LIBRDP_SECURITY_NLA;
            identity = &smoke_nla_default_identity;
        }
        CHECK(smoke_run_profile(security,
                                LIBRDP_STATUS_OK,
                                identity,
                                "127.0.0.1",
                                "127.0.0.1",
                                NULL,
                                0,
                                -1) == 0);
        if (cycle % 6u == 5u)
            CHECK(smoke_run_redirection((cycle / 6u) % 2u, 0) == 0);

        CHECK(smoke_take_resource_snapshot(&current));
        if (current.descriptor_count != baseline.descriptor_count)
        {
            fprintf(stderr,
                    "lifecycle stress descriptor growth cycle=%u baseline=%llu current=%llu\n",
                    cycle,
                    (unsigned long long)baseline.descriptor_count,
                    (unsigned long long)current.descriptor_count);
            return 1;
        }
        if (baseline.thread_count_available &&
            current.thread_count_available &&
            current.thread_count != baseline.thread_count)
        {
            fprintf(stderr,
                    "lifecycle stress thread growth cycle=%u baseline=%llu current=%llu\n",
                    cycle,
                    (unsigned long long)baseline.thread_count,
                    (unsigned long long)current.thread_count);
            return 1;
        }
        if (current.resident_bytes_available &&
            cycle == SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES)
            resident_floor = current.resident_bytes;
        else if (current.resident_bytes_available &&
                 cycle > SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES)
        {
            if (current.resident_bytes < resident_floor)
                resident_floor = current.resident_bytes;
            if (current.resident_bytes >
                resident_floor +
                    SMOKE_LIFECYCLE_STRESS_RSS_ALLOWANCE)
            {
                fprintf(stderr,
                        "lifecycle stress resident growth cycle=%u floor=%llu current=%llu\n",
                        cycle,
                        (unsigned long long)resident_floor,
                        (unsigned long long)current.resident_bytes);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Hold a real NLA server immediately after TLS so the client must expire its
 * CredSSP challenge read. The fixture also verifies phase attribution and that
 * identity material never reaches the session trace callback.
 */
static int smoke_run_credssp_timeout(void)
{
    const smoke_nla_identity* identity = &smoke_nla_default_identity;
    char cert_path[128] = {0};
    char key_path[128] = {0};
    smoke_nla_stall fixture;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_tls_policy tls_policy;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    uint16_t port = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&trace_capture, 0, sizeof(trace_capture));
    trace_capture.identity = identity;
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.authenticating, 0u);
    REQUIRE(test_server_make_tls_files(cert_path,
                                       sizeof(cert_path),
                                       key_path,
                                       sizeof(key_path)));
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_NLA;
    fixture.config.tls_certificate_path = cert_path;
    fixture.config.tls_private_key_path = key_path;
    fixture.config.nla_domain = identity->domain;
    fixture.config.nla_username = identity->username;
    fixture.config.nla_password = identity->password;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_nla_stall_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(settings,
                                              LIBRDP_SECURITY_NLA) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_username(settings, identity->username) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_password(settings, identity->password) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_domain(settings, identity->domain) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
    tls_policy.use_system_store = 0;
    REQUIRE(librdp_settings_set_tls_policy(settings, &tls_policy) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    REQUIRE(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "credssp-timeout";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);

    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_TIMEOUT);
    REQUIRE(atomic_load_explicit(&fixture.authenticating,
                                 memory_order_acquire) == 1u);
    REQUIRE(trace_capture.records > 0u);
    REQUIRE(trace_capture.connect_starts == 1u);
    REQUIRE(trace_capture.connect_completions == 1u);
    REQUIRE(trace_capture.address_matched);
    REQUIRE(trace_capture.credssp_failures == 1u);
    REQUIRE(trace_capture.leaked == 0);
    REQUIRE(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(librdp_session_last_error(session),
                                   &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == LIBRDP_STATUS_TIMEOUT);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component == LIBRDP_ERROR_COMPONENT_CREDSSP);
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   "credssp.nla.challenge.read") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id, "credssp-timeout") == 0);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
        result = 1;
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

/*
 * Drive one corrupted Standard Security packet through the public client
 * lifecycle. The peer must observe EOF, no decoded update may be delivered,
 * and the trace must identify the constant-time MAC rejection boundary.
 */
static int smoke_run_integrity_case(smoke_integrity_tamper tamper)
{
    smoke_integrity_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    unsigned int surface_events_before_failure = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.tamper = tamper;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_integrity_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "standard-integrity";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        if (status == LIBRDP_STATUS_PROTOCOL_ERROR)
            break;
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen)
            surface_events_before_failure = events.surface_events;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    REQUIRE(events.active_seen);
    REQUIRE(events.error_events == 1u);
    REQUIRE(events.surface_events == surface_events_before_failure);
    REQUIRE(librdp_session_get_state(session) ==
            LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_session_get_lifecycle(session) ==
            LIBRDP_LIFECYCLE_FAILED);
    REQUIRE(trace_capture.integrity_failures == 1u);
    if (tamper == SMOKE_INTEGRITY_FASTPATH_MAC)
    {
        REQUIRE(trace_capture.fastpath_integrity_failures == 1u);
        REQUIRE(trace_capture.slowpath_integrity_failures == 0u);
    }
    else
    {
        REQUIRE(trace_capture.slowpath_integrity_failures == 1u);
        REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    }
    REQUIRE(librdp_error_info_init(&error_info) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(
                librdp_session_last_error(session),
                &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == LIBRDP_STATUS_PROTOCOL_ERROR);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component ==
            LIBRDP_ERROR_COMPONENT_PROTOCOL);
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   tamper == SMOKE_INTEGRITY_FASTPATH_MAC
                       ? "rdp.fastpath.security"
                       : "rdp.slowpath.security") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id,
                   "standard-integrity") == 0);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_run_standard_integrity(void)
{
    static const smoke_integrity_tamper cases[] = {
        SMOKE_INTEGRITY_SLOWPATH_MAC,
        SMOKE_INTEGRITY_FASTPATH_MAC,
        SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT
    };
    size_t index = 0u;

    for (index = 0u;
         index < sizeof(cases) / sizeof(cases[0]);
         index++)
    {
        if (smoke_run_integrity_case(cases[index]) != 0)
            return 1;
    }
    return 0;
}

/*
 * Verify authenticated fast-path delivery against a whole-frame golden hash.
 * The fixture exercises raw and RLE bitmap rectangles through the public
 * client runtime rather than direct parser calls.
 */
static int smoke_run_fastpath_bitmap(void)
{
    smoke_fastpath_bitmap_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_fastpath_bitmap_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "fastpath-bitmap";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen &&
            events.surface_events >= 2u &&
            trace_capture.fastpath_bitmap_updates == 1u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.error_events == 0u);
    REQUIRE(events.surface_events >= 2u);
    REQUIRE(trace_capture.fastpath_bitmap_updates == 1u);
    REQUIRE(trace_capture.slowpath_bitmap_updates == 0u);
    REQUIRE(trace_capture.integrity_failures == 0u);
    REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    REQUIRE(smoke_frame_matches_sha256(
        librdp_surface_pixels(librdp_session_get_surface(session)),
        (size_t)librdp_surface_stride(
            librdp_session_get_surface(session)) *
            librdp_surface_height(
                librdp_session_get_surface(session)),
        smoke_fastpath_bitmap_sha256));
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_run_graphics_planar(void)
{
    static const uint8_t expected_row[] = {
        0x50u, 0x30u, 0x10u, 0xffu,
        0x60u, 0x40u, 0x20u, 0xffu,
        0x70u, 0x80u, 0x90u, 0xffu,
        0xa0u, 0xb0u, 0xc0u, 0xffu
    };
    smoke_graphics_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    const librdp_surface* surface = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t* expected = NULL;
    const uint8_t* pixels = NULL;
    size_t surface_bytes = 0u;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.caps_advertised, 0u);
    atomic_init(&fixture.frame_acknowledged, 0u);
    atomic_init(&fixture.frame_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_graphics_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "graphics-planar";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen &&
            trace_capture.graphics_caps_confirms != 0u &&
            trace_capture.graphics_surface_creates != 0u &&
            trace_capture.graphics_surface_maps != 0u &&
            trace_capture.graphics_planar_updates != 0u &&
            trace_capture.graphics_uncompressed_updates != 0u &&
            trace_capture.graphics_frame_starts != 0u &&
            trace_capture.graphics_frame_ends != 0u &&
            trace_capture.graphics_frame_acks != 0u &&
            trace_capture.graphics_surface_deletes != 0u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.error_events == 0u);
    REQUIRE(events.surface_events >= 2u);
    surface = librdp_session_get_surface(session);
    REQUIRE(surface != NULL);
    REQUIRE(librdp_surface_width(surface) == SMOKE_WIDTH + 1u);
    REQUIRE(librdp_surface_height(surface) == SMOKE_HEIGHT + 1u);
    REQUIRE(librdp_surface_stride(surface) ==
            (size_t)(SMOKE_WIDTH + 1u) * 4u);
    surface_bytes = librdp_surface_stride(surface) *
                    librdp_surface_height(surface);
    expected = (uint8_t*)calloc(1u, surface_bytes);
    REQUIRE(expected != NULL);
    memcpy(expected, expected_row, sizeof(expected_row));
    pixels = librdp_surface_pixels(surface);
    REQUIRE(pixels != NULL);
    REQUIRE(CRYPTO_memcmp(pixels, expected, surface_bytes) == 0);
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.caps_advertised,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.frame_acknowledged,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.frame_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    free(expected);
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_parse_security(const char* value,
                                librdp_security_mode* security,
                                librdp_status* expected_status,
                                const smoke_nla_identity** identity,
                                const char** bind_address,
                                const char** target)
{
    if (!value || !security || !expected_status || !identity ||
        !bind_address || !target)
        return 0;
    *expected_status = LIBRDP_STATUS_OK;
    *identity = &smoke_nla_default_identity;
    *bind_address = "127.0.0.1";
    *target = "127.0.0.1";
    if (strcmp(value, "standard") == 0)
        *security = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(value, "standard-dns") == 0)
    {
        *security = LIBRDP_SECURITY_STANDARD;
        *target = "localhost";
    }
    else if (strcmp(value, "standard-ipv6") == 0)
    {
        *security = LIBRDP_SECURITY_STANDARD;
        *bind_address = "::1";
        *target = "::1";
    }
    else if (strcmp(value, "tls") == 0)
        *security = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "nla") == 0)
        *security = LIBRDP_SECURITY_NLA;
    else if (strcmp(value, "nla-invalid") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_AUTHENTICATION_FAILED;
    }
    else if (strcmp(value, "nla-expired") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_CREDENTIALS_EXPIRED;
    }
    else if (strcmp(value, "nla-locked") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_ACCOUNT_LOCKED;
    }
    else if (strcmp(value, "nla-no-domain") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_no_domain_identity;
    }
    else if (strcmp(value, "nla-empty-domain") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_empty_domain_identity;
    }
    else if (strcmp(value, "nla-upn") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_upn_identity;
    }
    else if (strcmp(value, "nla-utf8") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_utf8_identity;
    }
    else
        return 0;
    return 1;
}

static const smoke_gateway_profile* smoke_gateway_profile_by_name(
    const char* name)
{
    if (!name)
        return NULL;
    if (strcmp(name, "gateway-http-connect") == 0)
        return &smoke_gateway_http_explicit;
    if (strcmp(name, "gateway-session-credentials") == 0)
        return &smoke_gateway_http_session;
    if (strcmp(name, "gateway-no-session-credentials") == 0)
        return &smoke_gateway_http_no_credentials;
    if (strcmp(name, "gateway-auth-failure") == 0)
        return &smoke_gateway_http_auth_failure;
    if (strcmp(name, "gateway-timeout") == 0)
        return &smoke_gateway_http_timeout;
    if (strcmp(name, "gateway-malformed") == 0)
        return &smoke_gateway_http_malformed;
    if (strcmp(name, "gateway-refused") == 0)
        return &smoke_gateway_http_refused;
    if (strcmp(name, "gateway-rdg") == 0)
        return &smoke_gateway_rdg;
    if (strcmp(name, "gateway-rdg-drop-out") == 0)
        return &smoke_gateway_rdg_drop_out;
    if (strcmp(name, "gateway-rdg-drop-in") == 0)
        return &smoke_gateway_rdg_drop_in;
    if (strcmp(name, "gateway-rdg-untrusted") == 0)
        return &smoke_gateway_rdg_untrusted;
    return NULL;
}

int main(int argc, char** argv)
{
    librdp_security_mode security = LIBRDP_SECURITY_AUTO;
    librdp_status expected_status = LIBRDP_STATUS_OK;
    const smoke_nla_identity* identity = NULL;
    const smoke_gateway_profile* gateway_profile = NULL;
    const char* bind_address = NULL;
    const char* target = NULL;

    if (argc == 2 && strcmp(argv[1], "timeout-credssp") == 0)
        return smoke_run_credssp_timeout();
    if (argc == 2 && strcmp(argv[1], "standard-integrity") == 0)
        return smoke_run_standard_integrity();
    if (argc == 2 && strcmp(argv[1], "fastpath-bitmap") == 0)
        return smoke_run_fastpath_bitmap();
    if (argc == 2 && strcmp(argv[1], "graphics-planar") == 0)
        return smoke_run_graphics_planar();
    if (argc == 2 && strcmp(argv[1], "security-downgrade") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_DOWNGRADE,
            LIBRDP_STATUS_SECURITY_DOWNGRADE,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-untrusted") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-hostname") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH,
            1,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-wrong-pin") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
            0,
            1);
    if (argc == 2 && strcmp(argv[1], "tls-handshake") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_INVALID,
            LIBRDP_STATUS_TLS_HANDSHAKE_FAILED,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "redirection-standard") == 0)
        return smoke_run_redirection(0, 0);
    if (argc == 2 && strcmp(argv[1], "redirection-tls") == 0)
        return smoke_run_redirection(1, 0);
    if (argc == 2 && strcmp(argv[1], "redirection-loop") == 0)
        return smoke_run_redirection(0, 1);
    if (argc == 2 && strcmp(argv[1], "lifecycle-stress") == 0)
        return smoke_run_lifecycle_stress();
    if (argc == 2 && strcmp(argv[1], "output-control") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 1,
                                 -1);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-connecting") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_CONNECTING);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-negotiating") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_NEGOTIATING);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-tls") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_TLS,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_TLS_HANDSHAKE);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-authenticating") == 0)
    {
        return smoke_run_profile(
            LIBRDP_SECURITY_NLA,
            LIBRDP_STATUS_OK,
            &smoke_nla_default_identity,
            "127.0.0.1",
            "127.0.0.1",
            NULL,
            0,
            LIBRDP_LIFECYCLE_AUTHENTICATING);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-activating") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_ACTIVATING);
    }
    if (argc == 2)
        gateway_profile =
            smoke_gateway_profile_by_name(argv[1]);
    if (gateway_profile)
    {
#ifdef RDP_HAVE_CURL
        return smoke_run_profile(
            LIBRDP_SECURITY_NLA,
            LIBRDP_STATUS_OK,
            &smoke_nla_default_identity,
            "127.0.0.1",
            "127.0.0.1",
            gateway_profile,
            0,
            -1);
#else
        return 77;
#endif
    }
    if (argc != 2 ||
        !smoke_parse_security(argv[1],
                              &security,
                              &expected_status,
                              &identity,
                              &bind_address,
                              &target))
    {
        fprintf(stderr,
                "usage: test_server_client_smoke "
                "standard|standard-dns|standard-ipv6|tls|nla|"
                "nla-invalid|nla-expired|nla-locked|"
                "nla-no-domain|nla-empty-domain|nla-upn|nla-utf8|"
                "timeout-credssp|standard-integrity|fastpath-bitmap|"
                "security-downgrade|"
                "tls-untrusted|tls-hostname|tls-wrong-pin|tls-handshake|"
                "redirection-standard|redirection-tls|redirection-loop|"
                "lifecycle-stress|output-control|"
                "cancel-connecting|cancel-negotiating|"
                "cancel-tls|cancel-authenticating|cancel-activating|"
                "gateway-http-connect|gateway-session-credentials|"
                "gateway-no-session-credentials|gateway-auth-failure|"
                "gateway-timeout|gateway-malformed|gateway-refused|"
                "gateway-rdg|gateway-rdg-drop-out|gateway-rdg-drop-in|"
                "gateway-rdg-untrusted\n");
        return 2;
    }
    return smoke_run_profile(security,
                             expected_status,
                             identity,
                             bind_address,
                             target,
                             NULL,
                             0,
                             -1);
}
