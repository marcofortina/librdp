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
#include "server_host.h"
#include "server_platform.h"
#include "test_server_support.h"

#include "protocol/fastpath.h"
#include "server/server_internal.h"
#include "server/server_security.h"

#include <librdp/librdp.h>

#include <openssl/err.h>

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

#define SMOKE_WIDTH 64u
#define SMOKE_HEIGHT 48u
#define SMOKE_CAPTURE_WIDTH 80u
#define SMOKE_CAPTURE_HEIGHT 60u
#define SMOKE_PIXEL_BYTES (SMOKE_CAPTURE_WIDTH * SMOKE_CAPTURE_HEIGHT * 4u)
#define SMOKE_PUMP_LIMIT 500u

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

typedef struct smoke_platform
{
    server_platform_capture_sink capture_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_drive_sink drive_sink;
    server_platform_permission_sink permission_sink;
    atomic_uint capture_requests;
    atomic_uint key_events;
    atomic_uint mouse_events;
    atomic_uint clipboard_offers;
    atomic_uint drive_presentations;
    atomic_uint releases;
    char drive_name[64];
    uint8_t pixels[SMOKE_PIXEL_BYTES];
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
    unsigned int credssp_failures;
    unsigned int slowpath_integrity_failures;
    unsigned int fastpath_integrity_failures;
    unsigned int integrity_failures;
    unsigned int security_downgrades;
    unsigned int tls_connect_failures;
    unsigned int tls_verify_failures;
    int leaked;
    int address_matched;
    const smoke_nla_identity* identity;
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
    if (!capture->identity)
        return;
    if ((capture->identity->username &&
         strstr(record->line, capture->identity->username)) ||
        (capture->identity->password &&
         strstr(record->line, capture->identity->password)) ||
        (capture->identity->domain && capture->identity->domain[0] != '\0' &&
         strstr(record->line, capture->identity->domain)))
        capture->leaked = 1;
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
    frame.pixels = platform->pixels;
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
    }
    atomic_init(&platform->capture_requests, 0u);
    atomic_init(&platform->key_events, 0u);
    atomic_init(&platform->mouse_events, 0u);
    atomic_init(&platform->clipboard_offers, 0u);
    atomic_init(&platform->drive_presentations, 0u);
    atomic_init(&platform->releases, 0u);
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

static librdp_status smoke_integrity_send_all(int fd,
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

static librdp_status smoke_integrity_send_fastpath(
    librdp_server_peer* peer)
{
    rdp_buffer update;
    rdp_buffer encrypted;
    rdp_buffer wire;
    uint8_t signature[8];
    size_t signature_offset = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !peer->standard_security_ready)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&update);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&wire);
    status = rdp_fastpath_write_update(
        &update,
        RDP_FASTPATH_UPDATE_SYNCHRONIZE,
        RDP_FASTPATH_FRAGMENT_SINGLE,
        0u,
        0u,
        NULL,
        0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_mac_signature(
            &peer->standard_security,
            update.data,
            update.length,
            signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&encrypted,
                                   update.data,
                                   update.length);
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
        wire.data[signature_offset] ^= 0x40u;
        status = smoke_integrity_send_all(peer->fd,
                                          wire.data,
                                          wire.length);
    }
    OPENSSL_cleanse(signature, sizeof(signature));
    rdp_buffer_free(&wire);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&update);
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
    unsigned int attempt = 0u;

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
    for (attempt = 0u; attempt < 500u && !peer; attempt++)
    {
        fixture->status = librdp_server_accept(server, 20, &peer);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    if (!peer)
        goto cleanup;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        if (librdp_server_peer_get_state(peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            break;
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    if (librdp_server_peer_get_state(peer) !=
        LIBRDP_SERVER_PEER_ACTIVE)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
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
                             const char* target)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char drive_directory[128] = {0};
    char drive_marker[160] = {0};
    static const uint8_t clipboard_data[] = {'s', 'm', 'o', 'k', 'e'};
    smoke_platform platform;
    smoke_host host_fixture;
    smoke_client_events events;
    smoke_nla_provider nla_provider;
    smoke_trace_capture trace_capture;
    server_host_config host_config;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    client_runtime runtime;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    librdp_key_event key;
    librdp_mouse_event mouse;
    librdp_status connect_status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    uint16_t default_port = 0u;
    unsigned int cycle = 0u;
    int clipboard_sent = 0;
    int input_sent = 0;
    int thread_started = 0;
    int result = 1;

    memset(&host_fixture, 0, sizeof(host_fixture));
    memset(&events, 0, sizeof(events));
    memset(&nla_provider, 0, sizeof(nla_provider));
    memset(&trace_capture, 0, sizeof(trace_capture));
    trace_capture.identity = identity;
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
    trace_capture.target = target;
    trace_capture.port = port;

    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
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
        if (desktop_ready && events.surface_events > 0u &&
            clipboard_sent &&
            atomic_load_explicit(&platform.clipboard_offers,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.key_events,
                                 memory_order_acquire) >= 2u &&
            atomic_load_explicit(&platform.mouse_events,
                                 memory_order_acquire) >= 1u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.surface_events > 0u);
    REQUIRE(events.error_events == 0u);
    REQUIRE(trace_capture.records > 0u);
    REQUIRE(trace_capture.connect_starts == 1u);
    REQUIRE(trace_capture.connect_completions == 1u);
    REQUIRE(trace_capture.address_matched);
    REQUIRE(trace_capture.leaked == 0);
    REQUIRE(librdp_surface_width(librdp_session_get_surface(session)) ==
            SMOKE_WIDTH);
    REQUIRE(librdp_surface_height(librdp_session_get_surface(session)) ==
            SMOKE_HEIGHT);
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
    REQUIRE(client_runtime_disconnect(&runtime) == LIBRDP_STATUS_OK);
    REQUIRE(server_host_cancel(host_fixture.host) == LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(strcmp(platform.drive_name, "SMOKE") == 0);
    REQUIRE(atomic_load_explicit(&platform.releases,
                                 memory_order_acquire) > 0u);
    result = 0;

cleanup:
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

int main(int argc, char** argv)
{
    librdp_security_mode security = LIBRDP_SECURITY_AUTO;
    librdp_status expected_status = LIBRDP_STATUS_OK;
    const smoke_nla_identity* identity = NULL;
    const char* bind_address = NULL;
    const char* target = NULL;

    if (argc == 2 && strcmp(argv[1], "timeout-credssp") == 0)
        return smoke_run_credssp_timeout();
    if (argc == 2 && strcmp(argv[1], "standard-integrity") == 0)
        return smoke_run_standard_integrity();
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
                "timeout-credssp|standard-integrity|security-downgrade|"
                "tls-untrusted|tls-hostname|tls-wrong-pin|tls-handshake\n");
        return 2;
    }
    return smoke_run_profile(security,
                             expected_status,
                             identity,
                             bind_address,
                             target);
}
