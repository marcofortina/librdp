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

#include <librdp/librdp.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SMOKE_WIDTH 64u
#define SMOKE_HEIGHT 48u
#define SMOKE_CAPTURE_WIDTH 80u
#define SMOKE_CAPTURE_HEIGHT 60u
#define SMOKE_PIXEL_BYTES (SMOKE_CAPTURE_WIDTH * SMOKE_CAPTURE_HEIGHT * 4u)
#define SMOKE_PUMP_LIMIT 500u

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

typedef struct smoke_client_events
{
    unsigned int state_events;
    unsigned int surface_events;
    unsigned int error_events;
    int active;
} smoke_client_events;

static int smoke_check(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_app_server_smoke:%d: check failed: %s\n",
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

static int smoke_wait_for_port(const smoke_host* fixture, uint16_t* port)
{
    unsigned int attempt = 0u;
    struct timespec delay = {0, 10000000L};

    if (!fixture || !port)
        return 0;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        unsigned int value = atomic_load_explicit(&fixture->port,
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
                                    const char* key_path)
{
    static const char username[] = "smoke-user-731";
    static const char password[] = "smoke-secret-739";
    static const char domain[] = "SMOKE-DOMAIN-733";
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
    host_config->server.nla_username = username;
    host_config->server.nla_password = password;
    host_config->server.nla_domain = domain;
    return librdp_settings_set_username(settings, username) ==
               LIBRDP_STATUS_OK &&
           librdp_settings_set_password(settings, password) ==
               LIBRDP_STATUS_OK &&
           librdp_settings_set_domain(settings, domain) == LIBRDP_STATUS_OK;
}

/*
 * Complete one security profile through the public client API and application
 * server host. Every provider must cross a real protocol boundary before the
 * fixture accepts the run.
 */
static int smoke_run_profile(librdp_security_mode security)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char drive_directory[128] = {0};
    char drive_marker[160] = {0};
    static const uint8_t clipboard_data[] = {'s', 'm', 'o', 'k', 'e'};
    smoke_platform platform;
    smoke_host host_fixture;
    smoke_client_events events;
    server_host_config host_config;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    client_runtime runtime;
    librdp_key_event key;
    librdp_mouse_event mouse;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int clipboard_sent = 0;
    int input_sent = 0;
    int thread_started = 0;
    int result = 1;

    memset(&host_fixture, 0, sizeof(host_fixture));
    memset(&events, 0, sizeof(events));
    memset(&runtime, 0, sizeof(runtime));
    memset(&key, 0, sizeof(key));
    memset(&mouse, 0, sizeof(mouse));
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
    host_config.server.bind_address = "127.0.0.1";
    host_config.server.width = SMOKE_CAPTURE_WIDTH;
    host_config.server.height = SMOKE_CAPTURE_HEIGHT;
    host_config.max_peers = 1u;
    host_config.dirty.frame_interval_ns = 0u;
    smoke_platform_init(&platform, &host_config);

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
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
                                     key_path));
    host_fixture.host = server_host_new(&host_config);
    REQUIRE(host_fixture.host != NULL);
    REQUIRE(pthread_create(&host_fixture.thread,
                           NULL,
                           smoke_host_main,
                           &host_fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&host_fixture, &port));
    REQUIRE(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);

    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session, smoke_client_event, &events);
    client_runtime_init(&runtime, session);
    REQUIRE(client_runtime_connect(&runtime) == LIBRDP_STATUS_OK);
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

static int smoke_parse_security(const char* value,
                                librdp_security_mode* security)
{
    if (!value || !security)
        return 0;
    if (strcmp(value, "standard") == 0)
        *security = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(value, "tls") == 0)
        *security = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "nla") == 0)
        *security = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

int main(int argc, char** argv)
{
    librdp_security_mode security = LIBRDP_SECURITY_AUTO;

    if (argc != 2 || !smoke_parse_security(argv[1], &security))
    {
        fprintf(stderr,
                "usage: test_app_server_smoke standard|tls|nla\n");
        return 2;
    }
    return smoke_run_profile(security);
}
