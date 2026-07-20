/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: workspace-to-viewer loopback smoke tests.
 * Coverage: the installed-style workspace process fetches a feed, resolves a
 * desktop or RemoteApp, launches a headless public-API viewer, reaches ACTIVE,
 * presents a frame, and sends the selected RAIL executable to a real server.
 * Bug classes: dropped feed metadata, malformed launch argv, wrong endpoint
 * selection, stalled activation, missing graphics, and lost RAIL requests.
 * Determinism: HTTP and RDP stay on loopback, all payloads are synthetic, and
 * process execution has a bounded deadline with process-group cleanup.
 */

#include "client_options.h"
#include "client_runtime.h"
#include "server_host.h"
#include "server_platform.h"

#include "channels/remote_programs.h"

#include <librdp/librdp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WORKSPACE_SMOKE_WIDTH 64u
#define WORKSPACE_SMOKE_HEIGHT 48u
#define WORKSPACE_SMOKE_PIXEL_BYTES \
    (WORKSPACE_SMOKE_WIDTH * WORKSPACE_SMOKE_HEIGHT * 4u)
#define WORKSPACE_SMOKE_PUMP_LIMIT 500u
#define WORKSPACE_SMOKE_PROCESS_TIMEOUT_NS 15000000000ULL

typedef struct workspace_smoke_platform
{
    server_platform_capture_sink capture_sink;
    server_platform_permission_sink permission_sink;
    uint8_t pixels[WORKSPACE_SMOKE_PIXEL_BYTES];
    uint64_t sequence;
} workspace_smoke_platform;

typedef struct workspace_smoke_observer
{
    const char* expected_app;
    atomic_uint active_peers;
    atomic_uint rail_exec_count;
    atomic_uint rail_exec_match;
    atomic_uint rail_malformed;
} workspace_smoke_observer;

typedef struct workspace_smoke_host
{
    server_host* host;
    pthread_t thread;
    atomic_uint port;
    atomic_int status;
    int thread_started;
} workspace_smoke_host;

typedef struct workspace_smoke_http
{
    int listen_fd;
    uint16_t port;
    pthread_t thread;
    char feed[2048];
    int status;
    int thread_started;
} workspace_smoke_http;

typedef struct workspace_probe_events
{
    unsigned int active;
    unsigned int frame_updates;
    unsigned int errors;
} workspace_probe_events;

static uint64_t workspace_smoke_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000ULL +
           (uint64_t)now.tv_nsec;
}

static void workspace_smoke_delay(void)
{
    const struct timespec delay = {0, 10000000L};

    (void)nanosleep(&delay, NULL);
}

static librdp_status workspace_smoke_capture_start(
    void* context,
    const server_platform_capture_sink* sink)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (!platform || !sink || !sink->frame || !sink->lost)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->capture_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void workspace_smoke_capture_stop(void* context)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (platform)
        memset(&platform->capture_sink, 0, sizeof(platform->capture_sink));
}

/*
 * Publish a complete deterministic frame for every host request. The callback
 * is synchronous, so frame storage remains valid for its full borrowed
 * lifetime and no native display server is involved.
 */
static librdp_status workspace_smoke_capture_request(void* context)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;
    const server_platform_rect dirty = {
        0u,
        0u,
        WORKSPACE_SMOKE_WIDTH,
        WORKSPACE_SMOKE_HEIGHT,
    };
    server_platform_frame frame;

    if (!platform || !platform->capture_sink.frame)
        return LIBRDP_STATUS_STATE;
    memset(&frame, 0, sizeof(frame));
    frame.width = WORKSPACE_SMOKE_WIDTH;
    frame.height = WORKSPACE_SMOKE_HEIGHT;
    frame.stride = WORKSPACE_SMOKE_WIDTH * 4u;
    frame.pixels = platform->pixels;
    frame.pixels_len = sizeof(platform->pixels);
    frame.dirty_rects = &dirty;
    frame.dirty_count = 1u;
    frame.sequence = ++platform->sequence;
    frame.timestamp_ns = workspace_smoke_now_ns();
    platform->capture_sink.frame(&frame,
                                 platform->capture_sink.user_data);
    return LIBRDP_STATUS_OK;
}

static librdp_status workspace_smoke_permission_start(
    void* context,
    const server_platform_permission_sink* sink)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (!platform || !sink || !sink->changed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->permission_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void workspace_smoke_permission_stop(void* context)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (platform)
        memset(&platform->permission_sink,
               0,
               sizeof(platform->permission_sink));
}

static librdp_status workspace_smoke_permission_query(
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

static librdp_status workspace_smoke_permission_request(
    void* context,
    server_platform_permission_kind kind)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (!platform ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
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

static librdp_status workspace_smoke_permission_revoke(
    void* context,
    server_platform_permission_kind kind)
{
    workspace_smoke_platform* platform =
        (workspace_smoke_platform*)context;

    if (!platform ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (platform->permission_sink.changed)
    {
        platform->permission_sink.changed(
            kind,
            SERVER_PLATFORM_PERMISSION_DENIED,
            platform->permission_sink.user_data);
    }
    return LIBRDP_STATUS_OK;
}

static const server_platform_capture_vtable workspace_smoke_capture = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    workspace_smoke_capture_start,
    workspace_smoke_capture_stop,
    workspace_smoke_capture_request,
    NULL,
};

static const server_platform_permission_vtable
    workspace_smoke_permission = {
        SERVER_PLATFORM_PERMISSION_VERSION,
        sizeof(server_platform_permission_vtable),
        workspace_smoke_permission_start,
        workspace_smoke_permission_stop,
        workspace_smoke_permission_query,
        workspace_smoke_permission_request,
        workspace_smoke_permission_revoke,
        NULL,
    };

static int workspace_smoke_utf16le_equals(const uint8_t* value,
                                          size_t value_len,
                                          const char* expected)
{
    size_t index = 0u;
    size_t expected_len = expected ? strlen(expected) : 0u;

    if (!value || !expected || value_len != expected_len * 2u)
        return 0;
    for (index = 0u; index < expected_len; index++)
    {
        if (value[index * 2u] != (uint8_t)expected[index] ||
            value[index * 2u + 1u] != 0u)
            return 0;
    }
    return 1;
}

/*
 * Observe the normalized server extension boundary and decode only EXEC
 * orders. The exact UTF-16LE application identifier must match the feed;
 * malformed or substituted requests are recorded independently.
 */
static void workspace_smoke_extension(
    librdp_server_peer* peer,
    const librdp_server_extension_event* event,
    void* user_data)
{
    workspace_smoke_observer* observer =
        (workspace_smoke_observer*)user_data;
    rdp_remote_programs_exec order;

    (void)peer;
    if (!observer || !event ||
        event->family != LIBRDP_SERVER_EXTENSION_RAIL ||
        event->message_type != RDP_REMOTE_PROGRAMS_ORDER_EXEC)
        return;
    atomic_fetch_add_explicit(&observer->rail_exec_count,
                              1u,
                              memory_order_relaxed);
    if (rdp_remote_programs_parse_exec(event->payload,
                                       event->payload_len,
                                       &order) != LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&observer->rail_malformed,
                                  1u,
                                  memory_order_relaxed);
        return;
    }
    if (workspace_smoke_utf16le_equals(order.exe_or_file,
                                       order.exe_or_file_len,
                                       observer->expected_app))
    {
        atomic_fetch_add_explicit(&observer->rail_exec_match,
                                  1u,
                                  memory_order_relaxed);
    }
}

static void workspace_smoke_host_trace(
    const server_host_trace_event* event,
    void* user_data)
{
    workspace_smoke_observer* observer =
        (workspace_smoke_observer*)user_data;

    if (!observer || !event)
        return;
    if (event->type == SERVER_HOST_TRACE_PEER_STATE &&
        event->value == (uint64_t)LIBRDP_SERVER_PEER_ACTIVE)
    {
        atomic_fetch_add_explicit(&observer->active_peers,
                                  1u,
                                  memory_order_relaxed);
    }
}

static void workspace_smoke_platform_init(
    workspace_smoke_platform* platform,
    server_host_config* config)
{
    size_t offset = 0u;

    memset(platform, 0, sizeof(*platform));
    for (offset = 0u; offset < sizeof(platform->pixels); offset += 4u)
    {
        platform->pixels[offset] = (uint8_t)(offset / 4u);
        platform->pixels[offset + 1u] = 0x35u;
        platform->pixels[offset + 2u] = 0x9au;
        platform->pixels[offset + 3u] = 0xffu;
    }
    config->platform.capture.vtable = &workspace_smoke_capture;
    config->platform.capture.context = platform;
    config->platform.permission.vtable = &workspace_smoke_permission;
    config->platform.permission.context = platform;
}

static void* workspace_smoke_host_main(void* user_data)
{
    workspace_smoke_host* fixture =
        (workspace_smoke_host*)user_data;

    if (!fixture)
        return NULL;
    atomic_store_explicit(&fixture->status,
                          server_host_start(fixture->host),
                          memory_order_release);
    if ((librdp_status)atomic_load_explicit(&fixture->status,
                                            memory_order_acquire) !=
        LIBRDP_STATUS_OK)
        return NULL;
    atomic_store_explicit(&fixture->port,
                          server_host_local_port(fixture->host),
                          memory_order_release);
    for (;;)
    {
        librdp_status status =
            server_host_run_once(fixture->host, 20);

        if (status == LIBRDP_STATUS_OK ||
            status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status == LIBRDP_STATUS_CANCELLED)
        {
            atomic_store_explicit(&fixture->status,
                                  LIBRDP_STATUS_OK,
                                  memory_order_release);
            break;
        }
        atomic_store_explicit(&fixture->status,
                              status,
                              memory_order_release);
        break;
    }
    if (server_host_get_state(fixture->host) != SERVER_HOST_STOPPED)
        (void)server_host_stop(fixture->host);
    return NULL;
}

static int workspace_smoke_host_start(
    workspace_smoke_host* fixture,
    workspace_smoke_platform* platform,
    workspace_smoke_observer* observer)
{
    server_host_config config;
    unsigned int attempt = 0u;

    if (!fixture || !platform || !observer)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    atomic_init(&fixture->port, 0u);
    atomic_init(&fixture->status, LIBRDP_STATUS_AGAIN);
    server_host_config_init(&config);
    config.server.bind_address = "127.0.0.1";
    config.server.security_mode = LIBRDP_SECURITY_STANDARD;
    config.server.width = WORKSPACE_SMOKE_WIDTH;
    config.server.height = WORKSPACE_SMOKE_HEIGHT;
    config.max_peers = 1u;
    config.dirty.frame_interval_ns = 0u;
    config.trace_callback = workspace_smoke_host_trace;
    config.trace_user_data = observer;
    config.extension_callback = workspace_smoke_extension;
    config.extension_user_data = observer;
    workspace_smoke_platform_init(platform, &config);
    fixture->host = server_host_new(&config);
    if (!fixture->host)
        return 0;
    if (pthread_create(&fixture->thread,
                       NULL,
                       workspace_smoke_host_main,
                       fixture) != 0)
        return 0;
    fixture->thread_started = 1;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        if (atomic_load_explicit(&fixture->port,
                                 memory_order_acquire) != 0u)
            return 1;
        if ((librdp_status)atomic_load_explicit(&fixture->status,
                                                memory_order_acquire) !=
            LIBRDP_STATUS_AGAIN)
            return 0;
        workspace_smoke_delay();
    }
    return 0;
}

static int workspace_smoke_host_stop(workspace_smoke_host* fixture)
{
    int ok = 1;

    if (!fixture)
        return 0;
    if (fixture->host && fixture->thread_started)
    {
        if (server_host_cancel(fixture->host) != LIBRDP_STATUS_OK)
            ok = 0;
        if (pthread_join(fixture->thread, NULL) != 0)
            ok = 0;
        fixture->thread_started = 0;
    }
    if ((librdp_status)atomic_load_explicit(&fixture->status,
                                            memory_order_acquire) !=
        LIBRDP_STATUS_OK)
        ok = 0;
    server_host_free(fixture->host);
    fixture->host = NULL;
    return ok;
}

static int workspace_smoke_write_all(int fd,
                                     const void* data,
                                     size_t length)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t count = write(fd, bytes + offset, length - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return 1;
}

static void* workspace_smoke_http_main(void* user_data)
{
    workspace_smoke_http* fixture =
        (workspace_smoke_http*)user_data;
    struct pollfd pfd;
    char request[2048];
    char header[256];
    size_t used = 0u;
    int client = -1;
    int header_len = 0;

    if (!fixture)
        return NULL;
    fixture->status = 1;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fixture->listen_fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1u, 10000) != 1)
        return NULL;
    client = accept(fixture->listen_fd, NULL, NULL);
    if (client < 0)
        return NULL;
    while (used + 1u < sizeof(request))
    {
        ssize_t count =
            read(client, request + used, sizeof(request) - used - 1u);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        used += (size_t)count;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            break;
    }
    if (!strstr(request, "GET /feed HTTP/"))
    {
        close(client);
        return NULL;
    }
    header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        strlen(fixture->feed));
    if (header_len > 0 &&
        (size_t)header_len < sizeof(header) &&
        workspace_smoke_write_all(client, header, (size_t)header_len) &&
        workspace_smoke_write_all(client,
                                  fixture->feed,
                                  strlen(fixture->feed)))
        fixture->status = 0;
    close(client);
    return NULL;
}

/*
 * Create one single-use HTTP feed endpoint. The resource embeds both target
 * and ephemeral RDP port so the workspace launch path cannot accidentally
 * connect to the conventional system port.
 */
static int workspace_smoke_http_start(workspace_smoke_http* fixture,
                                      uint16_t rdp_port,
                                      int remote_app)
{
    struct sockaddr_in address;
    socklen_t address_len = (socklen_t)sizeof(address);
    int one = 1;
    int feed_len = 0;

    if (!fixture || rdp_port == 0u)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->listen_fd = -1;
    if (remote_app)
    {
        feed_len = snprintf(
            fixture->feed,
            sizeof(fixture->feed),
            "<Workspace><Resources>"
            "<RemoteApp id=\"remoteapp-smoke\">"
            "<Title>RemoteApp Smoke</Title><Alias>remoteapp-smoke</Alias>"
            "<TerminalServer>127.0.0.1</TerminalServer>"
            "<RDPFileContents>full address:s:127.0.0.1\n"
            "server port:i:%u\n"
            "remoteapplicationprogram:s:||workspace-smoke-app"
            "</RDPFileContents>"
            "<RemoteAppProgram>||workspace-smoke-app</RemoteAppProgram>"
            "</RemoteApp></Resources></Workspace>",
            (unsigned int)rdp_port);
    }
    else
    {
        feed_len = snprintf(
            fixture->feed,
            sizeof(fixture->feed),
            "<Workspace><Resources>"
            "<Resource><ID>desktop-smoke</ID>"
            "<Title>Desktop Smoke</Title><Type>Desktop</Type>"
            "<TerminalServer>127.0.0.1</TerminalServer>"
            "<RDPFileContents>full address:s:127.0.0.1\n"
            "server port:i:%u</RDPFileContents>"
            "</Resource></Resources></Workspace>",
            (unsigned int)rdp_port);
    }
    if (feed_len <= 0 || (size_t)feed_len >= sizeof(fixture->feed))
        return 0;
    fixture->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fixture->listen_fd < 0)
        return 0;
    (void)setsockopt(fixture->listen_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &one,
                     sizeof(one));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0u;
    if (bind(fixture->listen_fd,
             (const struct sockaddr*)&address,
             sizeof(address)) != 0 ||
        getsockname(fixture->listen_fd,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(fixture->listen_fd, 1) != 0)
    {
        close(fixture->listen_fd);
        fixture->listen_fd = -1;
        return 0;
    }
    fixture->port = ntohs(address.sin_port);
    if (pthread_create(&fixture->thread,
                       NULL,
                       workspace_smoke_http_main,
                       fixture) != 0)
    {
        close(fixture->listen_fd);
        fixture->listen_fd = -1;
        return 0;
    }
    fixture->thread_started = 1;
    return 1;
}

static int workspace_smoke_http_stop(workspace_smoke_http* fixture)
{
    int ok = 1;

    if (!fixture)
        return 0;
    if (fixture->thread_started)
    {
        if (pthread_join(fixture->thread, NULL) != 0)
            ok = 0;
        fixture->thread_started = 0;
    }
    if (fixture->status != 0)
        ok = 0;
    if (fixture->listen_fd >= 0)
        close(fixture->listen_fd);
    fixture->listen_fd = -1;
    return ok;
}

static void workspace_probe_event(librdp_session* session,
                                  const librdp_event* event,
                                  void* user_data)
{
    workspace_probe_events* events =
        (workspace_probe_events*)user_data;

    if (!session || !events || !event)
        return;
    if (event->type == LIBRDP_EVENT_STATE_CHANGED &&
        event->data.state.new_state == LIBRDP_SESSION_ACTIVE)
        events->active = 1u;
    else if (event->type == LIBRDP_EVENT_SURFACE_INVALIDATED)
    {
        const librdp_surface* surface =
            librdp_session_get_surface(session);
        const uint8_t* pixels =
            surface ? librdp_surface_pixels(surface) : NULL;

        if (pixels && librdp_surface_width(surface) == WORKSPACE_SMOKE_WIDTH &&
            librdp_surface_height(surface) == WORKSPACE_SMOKE_HEIGHT &&
            pixels[1] == 0x35u && pixels[2] == 0x9au &&
            pixels[3] == 0xffu)
            events->frame_updates++;
    }
    else if (event->type == LIBRDP_EVENT_ERROR)
        events->errors++;
}

static librdp_status workspace_probe_pump(client_runtime* runtime)
{
    struct pollfd* fds = NULL;
    size_t count = 0u;
    int timeout_ms = 20;
    int ready = 0;
    librdp_status status = client_runtime_prepare_poll(runtime,
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

/*
 * Act as the viewer process selected by the workspace launch plan. Only the
 * public settings/session API and shared viewer option parser are used; a
 * successful exit requires ACTIVE, a normalized surface update, and an active
 * RAIL runtime when a RemoteApp argument was supplied.
 */
static int workspace_probe_main(int argc, char** argv)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    client_options options;
    client_option_policy policy;
    client_runtime runtime;
    workspace_probe_events events;
    uint32_t rail_apps = 0u;
    unsigned int cycle = 0u;
    int result = 1;

    memset(&runtime, 0, sizeof(runtime));
    memset(&events, 0, sizeof(events));
    client_option_policy_init(&policy);
    policy.error_stream = stderr;
    policy.rail_requires_app_prefix = 1;
    settings = librdp_settings_new();
    if (!settings)
        return 1;
    client_options_init(&options);
    if (!client_options_configure(settings,
                                  &options,
                                  &policy,
                                  argc,
                                  argv) ||
        librdp_settings_set_desktop_size(settings,
                                         WORKSPACE_SMOKE_WIDTH,
                                         WORKSPACE_SMOKE_HEIGHT) !=
            LIBRDP_STATUS_OK)
    {
        client_options_clear(&options);
        librdp_settings_free(settings);
        return 1;
    }
    rail_apps = librdp_settings_rail_app_count(settings);
    session = librdp_session_new(settings);
    if (!session)
    {
        client_options_clear(&options);
        librdp_settings_free(settings);
        return 1;
    }
    librdp_session_set_event_callback(session,
                                      workspace_probe_event,
                                      &events);
    client_runtime_init(&runtime, session);
    if (client_runtime_connect(&runtime) == LIBRDP_STATUS_OK)
    {
        for (cycle = 0u; cycle < WORKSPACE_SMOKE_PUMP_LIMIT; cycle++)
        {
            librdp_feature_status rail_status;
            librdp_status status = workspace_probe_pump(&runtime);
            int rail_ready = rail_apps == 0u;

            if (status != LIBRDP_STATUS_OK)
                break;
            memset(&rail_status, 0, sizeof(rail_status));
            if (rail_apps > 0u &&
                librdp_session_get_feature_status(
                    session,
                    LIBRDP_FEATURE_RAIL,
                    &rail_status) == LIBRDP_STATUS_OK)
                rail_ready = rail_status.active;
            if (events.active && events.frame_updates > 0u &&
                events.errors == 0u && rail_ready)
            {
                result = 0;
                break;
            }
        }
        if (client_runtime_disconnect(&runtime) != LIBRDP_STATUS_OK)
            result = 1;
    }
    client_runtime_clear(&runtime);
    librdp_session_free(session);
    client_options_clear(&options);
    librdp_settings_free(settings);
    return result;
}

/*
 * Execute the workspace and its viewer child as one process group. This keeps
 * timeout cleanup deterministic even when the workspace is blocked waiting
 * for a failed viewer process.
 */
static int workspace_smoke_run_process(const char* workspace_path,
                                       const char* probe_path,
                                       const char* feed_url,
                                       const char* selector)
{
    pid_t child = 0;
    uint64_t deadline_ns = 0u;
    int status = 0;

    if (!workspace_path || !probe_path || !feed_url || !selector)
        return 0;
    child = fork();
    if (child < 0)
        return 0;
    if (child == 0)
    {
        char* const arguments[] = {
            (char*)workspace_path,
            (char*)"--feed",
            (char*)feed_url,
            (char*)"--select",
            (char*)selector,
            (char*)"--viewer",
            (char*)probe_path,
            (char*)"--security",
            (char*)"rdp",
            (char*)"--launch",
            (char*)"--no-window",
            NULL,
        };

        (void)setpgid(0, 0);
        (void)setenv("LIBRDP_TRACE_CLIENT", "1", 1);
        (void)setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
        (void)setenv("LIBRDP_TRACE_PROTOCOL", "1", 1);
        (void)setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
        (void)setenv("LIBRDP_TRACE_HEX_BYTES", "32", 1);
        execv(workspace_path, arguments);
        _exit(127);
    }
    (void)setpgid(child, child);
    deadline_ns = workspace_smoke_now_ns() +
                  WORKSPACE_SMOKE_PROCESS_TIMEOUT_NS;
    while (workspace_smoke_now_ns() < deadline_ns)
    {
        pid_t waited = waitpid(child, &status, WNOHANG);

        if (waited == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (waited < 0 && errno != EINTR)
            return 0;
        workspace_smoke_delay();
    }
    (void)kill(-child, SIGTERM);
    workspace_smoke_delay();
    (void)kill(-child, SIGKILL);
    (void)waitpid(child, &status, 0);
    return 0;
}

static int workspace_smoke_run(const char* mode,
                               const char* workspace_path,
                               const char* probe_path)
{
    const int remote_app =
        mode && strcmp(mode, "remoteapp") == 0;
    const char* selector =
        remote_app ? "remoteapp-smoke" : "desktop-smoke";
    workspace_smoke_platform platform;
    workspace_smoke_observer observer;
    workspace_smoke_host host;
    workspace_smoke_http http;
    char feed_url[128];
    uint16_t rdp_port = 0u;
    int feed_url_len = 0;
    int process_ok = 0;
    int http_ok = 0;
    int host_ok = 0;
    int result = 1;

    if (!mode || (!remote_app && strcmp(mode, "desktop") != 0) ||
        !workspace_path || !probe_path)
        return 2;
    memset(&platform, 0, sizeof(platform));
    memset(&observer, 0, sizeof(observer));
    memset(&host, 0, sizeof(host));
    memset(&http, 0, sizeof(http));
    observer.expected_app = "||workspace-smoke-app";
    atomic_init(&observer.active_peers, 0u);
    atomic_init(&observer.rail_exec_count, 0u);
    atomic_init(&observer.rail_exec_match, 0u);
    atomic_init(&observer.rail_malformed, 0u);
    if (!workspace_smoke_host_start(&host, &platform, &observer))
    {
        (void)workspace_smoke_host_stop(&host);
        return 1;
    }
    rdp_port = (uint16_t)atomic_load_explicit(&host.port,
                                              memory_order_acquire);
    if (workspace_smoke_http_start(&http, rdp_port, remote_app))
    {
        feed_url_len = snprintf(feed_url,
                                sizeof(feed_url),
                                "http://127.0.0.1:%u/feed",
                                (unsigned int)http.port);
        if (feed_url_len > 0 &&
            (size_t)feed_url_len < sizeof(feed_url))
        {
            process_ok = workspace_smoke_run_process(workspace_path,
                                                     probe_path,
                                                     feed_url,
                                                     selector);
        }
        http_ok = workspace_smoke_http_stop(&http);
    }
    host_ok = workspace_smoke_host_stop(&host);
    if (process_ok && http_ok && host_ok &&
        atomic_load_explicit(&observer.active_peers,
                             memory_order_relaxed) == 1u &&
        atomic_load_explicit(&observer.rail_malformed,
                             memory_order_relaxed) == 0u)
    {
        if ((!remote_app &&
             atomic_load_explicit(&observer.rail_exec_count,
                                  memory_order_relaxed) == 0u) ||
            (remote_app &&
             atomic_load_explicit(&observer.rail_exec_count,
                                  memory_order_relaxed) == 1u &&
             atomic_load_explicit(&observer.rail_exec_match,
                                  memory_order_relaxed) == 1u))
            result = 0;
    }
    if (result != 0)
    {
        fprintf(stderr,
                "workspace smoke mode=%s process=%d http=%d host=%d active=%u "
                "rail_exec=%u rail_match=%u rail_malformed=%u\n",
                mode,
                process_ok,
                http_ok,
                host_ok,
                atomic_load_explicit(&observer.active_peers,
                                     memory_order_relaxed),
                atomic_load_explicit(&observer.rail_exec_count,
                                     memory_order_relaxed),
                atomic_load_explicit(&observer.rail_exec_match,
                                     memory_order_relaxed),
                atomic_load_explicit(&observer.rail_malformed,
                                     memory_order_relaxed));
    }
    return result;
}

int main(int argc, char** argv)
{
    if (argc > 1 && strcmp(argv[1], "--target") == 0)
        return workspace_probe_main(argc, argv);
    if (argc != 4)
        return 2;
    return workspace_smoke_run(argv[1], argv[2], argv[3]);
}
