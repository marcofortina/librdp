/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared desktop-server application layer tests.
 * Coverage: platform-provider contracts, bounded scheduling and host lifecycle.
 * Bug classes: malformed vtables, native-handle leakage, unbounded queues,
 * stale peer state, cancellation and event-loop starvation.
 * Determinism: providers are in-memory mocks and network tests use loopback.
 */

#include "server_dirty.h"
#include "server_host.h"
#include "server_platform.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct mock_platform_context
{
    server_platform_capture_sink capture_sink;
    server_platform_pointer_sink pointer_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_drive_sink drive_sink;
    server_platform_permission_sink permission_sink;
    server_platform_permission_state permissions[4];
    unsigned int starts;
    unsigned int stops;
    unsigned int frame_requests;
    unsigned int releases;
} mock_platform_context;

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_app_server:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expression)                                                                           \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expression), #expression, __LINE__) != 0)                                    \
            return 1;                                                                                \
    } while (0)

static librdp_status mock_get_pollfds(void* context,
                                      struct pollfd* fds,
                                      size_t capacity,
                                      size_t* count)
{
    (void)context;
    if (!count || (capacity > 0u && !fds))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 0u;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_notify_poll(void* context,
                                     const struct pollfd* fds,
                                     size_t count)
{
    (void)context;
    return count == 0u && !fds ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_dispatch(void* context, unsigned int max_events)
{
    (void)context;
    return max_events > 0u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_get_timeout(void* context, int* timeout_ms)
{
    (void)context;
    if (!timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = -1;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_capture_start(void* context,
                                        const server_platform_capture_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->frame || !sink->lost)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->capture_sink = *sink;
    mock->starts++;
    return LIBRDP_STATUS_OK;
}

static void mock_stop(void* context)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (mock)
        mock->stops++;
}

static librdp_status mock_request_frame(void* context)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->frame_requests++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_pointer_start(void* context,
                                        const server_platform_pointer_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->pointer_sink = *sink;
    mock->starts++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_inject(void* context,
                                 const librdp_server_input_event* event)
{
    (void)context;
    return event ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void mock_release_all(void* context)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (mock)
        mock->releases++;
}

static librdp_status mock_clipboard_start(
    void* context,
    const server_platform_clipboard_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->formats || !sink->data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->clipboard_sink = *sink;
    mock->starts++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_publish_formats(
    void* context,
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation)
{
    (void)context;
    (void)generation;
    return format_count == 0u || formats
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_request_data(void* context,
                                       uint64_t request_id,
                                       uint32_t format_id)
{
    (void)context;
    return request_id != 0u && format_id != 0u
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_write_data(void* context,
                                     const server_platform_clipboard_data* data)
{
    (void)context;
    return data ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void mock_release_ownership(void* context, uint64_t generation)
{
    (void)context;
    (void)generation;
}

static librdp_status mock_drive_start(void* context,
                                      const server_platform_drive_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->drive_sink = *sink;
    mock->starts++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_drive_present(
    void* context,
    const server_platform_drive_volume* volume)
{
    (void)context;
    return volume && volume->name
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void mock_drive_remove(void* context,
                              uint32_t peer_id,
                              uint32_t generation,
                              uint32_t device_id)
{
    (void)context;
    (void)peer_id;
    (void)generation;
    (void)device_id;
}

static void mock_drive_remove_peer(void* context,
                                   uint32_t peer_id,
                                   uint32_t generation)
{
    (void)context;
    (void)peer_id;
    (void)generation;
}

static librdp_status mock_permission_start(
    void* context,
    const server_platform_permission_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->changed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->permission_sink = *sink;
    mock->starts++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_permission_query(
    void* context,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!state || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!mock)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = mock->permissions[(size_t)kind - 1u];
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_permission_change(
    void* context,
    server_platform_permission_kind kind)
{
    (void)context;
    return kind >= SERVER_PLATFORM_PERMISSION_CAPTURE &&
                   kind <= SERVER_PLATFORM_PERMISSION_DRIVE
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static const server_platform_event_source_vtable mock_events = {
    SERVER_PLATFORM_EVENT_SOURCE_VERSION,
    sizeof(server_platform_event_source_vtable),
    mock_get_pollfds,
    mock_notify_poll,
    mock_dispatch,
    mock_get_timeout,
};

static const server_platform_capture_vtable mock_capture = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    mock_capture_start,
    mock_stop,
    mock_request_frame,
    &mock_events,
};

static const server_platform_pointer_vtable mock_pointer = {
    SERVER_PLATFORM_POINTER_VERSION,
    sizeof(server_platform_pointer_vtable),
    mock_pointer_start,
    mock_stop,
    &mock_events,
};

static const server_platform_input_vtable mock_input = {
    SERVER_PLATFORM_INPUT_VERSION,
    sizeof(server_platform_input_vtable),
    mock_inject,
    mock_release_all,
};

static const server_platform_clipboard_vtable mock_clipboard = {
    SERVER_PLATFORM_CLIPBOARD_VERSION,
    sizeof(server_platform_clipboard_vtable),
    mock_clipboard_start,
    mock_stop,
    mock_publish_formats,
    mock_request_data,
    mock_write_data,
    mock_release_ownership,
    &mock_events,
};

static const server_platform_drive_vtable mock_drive = {
    SERVER_PLATFORM_DRIVE_VERSION,
    sizeof(server_platform_drive_vtable),
    mock_drive_start,
    mock_stop,
    mock_drive_present,
    mock_drive_remove,
    mock_drive_remove_peer,
    &mock_events,
};

static const server_platform_permission_vtable mock_permission = {
    SERVER_PLATFORM_PERMISSION_VERSION,
    sizeof(server_platform_permission_vtable),
    mock_permission_start,
    mock_stop,
    mock_permission_query,
    mock_permission_change,
    mock_permission_change,
    &mock_events,
};

/*
 * Reject partial and stale provider tables before backend methods can run, and
 * retain a uniform event-source lookup for every asynchronous provider.
 */
static int test_platform_contract(void)
{
    server_platform platform;
    server_platform_capture_vtable bad_capture = mock_capture;
    server_platform_event_source_vtable bad_events = mock_events;
    void* context = NULL;
    mock_platform_context mock;

    memset(&mock, 0, sizeof(mock));

    server_platform_init(&platform);
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_OK);
    CHECK(!server_platform_provider_ready(&platform,
                                          SERVER_PLATFORM_PROVIDER_CAPTURE));

    platform.capture.vtable = &mock_capture;
    platform.capture.context = &mock;
    platform.pointer.vtable = &mock_pointer;
    platform.pointer.context = &mock;
    platform.input.vtable = &mock_input;
    platform.input.context = &mock;
    platform.clipboard.vtable = &mock_clipboard;
    platform.clipboard.context = &mock;
    platform.drive.vtable = &mock_drive;
    platform.drive.context = &mock;
    platform.permission.vtable = &mock_permission;
    platform.permission.context = &mock;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_OK);
    CHECK(server_platform_provider_ready(&platform,
                                         SERVER_PLATFORM_PROVIDER_CAPTURE));
    CHECK(server_platform_provider_ready(&platform,
                                         SERVER_PLATFORM_PROVIDER_INPUT));
    CHECK(server_platform_provider_events(&platform,
                                          SERVER_PLATFORM_PROVIDER_CAPTURE,
                                          &context) == &mock_events);
    CHECK(context == &mock);
    context = &mock;
    CHECK(server_platform_provider_events(&platform,
                                          SERVER_PLATFORM_PROVIDER_INPUT,
                                          &context) == NULL);
    CHECK(context == NULL);

    bad_capture.version = SERVER_PLATFORM_CAPTURE_VERSION + 1u;
    platform.capture.vtable = &bad_capture;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_INVALID_ARGUMENT);
    platform.capture.vtable = &mock_capture;

    bad_events.dispatch = NULL;
    bad_capture = mock_capture;
    bad_capture.events = &bad_events;
    platform.capture.vtable = &bad_capture;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_INVALID_ARGUMENT);
    platform.capture.vtable = NULL;
    platform.capture.context = &mock;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(server_platform_validate(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    return 0;
}

static int connect_loopback(uint16_t port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd,
                (const struct sockaddr*)&address,
                (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static void configure_mock_platform(server_host_config* config,
                                    mock_platform_context* mock)
{
    size_t index = 0;

    memset(mock, 0, sizeof(*mock));
    for (index = 0; index < 4u; index++)
        mock->permissions[index] = SERVER_PLATFORM_PERMISSION_GRANTED;
    config->platform.capture.vtable = &mock_capture;
    config->platform.capture.context = mock;
    config->platform.pointer.vtable = &mock_pointer;
    config->platform.pointer.context = mock;
    config->platform.input.vtable = &mock_input;
    config->platform.input.context = mock;
    config->platform.clipboard.vtable = &mock_clipboard;
    config->platform.clipboard.context = mock;
    config->platform.drive.vtable = &mock_drive;
    config->platform.drive.context = mock;
    config->platform.permission.vtable = &mock_permission;
    config->platform.permission.context = mock;
}

/*
 * Own listener and peer slots through start, bounded accept, slot reuse,
 * capture resize and deterministic stop while all native providers remain
 * represented only by opaque mock contexts.
 */
static int test_host_lifecycle(void)
{
    server_host_config config;
    server_host_peer_info first;
    server_host_peer_info reused;
    server_host* host = NULL;
    mock_platform_context mock;
    server_platform_frame frame;
    uint8_t pixels[4u * 3u * 4u];
    uint16_t port = 0;
    uint32_t first_id = 0;
    int clients[3] = {-1, -1, -1};

    server_host_config_init(&config);
    config.max_peers = 2u;
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_get_state(host) == SERVER_HOST_NEW);
    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_get_state(host) == SERVER_HOST_LISTENING);
    CHECK(server_host_get_provider_state(
              host,
              SERVER_PLATFORM_PROVIDER_CAPTURE) == SERVER_HOST_PROVIDER_READY);
    CHECK(server_host_start(host) == LIBRDP_STATUS_STATE);
    port = server_host_local_port(host);
    CHECK(port != 0u);

    clients[0] = connect_loopback(port);
    CHECK(clients[0] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    clients[1] = connect_loopback(port);
    CHECK(clients[1] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_peer_count(host) == 2u);
    CHECK(mock.frame_requests == 2u);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    server_host_peer_info_init(&first);
    CHECK(server_host_peer_at(host, 0u, &first) == LIBRDP_STATUS_OK);
    first_id = first.id;
    CHECK(first.generation == 1u);
    CHECK(first.state == SERVER_HOST_PEER_ACCEPTED);
    CHECK(server_host_close_peer(host, first_id) == LIBRDP_STATUS_OK);
    CHECK(server_host_peer_count(host) == 1u);

    clients[2] = connect_loopback(port);
    CHECK(clients[2] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&reused);
    CHECK(server_host_peer_at(host, 0u, &reused) == LIBRDP_STATUS_OK);
    CHECK(reused.id != first_id);
    CHECK(reused.generation == 2u);

    memset(&frame, 0, sizeof(frame));
    memset(pixels, 0x5a, sizeof(pixels));
    frame.width = 4u;
    frame.height = 3u;
    frame.stride = 16u;
    frame.pixels = pixels;
    frame.pixels_len = sizeof(pixels);
    frame.sequence = 1u;
    frame.timestamp_ns = 1000u;
    CHECK(mock.capture_sink.frame != NULL);
    mock.capture_sink.frame(&frame, mock.capture_sink.user_data);
    server_host_peer_info_init(&reused);
    CHECK(server_host_peer_at(host, 0u, &reused) == LIBRDP_STATUS_OK);
    CHECK(reused.desktop_width == 4u && reused.desktop_height == 3u);

    CHECK(server_host_stop(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_stop(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_get_state(host) == SERVER_HOST_STOPPED);
    CHECK(server_host_peer_count(host) == 0u);
    CHECK(mock.releases == 1u);
    CHECK(mock.stops == 5u);
    server_host_free(host);
    close(clients[0]);
    close(clients[1]);
    close(clients[2]);

    server_host_config_init(&config);
    configure_mock_platform(&config, &mock);
    mock.permissions[SERVER_PLATFORM_PERMISSION_CAPTURE - 1u] =
        SERVER_PLATFORM_PERMISSION_DENIED;
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_start(host) == LIBRDP_STATUS_STATE);
    CHECK(server_host_get_state(host) == SERVER_HOST_FAILED);
    CHECK(mock.stops == 1u);
    server_host_free(host);
    return 0;
}

/*
 * Exercise coalescing, hard queue bounds, pacing, backpressure and resize
 * invalidation so a stalled peer cannot retain capture-owned frame storage or
 * grow dirty-region memory.
 */
static int test_dirty_scheduler(void)
{
    server_dirty_config config;
    server_dirty_metrics metrics;
    server_dirty_scheduler* scheduler = NULL;
    const server_platform_rect* ready = NULL;
    server_platform_rect rect = {10u, 10u, 20u, 20u};
    server_platform_rect adjacent = {30u, 10u, 5u, 20u};
    server_platform_rect separate = {80u, 80u, 10u, 10u};
    server_platform_rect overflow = {99u, 99u, 2u, 2u};
    size_t count = 0;
    int timeout_ms = -1;

    server_dirty_config_init(&config);
    config.max_regions = 2u;
    config.max_regions_per_frame = 1u;
    config.frame_interval_ns = 10000000u;
    scheduler = server_dirty_scheduler_new(&config);
    CHECK(scheduler != NULL);
    CHECK(server_dirty_scheduler_resize(scheduler, 100u, 100u, 100u, 0) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_invalidate(scheduler, &rect, 100u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_invalidate(scheduler, &adjacent, 100u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_peek(scheduler, 100u, &ready, &count,
                                      &timeout_ms) == LIBRDP_STATUS_OK);
    CHECK(ready != NULL);
    CHECK(count == 1u);
    CHECK(ready[0].x == 10u && ready[0].y == 10u);
    CHECK(ready[0].width == 25u && ready[0].height == 20u);
    CHECK(server_dirty_scheduler_invalidate(scheduler, &separate, 100u) ==
          LIBRDP_STATUS_OK);
    rect.x = 50u;
    rect.y = 50u;
    rect.width = 5u;
    rect.height = 5u;
    CHECK(server_dirty_scheduler_invalidate(scheduler, &rect, 100u) ==
          LIBRDP_STATUS_OK);
    server_dirty_metrics_init(&metrics);
    CHECK(server_dirty_scheduler_get_metrics(scheduler, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.pending_regions == 1u);
    CHECK(metrics.merged_regions == 1u);
    CHECK(metrics.queue_collapses == 1u);
    CHECK(server_dirty_scheduler_commit(scheduler, 1u, 100u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_invalidate(scheduler, &separate, 101u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_peek(scheduler, 101u, &ready, &count,
                                      &timeout_ms) == LIBRDP_STATUS_AGAIN);
    CHECK(ready == NULL && count == 0u && timeout_ms == 10);
    CHECK(server_dirty_scheduler_peek(scheduler, 10000100u, &ready, &count,
                                      &timeout_ms) == LIBRDP_STATUS_OK);
    CHECK(count == 1u && timeout_ms == 0);
    CHECK(server_dirty_scheduler_defer(scheduler, 10000100u) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_peek(scheduler, 10000100u, &ready, &count,
                                      &timeout_ms) == LIBRDP_STATUS_AGAIN);
    CHECK(timeout_ms == 10);
    CHECK(server_dirty_scheduler_resize(scheduler, 64u, 48u, 20000000u, 1) ==
          LIBRDP_STATUS_OK);
    CHECK(server_dirty_scheduler_peek(scheduler, 20000000u, &ready, &count,
                                      &timeout_ms) == LIBRDP_STATUS_OK);
    CHECK(count == 1u);
    CHECK(ready[0].x == 0u && ready[0].y == 0u);
    CHECK(ready[0].width == 64u && ready[0].height == 48u);
    CHECK(server_dirty_scheduler_invalidate(scheduler, &overflow, 20000000u) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    server_dirty_metrics_init(&metrics);
    CHECK(server_dirty_scheduler_get_metrics(scheduler, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.deferred_frames == 1u);
    CHECK(metrics.presented_regions == 1u);
    CHECK(metrics.surface_resizes == 2u);
    server_dirty_scheduler_free(scheduler);

    config.max_regions = 0u;
    CHECK(server_dirty_scheduler_new(&config) == NULL);
    server_dirty_config_init(&config);
    config.max_regions = SERVER_DIRTY_MAX_REGIONS + 1u;
    CHECK(server_dirty_scheduler_new(&config) == NULL);
    return 0;
}

int main(void)
{
    if (test_platform_contract() != 0)
        return 1;
    if (test_dirty_scheduler() != 0)
        return 1;
    if (test_host_lifecycle() != 0)
        return 1;
    puts("app server tests passed");
    return 0;
}
