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
#include "server_platform.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <string.h>

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
    (void)context;
    return sink && sink->frame && sink->lost
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void mock_stop(void* context)
{
    (void)context;
}

static librdp_status mock_pointer_start(void* context,
                                        const server_platform_pointer_sink* sink)
{
    (void)context;
    return sink && sink->update ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_inject(void* context,
                                 const librdp_server_input_event* event)
{
    (void)context;
    return event ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static void mock_release_all(void* context)
{
    (void)context;
}

static librdp_status mock_clipboard_start(
    void* context,
    const server_platform_clipboard_sink* sink)
{
    (void)context;
    return sink && sink->formats && sink->data
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
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
    (void)context;
    return sink && sink->request ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
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
    (void)context;
    return sink && sink->changed ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status mock_permission_query(
    void* context,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    (void)context;
    if (!state || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = SERVER_PLATFORM_PERMISSION_GRANTED;
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
    int marker = 7;

    server_platform_init(&platform);
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_OK);
    CHECK(!server_platform_provider_ready(&platform,
                                          SERVER_PLATFORM_PROVIDER_CAPTURE));

    platform.capture.vtable = &mock_capture;
    platform.capture.context = &marker;
    platform.pointer.vtable = &mock_pointer;
    platform.pointer.context = &marker;
    platform.input.vtable = &mock_input;
    platform.input.context = &marker;
    platform.clipboard.vtable = &mock_clipboard;
    platform.clipboard.context = &marker;
    platform.drive.vtable = &mock_drive;
    platform.drive.context = &marker;
    platform.permission.vtable = &mock_permission;
    platform.permission.context = &marker;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_OK);
    CHECK(server_platform_provider_ready(&platform,
                                         SERVER_PLATFORM_PROVIDER_CAPTURE));
    CHECK(server_platform_provider_ready(&platform,
                                         SERVER_PLATFORM_PROVIDER_INPUT));
    CHECK(server_platform_provider_events(&platform,
                                          SERVER_PLATFORM_PROVIDER_CAPTURE,
                                          &context) == &mock_events);
    CHECK(context == &marker);
    context = &marker;
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
    platform.capture.context = &marker;
    CHECK(server_platform_validate(&platform) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(server_platform_validate(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
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
    puts("app server tests passed");
    return 0;
}
