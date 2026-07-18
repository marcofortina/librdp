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
#include "server_clipboard.h"
#include "server_host_internal.h"
#include "server_platform.h"

#include <librdp/librdp.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
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
    unsigned int injections;
    unsigned int dispatches;
    unsigned int clipboard_cancels;
    unsigned int clipboard_releases;
    unsigned int drive_peer_removals;
    unsigned int drive_completions;
    uint32_t last_cleanup_peer_id;
    uint32_t last_clipboard_generation;
    uint32_t last_drive_generation;
    uint64_t last_clipboard_request_id;
    uint64_t last_clipboard_ownership_generation;
    uint64_t last_drive_request_id;
    uint32_t last_clipboard_format_id;
    uint32_t last_clipboard_stream_id;
    uint32_t published_format_ids[8];
    size_t published_format_count;
    size_t clipboard_written_bytes;
    librdp_status clipboard_written_status;
    uint8_t clipboard_written_data[64];
    server_platform_clipboard_file_request last_file_request;
    int event_read_fd;
    int event_write_fd;
    short event_revents;
    int timeout_ms;
} mock_platform_context;

typedef struct mock_clipboard_protocol
{
    unsigned int monitor_ready;
    unsigned int capabilities;
    unsigned int format_lists;
    unsigned int format_list_responses;
    unsigned int data_requests;
    unsigned int data_responses;
    unsigned int file_requests;
    unsigned int file_responses;
    unsigned int cancellations;
    uint16_t channel_id;
    uint32_t capability_flags;
    uint32_t format_ids[8];
    uint32_t format_count;
    uint32_t requested_format_id;
    uint32_t stream_id;
    int response_ok;
    size_t response_len;
    uint8_t response_data[64];
} mock_clipboard_protocol;

#define MOCK_TRACE_CAPACITY 128u

typedef struct mock_trace_context
{
    server_host_trace_event events[MOCK_TRACE_CAPACITY];
    size_t count;
    size_t dropped;
} mock_trace_context;

static int connect_loopback(uint16_t port);
static void configure_mock_platform(server_host_config* config,
                                    mock_platform_context* mock);

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

static void mock_trace_event(const server_host_trace_event* event,
                             void* user_data)
{
    mock_trace_context* trace = (mock_trace_context*)user_data;

    if (!trace || !event)
        return;
    if (trace->count >= MOCK_TRACE_CAPACITY)
    {
        trace->dropped++;
        return;
    }
    trace->events[trace->count++] = *event;
}

static librdp_status mock_get_pollfds(void* context,
                                      struct pollfd* fds,
                                      size_t capacity,
                                      size_t* count)
{
    mock_platform_context* mock = (mock_platform_context*)context;
    size_t required = mock && mock->event_read_fd >= 0 ? 1u : 0u;

    if (!mock || !count || (capacity > 0u && !fds))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = required;
    if (!fds && capacity == 0u)
        return LIBRDP_STATUS_OK;
    if (capacity < required)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (required > 0u)
    {
        fds[0].fd = mock->event_read_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_notify_poll(void* context,
                                     const struct pollfd* fds,
                                     size_t count)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (mock->event_read_fd < 0)
        return count == 0u && !fds ? LIBRDP_STATUS_OK
                                  : LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!fds || count != 1u || fds[0].fd != mock->event_read_fd)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->event_revents = fds[0].revents;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_dispatch(void* context, unsigned int max_events)
{
    mock_platform_context* mock = (mock_platform_context*)context;
    uint8_t byte = 0;
    ssize_t count = 0;

    if (!mock || max_events == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (mock->event_read_fd >= 0 && (mock->event_revents & POLLIN) != 0)
    {
        do
        {
            count = read(mock->event_read_fd, &byte, sizeof(byte));
        } while (count < 0 && errno == EINTR);
        if (count != (ssize_t)sizeof(byte))
            return LIBRDP_STATUS_IO_ERROR;
        mock->event_revents = 0;
    }
    mock->dispatches++;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_get_timeout(void* context, int* timeout_ms)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = mock->timeout_ms;
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
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->injections++;
    return LIBRDP_STATUS_OK;
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

    if (!mock || !sink || !sink->formats || !sink->data ||
        !sink->request || !sink->file_request)
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
    mock_platform_context* mock = (mock_platform_context*)context;
    size_t index = 0;

    if (!mock || (format_count > 0u && !formats) ||
        format_count > sizeof(mock->published_format_ids) /
                           sizeof(mock->published_format_ids[0]))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->published_format_count = format_count;
    mock->last_clipboard_ownership_generation = generation;
    for (index = 0; index < format_count; index++)
        mock->published_format_ids[index] = formats[index].id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_request_data(void* context,
                                       uint64_t request_id,
                                       uint32_t format_id)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || request_id == 0u || format_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->last_clipboard_request_id = request_id;
    mock->last_clipboard_format_id = format_id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_request_file(
    void* context,
    const server_platform_clipboard_file_request* request)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !request || request->request_id == 0u ||
        request->stream_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->last_file_request = *request;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_write_data(void* context,
                                     const server_platform_clipboard_data* data)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !data ||
        data->data_len > sizeof(mock->clipboard_written_data))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->last_clipboard_request_id = data->request_id;
    mock->last_clipboard_format_id = data->format_id;
    mock->last_clipboard_stream_id = data->stream_id;
    mock->last_clipboard_ownership_generation =
        data->ownership_generation;
    mock->clipboard_written_status = data->status;
    mock->clipboard_written_bytes = data->data_len;
    if (data->data_len > 0u)
        memcpy(mock->clipboard_written_data, data->data, data->data_len);
    return LIBRDP_STATUS_OK;
}

static void mock_release_ownership(void* context, uint64_t generation)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock)
        return;
    mock->clipboard_releases++;
    mock->last_clipboard_generation = (uint32_t)generation;
}

static void mock_clipboard_cancel_peer(void* context,
                                       uint32_t peer_id,
                                       uint32_t generation)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock)
        return;
    mock->clipboard_cancels++;
    mock->last_cleanup_peer_id = peer_id;
    mock->last_clipboard_generation = generation;
}

static librdp_status mock_drive_start(void* context,
                                      const server_platform_drive_sink* sink)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !sink || !sink->request || !sink->cancel)
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
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock)
        return;
    mock->drive_peer_removals++;
    mock->last_cleanup_peer_id = peer_id;
    mock->last_drive_generation = generation;
}

static librdp_status mock_drive_complete(
    void* context,
    const server_platform_drive_completion* completion)
{
    mock_platform_context* mock = (mock_platform_context*)context;

    if (!mock || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mock->drive_completions++;
    mock->last_drive_request_id = completion->request_id;
    return LIBRDP_STATUS_OK;
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

static librdp_status mock_clipboard_send_monitor_ready(void* context,
                                                       uint16_t channel_id)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->monitor_ready++;
    protocol->channel_id = channel_id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_capabilities(void* context,
                                                      uint16_t channel_id,
                                                      uint32_t flags)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->capabilities++;
    protocol->channel_id = channel_id;
    protocol->capability_flags = flags;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_format_list(
    void* context,
    uint16_t channel_id,
    const librdp_server_clipboard_format* formats,
    uint32_t format_count,
    int long_names)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;
    uint32_t index = 0;

    if (!protocol || channel_id == 0u ||
        (format_count > 0u && !formats) || !long_names ||
        format_count > sizeof(protocol->format_ids) /
                           sizeof(protocol->format_ids[0]))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->format_lists++;
    protocol->channel_id = channel_id;
    protocol->format_count = format_count;
    for (index = 0; index < format_count; index++)
        protocol->format_ids[index] = formats[index].format_id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_format_list_response(
    void* context,
    uint16_t channel_id,
    int ok)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->format_list_responses++;
    protocol->response_ok = ok;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_data_request(void* context,
                                                      uint16_t channel_id,
                                                      uint32_t format_id)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u || format_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->data_requests++;
    protocol->requested_format_id = format_id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_save_response(
    mock_clipboard_protocol* protocol,
    int ok,
    uint32_t stream_id,
    const void* data,
    size_t data_len)
{
    if (!protocol || (!data && data_len > 0u) ||
        data_len > sizeof(protocol->response_data))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->response_ok = ok;
    protocol->stream_id = stream_id;
    protocol->response_len = data_len;
    if (data_len > 0u)
        memcpy(protocol->response_data, data, data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_data_response(void* context,
                                                       uint16_t channel_id,
                                                       int ok,
                                                       const void* data,
                                                       size_t data_len)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->data_responses++;
    return mock_clipboard_save_response(protocol, ok, 0u, data, data_len);
}

static librdp_status mock_clipboard_send_file_request(
    void* context,
    uint16_t channel_id,
    uint32_t stream_id,
    int32_t file_index,
    uint32_t flags,
    uint64_t position,
    uint32_t requested_bytes,
    const uint32_t* clip_data_id)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    (void)file_index;
    (void)flags;
    (void)position;
    (void)requested_bytes;
    (void)clip_data_id;
    if (!protocol || channel_id == 0u || stream_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->file_requests++;
    protocol->stream_id = stream_id;
    return LIBRDP_STATUS_OK;
}

static librdp_status mock_clipboard_send_file_response(void* context,
                                                       uint16_t channel_id,
                                                       int ok,
                                                       uint32_t stream_id,
                                                       const void* data,
                                                       size_t data_len)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol || channel_id == 0u || stream_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->file_responses++;
    return mock_clipboard_save_response(protocol,
                                        ok,
                                        stream_id,
                                        data,
                                        data_len);
}

static librdp_status mock_clipboard_cancel_requests(void* context)
{
    mock_clipboard_protocol* protocol = (mock_clipboard_protocol*)context;

    if (!protocol)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    protocol->cancellations++;
    return LIBRDP_STATUS_OK;
}

static const server_clipboard_protocol_vtable mock_clipboard_protocol_vtable = {
    mock_clipboard_send_monitor_ready,
    mock_clipboard_send_capabilities,
    mock_clipboard_send_format_list,
    mock_clipboard_send_format_list_response,
    mock_clipboard_send_data_request,
    mock_clipboard_send_data_response,
    mock_clipboard_send_file_request,
    mock_clipboard_send_file_response,
    mock_clipboard_cancel_requests,
};

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
    mock_request_file,
    mock_write_data,
    mock_clipboard_cancel_peer,
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
    mock_drive_complete,
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
    mock.event_read_fd = -1;
    mock.event_write_fd = -1;
    mock.timeout_ms = -1;

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

/*
 * Exercise the common clipboard state machine without a window system or wire
 * socket. The sequence covers both ownership directions, platform chunking,
 * file ranges, loop suppression, stale generations, limits and one terminal
 * response per correlated request.
 */
static int test_clipboard_runtime(void)
{
    static const char html_name[] = LIBRDP_CLIPBOARD_FORMAT_NAME_HTML;
    static const char png_name[] = LIBRDP_CLIPBOARD_FORMAT_NAME_PNG;
    static const char file_name[] =
        LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW;
    static const uint8_t remote_data[] = {'h', 't', 'm', 'l'};
    static const uint8_t first_chunk[] = {'a', 'b'};
    static const uint8_t second_chunk[] = {'c', 'd'};
    static const uint8_t file_data[] = {'f', 'i', 'l', 'e'};
    static const uint8_t remote_file_data[] = {'x', 'y'};
    server_clipboard_config config;
    server_clipboard_runtime* runtime = NULL;
    server_platform_clipboard_format local_formats[4];
    librdp_server_clipboard_format remote_formats[4];
    librdp_server_clipboard_event event;
    server_platform_clipboard_request request;
    server_platform_clipboard_file_request file_request;
    server_platform_clipboard_data data;
    mock_platform_context platform;
    mock_clipboard_protocol protocol;
    uint64_t ownership_generation = 0u;
    uint64_t local_request_id = 0u;
    unsigned int format_lists = 0u;

    memset(&platform, 0, sizeof(platform));
    memset(&protocol, 0, sizeof(protocol));
    server_clipboard_config_init(&config);
    config.max_peers = 2u;
    config.max_formats = 4u;
    config.max_pending_requests = 8u;
    config.max_data_bytes = 8u;
    config.max_file_range_bytes = 8u;
    CHECK(server_clipboard_config_validate(&config) == LIBRDP_STATUS_OK);
    config.max_formats = 0u;
    CHECK(server_clipboard_config_validate(&config) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    config.max_formats = 4u;
    runtime = server_clipboard_runtime_new(&config,
                                           &mock_clipboard,
                                           &platform);
    CHECK(runtime != NULL);
    CHECK(server_clipboard_runtime_add_peer(
              runtime,
              7u,
              1u,
              &mock_clipboard_protocol_vtable,
              &protocol) == LIBRDP_STATUS_OK);
    CHECK(server_clipboard_runtime_add_peer(
              runtime,
              7u,
              1u,
              &mock_clipboard_protocol_vtable,
              &protocol) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(server_clipboard_runtime_channel_ready(runtime, 7u, 1u, 1005u) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.monitor_ready == 1u);
    CHECK(protocol.capabilities == 1u);
    CHECK((protocol.capability_flags &
           LIBRDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED) != 0u);
    CHECK(protocol.format_lists == 1u && protocol.format_count == 0u);

    memset(local_formats, 0, sizeof(local_formats));
    local_formats[0].mime_type = "text/plain;charset=utf-8";
    local_formats[1].mime_type = "text/html";
    local_formats[2].mime_type = "image/png";
    local_formats[3].mime_type = "text/uri-list";
    CHECK(server_clipboard_runtime_platform_formats(runtime,
                                                    local_formats,
                                                    4u,
                                                    10u) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.format_lists == 2u && protocol.format_count == 4u);
    CHECK(protocol.format_ids[0] == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
    CHECK(protocol.format_ids[1] == LIBRDP_CLIPBOARD_FORMAT_HTML);
    CHECK(protocol.format_ids[2] == LIBRDP_CLIPBOARD_FORMAT_PNG);
    CHECK(protocol.format_ids[3] ==
          LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW);
    memset(&request, 0, sizeof(request));
    request.peer_id = 7u;
    request.generation = 1u;
    request.request_id = 40u;
    request.format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    CHECK(server_clipboard_runtime_platform_request(runtime, &request) ==
          LIBRDP_STATUS_STATE);

    memset(remote_formats, 0, sizeof(remote_formats));
    remote_formats[0].format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    remote_formats[1].format_id = 0xd001u;
    remote_formats[1].name = html_name;
    remote_formats[1].name_len = strlen(html_name);
    remote_formats[2].format_id = 0xd002u;
    remote_formats[2].name = png_name;
    remote_formats[2].name_len = strlen(png_name);
    remote_formats[3].format_id = 0xd003u;
    remote_formats[3].name = file_name;
    remote_formats[3].name_len = strlen(file_name);
    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST;
    event.channel_id = 1005u;
    event.formats = remote_formats;
    event.format_count = 4u;
    event.long_format_names = 0u;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.format_list_responses == 1u && protocol.response_ok);
    CHECK(platform.published_format_count == 4u);
    ownership_generation = platform.last_clipboard_ownership_generation;
    CHECK(ownership_generation != 0u);
    format_lists = protocol.format_lists;
    CHECK(server_clipboard_runtime_platform_formats(runtime,
                                                    local_formats,
                                                    4u,
                                                    ownership_generation) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.format_lists == format_lists);

    memset(&request, 0, sizeof(request));
    request.peer_id = 7u;
    request.generation = 1u;
    request.ownership_generation = ownership_generation;
    request.request_id = 41u;
    request.format_id = 0xd001u;
    CHECK(server_clipboard_runtime_platform_request(runtime, &request) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.data_requests == 1u);
    CHECK(protocol.requested_format_id == request.format_id);
    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE;
    event.channel_id = 1005u;
    event.success = 1u;
    event.data = remote_data;
    event.data_len = sizeof(remote_data);
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    CHECK(platform.last_clipboard_request_id == request.request_id);
    CHECK(platform.clipboard_written_status == LIBRDP_STATUS_OK);
    CHECK(platform.clipboard_written_bytes == sizeof(remote_data));
    CHECK(memcmp(platform.clipboard_written_data,
                 remote_data,
                 sizeof(remote_data)) == 0);
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    request.request_id = 42u;
    CHECK(server_clipboard_runtime_platform_request(runtime, &request) ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_CANCELLED;
    event.related_type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE;
    event.channel_id = 1005u;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_CANCELLED);

    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST;
    event.channel_id = 1005u;
    event.format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    local_request_id = platform.last_clipboard_request_id;
    CHECK(local_request_id != 0u);
    memset(&data, 0, sizeof(data));
    data.peer_id = 7u;
    data.generation = 1u;
    data.request_id = local_request_id;
    data.format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    data.status = LIBRDP_STATUS_OK;
    data.data = first_chunk;
    data.data_len = sizeof(first_chunk);
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.data_responses == 0u);
    data.data = second_chunk;
    data.data_len = sizeof(second_chunk);
    data.final_chunk = 1;
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.data_responses == 1u && protocol.response_ok);
    CHECK(protocol.response_len == 4u);
    CHECK(memcmp(protocol.response_data, "abcd", 4u) == 0);
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_STATE);

    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST;
    event.channel_id = 1005u;
    event.format_id = LIBRDP_CLIPBOARD_FORMAT_HTML;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    memset(&data, 0, sizeof(data));
    data.peer_id = 7u;
    data.generation = 1u;
    data.request_id = platform.last_clipboard_request_id;
    data.format_id = LIBRDP_CLIPBOARD_FORMAT_HTML;
    data.status = LIBRDP_STATUS_OK;
    data.final_chunk = 1;
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.data_responses == 2u && protocol.response_ok);
    CHECK(protocol.response_len == 0u);

    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST;
    event.channel_id = 1005u;
    event.format_id = LIBRDP_CLIPBOARD_FORMAT_PNG;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    memset(&data, 0, sizeof(data));
    data.peer_id = 7u;
    data.generation = 1u;
    data.request_id = platform.last_clipboard_request_id;
    data.format_id = LIBRDP_CLIPBOARD_FORMAT_PNG;
    data.status = LIBRDP_STATUS_OK;
    data.data = (const uint8_t*)"123456789";
    data.data_len = 9u;
    data.final_chunk = 1;
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_LIMIT_EXCEEDED);
    CHECK(protocol.data_responses == 3u && !protocol.response_ok);

    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST;
    event.channel_id = 1005u;
    event.stream_id = 31u;
    event.file_index = 2;
    event.file_flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    event.position = 4u;
    event.requested_bytes = 4u;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    CHECK(platform.last_file_request.stream_id == event.stream_id);
    memset(&data, 0, sizeof(data));
    data.peer_id = 7u;
    data.generation = 1u;
    data.request_id = platform.last_file_request.request_id;
    data.stream_id = event.stream_id;
    data.status = LIBRDP_STATUS_OK;
    data.data = file_data;
    data.data_len = sizeof(file_data);
    data.final_chunk = 1;
    CHECK(server_clipboard_runtime_platform_data(runtime, &data) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.file_responses == 1u && protocol.response_ok);
    CHECK(protocol.stream_id == event.stream_id);
    CHECK(protocol.response_len == sizeof(file_data));

    memset(&file_request, 0, sizeof(file_request));
    file_request.peer_id = 7u;
    file_request.generation = 1u;
    file_request.ownership_generation = ownership_generation;
    file_request.request_id = 73u;
    file_request.stream_id = 43u;
    file_request.file_index = 1;
    file_request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    file_request.position = 9u;
    file_request.requested_bytes = 2u;
    CHECK(server_clipboard_runtime_platform_file_request(runtime,
                                                         &file_request) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.file_requests == 1u);
    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE;
    event.channel_id = 1005u;
    event.stream_id = file_request.stream_id;
    event.success = 1u;
    event.data = remote_file_data;
    event.data_len = sizeof(remote_file_data);
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    CHECK(platform.last_clipboard_request_id == file_request.request_id);
    CHECK(platform.last_clipboard_stream_id == file_request.stream_id);
    CHECK(platform.clipboard_written_bytes == sizeof(remote_file_data));

    CHECK(librdp_server_clipboard_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST;
    event.channel_id = 1005u;
    event.stream_id = 55u;
    event.requested_bytes = 9u;
    CHECK(server_clipboard_runtime_protocol_event(runtime,
                                                  7u,
                                                  1u,
                                                  &event) ==
          LIBRDP_STATUS_OK);
    CHECK(protocol.file_responses == 2u && !protocol.response_ok);

    server_clipboard_runtime_remove_peer(runtime, 7u, 1u);
    CHECK(protocol.cancellations == 1u);
    CHECK(platform.clipboard_cancels == 1u);
    request.generation = 1u;
    CHECK(server_clipboard_runtime_platform_request(runtime, &request) ==
          LIBRDP_STATUS_STATE);
    CHECK(server_clipboard_runtime_add_peer(
              runtime,
              7u,
              2u,
              &mock_clipboard_protocol_vtable,
              &protocol) == LIBRDP_STATUS_OK);
    CHECK(server_clipboard_runtime_channel_ready(runtime, 7u, 2u, 1006u) ==
          LIBRDP_STATUS_OK);
    server_clipboard_runtime_revoke(runtime);
    request.generation = 2u;
    CHECK(server_clipboard_runtime_platform_request(runtime, &request) ==
          LIBRDP_STATUS_STATE);
    server_clipboard_runtime_free(runtime);
    CHECK(protocol.cancellations == 3u);
    return 0;
}

/*
 * Close and reuse one slot while asserting that every peer-scoped platform
 * resource is revoked with the old generation before the replacement peer is
 * accepted and requests a fresh capture frame.
 */
static int test_host_reconnect_cleanup(void)
{
    server_host_config config;
    server_host_peer_info first;
    server_host_peer_info replacement;
    server_host* host = NULL;
    mock_platform_context mock;
    uint32_t first_id = 0;
    int clients[2] = {-1, -1};

    server_host_config_init(&config);
    config.max_peers = 1u;
    config.input_policy = SERVER_HOST_INPUT_EXPLICIT;
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);
    clients[0] = connect_loopback(server_host_local_port(host));
    CHECK(clients[0] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&first);
    CHECK(server_host_peer_at(host, 0u, &first) == LIBRDP_STATUS_OK);
    first_id = first.id;
    CHECK(server_host_set_input_owner(host, first_id) == LIBRDP_STATUS_OK);
    CHECK(server_host_close_peer(host, first_id) == LIBRDP_STATUS_OK);
    CHECK(mock.releases == 1u);
    CHECK(mock.clipboard_cancels == 1u);
    CHECK(mock.clipboard_releases == 0u);
    CHECK(mock.drive_peer_removals == 1u);
    CHECK(mock.last_cleanup_peer_id == first_id);
    CHECK(mock.last_clipboard_generation == 1u);
    CHECK(mock.last_drive_generation == 1u);

    clients[1] = connect_loopback(server_host_local_port(host));
    CHECK(clients[1] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&replacement);
    CHECK(server_host_peer_at(host, 0u, &replacement) == LIBRDP_STATUS_OK);
    CHECK(replacement.id != first_id);
    CHECK(replacement.generation == 2u);
    CHECK(mock.frame_requests == 2u);
    CHECK(server_host_stop(host) == LIBRDP_STATUS_OK);
    CHECK(mock.clipboard_cancels == 2u);
    CHECK(mock.clipboard_releases == 0u);
    CHECK(mock.drive_peer_removals == 2u);
    CHECK(mock.last_clipboard_generation == 2u);
    CHECK(mock.last_drive_generation == 2u);
    CHECK(mock.stops == 5u);
    server_host_free(host);
    close(clients[0]);
    close(clients[1]);
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
    mock->event_read_fd = -1;
    mock->event_write_fd = -1;
    mock->timeout_ms = -1;
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
    config->drive.enabled = 1;
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
    int provider_ready = 0;
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
    CHECK(librdp_server_get_extension_provider_status(
              host->listener,
              LIBRDP_SERVER_EXTENSION_GRAPHICS,
              &provider_ready) == LIBRDP_STATUS_OK);
    CHECK(provider_ready);
    CHECK(librdp_server_get_extension_provider_status(
              host->listener,
              LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR,
              &provider_ready) == LIBRDP_STATUS_OK);
    CHECK(provider_ready);
    CHECK(librdp_server_get_extension_provider_status(
              host->listener,
              LIBRDP_SERVER_EXTENSION_CLIPBOARD,
              &provider_ready) == LIBRDP_STATUS_OK);
    CHECK(provider_ready);
    CHECK(librdp_server_get_extension_provider_status(
              host->listener,
              LIBRDP_SERVER_EXTENSION_FILESYSTEM,
              &provider_ready) == LIBRDP_STATUS_OK);
    CHECK(provider_ready);
    mock.permission_sink.changed(SERVER_PLATFORM_PERMISSION_DRIVE,
                                 SERVER_PLATFORM_PERMISSION_DENIED,
                                 mock.permission_sink.user_data);
    CHECK(librdp_server_get_extension_provider_status(
              host->listener,
              LIBRDP_SERVER_EXTENSION_FILESYSTEM,
              &provider_ready) == LIBRDP_STATUS_OK);
    CHECK(provider_ready);
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
    {
        server_host_peer_slot* first_slot =
            server_host_find_peer_slot(host, first.id);

        CHECK(first_slot != NULL);
        CHECK(librdp_server_peer_get_extension_provider_status(
                  first_slot->protocol,
                  LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                  &provider_ready) == LIBRDP_STATUS_OK);
        CHECK(provider_ready);
        CHECK(librdp_server_peer_get_extension_provider_status(
                  first_slot->protocol,
                  LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                  &provider_ready) == LIBRDP_STATUS_OK);
        CHECK(!provider_ready);
        mock.permission_sink.changed(SERVER_PLATFORM_PERMISSION_DRIVE,
                                     SERVER_PLATFORM_PERMISSION_GRANTED,
                                     mock.permission_sink.user_data);
        CHECK(librdp_server_peer_get_extension_provider_status(
                  first_slot->protocol,
                  LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                  &provider_ready) == LIBRDP_STATUS_OK);
        CHECK(provider_ready);
        CHECK(mock.permission_sink.changed != NULL);
        mock.permission_sink.changed(SERVER_PLATFORM_PERMISSION_CLIPBOARD,
                                     SERVER_PLATFORM_PERMISSION_DENIED,
                                     mock.permission_sink.user_data);
        CHECK(librdp_server_peer_get_extension_provider_status(
                  first_slot->protocol,
                  LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                  &provider_ready) == LIBRDP_STATUS_OK);
        CHECK(!provider_ready);
    }
    CHECK(server_host_close_peer(host, first_id) == LIBRDP_STATUS_OK);
    CHECK(server_host_peer_count(host) == 1u);

    clients[2] = connect_loopback(port);
    CHECK(clients[2] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&reused);
    CHECK(server_host_peer_at(host, 0u, &reused) == LIBRDP_STATUS_OK);
    CHECK(reused.id != first_id);
    CHECK(reused.generation == 2u);
    {
        server_host_peer_slot* reused_slot =
            server_host_find_peer_slot(host, reused.id);

        CHECK(reused_slot != NULL);
        CHECK(librdp_server_peer_get_extension_provider_status(
                  reused_slot->protocol,
                  LIBRDP_SERVER_EXTENSION_CLIPBOARD,
                  &provider_ready) == LIBRDP_STATUS_OK);
        CHECK(!provider_ready);
    }

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
    CHECK(mock.releases == 0u);
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

    server_host_config_init(&config);
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);
    CHECK(mock.capture_sink.lost != NULL);
    mock.capture_sink.lost(LIBRDP_STATUS_IO_ERROR,
                           mock.capture_sink.user_data);
    CHECK(server_host_get_state(host) == SERVER_HOST_FAILED);
    CHECK(server_host_stop(host) == LIBRDP_STATUS_OK);
    CHECK(mock.stops == 5u);
    server_host_free(host);
    return 0;
}

/*
 * Assign and transfer input ownership between isolated peer generations.
 * Non-owner and inactive peers must never reach the native input provider,
 * while ownership loss releases all pressed platform state exactly once.
 */
static int test_host_input_ownership(void)
{
    server_host_config config;
    server_host_peer_info first;
    server_host_peer_info second;
    server_host_peer_slot* first_slot = NULL;
    server_host_peer_slot* second_slot = NULL;
    librdp_server_input_event event;
    server_host* host = NULL;
    mock_platform_context mock;
    int clients[2] = {-1, -1};

    server_host_config_init(&config);
    config.max_peers = 2u;
    config.input_policy = SERVER_HOST_INPUT_EXPLICIT;
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);
    clients[0] = connect_loopback(server_host_local_port(host));
    clients[1] = connect_loopback(server_host_local_port(host));
    CHECK(clients[0] >= 0 && clients[1] >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&first);
    server_host_peer_info_init(&second);
    CHECK(server_host_peer_at(host, 0u, &first) == LIBRDP_STATUS_OK);
    CHECK(server_host_peer_at(host, 1u, &second) == LIBRDP_STATUS_OK);
    first_slot = server_host_find_peer_slot(host, first.id);
    second_slot = server_host_find_peer_slot(host, second.id);
    CHECK(first_slot != NULL && second_slot != NULL);
    CHECK(server_host_set_input_owner(host, first.id) == LIBRDP_STATUS_OK);
    CHECK(server_host_input_owner(host) == first.id);
    first_slot->state = SERVER_HOST_PEER_ACTIVE;
    second_slot->state = SERVER_HOST_PEER_ACTIVE;
    CHECK(librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK);
    event.type = LIBRDP_SERVER_INPUT_SCANCODE_KEY;
    event.param1 = 0x1eu;
    CHECK(server_host_dispatch_peer_input(first_slot, &event) ==
          LIBRDP_STATUS_OK);
    CHECK(mock.injections == 1u);
    CHECK(server_host_dispatch_peer_input(second_slot, &event) ==
          LIBRDP_STATUS_STATE);
    CHECK(server_host_set_input_owner(host, second.id) == LIBRDP_STATUS_OK);
    CHECK(mock.releases == 1u);
    CHECK(server_host_dispatch_peer_input(first_slot, &event) ==
          LIBRDP_STATUS_STATE);
    CHECK(server_host_dispatch_peer_input(second_slot, &event) ==
          LIBRDP_STATUS_OK);
    CHECK(mock.injections == 2u);
    CHECK(server_host_close_peer(host, second.id) == LIBRDP_STATUS_OK);
    CHECK(server_host_input_owner(host) == 0u);
    CHECK(mock.releases == 2u);
    CHECK(server_host_set_input_owner(host, 0u) == LIBRDP_STATUS_OK);
    CHECK(server_host_stop(host) == LIBRDP_STATUS_OK);
    CHECK(mock.releases == 2u);
    server_host_free(host);
    close(clients[0]);
    close(clients[1]);

    server_host_config_init(&config);
    config.input_policy = SERVER_HOST_INPUT_DISABLED;
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_set_input_owner(host, 1u) == LIBRDP_STATUS_STATE);
    server_host_free(host);
    return 0;
}

typedef struct cancel_thread_context
{
    server_host* host;
    librdp_status status;
} cancel_thread_context;

static void* cancel_host_after_delay(void* user_data)
{
    cancel_thread_context* context = (cancel_thread_context*)user_data;
    struct timespec delay;

    delay.tv_sec = 0;
    delay.tv_nsec = 20000000L;
    (void)nanosleep(&delay, NULL);
    context->status = server_host_cancel(context->host);
    return NULL;
}

/*
 * Merge listener, provider and wakeup descriptors into one blocking poll,
 * prove that provider dispatch is not periodic, and wake a blocked owner
 * thread through the only cross-thread host operation.
 */
static int test_host_poll_loop(void)
{
    server_host_config config;
    server_host* host = NULL;
    mock_platform_context mock;
    cancel_thread_context cancel;
    pthread_t thread;
    uint8_t byte = 1u;
    int event_fds[2] = {-1, -1};
    int client = -1;

    server_host_config_init(&config);
    configure_mock_platform(&config, &mock);
    CHECK(pipe(event_fds) == 0);
    CHECK(fcntl(event_fds[0], F_SETFL, O_NONBLOCK) == 0);
    CHECK(fcntl(event_fds[1], F_SETFL, O_NONBLOCK) == 0);
    mock.event_read_fd = event_fds[0];
    mock.event_write_fd = event_fds[1];
    host = server_host_new(&config);
    CHECK(host != NULL);
    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);

    client = connect_loopback(server_host_local_port(host));
    CHECK(client >= 0);
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_OK);
    CHECK(server_host_peer_count(host) == 1u);
    CHECK(mock.dispatches == 0u);

    CHECK(write(mock.event_write_fd, &byte, sizeof(byte)) ==
          (ssize_t)sizeof(byte));
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_OK);
    CHECK(mock.dispatches == 1u);
    CHECK(server_host_run_once(host, 10) == LIBRDP_STATUS_TIMEOUT);
    CHECK(mock.dispatches == 1u);
    CHECK(server_host_wakeup(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_OK);

    memset(&cancel, 0, sizeof(cancel));
    cancel.host = host;
    cancel.status = LIBRDP_STATUS_STATE;
    CHECK(pthread_create(&thread, NULL, cancel_host_after_delay, &cancel) == 0);
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_CANCELLED);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(cancel.status == LIBRDP_STATUS_OK);
    CHECK(server_host_get_state(host) == SERVER_HOST_STOPPED);
    server_host_free(host);
    close(client);
    close(event_fds[0]);
    close(event_fds[1]);
    return 0;
}

/*
 * Verify that host diagnostics expose only fixed-schema metadata while
 * accounting for queue pressure, backend activity and cancellation. Clipboard
 * canaries deliberately cross the platform boundary and must not enter trace.
 */
static int test_host_trace_metrics(void)
{
    static const char canary_name[] = "private-clipboard-format";
    static const uint8_t canary_data[] = "private-clipboard-payload";
    server_host_config config;
    server_host_metrics metrics;
    server_host_peer_info peer;
    server_host_peer_slot* slot = NULL;
    server_platform_clipboard_format format;
    server_platform_clipboard_data data;
    server_platform_drive_request drive_request;
    server_platform_frame frame;
    server_platform_rect rects[3];
    librdp_server_input_event input;
    mock_platform_context mock;
    mock_trace_context trace;
    server_host* host = NULL;
    uint8_t pixels[8u * 8u * 4u];
    int client = -1;
    size_t index = 0;

    memset(&trace, 0, sizeof(trace));
    server_host_config_init(&config);
    config.max_peers = 1u;
    config.input_policy = SERVER_HOST_INPUT_EXPLICIT;
    config.server.width = 8u;
    config.server.height = 8u;
    config.dirty.max_regions = 2u;
    config.dirty.max_regions_per_frame = 1u;
    config.trace_callback = mock_trace_event;
    config.trace_user_data = &trace;
    configure_mock_platform(&config, &mock);
    host = server_host_new(&config);
    CHECK(host != NULL);
    server_host_metrics_init(&metrics);
    CHECK(server_host_get_metrics(host, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.listener_starts == 0u);
    CHECK(server_host_get_metrics(host, NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&metrics, 0, sizeof(metrics));
    CHECK(server_host_get_metrics(host, &metrics) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);

    CHECK(server_host_start(host) == LIBRDP_STATUS_OK);
    client = connect_loopback(server_host_local_port(host));
    CHECK(client >= 0);
    CHECK(server_host_accept_pending(host) == LIBRDP_STATUS_OK);
    server_host_peer_info_init(&peer);
    CHECK(server_host_peer_at(host, 0u, &peer) == LIBRDP_STATUS_OK);
    slot = server_host_find_peer_slot(host, peer.id);
    CHECK(slot != NULL);
    slot->state = SERVER_HOST_PEER_ACTIVE;
    CHECK(server_host_set_input_owner(host, peer.id) == LIBRDP_STATUS_OK);
    CHECK(librdp_server_input_event_init(&input) == LIBRDP_STATUS_OK);
    input.type = LIBRDP_SERVER_INPUT_MOUSE;
    CHECK(server_host_dispatch_peer_input(slot, &input) == LIBRDP_STATUS_OK);
    slot->input_owner = 0;
    CHECK(server_host_dispatch_peer_input(slot, &input) ==
          LIBRDP_STATUS_STATE);
    slot->input_owner = 1;

    memset(&format, 0, sizeof(format));
    format.id = 13u;
    format.mime_type = canary_name;
    mock.clipboard_sink.formats(&format,
                                1u,
                                17u,
                                mock.clipboard_sink.user_data);
    memset(&data, 0, sizeof(data));
    data.request_id = 23u;
    data.format_id = format.id;
    data.data = canary_data;
    data.data_len = sizeof(canary_data);
    mock.clipboard_sink.data(&data, mock.clipboard_sink.user_data);
    memset(&drive_request, 0, sizeof(drive_request));
    drive_request.peer_id = peer.id;
    drive_request.generation = slot->generation;
    drive_request.request_id = 29u;
    mock.drive_sink.request(&drive_request, mock.drive_sink.user_data);
    CHECK(mock.drive_completions == 1u);
    CHECK(mock.last_drive_request_id == 29u);

    rects[0] = (server_platform_rect){0u, 0u, 1u, 1u};
    rects[1] = (server_platform_rect){3u, 3u, 1u, 1u};
    rects[2] = (server_platform_rect){7u, 7u, 1u, 1u};
    memset(pixels, 0x6cu, sizeof(pixels));
    memset(&frame, 0, sizeof(frame));
    frame.width = 8u;
    frame.height = 8u;
    frame.stride = 8u * 4u;
    frame.pixels = pixels;
    frame.pixels_len = sizeof(pixels);
    frame.dirty_rects = rects;
    frame.dirty_count = 3u;
    frame.sequence = 1u;
    frame.timestamp_ns = server_host_now_ns();
    mock.capture_sink.frame(&frame, mock.capture_sink.user_data);
    CHECK(server_host_wakeup(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_OK);

    server_host_metrics_init(&metrics);
    CHECK(server_host_get_metrics(host, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.listener_starts == 1u);
    CHECK(metrics.peers_accepted == 1u);
    CHECK(metrics.capture_frames == 1u);
    CHECK(metrics.dirty_regions == 3u);
    CHECK(metrics.queue_pressure == 1u);
    CHECK(metrics.frames_deferred == 1u);
    CHECK(metrics.input_events == 1u);
    CHECK(metrics.input_rejections == 1u);
    CHECK(metrics.clipboard_events == 2u);
    CHECK(metrics.clipboard_cleanups == 1u);
    CHECK(metrics.drive_requests == 1u);
    CHECK(metrics.drive_cleanups == 1u);
    CHECK(metrics.peers_failed == 1u);
    CHECK(metrics.wakeups == 1u);
    CHECK(metrics.loop_iterations == 1u);

    CHECK(trace.count > 0u);
    CHECK(trace.dropped == 0u);
    for (index = 0; index < trace.count; index++)
    {
        const server_host_trace_event* event = &trace.events[index];

        CHECK(event->version == SERVER_HOST_TRACE_EVENT_VERSION);
        CHECK(event->size == sizeof(*event));
        CHECK(event->name != NULL);
        CHECK(strncmp(event->name, "server.host.", 12u) == 0);
        if (index > 0u)
        {
            CHECK(event->sequence == trace.events[index - 1u].sequence + 1u);
            CHECK(event->timestamp_ns >=
                  trace.events[index - 1u].timestamp_ns);
        }
        CHECK(strstr(event->name, canary_name) == NULL);
        CHECK(strstr(event->name, (const char*)canary_data) == NULL);
    }
    for (index = SERVER_HOST_TRACE_LISTENER_START;
         index <= SERVER_HOST_TRACE_POINTER_FAILED;
         index++)
    {
        CHECK(strcmp(server_host_trace_name((server_host_trace_type)index),
                     "server.host.unknown") != 0);
    }
    CHECK(strcmp(server_host_trace_name((server_host_trace_type)0),
                 "server.host.unknown") == 0);

    CHECK(server_host_reset_metrics(host) == LIBRDP_STATUS_OK);
    server_host_metrics_init(&metrics);
    CHECK(server_host_get_metrics(host, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.listener_starts == 0u);
    CHECK(metrics.capture_frames == 0u);
    CHECK(server_host_cancel(host) == LIBRDP_STATUS_OK);
    CHECK(server_host_run_once(host, 1000) == LIBRDP_STATUS_CANCELLED);
    server_host_metrics_init(&metrics);
    CHECK(server_host_get_metrics(host, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.cancellations == 1u);
    CHECK(metrics.listener_stops == 1u);
    CHECK(metrics.peers_closed == 0u);
    CHECK(metrics.peers_failed == 0u);
    CHECK(server_host_reset_metrics(NULL) ==
          LIBRDP_STATUS_INVALID_ARGUMENT);
    server_host_free(host);
    close(client);
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
    if (test_clipboard_runtime() != 0)
        return 1;
    if (test_dirty_scheduler() != 0)
        return 1;
    if (test_host_lifecycle() != 0)
        return 1;
    if (test_host_poll_loop() != 0)
        return 1;
    if (test_host_trace_metrics() != 0)
        return 1;
    if (test_host_input_ownership() != 0)
        return 1;
    if (test_host_reconnect_cleanup() != 0)
        return 1;
    puts("app server tests passed");
    return 0;
}
