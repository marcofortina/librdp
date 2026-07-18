/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: sanitized desktop-server host trace and metrics support.
 * Invariants: event names come from a fixed table, sequence values increase
 * monotonically, and trace payloads contain no user-controlled strings.
 * Ownership: events are stack-owned for the synchronous callback duration;
 * metrics snapshots are copied into caller-owned storage.
 * Threading: emission and metric queries run on the serialized host thread.
 * Trust boundary: protocol and platform payload bytes are never accepted by
 * this module, preventing accidental content disclosure through the sink.
 */

#include "server_host_internal.h"

#include <string.h>
#include <time.h>

typedef struct server_host_trace_name_entry
{
    server_host_trace_type type;
    const char* name;
} server_host_trace_name_entry;

static const server_host_trace_name_entry server_host_trace_names[] = {
    {SERVER_HOST_TRACE_LISTENER_START, "server.host.listener.start"},
    {SERVER_HOST_TRACE_LISTENER_READY, "server.host.listener.ready"},
    {SERVER_HOST_TRACE_LISTENER_FAILED, "server.host.listener.failed"},
    {SERVER_HOST_TRACE_LISTENER_STOP, "server.host.listener.stop"},
    {SERVER_HOST_TRACE_PEER_ACCEPTED, "server.host.peer.accepted"},
    {SERVER_HOST_TRACE_PEER_STATE, "server.host.peer.state"},
    {SERVER_HOST_TRACE_PEER_CLEANUP, "server.host.peer.cleanup"},
    {SERVER_HOST_TRACE_CAPTURE_FRAME, "server.host.capture.frame"},
    {SERVER_HOST_TRACE_CAPTURE_DROPPED, "server.host.capture.dropped"},
    {SERVER_HOST_TRACE_CAPTURE_LOST, "server.host.capture.lost"},
    {SERVER_HOST_TRACE_FRAME_PRESENTED, "server.host.frame.presented"},
    {SERVER_HOST_TRACE_FRAME_DEFERRED, "server.host.frame.deferred"},
    {SERVER_HOST_TRACE_INPUT_ACCEPTED, "server.host.input.accepted"},
    {SERVER_HOST_TRACE_INPUT_REJECTED, "server.host.input.rejected"},
    {SERVER_HOST_TRACE_CLIPBOARD_EVENT, "server.host.clipboard.event"},
    {SERVER_HOST_TRACE_CLIPBOARD_CLEANUP, "server.host.clipboard.cleanup"},
    {SERVER_HOST_TRACE_DRIVE_REQUEST, "server.host.drive.request"},
    {SERVER_HOST_TRACE_DRIVE_CLEANUP, "server.host.drive.cleanup"},
    {SERVER_HOST_TRACE_PERMISSION_CHANGED, "server.host.permission.changed"},
    {SERVER_HOST_TRACE_QUEUE_PRESSURE, "server.host.queue.pressure"},
    {SERVER_HOST_TRACE_WAKEUP, "server.host.wakeup"},
    {SERVER_HOST_TRACE_SHUTDOWN_START, "server.host.shutdown.start"},
    {SERVER_HOST_TRACE_SHUTDOWN_DONE, "server.host.shutdown.done"},
};

uint64_t server_host_now_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return (uint64_t)value.tv_sec * 1000000000u +
           (uint64_t)value.tv_nsec;
}

void server_host_metric_add(uint64_t* counter, uint64_t amount)
{
    if (!counter)
        return;
    if (amount > UINT64_MAX - *counter)
        *counter = UINT64_MAX;
    else
        *counter += amount;
}

const char* server_host_trace_name(server_host_trace_type type)
{
    size_t index = 0;

    for (index = 0;
         index < sizeof(server_host_trace_names) /
                     sizeof(server_host_trace_names[0]);
         index++)
    {
        if (server_host_trace_names[index].type == type)
            return server_host_trace_names[index].name;
    }
    return "server.host.unknown";
}

void server_host_metrics_init(server_host_metrics* metrics)
{
    if (!metrics)
        return;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = SERVER_HOST_METRICS_VERSION;
    metrics->size = sizeof(*metrics);
}

/*
 * Emit only fixed-schema numeric metadata. The callback is synchronous and
 * cannot retain the stack event pointer beyond this call.
 */
void server_host_trace_emit(server_host* host,
                            server_host_trace_type type,
                            const server_host_peer_slot* peer,
                            librdp_status status,
                            uint64_t value,
                            uint64_t count)
{
    server_host_trace_event event;

    if (!host || !host->trace_callback)
        return;
    memset(&event, 0, sizeof(event));
    event.version = SERVER_HOST_TRACE_EVENT_VERSION;
    event.size = sizeof(event);
    host->trace_sequence++;
    if (host->trace_sequence == 0u)
        host->trace_sequence = 1u;
    event.sequence = host->trace_sequence;
    event.timestamp_ns = server_host_now_ns();
    event.type = type;
    event.name = server_host_trace_name(type);
    event.host_state = host->state;
    if (peer)
    {
        event.peer_id = peer->id;
        event.generation = peer->generation;
    }
    event.status = status;
    event.value = value;
    event.count = count;
    host->trace_callback(&event, host->trace_user_data);
}

librdp_status server_host_get_metrics(const server_host* host,
                                      server_host_metrics* metrics)
{
    if (!host || !metrics ||
        metrics->version != SERVER_HOST_METRICS_VERSION ||
        metrics->size < sizeof(*metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *metrics = host->metrics;
    return LIBRDP_STATUS_OK;
}

librdp_status server_host_reset_metrics(server_host* host)
{
    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    server_host_metrics_init(&host->metrics);
    return LIBRDP_STATUS_OK;
}
