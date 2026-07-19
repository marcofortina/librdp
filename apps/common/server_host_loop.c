/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: poll-driven shared desktop-server dispatch.
 * Invariants: one immutable descriptor snapshot is dispatched per iteration,
 * work is capped by host configuration, and cancellation cleanup runs only on
 * the owner thread.
 * Ownership: merged poll storage belongs to the host; descriptor ownership
 * remains with the listener, peers, providers and wakeup pipe.
 * Threading: run_once and wakeup are owner-thread operations; cancel is safe
 * from another thread and touches only an atomic flag and nonblocking pipe.
 * Trust boundary: provider descriptor counts and timeout values are bounded
 * before allocation or poll.
 */

#include "server_host_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_HOST_MAX_POLL_FDS 512u
#define SERVER_HOST_MAX_POLL_GROUPS \
    (SERVER_HOST_MAX_PEERS + SERVER_PLATFORM_PROVIDER_COUNT + 2u)

typedef enum server_host_poll_kind
{
    SERVER_HOST_POLL_WAKEUP = 1,
    SERVER_HOST_POLL_LISTENER = 2,
    SERVER_HOST_POLL_PEER = 3,
    SERVER_HOST_POLL_PROVIDER = 4
} server_host_poll_kind;

typedef struct server_host_poll_group
{
    server_host_poll_kind kind;
    size_t offset;
    size_t count;
    server_host_peer_slot* peer;
    const server_platform_event_source_vtable* events;
    void* context;
} server_host_poll_group;

typedef struct server_host_platform_source
{
    const server_platform_event_source_vtable* events;
    void* context;
    int timeout_ms;
} server_host_platform_source;

static int server_host_min_timeout(int current, int candidate)
{
    if (candidate < 0)
        return current;
    if (current < 0 || candidate < current)
        return candidate;
    return current;
}

static librdp_status server_host_reserve_pollfds(server_host* host,
                                                 size_t count)
{
    struct pollfd* resized = NULL;

    if (!host || count > SERVER_HOST_MAX_POLL_FDS ||
        count > SIZE_MAX / sizeof(*host->pollfds))
        return count > SERVER_HOST_MAX_POLL_FDS
                   ? LIBRDP_STATUS_LIMIT_EXCEEDED
                   : LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count <= host->poll_capacity)
        return LIBRDP_STATUS_OK;
    resized =
        (struct pollfd*)realloc(host->pollfds, count * sizeof(*host->pollfds));
    if (!resized)
        return LIBRDP_STATUS_NO_MEMORY;
    host->pollfds = resized;
    host->poll_capacity = count;
    return LIBRDP_STATUS_OK;
}

static librdp_status server_host_append_poll_group(
    server_host* host,
    server_host_poll_group* groups,
    size_t* group_count,
    server_host_poll_kind kind,
    server_host_peer_slot* peer,
    const server_platform_event_source_vtable* events,
    void* context,
    size_t descriptor_count,
    size_t* poll_count)
{
    server_host_poll_group* group = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !groups || !group_count || !poll_count ||
        *group_count >= SERVER_HOST_MAX_POLL_GROUPS ||
        descriptor_count > SERVER_HOST_MAX_POLL_FDS - *poll_count)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    status = server_host_reserve_pollfds(host,
                                         *poll_count + descriptor_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    group = &groups[(*group_count)++];
    memset(group, 0, sizeof(*group));
    group->kind = kind;
    group->offset = *poll_count;
    group->count = descriptor_count;
    group->peer = peer;
    group->events = events;
    group->context = context;
    *poll_count += descriptor_count;
    return LIBRDP_STATUS_OK;
}

static size_t server_host_collect_platform_sources(
    server_host* host,
    server_host_platform_source* sources)
{
    size_t count = 0;
    size_t kind_index = 0;

    for (kind_index = 0;
         kind_index < SERVER_PLATFORM_PROVIDER_COUNT;
         kind_index++)
    {
        server_platform_provider_kind kind =
            (server_platform_provider_kind)kind_index;
        const server_platform_event_source_vtable* events = NULL;
        void* context = NULL;
        size_t source_index = 0;

        if (host->provider_states[kind] != SERVER_HOST_PROVIDER_READY)
            continue;
        events = server_platform_provider_events(&host->platform,
                                                 kind,
                                                 &context);
        if (!events)
            continue;
        for (source_index = 0; source_index < count; source_index++)
        {
            if (sources[source_index].events == events &&
                sources[source_index].context == context)
                break;
        }
        if (source_index != count)
            continue;
        sources[count].events = events;
        sources[count].context = context;
        sources[count].timeout_ms = -1;
        count++;
    }
    return count;
}

/*
 * Build a bounded descriptor snapshot and derive one deadline from caller,
 * provider and dirty-frame timeouts. Validation rejects excessive descriptor
 * counts and malformed provider deadlines before poll storage is exposed;
 * each producer retains descriptor ownership and is queried twice only when
 * it actually contributes descriptors.
 */
static librdp_status server_host_prepare_poll(
    server_host* host,
    int requested_timeout_ms,
    server_host_poll_group* groups,
    size_t* group_count,
    server_host_platform_source* sources,
    size_t* source_count,
    size_t* poll_count,
    int* effective_timeout_ms)
{
    size_t descriptor_count = 0;
    size_t peer_index = 0;
    size_t source_index = 0;
    uint64_t now_ns = server_host_now_ns();
    librdp_status status = LIBRDP_STATUS_OK;

    *group_count = 0u;
    *poll_count = 0u;
    *effective_timeout_ms = requested_timeout_ms;
    *source_count = server_host_collect_platform_sources(host, sources);

    status = server_host_append_poll_group(host,
                                           groups,
                                           group_count,
                                           SERVER_HOST_POLL_WAKEUP,
                                           NULL,
                                           NULL,
                                           NULL,
                                           1u,
                                           poll_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    host->pollfds[0].fd = host->wakeup_read_fd;
    host->pollfds[0].events = POLLIN;
    host->pollfds[0].revents = 0;

    status = librdp_server_get_pollfds(host->listener,
                                       NULL,
                                       0u,
                                       &descriptor_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = server_host_append_poll_group(host,
                                           groups,
                                           group_count,
                                           SERVER_HOST_POLL_LISTENER,
                                           NULL,
                                           NULL,
                                           NULL,
                                           descriptor_count,
                                           poll_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_server_get_pollfds(
        host->listener,
        host->pollfds + groups[*group_count - 1u].offset,
        descriptor_count,
        &descriptor_count);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (peer_index = 0; peer_index < host->peer_capacity; peer_index++)
    {
        server_host_peer_slot* slot = &host->peers[peer_index];
        server_host_poll_group* group = NULL;

        if (!slot->occupied || !slot->protocol ||
            slot->state == SERVER_HOST_PEER_CLOSED ||
            slot->state == SERVER_HOST_PEER_FAILED)
            continue;
        status = librdp_server_peer_get_pollfds(slot->protocol,
                                                NULL,
                                                0u,
                                                &descriptor_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = server_host_append_poll_group(host,
                                               groups,
                                               group_count,
                                               SERVER_HOST_POLL_PEER,
                                               slot,
                                               NULL,
                                               NULL,
                                               descriptor_count,
                                               poll_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        group = &groups[*group_count - 1u];
        status = librdp_server_peer_get_pollfds(
            slot->protocol,
            host->pollfds + group->offset,
            descriptor_count,
            &descriptor_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (slot->state == SERVER_HOST_PEER_ACTIVE)
        {
            const server_platform_rect* rects = NULL;
            size_t rect_count = 0;
            int dirty_timeout_ms = -1;

            status = server_dirty_scheduler_peek(slot->dirty,
                                                 now_ns,
                                                 &rects,
                                                 &rect_count,
                                                 &dirty_timeout_ms);
            if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_AGAIN)
                return status;
            if (status == LIBRDP_STATUS_OK && rect_count > 0u)
                dirty_timeout_ms = 0;
            *effective_timeout_ms =
                server_host_min_timeout(*effective_timeout_ms,
                                        dirty_timeout_ms);
        }
    }

    for (source_index = 0; source_index < *source_count; source_index++)
    {
        server_host_platform_source* source = &sources[source_index];
        server_host_poll_group* group = NULL;

        status = source->events->get_next_timeout(source->context,
                                                  &source->timeout_ms);
        if (status != LIBRDP_STATUS_OK || source->timeout_ms < -1)
            return status == LIBRDP_STATUS_OK
                       ? LIBRDP_STATUS_INVALID_ARGUMENT
                       : status;
        *effective_timeout_ms =
            server_host_min_timeout(*effective_timeout_ms,
                                    source->timeout_ms);
        status = source->events->get_pollfds(source->context,
                                             NULL,
                                             0u,
                                             &descriptor_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = server_host_append_poll_group(host,
                                               groups,
                                               group_count,
                                               SERVER_HOST_POLL_PROVIDER,
                                               NULL,
                                               source->events,
                                               source->context,
                                               descriptor_count,
                                               poll_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        group = &groups[*group_count - 1u];
        if (descriptor_count > 0u)
        {
            status = source->events->get_pollfds(
                source->context,
                host->pollfds + group->offset,
                descriptor_count,
                &descriptor_count);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    if (host->drive)
    {
        *effective_timeout_ms = server_host_min_timeout(
            *effective_timeout_ms,
            server_drive_runtime_next_timeout(host->drive, now_ns));
    }
    return LIBRDP_STATUS_OK;
}

static int server_host_group_ready(const server_host* host,
                                   const server_host_poll_group* group)
{
    size_t index = 0;

    for (index = 0; index < group->count; index++)
    {
        if (host->pollfds[group->offset + index].revents != 0)
            return 1;
    }
    return 0;
}

static void server_host_drain_wakeup(server_host* host)
{
    uint8_t buffer[128];
    ssize_t count = 0;

    do
    {
        count = read(host->wakeup_read_fd, buffer, sizeof(buffer));
    } while (count > 0 || (count < 0 && errno == EINTR));
}

static librdp_status server_host_dispatch_listener(server_host* host,
                                                   unsigned int* work)
{
    while (*work < host->max_work_per_iteration)
    {
        librdp_status status = server_host_accept_pending(host);

        if (status == LIBRDP_STATUS_TIMEOUT ||
            status == LIBRDP_STATUS_LIMIT_EXCEEDED)
            return LIBRDP_STATUS_OK;
        if (status != LIBRDP_STATUS_OK)
            return status;
        (*work)++;
    }
    return LIBRDP_STATUS_OK;
}

static void server_host_mark_peer_failed(server_host_peer_slot* slot)
{
    if (!slot)
        return;
    slot->state = SERVER_HOST_PEER_FAILED;
    if (slot->protocol)
        (void)librdp_server_peer_close(slot->protocol);
}

static librdp_status server_host_dispatch_peer(
    server_host* host,
    server_host_poll_group* group,
    unsigned int* work)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (*work >= host->max_work_per_iteration || !group->peer ||
        !group->peer->occupied)
        return LIBRDP_STATUS_OK;
    status = librdp_server_peer_notify_poll(
        group->peer->protocol,
        host->pollfds + group->offset,
        group->count);
    if (status == LIBRDP_STATUS_OK)
        status =
            librdp_server_peer_dispatch_pending(group->peer->protocol);
    (*work)++;
    if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT)
        return LIBRDP_STATUS_OK;
    server_host_mark_peer_failed(group->peer);
    return LIBRDP_STATUS_OK;
}

static librdp_status server_host_dispatch_provider(
    server_host* host,
    server_host_poll_group* group,
    int timeout_due,
    unsigned int* work)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (*work >= host->max_work_per_iteration ||
        (!timeout_due && !server_host_group_ready(host, group)))
        return LIBRDP_STATUS_OK;
    if (group->count > 0u && server_host_group_ready(host, group))
    {
        status = group->events->notify_poll(
            group->context,
            host->pollfds + group->offset,
            group->count);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    status = group->events->dispatch(
        group->context,
        host->max_work_per_iteration - *work);
    (*work)++;
    return status;
}

/*
 * Present only a bounded prefix of each active peer's dirty queue. A temporary
 * state/backpressure rejection keeps regions queued and pushes the next retry
 * to the configured frame deadline.
 */
static void server_host_dispatch_frames(server_host* host,
                                        uint64_t now_ns,
                                        unsigned int* work)
{
    size_t peer_index = 0;

    for (peer_index = 0;
         peer_index < host->peer_capacity &&
         *work < host->max_work_per_iteration;
         peer_index++)
    {
        server_host_peer_slot* slot = &host->peers[peer_index];
        const server_platform_rect* rects = NULL;
        size_t rect_count = 0;
        size_t presented = 0;
        int timeout_ms = -1;
        librdp_status status = LIBRDP_STATUS_OK;

        if (!slot->occupied || slot->state != SERVER_HOST_PEER_ACTIVE ||
            host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] !=
                SERVER_HOST_PROVIDER_READY)
            continue;
        status = server_dirty_scheduler_peek(slot->dirty,
                                             now_ns,
                                             &rects,
                                             &rect_count,
                                             &timeout_ms);
        if (status != LIBRDP_STATUS_OK || rect_count == 0u)
            continue;
        while (presented < rect_count &&
               *work < host->max_work_per_iteration)
        {
            const server_platform_rect* rect = &rects[presented];

            status = librdp_server_peer_surface_present(slot->protocol,
                                                        rect->x,
                                                        rect->y,
                                                        rect->width,
                                                        rect->height);
            if (status != LIBRDP_STATUS_OK)
                break;
            presented++;
            (*work)++;
        }
        if (presented > 0u)
        {
            (void)server_dirty_scheduler_commit(slot->dirty,
                                                presented,
                                                now_ns);
            server_host_metric_add(&host->metrics.frames_presented,
                                   (uint64_t)presented);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_FRAME_PRESENTED,
                                   slot,
                                   LIBRDP_STATUS_OK,
                                   (uint64_t)presented,
                                   1u);
        }
        if (status == LIBRDP_STATUS_STATE || status == LIBRDP_STATUS_AGAIN)
        {
            (void)server_dirty_scheduler_defer(slot->dirty, now_ns);
            server_host_metric_add(&host->metrics.frames_deferred, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_FRAME_DEFERRED,
                                   slot,
                                   status,
                                   (uint64_t)(rect_count - presented),
                                   1u);
        }
        else if (status != LIBRDP_STATUS_OK)
            server_host_mark_peer_failed(slot);
    }
}

static void server_host_reap_terminal_peers(server_host* host)
{
    size_t index = 0;

    for (index = 0; index < host->peer_capacity; index++)
    {
        server_host_peer_slot* slot = &host->peers[index];

        if (slot->occupied &&
            (slot->state == SERVER_HOST_PEER_CLOSED ||
             slot->state == SERVER_HOST_PEER_FAILED))
            server_host_release_peer_slot(slot);
    }
}

/*
 * Poll exactly once, route the immutable readiness snapshot, then process due
 * frames and terminal cleanup. State validation requires a listening host,
 * and descriptor ownership remains with each source. No descriptor is polled
 * again until the caller starts another bounded iteration.
 */
librdp_status server_host_run_once(server_host* host, int timeout_ms)
{
    server_host_poll_group groups[SERVER_HOST_MAX_POLL_GROUPS];
    server_host_platform_source sources[SERVER_PLATFORM_PROVIDER_COUNT];
    size_t group_count = 0;
    size_t source_count = 0;
    size_t poll_count = 0;
    size_t group_index = 0;
    size_t source_index = 0;
    unsigned int work = 0;
    int effective_timeout_ms = timeout_ms;
    int ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    uint64_t now_ns = 0;

    if (!host || timeout_ms < -1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state != SERVER_HOST_LISTENING)
        return LIBRDP_STATUS_STATE;
    server_host_metric_add(&host->metrics.loop_iterations, 1u);
    status = server_host_prepare_poll(host,
                                      timeout_ms,
                                      groups,
                                      &group_count,
                                      sources,
                                      &source_count,
                                      &poll_count,
                                      &effective_timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    do
    {
        ready = poll(host->pollfds, (nfds_t)poll_count, effective_timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0)
        return LIBRDP_STATUS_IO_ERROR;

    now_ns = server_host_now_ns();
    for (group_index = 0;
         group_index < group_count &&
         work < host->max_work_per_iteration;
         group_index++)
    {
        server_host_poll_group* group = &groups[group_index];

        if (group->kind == SERVER_HOST_POLL_WAKEUP &&
            server_host_group_ready(host, group))
        {
            server_host_drain_wakeup(host);
            server_host_metric_add(&host->metrics.wakeups, 1u);
            server_host_trace_emit(
                host,
                SERVER_HOST_TRACE_WAKEUP,
                NULL,
                atomic_load_explicit(&host->cancellation_requested,
                                     memory_order_acquire)
                    ? LIBRDP_STATUS_CANCELLED
                    : LIBRDP_STATUS_OK,
                0u,
                1u);
            work++;
        }
        else if (group->kind == SERVER_HOST_POLL_LISTENER &&
                 server_host_group_ready(host, group))
        {
            status = server_host_dispatch_listener(host, &work);
        }
        else if (group->kind == SERVER_HOST_POLL_PEER &&
                 server_host_group_ready(host, group))
        {
            status = server_host_dispatch_peer(host, group, &work);
        }
        else if (group->kind == SERVER_HOST_POLL_PROVIDER)
        {
            int timeout_due = 0;

            for (source_index = 0; source_index < source_count; source_index++)
            {
                if (sources[source_index].events == group->events &&
                    sources[source_index].context == group->context)
                {
                    timeout_due = sources[source_index].timeout_ms == 0 ||
                                  (ready == 0 &&
                                   sources[source_index].timeout_ms ==
                                       effective_timeout_ms);
                    break;
                }
            }
            status = server_host_dispatch_provider(host,
                                                   group,
                                                   timeout_due,
                                                   &work);
        }
        if (status != LIBRDP_STATUS_OK)
        {
            host->state = SERVER_HOST_FAILED;
            return status;
        }
    }
    if (atomic_load_explicit(&host->cancellation_requested,
                             memory_order_acquire))
    {
        server_host_metric_add(&host->metrics.cancellations, 1u);
        (void)server_host_stop(host);
        return LIBRDP_STATUS_CANCELLED;
    }
    if (host->drive)
    {
        status = server_drive_runtime_dispatch_timeouts(host->drive, now_ns);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    server_host_dispatch_frames(host, now_ns, &work);
    server_host_reap_terminal_peers(host);
    return work > 0u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_TIMEOUT;
}

static librdp_status server_host_signal_wakeup(server_host* host)
{
    uint8_t byte = 1u;
    ssize_t written = 0;

    if (!host || host->wakeup_write_fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    do
    {
        written = write(host->wakeup_write_fd, &byte, sizeof(byte));
    } while (written < 0 && errno == EINTR);
    if (written == (ssize_t)sizeof(byte) ||
        (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)))
        return LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_IO_ERROR;
}

librdp_status server_host_wakeup(server_host* host)
{
    return server_host_signal_wakeup(host);
}

librdp_status server_host_cancel(server_host* host)
{
    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_store_explicit(&host->cancellation_requested,
                          1,
                          memory_order_release);
    return server_host_signal_wakeup(host);
}
