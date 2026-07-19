/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded dirty-region scheduling for shared desktop servers.
 * Invariants: every queued rectangle fits the current surface, storage is
 * bounded by configuration, and a resize invalidates all stale geometry.
 * Ownership: the scheduler owns its rectangle array; peeked rectangles remain
 * borrowed until the next scheduler operation.
 * Threading: all operations run on the serialized server-host thread.
 * Trust boundary: capture-provider geometry is checked before it can affect a
 * peer surface or transport update.
 */

#ifndef LIBRDP_APP_SERVER_DIRTY_H
#define LIBRDP_APP_SERVER_DIRTY_H

#include "server_platform.h"

#include <librdp/error.h>

#include <stddef.h>
#include <stdint.h>

#define SERVER_DIRTY_CONFIG_VERSION 1u
#define SERVER_DIRTY_METRICS_VERSION 1u
#define SERVER_DIRTY_MAX_REGIONS 4096u

typedef struct server_dirty_config
{
    uint32_t version;
    size_t size;
    size_t max_regions;
    size_t max_regions_per_frame;
    uint64_t frame_interval_ns;
} server_dirty_config;

typedef struct server_dirty_metrics
{
    uint32_t version;
    size_t size;
    uint64_t invalidations;
    uint64_t merged_regions;
    uint64_t queue_collapses;
    uint64_t deferred_frames;
    uint64_t presented_regions;
    uint64_t surface_resizes;
    size_t pending_regions;
} server_dirty_metrics;

typedef struct server_dirty_scheduler server_dirty_scheduler;

void server_dirty_config_init(server_dirty_config* config);
void server_dirty_metrics_init(server_dirty_metrics* metrics);
librdp_status server_dirty_config_validate(
    const server_dirty_config* config);
server_dirty_scheduler* server_dirty_scheduler_new(
    const server_dirty_config* config);
void server_dirty_scheduler_free(server_dirty_scheduler* scheduler);
librdp_status server_dirty_scheduler_resize(server_dirty_scheduler* scheduler,
                                            uint32_t width,
                                            uint32_t height,
                                            uint64_t now_ns,
                                            int invalidate);
librdp_status server_dirty_scheduler_invalidate(
    server_dirty_scheduler* scheduler,
    const server_platform_rect* rect,
    uint64_t now_ns);
librdp_status server_dirty_scheduler_peek(
    server_dirty_scheduler* scheduler,
    uint64_t now_ns,
    const server_platform_rect** rects,
    size_t* count,
    int* timeout_ms);
librdp_status server_dirty_scheduler_commit(server_dirty_scheduler* scheduler,
                                            size_t count,
                                            uint64_t now_ns);
librdp_status server_dirty_scheduler_defer(server_dirty_scheduler* scheduler,
                                           uint64_t now_ns);
librdp_status server_dirty_scheduler_clear(server_dirty_scheduler* scheduler,
                                           uint64_t now_ns);
librdp_status server_dirty_scheduler_get_metrics(
    const server_dirty_scheduler* scheduler,
    server_dirty_metrics* metrics);

#endif
