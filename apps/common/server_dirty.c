/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded dirty-region queue and frame pacing implementation.
 * Invariants: queued geometry is surface-relative, queue growth stops at the
 * configured cap, and commit is the only operation that discards delivered
 * regions.
 * Ownership: queue storage is allocated once and released with the scheduler.
 * Threading: state is intentionally lock-free and owner-thread confined.
 * Trust boundary: all dimensions and timestamp arithmetic are checked before
 * they influence allocation, queue state, or poll timeout calculation.
 */

#include "server_dirty.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct server_dirty_scheduler
{
    server_platform_rect* regions;
    size_t count;
    size_t capacity;
    size_t max_per_frame;
    uint32_t width;
    uint32_t height;
    uint64_t frame_interval_ns;
    uint64_t next_frame_ns;
    server_dirty_metrics metrics;
};

void server_dirty_config_init(server_dirty_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = SERVER_DIRTY_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->max_regions = 128u;
    config->max_regions_per_frame = 32u;
    config->frame_interval_ns = 16666667u;
}

void server_dirty_metrics_init(server_dirty_metrics* metrics)
{
    if (!metrics)
        return;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = SERVER_DIRTY_METRICS_VERSION;
    metrics->size = sizeof(*metrics);
}

static int server_dirty_config_valid(const server_dirty_config* config)
{
    return config && config->version == SERVER_DIRTY_CONFIG_VERSION &&
           config->size >= sizeof(*config) && config->max_regions > 0u &&
           config->max_regions <= SERVER_DIRTY_MAX_REGIONS &&
           config->max_regions_per_frame > 0u &&
           config->max_regions_per_frame <= config->max_regions;
}

server_dirty_scheduler* server_dirty_scheduler_new(
    const server_dirty_config* config)
{
    server_dirty_scheduler* scheduler = NULL;

    if (!server_dirty_config_valid(config) ||
        config->max_regions > SIZE_MAX / sizeof(*scheduler->regions))
        return NULL;
    scheduler = (server_dirty_scheduler*)calloc(1u, sizeof(*scheduler));
    if (!scheduler)
        return NULL;
    scheduler->regions = (server_platform_rect*)calloc(
        config->max_regions,
        sizeof(*scheduler->regions));
    if (!scheduler->regions)
    {
        free(scheduler);
        return NULL;
    }
    scheduler->capacity = config->max_regions;
    scheduler->max_per_frame = config->max_regions_per_frame;
    scheduler->frame_interval_ns = config->frame_interval_ns;
    server_dirty_metrics_init(&scheduler->metrics);
    return scheduler;
}

void server_dirty_scheduler_free(server_dirty_scheduler* scheduler)
{
    if (!scheduler)
        return;
    free(scheduler->regions);
    memset(scheduler, 0, sizeof(*scheduler));
    free(scheduler);
}

static uint64_t server_dirty_deadline(uint64_t now_ns, uint64_t interval_ns)
{
    if (interval_ns > UINT64_MAX - now_ns)
        return UINT64_MAX;
    return now_ns + interval_ns;
}

static int server_dirty_rect_valid(const server_dirty_scheduler* scheduler,
                                   const server_platform_rect* rect)
{
    if (!scheduler || !rect || rect->width == 0u || rect->height == 0u ||
        scheduler->width == 0u || scheduler->height == 0u ||
        rect->x >= scheduler->width || rect->y >= scheduler->height)
        return 0;
    return rect->width <= scheduler->width - rect->x &&
           rect->height <= scheduler->height - rect->y;
}

static uint32_t server_dirty_max_u32(uint32_t left, uint32_t right)
{
    return left > right ? left : right;
}

static uint32_t server_dirty_min_u32(uint32_t left, uint32_t right)
{
    return left < right ? left : right;
}

/*
 * Rectangle endpoints are safe because every input rectangle was preflighted
 * against the current surface dimensions before reaching this helper.
 */
static int server_dirty_rects_touch(const server_platform_rect* left,
                                    const server_platform_rect* right)
{
    uint32_t left_right = left->x + left->width;
    uint32_t right_right = right->x + right->width;
    uint32_t left_bottom = left->y + left->height;
    uint32_t right_bottom = right->y + right->height;

    return left->x <= right_right && right->x <= left_right &&
           left->y <= right_bottom && right->y <= left_bottom;
}

static server_platform_rect server_dirty_union(
    const server_platform_rect* left,
    const server_platform_rect* right)
{
    server_platform_rect result;
    uint32_t right_edge =
        server_dirty_max_u32(left->x + left->width, right->x + right->width);
    uint32_t bottom_edge =
        server_dirty_max_u32(left->y + left->height, right->y + right->height);

    result.x = server_dirty_min_u32(left->x, right->x);
    result.y = server_dirty_min_u32(left->y, right->y);
    result.width = right_edge - result.x;
    result.height = bottom_edge - result.y;
    return result;
}

static void server_dirty_remove_at(server_dirty_scheduler* scheduler,
                                   size_t index)
{
    if (index + 1u < scheduler->count)
    {
        memmove(&scheduler->regions[index],
                &scheduler->regions[index + 1u],
                (scheduler->count - index - 1u) * sizeof(*scheduler->regions));
    }
    scheduler->count--;
}

static void server_dirty_merge_existing(server_dirty_scheduler* scheduler,
                                        server_platform_rect* candidate)
{
    size_t index = 0;

    while (index < scheduler->count)
    {
        if (!server_dirty_rects_touch(candidate, &scheduler->regions[index]))
        {
            index++;
            continue;
        }
        *candidate =
            server_dirty_union(candidate, &scheduler->regions[index]);
        server_dirty_remove_at(scheduler, index);
        scheduler->metrics.merged_regions++;
        index = 0;
    }
}

librdp_status server_dirty_scheduler_resize(server_dirty_scheduler* scheduler,
                                            uint32_t width,
                                            uint32_t height,
                                            uint64_t now_ns,
                                            int invalidate)
{
    server_platform_rect full;

    if (!scheduler || width == 0u || height == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    scheduler->width = width;
    scheduler->height = height;
    scheduler->count = 0u;
    scheduler->next_frame_ns = now_ns;
    scheduler->metrics.surface_resizes++;
    scheduler->metrics.pending_regions = 0u;
    if (!invalidate)
        return LIBRDP_STATUS_OK;
    full.x = 0u;
    full.y = 0u;
    full.width = width;
    full.height = height;
    return server_dirty_scheduler_invalidate(scheduler, &full, now_ns);
}

librdp_status server_dirty_scheduler_invalidate(
    server_dirty_scheduler* scheduler,
    const server_platform_rect* rect,
    uint64_t now_ns)
{
    server_platform_rect candidate;

    if (!server_dirty_rect_valid(scheduler, rect))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    candidate = *rect;
    scheduler->metrics.invalidations++;
    server_dirty_merge_existing(scheduler, &candidate);
    if (scheduler->count == 0u && scheduler->next_frame_ns < now_ns)
        scheduler->next_frame_ns = now_ns;
    if (scheduler->count < scheduler->capacity)
    {
        scheduler->regions[scheduler->count++] = candidate;
    }
    else
    {
        size_t index = 0;

        for (index = 0; index < scheduler->count; index++)
            candidate = server_dirty_union(&candidate,
                                           &scheduler->regions[index]);
        scheduler->regions[0] = candidate;
        scheduler->count = 1u;
        scheduler->metrics.queue_collapses++;
    }
    scheduler->metrics.pending_regions = scheduler->count;
    return LIBRDP_STATUS_OK;
}

static int server_dirty_timeout_ms(uint64_t now_ns, uint64_t deadline_ns)
{
    uint64_t remaining_ns = 0;
    uint64_t milliseconds = 0;

    if (deadline_ns <= now_ns)
        return 0;
    remaining_ns = deadline_ns - now_ns;
    milliseconds = remaining_ns / 1000000u;
    if (remaining_ns % 1000000u != 0u)
        milliseconds++;
    if (milliseconds > (uint64_t)INT_MAX)
        return INT_MAX;
    return (int)milliseconds;
}

librdp_status server_dirty_scheduler_peek(
    server_dirty_scheduler* scheduler,
    uint64_t now_ns,
    const server_platform_rect** rects,
    size_t* count,
    int* timeout_ms)
{
    if (!scheduler || !rects || !count || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *rects = NULL;
    *count = 0u;
    *timeout_ms = -1;
    if (scheduler->count == 0u)
        return LIBRDP_STATUS_OK;
    if (now_ns < scheduler->next_frame_ns)
    {
        *timeout_ms =
            server_dirty_timeout_ms(now_ns, scheduler->next_frame_ns);
        return LIBRDP_STATUS_AGAIN;
    }
    *rects = scheduler->regions;
    *count = scheduler->count < scheduler->max_per_frame
                 ? scheduler->count
                 : scheduler->max_per_frame;
    *timeout_ms = 0;
    return LIBRDP_STATUS_OK;
}

librdp_status server_dirty_scheduler_commit(server_dirty_scheduler* scheduler,
                                            size_t count,
                                            uint64_t now_ns)
{
    if (!scheduler || count == 0u || count > scheduler->count ||
        count > scheduler->max_per_frame)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count < scheduler->count)
    {
        memmove(scheduler->regions,
                scheduler->regions + count,
                (scheduler->count - count) * sizeof(*scheduler->regions));
    }
    scheduler->count -= count;
    scheduler->metrics.presented_regions += (uint64_t)count;
    scheduler->metrics.pending_regions = scheduler->count;
    scheduler->next_frame_ns =
        server_dirty_deadline(now_ns, scheduler->frame_interval_ns);
    return LIBRDP_STATUS_OK;
}

librdp_status server_dirty_scheduler_defer(server_dirty_scheduler* scheduler,
                                           uint64_t now_ns)
{
    uint64_t deadline = 0;

    if (!scheduler || scheduler->count == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    deadline = server_dirty_deadline(now_ns, scheduler->frame_interval_ns);
    if (scheduler->next_frame_ns < deadline)
        scheduler->next_frame_ns = deadline;
    scheduler->metrics.deferred_frames++;
    return LIBRDP_STATUS_OK;
}

librdp_status server_dirty_scheduler_get_metrics(
    const server_dirty_scheduler* scheduler,
    server_dirty_metrics* metrics)
{
    if (!scheduler || !metrics ||
        metrics->version != SERVER_DIRTY_METRICS_VERSION ||
        metrics->size < sizeof(*metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *metrics = scheduler->metrics;
    return LIBRDP_STATUS_OK;
}
