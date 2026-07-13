/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer audio backend regression tests.
 * Coverage: deterministic memory sink used to verify the PipeWire backend
 * queue policy without requiring a live PipeWire daemon.
 * Bug classes: unbounded audio queue growth, wrong drop-oldest ordering,
 * latency accounting drift, and shutdown cleanup of queued data.
 * Determinism: tests use fixed byte arrays and do not open host audio devices.
 */

#include "audio_pipewire.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_audio:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * The audio sink keeps the most recent bytes when the queue is full. That
 * policy bounds latency during decoder bursts and is the same policy used by
 * the PipeWire output ring.
 */
static int test_memory_sink_backpressure(void)
{
    static const uint8_t first[] = {1, 2, 3, 4, 5, 6};
    static const uint8_t second[] = {7, 8, 9, 10, 11, 12};
    static const uint8_t expected[] = {5, 6, 7, 8};
    uint8_t out[4] = {0};
    x11_audio_backend_stats stats;
    x11_audio_memory_sink* sink = x11_audio_memory_sink_new(8u, 2u, 1000u);

    CHECK(sink != NULL);
    CHECK(x11_audio_memory_sink_write(sink, first, sizeof(first)) == 1);
    memset(&stats, 0, sizeof(stats));
    x11_audio_memory_sink_get_stats(sink, &stats);
    CHECK(stats.output_written_bytes == 6u);
    CHECK(stats.output_dropped_bytes == 0u);
    CHECK(stats.output_queued_bytes == 6u);
    CHECK(stats.output_latency_ms == 3u);
    CHECK(x11_audio_memory_sink_write(sink, second, sizeof(second)) == 1);
    memset(&stats, 0, sizeof(stats));
    x11_audio_memory_sink_get_stats(sink, &stats);
    CHECK(stats.output_written_bytes == 12u);
    CHECK(stats.output_dropped_bytes == 4u);
    CHECK(stats.output_queued_bytes == 8u);
    CHECK(stats.output_latency_ms == 4u);
    CHECK(x11_audio_memory_sink_read(sink, out, sizeof(out)) == sizeof(out));
    CHECK(memcmp(out, expected, sizeof(expected)) == 0);
    x11_audio_memory_sink_free(sink);
    return 0;
}

/*
 * Invalid sink construction and NULL writes fail closed. Zero-length writes
 * remain a successful no-op so callers can forward empty decoded blocks without
 * special-case error handling.
 */
static int test_memory_sink_invalid_inputs(void)
{
    x11_audio_backend_stats stats;
    x11_audio_memory_sink* sink = NULL;

    CHECK(x11_audio_memory_sink_new(0u, 2u, 1000u) == NULL);
    CHECK(x11_audio_memory_sink_new(8u, 0u, 1000u) == NULL);
    sink = x11_audio_memory_sink_new(8u, 2u, 1000u);
    CHECK(sink != NULL);
    CHECK(x11_audio_memory_sink_write(NULL, "x", 1u) == 0);
    CHECK(x11_audio_memory_sink_write(sink, NULL, 1u) == 0);
    CHECK(x11_audio_memory_sink_write(sink, NULL, 0u) == 1);
    memset(&stats, 0xff, sizeof(stats));
    x11_audio_memory_sink_get_stats(NULL, &stats);
    CHECK(stats.output_written_bytes == 0u);
    CHECK(stats.output_queued_bytes == 0u);
    x11_audio_memory_sink_free(sink);
    return 0;
}

int main(void)
{
    if (test_memory_sink_backpressure() != 0)
        return 1;
    if (test_memory_sink_invalid_inputs() != 0)
        return 1;
    return 0;
}
