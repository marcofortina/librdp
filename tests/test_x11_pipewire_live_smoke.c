/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: opt-in live PipeWire viewer audio smoke.
 * Coverage: PCM, A-law and mu-law playback negotiation, bounded output queue,
 * virtual-source capture, format restart and clean stream teardown.
 * Bug classes: asynchronous negotiation failure, stalled streams, unbounded
 * latency, incorrect format mapping and stale buffers across stop/restart.
 * Determinism: disposable virtual nodes isolate the test from physical audio
 * hardware; fixed payloads, byte counters and bounded waits drive assertions.
 * Environment: LIBRDP_TEST_PIPEWIRE_SINK and LIBRDP_TEST_PIPEWIRE_SOURCE name
 * disposable PipeWire nodes. Missing variables skip their respective paths.
 */

#include "x11_audio_pipewire.h"

#include <librdp/audio.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_SKIP 77
#define TEST_OUTPUT_QUEUE_BYTES (4u * 1024u * 1024u)
#define TEST_OUTPUT_OVERFLOW_BYTES (TEST_OUTPUT_QUEUE_BYTES + 65536u)
#define TEST_WAIT_STEP_MS 20u
#define TEST_WAIT_LIMIT_MS 3000u

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_x11_pipewire_live_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

static void test_sleep_ms(uint32_t milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec = (long)((milliseconds % 1000u) * 1000000u);
    while (nanosleep(&delay, &delay) != 0)
    {
    }
}

static int test_wait_output_empty(x11_pipewire_audio* audio,
                                  uint64_t minimum_written)
{
    uint32_t waited = 0u;

    while (waited <= TEST_WAIT_LIMIT_MS)
    {
        x11_audio_backend_stats stats;

        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        if (stats.output_written_bytes >= minimum_written &&
            stats.output_queued_bytes == 0u)
            return 1;
        test_sleep_ms(TEST_WAIT_STEP_MS);
        waited += TEST_WAIT_STEP_MS;
    }
    return 0;
}

static int test_wait_input_data(x11_pipewire_audio* audio,
                                uint64_t minimum_captured)
{
    uint32_t waited = 0u;

    while (waited <= TEST_WAIT_LIMIT_MS)
    {
        x11_audio_backend_stats stats;

        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        if (stats.input_captured_bytes >= minimum_captured &&
            stats.input_queued_bytes > 0u)
            return 1;
        test_sleep_ms(TEST_WAIT_STEP_MS);
        waited += TEST_WAIT_STEP_MS;
    }
    return 0;
}

/*
 * Drive each advertised playback format through the actual PipeWire graph.
 * A drained queue proves that the asynchronous stream reached a working node,
 * rather than merely accepting the initial connect request.
 */
static int test_live_output(const char* sink)
{
    static const librdp_audio_format formats[] = {
        {
            .format_tag = LIBRDP_AUDIO_FORMAT_PCM,
            .channels = 2u,
            .samples_per_sec = 48000u,
            .avg_bytes_per_sec = 192000u,
            .block_align = 4u,
            .bits_per_sample = 16u,
        },
        {
            .format_tag = LIBRDP_AUDIO_FORMAT_ALAW,
            .channels = 1u,
            .samples_per_sec = 8000u,
            .avg_bytes_per_sec = 8000u,
            .block_align = 1u,
            .bits_per_sample = 8u,
        },
        {
            .format_tag = LIBRDP_AUDIO_FORMAT_MULAW,
            .channels = 1u,
            .samples_per_sec = 8000u,
            .avg_bytes_per_sec = 8000u,
            .block_align = 1u,
            .bits_per_sample = 8u,
        },
    };
    x11_pipewire_audio* audio = NULL;
    uint8_t payload[19200];
    uint64_t expected_written = 0u;
    size_t i = 0u;

    for (i = 0u; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 17u + 3u);
    audio = x11_pipewire_audio_new();
    CHECK(audio != NULL);

    for (i = 0u; i < sizeof(formats) / sizeof(formats[0]); i++)
    {
        size_t payload_len = formats[i].format_tag == LIBRDP_AUDIO_FORMAT_PCM ?
            sizeof(payload) :
            800u;
        x11_audio_backend_stats stats;

        CHECK(x11_pipewire_audio_start_output(audio, &formats[i], sink));
        test_sleep_ms(100u);
        CHECK(x11_pipewire_audio_write_output(audio, payload, payload_len));
        expected_written += payload_len;
        CHECK(test_wait_output_empty(audio, expected_written));
        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        CHECK(stats.output_written_bytes == expected_written);
        CHECK(stats.output_dropped_bytes == 0u);
        CHECK(stats.output_queued_bytes == 0u);
        x11_pipewire_audio_stop_output(audio);
    }

    {
        uint8_t* overflow = (uint8_t*)malloc(TEST_OUTPUT_OVERFLOW_BYTES);
        x11_audio_backend_stats stats;

        CHECK(overflow != NULL);
        memset(overflow, 0x5au, TEST_OUTPUT_OVERFLOW_BYTES);
        CHECK(x11_pipewire_audio_start_output(audio, &formats[0], sink));
        CHECK(x11_pipewire_audio_write_output(audio,
                                               overflow,
                                               TEST_OUTPUT_OVERFLOW_BYTES));
        expected_written += TEST_OUTPUT_OVERFLOW_BYTES;
        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        CHECK(stats.output_written_bytes == expected_written);
        CHECK(stats.output_dropped_bytes >=
              TEST_OUTPUT_OVERFLOW_BYTES - TEST_OUTPUT_QUEUE_BYTES);
        CHECK(stats.output_queued_bytes <= TEST_OUTPUT_QUEUE_BYTES);
        CHECK(stats.output_latency_ms <=
              (TEST_OUTPUT_QUEUE_BYTES / formats[0].block_align) * 1000u /
                  formats[0].samples_per_sec);
        free(overflow);
        x11_pipewire_audio_stop_output(audio);
        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        CHECK(stats.output_queued_bytes == 0u);
    }

    x11_pipewire_audio_free(audio);
    return 0;
}

/*
 * Capture from a disposable virtual source, then restart with a second PCM
 * format. Captured-byte growth and readable data verify that both negotiations
 * reached the live graph and that stop discarded stale queued samples.
 */
static int test_live_input(const char* source)
{
    static const librdp_audio_format formats[] = {
        {
            .format_tag = LIBRDP_AUDIO_FORMAT_PCM,
            .channels = 2u,
            .samples_per_sec = 48000u,
            .avg_bytes_per_sec = 192000u,
            .block_align = 4u,
            .bits_per_sample = 16u,
        },
        {
            .format_tag = LIBRDP_AUDIO_FORMAT_PCM,
            .channels = 1u,
            .samples_per_sec = 16000u,
            .avg_bytes_per_sec = 16000u,
            .block_align = 1u,
            .bits_per_sample = 8u,
        },
    };
    x11_pipewire_audio* audio = x11_pipewire_audio_new();
    uint8_t capture[4096];
    uint64_t minimum_captured = 1u;
    size_t i = 0u;

    CHECK(audio != NULL);
    for (i = 0u; i < sizeof(formats) / sizeof(formats[0]); i++)
    {
        x11_audio_backend_stats stats;
        size_t read_len = 0u;

        CHECK(x11_pipewire_audio_start_input(audio, &formats[i], source));
        CHECK(test_wait_input_data(audio, minimum_captured));
        memset(capture, 0xa5, sizeof(capture));
        read_len = x11_pipewire_audio_read_input(audio,
                                                 capture,
                                                 sizeof(capture));
        CHECK(read_len > 0u);
        CHECK(read_len % formats[i].block_align == 0u);
        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        CHECK(stats.input_captured_bytes >= read_len);
        minimum_captured = stats.input_captured_bytes + 1u;
        x11_pipewire_audio_stop_input(audio);
        memset(&stats, 0, sizeof(stats));
        x11_pipewire_audio_get_stats(audio, &stats);
        CHECK(stats.input_queued_bytes == 0u);
    }
    x11_pipewire_audio_free(audio);
    return 0;
}

int main(void)
{
    const char* sink = getenv("LIBRDP_TEST_PIPEWIRE_SINK");
    const char* source = getenv("LIBRDP_TEST_PIPEWIRE_SOURCE");
    int exercised = 0;

    if (sink && sink[0] != '\0')
    {
        if (test_live_output(sink) != 0)
            return 1;
        exercised = 1;
    }
    if (source && source[0] != '\0')
    {
        if (test_live_input(source) != 0)
            return 1;
        exercised = 1;
    }
    return exercised ? 0 : TEST_SKIP;
}
