/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer clipboard bridge regression tests.
 * Coverage: INCR helper state used by X11 clipboard transfers without opening a
 * real X server.
 * Bug classes: chunk bounds, accumulator overflow, zero-length final chunks,
 * timeout decisions, and payload-size limits before RDP publication.
 * Determinism: tests use in-memory byte slices and synthetic timestamps only.
 */

#include "viewer_clipboard.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_clipboard:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * Outbound INCR chunk sizing must never read beyond the advertised payload and
 * must produce a zero-sized final marker after the last byte has been sent.
 */
static int test_next_incr_chunk_size(void)
{
    CHECK(x11_clipboard_next_incr_chunk_size(100u, 0u, 32u) == 32u);
    CHECK(x11_clipboard_next_incr_chunk_size(100u, 96u, 32u) == 4u);
    CHECK(x11_clipboard_next_incr_chunk_size(100u, 100u, 32u) == 0u);
    CHECK(x11_clipboard_next_incr_chunk_size(100u, 101u, 32u) == 0u);
    CHECK(x11_clipboard_next_incr_chunk_size(100u, 0u, 0u) == 0u);
    return 0;
}

/*
 * Inbound INCR accumulation validates the configured maximum before realloc and
 * preserves byte order across multiple chunks.
 */
static int test_accumulate_incr_chunks(void)
{
    static const uint8_t first[] = {0x01u, 0x02u, 0x03u};
    static const uint8_t second[] = {0x04u, 0x05u};
    static const uint8_t expected[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u};
    uint8_t* buffer = NULL;
    size_t length = 0;
    size_t capacity = 0;

    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, &length, &capacity, first, sizeof(first), 8u) == 1);
    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, &length, &capacity, second, sizeof(second), 8u) == 1);
    CHECK(length == sizeof(expected));
    CHECK(capacity >= length);
    CHECK(memcmp(buffer, expected, sizeof(expected)) == 0);
    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, &length, &capacity, second, sizeof(second), 6u) == 0);
    CHECK(length == sizeof(expected));
    free(buffer);
    return 0;
}

/*
 * Malformed accumulator state and NULL chunks with non-zero length must fail
 * closed without mutating caller-owned storage.
 */
static int test_accumulate_rejects_invalid_state(void)
{
    uint8_t storage[4] = {0};
    uint8_t* buffer = storage;
    size_t length = 5u;
    size_t capacity = 4u;

    CHECK(x11_clipboard_accumulate_incr_chunk(NULL, &length, &capacity, storage, 1u, 8u) == 0);
    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, NULL, &capacity, storage, 1u, 8u) == 0);
    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, &length, &capacity, NULL, 1u, 8u) == 0);
    CHECK(x11_clipboard_accumulate_incr_chunk(&buffer, &length, &capacity, storage, 1u, 8u) == 0);
    return 0;
}

/*
 * Timeout checks treat zero as "no deadline" and otherwise use monotonic
 * deadline comparison without wrap-prone signed arithmetic.
 */
static int test_incr_timeout(void)
{
    CHECK(x11_clipboard_incr_timed_out(10u, 0u) == 0);
    CHECK(x11_clipboard_incr_timed_out(10u, 11u) == 0);
    CHECK(x11_clipboard_incr_timed_out(11u, 11u) == 1);
    CHECK(x11_clipboard_incr_timed_out(12u, 11u) == 1);
    return 0;
}

int main(void)
{
    if (test_next_incr_chunk_size() != 0)
        return 1;
    if (test_accumulate_incr_chunks() != 0)
        return 1;
    if (test_accumulate_rejects_invalid_state() != 0)
        return 1;
    if (test_incr_timeout() != 0)
        return 1;
    return 0;
}
