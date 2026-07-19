/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer render copy regression tests.
 * Coverage: row-stride conversion used by the XShm presenter without opening
 * a real X11 window.
 * Bug classes: bounds overrun, stride confusion, zero-sized frames, and
 * fallback-copy corruption during resize.
 * Determinism: tests operate only on in-memory byte arrays and do not require
 * a display server.
 */

#include "x11_render.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_int(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr, "test_viewer_render:%d: check failed: %s\n", line, expression);
    return 1;
}

#define CHECK(expr)                                                                                  \
    do                                                                                               \
    {                                                                                                \
        if (check_int((expr), #expr, __LINE__) != 0)                                                 \
            return 1;                                                                                \
    } while (0)

/*
 * Protects the XShm fast path against row-stride mistakes: each BGRA row is
 * copied exactly up to width*4 bytes while source and destination padding stay
 * untouched.
 */
static int test_copy_bgra_rows_preserves_padding(void)
{
    static const uint8_t source[] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0xaau, 0xbbu,
        0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu, 0x10u, 0xccu, 0xddu,
    };
    static const uint8_t expected[] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0xeeu, 0xeeu, 0xeeu, 0xeeu,
        0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu, 0x10u, 0xeeu, 0xeeu, 0xeeu, 0xeeu,
    };
    uint8_t destination[24];

    memset(destination, 0xee, sizeof(destination));
    CHECK(x11_render_copy_bgra_rows(destination, 12u, source, 10u, 2u, 2u) == 1);
    CHECK(memcmp(destination, expected, sizeof(expected)) == 0);
    return 0;
}

/*
 * Rejects malformed geometry before any copy occurs. These cases mirror the
 * inputs produced by invalid server dimensions or stale resize state.
 */
static int test_copy_bgra_rows_rejects_invalid_inputs(void)
{
    uint8_t source[8] = { 0 };
    uint8_t destination[8] = { 0 };

    CHECK(x11_render_copy_bgra_rows(NULL, 8u, source, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, NULL, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 3u, source, 8u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 3u, 1u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 8u, 0u, 1u) == 0);
    CHECK(x11_render_copy_bgra_rows(destination, 8u, source, 8u, 1u, 0u) == 0);
    return 0;
}

int main(void)
{
    if (test_copy_bgra_rows_preserves_padding() != 0)
        return 1;
    if (test_copy_bgra_rows_rejects_invalid_inputs() != 0)
        return 1;
    return 0;
}
