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

/*
 * HTML clipboard data exported by X11 is wrapped in the registered wire format
 * with stable offsets, and inbound wire data exposes only the fragment to local
 * X11 clients.
 */
static int test_html_format_offsets(void)
{
    static const uint8_t html[] = "<b>x</b>";
    uint8_t* formatted = NULL;
    size_t formatted_len = 0;
    const uint8_t* fragment = NULL;
    size_t fragment_len = 0;

    CHECK(x11_clipboard_build_html_format(html, sizeof(html) - 1u, &formatted, &formatted_len) == 1);
    CHECK(formatted != NULL);
    CHECK(formatted_len > sizeof(html));
    CHECK(x11_clipboard_extract_html_fragment(formatted, formatted_len, &fragment, &fragment_len) == 1);
    CHECK(fragment_len == sizeof(html) - 1u);
    CHECK(memcmp(fragment, html, fragment_len) == 0);
    free(formatted);
    return 0;
}

/*
 * URI lists must keep only local file:// entries, percent-decode paths, and
 * avoid treating comments or remote-host URIs as files.
 */
static int test_uri_list_parse(void)
{
    static const uint8_t uris[] =
        "# comment\r\n"
        "file:///tmp/a%20b.txt\r\n"
        "https://example.invalid/not-local\r\n"
        "file://remote/tmp/nope\r\n"
        "file://localhost/tmp/c.txt\n";
    librdp_clipboard_file files[4];
    char* paths[4];
    uint32_t count = 0;

    memset(files, 0, sizeof(files));
    memset(paths, 0, sizeof(paths));
    CHECK(x11_clipboard_parse_uri_list(uris, sizeof(uris) - 1u, files, paths, 4u, &count) == 1);
    CHECK(count == 2u);
    CHECK(strcmp(files[0].path, "/tmp/a b.txt") == 0);
    CHECK(strcmp(files[0].name, "a b.txt") == 0);
    CHECK(strcmp(files[1].path, "/tmp/c.txt") == 0);
    CHECK(strcmp(files[1].name, "c.txt") == 0);
    x11_clipboard_free_uri_paths(paths, 4u);
    return 0;
}

/*
 * Remote format selection inspects registered-format names in UTF-16LE and
 * chooses richer payloads before falling back to plain Unicode text.
 */
static int test_remote_format_selection(void)
{
    static const uint8_t html_name[] = {
        'H', 0, 'T', 0, 'M', 0, 'L', 0, ' ', 0, 'F', 0, 'o', 0, 'r', 0,
        'm', 0, 'a', 0, 't', 0, 0, 0};
    static const uint8_t png_name[] = {'P', 0, 'N', 0, 'G', 0, 0, 0};
    librdp_clipboard_format formats[3];
    uint32_t kind = X11_CLIPBOARD_REMOTE_KIND_NONE;

    memset(formats, 0, sizeof(formats));
    formats[0].format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    formats[1].format_id = 49152u;
    formats[1].name = html_name;
    formats[1].name_len = sizeof(html_name);
    formats[2].format_id = 49153u;
    formats[2].name = png_name;
    formats[2].name_len = sizeof(png_name);
    CHECK(x11_clipboard_choose_remote_format(formats, 3u, &kind) == 49152u);
    CHECK(kind == X11_CLIPBOARD_REMOTE_KIND_HTML);
    CHECK(x11_clipboard_choose_remote_format(formats + 2, 1u, &kind) == 49153u);
    CHECK(kind == X11_CLIPBOARD_REMOTE_KIND_PNG);
    CHECK(x11_clipboard_choose_remote_format(formats, 1u, &kind) == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
    CHECK(kind == X11_CLIPBOARD_REMOTE_KIND_TEXT);
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
    if (test_html_format_offsets() != 0)
        return 1;
    if (test_uri_list_parse() != 0)
        return 1;
    if (test_remote_format_selection() != 0)
        return 1;
    return 0;
}
