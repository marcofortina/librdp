/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Cocoa server clipboard adapter tests.
 * Coverage: isolated pasteboard discovery, text/HTML/PNG conversion, local
 * file metadata and range reads, remote ownership, feedback suppression and
 * pending-request cancellation.
 * Bug classes: global clipboard mutation, format confusion, unbounded native
 * data, stale request correlation, ownership loops and file lifetime errors.
 * Determinism: a process-scoped named pasteboard and temporary regular file
 * replace the user's general pasteboard and any remote endpoint.
 * Failure policy: malformed or stale work must fail before native publication
 * or filesystem access.
 */

#include "cocoa_clipboard.h"

#include <librdp/clipboard.h>

#import <Cocoa/Cocoa.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_FORMAT_CAPACITY 16u
#define TEST_DATA_CAPACITY (1024u * 1024u)

typedef struct test_clipboard_state
{
    server_platform_clipboard_format formats[TEST_FORMAT_CAPACITY];
    size_t format_count;
    uint64_t local_generation;
    server_platform_clipboard_request request;
    server_platform_clipboard_file_request file_request;
    uint8_t data[TEST_DATA_CAPACITY];
    size_t data_len;
    librdp_status data_status;
    uint64_t data_request_id;
    uint32_t data_format_id;
    uint32_t data_stream_id;
    uint64_t cancelled_request_id;
    size_t format_events;
    size_t request_events;
    size_t file_request_events;
    size_t data_events;
    size_t cancel_events;
    int data_final;
} test_clipboard_state;

static int test_check(int condition, const char* expression, int line)
{
    if (!condition)
        fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, line, expression);
    return condition;
}

#define CHECK(expression)                                                      \
    do                                                                         \
    {                                                                          \
        if (!test_check((expression), #expression, __LINE__))                  \
            return 0;                                                          \
    } while (0)

#define MAIN_CHECK(expression)                                                 \
    do                                                                         \
    {                                                                          \
        if (!test_check((expression), #expression, __LINE__))                  \
            goto cleanup_pool;                                                 \
    } while (0)

static int test_contains(const uint8_t* data,
                         size_t data_len,
                         const void* needle,
                         size_t needle_len)
{
    size_t index = 0u;

    if (!data || !needle || needle_len == 0u || needle_len > data_len)
        return 0;
    for (index = 0u; index <= data_len - needle_len; index++)
    {
        if (memcmp(data + index, needle, needle_len) == 0)
            return 1;
    }
    return 0;
}

static void test_formats(const server_platform_clipboard_format* formats,
                         size_t format_count,
                         uint64_t generation,
                         void* user_data)
{
    test_clipboard_state* state = (test_clipboard_state*)user_data;

    if (!state || format_count > TEST_FORMAT_CAPACITY ||
        (format_count > 0u && !formats))
        return;
    memset(state->formats, 0, sizeof(state->formats));
    if (format_count > 0u)
    {
        memcpy(state->formats, formats, format_count * sizeof(*formats));
    }
    state->format_count = format_count;
    state->local_generation = generation;
    state->format_events++;
}

static void test_data(const server_platform_clipboard_data* data,
                      void* user_data)
{
    test_clipboard_state* state = (test_clipboard_state*)user_data;

    if (!state || !data || state->data_len > TEST_DATA_CAPACITY ||
        data->data_len > TEST_DATA_CAPACITY - state->data_len ||
        (data->data_len > 0u && !data->data))
        return;
    if (data->data_len > 0u)
    {
        memcpy(state->data + state->data_len, data->data, data->data_len);
        state->data_len += data->data_len;
    }
    state->data_status = data->status;
    state->data_request_id = data->request_id;
    state->data_format_id = data->format_id;
    state->data_stream_id = data->stream_id;
    state->data_final = data->final_chunk;
    state->data_events++;
}

static librdp_status
test_request(const server_platform_clipboard_request* request, void* user_data)
{
    test_clipboard_state* state = (test_clipboard_state*)user_data;

    if (!state || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->request = *request;
    state->request_events++;
    return LIBRDP_STATUS_OK;
}

static librdp_status
test_file_request(const server_platform_clipboard_file_request* request,
                  void* user_data)
{
    test_clipboard_state* state = (test_clipboard_state*)user_data;

    if (!state || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->file_request = *request;
    state->file_request_events++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_cancel(uint32_t peer_id,
                                 uint32_t generation,
                                 uint64_t ownership_generation,
                                 uint64_t request_id,
                                 void* user_data)
{
    test_clipboard_state* state = (test_clipboard_state*)user_data;

    if (!state || peer_id == 0u || generation == 0u ||
        ownership_generation == 0u || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->cancelled_request_id = request_id;
    state->cancel_events++;
    return LIBRDP_STATUS_OK;
}

static void test_data_reset(test_clipboard_state* state)
{
    if (!state)
        return;
    memset(state->data, 0, sizeof(state->data));
    state->data_len = 0u;
    state->data_status = LIBRDP_STATUS_STATE;
    state->data_request_id = 0u;
    state->data_format_id = 0u;
    state->data_stream_id = 0u;
    state->data_final = 0;
    state->data_events = 0u;
}

static int test_has_format(const test_clipboard_state* state,
                           uint32_t format_id)
{
    size_t index = 0u;

    if (!state)
        return 0;
    for (index = 0u; index < state->format_count; index++)
    {
        if (state->formats[index].id == format_id)
            return 1;
    }
    return 0;
}

static NSData* test_png_data(void)
{
    NSBitmapImageRep* image = nil;
    unsigned char* pixels = NULL;

    image = [[[NSBitmapImageRep alloc]
        initWithBitmapDataPlanes:NULL
                      pixelsWide:1
                      pixelsHigh:1
                   bitsPerSample:8
                 samplesPerPixel:4
                        hasAlpha:YES
                        isPlanar:NO
                  colorSpaceName:NSCalibratedRGBColorSpace
                     bytesPerRow:4
                    bitsPerPixel:32] autorelease];
    if (!image)
        return nil;
    pixels = [image bitmapData];
    if (!pixels)
        return nil;
    pixels[0] = 0x11u;
    pixels[1] = 0x22u;
    pixels[2] = 0x33u;
    pixels[3] = 0xffu;
    return [image representationUsingType:NSBitmapImageFileTypePNG
                               properties:@{}];
}

static int test_dispatch(cocoa_server_clipboard* clipboard)
{
    return cocoa_server_clipboard_vtable.events->dispatch(clipboard, 32u) ==
           LIBRDP_STATUS_OK;
}

static int test_local_content(cocoa_server_clipboard* clipboard,
                              NSPasteboard* pasteboard,
                              test_clipboard_state* state,
                              const char* path,
                              const uint8_t* file_data,
                              size_t file_data_len)
{
    NSPasteboardItem* item = nil;
    NSData* png = test_png_data();
    NSURL* file_url = nil;
    server_platform_clipboard_file_request file_request;
    librdp_clipboard_file_metadata metadata;
    uint32_t file_count = 0u;
    char name[256];
    size_t name_len = 0u;

    CHECK(clipboard != NULL && pasteboard != nil && state != NULL &&
          path != NULL && png != nil);
    item = [[[NSPasteboardItem alloc] init] autorelease];
    CHECK(item != nil);
    CHECK([item setString:@"local text" forType:NSPasteboardTypeString]);
    CHECK([item setString:@"<b>local html</b>" forType:NSPasteboardTypeHTML]);
    CHECK([item setData:png forType:NSPasteboardTypePNG]);
    file_url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
    CHECK(file_url != nil);
    [pasteboard clearContents];
    CHECK([pasteboard writeObjects:@[ item, file_url ]]);
    CHECK(test_dispatch(clipboard));
    CHECK(state->format_events == 1u);
    CHECK(state->format_count == 4u);
    CHECK(state->local_generation != 0u);
    CHECK(test_has_format(state, LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT));
    CHECK(test_has_format(state, LIBRDP_CLIPBOARD_FORMAT_HTML));
    CHECK(test_has_format(state, LIBRDP_CLIPBOARD_FORMAT_PNG));
    CHECK(test_has_format(state, LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW));

    test_data_reset(state);
    CHECK(cocoa_server_clipboard_vtable.request_data(
              clipboard, 11u, LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT) ==
          LIBRDP_STATUS_OK);
    CHECK(state->data_events == 1u && state->data_final);
    CHECK(state->data_status == LIBRDP_STATUS_OK);
    CHECK(state->data_request_id == 11u);
    CHECK(state->data_len == 22u);
    CHECK(state->data[0] == (uint8_t)'l' && state->data[1] == 0u &&
          state->data[state->data_len - 1u] == 0u);

    test_data_reset(state);
    CHECK(cocoa_server_clipboard_vtable.request_data(
              clipboard, 12u, LIBRDP_CLIPBOARD_FORMAT_HTML) ==
          LIBRDP_STATUS_OK);
    CHECK(state->data_status == LIBRDP_STATUS_OK && state->data_final);
    CHECK(test_contains(state->data,
                        state->data_len,
                        "StartFragment:",
                        sizeof("StartFragment:") - 1u));

    test_data_reset(state);
    CHECK(cocoa_server_clipboard_vtable.request_data(
              clipboard, 13u, LIBRDP_CLIPBOARD_FORMAT_PNG) == LIBRDP_STATUS_OK);
    CHECK(state->data_status == LIBRDP_STATUS_OK && state->data_final &&
          state->data_len > 8u);
    CHECK(memcmp(state->data, "\x89PNG\r\n\x1a\n", 8u) == 0);

    test_data_reset(state);
    CHECK(cocoa_server_clipboard_vtable.request_data(
              clipboard, 14u, LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW) ==
          LIBRDP_STATUS_OK);
    CHECK(state->data_status == LIBRDP_STATUS_OK && state->data_final);
    CHECK(librdp_clipboard_file_group_count(
              state->data, state->data_len, &file_count) == LIBRDP_STATUS_OK);
    CHECK(file_count == 1u);
    CHECK(librdp_clipboard_file_metadata_init(&metadata) == LIBRDP_STATUS_OK);
    CHECK(librdp_clipboard_file_group_get(state->data,
                                          state->data_len,
                                          0u,
                                          &metadata,
                                          name,
                                          sizeof(name),
                                          &name_len) == LIBRDP_STATUS_OK);
    CHECK(metadata.file_size == file_data_len);
    CHECK(name_len > 1u);

    memset(&file_request, 0, sizeof(file_request));
    file_request.peer_id = 9u;
    file_request.generation = 2u;
    file_request.ownership_generation = state->local_generation;
    file_request.request_id = 15u;
    file_request.stream_id = 3u;
    file_request.file_index = 0;
    file_request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    file_request.position = 1u;
    file_request.requested_bytes = 3u;
    test_data_reset(state);
    CHECK(cocoa_server_clipboard_vtable.request_file(
              clipboard, &file_request) == LIBRDP_STATUS_OK);
    CHECK(state->data_status == LIBRDP_STATUS_OK && state->data_final &&
          state->data_stream_id == 3u);
    CHECK(state->data_len == 3u);
    CHECK(memcmp(state->data, file_data + 1u, 3u) == 0);
    return 1;
}

static int test_remote_content(cocoa_server_clipboard* clipboard,
                               NSPasteboard* pasteboard,
                               test_clipboard_state* state)
{
    const server_platform_clipboard_format text_format = {
        LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
        "text/plain;charset=utf-8",
    };
    const uint8_t remote_text[] = {
        (uint8_t)'r',
        0u,
        (uint8_t)'e',
        0u,
        (uint8_t)'m',
        0u,
        (uint8_t)'o',
        0u,
        (uint8_t)'t',
        0u,
        (uint8_t)'e',
        0u,
        0u,
        0u,
    };
    server_platform_clipboard_offer offer;
    server_platform_clipboard_data response;
    size_t local_events = 0u;
    uint64_t pending_id = 0u;

    memset(&offer, 0, sizeof(offer));
    offer.peer_id = 21u;
    offer.generation = 4u;
    offer.ownership_generation = 7u;
    offer.formats = &text_format;
    offer.format_count = 1u;
    state->request_events = 0u;
    CHECK(cocoa_server_clipboard_vtable.publish_formats(clipboard, &offer) ==
          LIBRDP_STATUS_OK);
    CHECK(test_dispatch(clipboard));
    CHECK(state->request_events == 1u);
    CHECK(state->request.peer_id == offer.peer_id);
    CHECK(state->request.generation == offer.generation);
    CHECK(state->request.ownership_generation == offer.ownership_generation);
    CHECK(state->request.format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);

    memset(&response, 0, sizeof(response));
    response.peer_id = offer.peer_id;
    response.generation = offer.generation;
    response.ownership_generation = offer.ownership_generation;
    response.request_id = state->request.request_id;
    response.format_id = state->request.format_id;
    response.status = LIBRDP_STATUS_OK;
    response.data = remote_text;
    response.data_len = sizeof(remote_text);
    response.final_chunk = 1;
    CHECK(cocoa_server_clipboard_vtable.write_data(clipboard, &response) ==
          LIBRDP_STATUS_OK);
    CHECK(test_dispatch(clipboard));
    CHECK([[pasteboard stringForType:NSPasteboardTypeString]
        isEqualToString:@"remote"]);
    local_events = state->format_events;
    CHECK(test_dispatch(clipboard));
    CHECK(state->format_events == local_events);

    offer.ownership_generation = 8u;
    state->request_events = 0u;
    state->cancel_events = 0u;
    CHECK(cocoa_server_clipboard_vtable.publish_formats(clipboard, &offer) ==
          LIBRDP_STATUS_OK);
    CHECK(test_dispatch(clipboard));
    CHECK(state->request_events == 1u);
    pending_id = state->request.request_id;
    cocoa_server_clipboard_vtable.cancel_peer(
        clipboard, offer.peer_id, offer.generation);
    CHECK(state->cancel_events == 1u);
    CHECK(state->cancelled_request_id == pending_id);
    return 1;
}

int main(void)
{
    const uint8_t file_data[] = {
        (uint8_t)'a',
        (uint8_t)'b',
        (uint8_t)'c',
        (uint8_t)'d',
        (uint8_t)'e',
    };
    char pasteboard_name[128];
    char file_path[] = "/tmp/librdp-cocoa-clipboard-XXXXXX";
    int descriptor = -1;
    int ok = 0;
    cocoa_server_clipboard* clipboard = NULL;
    NSPasteboard* pasteboard = nil;
    server_platform_clipboard_sink sink;
    test_clipboard_state state;

    @autoreleasepool
    {
        MAIN_CHECK(snprintf(pasteboard_name,
                            sizeof(pasteboard_name),
                            "org.librdp.test.server.clipboard.%ld",
                            (long)getpid()) > 0);
        descriptor = mkstemp(file_path);
        MAIN_CHECK(descriptor >= 0);
        MAIN_CHECK(write(descriptor, file_data, sizeof(file_data)) ==
                   (ssize_t)sizeof(file_data));
        MAIN_CHECK(close(descriptor) == 0);
        descriptor = -1;

        memset(&state, 0, sizeof(state));
        memset(&sink, 0, sizeof(sink));
        sink.formats = test_formats;
        sink.data = test_data;
        sink.request = test_request;
        sink.file_request = test_file_request;
        sink.cancel = test_cancel;
        sink.user_data = &state;
        clipboard = cocoa_server_clipboard_new_named(pasteboard_name);
        MAIN_CHECK(clipboard != NULL);
        pasteboard = [NSPasteboard
            pasteboardWithName:[NSString stringWithUTF8String:pasteboard_name]];
        MAIN_CHECK(pasteboard != nil);
        MAIN_CHECK(cocoa_server_clipboard_vtable.start(clipboard, &sink) ==
                   LIBRDP_STATUS_OK);
        MAIN_CHECK(test_local_content(clipboard,
                                      pasteboard,
                                      &state,
                                      file_path,
                                      file_data,
                                      sizeof(file_data)));
        MAIN_CHECK(test_remote_content(clipboard, pasteboard, &state));
        ok = 1;

    cleanup_pool:
        if (pasteboard)
            [pasteboard clearContents];
        cocoa_server_clipboard_free(clipboard);
        clipboard = NULL;
    }
    if (descriptor >= 0)
        close(descriptor);
    unlink(file_path);
    return ok ? 0 : 1;
}
