/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Cocoa viewer clipboard bridge tests.
 * Coverage: local text, HTML, PNG and file publication; remote format choice,
 * native pasteboard updates, range-based file transfer, feedback suppression,
 * request correlation and timeout cleanup.
 * Bug classes: format confusion, malformed native or remote data, unbounded
 * allocation, stale stream acceptance, ownership loops and temporary-file
 * lifetime errors.
 * Determinism: process-scoped pasteboards, temporary regular files and an
 * injected monotonic clock avoid the user clipboard, network and wall time.
 */

#include "cocoa_clipboard.h"

#import <Cocoa/Cocoa.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_CLIPBOARD_BYTES (1024u * 1024u)
#define TEST_CLIPBOARD_FILES 32u

typedef struct test_clipboard_capture
{
    uint8_t data[TEST_CLIPBOARD_BYTES];
    size_t data_len;
    uint32_t format_id;
    char format_name[64];
    char file_paths[TEST_CLIPBOARD_FILES][1024];
    char file_names[TEST_CLIPBOARD_FILES][256];
    uint32_t file_count;
    uint32_t stream_id;
    int32_t file_index;
    uint64_t position;
    uint32_t requested;
    size_t set_data_calls;
    size_t set_named_calls;
    size_t set_files_calls;
    size_t clear_calls;
    size_t request_data_calls;
    size_t request_range_calls;
    double now;
} test_clipboard_capture;

static int test_check(int condition,
                      const char* expression,
                      int line)
{
    if (!condition)
    {
        fprintf(stderr,
                "test_cocoa_viewer_clipboard:%d: check failed: %s\n",
                line,
                expression);
    }
    return condition;
}

#define CHECK(expression)                                      \
    do                                                         \
    {                                                          \
        if (!test_check((expression), #expression, __LINE__))  \
            return 0;                                          \
    } while (0)

static void test_capture_reset_data(
    test_clipboard_capture* capture)
{
    if (!capture)
        return;
    capture->data_len = 0u;
    capture->format_id = 0u;
    capture->format_name[0] = '\0';
    capture->file_count = 0u;
    capture->stream_id = 0u;
    capture->file_index = -1;
    capture->position = 0u;
    capture->requested = 0u;
}

static librdp_status test_set_data(void* context,
                                   uint32_t format_id,
                                   const void* data,
                                   size_t data_len)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;

    if (!capture || (!data && data_len > 0u) ||
        data_len > sizeof(capture->data))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    test_capture_reset_data(capture);
    if (data_len > 0u)
        memcpy(capture->data, data, data_len);
    capture->data_len = data_len;
    capture->format_id = format_id;
    capture->set_data_calls++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_set_named_data(void* context,
                                         uint32_t format_id,
                                         const char* format_name,
                                         const void* data,
                                         size_t data_len)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;
    size_t name_len = format_name ? strlen(format_name) : 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!capture || !format_name ||
        name_len >= sizeof(capture->format_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = test_set_data(context,
                           format_id,
                           data,
                           data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memcpy(capture->format_name,
           format_name,
           name_len + 1u);
    capture->set_named_calls++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_set_files(
    void* context,
    const librdp_clipboard_file* files,
    uint32_t count)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;
    uint32_t index = 0u;

    if (!capture || !files || count == 0u ||
        count > TEST_CLIPBOARD_FILES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    test_capture_reset_data(capture);
    for (index = 0u; index < count; index++)
    {
        size_t path_len = files[index].path
                              ? strlen(files[index].path)
                              : 0u;
        size_t name_len = files[index].name
                              ? strlen(files[index].name)
                              : 0u;

        if (path_len == 0u ||
            path_len >= sizeof(capture->file_paths[index]) ||
            name_len == 0u ||
            name_len >= sizeof(capture->file_names[index]))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        memcpy(capture->file_paths[index],
               files[index].path,
               path_len + 1u);
        memcpy(capture->file_names[index],
               files[index].name,
               name_len + 1u);
    }
    capture->file_count = count;
    capture->set_files_calls++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_clear(void* context)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;

    if (!capture)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    test_capture_reset_data(capture);
    capture->clear_calls++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_request_data(void* context,
                                       uint32_t format_id)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;

    if (!capture || format_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    capture->format_id = format_id;
    capture->request_data_calls++;
    return LIBRDP_STATUS_OK;
}

static librdp_status test_request_file_range(
    void* context,
    uint32_t stream_id,
    int32_t file_index,
    uint64_t position,
    uint32_t requested)
{
    test_clipboard_capture* capture =
        (test_clipboard_capture*)context;

    if (!capture || stream_id == 0u || file_index < 0 ||
        requested == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    capture->stream_id = stream_id;
    capture->file_index = file_index;
    capture->position = position;
    capture->requested = requested;
    capture->request_range_calls++;
    return LIBRDP_STATUS_OK;
}

static double test_now(void* context)
{
    const test_clipboard_capture* capture =
        (const test_clipboard_capture*)context;

    return capture ? capture->now : 0.0;
}

static CocoaViewerClipboard* test_bridge(
    NSPasteboard* pasteboard,
    test_clipboard_capture* capture)
{
    const cocoa_viewer_clipboard_callbacks callbacks = {
        test_set_data,
        test_set_named_data,
        test_set_files,
        test_clear,
        test_request_data,
        test_request_file_range,
        test_now,
    };

    return [[CocoaViewerClipboard alloc]
        initWithPasteboard:pasteboard
                  callbacks:&callbacks
                    context:capture];
}

static int test_contains(const uint8_t* data,
                         size_t data_len,
                         const void* expected,
                         size_t expected_len)
{
    size_t index = 0u;

    if (!data || !expected || expected_len == 0u ||
        expected_len > data_len)
        return 0;
    for (index = 0u;
         index <= data_len - expected_len;
         index++)
    {
        if (memcmp(data + index,
                   expected,
                   expected_len) == 0)
            return 1;
    }
    return 0;
}

static int test_write_all(int descriptor,
                          const void* data,
                          size_t data_len)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0u;

    while (offset < data_len)
    {
        ssize_t written = write(descriptor,
                                bytes + offset,
                                data_len - offset);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int test_local_publication(NSPasteboard* pasteboard)
{
    static const uint8_t png[] = {
        0x89u, 'P', 'N', 'G', 0x0du, 0x0au, 0x1au, 0x0au,
        0x00u, 0x01u
    };
    test_clipboard_capture capture;
    CocoaViewerClipboard* bridge = nil;
    NSData* html = nil;
    NSData* png_data = nil;
    NSString* temporary = nil;
    NSURL* file_url = nil;
    int descriptor = -1;
    char path[] = "/tmp/librdp-cocoa-local-XXXXXX";
    int result = 0;

    memset(&capture, 0, sizeof(capture));
    capture.now = 1.0;
    bridge = test_bridge(pasteboard, &capture);
    CHECK(bridge != nil);

    [pasteboard clearContents];
    CHECK([pasteboard setString:@"Local text"
                        forType:NSPasteboardTypeString]);
    CHECK([bridge poll] == LIBRDP_STATUS_OK);
    CHECK(capture.set_data_calls == 1u);
    CHECK(capture.format_id ==
          LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
    CHECK(capture.data_len == 22u);
    CHECK(capture.data[capture.data_len - 2u] == 0u);
    CHECK(capture.data[capture.data_len - 1u] == 0u);

    html = [@"<b>Local HTML</b>"
        dataUsingEncoding:NSUTF8StringEncoding];
    [pasteboard clearContents];
    CHECK([pasteboard setData:html
                       forType:NSPasteboardTypeHTML]);
    CHECK([bridge poll] == LIBRDP_STATUS_OK);
    CHECK(capture.set_named_calls == 1u);
    CHECK(capture.format_id == LIBRDP_CLIPBOARD_FORMAT_HTML);
    CHECK(strcmp(capture.format_name,
                 LIBRDP_CLIPBOARD_FORMAT_NAME_HTML) == 0);
    CHECK(test_contains(capture.data,
                        capture.data_len,
                        "StartFragment:",
                        strlen("StartFragment:")));
    CHECK(test_contains(capture.data,
                        capture.data_len,
                        [html bytes],
                        (size_t)[html length]));

    png_data = [NSData dataWithBytes:png length:sizeof(png)];
    [pasteboard clearContents];
    CHECK([pasteboard setData:png_data
                       forType:NSPasteboardTypePNG]);
    CHECK([bridge poll] == LIBRDP_STATUS_OK);
    CHECK(capture.set_named_calls == 2u);
    CHECK(capture.format_id == LIBRDP_CLIPBOARD_FORMAT_PNG);
    CHECK(capture.data_len == sizeof(png));
    CHECK(memcmp(capture.data, png, sizeof(png)) == 0);

    descriptor = mkstemp(path);
    CHECK(descriptor >= 0);
    CHECK(test_write_all(descriptor, "local", 5u));
    CHECK(close(descriptor) == 0);
    descriptor = -1;
    temporary = [NSString stringWithUTF8String:path];
    file_url = [NSURL fileURLWithPath:temporary];
    [pasteboard clearContents];
    CHECK([pasteboard writeObjects:@[ file_url ]]);
    CHECK([bridge poll] == LIBRDP_STATUS_OK);
    CHECK(capture.set_files_calls == 1u);
    CHECK(capture.file_count == 1u);
    CHECK(strcmp(capture.file_paths[0], path) == 0);
    CHECK(strcmp(capture.file_names[0],
                 [temporary lastPathComponent].UTF8String) == 0);
    result = 1;

    [bridge shutdown];
#if !__has_feature(objc_arc)
    [bridge release];
#endif
    if (descriptor >= 0)
        close(descriptor);
    (void)unlink(path);
    return result;
}

static librdp_status test_deliver(
    CocoaViewerClipboard* bridge,
    librdp_event_type type,
    const void* payload,
    size_t payload_size)
{
    librdp_event_envelope envelope;

    if (librdp_event_envelope_init(&envelope) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    envelope.type = type;
    envelope.payload = payload;
    envelope.payload_size = payload_size;
    return [bridge handleEnvelope:&envelope];
}

static int test_remote_native_formats(NSPasteboard* pasteboard)
{
    static const uint8_t utf16[] = {
        'R', 0u, 'e', 0u, 'm', 0u, 'o', 0u, 't', 0u, 'e', 0u,
        0u, 0u
    };
    static const uint8_t html_name[] = {
        'H', 0u, 'T', 0u, 'M', 0u, 'L', 0u, ' ', 0u,
        'F', 0u, 'o', 0u, 'r', 0u, 'm', 0u, 'a', 0u, 't', 0u
    };
    static const char html[] =
        "Version:0.9\r\n"
        "StartHTML:0000000105\r\n"
        "EndHTML:0000000182\r\n"
        "StartFragment:0000000137\r\n"
        "EndFragment:0000000150\r\n"
        "<html><body><!--StartFragment-->"
        "<b>remote</b>"
        "<!--EndFragment--></body></html>";
    static const uint8_t png[] = {
        0x89u, 'P', 'N', 'G', 0x0du, 0x0au, 0x1au, 0x0au,
        0x02u, 0x03u
    };
    test_clipboard_capture capture;
    CocoaViewerClipboard* bridge = nil;
    librdp_clipboard_format format;
    librdp_clipboard_formats_event formats;
    librdp_clipboard_data_event data;
    size_t local_calls = 0u;

    memset(&capture, 0, sizeof(capture));
    memset(&format, 0, sizeof(format));
    memset(&formats, 0, sizeof(formats));
    memset(&data, 0, sizeof(data));
    capture.now = 10.0;
    bridge = test_bridge(pasteboard, &capture);
    CHECK(bridge != nil);

    format.format_id = LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    formats.formats = &format;
    formats.count = 1u;
    formats.total_count = 1u;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    CHECK(capture.request_data_calls == 1u);
    CHECK(capture.format_id == format.format_id);
    data.format_id = format.format_id;
    data.data = utf16;
    data.data_len = sizeof(utf16);
    data.ok = 1;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    CHECK([[pasteboard stringForType:NSPasteboardTypeString]
              isEqualToString:@"Remote"]);
    local_calls = capture.set_data_calls;
    CHECK([bridge poll] == LIBRDP_STATUS_OK);
    CHECK(capture.set_data_calls == local_calls);

    format.format_id = 0xd123u;
    format.name = html_name;
    format.name_len = sizeof(html_name);
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    CHECK(capture.format_id == format.format_id);
    data.format_id = format.format_id;
    data.data = (const uint8_t*)html;
    data.data_len = sizeof(html) - 1u;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    CHECK([[pasteboard dataForType:NSPasteboardTypeHTML]
              isEqualToData:[NSData dataWithBytes:"<b>remote</b>"
                                          length:strlen("<b>remote</b>")]]);

    format.format_id = LIBRDP_CLIPBOARD_FORMAT_PNG;
    format.name = NULL;
    format.name_len = 0u;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    data.format_id = format.format_id;
    data.data = png;
    data.data_len = sizeof(png);
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    CHECK([[pasteboard dataForType:NSPasteboardTypePNG]
              isEqualToData:[NSData dataWithBytes:png
                                            length:sizeof(png)]]);

    [bridge shutdown];
#if !__has_feature(objc_arc)
    [bridge release];
#endif
    return 1;
}

static int test_remote_file_transfer(NSPasteboard* pasteboard)
{
    static const uint8_t contents[] = {
        'r', 'e', 'm', 'o', 't', 'e'
    };
    test_clipboard_capture capture;
    CocoaViewerClipboard* bridge = nil;
    librdp_clipboard_file_metadata metadata;
    librdp_clipboard_format format;
    librdp_clipboard_formats_event formats;
    librdp_clipboard_data_event data;
    librdp_clipboard_file_contents_event range;
    uint8_t* encoded = NULL;
    size_t encoded_len = 0u;
    NSArray* urls = nil;
    NSData* downloaded = nil;

    memset(&capture, 0, sizeof(capture));
    memset(&format, 0, sizeof(format));
    memset(&formats, 0, sizeof(formats));
    memset(&data, 0, sizeof(data));
    memset(&range, 0, sizeof(range));
    capture.now = 20.0;
    CHECK(librdp_clipboard_file_metadata_init(&metadata) ==
          LIBRDP_STATUS_OK);
    metadata.name = "remote.bin";
    metadata.file_size = sizeof(contents);
    CHECK(librdp_clipboard_file_group_encode(
              &metadata,
              1u,
              NULL,
              0u,
              &encoded_len) == LIBRDP_STATUS_OK);
    encoded = (uint8_t*)malloc(encoded_len);
    CHECK(encoded != NULL);
    CHECK(librdp_clipboard_file_group_encode(
              &metadata,
              1u,
              encoded,
              encoded_len,
              &encoded_len) == LIBRDP_STATUS_OK);
    bridge = test_bridge(pasteboard, &capture);
    CHECK(bridge != nil);

    format.format_id =
        LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW;
    formats.formats = &format;
    formats.count = 1u;
    formats.total_count = 1u;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    data.format_id = format.format_id;
    data.data = encoded;
    data.data_len = encoded_len;
    data.ok = 1;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    CHECK(capture.request_range_calls == 1u);
    CHECK(capture.file_index == 0);
    CHECK(capture.position == 0u);
    CHECK(capture.requested == sizeof(contents));

    range.stream_id = capture.stream_id + 1u;
    range.file_index = 0;
    range.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    range.position = 0u;
    range.requested = capture.requested;
    range.data = contents;
    range.data_len = sizeof(contents);
    range.ok = 1;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS,
                       &range,
                       sizeof(range)) == LIBRDP_STATUS_PROTOCOL_ERROR);

    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    range.stream_id = capture.stream_id;
    range.requested = capture.requested;
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS,
                       &range,
                       sizeof(range)) == LIBRDP_STATUS_OK);
    urls = [pasteboard
        readObjectsForClasses:@[ [NSURL class] ]
                      options:@{
                          NSPasteboardURLReadingFileURLsOnlyKey : @YES
                      }];
    CHECK([urls count] == 1u);
    downloaded = [NSData dataWithContentsOfURL:[urls objectAtIndex:0]];
    CHECK(downloaded != nil);
    CHECK([downloaded length] == sizeof(contents));
    CHECK(memcmp([downloaded bytes],
                 contents,
                 sizeof(contents)) == 0);

    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_FORMATS,
                       &formats,
                       sizeof(formats)) == LIBRDP_STATUS_OK);
    CHECK(test_deliver(bridge,
                       LIBRDP_EVENT_CLIPBOARD_DATA,
                       &data,
                       sizeof(data)) == LIBRDP_STATUS_OK);
    capture.now += 16.0;
    CHECK([bridge poll] == LIBRDP_STATUS_TIMEOUT);

    [bridge shutdown];
#if !__has_feature(objc_arc)
    [bridge release];
#endif
    free(encoded);
    return 1;
}

int main(void)
{
    int result = 1;

    @autoreleasepool
    {
        NSPasteboard* pasteboard =
            [NSPasteboard pasteboardWithUniqueName];

        if (!pasteboard ||
            !test_local_publication(pasteboard) ||
            !test_remote_native_formats(pasteboard) ||
            !test_remote_file_transfer(pasteboard))
            result = 0;
        [pasteboard releaseGlobally];
    }
    return result ? 0 : 1;
}
