/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer pasteboard bridge.
 * Invariants: pasteboard ownership generations suppress feedback, one bounded
 * remote request is active at a time, and file URLs are published only after
 * exact range completion.
 * Ownership: the bridge owns remote file descriptors, secure temporary paths,
 * and copied metadata; callback and event payloads remain caller-owned.
 * Threading: synchronous AppKit/session-owner thread only.
 * Trust boundary: pasteboard types, UTF encodings, file metadata, offsets,
 * lengths, filesystem object types, and remote response correlation are checked
 * before allocation, writing, or publication.
 */

#include "cocoa_clipboard.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define COCOA_VIEWER_CLIPBOARD_MAX_BYTES (16u * 1024u * 1024u)
#define COCOA_VIEWER_CLIPBOARD_MAX_FILES 32u
#define COCOA_VIEWER_CLIPBOARD_MAX_FILE_BYTES (256u * 1024u * 1024u)
#define COCOA_VIEWER_CLIPBOARD_MAX_TOTAL_FILE_BYTES (512u * 1024u * 1024u)
#define COCOA_VIEWER_CLIPBOARD_FILE_CHUNK 65536u
#define COCOA_VIEWER_CLIPBOARD_FILE_TIMEOUT 15.0
#define COCOA_VIEWER_CLIPBOARD_MAX_FORMATS 256u

typedef enum cocoa_viewer_remote_kind
{
    COCOA_VIEWER_REMOTE_NONE = 0,
    COCOA_VIEWER_REMOTE_TEXT = 1,
    COCOA_VIEWER_REMOTE_HTML = 2,
    COCOA_VIEWER_REMOTE_PNG = 3,
    COCOA_VIEWER_REMOTE_FILES = 4
} cocoa_viewer_remote_kind;

typedef struct cocoa_viewer_remote_file
{
    char* name;
    char* path;
    uint64_t size;
    uint64_t received;
    int descriptor;
} cocoa_viewer_remote_file;

struct cocoa_viewer_clipboard_state
{
    __unsafe_unretained NSPasteboard* pasteboard;
    cocoa_viewer_clipboard_callbacks callbacks;
    void* context;
    NSInteger observed_change_count;
    NSInteger remote_change_count;
    cocoa_viewer_remote_kind pending_kind;
    uint32_t pending_format_id;
    cocoa_viewer_remote_file files[COCOA_VIEWER_CLIPBOARD_MAX_FILES];
    uint32_t file_count;
    uint32_t current_file;
    uint32_t pending_stream_id;
    uint32_t next_stream_id;
    uint32_t pending_requested;
    uint64_t pending_position;
    double pending_deadline;
    char* temporary_directory;
    int stopped;
};

static librdp_status cocoa_clipboard_session_set_data(
    void* context,
    uint32_t format_id,
    const void* data,
    size_t data_len)
{
    return librdp_session_clipboard_set_data(
        (librdp_session*)context,
        format_id,
        data,
        data_len);
}

static librdp_status cocoa_clipboard_session_set_named_data(
    void* context,
    uint32_t format_id,
    const char* format_name,
    const void* data,
    size_t data_len)
{
    return librdp_session_clipboard_set_named_data(
        (librdp_session*)context,
        format_id,
        format_name,
        data,
        data_len);
}

static librdp_status cocoa_clipboard_session_set_files(
    void* context,
    const librdp_clipboard_file* files,
    uint32_t count)
{
    return librdp_session_clipboard_set_files(
        (librdp_session*)context,
        files,
        count);
}

static librdp_status cocoa_clipboard_session_clear(void* context)
{
    return librdp_session_clipboard_clear(
        (librdp_session*)context);
}

static librdp_status cocoa_clipboard_session_request_data(
    void* context,
    uint32_t format_id)
{
    return librdp_session_clipboard_request_data(
        (librdp_session*)context,
        format_id);
}

static librdp_status cocoa_clipboard_session_request_file_range(
    void* context,
    uint32_t stream_id,
    int32_t file_index,
    uint64_t position,
    uint32_t requested)
{
    return librdp_session_clipboard_request_file_range(
        (librdp_session*)context,
        stream_id,
        file_index,
        position,
        requested);
}

static double cocoa_clipboard_monotonic_now(void* context)
{
    struct timespec now;

    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1.0;
    return (double)now.tv_sec +
           (double)now.tv_nsec / 1000000000.0;
}

static int cocoa_clipboard_callbacks_valid(
    const cocoa_viewer_clipboard_callbacks* callbacks)
{
    return callbacks && callbacks->set_data &&
           callbacks->set_named_data && callbacks->set_files &&
           callbacks->clear && callbacks->request_data &&
           callbacks->request_file_range && callbacks->now;
}

static char* cocoa_clipboard_strdup(const char* text)
{
    size_t length = text ? strlen(text) : 0u;
    char* copy = NULL;

    if (!text || length == 0u || length == SIZE_MAX)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (copy)
        memcpy(copy, text, length + 1u);
    return copy;
}

static void cocoa_clipboard_remove_directory(const char* path)
{
    if (path)
        (void)rmdir(path);
}

static void cocoa_clipboard_files_clear(
    cocoa_viewer_clipboard_state* state)
{
    uint32_t index = 0u;

    if (!state)
        return;
    for (index = 0u; index < state->file_count; index++)
    {
        if (state->files[index].descriptor >= 0)
            close(state->files[index].descriptor);
        if (state->files[index].path)
            (void)unlink(state->files[index].path);
        free(state->files[index].name);
        free(state->files[index].path);
        memset(&state->files[index],
               0,
               sizeof(state->files[index]));
        state->files[index].descriptor = -1;
    }
    cocoa_clipboard_remove_directory(
        state->temporary_directory);
    free(state->temporary_directory);
    state->temporary_directory = NULL;
    state->file_count = 0u;
    state->current_file = 0u;
    state->pending_stream_id = 0u;
    state->pending_requested = 0u;
    state->pending_position = 0u;
    state->pending_deadline = 0.0;
}

static void cocoa_clipboard_remote_reset(
    cocoa_viewer_clipboard_state* state)
{
    if (!state)
        return;
    cocoa_clipboard_files_clear(state);
    state->pending_kind = COCOA_VIEWER_REMOTE_NONE;
    state->pending_format_id = 0u;
}

static librdp_status cocoa_clipboard_remote_fail(
    cocoa_viewer_clipboard_state* state,
    librdp_status status)
{
    cocoa_clipboard_remote_reset(state);
    return status;
}

static NSString* cocoa_clipboard_string(const uint8_t* data,
                                        size_t data_len,
                                        NSStringEncoding encoding)
{
    NSString* string = nil;

    if (!data && data_len > 0u)
        return nil;
    if (data_len == 0u)
        return @"";
    string = [[NSString alloc] initWithBytes:data
                                      length:data_len
                                    encoding:encoding];
#if !__has_feature(objc_arc)
    return [string autorelease];
#else
    return string;
#endif
}

static int cocoa_clipboard_write_decimal(uint8_t* output,
                                         size_t value)
{
    char digits[11];

    if (!output || value > 9999999999u)
        return 0;
    if (snprintf(digits, sizeof(digits), "%010zu", value) != 10)
        return 0;
    memcpy(output, digits, 10u);
    return 1;
}

static librdp_status cocoa_clipboard_package_html(
    NSData* html,
    uint8_t** output,
    size_t* output_len)
{
    static const char header[] =
        "Version:0.9\r\n"
        "StartHTML:0000000000\r\n"
        "EndHTML:0000000000\r\n"
        "StartFragment:0000000000\r\n"
        "EndFragment:0000000000\r\n";
    static const char prefix[] =
        "<html><body><!--StartFragment-->";
    static const char suffix[] =
        "<!--EndFragment--></body></html>";
    const size_t header_len = sizeof(header) - 1u;
    const size_t prefix_len = sizeof(prefix) - 1u;
    const size_t suffix_len = sizeof(suffix) - 1u;
    size_t html_len = html ? (size_t)[html length] : 0u;
    size_t total = 0u;
    size_t fragment_start = 0u;
    size_t fragment_end = 0u;
    uint8_t* buffer = NULL;

    if (!html || !output || !output_len ||
        html_len > COCOA_VIEWER_CLIPBOARD_MAX_BYTES ||
        html_len > SIZE_MAX - header_len - prefix_len - suffix_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = header_len + prefix_len + html_len + suffix_len;
    buffer = (uint8_t*)malloc(total);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(buffer, header, header_len);
    fragment_start = header_len + prefix_len;
    fragment_end = fragment_start + html_len;
    if (!cocoa_clipboard_write_decimal(
            buffer + 23u, header_len) ||
        !cocoa_clipboard_write_decimal(
            buffer + 43u, total) ||
        !cocoa_clipboard_write_decimal(
            buffer + 69u, fragment_start) ||
        !cocoa_clipboard_write_decimal(
            buffer + 93u, fragment_end))
    {
        free(buffer);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memcpy(buffer + header_len, prefix, prefix_len);
    if (html_len > 0u)
    {
        memcpy(buffer + fragment_start,
               [html bytes],
               html_len);
    }
    memcpy(buffer + fragment_end, suffix, suffix_len);
    *output = buffer;
    *output_len = total;
    return LIBRDP_STATUS_OK;
}

static int cocoa_clipboard_html_offset(const uint8_t* data,
                                       size_t data_len,
                                       const char* key,
                                       size_t* value)
{
    size_t key_len = key ? strlen(key) : 0u;
    size_t index = 0u;

    if (!data || !key || !value || key_len == 0u)
        return 0;
    for (index = 0u; index + key_len < data_len; index++)
    {
        size_t cursor = 0u;
        size_t parsed = 0u;
        size_t digits = 0u;

        if (memcmp(data + index, key, key_len) != 0)
            continue;
        cursor = index + key_len;
        while (cursor < data_len &&
               data[cursor] >= (uint8_t)'0' &&
               data[cursor] <= (uint8_t)'9')
        {
            size_t digit =
                (size_t)(data[cursor] - (uint8_t)'0');

            if (parsed > (SIZE_MAX - digit) / 10u)
                return 0;
            parsed = parsed * 10u + digit;
            cursor++;
            digits++;
        }
        if (digits == 0u)
            return 0;
        *value = parsed;
        return 1;
    }
    return 0;
}

static NSData* cocoa_clipboard_extract_html(const uint8_t* data,
                                            size_t data_len)
{
    size_t start = 0u;
    size_t end = 0u;

    if (!data || data_len > COCOA_VIEWER_CLIPBOARD_MAX_BYTES ||
        !cocoa_clipboard_html_offset(
            data, data_len, "StartFragment:", &start) ||
        !cocoa_clipboard_html_offset(
            data, data_len, "EndFragment:", &end) ||
        start > end || end > data_len)
        return nil;
    return [NSData dataWithBytes:data + start
                          length:end - start];
}

static int cocoa_clipboard_utf16_name_equals(
    const librdp_clipboard_format* format,
    const char* expected)
{
    size_t expected_len = expected ? strlen(expected) : 0u;
    size_t encoded_len = 0u;
    size_t index = 0u;

    if (!format || !format->name || expected_len == 0u ||
        expected_len > SIZE_MAX / 2u ||
        (format->name_len & 1u) != 0u)
        return 0;
    encoded_len = expected_len * 2u;
    if (format->name_len != encoded_len)
        return 0;
    for (index = 0u; index < expected_len; index++)
    {
        unsigned char actual = format->name[index * 2u];
        unsigned char high = format->name[index * 2u + 1u];
        unsigned char wanted = (unsigned char)expected[index];

        if (high != 0u)
            return 0;
        if (actual >= (unsigned char)'A' &&
            actual <= (unsigned char)'Z')
            actual = (unsigned char)(actual +
                                     ((unsigned char)'a' -
                                      (unsigned char)'A'));
        if (wanted >= (unsigned char)'A' &&
            wanted <= (unsigned char)'Z')
            wanted = (unsigned char)(wanted +
                                     ((unsigned char)'a' -
                                      (unsigned char)'A'));
        if (actual != wanted)
            return 0;
    }
    return 1;
}

static librdp_status cocoa_clipboard_publish_local_files(
    cocoa_viewer_clipboard_state* state,
    NSArray* urls)
{
    librdp_clipboard_file files[COCOA_VIEWER_CLIPBOARD_MAX_FILES];
    uint32_t count = 0u;

    if (!state || !urls || [urls count] == 0u ||
        [urls count] > COCOA_VIEWER_CLIPBOARD_MAX_FILES)
        return LIBRDP_STATUS_UNSUPPORTED;
    memset(files, 0, sizeof(files));
    for (NSURL* url in urls)
    {
        NSString* path = nil;
        NSString* name = nil;
        struct stat attributes;

        if (![url isFileURL])
            return LIBRDP_STATUS_UNSUPPORTED;
        path = [url path];
        name = [url lastPathComponent];
        if (!path || !name || [name length] == 0u ||
            lstat([path fileSystemRepresentation], &attributes) != 0 ||
            !S_ISREG(attributes.st_mode))
            return LIBRDP_STATUS_UNSUPPORTED;
        files[count].path = [path fileSystemRepresentation];
        files[count].name = [name UTF8String];
        if (!files[count].path || !files[count].name)
            return LIBRDP_STATUS_UNSUPPORTED;
        count++;
    }
    return state->callbacks.set_files(
        state->context, files, count);
}

/*
 * Publish exactly one native representation in descending fidelity order.
 * Callback arguments remain borrowed for the call, and no lower-priority
 * representation is attempted after a selected format fails validation.
 */
static librdp_status cocoa_clipboard_publish_local(
    cocoa_viewer_clipboard_state* state)
{
    NSDictionary* options = @{
        NSPasteboardURLReadingFileURLsOnlyKey : @YES
    };
    NSArray* urls = nil;
    NSData* data = nil;
    NSString* string = nil;
    librdp_status status = LIBRDP_STATUS_UNSUPPORTED;

    if (!state || !state->pasteboard)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    urls = [state->pasteboard
        readObjectsForClasses:@[ [NSURL class] ]
                      options:options];
    if ([urls count] > 0u)
    {
        status = cocoa_clipboard_publish_local_files(
            state, urls);
        if (status != LIBRDP_STATUS_UNSUPPORTED)
            return status;
    }
    data = [state->pasteboard dataForType:NSPasteboardTypeHTML];
    if (data && [data length] <=
                    COCOA_VIEWER_CLIPBOARD_MAX_BYTES)
    {
        uint8_t* packaged = NULL;
        size_t packaged_len = 0u;

        status = cocoa_clipboard_package_html(
            data, &packaged, &packaged_len);
        if (status == LIBRDP_STATUS_OK)
        {
            status = state->callbacks.set_named_data(
                state->context,
                LIBRDP_CLIPBOARD_FORMAT_HTML,
                LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
                packaged,
                packaged_len);
        }
        free(packaged);
        return status;
    }
    data = [state->pasteboard dataForType:NSPasteboardTypePNG];
    if (data && [data length] > 0u &&
        [data length] <= COCOA_VIEWER_CLIPBOARD_MAX_BYTES)
    {
        static const uint8_t signature[] = {
            0x89u, (uint8_t)'P', (uint8_t)'N', (uint8_t)'G',
            0x0du, 0x0au, 0x1au, 0x0au
        };

        if ([data length] < sizeof(signature) ||
            memcmp([data bytes], signature, sizeof(signature)) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return state->callbacks.set_named_data(
            state->context,
            LIBRDP_CLIPBOARD_FORMAT_PNG,
            LIBRDP_CLIPBOARD_FORMAT_NAME_PNG,
            [data bytes],
            (size_t)[data length]);
    }
    string = [state->pasteboard
        stringForType:NSPasteboardTypeString];
    if (string)
    {
        NSData* utf16 = [string
            dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        NSMutableData* terminated = nil;
        const uint8_t terminator[2] = { 0u, 0u };

        if (!utf16 || [utf16 length] >
                          COCOA_VIEWER_CLIPBOARD_MAX_BYTES -
                              sizeof(terminator))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        terminated = [NSMutableData dataWithData:utf16];
        if (!terminated)
            return LIBRDP_STATUS_NO_MEMORY;
        [terminated appendBytes:terminator
                         length:sizeof(terminator)];
        return state->callbacks.set_data(
            state->context,
            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
            [terminated bytes],
            (size_t)[terminated length]);
    }
    return state->callbacks.clear(state->context);
}

/*
 * Validate a correlated remote response before replacing native ownership.
 * The pasteboard is changed only after conversion succeeds; any failed commit
 * clears pending remote state so stale responses cannot be accepted later.
 */
static librdp_status cocoa_clipboard_publish_remote_data(
    cocoa_viewer_clipboard_state* state,
    const librdp_clipboard_data_event* event)
{
    NSData* native = nil;
    NSString* string = nil;
    BOOL published = NO;

    if (!state || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->format_id != state->pending_format_id ||
        (!event->data && event->data_len > 0u) ||
        event->data_len > COCOA_VIEWER_CLIPBOARD_MAX_BYTES)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_PROTOCOL_ERROR);
    if (!event->ok)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_IO_ERROR);
    if (state->pending_kind == COCOA_VIEWER_REMOTE_TEXT)
    {
        if (event->format_id ==
            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
        {
            size_t length = event->data_len;

            if ((length & 1u) != 0u)
                return cocoa_clipboard_remote_fail(
                    state, LIBRDP_STATUS_PROTOCOL_ERROR);
            while (length >= 2u &&
                   event->data[length - 2u] == 0u &&
                   event->data[length - 1u] == 0u)
                length -= 2u;
            string = cocoa_clipboard_string(
                event->data,
                length,
                NSUTF16LittleEndianStringEncoding);
        }
        else
        {
            string = cocoa_clipboard_string(
                event->data,
                event->data_len,
                NSUTF8StringEncoding);
            if (!string)
            {
                string = cocoa_clipboard_string(
                    event->data,
                    event->data_len,
                    NSISOLatin1StringEncoding);
            }
        }
        if (!string)
            return cocoa_clipboard_remote_fail(
                state, LIBRDP_STATUS_PROTOCOL_ERROR);
        [state->pasteboard clearContents];
        published = [state->pasteboard
            setString:string
              forType:NSPasteboardTypeString];
    }
    else if (state->pending_kind ==
             COCOA_VIEWER_REMOTE_HTML)
    {
        native = cocoa_clipboard_extract_html(
            event->data, event->data_len);
        if (!native)
            return cocoa_clipboard_remote_fail(
                state, LIBRDP_STATUS_PROTOCOL_ERROR);
        [state->pasteboard clearContents];
        published = [state->pasteboard
            setData:native
             forType:NSPasteboardTypeHTML];
    }
    else if (state->pending_kind ==
             COCOA_VIEWER_REMOTE_PNG)
    {
        static const uint8_t signature[] = {
            0x89u, (uint8_t)'P', (uint8_t)'N', (uint8_t)'G',
            0x0du, 0x0au, 0x1au, 0x0au
        };

        if (event->data_len < sizeof(signature) ||
            memcmp(event->data,
                   signature,
                   sizeof(signature)) != 0)
            return cocoa_clipboard_remote_fail(
                state, LIBRDP_STATUS_PROTOCOL_ERROR);
        native = [NSData dataWithBytes:event->data
                                length:event->data_len];
        [state->pasteboard clearContents];
        published = [state->pasteboard
            setData:native
             forType:NSPasteboardTypePNG];
    }
    else
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_STATE);
    if (!published)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_IO_ERROR);
    state->remote_change_count =
        [state->pasteboard changeCount];
    state->observed_change_count =
        state->remote_change_count;
    state->pending_kind = COCOA_VIEWER_REMOTE_NONE;
    state->pending_format_id = 0u;
    return LIBRDP_STATUS_OK;
}

static int cocoa_clipboard_create_temp_directory(
    cocoa_viewer_clipboard_state* state)
{
    char pattern[] =
        "/tmp/librdp-cocoa-clipboard-XXXXXX";
    char* directory = NULL;

    if (!state)
        return 0;
    directory = mkdtemp(pattern);
    if (!directory || chmod(directory, 0700) != 0)
    {
        if (directory)
            (void)rmdir(directory);
        return 0;
    }
    state->temporary_directory =
        cocoa_clipboard_strdup(directory);
    if (!state->temporary_directory)
    {
        (void)rmdir(directory);
        return 0;
    }
    return 1;
}

static int cocoa_clipboard_file_name_valid(const char* name)
{
    return name && name[0] != '\0' &&
           strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 &&
           strchr(name, '/') == NULL &&
           strchr(name, '\\') == NULL;
}

static librdp_status cocoa_clipboard_request_next_range(
    cocoa_viewer_clipboard_state* state);

static librdp_status cocoa_clipboard_publish_remote_files(
    cocoa_viewer_clipboard_state* state)
{
    NSMutableArray* urls = nil;
    uint32_t index = 0u;

    if (!state || state->file_count == 0u)
        return LIBRDP_STATUS_STATE;
    urls = [NSMutableArray arrayWithCapacity:state->file_count];
    for (index = 0u; index < state->file_count; index++)
    {
        NSURL* url = nil;

        if (!state->files[index].path ||
            state->files[index].received !=
                state->files[index].size)
            return LIBRDP_STATUS_STATE;
        url = [NSURL fileURLWithPath:
                         [NSString stringWithUTF8String:
                                      state->files[index].path]];
        if (!url)
            return LIBRDP_STATUS_NO_MEMORY;
        [urls addObject:url];
    }
    [state->pasteboard clearContents];
    if (![state->pasteboard writeObjects:urls])
        return LIBRDP_STATUS_IO_ERROR;
    state->remote_change_count =
        [state->pasteboard changeCount];
    state->observed_change_count =
        state->remote_change_count;
    state->pending_kind = COCOA_VIEWER_REMOTE_NONE;
    state->pending_format_id = 0u;
    state->pending_stream_id = 0u;
    return LIBRDP_STATUS_OK;
}

/*
 * Materialize validated file descriptors inside one private temporary root.
 * Names cannot escape that root, every file is created exclusively without
 * following links, and partial setup is removed before any error is returned.
 */
static librdp_status cocoa_clipboard_start_remote_files(
    cocoa_viewer_clipboard_state* state,
    const librdp_clipboard_data_event* event)
{
    uint32_t count = 0u;
    uint32_t index = 0u;
    uint64_t total_size = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->format_id != state->pending_format_id)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_PROTOCOL_ERROR);
    if (!event->ok)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_IO_ERROR);
    if (!event->data || event->data_len == 0u)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_PROTOCOL_ERROR);
    status = librdp_clipboard_file_group_count(
        event->data, event->data_len, &count);
    if (status != LIBRDP_STATUS_OK || count == 0u ||
        count > COCOA_VIEWER_CLIPBOARD_MAX_FILES)
        return status == LIBRDP_STATUS_OK
                   ? LIBRDP_STATUS_LIMIT_EXCEEDED
                   : status;
    cocoa_clipboard_files_clear(state);
    if (!cocoa_clipboard_create_temp_directory(state))
        return LIBRDP_STATUS_IO_ERROR;
    state->file_count = count;
    for (index = 0u; index < count; index++)
    {
        librdp_clipboard_file_metadata metadata;
        size_t name_length = 0u;
        char* name = NULL;
        size_t path_length = 0u;
        char* path = NULL;

        state->files[index].descriptor = -1;
        status = librdp_clipboard_file_metadata_init(
            &metadata);
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_clipboard_file_group_get(
                event->data,
                event->data_len,
                index,
                &metadata,
                NULL,
                0u,
                &name_length);
        }
        if (status != LIBRDP_STATUS_OK || name_length < 2u ||
            name_length > NAME_MAX + 1u)
            break;
        name = (char*)malloc(name_length);
        if (!name)
        {
            status = LIBRDP_STATUS_NO_MEMORY;
            break;
        }
        status = librdp_clipboard_file_group_get(
            event->data,
            event->data_len,
            index,
            &metadata,
            name,
            name_length,
            &name_length);
        if (status != LIBRDP_STATUS_OK ||
            !cocoa_clipboard_file_name_valid(name) ||
            (metadata.attributes &
             LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_DIRECTORY) != 0u ||
            metadata.file_size >
                COCOA_VIEWER_CLIPBOARD_MAX_FILE_BYTES ||
            total_size >
                COCOA_VIEWER_CLIPBOARD_MAX_TOTAL_FILE_BYTES -
                    metadata.file_size)
        {
            free(name);
            status = status == LIBRDP_STATUS_OK
                         ? LIBRDP_STATUS_LIMIT_EXCEEDED
                         : status;
            break;
        }
        total_size += metadata.file_size;
        path_length = strlen(state->temporary_directory) +
                      1u + strlen(name) + 1u;
        path = (char*)malloc(path_length);
        if (!path)
        {
            free(name);
            status = LIBRDP_STATUS_NO_MEMORY;
            break;
        }
        if (snprintf(path,
                     path_length,
                     "%s/%s",
                     state->temporary_directory,
                     name) != (int)(path_length - 1u))
        {
            free(name);
            free(path);
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        state->files[index].descriptor =
            open(path,
                 O_WRONLY | O_CREAT | O_EXCL |
                     O_NOFOLLOW | O_CLOEXEC,
                 0600);
        if (state->files[index].descriptor < 0)
        {
            free(name);
            free(path);
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        state->files[index].name = name;
        state->files[index].path = path;
        state->files[index].size = metadata.file_size;
    }
    if (status != LIBRDP_STATUS_OK || index != count)
    {
        cocoa_clipboard_remote_reset(state);
        return status == LIBRDP_STATUS_OK
                   ? LIBRDP_STATUS_PROTOCOL_ERROR
                   : status;
    }
    state->current_file = 0u;
    return cocoa_clipboard_request_next_range(state);
}

static librdp_status cocoa_clipboard_request_next_range(
    cocoa_viewer_clipboard_state* state)
{
    cocoa_viewer_remote_file* file = NULL;
    uint64_t remaining = 0u;
    uint32_t requested = 0u;
    uint32_t stream_id = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (state->current_file < state->file_count &&
           state->files[state->current_file].received ==
               state->files[state->current_file].size)
    {
        if (state->files[state->current_file].descriptor >= 0)
        {
            close(state->files[state->current_file].descriptor);
            state->files[state->current_file].descriptor = -1;
        }
        state->current_file++;
    }
    if (state->current_file >= state->file_count)
        return cocoa_clipboard_publish_remote_files(state);
    file = &state->files[state->current_file];
    remaining = file->size - file->received;
    requested = remaining > COCOA_VIEWER_CLIPBOARD_FILE_CHUNK
                    ? COCOA_VIEWER_CLIPBOARD_FILE_CHUNK
                    : (uint32_t)remaining;
    stream_id = state->next_stream_id++;
    if (stream_id == 0u)
        stream_id = state->next_stream_id++;
    status = state->callbacks.request_file_range(
        state->context,
        stream_id,
        (int32_t)state->current_file,
        file->received,
        requested);
    if (status != LIBRDP_STATUS_OK)
    {
        cocoa_clipboard_remote_reset(state);
        return status;
    }
    state->pending_stream_id = stream_id;
    state->pending_position = file->received;
    state->pending_requested = requested;
    state->pending_deadline = state->callbacks.now(
        state->context);
    if (state->pending_deadline < 0.0)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_IO_ERROR);
    state->pending_deadline +=
        COCOA_VIEWER_CLIPBOARD_FILE_TIMEOUT;
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_clipboard_write_remote_range(
    cocoa_viewer_clipboard_state* state,
    const librdp_clipboard_file_contents_event* event)
{
    cocoa_viewer_remote_file* file = NULL;
    size_t offset = 0u;

    if (!state || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (state->pending_stream_id == 0u ||
        event->stream_id != state->pending_stream_id ||
        event->file_index != (int32_t)state->current_file ||
        event->flags != LIBRDP_CLIPBOARD_FILECONTENTS_RANGE ||
        event->position != state->pending_position ||
        event->requested != state->pending_requested ||
        event->data_len > state->pending_requested ||
        state->current_file >= state->file_count)
    {
        cocoa_clipboard_remote_reset(state);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (!event->ok)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_IO_ERROR);
    if (!event->data || event->data_len == 0u)
        return cocoa_clipboard_remote_fail(
            state, LIBRDP_STATUS_PROTOCOL_ERROR);
    file = &state->files[state->current_file];
    if (file->descriptor < 0 ||
        event->data_len > file->size - file->received)
    {
        cocoa_clipboard_remote_reset(state);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    while (offset < event->data_len)
    {
        ssize_t written = pwrite(
            file->descriptor,
            event->data + offset,
            event->data_len - offset,
            (off_t)(file->received + offset));

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            cocoa_clipboard_remote_reset(state);
            return LIBRDP_STATUS_IO_ERROR;
        }
        offset += (size_t)written;
    }
    file->received += event->data_len;
    state->pending_stream_id = 0u;
    state->pending_requested = 0u;
    state->pending_position = 0u;
    state->pending_deadline = 0.0;
    return cocoa_clipboard_request_next_range(state);
}

/*
 * Select one supported remote representation and issue one correlated request.
 * File transfer takes precedence over rich data and text; the selected state is
 * discarded if request submission fails or a new format list supersedes it.
 */
static librdp_status cocoa_clipboard_handle_formats(
    cocoa_viewer_clipboard_state* state,
    const librdp_clipboard_formats_event* event)
{
    uint32_t file_id = 0u;
    uint32_t html_id = 0u;
    uint32_t png_id = 0u;
    uint32_t unicode_id = 0u;
    uint32_t text_id = 0u;
    uint32_t index = 0u;

    if (!state || !event ||
        (!event->formats && event->count > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    cocoa_clipboard_remote_reset(state);
    if (event->count > COCOA_VIEWER_CLIPBOARD_MAX_FORMATS ||
        event->total_count < event->count)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (index = 0u; index < event->count; index++)
    {
        const librdp_clipboard_format* format =
            &event->formats[index];

        if (format->format_id ==
                LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW ||
            cocoa_clipboard_utf16_name_equals(
                format,
                LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW))
            file_id = format->format_id;
        else if (format->format_id ==
                     LIBRDP_CLIPBOARD_FORMAT_HTML ||
                 cocoa_clipboard_utf16_name_equals(
                     format,
                     LIBRDP_CLIPBOARD_FORMAT_NAME_HTML))
            html_id = format->format_id;
        else if (format->format_id ==
                     LIBRDP_CLIPBOARD_FORMAT_PNG ||
                 cocoa_clipboard_utf16_name_equals(
                     format,
                     LIBRDP_CLIPBOARD_FORMAT_NAME_PNG))
            png_id = format->format_id;
        else if (format->format_id ==
                 LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
            unicode_id = format->format_id;
        else if (format->format_id ==
                 LIBRDP_CLIPBOARD_FORMAT_TEXT)
            text_id = format->format_id;
    }
    if (file_id != 0u)
    {
        state->pending_kind = COCOA_VIEWER_REMOTE_FILES;
        state->pending_format_id = file_id;
    }
    else if (html_id != 0u)
    {
        state->pending_kind = COCOA_VIEWER_REMOTE_HTML;
        state->pending_format_id = html_id;
    }
    else if (png_id != 0u)
    {
        state->pending_kind = COCOA_VIEWER_REMOTE_PNG;
        state->pending_format_id = png_id;
    }
    else if (unicode_id != 0u || text_id != 0u)
    {
        state->pending_kind = COCOA_VIEWER_REMOTE_TEXT;
        state->pending_format_id = unicode_id != 0u
                                       ? unicode_id
                                       : text_id;
    }
    else
        return LIBRDP_STATUS_UNSUPPORTED;
    {
        librdp_status status = state->callbacks.request_data(
            state->context, state->pending_format_id);

        if (status != LIBRDP_STATUS_OK)
            cocoa_clipboard_remote_reset(state);
        return status;
    }
}

@implementation CocoaViewerClipboard

- (id)initWithSession:(librdp_session*)session
{
    const cocoa_viewer_clipboard_callbacks callbacks = {
        cocoa_clipboard_session_set_data,
        cocoa_clipboard_session_set_named_data,
        cocoa_clipboard_session_set_files,
        cocoa_clipboard_session_clear,
        cocoa_clipboard_session_request_data,
        cocoa_clipboard_session_request_file_range,
        cocoa_clipboard_monotonic_now,
    };

    if (!session)
        return nil;
    return [self initWithPasteboard:
                     [NSPasteboard generalPasteboard]
                          callbacks:&callbacks
                            context:session];
}

- (id)initWithPasteboard:(NSPasteboard*)pasteboard
                callbacks:(const cocoa_viewer_clipboard_callbacks*)callbacks
                  context:(void*)context
{
    self = [super init];
    if (!self)
        return nil;
    if (!pasteboard || !context ||
        !cocoa_clipboard_callbacks_valid(callbacks))
    {
#if !__has_feature(objc_arc)
        [self release];
#endif
        return nil;
    }
    _state = (cocoa_viewer_clipboard_state*)calloc(
        1u, sizeof(*_state));
    if (!_state)
    {
#if !__has_feature(objc_arc)
        [self release];
#endif
        return nil;
    }
#if __has_feature(objc_arc)
    _pasteboard = pasteboard;
#else
    _pasteboard = [pasteboard retain];
#endif
    _state->pasteboard = _pasteboard;
    _state->callbacks = *callbacks;
    _state->context = context;
    _state->observed_change_count = -1;
    _state->remote_change_count = -1;
    _state->next_stream_id = 1u;
    for (uint32_t index = 0u;
         index < COCOA_VIEWER_CLIPBOARD_MAX_FILES;
         index++)
        _state->files[index].descriptor = -1;
    return self;
}

- (librdp_status)poll
{
    NSInteger change_count = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    double now = 0.0;

    if (!_state || _state->stopped)
        return LIBRDP_STATUS_STATE;
    if (_state->pending_stream_id != 0u &&
        _state->pending_deadline > 0.0)
    {
        now = _state->callbacks.now(_state->context);
        if (now < 0.0)
            return cocoa_clipboard_remote_fail(
                _state, LIBRDP_STATUS_IO_ERROR);
        if (now >= _state->pending_deadline)
            return cocoa_clipboard_remote_fail(
                _state, LIBRDP_STATUS_TIMEOUT);
    }
    change_count = [_state->pasteboard changeCount];
    if (change_count == _state->observed_change_count)
        return LIBRDP_STATUS_OK;
    if (change_count == _state->remote_change_count)
    {
        _state->observed_change_count = change_count;
        return LIBRDP_STATUS_OK;
    }
    cocoa_clipboard_remote_reset(_state);
    status = cocoa_clipboard_publish_local(_state);
    if (status == LIBRDP_STATUS_OK)
        _state->observed_change_count = change_count;
    return status;
}

- (librdp_status)handleEnvelope:(const librdp_event_envelope*)envelope
{
    if (!_state || _state->stopped || !envelope)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (envelope->type)
    {
    case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        if (!envelope->payload ||
            envelope->payload_size <
                sizeof(librdp_clipboard_formats_event))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return cocoa_clipboard_handle_formats(
            _state,
            (const librdp_clipboard_formats_event*)
                envelope->payload);
    case LIBRDP_EVENT_CLIPBOARD_DATA:
    {
        const librdp_clipboard_data_event* event = NULL;

        if (!envelope->payload ||
            envelope->payload_size <
                sizeof(librdp_clipboard_data_event))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event = (const librdp_clipboard_data_event*)
            envelope->payload;
        if (_state->pending_kind ==
            COCOA_VIEWER_REMOTE_FILES)
            return cocoa_clipboard_start_remote_files(
                _state, event);
        return cocoa_clipboard_publish_remote_data(
            _state, event);
    }
    case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
        if (!envelope->payload ||
            envelope->payload_size <
                sizeof(librdp_clipboard_file_contents_event))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return cocoa_clipboard_write_remote_range(
            _state,
            (const librdp_clipboard_file_contents_event*)
                envelope->payload);
    case LIBRDP_EVENT_CLIPBOARD_REQUEST:
        return [self poll];
    default:
        return LIBRDP_STATUS_UNSUPPORTED;
    }
}

- (void)shutdown
{
    if (!_state)
        return;
    _state->stopped = 1;
    cocoa_clipboard_remote_reset(_state);
    _state->pasteboard = nil;
    free(_state);
    _state = NULL;
#if !__has_feature(objc_arc)
    [_pasteboard release];
#endif
    _pasteboard = nil;
}

- (void)dealloc
{
    [self shutdown];
#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}

@end
