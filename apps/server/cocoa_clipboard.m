/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: NSPasteboard adapter for the Cocoa desktop server.
 * Invariants: one remote format fetch and one promised-file range request are
 * pending at a time, ownership generations suppress feedback, and every
 * retained payload stays within the common clipboard quotas.
 * Ownership: the provider owns native data, promise delegates, descriptors,
 * pipes and synchronization state; callback arguments are borrowed.
 * Threading: pasteboard and protocol methods execute on the host thread.
 * File promises run on one operation queue and exchange bounded work through
 * a mutex, condition variable and pollable wakeup pipe.
 * Trust boundary: native pasteboard content and remote clipboard bytes are
 * untrusted. Types, encodings, metadata, file names, offsets and lengths are
 * checked before publication, allocation or file creation.
 */

#include "cocoa_clipboard.h"

#include "server_clipboard_files.h"

#import <Cocoa/Cocoa.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
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

#define COCOA_CLIPBOARD_MAX_FORMATS 16u
#define COCOA_CLIPBOARD_MAX_FILES 32u
#define COCOA_CLIPBOARD_MAX_BYTES (16u * 1024u * 1024u)
#define COCOA_CLIPBOARD_CHUNK_BYTES 65536u
#define COCOA_CLIPBOARD_FILE_CHUNK_BYTES (1024u * 1024u)
#define COCOA_CLIPBOARD_POLL_MS 200
#define COCOA_CLIPBOARD_FILE_TIMEOUT_SECONDS 15

typedef enum cocoa_clipboard_format_class
{
    COCOA_CLIPBOARD_FORMAT_TEXT = 1,
    COCOA_CLIPBOARD_FORMAT_HTML = 2,
    COCOA_CLIPBOARD_FORMAT_PNG = 3,
    COCOA_CLIPBOARD_FORMAT_FILES = 4
} cocoa_clipboard_format_class;

typedef enum cocoa_clipboard_fetch_state
{
    COCOA_CLIPBOARD_FETCH_NEW = 0,
    COCOA_CLIPBOARD_FETCH_PENDING = 1,
    COCOA_CLIPBOARD_FETCH_READY = 2,
    COCOA_CLIPBOARD_FETCH_FAILED = 3
} cocoa_clipboard_fetch_state;

typedef struct cocoa_clipboard_remote_format
{
    uint32_t id;
    cocoa_clipboard_format_class format_class;
    cocoa_clipboard_fetch_state state;
    uint64_t request_id;
    NSData* data;
} cocoa_clipboard_remote_format;

typedef struct cocoa_clipboard_remote_file
{
    char* name;
    uint64_t size;
    uint32_t index;
} cocoa_clipboard_remote_file;

typedef struct cocoa_clipboard_file_wait
{
    server_platform_clipboard_file_request request;
    uint8_t* data;
    size_t data_len;
    librdp_status status;
    int active;
    int queued;
    int complete;
    int cancelled;
    int cancel_queued;
} cocoa_clipboard_file_wait;

@class CocoaServerFilePromiseDelegate;

struct cocoa_server_clipboard
{
    NSPasteboard* pasteboard;
    NSOperationQueue* promise_queue;
    NSMutableArray* promise_objects;
    server_clipboard_files* local_files;
    server_platform_clipboard_sink sink;
    cocoa_clipboard_remote_format remote_formats[COCOA_CLIPBOARD_MAX_FORMATS];
    cocoa_clipboard_remote_file remote_files[COCOA_CLIPBOARD_MAX_FILES];
    size_t remote_format_count;
    size_t remote_file_count;
    uint32_t remote_peer_id;
    uint32_t remote_peer_generation;
    uint64_t remote_ownership_generation;
    uint64_t local_generation;
    uint64_t next_format_request_id;
    uint64_t next_file_request_id;
    uint32_t next_stream_id;
    NSInteger observed_change_count;
    NSInteger remote_change_count;
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int lock_ready;
    int condition_ready;
    int wakeup_read_fd;
    int wakeup_write_fd;
    cocoa_clipboard_file_wait file_wait;
    int prefetch_pending;
    int promise_cancelled;
    int started;
    int stopping;
};

@interface CocoaServerFilePromiseDelegate
    : NSObject <NSFilePromiseProviderDelegate>
{
    cocoa_server_clipboard* _clipboard;
    NSString* _name;
    uint32_t _index;
    uint64_t _size;
}
- (id)initWithClipboard:(cocoa_server_clipboard*)clipboard
                   name:(NSString*)name
                  index:(uint32_t)index
                   size:(uint64_t)size;
- (void)invalidate;
@end

static void cocoa_clipboard_wakeup(cocoa_server_clipboard* clipboard)
{
    uint8_t byte = 1u;

    if (!clipboard || clipboard->wakeup_write_fd < 0)
        return;
    while (write(clipboard->wakeup_write_fd, &byte, 1u) < 0 && errno == EINTR)
    {
    }
}

static int cocoa_clipboard_set_nonblocking(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFL, 0);
    int descriptor_flags = fcntl(descriptor, F_GETFD, 0);

    return flags >= 0 && descriptor_flags >= 0 &&
           fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 &&
           fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
}

static int cocoa_clipboard_create_pipe(cocoa_server_clipboard* clipboard)
{
    int descriptors[2] = {-1, -1};

    if (!clipboard || pipe(descriptors) != 0)
        return 0;
    if (!cocoa_clipboard_set_nonblocking(descriptors[0]) ||
        !cocoa_clipboard_set_nonblocking(descriptors[1]))
    {
        close(descriptors[0]);
        close(descriptors[1]);
        return 0;
    }
    clipboard->wakeup_read_fd = descriptors[0];
    clipboard->wakeup_write_fd = descriptors[1];
    return 1;
}

static uint64_t cocoa_clipboard_next_request_id(uint64_t* next_request_id)
{
    uint64_t value = 0u;

    if (!next_request_id)
        return 0u;
    value = *next_request_id;
    *next_request_id += 2u;
    if (value == 0u)
    {
        value = *next_request_id;
        *next_request_id += 2u;
    }
    return value;
}

static uint32_t
cocoa_clipboard_next_stream_id(cocoa_server_clipboard* clipboard)
{
    uint32_t value = clipboard->next_stream_id++;

    if (value == 0u)
        value = clipboard->next_stream_id++;
    return value;
}

static cocoa_clipboard_format_class cocoa_clipboard_class(uint32_t format_id,
                                                          const char* mime_type)
{
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT ||
        (mime_type && (strcmp(mime_type, "text/plain") == 0 ||
                       strcmp(mime_type, "text/plain;charset=utf-8") == 0)))
        return COCOA_CLIPBOARD_FORMAT_TEXT;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_HTML ||
        (mime_type && strcmp(mime_type, "text/html") == 0))
        return COCOA_CLIPBOARD_FORMAT_HTML;
    if (format_id == LIBRDP_CLIPBOARD_FORMAT_PNG ||
        (mime_type && strcmp(mime_type, "image/png") == 0))
        return COCOA_CLIPBOARD_FORMAT_PNG;
    if (format_id != LIBRDP_CLIPBOARD_FORMAT_HDROP &&
        (format_id == LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW ||
         (mime_type && strcmp(mime_type, "text/uri-list") == 0)))
        return COCOA_CLIPBOARD_FORMAT_FILES;
    return 0;
}

static NSString*
cocoa_clipboard_native_type(cocoa_clipboard_format_class format_class)
{
    switch (format_class)
    {
    case COCOA_CLIPBOARD_FORMAT_TEXT:
        return NSPasteboardTypeString;
    case COCOA_CLIPBOARD_FORMAT_HTML:
        return NSPasteboardTypeHTML;
    case COCOA_CLIPBOARD_FORMAT_PNG:
        return NSPasteboardTypePNG;
    case COCOA_CLIPBOARD_FORMAT_FILES:
        return NSPasteboardTypeFileURL;
    default:
        return nil;
    }
}

static uint32_t
cocoa_clipboard_default_format_id(cocoa_clipboard_format_class format_class)
{
    switch (format_class)
    {
    case COCOA_CLIPBOARD_FORMAT_TEXT:
        return LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT;
    case COCOA_CLIPBOARD_FORMAT_HTML:
        return LIBRDP_CLIPBOARD_FORMAT_HTML;
    case COCOA_CLIPBOARD_FORMAT_PNG:
        return LIBRDP_CLIPBOARD_FORMAT_PNG;
    case COCOA_CLIPBOARD_FORMAT_FILES:
        return LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW;
    default:
        return 0u;
    }
}

static const char*
cocoa_clipboard_mime(cocoa_clipboard_format_class format_class)
{
    switch (format_class)
    {
    case COCOA_CLIPBOARD_FORMAT_TEXT:
        return "text/plain;charset=utf-8";
    case COCOA_CLIPBOARD_FORMAT_HTML:
        return "text/html";
    case COCOA_CLIPBOARD_FORMAT_PNG:
        return "image/png";
    case COCOA_CLIPBOARD_FORMAT_FILES:
        return "text/uri-list";
    default:
        return NULL;
    }
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
        while (cursor < data_len && data[cursor] >= (uint8_t)'0' &&
               data[cursor] <= (uint8_t)'9')
        {
            size_t digit = (size_t)(data[cursor] - (uint8_t)'0');

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

static librdp_status cocoa_clipboard_html_extract(const uint8_t* data,
                                                  size_t data_len,
                                                  NSData** output)
{
    size_t start = 0u;
    size_t end = 0u;

    if (!data || !output ||
        !cocoa_clipboard_html_offset(
            data, data_len, "StartFragment:", &start) ||
        !cocoa_clipboard_html_offset(data, data_len, "EndFragment:", &end) ||
        start > end || end > data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *output = [[NSData alloc] initWithBytes:data + start length:end - start];
    return *output ? LIBRDP_STATUS_OK : LIBRDP_STATUS_NO_MEMORY;
}

static int cocoa_clipboard_write_decimal(uint8_t* output, size_t value)
{
    char text[11];
    int written = 0;

    if (!output || value > 9999999999u)
        return 0;
    written = snprintf(text, sizeof(text), "%010zu", value);
    if (written != 10)
        return 0;
    memcpy(output, text, 10u);
    return 1;
}

static librdp_status
cocoa_clipboard_html_package(NSData* data, uint8_t** output, size_t* output_len)
{
    static const char header[] = "Version:0.9\r\n"
                                 "StartHTML:0000000000\r\n"
                                 "EndHTML:0000000000\r\n"
                                 "StartFragment:0000000000\r\n"
                                 "EndFragment:0000000000\r\n";
    static const char prefix[] = "<html><body><!--StartFragment-->";
    static const char suffix[] = "<!--EndFragment--></body></html>";
    const size_t header_len = sizeof(header) - 1u;
    const size_t prefix_len = sizeof(prefix) - 1u;
    const size_t suffix_len = sizeof(suffix) - 1u;
    size_t data_len = data ? (size_t)[data length] : 0u;
    size_t total = 0u;
    size_t start = 0u;
    size_t end = 0u;
    uint8_t* buffer = NULL;

    if (!data || !output || !output_len ||
        data_len >
            COCOA_CLIPBOARD_MAX_BYTES - header_len - prefix_len - suffix_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = header_len + prefix_len + data_len + suffix_len;
    buffer = (uint8_t*)malloc(total);
    if (!buffer)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(buffer, header, header_len);
    start = header_len + prefix_len;
    end = start + data_len;
    if (!cocoa_clipboard_write_decimal(buffer + 23u, header_len) ||
        !cocoa_clipboard_write_decimal(buffer + 43u, total) ||
        !cocoa_clipboard_write_decimal(buffer + 69u, start) ||
        !cocoa_clipboard_write_decimal(buffer + 93u, end))
    {
        free(buffer);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memcpy(buffer + header_len, prefix, prefix_len);
    if (data_len > 0u)
        memcpy(buffer + start, [data bytes], data_len);
    memcpy(buffer + end, suffix, suffix_len);
    *output = buffer;
    *output_len = total;
    return LIBRDP_STATUS_OK;
}

static void
cocoa_clipboard_remote_files_clear(cocoa_server_clipboard* clipboard)
{
    size_t index = 0u;

    if (!clipboard)
        return;
    for (index = 0u; index < clipboard->remote_file_count; index++)
    {
        free(clipboard->remote_files[index].name);
        memset(&clipboard->remote_files[index],
               0,
               sizeof(clipboard->remote_files[index]));
    }
    clipboard->remote_file_count = 0u;
}

static void
cocoa_clipboard_invalidate_promises(cocoa_server_clipboard* clipboard)
{
    if (!clipboard || !clipboard->promise_objects)
        return;
    for (id object in clipboard->promise_objects)
    {
        if ([object isKindOfClass:[CocoaServerFilePromiseDelegate class]])
            [(CocoaServerFilePromiseDelegate*)object invalidate];
    }
    [clipboard->promise_objects removeAllObjects];
}

/*
 * Wake a promise worker before waiting for its operation queue. Requests
 * already handed to the protocol runtime are marked for one cancellation;
 * work still queued locally is discarded without emitting a spurious cancel.
 */
static void cocoa_clipboard_cancel_file_wait(cocoa_server_clipboard* clipboard)
{
    cocoa_clipboard_file_wait* wait = NULL;
    int wake = 0;

    if (!clipboard || !clipboard->lock_ready)
        return;
    wait = &clipboard->file_wait;
    pthread_mutex_lock(&clipboard->lock);
    if (wait->active && !wait->complete)
    {
        if (!wait->queued && wait->request.request_id != 0u)
            wait->cancel_queued = 1;
        wait->cancelled = 1;
        wait->status = LIBRDP_STATUS_CANCELLED;
        wait->complete = 1;
        pthread_cond_broadcast(&clipboard->condition);
        wake = 1;
    }
    pthread_mutex_unlock(&clipboard->lock);
    if (wake)
        cocoa_clipboard_wakeup(clipboard);
}

static void cocoa_clipboard_flush_file_cancel(cocoa_server_clipboard* clipboard)
{
    server_platform_clipboard_file_request request;
    int have_cancel = 0;

    if (!clipboard || !clipboard->lock_ready)
        return;
    memset(&request, 0, sizeof(request));
    pthread_mutex_lock(&clipboard->lock);
    if (clipboard->file_wait.cancel_queued)
    {
        request = clipboard->file_wait.request;
        clipboard->file_wait.cancel_queued = 0;
        have_cancel = 1;
    }
    if (!clipboard->file_wait.active && !clipboard->file_wait.queued)
    {
        free(clipboard->file_wait.data);
        memset(&clipboard->file_wait, 0, sizeof(clipboard->file_wait));
    }
    pthread_mutex_unlock(&clipboard->lock);
    if (have_cancel && clipboard->started && clipboard->sink.cancel)
    {
        (void)clipboard->sink.cancel(request.peer_id,
                                     request.generation,
                                     request.ownership_generation,
                                     request.request_id,
                                     clipboard->sink.user_data);
    }
}

static void cocoa_clipboard_reset_promises(cocoa_server_clipboard* clipboard)
{
    if (!clipboard)
        return;
    if (clipboard->lock_ready)
    {
        pthread_mutex_lock(&clipboard->lock);
        clipboard->promise_cancelled = 1;
        pthread_mutex_unlock(&clipboard->lock);
    }
    cocoa_clipboard_cancel_file_wait(clipboard);
    if (clipboard->promise_queue)
    {
        [clipboard->promise_queue cancelAllOperations];
        [clipboard->promise_queue waitUntilAllOperationsAreFinished];
    }
    cocoa_clipboard_invalidate_promises(clipboard);
    cocoa_clipboard_flush_file_cancel(clipboard);
    if (clipboard->lock_ready)
    {
        pthread_mutex_lock(&clipboard->lock);
        clipboard->promise_cancelled = 0;
        pthread_mutex_unlock(&clipboard->lock);
    }
}

static void cocoa_clipboard_remote_clear(cocoa_server_clipboard* clipboard,
                                         int clear_native)
{
    size_t index = 0u;

    if (!clipboard)
        return;
    cocoa_clipboard_reset_promises(clipboard);
    for (index = 0u; index < clipboard->remote_format_count; index++)
    {
        if (clipboard->remote_formats[index].state ==
                COCOA_CLIPBOARD_FETCH_PENDING &&
            clipboard->started && clipboard->sink.cancel)
        {
            (void)clipboard->sink.cancel(
                clipboard->remote_peer_id,
                clipboard->remote_peer_generation,
                clipboard->remote_ownership_generation,
                clipboard->remote_formats[index].request_id,
                clipboard->sink.user_data);
        }
        [clipboard->remote_formats[index].data release];
        memset(&clipboard->remote_formats[index],
               0,
               sizeof(clipboard->remote_formats[index]));
    }
    cocoa_clipboard_remote_files_clear(clipboard);
    clipboard->remote_format_count = 0u;
    clipboard->remote_peer_id = 0u;
    clipboard->remote_peer_generation = 0u;
    clipboard->remote_ownership_generation = 0u;
    clipboard->prefetch_pending = 0;
    if (clear_native && clipboard->pasteboard &&
        [clipboard->pasteboard changeCount] == clipboard->remote_change_count)
    {
        [clipboard->pasteboard clearContents];
        clipboard->remote_change_count = [clipboard->pasteboard changeCount];
        clipboard->observed_change_count = clipboard->remote_change_count;
    }
}

static librdp_status cocoa_clipboard_decode_files(
    cocoa_server_clipboard* clipboard, const uint8_t* data, size_t data_len)
{
    uint32_t count = 0u;
    uint32_t index = 0u;
    librdp_status status =
        librdp_clipboard_file_group_count(data, data_len, &count);

    if (!clipboard)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (count == 0u || count > COCOA_CLIPBOARD_MAX_FILES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    cocoa_clipboard_remote_files_clear(clipboard);
    for (index = 0u; index < count; index++)
    {
        librdp_clipboard_file_metadata metadata;
        size_t name_len = 0u;
        char* name = NULL;

        status = librdp_clipboard_file_metadata_init(&metadata);
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_clipboard_file_group_get(
                data, data_len, index, &metadata, NULL, 0u, &name_len);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            name = (char*)malloc(name_len);
            if (!name)
                status = LIBRDP_STATUS_NO_MEMORY;
        }
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_clipboard_file_group_get(
                data, data_len, index, &metadata, name, name_len, &name_len);
        }
        if (status == LIBRDP_STATUS_OK &&
            (metadata.attributes & LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_DIRECTORY) !=
                0u)
            status = LIBRDP_STATUS_UNSUPPORTED;
        if (status != LIBRDP_STATUS_OK)
        {
            free(name);
            cocoa_clipboard_remote_files_clear(clipboard);
            return status;
        }
        clipboard->remote_files[index].name = name;
        clipboard->remote_files[index].size = metadata.file_size;
        clipboard->remote_files[index].index = index;
        clipboard->remote_file_count++;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status
cocoa_clipboard_decode_remote_data(cocoa_server_clipboard* clipboard,
                                   cocoa_clipboard_remote_format* format,
                                   const server_platform_clipboard_data* data)
{
    NSData* native = nil;

    if (!clipboard || !format || !data ||
        data->data_len > COCOA_CLIPBOARD_MAX_BYTES ||
        (!data->data && data->data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (format->format_class)
    {
    case COCOA_CLIPBOARD_FORMAT_TEXT:
    {
        size_t content_len = data->data_len;
        NSString* string = nil;

        if ((content_len & 1u) != 0u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        while (content_len >= 2u && data->data[content_len - 2u] == 0u &&
               data->data[content_len - 1u] == 0u)
            content_len -= 2u;
        string =
            [[NSString alloc] initWithBytes:data->data
                                     length:content_len
                                   encoding:NSUTF16LittleEndianStringEncoding];
        if (!string)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        native = [[string dataUsingEncoding:NSUTF8StringEncoding] retain];
        [string release];
        break;
    }
    case COCOA_CLIPBOARD_FORMAT_HTML:
        return cocoa_clipboard_html_extract(
            data->data, data->data_len, &format->data);
    case COCOA_CLIPBOARD_FORMAT_PNG:
    {
        NSBitmapImageRep* image = nil;

        native = [[NSData alloc] initWithBytes:data->data
                                        length:data->data_len];
        if (!native)
            return LIBRDP_STATUS_NO_MEMORY;
        image = [[NSBitmapImageRep alloc] initWithData:native];
        if (!image)
        {
            [native release];
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        [image release];
        break;
    }
    case COCOA_CLIPBOARD_FORMAT_FILES:
        return cocoa_clipboard_decode_files(
            clipboard, data->data, data->data_len);
    default:
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (!native)
        return LIBRDP_STATUS_NO_MEMORY;
    format->data = native;
    return LIBRDP_STATUS_OK;
}

static NSError* cocoa_clipboard_error(librdp_status status)
{
    return [NSError
        errorWithDomain:@"org.librdp.cocoa-server.clipboard"
                   code:(NSInteger)status
               userInfo:@{
                   NSLocalizedDescriptionKey : [NSString
                       stringWithUTF8String:librdp_status_description(status)]
               }];
}

static void cocoa_clipboard_file_wait_finish(cocoa_server_clipboard* clipboard,
                                             librdp_status status,
                                             const uint8_t* data,
                                             size_t data_len)
{
    cocoa_clipboard_file_wait* wait = NULL;
    uint8_t* copy = NULL;

    if (!clipboard)
        return;
    wait = &clipboard->file_wait;
    if (data_len > 0u && !data)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK && data_len > 0u)
    {
        copy = (uint8_t*)malloc(data_len);
        if (!copy)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            memcpy(copy, data, data_len);
    }
    pthread_mutex_lock(&clipboard->lock);
    if (!wait->active || wait->complete || wait->cancelled)
    {
        pthread_mutex_unlock(&clipboard->lock);
        free(copy);
        return;
    }
    wait->data = status == LIBRDP_STATUS_OK ? copy : NULL;
    wait->data_len = status == LIBRDP_STATUS_OK ? data_len : 0u;
    wait->status = status;
    wait->complete = 1;
    pthread_cond_broadcast(&clipboard->condition);
    pthread_mutex_unlock(&clipboard->lock);
    if (status != LIBRDP_STATUS_OK)
        free(copy);
}

static void cocoa_clipboard_deadline(struct timespec* deadline)
{
    if (!deadline)
        return;
    if (clock_gettime(CLOCK_REALTIME, deadline) != 0)
    {
        deadline->tv_sec = 0;
        deadline->tv_nsec = 0;
        return;
    }
    if (deadline->tv_sec >
        (time_t)(INT64_MAX - COCOA_CLIPBOARD_FILE_TIMEOUT_SECONDS))
        deadline->tv_sec = (time_t)INT64_MAX;
    else
        deadline->tv_sec += (time_t)COCOA_CLIPBOARD_FILE_TIMEOUT_SECONDS;
}

/*
 * Marshal one bounded range request from the AppKit promise queue to the host
 * event loop and wait for its uniquely correlated completion. Teardown marks
 * the wait complete before draining the operation queue, while a timeout
 * schedules protocol cancellation only after the request was submitted.
 * Reject concurrent waits so one response cannot satisfy another promise.
 */
static librdp_status
cocoa_clipboard_request_file_range(cocoa_server_clipboard* clipboard,
                                   uint32_t file_index,
                                   uint64_t position,
                                   uint32_t requested,
                                   uint8_t** data,
                                   size_t* data_len)
{
    cocoa_clipboard_file_wait* wait = NULL;
    struct timespec deadline;
    int wait_result = 0;
    librdp_status status = LIBRDP_STATUS_STATE;

    if (!clipboard || !data || !data_len || requested == 0u ||
        requested > COCOA_CLIPBOARD_FILE_CHUNK_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    *data_len = 0u;
    wait = &clipboard->file_wait;
    cocoa_clipboard_deadline(&deadline);
    pthread_mutex_lock(&clipboard->lock);
    if (clipboard->stopping || clipboard->promise_cancelled)
    {
        pthread_mutex_unlock(&clipboard->lock);
        return LIBRDP_STATUS_CANCELLED;
    }
    if (wait->active || wait->cancel_queued ||
        clipboard->remote_peer_id == 0u ||
        clipboard->remote_peer_generation == 0u ||
        clipboard->remote_ownership_generation == 0u)
    {
        pthread_mutex_unlock(&clipboard->lock);
        return LIBRDP_STATUS_STATE;
    }
    memset(wait, 0, sizeof(*wait));
    wait->active = 1;
    wait->queued = 1;
    wait->status = LIBRDP_STATUS_AGAIN;
    wait->request.peer_id = clipboard->remote_peer_id;
    wait->request.generation = clipboard->remote_peer_generation;
    wait->request.ownership_generation = clipboard->remote_ownership_generation;
    wait->request.request_id =
        cocoa_clipboard_next_request_id(&clipboard->next_file_request_id);
    wait->request.stream_id = cocoa_clipboard_next_stream_id(clipboard);
    wait->request.file_index = (int32_t)file_index;
    wait->request.flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
    wait->request.position = position;
    wait->request.requested_bytes = requested;
    pthread_mutex_unlock(&clipboard->lock);
    cocoa_clipboard_wakeup(clipboard);

    pthread_mutex_lock(&clipboard->lock);
    while (!wait->complete && !clipboard->stopping)
    {
        wait_result = pthread_cond_timedwait(
            &clipboard->condition, &clipboard->lock, &deadline);
        if (wait_result == ETIMEDOUT)
            break;
    }
    if (!wait->complete && !clipboard->stopping)
    {
        wait->cancelled = 1;
        if (!wait->queued)
            wait->cancel_queued = 1;
        wait->status = LIBRDP_STATUS_TIMEOUT;
        cocoa_clipboard_wakeup(clipboard);
    }
    if (clipboard->stopping)
        wait->status = LIBRDP_STATUS_CANCELLED;
    status = wait->status;
    if (status == LIBRDP_STATUS_OK)
    {
        *data = wait->data;
        *data_len = wait->data_len;
        wait->data = NULL;
        wait->data_len = 0u;
    }
    wait->active = 0;
    wait->queued = 0;
    wait->complete = 0;
    free(wait->data);
    wait->data = NULL;
    wait->data_len = 0u;
    pthread_mutex_unlock(&clipboard->lock);
    return status;
}

static librdp_status
cocoa_clipboard_write_promised_file_contents(cocoa_server_clipboard* clipboard,
                                             uint32_t index,
                                             uint64_t file_size,
                                             NSURL* destination)
{
    const char* path = NULL;
    uint64_t position = 0u;
    int descriptor = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!clipboard || !destination || ![destination isFileURL])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    path = [[destination path] fileSystemRepresentation];
    if (!path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    descriptor =
        open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0)
        return LIBRDP_STATUS_IO_ERROR;
    while (position < file_size)
    {
        uint64_t remaining = file_size - position;
        uint32_t requested = remaining > COCOA_CLIPBOARD_FILE_CHUNK_BYTES
                                 ? COCOA_CLIPBOARD_FILE_CHUNK_BYTES
                                 : (uint32_t)remaining;
        uint8_t* data = NULL;
        size_t data_len = 0u;
        size_t written = 0u;

        status = cocoa_clipboard_request_file_range(
            clipboard, index, position, requested, &data, &data_len);
        if (status != LIBRDP_STATUS_OK || data_len == 0u ||
            data_len > requested)
        {
            free(data);
            if (status == LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        while (written < data_len)
        {
            ssize_t result =
                write(descriptor, data + written, data_len - written);

            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
            {
                status = LIBRDP_STATUS_IO_ERROR;
                break;
            }
            written += (size_t)result;
        }
        free(data);
        if (status != LIBRDP_STATUS_OK)
            break;
        position += data_len;
    }
    if (close(descriptor) != 0 && status == LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_IO_ERROR;
    if (status != LIBRDP_STATUS_OK)
        (void)unlink(path);
    return status;
}

static librdp_status
cocoa_clipboard_write_promised_file(cocoa_server_clipboard* clipboard,
                                    uint32_t index,
                                    uint64_t file_size,
                                    NSURL* destination)
{
    NSFileCoordinator* coordinator = nil;
    __block librdp_status status = LIBRDP_STATUS_IO_ERROR;
    __block int invoked = 0;
    NSError* error = nil;

    if (!clipboard || !destination)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    coordinator =
        [[[NSFileCoordinator alloc] initWithFilePresenter:nil] autorelease];
    if (!coordinator)
        return LIBRDP_STATUS_NO_MEMORY;
    [coordinator
        coordinateWritingItemAtURL:destination
                           options:0
                             error:&error
                        byAccessor:^(NSURL* coordinated_url) {
                          invoked = 1;
                          status = cocoa_clipboard_write_promised_file_contents(
                              clipboard, index, file_size, coordinated_url);
                        }];
    if (!invoked || error)
        return LIBRDP_STATUS_IO_ERROR;
    return status;
}

@implementation CocoaServerFilePromiseDelegate
- (id)initWithClipboard:(cocoa_server_clipboard*)clipboard
                   name:(NSString*)name
                  index:(uint32_t)index
                   size:(uint64_t)size
{
    self = [super init];
    if (self)
    {
        _clipboard = clipboard;
        _name = [name copy];
        _index = index;
        _size = size;
    }
    return self;
}

- (void)dealloc
{
    [_name release];
    [super dealloc];
}

- (void)invalidate
{
    _clipboard = NULL;
}

- (NSString*)filePromiseProvider:(NSFilePromiseProvider*)provider
                 fileNameForType:(NSString*)fileType
{
    (void)provider;
    (void)fileType;
    return _name;
}

- (NSOperationQueue*)operationQueueForFilePromiseProvider:
    (NSFilePromiseProvider*)provider
{
    (void)provider;
    return _clipboard ? _clipboard->promise_queue : nil;
}

- (void)filePromiseProvider:(NSFilePromiseProvider*)provider
          writePromiseToURL:(NSURL*)url
          completionHandler:(void (^)(NSError* error))completionHandler
{
    librdp_status status = LIBRDP_STATUS_CANCELLED;

    (void)provider;
    if (_clipboard)
    {
        status =
            cocoa_clipboard_write_promised_file(_clipboard, _index, _size, url);
    }
    completionHandler(
        status == LIBRDP_STATUS_OK ? nil : cocoa_clipboard_error(status));
}
@end

static librdp_status
cocoa_clipboard_publish_native(cocoa_server_clipboard* clipboard)
{
    NSMutableArray* objects = nil;
    NSPasteboardItem* item = nil;
    size_t index = 0u;
    int item_has_data = 0;

    if (!clipboard || !clipboard->pasteboard)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    objects = [NSMutableArray array];
    item = [[[NSPasteboardItem alloc] init] autorelease];
    cocoa_clipboard_reset_promises(clipboard);
    for (index = 0u; index < clipboard->remote_format_count; index++)
    {
        cocoa_clipboard_remote_format* format =
            &clipboard->remote_formats[index];
        NSString* type = cocoa_clipboard_native_type(format->format_class);

        if (format->state != COCOA_CLIPBOARD_FETCH_READY || !format->data ||
            !type || format->format_class == COCOA_CLIPBOARD_FORMAT_FILES)
            continue;
        if (format->format_class == COCOA_CLIPBOARD_FORMAT_TEXT)
        {
            NSString* string = [[[NSString alloc]
                initWithData:format->data
                    encoding:NSUTF8StringEncoding] autorelease];

            if (!string || ![item setString:string forType:type])
                continue;
        }
        else if (![item setData:format->data forType:type])
            continue;
        item_has_data = 1;
    }
    if (item_has_data)
        [objects addObject:item];
    for (index = 0u; index < clipboard->remote_file_count; index++)
    {
        cocoa_clipboard_remote_file* file = &clipboard->remote_files[index];
        NSString* name = [NSString stringWithUTF8String:file->name];
        CocoaServerFilePromiseDelegate* delegate = nil;
        NSFilePromiseProvider* provider = nil;

        if (!name)
            continue;
        delegate = [[[CocoaServerFilePromiseDelegate alloc]
            initWithClipboard:clipboard
                         name:name
                        index:file->index
                         size:file->size] autorelease];
        provider = [[[NSFilePromiseProvider alloc]
            initWithFileType:@"public.data"
                    delegate:delegate] autorelease];
        if (!delegate || !provider)
            continue;
        [clipboard->promise_objects addObject:delegate];
        [clipboard->promise_objects addObject:provider];
        [objects addObject:provider];
    }
    [clipboard->pasteboard clearContents];
    if ([objects count] > 0u && ![clipboard->pasteboard writeObjects:objects])
        return LIBRDP_STATUS_IO_ERROR;
    clipboard->remote_change_count = [clipboard->pasteboard changeCount];
    clipboard->observed_change_count = clipboard->remote_change_count;
    return LIBRDP_STATUS_OK;
}

static void cocoa_clipboard_prefetch(cocoa_server_clipboard* clipboard)
{
    size_t index = 0u;

    if (!clipboard || !clipboard->started || !clipboard->prefetch_pending)
        return;
    for (index = 0u; index < clipboard->remote_format_count; index++)
    {
        cocoa_clipboard_remote_format* format =
            &clipboard->remote_formats[index];
        server_platform_clipboard_request request;
        librdp_status status = LIBRDP_STATUS_OK;

        if (format->state == COCOA_CLIPBOARD_FETCH_PENDING)
            return;
        if (format->state != COCOA_CLIPBOARD_FETCH_NEW)
            continue;
        memset(&request, 0, sizeof(request));
        request.peer_id = clipboard->remote_peer_id;
        request.generation = clipboard->remote_peer_generation;
        request.ownership_generation = clipboard->remote_ownership_generation;
        request.request_id =
            cocoa_clipboard_next_request_id(&clipboard->next_format_request_id);
        request.format_id = format->id;
        status = clipboard->sink.request(&request, clipboard->sink.user_data);
        if (status == LIBRDP_STATUS_OK)
        {
            format->request_id = request.request_id;
            format->state = COCOA_CLIPBOARD_FETCH_PENDING;
            return;
        }
        format->state = COCOA_CLIPBOARD_FETCH_FAILED;
    }
    clipboard->prefetch_pending = 0;
    (void)cocoa_clipboard_publish_native(clipboard);
}

static int cocoa_clipboard_has_type(NSPasteboard* pasteboard, NSString* type)
{
    return pasteboard && type &&
           [pasteboard availableTypeFromArray:@[ type ]] != nil;
}

static void
cocoa_clipboard_publish_local_formats(cocoa_server_clipboard* clipboard)
{
    server_platform_clipboard_format formats[COCOA_CLIPBOARD_MAX_FORMATS];
    size_t count = 0u;
    cocoa_clipboard_format_class format_class = 0;

    if (!clipboard || !clipboard->started || !clipboard->sink.formats)
        return;
    memset(formats, 0, sizeof(formats));
    for (format_class = COCOA_CLIPBOARD_FORMAT_TEXT;
         format_class <= COCOA_CLIPBOARD_FORMAT_FILES;
         format_class++)
    {
        NSString* type = cocoa_clipboard_native_type(format_class);

        if (!cocoa_clipboard_has_type(clipboard->pasteboard, type))
            continue;
        formats[count].id = cocoa_clipboard_default_format_id(format_class);
        formats[count].mime_type = cocoa_clipboard_mime(format_class);
        count++;
    }
    clipboard->local_generation++;
    if (clipboard->local_generation == 0u)
        clipboard->local_generation++;
    server_clipboard_files_reset(clipboard->local_files);
    clipboard->sink.formats(
        formats, count, clipboard->local_generation, clipboard->sink.user_data);
}

static librdp_status cocoa_clipboard_read_file_urls(
    cocoa_server_clipboard* clipboard, uint8_t** output, size_t* output_len)
{
    NSDictionary* options = @{NSPasteboardURLReadingFileURLsOnlyKey : @YES};
    NSArray* urls =
        [clipboard->pasteboard readObjectsForClasses:@[ [NSURL class] ]
                                             options:options];
    NSMutableData* uri_list = [NSMutableData data];

    if (!output || !output_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (NSURL* url in urls)
    {
        NSData* encoded = nil;
        static const uint8_t separator[] = {'\r', '\n'};

        if (![url isFileURL])
            continue;
        encoded = [[url absoluteString] dataUsingEncoding:NSUTF8StringEncoding];
        if (!encoded ||
            [encoded length] > COCOA_CLIPBOARD_MAX_BYTES - sizeof(separator) ||
            [uri_list length] > COCOA_CLIPBOARD_MAX_BYTES - [encoded length] -
                                    sizeof(separator))
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        [uri_list appendData:encoded];
        [uri_list appendBytes:separator length:sizeof(separator)];
    }
    if ([uri_list length] == 0u)
        return LIBRDP_STATUS_UNSUPPORTED;
    return server_clipboard_files_import_uri_list(clipboard->local_files,
                                                  [uri_list bytes],
                                                  (size_t)[uri_list length],
                                                  clipboard->local_generation,
                                                  output,
                                                  output_len);
}

static librdp_status
cocoa_clipboard_read_wire(cocoa_server_clipboard* clipboard,
                          uint32_t format_id,
                          uint8_t** output,
                          size_t* output_len)
{
    cocoa_clipboard_format_class format_class =
        cocoa_clipboard_class(format_id, NULL);
    NSData* native = nil;

    if (!clipboard || !output || !output_len || format_class == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = NULL;
    *output_len = 0u;
    if (format_class == COCOA_CLIPBOARD_FORMAT_FILES)
        return cocoa_clipboard_read_file_urls(clipboard, output, output_len);
    if (format_class == COCOA_CLIPBOARD_FORMAT_TEXT)
    {
        NSString* string =
            [clipboard->pasteboard stringForType:NSPasteboardTypeString];
        NSData* encoded = nil;
        size_t length = 0u;

        if (!string)
            return LIBRDP_STATUS_UNSUPPORTED;
        encoded = [string dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        if (!encoded || [encoded length] > COCOA_CLIPBOARD_MAX_BYTES - 2u)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        length = (size_t)[encoded length];
        *output = (uint8_t*)calloc(1u, length + 2u);
        if (!*output)
            return LIBRDP_STATUS_NO_MEMORY;
        if (length > 0u)
            memcpy(*output, [encoded bytes], length);
        *output_len = length + 2u;
        return LIBRDP_STATUS_OK;
    }
    native = [clipboard->pasteboard
        dataForType:cocoa_clipboard_native_type(format_class)];
    if (!native || [native length] > COCOA_CLIPBOARD_MAX_BYTES)
        return native ? LIBRDP_STATUS_LIMIT_EXCEEDED
                      : LIBRDP_STATUS_UNSUPPORTED;
    if (format_class == COCOA_CLIPBOARD_FORMAT_HTML)
        return cocoa_clipboard_html_package(native, output, output_len);
    if (format_class == COCOA_CLIPBOARD_FORMAT_PNG)
    {
        NSBitmapImageRep* image =
            [[[NSBitmapImageRep alloc] initWithData:native] autorelease];

        if (!image)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *output_len = (size_t)[native length];
    *output = (uint8_t*)malloc(*output_len > 0u ? *output_len : 1u);
    if (!*output)
        return LIBRDP_STATUS_NO_MEMORY;
    if (*output_len > 0u)
        memcpy(*output, [native bytes], *output_len);
    return LIBRDP_STATUS_OK;
}

static void cocoa_clipboard_deliver_local_data(
    cocoa_server_clipboard* clipboard, uint64_t request_id, uint32_t format_id)
{
    server_platform_clipboard_data response;
    uint8_t* data = NULL;
    size_t data_len = 0u;
    size_t offset = 0u;
    librdp_status status =
        cocoa_clipboard_read_wire(clipboard, format_id, &data, &data_len);

    do
    {
        size_t chunk = status == LIBRDP_STATUS_OK ? data_len - offset : 0u;

        if (chunk > COCOA_CLIPBOARD_CHUNK_BYTES)
            chunk = COCOA_CLIPBOARD_CHUNK_BYTES;
        memset(&response, 0, sizeof(response));
        response.ownership_generation = clipboard->local_generation;
        response.request_id = request_id;
        response.format_id = format_id;
        response.status = status;
        response.data = status == LIBRDP_STATUS_OK ? data + offset : NULL;
        response.data_len = chunk;
        response.final_chunk =
            status != LIBRDP_STATUS_OK || offset + chunk == data_len;
        clipboard->sink.data(&response, clipboard->sink.user_data);
        offset += chunk;
    } while (status == LIBRDP_STATUS_OK && offset < data_len);
    free(data);
}

static librdp_status
cocoa_clipboard_start(void* opaque, const server_platform_clipboard_sink* sink)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || !sink || !sink->formats || !sink->data ||
        !sink->request || !sink->file_request || !sink->cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (clipboard->started)
        return LIBRDP_STATUS_STATE;
    clipboard->sink = *sink;
    clipboard->stopping = 0;
    clipboard->started = 1;
    clipboard->observed_change_count = -1;
    cocoa_clipboard_wakeup(clipboard);
    return LIBRDP_STATUS_OK;
}

static void cocoa_clipboard_stop(void* opaque)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard)
        return;
    pthread_mutex_lock(&clipboard->lock);
    clipboard->stopping = 1;
    pthread_mutex_unlock(&clipboard->lock);
    cocoa_clipboard_remote_clear(clipboard, 1);
    server_clipboard_files_reset(clipboard->local_files);
    memset(&clipboard->sink, 0, sizeof(clipboard->sink));
    clipboard->started = 0;
}

static librdp_status
cocoa_clipboard_publish_formats(void* opaque,
                                const server_platform_clipboard_offer* offer)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;
    size_t index = 0u;

    if (!clipboard || !clipboard->started || !offer || offer->peer_id == 0u ||
        offer->generation == 0u || offer->ownership_generation == 0u ||
        offer->format_count > COCOA_CLIPBOARD_MAX_FORMATS ||
        (offer->format_count > 0u && !offer->formats))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    cocoa_clipboard_remote_clear(clipboard, 1);
    clipboard->remote_peer_id = offer->peer_id;
    clipboard->remote_peer_generation = offer->generation;
    clipboard->remote_ownership_generation = offer->ownership_generation;
    for (index = 0u; index < offer->format_count; index++)
    {
        cocoa_clipboard_format_class format_class = cocoa_clipboard_class(
            offer->formats[index].id, offer->formats[index].mime_type);
        size_t duplicate = 0u;

        if (format_class == 0)
            continue;
        for (duplicate = 0u; duplicate < clipboard->remote_format_count;
             duplicate++)
        {
            if (clipboard->remote_formats[duplicate].format_class ==
                format_class)
                break;
        }
        if (duplicate < clipboard->remote_format_count)
            continue;
        clipboard->remote_formats[clipboard->remote_format_count].id =
            offer->formats[index].id;
        clipboard->remote_formats[clipboard->remote_format_count].format_class =
            format_class;
        clipboard->remote_formats[clipboard->remote_format_count].state =
            COCOA_CLIPBOARD_FETCH_NEW;
        clipboard->remote_format_count++;
    }
    clipboard->prefetch_pending = 1;
    cocoa_clipboard_wakeup(clipboard);
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_clipboard_request_data(void* opaque,
                                                  uint64_t request_id,
                                                  uint32_t format_id)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || !clipboard->started || request_id == 0u ||
        format_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    cocoa_clipboard_deliver_local_data(clipboard, request_id, format_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_clipboard_request_file(
    void* opaque, const server_platform_clipboard_file_request* request)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;
    server_platform_clipboard_data response;
    uint8_t* data = NULL;
    size_t data_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!clipboard || !clipboard->started || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = server_clipboard_files_read(
        clipboard->local_files, request, &data, &data_len);
    memset(&response, 0, sizeof(response));
    response.peer_id = request->peer_id;
    response.generation = request->generation;
    response.ownership_generation = request->ownership_generation;
    response.request_id = request->request_id;
    response.stream_id = request->stream_id;
    response.status = status;
    response.data = status == LIBRDP_STATUS_OK ? data : NULL;
    response.data_len = status == LIBRDP_STATUS_OK ? data_len : 0u;
    response.final_chunk = 1;
    clipboard->sink.data(&response, clipboard->sink.user_data);
    free(data);
    return status;
}

/*
 * Correlate protocol completions before exposing bytes to AppKit. File-range
 * replies are accepted only for the active promise wait; regular format
 * replies must match peer, reconnect and ownership generations and are
 * committed only after native decoding succeeds.
 */
static librdp_status
cocoa_clipboard_write_data(void* opaque,
                           const server_platform_clipboard_data* data)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;
    size_t index = 0u;

    if (!clipboard || !clipboard->started || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data->stream_id != 0u)
    {
        pthread_mutex_lock(&clipboard->lock);
        if (!clipboard->file_wait.active || clipboard->file_wait.cancelled ||
            clipboard->file_wait.request.request_id != data->request_id ||
            clipboard->file_wait.request.stream_id != data->stream_id ||
            clipboard->file_wait.request.peer_id != data->peer_id ||
            clipboard->file_wait.request.generation != data->generation ||
            clipboard->file_wait.request.ownership_generation !=
                data->ownership_generation)
        {
            pthread_mutex_unlock(&clipboard->lock);
            return LIBRDP_STATUS_STATE;
        }
        pthread_mutex_unlock(&clipboard->lock);
        if (!data->final_chunk || (!data->data && data->data_len > 0u) ||
            data->data_len > COCOA_CLIPBOARD_FILE_CHUNK_BYTES)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        cocoa_clipboard_file_wait_finish(
            clipboard, data->status, data->data, data->data_len);
        return data->status;
    }
    if (data->peer_id != clipboard->remote_peer_id ||
        data->generation != clipboard->remote_peer_generation ||
        data->ownership_generation != clipboard->remote_ownership_generation ||
        !data->final_chunk)
        return LIBRDP_STATUS_STATE;
    for (index = 0u; index < clipboard->remote_format_count; index++)
    {
        cocoa_clipboard_remote_format* format =
            &clipboard->remote_formats[index];
        librdp_status status = data->status;

        if (format->state != COCOA_CLIPBOARD_FETCH_PENDING ||
            format->request_id != data->request_id ||
            format->id != data->format_id)
            continue;
        if (status == LIBRDP_STATUS_OK)
            status =
                cocoa_clipboard_decode_remote_data(clipboard, format, data);
        format->state = status == LIBRDP_STATUS_OK
                            ? COCOA_CLIPBOARD_FETCH_READY
                            : COCOA_CLIPBOARD_FETCH_FAILED;
        clipboard->prefetch_pending = 1;
        cocoa_clipboard_wakeup(clipboard);
        return status;
    }
    return LIBRDP_STATUS_STATE;
}

static void
cocoa_clipboard_cancel_peer(void* opaque, uint32_t peer_id, uint32_t generation)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || peer_id != clipboard->remote_peer_id ||
        generation != clipboard->remote_peer_generation)
        return;
    cocoa_clipboard_remote_clear(clipboard, 1);
}

static void cocoa_clipboard_release_ownership(void* opaque, uint64_t generation)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || generation != clipboard->remote_ownership_generation)
        return;
    cocoa_clipboard_remote_clear(clipboard, 1);
}

static librdp_status cocoa_clipboard_get_pollfds(void* opaque,
                                                 struct pollfd* fds,
                                                 size_t capacity,
                                                 size_t* count)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || !count || (!fds && capacity != 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 1u;
    if (!fds)
        return LIBRDP_STATUS_OK;
    if (capacity < 1u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    fds[0].fd = clipboard->wakeup_read_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_clipboard_notify_poll(void* opaque,
                                                 const struct pollfd* fds,
                                                 size_t count)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || (count > 0u && !fds))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count == 0u)
        return LIBRDP_STATUS_OK;
    if (count != 1u || fds[0].fd != clipboard->wakeup_read_fd)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    return LIBRDP_STATUS_OK;
}

static void cocoa_clipboard_drain(cocoa_server_clipboard* clipboard)
{
    uint8_t bytes[64];
    ssize_t received = 0;

    if (!clipboard)
        return;
    do
    {
        received = read(clipboard->wakeup_read_fd, bytes, sizeof(bytes));
    } while (received > 0 || (received < 0 && errno == EINTR));
}

static void
cocoa_clipboard_dispatch_file_request(cocoa_server_clipboard* clipboard)
{
    server_platform_clipboard_file_request request;
    uint32_t cancel_peer = 0u;
    uint32_t cancel_generation = 0u;
    uint64_t cancel_ownership = 0u;
    uint64_t cancel_request = 0u;
    int have_request = 0;
    int have_cancel = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!clipboard)
        return;
    memset(&request, 0, sizeof(request));
    pthread_mutex_lock(&clipboard->lock);
    if (clipboard->file_wait.active && clipboard->file_wait.queued &&
        !clipboard->file_wait.cancelled)
    {
        request = clipboard->file_wait.request;
        clipboard->file_wait.queued = 0;
        have_request = 1;
    }
    if (clipboard->file_wait.cancel_queued)
    {
        cancel_peer = clipboard->file_wait.request.peer_id;
        cancel_generation = clipboard->file_wait.request.generation;
        cancel_ownership = clipboard->file_wait.request.ownership_generation;
        cancel_request = clipboard->file_wait.request.request_id;
        clipboard->file_wait.cancel_queued = 0;
        have_cancel = 1;
    }
    pthread_mutex_unlock(&clipboard->lock);
    if (have_cancel)
    {
        (void)clipboard->sink.cancel(cancel_peer,
                                     cancel_generation,
                                     cancel_ownership,
                                     cancel_request,
                                     clipboard->sink.user_data);
    }
    if (!have_request)
        return;
    status = clipboard->sink.file_request(&request, clipboard->sink.user_data);
    if (status != LIBRDP_STATUS_OK)
    {
        cocoa_clipboard_file_wait_finish(clipboard, status, NULL, 0u);
    }
}

static librdp_status cocoa_clipboard_dispatch(void* opaque,
                                              unsigned int max_events)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;
    NSInteger change_count = 0;

    if (!clipboard || !clipboard->started || max_events == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    cocoa_clipboard_drain(clipboard);
    cocoa_clipboard_dispatch_file_request(clipboard);
    cocoa_clipboard_prefetch(clipboard);
    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                             beforeDate:[NSDate date]];
    change_count = [clipboard->pasteboard changeCount];
    if (change_count != clipboard->observed_change_count)
    {
        clipboard->observed_change_count = change_count;
        if (change_count != clipboard->remote_change_count)
            cocoa_clipboard_publish_local_formats(clipboard);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status cocoa_clipboard_get_next_timeout(void* opaque,
                                                      int* timeout_ms)
{
    cocoa_server_clipboard* clipboard = (cocoa_server_clipboard*)opaque;

    if (!clipboard || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = COCOA_CLIPBOARD_POLL_MS;
    return LIBRDP_STATUS_OK;
}

static const server_platform_event_source_vtable cocoa_clipboard_events = {
    SERVER_PLATFORM_EVENT_SOURCE_VERSION,
    sizeof(server_platform_event_source_vtable),
    cocoa_clipboard_get_pollfds,
    cocoa_clipboard_notify_poll,
    cocoa_clipboard_dispatch,
    cocoa_clipboard_get_next_timeout,
};

const server_platform_clipboard_vtable cocoa_server_clipboard_vtable = {
    SERVER_PLATFORM_CLIPBOARD_VERSION,
    sizeof(server_platform_clipboard_vtable),
    cocoa_clipboard_start,
    cocoa_clipboard_stop,
    cocoa_clipboard_publish_formats,
    cocoa_clipboard_request_data,
    cocoa_clipboard_request_file,
    cocoa_clipboard_write_data,
    cocoa_clipboard_cancel_peer,
    cocoa_clipboard_release_ownership,
    &cocoa_clipboard_events,
};

static cocoa_server_clipboard*
cocoa_server_clipboard_create(NSPasteboard* pasteboard)
{
    cocoa_server_clipboard* clipboard = NULL;

    if (!pasteboard)
        return NULL;
    clipboard = (cocoa_server_clipboard*)calloc(1u, sizeof(*clipboard));
    if (!clipboard)
        return NULL;
    clipboard->wakeup_read_fd = -1;
    clipboard->wakeup_write_fd = -1;
    clipboard->next_format_request_id = 1u;
    clipboard->next_file_request_id = 2u;
    clipboard->next_stream_id = 1u;
    clipboard->observed_change_count = -1;
    clipboard->remote_change_count = -1;
    clipboard->pasteboard = [pasteboard retain];
    clipboard->promise_queue = [[NSOperationQueue alloc] init];
    clipboard->promise_objects = [[NSMutableArray alloc] init];
    clipboard->local_files = server_clipboard_files_new();
    if (clipboard->promise_queue)
    {
        [clipboard->promise_queue setMaxConcurrentOperationCount:1];
        [clipboard->promise_queue
            setQualityOfService:NSQualityOfServiceUtility];
    }
    if (!clipboard->pasteboard || !clipboard->promise_queue ||
        !clipboard->promise_objects || !clipboard->local_files ||
        pthread_mutex_init(&clipboard->lock, NULL) != 0)
    {
        cocoa_server_clipboard_free(clipboard);
        return NULL;
    }
    clipboard->lock_ready = 1;
    if (pthread_cond_init(&clipboard->condition, NULL) != 0)
    {
        cocoa_server_clipboard_free(clipboard);
        return NULL;
    }
    clipboard->condition_ready = 1;
    if (!cocoa_clipboard_create_pipe(clipboard))
    {
        cocoa_server_clipboard_free(clipboard);
        return NULL;
    }
    return clipboard;
}

cocoa_server_clipboard* cocoa_server_clipboard_new(void)
{
    return cocoa_server_clipboard_create([NSPasteboard generalPasteboard]);
}

#ifdef LIBRDP_COCOA_SERVER_TESTING
cocoa_server_clipboard*
cocoa_server_clipboard_new_named(const char* pasteboard_name)
{
    NSString* name = nil;

    if (!pasteboard_name)
        return NULL;
    name = [NSString stringWithUTF8String:pasteboard_name];
    if (!name)
        return NULL;
    return cocoa_server_clipboard_create(
        [NSPasteboard pasteboardWithName:name]);
}
#endif

void cocoa_server_clipboard_revoke(cocoa_server_clipboard* clipboard)
{
    if (!clipboard)
        return;
    cocoa_clipboard_remote_clear(clipboard, 1);
    server_clipboard_files_reset(clipboard->local_files);
}

void cocoa_server_clipboard_free(cocoa_server_clipboard* clipboard)
{
    if (!clipboard)
        return;
    if (clipboard->started)
        cocoa_clipboard_stop(clipboard);
    else
        cocoa_server_clipboard_revoke(clipboard);
    server_clipboard_files_free(clipboard->local_files);
    clipboard->local_files = NULL;
    if (clipboard->wakeup_read_fd >= 0)
        close(clipboard->wakeup_read_fd);
    if (clipboard->wakeup_write_fd >= 0)
        close(clipboard->wakeup_write_fd);
    if (clipboard->condition_ready)
        pthread_cond_destroy(&clipboard->condition);
    if (clipboard->lock_ready)
        pthread_mutex_destroy(&clipboard->lock);
    [clipboard->promise_objects release];
    [clipboard->promise_queue release];
    [clipboard->pasteboard release];
    memset(clipboard, 0, sizeof(*clipboard));
    free(clipboard);
}
