/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral desktop-server provider contracts.
 * Invariants: provider tables are immutable while registered, callback payloads
 * are borrowed for the callback duration, and native platform handles never
 * cross this boundary.
 * Ownership: the frontend owns provider contexts and all callback payloads;
 * the shared host owns no native resources.
 * Threading: provider methods and callbacks run on the serialized server-host
 * thread unless a provider documents an internal worker and posts completion
 * through its event source.
 * Trust boundary: providers validate native events before producing normalized
 * capture, pointer, clipboard, drive, or permission data.
 */

#ifndef LIBRDP_APP_SERVER_PLATFORM_H
#define LIBRDP_APP_SERVER_PLATFORM_H

#include <librdp/librdp.h>

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#define SERVER_PLATFORM_EVENT_SOURCE_VERSION 1u
#define SERVER_PLATFORM_CAPTURE_VERSION 1u
#define SERVER_PLATFORM_POINTER_VERSION 1u
#define SERVER_PLATFORM_INPUT_VERSION 1u
#define SERVER_PLATFORM_CLIPBOARD_VERSION 4u
#define SERVER_PLATFORM_DRIVE_VERSION 2u
#define SERVER_PLATFORM_PERMISSION_VERSION 1u

typedef struct server_platform_rect
{
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} server_platform_rect;

typedef struct server_platform_frame
{
    uint32_t width;
    uint32_t height;
    size_t stride;
    const uint8_t* pixels;
    size_t pixels_len;
    const server_platform_rect* dirty_rects;
    size_t dirty_count;
    uint64_t sequence;
    uint64_t timestamp_ns;
} server_platform_frame;

typedef struct server_platform_pointer
{
    uint32_t width;
    uint32_t height;
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    int32_t x;
    int32_t y;
    size_t stride;
    const uint8_t* pixels;
    size_t pixels_len;
    uint64_t sequence;
    int visible;
    int shape_valid;
} server_platform_pointer;

typedef struct server_platform_clipboard_format
{
    uint32_t id;
    const char* mime_type;
} server_platform_clipboard_format;

typedef struct server_platform_clipboard_offer
{
    uint32_t peer_id;
    uint32_t generation;
    uint64_t ownership_generation;
    const server_platform_clipboard_format* formats;
    size_t format_count;
} server_platform_clipboard_offer;

typedef struct server_platform_clipboard_data
{
    uint32_t peer_id;
    uint32_t generation;
    uint64_t ownership_generation;
    uint64_t request_id;
    uint32_t format_id;
    uint32_t stream_id;
    librdp_status status;
    const uint8_t* data;
    size_t data_len;
    int final_chunk;
} server_platform_clipboard_data;

typedef struct server_platform_clipboard_request
{
    uint32_t peer_id;
    uint32_t generation;
    uint64_t ownership_generation;
    uint64_t request_id;
    uint32_t format_id;
} server_platform_clipboard_request;

typedef struct server_platform_clipboard_file_request
{
    uint32_t peer_id;
    uint32_t generation;
    uint64_t ownership_generation;
    uint64_t request_id;
    uint32_t stream_id;
    int32_t file_index;
    uint32_t flags;
    uint64_t position;
    uint32_t requested_bytes;
    uint8_t has_clip_data_id;
    uint32_t clip_data_id;
} server_platform_clipboard_file_request;

typedef struct server_platform_drive_volume
{
    uint64_t volume_id;
    uint32_t peer_id;
    uint32_t generation;
    librdp_server_drive_device_handle device;
    const char* name;
    int read_only;
} server_platform_drive_volume;

typedef struct server_platform_drive_request
{
    uint64_t request_id;
    uint64_t volume_id;
    uint32_t peer_id;
    uint32_t generation;
    librdp_server_drive_request operation;
} server_platform_drive_request;

typedef struct server_platform_drive_completion
{
    uint64_t request_id;
    uint64_t volume_id;
    uint32_t peer_id;
    uint32_t generation;
    librdp_server_drive_event_type type;
    librdp_status status;
    uint32_t io_status;
    librdp_server_drive_operation operation;
    librdp_server_drive_device_handle device;
    librdp_server_drive_file_handle file;
    uint32_t information_class;
    uint32_t information;
    uint64_t transferred;
    const uint8_t* data;
    size_t data_len;
} server_platform_drive_completion;

typedef enum server_platform_permission_kind
{
    SERVER_PLATFORM_PERMISSION_CAPTURE = 1,
    SERVER_PLATFORM_PERMISSION_INPUT = 2,
    SERVER_PLATFORM_PERMISSION_CLIPBOARD = 3,
    SERVER_PLATFORM_PERMISSION_DRIVE = 4
} server_platform_permission_kind;

typedef enum server_platform_permission_state
{
    SERVER_PLATFORM_PERMISSION_UNKNOWN = 0,
    SERVER_PLATFORM_PERMISSION_DENIED = 1,
    SERVER_PLATFORM_PERMISSION_GRANTED = 2
} server_platform_permission_state;

typedef void (*server_platform_frame_callback)(const server_platform_frame* frame,
                                               void* user_data);
typedef void (*server_platform_capture_lost_callback)(librdp_status status,
                                                      void* user_data);
typedef void (*server_platform_pointer_callback)(const server_platform_pointer* pointer,
                                                 void* user_data);
typedef void (*server_platform_clipboard_formats_callback)(
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation,
    void* user_data);
typedef void (*server_platform_clipboard_data_callback)(
    const server_platform_clipboard_data* data,
    void* user_data);
typedef librdp_status (*server_platform_clipboard_request_callback)(
    const server_platform_clipboard_request* request,
    void* user_data);
typedef librdp_status (*server_platform_clipboard_file_request_callback)(
    const server_platform_clipboard_file_request* request,
    void* user_data);
typedef librdp_status (*server_platform_clipboard_cancel_callback)(
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    uint64_t request_id,
    void* user_data);
typedef void (*server_platform_drive_request_callback)(
    const server_platform_drive_request* request,
    void* user_data);
typedef void (*server_platform_drive_cancel_callback)(uint32_t peer_id,
                                                      uint32_t generation,
                                                      uint64_t request_id,
                                                      void* user_data);
typedef void (*server_platform_permission_callback)(server_platform_permission_kind kind,
                                                    server_platform_permission_state state,
                                                    void* user_data);

typedef struct server_platform_capture_sink
{
    server_platform_frame_callback frame;
    server_platform_capture_lost_callback lost;
    void* user_data;
} server_platform_capture_sink;

typedef struct server_platform_pointer_sink
{
    server_platform_pointer_callback update;
    void* user_data;
} server_platform_pointer_sink;

typedef struct server_platform_clipboard_sink
{
    server_platform_clipboard_formats_callback formats;
    server_platform_clipboard_data_callback data;
    server_platform_clipboard_request_callback request;
    server_platform_clipboard_file_request_callback file_request;
    server_platform_clipboard_cancel_callback cancel;
    void* user_data;
} server_platform_clipboard_sink;

typedef struct server_platform_drive_sink
{
    server_platform_drive_request_callback request;
    server_platform_drive_cancel_callback cancel;
    void* user_data;
} server_platform_drive_sink;

typedef struct server_platform_permission_sink
{
    server_platform_permission_callback changed;
    void* user_data;
} server_platform_permission_sink;

/*
 * Event-source methods expose only POSIX poll descriptors. get_pollfds accepts
 * fds NULL with capacity zero as a count query. A provider with no asynchronous
 * work leaves events NULL; otherwise all methods are required.
 */
typedef struct server_platform_event_source_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*get_pollfds)(void* context,
                                 struct pollfd* fds,
                                 size_t capacity,
                                 size_t* count);
    librdp_status (*notify_poll)(void* context,
                                const struct pollfd* fds,
                                size_t count);
    librdp_status (*dispatch)(void* context, unsigned int max_events);
    librdp_status (*get_next_timeout)(void* context, int* timeout_ms);
} server_platform_event_source_vtable;

typedef struct server_platform_capture_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*start)(void* context,
                           const server_platform_capture_sink* sink);
    void (*stop)(void* context);
    librdp_status (*request_frame)(void* context);
    const server_platform_event_source_vtable* events;
} server_platform_capture_vtable;

typedef struct server_platform_pointer_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*start)(void* context,
                           const server_platform_pointer_sink* sink);
    void (*stop)(void* context);
    const server_platform_event_source_vtable* events;
} server_platform_pointer_vtable;

typedef struct server_platform_input_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*inject)(void* context,
                            const librdp_server_input_event* event);
    void (*release_all)(void* context);
} server_platform_input_vtable;

typedef struct server_platform_clipboard_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*start)(void* context,
                           const server_platform_clipboard_sink* sink);
    void (*stop)(void* context);
    librdp_status (*publish_formats)(
        void* context,
        const server_platform_clipboard_offer* offer);
    librdp_status (*request_data)(void* context,
                                  uint64_t request_id,
                                  uint32_t format_id);
    librdp_status (*request_file)(void* context,
                                 const server_platform_clipboard_file_request* request);
    librdp_status (*write_data)(void* context,
                                const server_platform_clipboard_data* data);
    void (*cancel_peer)(void* context,
                        uint32_t peer_id,
                        uint32_t generation);
    void (*release_ownership)(void* context, uint64_t generation);
    const server_platform_event_source_vtable* events;
} server_platform_clipboard_vtable;

typedef struct server_platform_drive_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*start)(void* context,
                           const server_platform_drive_sink* sink);
    void (*stop)(void* context);
    librdp_status (*present)(void* context,
                             const server_platform_drive_volume* volume);
    void (*remove)(void* context,
                   uint32_t peer_id,
                   uint32_t generation,
                   uint32_t device_id);
    void (*remove_peer)(void* context,
                        uint32_t peer_id,
                        uint32_t generation);
    librdp_status (*complete)(
        void* context,
        const server_platform_drive_completion* completion);
    const server_platform_event_source_vtable* events;
} server_platform_drive_vtable;

typedef struct server_platform_permission_vtable
{
    uint32_t version;
    size_t size;
    librdp_status (*start)(void* context,
                           const server_platform_permission_sink* sink);
    void (*stop)(void* context);
    librdp_status (*query)(void* context,
                           server_platform_permission_kind kind,
                           server_platform_permission_state* state);
    /*
     * Successful request and revoke operations update query state before
     * notifying sink.changed on the serialized host thread.
     */
    librdp_status (*request)(void* context,
                             server_platform_permission_kind kind);
    librdp_status (*revoke)(void* context,
                            server_platform_permission_kind kind);
    const server_platform_event_source_vtable* events;
} server_platform_permission_vtable;

typedef struct server_platform_binding
{
    const void* vtable;
    void* context;
} server_platform_binding;

typedef struct server_platform
{
    server_platform_binding capture;
    server_platform_binding pointer;
    server_platform_binding input;
    server_platform_binding clipboard;
    server_platform_binding drive;
    server_platform_binding permission;
} server_platform;

typedef enum server_platform_provider_kind
{
    SERVER_PLATFORM_PROVIDER_CAPTURE = 0,
    SERVER_PLATFORM_PROVIDER_POINTER = 1,
    SERVER_PLATFORM_PROVIDER_INPUT = 2,
    SERVER_PLATFORM_PROVIDER_CLIPBOARD = 3,
    SERVER_PLATFORM_PROVIDER_DRIVE = 4,
    SERVER_PLATFORM_PROVIDER_PERMISSION = 5,
    SERVER_PLATFORM_PROVIDER_COUNT = 6
} server_platform_provider_kind;

void server_platform_init(server_platform* platform);
librdp_status server_platform_validate(const server_platform* platform);
int server_platform_provider_ready(const server_platform* platform,
                                   server_platform_provider_kind kind);
const server_platform_event_source_vtable* server_platform_provider_events(
    const server_platform* platform,
    server_platform_provider_kind kind,
    void** context);

#endif
