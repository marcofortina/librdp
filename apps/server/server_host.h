/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral shared desktop-server host.
 * Invariants: one host owns one listener, peer slots are isolated by id and
 * generation, and only validated providers receive host callbacks.
 * Ownership: the host owns the listener, accepted peers and dirty schedulers;
 * platform vtables and contexts are borrowed until the host is freed.
 * Threading: host lifecycle and peer operations run on one owner thread.
 * Trust boundary: capture and input cross between native providers and
 * untrusted remote peers only through normalized, bounds-checked structures.
 */

#ifndef LIBRDP_APP_SERVER_HOST_H
#define LIBRDP_APP_SERVER_HOST_H

#include "server_dirty.h"
#include "server_clipboard.h"
#include "server_drive.h"
#include "server_platform.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define SERVER_HOST_CONFIG_VERSION 1u
#define SERVER_HOST_PEER_INFO_VERSION 1u
#define SERVER_HOST_TRACE_EVENT_VERSION 1u
#define SERVER_HOST_METRICS_VERSION 1u
#define SERVER_HOST_MAX_PEERS 64u
#define SERVER_HOST_POLL_FD_LIMIT 512u
#define SERVER_HOST_WORK_LIMIT 4096u

typedef enum server_host_state
{
    SERVER_HOST_NEW = 0,
    SERVER_HOST_STARTING = 1,
    SERVER_HOST_LISTENING = 2,
    SERVER_HOST_STOPPING = 3,
    SERVER_HOST_STOPPED = 4,
    SERVER_HOST_FAILED = 5
} server_host_state;

typedef enum server_host_provider_state
{
    SERVER_HOST_PROVIDER_UNAVAILABLE = 0,
    SERVER_HOST_PROVIDER_STOPPED = 1,
    SERVER_HOST_PROVIDER_STARTING = 2,
    SERVER_HOST_PROVIDER_READY = 3,
    SERVER_HOST_PROVIDER_DENIED = 4,
    SERVER_HOST_PROVIDER_FAILED = 5
} server_host_provider_state;

typedef enum server_host_peer_state
{
    SERVER_HOST_PEER_ACCEPTED = 1,
    SERVER_HOST_PEER_NEGOTIATING = 2,
    SERVER_HOST_PEER_ACTIVE = 3,
    SERVER_HOST_PEER_CLOSING = 4,
    SERVER_HOST_PEER_CLOSED = 5,
    SERVER_HOST_PEER_FAILED = 6
} server_host_peer_state;

typedef enum server_host_input_policy
{
    SERVER_HOST_INPUT_DISABLED = 0,
    SERVER_HOST_INPUT_FIRST_ACTIVE = 1,
    SERVER_HOST_INPUT_EXPLICIT = 2
} server_host_input_policy;

typedef enum server_host_trace_type
{
    SERVER_HOST_TRACE_LISTENER_START = 1,
    SERVER_HOST_TRACE_LISTENER_READY = 2,
    SERVER_HOST_TRACE_LISTENER_FAILED = 3,
    SERVER_HOST_TRACE_LISTENER_STOP = 4,
    SERVER_HOST_TRACE_PEER_ACCEPTED = 5,
    SERVER_HOST_TRACE_PEER_STATE = 6,
    SERVER_HOST_TRACE_PEER_CLEANUP = 7,
    SERVER_HOST_TRACE_CAPTURE_FRAME = 8,
    SERVER_HOST_TRACE_CAPTURE_DROPPED = 9,
    SERVER_HOST_TRACE_CAPTURE_LOST = 10,
    SERVER_HOST_TRACE_FRAME_PRESENTED = 11,
    SERVER_HOST_TRACE_FRAME_DEFERRED = 12,
    SERVER_HOST_TRACE_INPUT_ACCEPTED = 13,
    SERVER_HOST_TRACE_INPUT_REJECTED = 14,
    SERVER_HOST_TRACE_CLIPBOARD_EVENT = 15,
    SERVER_HOST_TRACE_CLIPBOARD_CLEANUP = 16,
    SERVER_HOST_TRACE_DRIVE_REQUEST = 17,
    SERVER_HOST_TRACE_DRIVE_CLEANUP = 18,
    SERVER_HOST_TRACE_PERMISSION_CHANGED = 19,
    SERVER_HOST_TRACE_QUEUE_PRESSURE = 20,
    SERVER_HOST_TRACE_WAKEUP = 21,
    SERVER_HOST_TRACE_SHUTDOWN_START = 22,
    SERVER_HOST_TRACE_SHUTDOWN_DONE = 23,
    SERVER_HOST_TRACE_POINTER_UPDATE = 24,
    SERVER_HOST_TRACE_POINTER_FAILED = 25,
    SERVER_HOST_TRACE_PROVIDER_POLL = 26,
    SERVER_HOST_TRACE_PROVIDER_DISPATCH = 27,
    SERVER_HOST_TRACE_REFRESH_REQUEST = 28,
    SERVER_HOST_TRACE_OUTPUT_SUPPRESSION = 29,
    SERVER_HOST_TRACE_PEER_ERROR = 30
} server_host_trace_type;

typedef struct server_host_trace_event
{
    uint32_t version;
    size_t size;
    uint64_t sequence;
    uint64_t timestamp_ns;
    server_host_trace_type type;
    const char* name;
    server_host_state host_state;
    uint32_t peer_id;
    uint32_t generation;
    librdp_status status;
    uint64_t value;
    uint64_t count;
} server_host_trace_event;

typedef void (*server_host_trace_callback)(
    const server_host_trace_event* event,
    void* user_data);

typedef struct server_host_metrics
{
    uint32_t version;
    size_t size;
    uint64_t listener_starts;
    uint64_t listener_stops;
    uint64_t listener_failures;
    uint64_t peers_accepted;
    uint64_t peers_closed;
    uint64_t peers_failed;
    uint64_t capture_frames;
    uint64_t capture_frames_dropped;
    uint64_t pointer_updates;
    uint64_t pointer_failures;
    uint64_t dirty_regions;
    uint64_t frames_presented;
    uint64_t frames_deferred;
    uint64_t queue_pressure;
    uint64_t input_events;
    uint64_t input_rejections;
    uint64_t clipboard_events;
    uint64_t clipboard_cleanups;
    uint64_t drive_requests;
    uint64_t drive_cleanups;
    uint64_t permission_denials;
    uint64_t wakeups;
    uint64_t cancellations;
    uint64_t loop_iterations;
} server_host_metrics;

typedef struct server_host_config
{
    uint32_t version;
    size_t size;
    librdp_server_config server;
    server_platform platform;
    server_dirty_config dirty;
    server_clipboard_config clipboard;
    server_drive_config drive;
    uint32_t max_peers;
    unsigned int max_work_per_iteration;
    server_host_input_policy input_policy;
    server_host_trace_callback trace_callback;
    void* trace_user_data;
    librdp_server_channel_callback channel_callback;
    void* channel_user_data;
    librdp_server_extension_callback extension_callback;
    void* extension_user_data;
    librdp_server_credentials_provider credentials_provider;
    void* credentials_provider_user_data;
} server_host_config;

typedef struct server_host_peer_info
{
    uint32_t version;
    size_t size;
    uint32_t id;
    uint32_t generation;
    server_host_peer_state state;
    librdp_server_peer_state protocol_state;
    uint32_t desktop_width;
    uint32_t desktop_height;
    int input_owner;
} server_host_peer_info;

typedef struct server_host server_host;

void server_host_config_init(server_host_config* config);
void server_host_peer_info_init(server_host_peer_info* info);
void server_host_metrics_init(server_host_metrics* metrics);
server_host* server_host_new(const server_host_config* config);
void server_host_free(server_host* host);
librdp_status server_host_start(server_host* host);
librdp_status server_host_stop(server_host* host);
server_host_state server_host_get_state(const server_host* host);
server_host_provider_state server_host_get_provider_state(
    const server_host* host,
    server_platform_provider_kind kind);
uint16_t server_host_local_port(const server_host* host);
librdp_status server_host_accept_pending(server_host* host);
librdp_status server_host_run_once(server_host* host, int timeout_ms);
librdp_status server_host_wakeup(server_host* host);
librdp_status server_host_cancel(server_host* host);
librdp_status server_host_set_input_owner(server_host* host,
                                          uint32_t peer_id);
uint32_t server_host_input_owner(const server_host* host);
librdp_status server_host_request_permission(
    server_host* host,
    server_platform_permission_kind kind);
librdp_status server_host_revoke_permission(
    server_host* host,
    server_platform_permission_kind kind);
librdp_status server_host_get_metrics(const server_host* host,
                                      server_host_metrics* metrics);
librdp_status server_host_reset_metrics(server_host* host);
const char* server_host_trace_name(server_host_trace_type type);
size_t server_host_peer_count(const server_host* host);
librdp_status server_host_peer_at(const server_host* host,
                                  size_t index,
                                  server_host_peer_info* info);
librdp_status server_host_close_peer(server_host* host, uint32_t peer_id);

#endif
