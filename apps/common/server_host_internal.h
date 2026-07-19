/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal state shared by desktop-server host modules.
 * Invariants: peer slots and poll storage belong to one host, and generations
 * distinguish every reuse of a slot.
 * Ownership: the host owns peer handles, schedulers, poll storage and wakeup
 * descriptors; platform contexts remain borrowed.
 * Threading: only cancellation_requested and the wakeup write descriptor are
 * touched cross-thread; every other field is owner-thread confined.
 * Trust boundary: poll and peer metadata remain private so native providers
 * cannot mutate protocol ownership directly.
 */

#ifndef LIBRDP_APP_SERVER_HOST_INTERNAL_H
#define LIBRDP_APP_SERVER_HOST_INTERNAL_H

#include "server_host.h"

#include <stdatomic.h>

typedef struct server_host_peer_slot
{
    struct server_host* host;
    librdp_server_peer* protocol;
    server_dirty_scheduler* dirty;
    uint32_t id;
    uint32_t generation;
    uint32_t surface_width;
    uint32_t surface_height;
    uint32_t clipboard_generation;
    server_host_peer_state state;
    int occupied;
    int input_owner;
} server_host_peer_slot;

struct server_host
{
    librdp_server* listener;
    server_platform platform;
    server_dirty_config dirty_config;
    server_host_peer_slot* peers;
    server_clipboard_runtime* clipboard;
    server_drive_runtime* drive;
    size_t peer_capacity;
    size_t peer_count;
    uint32_t next_peer_id;
    unsigned int max_work_per_iteration;
    server_host_input_policy input_policy;
    uint32_t input_owner_id;
    server_host_state state;
    server_host_provider_state provider_states[SERVER_PLATFORM_PROVIDER_COUNT];
    uint8_t provider_started[SERVER_PLATFORM_PROVIDER_COUNT];
    server_host_trace_callback trace_callback;
    void* trace_user_data;
    uint64_t trace_sequence;
    server_host_metrics metrics;
    uint16_t next_pointer_cache_index;
    uint8_t pointer_visible;
    uint8_t drive_configured;
    uint8_t capture_pending;
    int listener_running;
    struct pollfd* pollfds;
    size_t poll_capacity;
    int wakeup_read_fd;
    int wakeup_write_fd;
    atomic_int cancellation_requested;
};

server_host_peer_slot* server_host_find_peer_slot(server_host* host,
                                                  uint32_t peer_id);
void server_host_release_peer_slot(server_host_peer_slot* slot);
librdp_status server_host_dispatch_peer_input(
    server_host_peer_slot* slot,
    const librdp_server_input_event* event);
uint64_t server_host_now_ns(void);
void server_host_metric_add(uint64_t* counter, uint64_t amount);
void server_host_trace_emit(server_host* host,
                            server_host_trace_type type,
                            const server_host_peer_slot* peer,
                            librdp_status status,
                            uint64_t value,
                            uint64_t count);

#endif
