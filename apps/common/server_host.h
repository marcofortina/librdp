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
#include "server_platform.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define SERVER_HOST_CONFIG_VERSION 1u
#define SERVER_HOST_PEER_INFO_VERSION 1u
#define SERVER_HOST_MAX_PEERS 64u

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

typedef struct server_host_config
{
    uint32_t version;
    size_t size;
    librdp_server_config server;
    server_platform platform;
    server_dirty_config dirty;
    uint32_t max_peers;
    unsigned int max_work_per_iteration;
    server_host_input_policy input_policy;
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
size_t server_host_peer_count(const server_host* host);
librdp_status server_host_peer_at(const server_host* host,
                                  size_t index,
                                  server_host_peer_info* info);
librdp_status server_host_close_peer(server_host* host, uint32_t peer_id);

#endif
