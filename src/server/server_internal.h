/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal server object contract.
 * Invariants: public config strings are copied before storage and released by
 * the server object; runtime listener state is added only through this header.
 * Ownership: librdp_server owns copied config strings and future listener
 * descriptors until librdp_server_free().
 * Threading: server objects are single-owner unless a caller serializes all
 * access externally.
 * Trust boundary: server configuration is local input and must be validated
 * before it influences sockets or wire behavior.
 */

#ifndef RDP_SERVER_INTERNAL_H
#define RDP_SERVER_INTERNAL_H

#include "common/buffer.h"

#include <librdp/server.h>

struct librdp_server
{
    char* bind_address;
    char* server_name;
    int listen_fd;
    uint16_t port;
    uint16_t local_port;
    uint32_t backlog;
    uint32_t max_peers;
    uint32_t accepted_peers;
    uint32_t width;
    uint32_t height;
};

struct librdp_server_peer
{
    int fd;
    librdp_server_peer_state state;
    rdp_buffer input;
};

#endif
