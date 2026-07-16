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
#include "protocol/gcc.h"
#include "security/security.h"

#include <librdp/server.h>

#include <openssl/types.h>

struct librdp_server
{
    char* bind_address;
    char* server_name;
    char* tls_certificate_path;
    char* tls_private_key_path;
    int listen_fd;
    uint16_t port;
    uint16_t local_port;
    uint32_t backlog;
    uint32_t max_peers;
    uint32_t accepted_peers;
    uint32_t width;
    uint32_t height;
    uint32_t requested_features;
    librdp_security_mode security_mode;
};

struct librdp_server_peer
{
    int fd;
    librdp_server_peer_state state;
    uint32_t selected_protocol;
    uint32_t share_id;
    uint16_t user_id;
    uint16_t width;
    uint16_t height;
    char* server_name;
    char* tls_certificate_path;
    char* tls_private_key_path;
    uint32_t requested_features;
    librdp_security_mode security_mode;
    SSL_CTX* tls_context;
    SSL* tls;
    EVP_PKEY* standard_private_key;
    rdp_standard_security_context standard_security;
    rdp_buffer standard_certificate;
    uint8_t standard_server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t tls_active;
    uint8_t standard_security_ready;
    short pending_revents;
    uint16_t advertised_channel_count;
    uint16_t joined_channel_count;
    rdp_gcc_channel_definition advertised_channels[RDP_GCC_MAX_SERVER_CHANNELS];
    uint16_t advertised_channel_ids[RDP_GCC_MAX_SERVER_CHANNELS];
    uint8_t advertised_channel_joined[RDP_GCC_MAX_SERVER_CHANNELS];
    uint8_t confirm_active_seen;
    uint8_t licensing_done;
    uint8_t client_info_seen;
    uint8_t synchronize_seen;
    uint8_t control_seen;
    uint8_t font_list_seen;
    uint8_t updates_suppressed;
    uint8_t* framebuffer;
    size_t framebuffer_len;
    size_t framebuffer_stride;
    librdp_server_input_callback input_callback;
    void* input_callback_user_data;
    librdp_server_channel_callback channel_callback;
    void* channel_callback_user_data;
    librdp_server_event_callback event_callback;
    void* event_callback_user_data;
    librdp_server_status last_status;
    librdp_server_metrics metrics;
    rdp_buffer input;
};

#endif
