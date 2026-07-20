/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal server-redirection and session-selection contracts.
 * Invariants: redirected targets, routing tokens, credentials, and session
 * identifiers are committed atomically and bounded by a finite hop count.
 * Ownership: the session owns all staged strings and routing bytes.
 * Threading: redirection processing runs on the session owner thread.
 * Trust boundary: every field originates from an untrusted server packet and
 * remains unavailable to connection code until semantic validation succeeds.
 */

#ifndef RDP_CLIENT_SESSION_REDIRECTION_H
#define RDP_CLIENT_SESSION_REDIRECTION_H

#include <librdp/session.h>

#include "protocol/session_selection.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_SESSION_MAX_SERVER_REDIRECTS 8u

typedef struct rdp_session_redirection_state
{
    char* target_host;
    rdp_buffer routing_data;
    librdp_credentials credentials;
    uint32_t session_id;
    uint32_t flags;
    uint32_t hop_count;
    uint8_t active;
} rdp_session_redirection_state;

librdp_status rdp_session_redirection_init(librdp_session* session);
void rdp_session_redirection_clear(librdp_session* session);
const char* rdp_session_redirection_target(const librdp_session* session);
const void* rdp_session_redirection_routing_data(
    const librdp_session* session,
    size_t* length);
const librdp_credentials* rdp_session_redirection_credentials(
    const librdp_session* session);
uint32_t rdp_session_redirection_session_id(const librdp_session* session);
uint8_t rdp_session_redirection_active(const librdp_session* session);
librdp_status rdp_session_redirection_stage(
    librdp_session* session,
    const rdp_server_redirection_packet* packet,
    int* reconnect);
librdp_status rdp_session_redirection_follow(librdp_session* session);

#endif
