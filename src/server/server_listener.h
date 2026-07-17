/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: listener configuration, socket setup, and server construction.
 * Invariants: configuration is validated before sockets or peers are created.
 * Ownership: the listener owns copied configuration and its listening socket.
 * Threading: callers serialize access to each listener.
 * Trust boundary: local configuration is bounded before affecting resources.
 */

#ifndef RDP_SERVER_LISTENER_H
#define RDP_SERVER_LISTENER_H

#include "server/server_common.h"

librdp_status librdp_server_input_event_init(librdp_server_input_event* event);

librdp_status librdp_server_static_channel_info_init(librdp_server_static_channel_info* info);

librdp_status librdp_server_dynamic_channel_info_init(librdp_server_dynamic_channel_info* info);

librdp_status librdp_server_extension_event_init(librdp_server_extension_event* event);

librdp_status librdp_server_event_init(librdp_server_event* event);

librdp_status librdp_server_credentials_request_init(librdp_server_credentials_request* request);

int rdp_server_status_valid(const librdp_server_status* status);

int rdp_server_clipboard_state_valid(const librdp_server_clipboard_state* state);

int rdp_server_extension_state_valid(const librdp_server_extension_state* state);

#endif
