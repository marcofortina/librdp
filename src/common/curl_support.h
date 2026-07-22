/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: common libcurl socket policy for supported Unix-like platforms.
 * Invariants: each socket opened by an easy handle receives the platform
 * protection required to turn peer disconnects into ordinary I/O failures.
 * Ownership: the caller retains ownership of the easy handle and sockets.
 * Threading: configuration is handle-local and must precede network I/O.
 * Trust boundary: remote disconnects must never deliver process-wide signals.
 */

#ifndef RDP_COMMON_CURL_SUPPORT_H
#define RDP_COMMON_CURL_SUPPORT_H

int rdp_curl_apply_socket_policy(void* easy_handle);

#endif
