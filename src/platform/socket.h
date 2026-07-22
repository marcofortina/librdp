/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: portable socket abstraction for supported Unix-like platforms.
 * Invariants: socket/TLS handles and buffered bytes change ownership only on
 * successful setup or teardown calls.
 * Ownership: file descriptors are transferred only through explicit transport
 * ownership paths.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_PLATFORM_SOCKET_H
#define RDP_PLATFORM_SOCKET_H

int rdp_socket_set_nonblocking(int fd, int enabled);
int rdp_socket_get_nonblocking(int fd, int* enabled);
int rdp_socket_set_nodelay(int fd);
int rdp_socket_set_nosigpipe(int fd);
int rdp_socket_close(int fd);

#endif
