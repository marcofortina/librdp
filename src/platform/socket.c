/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: portable socket, polling, and address-resolution abstraction for
 * supported Unix-like platforms.
 * Invariants: file descriptors, TLS state, and buffered bytes are updated only
 * after successful system calls.
 * Ownership: file descriptors are owned by transport objects and closed on
 * every error path.
 * Threading: not internally synchronized; callers must serialize access
 * through the owning session or transport.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "platform/socket.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

int rdp_socket_set_nonblocking(int fd, int enabled)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (enabled)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int rdp_socket_set_nodelay(int fd)
{
    int enabled = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
}

int rdp_socket_close(int fd)
{
    if (fd < 0)
        return 0;
    return close(fd);
}
