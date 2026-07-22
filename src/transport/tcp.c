/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: TCP connect, read, write, wait, and timeout implementation.
 * Invariants: file descriptors, TLS state, and buffered bytes are updated only
 * after successful system calls.
 * Ownership: socket ownership transfers to the transport only after successful
 * setup.
 * Threading: not internally synchronized; callers must serialize access
 * through the owning session or transport.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "transport/tcp.h"

#include "common/trace.h"
#include "platform/socket.h"

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Reject inputs that cannot be DNS names or numeric network addresses. */
static int rdp_tcp_host_valid(const char* host)
{
    const unsigned char* cursor =
        (const unsigned char*)host;

    if (!cursor || *cursor == '\0')
        return 0;
    while (*cursor != '\0')
    {
        if (*cursor <= 0x20u || *cursor == 0x7fu)
            return 0;
        cursor++;
    }
    return 1;
}

/*
 * Wait for a nonblocking connect to finish and verify SO_ERROR before the
 * descriptor is handed to the transport. A writable descriptor alone does not
 * prove that the connection succeeded.
 */
librdp_status rdp_tcp_wait_connected(int fd, int timeout_ms)
{
    struct pollfd pfd;
    int result = 0;
    int error_value = 0;
    socklen_t error_len = (socklen_t)sizeof(error_value);

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    result = poll(&pfd, 1, timeout_ms);
    if (result == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (result < 0)
        return errno == EINTR ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_IO_ERROR;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error_value, &error_len) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    if (error_value != 0)
        return LIBRDP_STATUS_IO_ERROR;

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_tcp_connect(const char* host, uint16_t port, int timeout_ms, int* out_fd)
{
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;
    struct addrinfo* it = NULL;
    char service[16];
    int rc = 0;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    if (!host || !out_fd || port == 0 || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (!rdp_tcp_host_valid(host))
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.tcp.resolve.failed",
                        "code=%d",
                        EAI_NONAME);
        return LIBRDP_STATUS_IO_ERROR;
    }

    *out_fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);

    rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.connect.start", "host=%s port=%u", host, (unsigned)port);
    rc = getaddrinfo(host, service, &hints, &addresses);
    if (rc != 0)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.resolve.failed", "code=%d", rc);
        return LIBRDP_STATUS_IO_ERROR;
    }

    for (it = addresses; it; it = it->ai_next)
    {
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;

        if (rdp_socket_set_nosigpipe(fd) != 0 ||
            rdp_socket_set_nonblocking(fd, 1) != 0)
        {
            rdp_socket_close(fd);
            continue;
        }

        rc = connect(fd, it->ai_addr, it->ai_addrlen);
        if (rc != 0 && errno != EINPROGRESS)
        {
            rdp_socket_close(fd);
            continue;
        }

        status = (rc == 0) ? LIBRDP_STATUS_OK : rdp_tcp_wait_connected(fd, timeout_ms);
        if (status == LIBRDP_STATUS_OK && rdp_socket_set_nonblocking(fd, 0) != 0)
            status = LIBRDP_STATUS_IO_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            (void)rdp_socket_set_nodelay(fd);
            *out_fd = fd;
            break;
        }

        rdp_socket_close(fd);
    }

    freeaddrinfo(addresses);

    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.connect.done", "fd=%d", *out_fd);
    else
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.connect.failed", "status=%d", (int)status);

    return status;
}
