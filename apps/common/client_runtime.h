/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared client session and poll-loop orchestration.
 * Invariants: the runtime borrows one session, preserves native descriptor
 * ordering, and performs bounded protocol dispatch after each poll result.
 * Ownership: the runtime owns only its merged poll array; the session and
 * native descriptors remain frontend-owned.
 * Threading: connect, prepare, dispatch, and disconnect run on one owner
 * thread; cancel is the only cross-thread operation.
 * Trust boundary: readiness flags are kernel input and protocol processing is
 * delegated exclusively to public librdp APIs.
 */

#ifndef LIBRDP_APP_CLIENT_RUNTIME_H
#define LIBRDP_APP_CLIENT_RUNTIME_H

#include <librdp/librdp.h>

#include <poll.h>
#include <stddef.h>

typedef struct client_runtime
{
    librdp_session* session;
    struct pollfd* pollfds;
    size_t poll_capacity;
    size_t poll_count;
    size_t native_count;
    size_t session_count;
    int connected;
} client_runtime;

void client_runtime_init(client_runtime* runtime, librdp_session* session);
void client_runtime_clear(client_runtime* runtime);
librdp_status client_runtime_connect(client_runtime* runtime);
librdp_status client_runtime_prepare_poll(client_runtime* runtime,
                                          const struct pollfd* native_fds,
                                          size_t native_count,
                                          int native_timeout_ms,
                                          struct pollfd** pollfds,
                                          size_t* poll_count,
                                          int* timeout_ms);
librdp_status client_runtime_dispatch_poll(client_runtime* runtime,
                                           unsigned int max_dispatch);
librdp_status client_runtime_cancel(client_runtime* runtime);
librdp_status client_runtime_disconnect(client_runtime* runtime);

#endif
