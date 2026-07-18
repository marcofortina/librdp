/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared client session and poll-loop implementation.
 * Invariants: session descriptors occupy the tail of a merged array, internal
 * deadlines never lengthen a frontend deadline, and dispatch work is bounded.
 * Ownership: poll storage is runtime-owned and may move on each preparation;
 * callers borrow it only until the next runtime call.
 * Threading: serialized owner-thread operation except for thread-safe cancel.
 * Trust boundary: poll results are validated against the current descriptor
 * snapshot before they are handed to the protocol session.
 */

#include "client_runtime.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void client_runtime_init(client_runtime* runtime, librdp_session* session)
{
    if (!runtime)
        return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->session = session;
}

void client_runtime_clear(client_runtime* runtime)
{
    if (!runtime)
        return;
    if (runtime->connected && runtime->session)
        (void)librdp_session_disconnect(runtime->session);
    free(runtime->pollfds);
    memset(runtime, 0, sizeof(*runtime));
}

librdp_status client_runtime_connect(client_runtime* runtime)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (runtime->connected)
        return LIBRDP_STATUS_STATE;
    status = librdp_session_connect(runtime->session);
    if (status == LIBRDP_STATUS_OK)
        runtime->connected = 1;
    return status;
}

static librdp_status client_runtime_reserve_pollfds(client_runtime* runtime,
                                                    size_t count)
{
    struct pollfd* resized = NULL;

    if (!runtime)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count <= runtime->poll_capacity)
        return LIBRDP_STATUS_OK;
    if (count > SIZE_MAX / sizeof(*runtime->pollfds))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    resized = (struct pollfd*)realloc(runtime->pollfds,
                                     count * sizeof(*runtime->pollfds));
    if (!resized)
        return LIBRDP_STATUS_NO_MEMORY;
    runtime->pollfds = resized;
    runtime->poll_capacity = count;
    return LIBRDP_STATUS_OK;
}

static librdp_status client_runtime_refresh_session_pollfds(client_runtime* runtime)
{
    size_t session_count = 0;
    size_t total_count = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_session_get_pollfds(runtime->session, NULL, 0, &session_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (runtime->native_count > SIZE_MAX - session_count)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    total_count = runtime->native_count + session_count;
    status = client_runtime_reserve_pollfds(runtime, total_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session_count > 0)
    {
        status = librdp_session_get_pollfds(runtime->session,
                                            runtime->pollfds + runtime->native_count,
                                            session_count,
                                            &session_count);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    runtime->session_count = session_count;
    runtime->poll_count = runtime->native_count + session_count;
    return LIBRDP_STATUS_OK;
}

/*
 * Merge frontend descriptors with the current session snapshot. The returned
 * array is mutable for poll(2), but its storage remains runtime-owned and is
 * invalidated by the next prepare, dispatch, clear, or disconnect call.
 */
librdp_status client_runtime_prepare_poll(client_runtime* runtime,
                                          const struct pollfd* native_fds,
                                          size_t native_count,
                                          int native_timeout_ms,
                                          struct pollfd** pollfds,
                                          size_t* poll_count,
                                          int* timeout_ms)
{
    size_t session_count = 0;
    size_t total_count = 0;
    int session_timeout_ms = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->session || !pollfds || !poll_count || !timeout_ms ||
        (native_count > 0 && !native_fds) || native_timeout_ms < -1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!runtime->connected)
        return LIBRDP_STATUS_STATE;

    runtime->native_count = native_count;
    status = librdp_session_get_pollfds(runtime->session, NULL, 0, &session_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (native_count > SIZE_MAX - session_count)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    total_count = native_count + session_count;
    status = client_runtime_reserve_pollfds(runtime, total_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (native_count > 0)
        memcpy(runtime->pollfds, native_fds, native_count * sizeof(*native_fds));
    status = client_runtime_refresh_session_pollfds(runtime);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_session_get_next_timeout(runtime->session, &session_timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;

    *timeout_ms = native_timeout_ms;
    if (*timeout_ms < 0 || (session_timeout_ms >= 0 && session_timeout_ms < *timeout_ms))
        *timeout_ms = session_timeout_ms;
    *pollfds = runtime->pollfds;
    *poll_count = runtime->poll_count;
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatch the current readiness snapshot and drain only immediately ready
 * session work. The bounded zero-time poll loop prevents one busy connection
 * from starving a frontend's native events.
 */
librdp_status client_runtime_dispatch_poll(client_runtime* runtime,
                                           unsigned int max_dispatch)
{
    unsigned int cycle = 0;

    if (!runtime || !runtime->session || max_dispatch == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!runtime->connected)
        return LIBRDP_STATUS_STATE;

    for (cycle = 0; cycle < max_dispatch; cycle++)
    {
        struct pollfd* session_fds = runtime->session_count > 0
                                         ? runtime->pollfds + runtime->native_count
                                         : NULL;
        int ready = 0;
        size_t index = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        for (index = 0; index < runtime->session_count; index++)
        {
            if (session_fds[index].revents != 0)
            {
                ready = 1;
                break;
            }
        }
        if (ready)
        {
            status = librdp_session_notify_poll(runtime->session,
                                                session_fds,
                                                runtime->session_count);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        status = librdp_session_dispatch_pending(runtime->session);
        if (status != LIBRDP_STATUS_OK)
            return status;

        if (cycle + 1u >= max_dispatch || runtime->session_count == 0)
            break;
        status = client_runtime_refresh_session_pollfds(runtime);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session_fds = runtime->session_count > 0
                          ? runtime->pollfds + runtime->native_count
                          : NULL;
        if (runtime->session_count == 0)
            break;
        do
        {
            ready = poll(session_fds, (nfds_t)runtime->session_count, 0);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0)
            return LIBRDP_STATUS_IO_ERROR;
        if (ready == 0)
            break;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status client_runtime_cancel(client_runtime* runtime)
{
    if (!runtime || !runtime->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_session_cancel(runtime->session);
}

librdp_status client_runtime_disconnect(client_runtime* runtime)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_session_disconnect(runtime->session);
    if (status == LIBRDP_STATUS_OK)
    {
        runtime->connected = 0;
        runtime->poll_count = 0;
        runtime->native_count = 0;
        runtime->session_count = 0;
    }
    return status;
}
