/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: custom poll loop example.
 * Invariants: pollfds and timeout are obtained from the session immediately
 * before dispatch and are not retained across iterations.
 * Ownership: session owns descriptors; the caller owns only the stack copy.
 * Threading: single-threaded event loop.
 * Trust boundary: readiness notifications are treated as hints before dispatch.
 */

#include <poll.h>
#include <stdio.h>
#include <string.h>

#include <librdp/librdp.h>

static int drive_session(librdp_session* session)
{
    struct pollfd fds[8];
    librdp_status status;
    size_t count = 0;
    int timeout_ms = 0;

    status = librdp_session_get_pollfds(session, fds, 8u, &count);
    if (status != LIBRDP_STATUS_OK)
        return status == LIBRDP_STATUS_STATE ? 0 : 1;

    status = librdp_session_get_next_timeout(session, &timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return 1;

    if (count > sizeof(fds) / sizeof(fds[0]) || count > (size_t)((nfds_t)-1))
        return 1;

    if (poll(fds, (nfds_t)count, timeout_ms) < 0)
        return 1;

    status = librdp_session_notify_poll(session, fds, count);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_session_dispatch_pending(session);

    return status == LIBRDP_STATUS_OK ? 0 : 1;
}

int main(int argc, char** argv)
{
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    int rc = 0;

    if (!settings)
        return 1;

    if (argc > 1 && librdp_settings_set_target(settings, argv[1]) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return 1;
    }

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    if (argc > 1)
    {
        librdp_status status = librdp_session_connect(session);
        if (status == LIBRDP_STATUS_OK)
            rc = drive_session(session);
        else
            rc = 1;
        librdp_session_disconnect(session);
    }
    else
    {
        rc = drive_session(session);
        printf("custom poll loop is ready for connected sessions\n");
    }

    librdp_session_free(session);
    return rc;
}
