/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: portable containment of socket- and pipe-generated SIGPIPE.
 * Invariants: only a signal generated while the guard is active is consumed;
 * caller-owned pending signals are left untouched.
 * Ownership: all state is retained in the caller-provided guard.
 * Threading: pthread signal masks isolate concurrent guarded operations.
 * Trust boundary: remote closure cannot terminate the hosting process.
 */

#include "platform/sigpipe.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>

int rdp_sigpipe_guard_begin(rdp_sigpipe_guard* guard)
{
    sigset_t pending;
    int rc = 0;

    if (!guard)
    {
        errno = EINVAL;
        return 0;
    }
    memset(guard, 0, sizeof(*guard));
    if (sigemptyset(&guard->signals) != 0 ||
        sigaddset(&guard->signals, SIGPIPE) != 0)
        return 0;
    rc = pthread_sigmask(SIG_BLOCK,
                         &guard->signals,
                         &guard->previous_mask);
    if (rc != 0)
    {
        errno = rc;
        return 0;
    }
    guard->active = 1;
    if (sigpending(&pending) != 0)
    {
        int saved_errno = errno;

        (void)pthread_sigmask(SIG_SETMASK,
                              &guard->previous_mask,
                              NULL);
        guard->active = 0;
        errno = saved_errno;
        return 0;
    }
    guard->pending_before =
        sigismember(&pending, SIGPIPE) == 1;
    return 1;
}

void rdp_sigpipe_guard_end(rdp_sigpipe_guard* guard)
{
    int saved_errno = errno;
    sigset_t pending;

    if (!guard || !guard->active)
        return;
    if (!guard->pending_before &&
        sigpending(&pending) == 0 &&
        sigismember(&pending, SIGPIPE) == 1)
    {
        int signal_number = 0;

        (void)sigwait(&guard->signals, &signal_number);
    }
    (void)pthread_sigmask(SIG_SETMASK,
                          &guard->previous_mask,
                          NULL);
    guard->active = 0;
    errno = saved_errno;
}
