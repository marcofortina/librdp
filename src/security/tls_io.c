/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: thread-scoped SIGPIPE containment for OpenSSL transport calls.
 * Invariants: pre-existing pending signals and the original thread mask are
 * preserved across every call.
 * Ownership: no OpenSSL object or payload ownership is transferred.
 * Threading: state is stack-local; concurrent TLS sessions remain independent.
 * Trust boundary: peer disconnects are converted into ordinary OpenSSL
 * failures instead of process-wide signal delivery.
 */

#include "security/tls_io.h"

#include <openssl/ssl.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

typedef struct rdp_tls_sigpipe_guard
{
    sigset_t signals;
    sigset_t previous_mask;
    int pending_before;
    int active;
} rdp_tls_sigpipe_guard;

/*
 * Block SIGPIPE on the current thread and remember whether the caller already
 * had one pending. Failure is reported before OpenSSL can perform any I/O.
 */
static int rdp_tls_sigpipe_guard_begin(rdp_tls_sigpipe_guard* guard)
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
    rc = pthread_sigmask(SIG_BLOCK, &guard->signals, &guard->previous_mask);
    if (rc != 0)
    {
        errno = rc;
        return 0;
    }
    guard->active = 1;
    if (sigpending(&pending) != 0)
    {
        int saved_errno = errno;

        (void)pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
        guard->active = 0;
        errno = saved_errno;
        return 0;
    }
    guard->pending_before = sigismember(&pending, SIGPIPE) == 1;
    return 1;
}

/*
 * Consume only a newly generated SIGPIPE before restoring the caller's mask.
 * errno is retained because SSL_get_error() uses it for SSL_ERROR_SYSCALL.
 */
static void rdp_tls_sigpipe_guard_end(rdp_tls_sigpipe_guard* guard)
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
    (void)pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
    guard->active = 0;
    errno = saved_errno;
}

int rdp_tls_io_connect(SSL* tls)
{
    rdp_tls_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_tls_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_connect(tls);
    rdp_tls_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_accept(SSL* tls)
{
    rdp_tls_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_tls_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_accept(tls);
    rdp_tls_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_read(SSL* tls, void* data, int length)
{
    rdp_tls_sigpipe_guard guard;
    int result = -1;

    if (!tls || (!data && length > 0) || length < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_tls_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_read(tls, data, length);
    rdp_tls_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_write(SSL* tls, const void* data, int length)
{
    rdp_tls_sigpipe_guard guard;
    int result = -1;

    if (!tls || (!data && length > 0) || length < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_tls_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_write(tls, data, length);
    rdp_tls_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_shutdown(SSL* tls)
{
    rdp_tls_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_tls_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_shutdown(tls);
    rdp_tls_sigpipe_guard_end(&guard);
    return result;
}
