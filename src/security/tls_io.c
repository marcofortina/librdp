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

#include "platform/sigpipe.h"

#include <openssl/ssl.h>

#include <errno.h>
#include <string.h>

int rdp_tls_io_connect(SSL* tls)
{
    rdp_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_connect(tls);
    rdp_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_accept(SSL* tls)
{
    rdp_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_accept(tls);
    rdp_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_read(SSL* tls, void* data, int length)
{
    rdp_sigpipe_guard guard;
    int result = -1;

    if (!tls || (!data && length > 0) || length < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_read(tls, data, length);
    rdp_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_write(SSL* tls, const void* data, int length)
{
    rdp_sigpipe_guard guard;
    int result = -1;

    if (!tls || (!data && length > 0) || length < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_write(tls, data, length);
    rdp_sigpipe_guard_end(&guard);
    return result;
}

int rdp_tls_io_shutdown(SSL* tls)
{
    rdp_sigpipe_guard guard;
    int result = -1;

    if (!tls)
    {
        errno = EINVAL;
        return -1;
    }
    if (!rdp_sigpipe_guard_begin(&guard))
        return -1;
    result = SSL_shutdown(tls);
    rdp_sigpipe_guard_end(&guard);
    return result;
}
