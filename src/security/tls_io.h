/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: process-safe OpenSSL I/O adapter for POSIX transports.
 * Invariants: each operation restores the calling thread's signal mask and
 * preserves any SIGPIPE that was pending before the call.
 * Ownership: SSL objects and caller buffers remain borrowed.
 * Threading: wrappers affect only the calling thread and do not serialize SSL
 * object access.
 * Trust boundary: transport failures are returned through OpenSSL semantics
 * without allowing a disconnected peer to terminate the process.
 */

#ifndef RDP_SECURITY_TLS_IO_H
#define RDP_SECURITY_TLS_IO_H

typedef struct ssl_st SSL;

int rdp_tls_io_connect(SSL* tls);
int rdp_tls_io_accept(SSL* tls);
int rdp_tls_io_read(SSL* tls, void* data, int length);
int rdp_tls_io_write(SSL* tls, const void* data, int length);
int rdp_tls_io_shutdown(SSL* tls);

#endif
