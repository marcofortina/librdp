/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: transport abstraction combining TCP, TLS, buffering, wait, and
 * trace-visible I/O.
 * Invariants: socket/TLS handles and buffered bytes change ownership only on
 * successful setup or teardown calls.
 * Ownership: transport objects own sockets, TLS state, read buffers, and close
 * semantics.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_TRANSPORT_TRANSPORT_H
#define RDP_TRANSPORT_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>
#include <librdp/settings.h>

#include "common/buffer.h"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_st X509;

typedef struct rdp_transport_tls_config
{
    const char* host;
    int timeout_ms;
    int use_system_store;
    X509* trust_anchor;
    librdp_tls_policy_mode policy_mode;
    const char* pinned_sha256;
    librdp_tls_certificate_callback certificate_callback;
    void* certificate_callback_user_data;
} rdp_transport_tls_config;

typedef struct rdp_transport_backend_ops
{
    int (*poll_fd)(void* context);
    librdp_status (*wait)(void* context, int timeout_ms, short events, short* revents);
    librdp_status (*peek)(void* context, void* data, size_t length, size_t* read_len);
    librdp_status (*read)(void* context, void* data, size_t length, size_t* read_len);
    librdp_status (*write)(void* context, const void* data, size_t length, size_t* written_len);
    void (*close)(void* context);
} rdp_transport_backend_ops;

typedef struct rdp_transport
{
    int fd;
    int owns_fd;
    SSL_CTX* tls_context;
    SSL* tls;
    int tls_active;
    void* curl_easy;
    int curl_active;
    int curl_socket;
    void* backend_context;
    const rdp_transport_backend_ops* backend_ops;
} rdp_transport;

void rdp_transport_init(rdp_transport* transport);
void rdp_transport_attach_fd(rdp_transport* transport, int fd, int owns_fd);
void rdp_transport_attach_curl_easy(rdp_transport* transport, void* curl_easy, int fd);
void rdp_transport_attach_backend(rdp_transport* transport,
                                  void* context,
                                  const rdp_transport_backend_ops* ops);
librdp_status rdp_transport_connect(rdp_transport* transport, const char* host, uint16_t port, int timeout_ms);
librdp_status rdp_transport_start_tls(rdp_transport* transport, const char* host);
librdp_status rdp_transport_start_tls_with_config(rdp_transport* transport, const rdp_transport_tls_config* config);
librdp_status rdp_transport_get_tls_public_key(rdp_transport* transport, rdp_buffer* public_key);
librdp_status rdp_transport_wait(rdp_transport* transport, int timeout_ms, short events, short* revents);
librdp_status rdp_transport_peek(rdp_transport* transport, void* data, size_t length, size_t* read_len);
librdp_status rdp_transport_read(rdp_transport* transport, void* data, size_t length, size_t* read_len);
librdp_status rdp_transport_write(rdp_transport* transport, const void* data, size_t length, size_t* written_len);
librdp_status rdp_transport_read_exact(rdp_transport* transport, void* data, size_t length);
librdp_status rdp_transport_deadline_create(int timeout_ms, uint64_t* deadline_ns);
librdp_status rdp_transport_read_exact_until(rdp_transport* transport,
                                             void* data,
                                             size_t length,
                                             uint64_t deadline_ns);
librdp_status rdp_transport_read_exact_timeout(rdp_transport* transport,
                                               void* data,
                                               size_t length,
                                               int timeout_ms);
librdp_status rdp_transport_write_all(rdp_transport* transport, const void* data, size_t length);
librdp_status rdp_transport_read_tpkt(rdp_transport* transport, rdp_buffer* packet);
librdp_status rdp_transport_read_tpkt_timeout(rdp_transport* transport,
                                              rdp_buffer* packet,
                                              int timeout_ms);
void rdp_transport_close(rdp_transport* transport);

#endif
