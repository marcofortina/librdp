#ifndef RDP_TRANSPORT_TRANSPORT_H
#define RDP_TRANSPORT_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

typedef struct rdp_transport
{
    int fd;
    int owns_fd;
    SSL_CTX* tls_context;
    SSL* tls;
    int tls_active;
} rdp_transport;

void rdp_transport_init(rdp_transport* transport);
void rdp_transport_attach_fd(rdp_transport* transport, int fd, int owns_fd);
librdp_status rdp_transport_connect(rdp_transport* transport, const char* host, uint16_t port, int timeout_ms);
librdp_status rdp_transport_start_tls(rdp_transport* transport, const char* host);
librdp_status rdp_transport_get_tls_public_key(rdp_transport* transport, rdp_buffer* public_key);
librdp_status rdp_transport_wait(rdp_transport* transport, int timeout_ms, short events, short* revents);
librdp_status rdp_transport_peek(rdp_transport* transport, void* data, size_t length, size_t* read_len);
librdp_status rdp_transport_read(rdp_transport* transport, void* data, size_t length, size_t* read_len);
librdp_status rdp_transport_write(rdp_transport* transport, const void* data, size_t length, size_t* written_len);
librdp_status rdp_transport_read_exact(rdp_transport* transport, void* data, size_t length);
librdp_status rdp_transport_write_all(rdp_transport* transport, const void* data, size_t length);
librdp_status rdp_transport_read_tpkt(rdp_transport* transport, rdp_buffer* packet);
void rdp_transport_close(rdp_transport* transport);

#endif
