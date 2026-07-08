#include "transport/transport.h"

#include "common/trace.h"
#include "platform/socket.h"
#include "protocol/tpkt.h"
#include "transport/tcp.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void rdp_transport_init(rdp_transport* transport)
{
    if (!transport)
        return;
    transport->fd = -1;
    transport->owns_fd = 0;
    transport->tls_context = NULL;
    transport->tls = NULL;
    transport->tls_active = 0;
}

void rdp_transport_attach_fd(rdp_transport* transport, int fd, int owns_fd)
{
    if (!transport)
        return;
    rdp_transport_close(transport);
    transport->fd = fd;
    transport->owns_fd = owns_fd;
}

librdp_status rdp_transport_connect(rdp_transport* transport, const char* host, uint16_t port, int timeout_ms)
{
    int fd = -1;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_tcp_connect(host, port, timeout_ms, &fd);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_transport_attach_fd(transport, fd, 1);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_transport_tls_status(SSL* tls, int rc)
{
    int error = SSL_get_error(tls, rc);

    if (error == SSL_ERROR_ZERO_RETURN)
        return LIBRDP_STATUS_CLOSED;
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return LIBRDP_STATUS_AGAIN;
    return LIBRDP_STATUS_IO_ERROR;
}

librdp_status rdp_transport_start_tls(rdp_transport* transport, const char* host)
{
    SSL_CTX* context = NULL;
    SSL* tls = NULL;
    int rc = 0;

    if (!transport || transport->fd < 0 || !host || transport->tls_active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tls.connect.start", "host=%s", host);
    context = SSL_CTX_new(TLS_client_method());
    if (!context)
        return LIBRDP_STATUS_IO_ERROR;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    tls = SSL_new(context);
    if (!tls)
    {
        SSL_CTX_free(context);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (SSL_set_fd(tls, transport->fd) != 1)
    {
        SSL_free(tls);
        SSL_CTX_free(context);
        return LIBRDP_STATUS_IO_ERROR;
    }
    (void)SSL_set_tlsext_host_name(tls, host);

    rc = SSL_connect(tls);
    if (rc != 1)
    {
        librdp_status status = rdp_transport_tls_status(tls, rc);
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tls.connect.failed", "status=%d", (int)status);
        SSL_free(tls);
        SSL_CTX_free(context);
        ERR_clear_error();
        return status;
    }

    transport->tls_context = context;
    transport->tls = tls;
    transport->tls_active = 1;
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.tls.connect.done",
                    "version=%s cipher=%s",
                    SSL_get_version(tls),
                    SSL_get_cipher(tls));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_get_tls_public_key(rdp_transport* transport, rdp_buffer* public_key)
{
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char* out = NULL;
    int length = 0;
    int written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !transport->tls_active || !transport->tls || !public_key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    cert = SSL_get1_peer_certificate(transport->tls);
    if (!cert)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pkey = X509_get_pubkey(cert);
    if (!pkey)
    {
        X509_free(cert);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    length = i2d_PublicKey(pkey, NULL);
    if (length <= 0)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }
    status = rdp_buffer_reserve(public_key, (size_t)length);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    out = public_key->data;
    written = i2d_PublicKey(pkey, &out);
    if (written != length)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }
    public_key->length = (size_t)written;
    rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tls.public_key", "length=%u", (unsigned)public_key->length);

out:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return status;
}

librdp_status rdp_transport_wait(rdp_transport* transport, int timeout_ms, short events, short* revents)
{
    struct pollfd pfd;
    int rc = 0;

    if (!transport || transport->fd < 0 || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    pfd.fd = transport->fd;
    pfd.events = events;
    pfd.revents = 0;

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.wait.start",
                          "timeout_ms=%d events=%d",
                          timeout_ms,
                          (int)events);
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
    {
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tcp.timeout",
                              "timeout_ms=%d",
                              timeout_ms);
        return LIBRDP_STATUS_TIMEOUT;
    }
    if (rc < 0)
        return errno == EINTR ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_IO_ERROR;

    if (revents)
        *revents = pfd.revents;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.wait.done",
                          "revents=%d",
                          (int)pfd.revents);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_peek(rdp_transport* transport, void* data, size_t length, size_t* read_len)
{
    ssize_t rc = 0;

    if (!transport || transport->fd < 0 || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.peek.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_peek(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (read_len)
            *read_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.peek.done",
                              "read=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.peek.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = recv(transport->fd, data, length, MSG_PEEK);
    if (rc == 0)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.eof", "length=0");
        return LIBRDP_STATUS_CLOSED;
    }
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (read_len)
        *read_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.peek.done",
                          "read=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read(rdp_transport* transport, void* data, size_t length, size_t* read_len)
{
    ssize_t rc = 0;

    if (!transport || transport->fd < 0 || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.read.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_read(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (read_len)
            *read_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.read.done",
                              "read=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.read.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = recv(transport->fd, data, length, 0);
    if (rc == 0)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.tcp.eof", "length=0");
        return LIBRDP_STATUS_CLOSED;
    }
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (read_len)
        *read_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.read.done",
                          "read=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_write(rdp_transport* transport, const void* data, size_t length, size_t* written_len)
{
    ssize_t rc = 0;
    int flags = 0;

    if (!transport || transport->fd < 0 || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    if (transport->tls_active)
    {
        int tls_rc = 0;
        if (length > INT_MAX)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.write.start",
                              "length=%llu",
                              (unsigned long long)length);
        tls_rc = SSL_write(transport->tls, data, (int)length);
        if (tls_rc <= 0)
            return rdp_transport_tls_status(transport->tls, tls_rc);
        if (written_len)
            *written_len = (size_t)tls_rc;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.tls.write.done",
                              "written=%d",
                              tls_rc);
        return LIBRDP_STATUS_OK;
    }

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.write.start",
                          "length=%llu",
                          (unsigned long long)length);
    rc = send(transport->fd, data, length, flags);
    if (rc < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBRDP_STATUS_AGAIN;
        return LIBRDP_STATUS_IO_ERROR;
    }

    if (written_len)
        *written_len = (size_t)rc;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.tcp.write.done",
                          "written=%llu",
                          (unsigned long long)rc);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read_exact(rdp_transport* transport, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        size_t got = 0;
        librdp_status status = rdp_transport_read(transport, out + offset, length - offset, &got);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += got;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_write_all(rdp_transport* transport, const void* data, size_t length)
{
    const uint8_t* in = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        size_t wrote = 0;
        librdp_status status = rdp_transport_write(transport, in + offset, length - offset, &wrote);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += wrote;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_transport_read_tpkt(rdp_transport* transport, rdp_buffer* packet)
{
    uint8_t header[4];
    uint16_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_read_exact(transport, header, sizeof(header));
    if (status != LIBRDP_STATUS_OK)
        return status;

    total = (uint16_t)(((uint16_t)header[2] << 8) | header[3]);
    if (header[0] != 3 || header[1] != 0 || total < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_buffer_append(packet, header, sizeof(header));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    return rdp_transport_read_exact(transport, packet->data + 4, (size_t)total - 4u);
}

void rdp_transport_close(rdp_transport* transport)
{
    if (!transport)
        return;
    if (transport->tls)
    {
        SSL_set_quiet_shutdown(transport->tls, 1);
        (void)SSL_shutdown(transport->tls);
        SSL_free(transport->tls);
    }
    if (transport->tls_context)
        SSL_CTX_free(transport->tls_context);
    transport->tls = NULL;
    transport->tls_context = NULL;
    transport->tls_active = 0;
    if (transport->fd >= 0 && transport->owns_fd)
        rdp_socket_close(transport->fd);
    transport->fd = -1;
    transport->owns_fd = 0;
}
