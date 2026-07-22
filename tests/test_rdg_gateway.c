/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic Microsoft RD Gateway fixture.
 * Coverage: HTTPS OUT/IN streams, gateway control handshake, tunnel and
 * channel creation, and bidirectional downstream forwarding.
 * Bug classes: split-stream ordering, malformed framing, half-open tunnels,
 * and transport-layer data loss.
 * Determinism: all sockets stay on loopback and use generated certificates.
 */

#include "test_rdg_gateway.h"

#include "platform/socket.h"
#include "security/tls_io.h"

#include "common/buffer.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define TEST_RDG_HTTP_HEADER_MAX 8192u
#define TEST_RDG_CONNECTION_ID_MAX 96u
#define TEST_RDG_CHUNK_LINE_MAX 32u
#define TEST_RDG_PACKET_MAX 1048576u
#define TEST_RDG_RELAY_BUFFER 16384u

#define TEST_RDG_PKT_HANDSHAKE_REQUEST 0x0001u
#define TEST_RDG_PKT_HANDSHAKE_RESPONSE 0x0002u
#define TEST_RDG_PKT_TUNNEL_CREATE 0x0004u
#define TEST_RDG_PKT_TUNNEL_RESPONSE 0x0005u
#define TEST_RDG_PKT_TUNNEL_AUTH 0x0006u
#define TEST_RDG_PKT_TUNNEL_AUTH_RESPONSE 0x0007u
#define TEST_RDG_PKT_CHANNEL_CREATE 0x0008u
#define TEST_RDG_PKT_CHANNEL_RESPONSE 0x0009u
#define TEST_RDG_PKT_DATA 0x000au
#define TEST_RDG_PKT_CLOSE_CHANNEL 0x0010u
#define TEST_RDG_PKT_CLOSE_CHANNEL_RESPONSE 0x0011u

typedef enum test_rdg_process_result
{
    TEST_RDG_PROCESS_ERROR = 0,
    TEST_RDG_PROCESS_CONTINUE = 1,
    TEST_RDG_PROCESS_CLOSED = 2
} test_rdg_process_result;

static uint16_t test_rdg_read_u16_le(const uint8_t* data)
{
    return (uint16_t)((uint16_t)data[0] |
                      ((uint16_t)data[1] << 8u));
}

static uint32_t test_rdg_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8u) |
           ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}

static int test_rdg_socket_send_all(int fd,
                                    const uint8_t* data,
                                    size_t length)
{
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t sent = 0;

#ifdef MSG_NOSIGNAL
        sent = send(fd,
                    data + offset,
                    length - offset,
                    MSG_NOSIGNAL);
#else
        sent = send(fd, data + offset, length - offset, 0);
#endif
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return 0;
        offset += (size_t)sent;
    }
    return 1;
}

static int test_rdg_tls_read(SSL* tls,
                             void* data,
                             size_t length,
                             size_t* read_len)
{
    int result = 0;

    if (!tls || (!data && length > 0u) ||
        length > (size_t)INT_MAX)
        return 0;
    result = rdp_tls_io_read(tls, data, (int)length);
    if (result <= 0)
        return 0;
    if (read_len)
        *read_len = (size_t)result;
    return 1;
}

static int test_rdg_tls_read_exact(SSL* tls,
                                   void* data,
                                   size_t length)
{
    uint8_t* cursor = (uint8_t*)data;
    size_t offset = 0u;

    while (offset < length)
    {
        size_t received = 0u;

        if (!test_rdg_tls_read(tls,
                               cursor + offset,
                               length - offset,
                               &received))
            return 0;
        offset += received;
    }
    return 1;
}

static int test_rdg_tls_write_all(SSL* tls,
                                  const void* data,
                                  size_t length)
{
    const uint8_t* cursor = (const uint8_t*)data;
    size_t offset = 0u;

    if (!tls || (!data && length > 0u))
        return 0;
    while (offset < length)
    {
        size_t remaining = length - offset;
        int written = rdp_tls_io_write(
            tls,
            cursor + offset,
            remaining > (size_t)INT_MAX
                ? INT_MAX
                : (int)remaining);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int test_rdg_tls_read_headers(SSL* tls,
                                     char* headers,
                                     size_t headers_len)
{
    size_t used = 0u;

    if (!tls || !headers || headers_len < 5u)
        return 0;
    headers[0] = '\0';
    while (used + 1u < headers_len)
    {
        size_t received = 0u;

        if (!test_rdg_tls_read(tls,
                               headers + used,
                               1u,
                               &received) ||
            received != 1u)
            return 0;
        used++;
        headers[used] = '\0';
        if (used >= 4u &&
            memcmp(headers + used - 4u, "\r\n\r\n", 4u) == 0)
            return 1;
    }
    return 0;
}

static int test_rdg_copy_header(const char* headers,
                                const char* name,
                                char* output,
                                size_t output_len)
{
    const char* line = headers;
    size_t name_len = 0u;

    if (!headers || !name || !output || output_len == 0u)
        return 0;
    name_len = strlen(name);
    while (line && *line)
    {
        const char* end = strstr(line, "\r\n");

        if (!end)
            return 0;
        if ((size_t)(end - line) > name_len &&
            strncasecmp(line, name, name_len) == 0 &&
            line[name_len] == ':')
        {
            size_t length = 0u;

            line += name_len + 1u;
            while (*line == ' ' || *line == '\t')
                line++;
            length = (size_t)(end - line);
            if (length == 0u || length >= output_len)
                return 0;
            memcpy(output, line, length);
            output[length] = '\0';
            return 1;
        }
        line = end + 2u;
    }
    return 0;
}

static int test_rdg_send_http_response(SSL* tls)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache\r\n\r\n";

    return test_rdg_tls_write_all(tls,
                                  response,
                                  sizeof(response) - 1u);
}

/*
 * Parse one HTTP/1.1 chunk from the upload stream. The fixture accepts only
 * canonical hexadecimal sizes and rejects extensions or oversized bodies.
 */
static int test_rdg_read_http_chunk(SSL* tls,
                                    rdp_buffer* chunk)
{
    char line[TEST_RDG_CHUNK_LINE_MAX];
    size_t used = 0u;
    unsigned long length = 0ul;
    char* end = NULL;
    uint8_t suffix[2];

    if (!tls || !chunk)
        return -1;
    rdp_buffer_init(chunk);
    while (used + 1u < sizeof(line))
    {
        size_t received = 0u;

        if (!test_rdg_tls_read(tls,
                               line + used,
                               1u,
                               &received) ||
            received != 1u)
            return -1;
        used++;
        line[used] = '\0';
        if (used >= 2u &&
            line[used - 2u] == '\r' &&
            line[used - 1u] == '\n')
            break;
    }
    if (used < 2u ||
        line[used - 2u] != '\r' ||
        line[used - 1u] != '\n')
        return -1;
    line[used - 2u] = '\0';
    errno = 0;
    length = strtoul(line, &end, 16);
    if (errno != 0 || end == line || *end != '\0' ||
        length > TEST_RDG_PACKET_MAX)
        return -1;
    if (length == 0ul)
    {
        if (!test_rdg_tls_read_exact(tls, suffix, sizeof(suffix)) ||
            suffix[0] != '\r' || suffix[1] != '\n')
            return -1;
        return 0;
    }
    if (rdp_buffer_reserve(chunk, (size_t)length) !=
        LIBRDP_STATUS_OK)
        return -1;
    chunk->length = (size_t)length;
    if (!test_rdg_tls_read_exact(tls,
                                 chunk->data,
                                 chunk->length) ||
        !test_rdg_tls_read_exact(tls,
                                 suffix,
                                 sizeof(suffix)) ||
        suffix[0] != '\r' || suffix[1] != '\n')
    {
        rdp_buffer_free(chunk);
        return -1;
    }
    return 1;
}

static int test_rdg_send_http_chunk(SSL* tls,
                                    const uint8_t* data,
                                    size_t length)
{
    char header[32];
    int written = 0;

    if (!tls || (!data && length > 0u))
        return 0;
    written = snprintf(header, sizeof(header), "%zx\r\n", length);
    if (written <= 0 || (size_t)written >= sizeof(header) ||
        !test_rdg_tls_write_all(tls,
                                header,
                                (size_t)written) ||
        (length > 0u &&
         !test_rdg_tls_write_all(tls, data, length)) ||
        !test_rdg_tls_write_all(tls, "\r\n", 2u))
        return 0;
    return 1;
}

static int test_rdg_make_packet(uint16_t type,
                                const rdp_buffer* body,
                                rdp_buffer* packet)
{
    size_t body_len = body ? body->length : 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet || body_len > UINT32_MAX - 8u)
        return 0;
    rdp_buffer_init(packet);
    status = rdp_buffer_append_u16_le(packet, type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(packet, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            packet,
            (uint32_t)(body_len + 8u));
    if (status == LIBRDP_STATUS_OK && body_len > 0u)
        status = rdp_buffer_append(packet,
                                   body->data,
                                   body_len);
    if (status != LIBRDP_STATUS_OK)
        rdp_buffer_free(packet);
    return status == LIBRDP_STATUS_OK;
}

static int test_rdg_send_packet(SSL* out_tls,
                                uint16_t type,
                                const rdp_buffer* body)
{
    rdp_buffer packet;
    int result = 0;

    if (!test_rdg_make_packet(type, body, &packet))
        return 0;
    result = test_rdg_send_http_chunk(out_tls,
                                      packet.data,
                                      packet.length);
    rdp_buffer_free(&packet);
    return result;
}

static int test_rdg_send_handshake_response(SSL* out_tls)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 0;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&body, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_HANDSHAKE_RESPONSE,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_send_tunnel_response(SSL* out_tls)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 0;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0x0003u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, 0x1001u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_TUNNEL_RESPONSE,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_send_auth_response(SSL* out_tls)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 0;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_TUNNEL_AUTH_RESPONSE,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_send_channel_response(SSL* out_tls)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 0;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0x0001u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, 0x2001u);
    if (status == LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_CHANNEL_RESPONSE,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_send_close_response(SSL* out_tls)
{
    rdp_buffer body;
    int result = 0;

    rdp_buffer_init(&body);
    if (rdp_buffer_append_u32_le(&body, 0u) ==
        LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_CLOSE_CHANNEL_RESPONSE,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_send_data(SSL* out_tls,
                              const uint8_t* data,
                              size_t length)
{
    rdp_buffer body;
    int result = 0;

    if ((!data && length > 0u) || length > UINT16_MAX)
        return 0;
    rdp_buffer_init(&body);
    if (rdp_buffer_append_u16_le(&body,
                                 (uint16_t)length) ==
            LIBRDP_STATUS_OK &&
        rdp_buffer_append(&body, data, length) ==
            LIBRDP_STATUS_OK)
        result = test_rdg_send_packet(
            out_tls,
            TEST_RDG_PKT_DATA,
            &body);
    rdp_buffer_free(&body);
    return result;
}

static int test_rdg_connect_target(
    const test_rdg_gateway_config* config)
{
    struct sockaddr_in address;
    int fd = -1;

    if (!config || !config->target_host ||
        strcmp(config->target_host, "127.0.0.1") != 0 ||
        config->target_port == 0u)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (rdp_socket_set_nosigpipe(fd) != 0)
    {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(config->target_port);
    if (connect(fd,
                (const struct sockaddr*)&address,
                (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_rdg_set_fd(test_rdg_gateway* gateway,
                            int* slot,
                            int fd)
{
    if (pthread_mutex_lock(&gateway->lock) != 0)
        return;
    *slot = fd;
    (void)pthread_mutex_unlock(&gateway->lock);
}

static int test_rdg_take_fd(test_rdg_gateway* gateway,
                            int* slot)
{
    int fd = -1;

    if (pthread_mutex_lock(&gateway->lock) != 0)
        return -1;
    fd = *slot;
    *slot = -1;
    (void)pthread_mutex_unlock(&gateway->lock);
    return fd;
}

/*
 * Validate each control packet before advancing the gateway state. Once the
 * channel exists, DATA payloads are the only bytes forwarded downstream.
 */
static test_rdg_process_result test_rdg_process_packet(
    test_rdg_gateway* gateway,
    SSL* out_tls,
    const uint8_t* packet,
    size_t packet_len)
{
    uint16_t type = 0u;
    uint32_t wire_len = 0u;
    const uint8_t* payload = NULL;
    size_t payload_len = 0u;

    if (!gateway || !out_tls || !packet ||
        packet_len < 8u)
        return TEST_RDG_PROCESS_ERROR;
    type = test_rdg_read_u16_le(packet);
    wire_len = test_rdg_read_u32_le(packet + 4u);
    if (wire_len < 8u || (size_t)wire_len != packet_len)
        return TEST_RDG_PROCESS_ERROR;
    payload = packet + 8u;
    payload_len = packet_len - 8u;
    if (type == TEST_RDG_PKT_HANDSHAKE_REQUEST)
    {
        if (atomic_load_explicit(&gateway->handshake,
                                 memory_order_acquire) != 0u ||
            payload_len < 6u ||
            !test_rdg_send_handshake_response(out_tls))
            return TEST_RDG_PROCESS_ERROR;
        atomic_store_explicit(&gateway->handshake,
                              1u,
                              memory_order_release);
        return TEST_RDG_PROCESS_CONTINUE;
    }
    if (type == TEST_RDG_PKT_TUNNEL_CREATE)
    {
        if (atomic_load_explicit(&gateway->handshake,
                                 memory_order_acquire) == 0u ||
            atomic_load_explicit(&gateway->tunnel,
                                 memory_order_acquire) != 0u ||
            !test_rdg_send_tunnel_response(out_tls))
            return TEST_RDG_PROCESS_ERROR;
        atomic_store_explicit(&gateway->tunnel,
                              1u,
                              memory_order_release);
        return TEST_RDG_PROCESS_CONTINUE;
    }
    if (type == TEST_RDG_PKT_TUNNEL_AUTH)
    {
        if (atomic_load_explicit(&gateway->tunnel,
                                 memory_order_acquire) == 0u ||
            atomic_load_explicit(&gateway->authorized,
                                 memory_order_acquire) != 0u ||
            !test_rdg_send_auth_response(out_tls))
            return TEST_RDG_PROCESS_ERROR;
        atomic_store_explicit(&gateway->authorized,
                              1u,
                              memory_order_release);
        return TEST_RDG_PROCESS_CONTINUE;
    }
    if (type == TEST_RDG_PKT_CHANNEL_CREATE)
    {
        int target_fd = -1;

        if (atomic_load_explicit(&gateway->authorized,
                                 memory_order_acquire) == 0u ||
            atomic_load_explicit(&gateway->channel,
                                 memory_order_acquire) != 0u)
            return TEST_RDG_PROCESS_ERROR;
        target_fd = test_rdg_connect_target(&gateway->config);
        if (target_fd < 0)
            return TEST_RDG_PROCESS_ERROR;
        test_rdg_set_fd(gateway,
                        &gateway->target_fd,
                        target_fd);
        if (!test_rdg_send_channel_response(out_tls))
            return TEST_RDG_PROCESS_ERROR;
        atomic_store_explicit(&gateway->channel,
                              1u,
                              memory_order_release);
        return TEST_RDG_PROCESS_CONTINUE;
    }
    if (type == TEST_RDG_PKT_DATA)
    {
        uint16_t data_len = 0u;

        if (atomic_load_explicit(&gateway->channel,
                                 memory_order_acquire) == 0u ||
            payload_len < 2u)
            return TEST_RDG_PROCESS_ERROR;
        data_len = test_rdg_read_u16_le(payload);
        if ((size_t)data_len != payload_len - 2u ||
            !test_rdg_socket_send_all(gateway->target_fd,
                                      payload + 2u,
                                      data_len))
            return TEST_RDG_PROCESS_ERROR;
        atomic_fetch_add_explicit(&gateway->downstream_received,
                                  data_len,
                                  memory_order_acq_rel);
        return TEST_RDG_PROCESS_CONTINUE;
    }
    if (type == TEST_RDG_PKT_CLOSE_CHANNEL)
    {
        if (!test_rdg_send_close_response(out_tls))
            return TEST_RDG_PROCESS_ERROR;
        atomic_store_explicit(&gateway->closed,
                              1u,
                              memory_order_release);
        return TEST_RDG_PROCESS_CLOSED;
    }
    return TEST_RDG_PROCESS_ERROR;
}

static test_rdg_process_result test_rdg_process_buffer(
    test_rdg_gateway* gateway,
    SSL* out_tls,
    rdp_buffer* incoming)
{
    while (incoming->length >= 8u)
    {
        uint32_t packet_len =
            test_rdg_read_u32_le(incoming->data + 4u);
        test_rdg_process_result result =
            TEST_RDG_PROCESS_CONTINUE;

        if (packet_len < 8u ||
            packet_len > TEST_RDG_PACKET_MAX)
            return TEST_RDG_PROCESS_ERROR;
        if ((size_t)packet_len > incoming->length)
            return TEST_RDG_PROCESS_CONTINUE;
        result = test_rdg_process_packet(
            gateway,
            out_tls,
            incoming->data,
            packet_len);
        if (result != TEST_RDG_PROCESS_CONTINUE)
            return result;
        if (rdp_buffer_consume(incoming,
                               packet_len) != LIBRDP_STATUS_OK)
            return TEST_RDG_PROCESS_ERROR;
    }
    return TEST_RDG_PROCESS_CONTINUE;
}

static int test_rdg_receive_upload(test_rdg_gateway* gateway,
                                   SSL* in_tls,
                                   SSL* out_tls,
                                   rdp_buffer* incoming,
                                   int* closed)
{
    rdp_buffer chunk;
    int chunk_result = test_rdg_read_http_chunk(in_tls, &chunk);
    test_rdg_process_result process_result =
        TEST_RDG_PROCESS_CONTINUE;

    if (chunk_result <= 0)
        return 0;
    if (rdp_buffer_append(incoming,
                          chunk.data,
                          chunk.length) != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&chunk);
        return 0;
    }
    rdp_buffer_free(&chunk);
    process_result = test_rdg_process_buffer(
        gateway,
        out_tls,
        incoming);
    if (process_result == TEST_RDG_PROCESS_ERROR)
        return 0;
    if (process_result == TEST_RDG_PROCESS_CLOSED)
        *closed = 1;
    return 1;
}

/*
 * Relay upload chunks and target bytes independently after channel creation.
 * SSL_pending covers bytes already buffered above the socket poll boundary.
 */
static int test_rdg_relay(test_rdg_gateway* gateway,
                          SSL* in_tls,
                          SSL* out_tls,
                          rdp_buffer* incoming)
{
    int closed = 0;

    while (!closed &&
           atomic_load_explicit(&gateway->stop,
                                memory_order_acquire) == 0u)
    {
        struct pollfd fds[2];
        int ready = 0;

        memset(fds, 0, sizeof(fds));
        fds[0].fd = gateway->in_fd;
        fds[0].events = POLLIN;
        fds[1].fd = gateway->target_fd;
        fds[1].events = POLLIN;
        if (SSL_pending(in_tls) > 0)
            ready = 1;
        else
        {
            do
            {
                ready = poll(fds, 2u, 100);
            } while (ready < 0 && errno == EINTR);
            if (ready < 0)
                return 0;
        }
        if (SSL_pending(in_tls) > 0 ||
            (ready > 0 &&
             (fds[0].revents &
              (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0))
        {
            if (!test_rdg_receive_upload(gateway,
                                         in_tls,
                                         out_tls,
                                         incoming,
                                         &closed))
                return atomic_load_explicit(
                           &gateway->stop,
                           memory_order_acquire) != 0u;
        }
        if (!closed && ready > 0 &&
            (fds[1].revents &
             (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0)
        {
            uint8_t data[TEST_RDG_RELAY_BUFFER];
            ssize_t received = recv(gateway->target_fd,
                                    data,
                                    sizeof(data),
                                    0);

            if (received <= 0)
                return received == 0;
            if (!test_rdg_send_data(out_tls,
                                    data,
                                    (size_t)received))
                return 0;
            atomic_fetch_add_explicit(
                &gateway->downstream_sent,
                (unsigned int)received,
                memory_order_acq_rel);
        }
    }
    return 1;
}

static int test_rdg_accept(test_rdg_gateway* gateway)
{
    for (;;)
    {
        struct pollfd descriptor;
        int ready = 0;
        int fd = -1;

        if (!gateway ||
            atomic_load_explicit(&gateway->stop,
                                 memory_order_acquire) != 0u)
            return -1;
        descriptor.fd = gateway->listener_fd;
        descriptor.events = POLLIN;
        descriptor.revents = 0;
        ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
        {
            if (ready == 0)
                continue;
            return -1;
        }
        if ((descriptor.revents & POLLIN) == 0)
            return -1;
        fd = accept(gateway->listener_fd, NULL, NULL);

        if (fd < 0 && errno == EINTR)
            continue;
        if (fd >= 0 && rdp_socket_set_nosigpipe(fd) != 0)
        {
            close(fd);
            return -1;
        }
        return fd;
    }
}

static SSL* test_rdg_accept_tls(SSL_CTX* context,
                                int fd)
{
    SSL* tls = NULL;

    if (!context || fd < 0)
        return NULL;
    tls = SSL_new(context);
    if (!tls)
        return NULL;
    if (SSL_set_fd(tls, fd) != 1 ||
        rdp_tls_io_accept(tls) != 1)
    {
        SSL_free(tls);
        return NULL;
    }
    return tls;
}

static SSL_CTX* test_rdg_tls_context_new(
    const test_rdg_gateway_config* config)
{
    SSL_CTX* context = NULL;

    if (!config || !config->certificate_path ||
        !config->private_key_path)
        return NULL;
    context = SSL_CTX_new(TLS_server_method());
    if (!context)
        return NULL;
    if (SSL_CTX_set_min_proto_version(context,
                                      TLS1_2_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(
            context,
            config->certificate_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(
            context,
            config->private_key_path,
            SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1)
    {
        SSL_CTX_free(context);
        return NULL;
    }
    return context;
}

static int test_rdg_accept_stream(test_rdg_gateway* gateway,
                                  SSL_CTX* context,
                                  const char* method,
                                  const char* expected_connection_id,
                                  int* fd_out,
                                  SSL** tls_out,
                                  char connection_id[
                                      TEST_RDG_CONNECTION_ID_MAX])
{
    char headers[TEST_RDG_HTTP_HEADER_MAX];
    char request_prefix[64];
    int fd = -1;
    SSL* tls = NULL;
    int written = 0;

    if (!gateway || !context || !method || !fd_out ||
        !tls_out || !connection_id)
        return 0;
    fd = test_rdg_accept(gateway);
    if (fd < 0)
        return 0;
    test_rdg_set_fd(gateway, fd_out, fd);
    tls = test_rdg_accept_tls(context, fd);
    if (!tls ||
        !test_rdg_tls_read_headers(tls,
                                   headers,
                                   sizeof(headers)))
        return 0;
    written = snprintf(request_prefix,
                       sizeof(request_prefix),
                       "%s ",
                       method);
    if (written <= 0 ||
        (size_t)written >= sizeof(request_prefix) ||
        strncmp(headers,
                request_prefix,
                (size_t)written) != 0 ||
        !test_rdg_copy_header(headers,
                              "RDG-Connection-Id",
                              connection_id,
                              TEST_RDG_CONNECTION_ID_MAX) ||
        (expected_connection_id &&
         strcmp(connection_id,
                expected_connection_id) != 0) ||
        !test_rdg_send_http_response(tls))
    {
        SSL_free(tls);
        return 0;
    }
    *tls_out = tls;
    return 1;
}

static void test_rdg_close_tls(SSL** tls)
{
    if (!tls || !*tls)
        return;
    SSL_set_quiet_shutdown(*tls, 1);
    SSL_free(*tls);
    *tls = NULL;
}

static void* test_rdg_gateway_main(void* user_data)
{
    test_rdg_gateway* gateway =
        (test_rdg_gateway*)user_data;
    sigset_t blocked_signals;
    SSL_CTX* context = NULL;
    SSL* out_tls = NULL;
    SSL* in_tls = NULL;
    rdp_buffer incoming;
    char out_connection_id[TEST_RDG_CONNECTION_ID_MAX];
    char in_connection_id[TEST_RDG_CONNECTION_ID_MAX];
    int target_fd = -1;
    int in_fd = -1;
    int out_fd = -1;
    int closed = 0;
    int success = 0;

    if (!gateway)
        return NULL;
    rdp_buffer_init(&incoming);
    gateway->status = LIBRDP_STATUS_IO_ERROR;
    if (sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGPIPE) != 0 ||
        pthread_sigmask(SIG_BLOCK,
                        &blocked_signals,
                        NULL) != 0)
        goto cleanup;
    context = test_rdg_tls_context_new(&gateway->config);
    if (!context ||
        !test_rdg_accept_stream(gateway,
                                context,
                                "RDG_OUT_DATA",
                                NULL,
                                &gateway->out_fd,
                                &out_tls,
                                out_connection_id))
        goto cleanup;
    atomic_store_explicit(&gateway->out_stream,
                          1u,
                          memory_order_release);
    if (!test_rdg_accept_stream(gateway,
                                context,
                                "RDG_IN_DATA",
                                out_connection_id,
                                &gateway->in_fd,
                                &in_tls,
                                in_connection_id))
        goto cleanup;
    atomic_store_explicit(&gateway->in_stream,
                          1u,
                          memory_order_release);
    while (atomic_load_explicit(&gateway->channel,
                                memory_order_acquire) == 0u)
    {
        if (!test_rdg_receive_upload(gateway,
                                     in_tls,
                                     out_tls,
                                     &incoming,
                                     &closed) ||
            closed)
            goto cleanup;
    }
    success = test_rdg_relay(gateway,
                             in_tls,
                             out_tls,
                             &incoming);

cleanup:
    if (out_tls &&
        atomic_load_explicit(&gateway->channel,
                             memory_order_acquire) != 0u)
        (void)test_rdg_send_http_chunk(out_tls, NULL, 0u);
    test_rdg_close_tls(&in_tls);
    test_rdg_close_tls(&out_tls);
    SSL_CTX_free(context);
    rdp_buffer_free(&incoming);
    target_fd = test_rdg_take_fd(gateway,
                                 &gateway->target_fd);
    in_fd = test_rdg_take_fd(gateway, &gateway->in_fd);
    out_fd = test_rdg_take_fd(gateway, &gateway->out_fd);
    if (target_fd >= 0)
        close(target_fd);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    gateway->status =
        success &&
        atomic_load_explicit(&gateway->dropped,
                             memory_order_acquire) == 0u &&
        atomic_load_explicit(&gateway->out_stream,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->in_stream,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->handshake,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->tunnel,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->authorized,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->channel,
                             memory_order_acquire) != 0u &&
        atomic_load_explicit(&gateway->downstream_sent,
                             memory_order_acquire) > 0u &&
        atomic_load_explicit(&gateway->downstream_received,
                             memory_order_acquire) > 0u
            ? LIBRDP_STATUS_OK
            : LIBRDP_STATUS_IO_ERROR;
    ERR_clear_error();
    return NULL;
}

int test_rdg_gateway_start(test_rdg_gateway* gateway,
                           const test_rdg_gateway_config* config)
{
    struct sockaddr_in address;
    socklen_t address_len = (socklen_t)sizeof(address);
    int one = 1;

    if (!gateway || !config || !config->target_host ||
        !config->certificate_path || !config->private_key_path)
        return 0;
    memset(gateway, 0, sizeof(*gateway));
    gateway->config = *config;
    gateway->listener_fd = -1;
    gateway->out_fd = -1;
    gateway->in_fd = -1;
    gateway->target_fd = -1;
    gateway->status = LIBRDP_STATUS_AGAIN;
    atomic_init(&gateway->stop, 0u);
    atomic_init(&gateway->out_stream, 0u);
    atomic_init(&gateway->in_stream, 0u);
    atomic_init(&gateway->handshake, 0u);
    atomic_init(&gateway->tunnel, 0u);
    atomic_init(&gateway->authorized, 0u);
    atomic_init(&gateway->channel, 0u);
    atomic_init(&gateway->closed, 0u);
    atomic_init(&gateway->dropped, 0u);
    atomic_init(&gateway->downstream_sent, 0u);
    atomic_init(&gateway->downstream_received, 0u);
    if (pthread_mutex_init(&gateway->lock, NULL) != 0)
        return 0;
    gateway->listener_fd = socket(AF_INET,
                                  SOCK_STREAM,
                                  0);
    if (gateway->listener_fd < 0)
        goto fail;
    (void)setsockopt(gateway->listener_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &one,
                     (socklen_t)sizeof(one));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(gateway->listener_fd,
             (const struct sockaddr*)&address,
             (socklen_t)sizeof(address)) != 0 ||
        getsockname(gateway->listener_fd,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(gateway->listener_fd, 4) != 0)
        goto fail;
    gateway->port = ntohs(address.sin_port);
    if (pthread_create(&gateway->thread,
                       NULL,
                       test_rdg_gateway_main,
                       gateway) != 0)
        goto fail;
    gateway->thread_started = 1;
    return 1;

fail:
    test_rdg_gateway_clear(gateway);
    return 0;
}

void test_rdg_gateway_cancel(test_rdg_gateway* gateway)
{
    if (!gateway)
        return;
    atomic_store_explicit(&gateway->stop,
                          1u,
                          memory_order_release);
    if (pthread_mutex_lock(&gateway->lock) != 0)
        return;
    if (gateway->listener_fd >= 0)
        (void)shutdown(gateway->listener_fd, SHUT_RDWR);
    if (gateway->out_fd >= 0)
        (void)shutdown(gateway->out_fd, SHUT_RDWR);
    if (gateway->in_fd >= 0)
        (void)shutdown(gateway->in_fd, SHUT_RDWR);
    if (gateway->target_fd >= 0)
        (void)shutdown(gateway->target_fd, SHUT_RDWR);
    (void)pthread_mutex_unlock(&gateway->lock);
}

int test_rdg_gateway_join(test_rdg_gateway* gateway)
{
    return test_rdg_gateway_join_status(gateway,
                                        LIBRDP_STATUS_OK);
}

int test_rdg_gateway_join_status(test_rdg_gateway* gateway,
                                 librdp_status expected_status)
{
    if (!gateway || !gateway->thread_started)
        return 0;
    if (pthread_join(gateway->thread, NULL) != 0)
        return 0;
    gateway->thread_started = 0;
    return gateway->status == expected_status;
}

int test_rdg_gateway_drop_stream(test_rdg_gateway* gateway,
                                 test_rdg_stream stream)
{
    int fd = -1;
    int result = 0;

    if (!gateway ||
        (stream != TEST_RDG_STREAM_OUT &&
         stream != TEST_RDG_STREAM_IN) ||
        pthread_mutex_lock(&gateway->lock) != 0)
        return 0;
    fd = stream == TEST_RDG_STREAM_OUT
             ? gateway->out_fd
             : gateway->in_fd;
    if (fd >= 0 && shutdown(fd, SHUT_RDWR) == 0)
    {
        atomic_store_explicit(&gateway->dropped,
                              (unsigned int)stream,
                              memory_order_release);
        result = 1;
    }
    (void)pthread_mutex_unlock(&gateway->lock);
    return result;
}

void test_rdg_gateway_clear(test_rdg_gateway* gateway)
{
    int listener_fd = -1;

    if (!gateway)
        return;
    test_rdg_gateway_cancel(gateway);
    if (gateway->thread_started)
        (void)pthread_join(gateway->thread, NULL);
    gateway->thread_started = 0;
    listener_fd = test_rdg_take_fd(gateway,
                                   &gateway->listener_fd);
    if (listener_fd >= 0)
        close(listener_fd);
    (void)pthread_mutex_destroy(&gateway->lock);
}
