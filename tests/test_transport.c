/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: transport, TLS, UDP, UDP2, and multitransport unit tests.
 * Coverage: fixtures use local sockets and generated certificates to avoid
 * external network dependencies.
 * Bug classes: framing bounds, TLS I/O lifetime, timeout handling, UDP
 * sequence validation, and packet classification.
 * Determinism: tests are self-contained and avoid external services unless
 * using local loopback fixtures.
 */


#include "common/buffer.h"
#include "common/trace.h"
#include "gateway/gateway.h"
#include "gateway/rdg_http.h"
#include "platform/socket.h"
#include "protocol/tpkt.h"
#include "transport/tcp.h"
#include "transport/multitransport.h"
#include "transport/transport.h"
#include "transport/udp_transport.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

/*
 * Validate the standalone RDG framing boundary used by both the HTTP worker
 * and the fuzz harness. The trailing-byte case protects stream reassembly,
 * while malformed nested lengths exercise the data packet trust boundary.
 */
static int test_rdg_packet_parser(void)
{
    const uint8_t incomplete[7] = {0};
    const uint8_t short_header[8] = {0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00};
    const uint8_t oversized[8] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00};
    const uint8_t control[] = {
        0x02, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
    };
    const uint8_t data_packet[] = {
        0x0a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x11, 0x22, 0x33
    };
    const uint8_t invalid_data[] = {
        0x0a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x11, 0x22
    };
    rdp_rdg_packet_view packet;

    TCHECK(rdp_rdg_parse_packet(NULL, 1u, &packet) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_rdg_parse_packet(incomplete, sizeof(incomplete), NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_rdg_parse_packet(NULL, 0u, &packet) == LIBRDP_STATUS_AGAIN);
    TCHECK(rdp_rdg_parse_packet(incomplete, sizeof(incomplete), &packet) == LIBRDP_STATUS_AGAIN);
    TCHECK(rdp_rdg_parse_packet(short_header, sizeof(short_header), &packet) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    TCHECK(rdp_rdg_parse_packet(oversized, sizeof(oversized), &packet) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    TCHECK(rdp_rdg_parse_packet(control, sizeof(control), &packet) == LIBRDP_STATUS_OK);
    TCHECK(packet.type == 0x0002u);
    TCHECK(packet.packet_len == 11u);
    TCHECK(packet.payload == control + 8u);
    TCHECK(packet.payload_len == 3u);
    TCHECK(packet.data == NULL);
    TCHECK(packet.data_len == 0u);

    TCHECK(rdp_rdg_parse_packet(data_packet, sizeof(data_packet), &packet) == LIBRDP_STATUS_OK);
    TCHECK(packet.type == 0x000au);
    TCHECK(packet.packet_len == sizeof(data_packet));
    TCHECK(packet.payload_len == 5u);
    TCHECK(packet.data == data_packet + 10u);
    TCHECK(packet.data_len == 3u);
    TCHECK(memcmp(packet.data, "\x11\x22\x33", packet.data_len) == 0);

    TCHECK(rdp_rdg_parse_packet(invalid_data, sizeof(invalid_data), &packet) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    return 0;
}

/*
 * Model both stalled HTTP legs with deliberately small queue limits. The
 * outbound case represents a gateway that stops reading, while the inbound
 * case represents a peer producing data faster than the transport consumer.
 * Partial drains must restore capacity without corrupting byte/node accounting,
 * and clear must release every queued allocation during teardown.
 */
static int test_rdg_bounded_queues(void)
{
    const uint8_t first[] = {0x10u, 0x11u, 0x12u, 0x13u};
    const uint8_t second[] = {0x20u, 0x21u, 0x22u, 0x23u};
    const uint8_t inbound_data[] = {0x30u, 0x31u, 0x32u};
    uint8_t bytes[8];
    uint16_t type = 0;
    rdp_buffer payload;
    rdp_rdg_bounded_queue outbound;
    rdp_rdg_bounded_queue inbound;
    rdp_rdg_bounded_queue control;
    rdp_rdg_bounded_queue invalid;

    rdp_buffer_init(&payload);
    rdp_rdg_bounded_queue_init(&outbound, 8u, 2u);
    TCHECK(rdp_rdg_bounded_queue_push(&outbound, 1u, first, sizeof(first)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_rdg_bounded_queue_push(&outbound, 2u, second, sizeof(second)) == LIBRDP_STATUS_OK);
    TCHECK(outbound.bytes == 8u && outbound.nodes == 2u);
    TCHECK(!rdp_rdg_bounded_queue_can_push(&outbound, 1u));
    TCHECK(rdp_rdg_bounded_queue_push(&outbound, 3u, first, 1u) == LIBRDP_STATUS_AGAIN);
    TCHECK(rdp_rdg_bounded_queue_push(&outbound, 3u, first, 9u) ==
           LIBRDP_STATUS_LIMIT_EXCEEDED);
    TCHECK(rdp_rdg_bounded_queue_peek(&outbound, bytes, sizeof(bytes)) == sizeof(bytes));
    TCHECK(memcmp(bytes, "\x10\x11\x12\x13\x20\x21\x22\x23", sizeof(bytes)) == 0);
    TCHECK(rdp_rdg_bounded_queue_read(&outbound, bytes, 3u) == 3u);
    TCHECK(outbound.bytes == 5u && outbound.nodes == 2u);
    TCHECK(!rdp_rdg_bounded_queue_can_push(&outbound, 1u));
    TCHECK(rdp_rdg_bounded_queue_read(&outbound, bytes, 1u) == 1u);
    TCHECK(outbound.bytes == 4u && outbound.nodes == 1u);
    TCHECK(rdp_rdg_bounded_queue_can_push(&outbound, sizeof(first)));
    TCHECK(rdp_rdg_bounded_queue_push(&outbound, 3u, first, sizeof(first)) == LIBRDP_STATUS_OK);
    TCHECK(outbound.bytes == 8u && outbound.nodes == 2u);

    rdp_rdg_bounded_queue_init(&inbound, 6u, 2u);
    TCHECK(rdp_rdg_bounded_queue_push(&inbound, 10u, inbound_data, sizeof(inbound_data)) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_rdg_bounded_queue_push(&inbound, 10u, inbound_data, sizeof(inbound_data)) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_rdg_bounded_queue_push(&inbound, 10u, inbound_data, sizeof(inbound_data)) ==
           LIBRDP_STATUS_AGAIN);
    TCHECK(rdp_rdg_bounded_queue_read(&inbound, bytes, sizeof(inbound_data)) ==
           sizeof(inbound_data));
    TCHECK(inbound.bytes == 3u && inbound.nodes == 1u);
    TCHECK(rdp_rdg_bounded_queue_push(&inbound, 10u, inbound_data, sizeof(inbound_data)) ==
           LIBRDP_STATUS_OK);

    rdp_rdg_bounded_queue_init(&control, 4u, 2u);
    TCHECK(rdp_rdg_bounded_queue_push(&control, 0x100u, NULL, 0u) == LIBRDP_STATUS_OK);
    TCHECK(rdp_rdg_bounded_queue_push(&control, 0x101u, first, sizeof(first)) ==
           LIBRDP_STATUS_OK);
    TCHECK(control.bytes == 4u && control.nodes == 2u);
    TCHECK(rdp_rdg_bounded_queue_push(&control, 0x102u, NULL, 0u) == LIBRDP_STATUS_AGAIN);
    TCHECK(rdp_rdg_bounded_queue_pop(&control, &type, &payload) == LIBRDP_STATUS_OK);
    TCHECK(type == 0x100u && payload.length == 0u && payload.data == NULL);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    TCHECK(rdp_rdg_bounded_queue_push(&control, 0x102u, NULL, 0u) == LIBRDP_STATUS_OK);
    TCHECK(control.bytes == 4u && control.nodes == 2u);
    TCHECK(rdp_rdg_bounded_queue_pop(&control, &type, &payload) == LIBRDP_STATUS_OK);
    TCHECK(type == 0x101u && payload.length == sizeof(first));
    TCHECK(memcmp(payload.data, first, sizeof(first)) == 0);
    rdp_buffer_free(&payload);

    rdp_rdg_bounded_queue_init(&invalid, 0u, 0u);
    TCHECK(rdp_rdg_bounded_queue_push(&invalid, 0u, NULL, 0u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_rdg_bounded_queue_push(NULL, 0u, NULL, 0u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_rdg_bounded_queue_clear(&outbound);
    rdp_rdg_bounded_queue_clear(&inbound);
    rdp_rdg_bounded_queue_clear(&control);
    rdp_rdg_bounded_queue_clear(&invalid);
    TCHECK(outbound.head == NULL && outbound.tail == NULL && outbound.bytes == 0u &&
           outbound.nodes == 0u);
    TCHECK(inbound.head == NULL && inbound.tail == NULL && inbound.bytes == 0u &&
           inbound.nodes == 0u);
    TCHECK(control.head == NULL && control.tail == NULL && control.bytes == 0u &&
           control.nodes == 0u);
    return 0;
}

#ifdef RDP_HAVE_CURL
static int test_gateway_proxy_listen(uint16_t* port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);
    int fd = -1;
    int one = 1;

    if (!port)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(fd, 1) != 0)
    {
        close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

static int test_write_all_fd(int fd, const void* data, size_t length)
{
    const uint8_t* cursor = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t wrote = write(fd, cursor + offset, length - offset);

        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return 0;
        offset += (size_t)wrote;
    }
    return 1;
}

static int test_read_exact_fd(int fd, void* data, size_t length)
{
    uint8_t* cursor = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t got = read(fd, cursor + offset, length - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return 0;
        offset += (size_t)got;
    }
    return 1;
}

static int test_gateway_read_http_headers(int fd, char* request, size_t request_len)
{
    size_t used = 0;

    if (!request || request_len == 0)
        return 0;
    while (used + 1u < request_len)
    {
        ssize_t got = read(fd, request + used, 1u);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return 0;
        used += (size_t)got;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            return 1;
    }
    return 0;
}

static void test_rdg_append_header(rdp_buffer* packet, uint16_t type, uint32_t length)
{
    (void)rdp_buffer_append_u16_le(packet, type);
    (void)rdp_buffer_append_u16_le(packet, 0);
    (void)rdp_buffer_append_u32_le(packet, length);
}

static int test_rdg_make_packet(uint16_t type, const rdp_buffer* body, rdp_buffer* packet)
{
    uint32_t length = 8u + (uint32_t)(body ? body->length : 0u);

    rdp_buffer_init(packet);
    test_rdg_append_header(packet, type, length);
    if (body && body->length > 0 && rdp_buffer_append(packet, body->data, body->length) != LIBRDP_STATUS_OK)
        return 0;
    return 1;
}

static int test_rdg_write_chunk(int fd, const rdp_buffer* packet)
{
    char header[32];
    int written = snprintf(header, sizeof(header), "%zx\r\n", packet ? packet->length : 0u);

    if (written <= 0 || (size_t)written >= sizeof(header))
        return 0;
    if (!test_write_all_fd(fd, header, (size_t)written))
        return 0;
    if (packet && packet->length > 0 && !test_write_all_fd(fd, packet->data, packet->length))
        return 0;
    return test_write_all_fd(fd, "\r\n", 2u);
}

static int test_rdg_send_handshake_response(int out_fd)
{
    rdp_buffer body;
    rdp_buffer packet;
    int ok = 0;

    rdp_buffer_init(&body);
    (void)rdp_buffer_append_u32_le(&body, 0);
    (void)rdp_buffer_append_u8(&body, 1);
    (void)rdp_buffer_append_u8(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0);
    ok = test_rdg_make_packet(0x0002u, &body, &packet) && test_rdg_write_chunk(out_fd, &packet);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&body);
    return ok;
}

static int test_rdg_send_tunnel_response(int out_fd)
{
    rdp_buffer body;
    rdp_buffer packet;
    int ok = 0;

    rdp_buffer_init(&body);
    (void)rdp_buffer_append_u16_le(&body, 0);
    (void)rdp_buffer_append_u32_le(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0x0003u);
    (void)rdp_buffer_append_u16_le(&body, 0);
    (void)rdp_buffer_append_u32_le(&body, 6);
    (void)rdp_buffer_append_u32_le(&body, 0);
    ok = test_rdg_make_packet(0x0005u, &body, &packet) && test_rdg_write_chunk(out_fd, &packet);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&body);
    return ok;
}

static int test_rdg_send_auth_response(int out_fd)
{
    rdp_buffer body;
    rdp_buffer packet;
    int ok = 0;

    rdp_buffer_init(&body);
    (void)rdp_buffer_append_u32_le(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0);
    ok = test_rdg_make_packet(0x0007u, &body, &packet) && test_rdg_write_chunk(out_fd, &packet);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&body);
    return ok;
}

static int test_rdg_send_channel_response(int out_fd)
{
    rdp_buffer body;
    rdp_buffer packet;
    int ok = 0;

    rdp_buffer_init(&body);
    (void)rdp_buffer_append_u32_le(&body, 0);
    (void)rdp_buffer_append_u16_le(&body, 0x0001u);
    (void)rdp_buffer_append_u16_le(&body, 0);
    (void)rdp_buffer_append_u32_le(&body, 1);
    ok = test_rdg_make_packet(0x0009u, &body, &packet) && test_rdg_write_chunk(out_fd, &packet);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&body);
    return ok;
}

static int test_rdg_append_data_packet(rdp_buffer* stream,
                                       const void* data,
                                       size_t length)
{
    rdp_buffer body;
    rdp_buffer packet;
    int ok = 0;

    if (!stream || length > UINT16_MAX)
        return 0;
    rdp_buffer_init(&body);
    (void)rdp_buffer_append_u16_le(&body, (uint16_t)length);
    (void)rdp_buffer_append(&body, data, length);
    ok = test_rdg_make_packet(0x000au, &body, &packet) &&
         rdp_buffer_append(stream, packet.data, packet.length) == LIBRDP_STATUS_OK;
    rdp_buffer_free(&packet);
    rdp_buffer_free(&body);
    return ok;
}

static int test_rdg_send_data_pair(int out_fd)
{
    rdp_buffer stream;
    int ok = 0;

    rdp_buffer_init(&stream);
    ok = test_rdg_append_data_packet(&stream, "pong", 4u) &&
         test_rdg_append_data_packet(&stream, "next", 4u) &&
         test_rdg_write_chunk(out_fd, &stream);
    rdp_buffer_free(&stream);
    return ok;
}

static uint16_t test_rdg_read_u16_le(const uint8_t* data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t test_rdg_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static int test_rdg_read_chunk(int fd, rdp_buffer* chunk)
{
    char line[32];
    size_t used = 0;
    unsigned long length = 0;
    char* end = NULL;
    char crlf[2];

    rdp_buffer_init(chunk);
    while (used + 1u < sizeof(line))
    {
        char c = '\0';

        if (!test_read_exact_fd(fd, &c, 1u))
            return 0;
        line[used++] = c;
        line[used] = '\0';
        if (used >= 2u && line[used - 2u] == '\r' && line[used - 1u] == '\n')
            break;
    }
    length = strtoul(line, &end, 16);
    if (end == line || length > 65536ul)
        return 0;
    if (rdp_buffer_reserve(chunk, (size_t)length) != LIBRDP_STATUS_OK)
        return 0;
    chunk->length = (size_t)length;
    if (length > 0 && !test_read_exact_fd(fd, chunk->data, (size_t)length))
        return 0;
    return test_read_exact_fd(fd, crlf, sizeof(crlf)) && crlf[0] == '\r' && crlf[1] == '\n';
}

static int test_rdg_process_packet(int out_fd, const uint8_t* packet, size_t packet_len, int* echoed)
{
    uint16_t type = 0;
    uint32_t length = 0;
    const uint8_t* payload = NULL;
    size_t payload_len = 0;

    if (!packet || packet_len < 8u || !echoed)
        return 0;
    type = test_rdg_read_u16_le(packet);
    length = test_rdg_read_u32_le(packet + 4u);
    if (length < 8u || (size_t)length > packet_len)
        return 0;
    payload = packet + 8u;
    payload_len = (size_t)length - 8u;
    if (type == 0x0001u)
        return test_rdg_send_handshake_response(out_fd);
    if (type == 0x0004u)
        return test_rdg_send_tunnel_response(out_fd);
    if (type == 0x0006u)
        return test_rdg_send_auth_response(out_fd);
    if (type == 0x0008u)
        return test_rdg_send_channel_response(out_fd);
    if (type == 0x000au)
    {
        uint16_t data_len = 0;

        if (payload_len < 2u)
            return 0;
        data_len = test_rdg_read_u16_le(payload);
        if ((size_t)data_len > payload_len - 2u || data_len != 4u || memcmp(payload + 2u, "ping", 4u) != 0)
            return 0;
        *echoed = 1;
        return test_rdg_send_data_pair(out_fd);
    }
    return type == 0x0010u;
}

static int test_rdg_server_loop(int in_fd, int out_fd)
{
    rdp_buffer incoming;
    int echoed = 0;

    rdp_buffer_init(&incoming);
    while (!echoed)
    {
        rdp_buffer chunk;

        if (!test_rdg_read_chunk(in_fd, &chunk))
        {
            rdp_buffer_free(&incoming);
            return echoed;
        }
        if (rdp_buffer_append(&incoming, chunk.data, chunk.length) != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&chunk);
            rdp_buffer_free(&incoming);
            return 0;
        }
        rdp_buffer_free(&chunk);
        while (incoming.length >= 8u)
        {
            uint32_t packet_len = test_rdg_read_u32_le(incoming.data + 4u);

            if (packet_len < 8u || packet_len > incoming.length)
                break;
            if (!test_rdg_process_packet(out_fd, incoming.data, packet_len, &echoed) ||
                rdp_buffer_consume(&incoming, packet_len) != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&incoming);
                return 0;
            }
        }
    }
    for (;;)
    {
        rdp_buffer chunk;

        if (!test_rdg_read_chunk(in_fd, &chunk))
            break;
        rdp_buffer_free(&chunk);
    }
    rdp_buffer_free(&incoming);
    return 1;
}

static int test_gateway_rdg_http_child(int listen_fd)
{
    char request[2048];
    int out_fd = -1;
    int in_fd = -1;
    const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    int ok = 0;
    int i = 0;

    for (i = 0; i < 2 && ok == 0; i++)
    {
        int client = accept(listen_fd, NULL, NULL);

        if (client < 0 || !test_gateway_read_http_headers(client, request, sizeof(request)))
        {
            if (client >= 0)
                close(client);
            break;
        }
        if (i == 0 && strstr(request, "RDG_OUT_DATA "))
        {
            if (out_fd >= 0)
            {
                close(client);
                break;
            }
            out_fd = client;
        }
        else if (i == 1 && strstr(request, "RDG_IN_DATA "))
        {
            if (in_fd >= 0)
            {
                close(client);
                break;
            }
            in_fd = client;
        }
        else
        {
            close(client);
            break;
        }
        if (!test_write_all_fd(client, response, sizeof(response) - 1u))
            break;
        if (i == 1)
            ok = 1;
    }
    if (ok && in_fd >= 0 && out_fd >= 0)
        ok = test_rdg_server_loop(in_fd, out_fd);
    else
        ok = 0;

    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return ok ? 0 : 1;
}

/*
 * Fixture: minimal local HTTP CONNECT proxy used to exercise the curl-backed
 * gateway transport without a remote network dependency or real credentials.
 */
static int test_gateway_proxy_child(int listen_fd)
{
    char request[1024];
    size_t used = 0;
    int client = -1;
    const char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    char tunnel[4];

    client = accept(listen_fd, NULL, NULL);
    if (client < 0)
        return 1;
    while (used + 1u < sizeof(request))
    {
        ssize_t got = read(client, request + used, sizeof(request) - used - 1u);

        if (got <= 0)
        {
            close(client);
            return 1;
        }
        used += (size_t)got;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            break;
    }
    if (!strstr(request, "CONNECT 127.0.0.1:3390 HTTP/"))
    {
        close(client);
        return 1;
    }
    if (write(client, response, sizeof(response) - 1u) != (ssize_t)(sizeof(response) - 1u))
    {
        close(client);
        return 1;
    }
    if (read(client, tunnel, sizeof(tunnel)) != (ssize_t)sizeof(tunnel) ||
        memcmp(tunnel, "ping", sizeof(tunnel)) != 0)
    {
        close(client);
        return 1;
    }
    if (write(client, "pong", 4u) != 4)
    {
        close(client);
        return 1;
    }
    close(client);
    return 0;
}
#endif

static int test_gateway_connect_transport(void)
{
    rdp_transport transport;
    rdp_gateway_connect_config config;
#ifdef RDP_HAVE_CURL
    char gateway_url[64];
    char data[4];
    size_t got = 0;
    uint16_t port = 0;
    int listen_fd = -1;
    pid_t child = -1;
    int child_status = 0;
#endif

    memset(&config, 0, sizeof(config));
    config.gateway_url = "http://127.0.0.1:1";
    config.target_host = "127.0.0.1";
    config.target_port = 3390;
    config.timeout_ms = 1000u;
    config.mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    rdp_transport_init(&transport);
#ifndef RDP_HAVE_CURL
    TCHECK(rdp_gateway_connect_transport(&transport, &config) == LIBRDP_STATUS_UNSUPPORTED);
    config.mode = LIBRDP_GATEWAY_RDG_HTTP;
    config.gateway_url = "https://gateway.example.com/rdg";
    TCHECK(rdp_gateway_connect_transport(&transport, &config) == LIBRDP_STATUS_UNSUPPORTED);
    return 0;
#else
    config.mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    listen_fd = test_gateway_proxy_listen(&port);
    TCHECK(listen_fd >= 0);
    child = fork();
    TCHECK(child >= 0);
    if (child == 0)
    {
        int rc = test_gateway_proxy_child(listen_fd);

        close(listen_fd);
        _exit(rc == 0 ? 0 : 1);
    }
    close(listen_fd);
    listen_fd = -1;
    TCHECK(snprintf(gateway_url, sizeof(gateway_url), "http://127.0.0.1:%u", (unsigned)port) > 0);
    config.gateway_url = gateway_url;
    config.username = "gateway-user";
    config.password = "gateway-secret";
    config.domain = "DOMAIN";
    TCHECK(rdp_gateway_connect_transport(&transport, &config) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_write_all(&transport, "ping", 4u) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_wait(&transport, 1000, POLLIN, NULL) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_peek(&transport, data, sizeof(data), &got) == LIBRDP_STATUS_OK);
    TCHECK(got == sizeof(data));
    TCHECK(memcmp(data, "pong", sizeof(data)) == 0);
    TCHECK(rdp_transport_read_exact(&transport, data, sizeof(data)) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "pong", sizeof(data)) == 0);
    rdp_transport_close(&transport);
    TCHECK(waitpid(child, &child_status, 0) == child);
    TCHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    listen_fd = test_gateway_proxy_listen(&port);
    TCHECK(listen_fd >= 0);
    child = fork();
    TCHECK(child >= 0);
    if (child == 0)
    {
        int rc = test_gateway_rdg_http_child(listen_fd);

        close(listen_fd);
        _exit(rc == 0 ? 0 : 1);
    }
    close(listen_fd);
    listen_fd = -1;
    rdp_transport_init(&transport);
    TCHECK(snprintf(gateway_url,
                    sizeof(gateway_url),
                    "http://127.0.0.1:%u/remoteDesktopGateway/",
                    (unsigned)port) > 0);
    config.gateway_url = gateway_url;
    config.mode = LIBRDP_GATEWAY_RDG_HTTP;
    config.timeout_ms = 5000u;
    config.queue_bytes = 0u;
    config.queue_nodes = 1u;
    TCHECK(rdp_gateway_connect_transport(&transport, &config) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_write_all(&transport, "ping", 4u) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_wait(&transport, 1000, POLLIN, NULL) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_peek(&transport, data, sizeof(data), &got) == LIBRDP_STATUS_OK);
    TCHECK(got == sizeof(data));
    TCHECK(memcmp(data, "pong", sizeof(data)) == 0);
    TCHECK(rdp_transport_read_exact(&transport, data, sizeof(data)) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "pong", sizeof(data)) == 0);
    TCHECK(rdp_transport_wait(&transport, 1000, POLLIN, NULL) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_read_exact(&transport, data, sizeof(data)) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "next", sizeof(data)) == 0);
    rdp_transport_close(&transport);
    TCHECK(waitpid(child, &child_status, 0) == child);
    TCHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
#endif
}

static int capture_stderr_fn(void (*fn)(void*), void* user_data, char* out, size_t out_len)
{
    int pipe_fds[2] = {-1, -1};
    int saved = -1;
    ssize_t got = 0;

    if (!fn || !out || out_len == 0 || pipe(pipe_fds) != 0)
        return 0;
    saved = dup(STDERR_FILENO);
    if (saved < 0)
        return 0;
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0)
        return 0;
    close(pipe_fds[1]);
    fn(user_data);
    fflush(stderr);
    if (dup2(saved, STDERR_FILENO) < 0)
        return 0;
    close(saved);

    got = read(pipe_fds[0], out, out_len - 1u);
    close(pipe_fds[0]);
    if (got < 0)
        got = 0;
    out[got] = '\0';
    return 1;
}

static int add_test_certificate_extension(X509* cert, X509* issuer, int nid, const char* value)
{
    X509V3_CTX context;
    X509_EXTENSION* extension = NULL;
    int ok = 0;

    if (!cert || !issuer || !value)
        return 0;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer, cert, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char*)value);
    if (!extension)
        return 0;
    ok = X509_add_ext(cert, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return ok;
}

static int set_test_certificate_name(X509* cert, const char* common_name)
{
    X509_NAME* name = NULL;

    if (!cert || !common_name)
        return 0;
    name = X509_get_subject_name(cert);
    if (!name)
        return 0;
    return X509_NAME_add_entry_by_txt(name,
                                      "CN",
                                      MBSTRING_ASC,
                                      (const unsigned char*)common_name,
                                      -1,
                                      -1,
                                      0) == 1;
}

/*
 * Fixture: generates an in-memory CA for strict TLS tests. The trust anchor is
 * added explicitly to the client store, so successful handshakes do not depend
 * on disabling certificate verification.
 */
static int make_test_ca_certificate(EVP_PKEY** key, X509** cert)
{
    X509_NAME* name = NULL;

    if (!key || !cert)
        return 0;
    *key = EVP_RSA_gen(2048);
    *cert = X509_new();
    if (!*key || !*cert)
        return 0;
    if (ASN1_INTEGER_set(X509_get_serialNumber(*cert), 1) != 1)
        return 0;
    if (!X509_gmtime_adj(X509_get_notBefore(*cert), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(*cert), 3600))
        return 0;
    if (X509_set_version(*cert, 2) != 1 || X509_set_pubkey(*cert, *key) != 1)
        return 0;
    if (!set_test_certificate_name(*cert, "librdp-test-ca"))
        return 0;
    name = X509_get_subject_name(*cert);
    if (X509_set_issuer_name(*cert, name) != 1)
        return 0;
    if (!add_test_certificate_extension(*cert, *cert, NID_basic_constraints, "critical,CA:TRUE") ||
        !add_test_certificate_extension(*cert, *cert, NID_key_usage, "critical,keyCertSign,cRLSign"))
        return 0;
    return X509_sign(*cert, *key, EVP_sha256()) > 0;
}

static int make_test_server_certificate(EVP_PKEY** key,
                                        X509** cert,
                                        EVP_PKEY* issuer_key,
                                        X509* issuer,
                                        int serial,
                                        const char* common_name,
                                        const char* san,
                                        long not_before_offset,
                                        long not_after_offset)
{
    X509_NAME* issuer_name = NULL;

    if (!key || !cert || !issuer_key || !issuer || !common_name || !san)
        return 0;
    *key = EVP_RSA_gen(2048);
    *cert = X509_new();
    if (!*key || !*cert)
        return 0;
    if (ASN1_INTEGER_set(X509_get_serialNumber(*cert), serial) != 1)
        return 0;
    if (!X509_gmtime_adj(X509_get_notBefore(*cert), not_before_offset) ||
        !X509_gmtime_adj(X509_get_notAfter(*cert), not_after_offset))
        return 0;
    if (X509_set_version(*cert, 2) != 1 || X509_set_pubkey(*cert, *key) != 1)
        return 0;
    if (!set_test_certificate_name(*cert, common_name))
        return 0;
    issuer_name = X509_get_subject_name(issuer);
    if (!issuer_name || X509_set_issuer_name(*cert, issuer_name) != 1)
        return 0;
    if (!add_test_certificate_extension(*cert, issuer, NID_basic_constraints, "critical,CA:FALSE") ||
        !add_test_certificate_extension(*cert, issuer, NID_key_usage, "digitalSignature,keyEncipherment") ||
        !add_test_certificate_extension(*cert, issuer, NID_ext_key_usage, "serverAuth") ||
        !add_test_certificate_extension(*cert, issuer, NID_subject_alt_name, san))
        return 0;
    return X509_sign(*cert, issuer_key, EVP_sha256()) > 0;
}

static int make_test_self_signed_server_certificate(EVP_PKEY** key, X509** cert)
{
    if (!make_test_ca_certificate(key, cert))
        return 0;
    return add_test_certificate_extension(*cert, *cert, NID_subject_alt_name, "DNS:localhost");
}

static int test_certificate_fingerprint(X509* cert,
                                        char output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    static const char hex[] = "0123456789abcdef";

    if (!cert || !output)
        return 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1 || digest_len != 32u)
        return 0;
    for (size_t i = 0; i < 32u; i++)
    {
        output[i * 2u] = hex[(digest[i] >> 4) & 0x0fu];
        output[(i * 2u) + 1u] = hex[digest[i] & 0x0fu];
    }
    output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH] = '\0';
    return 1;
}

typedef struct test_tls_callback_state
{
    int calls;
    int accept;
    int reject;
    librdp_status verify_status;
    char fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
} test_tls_callback_state;

typedef struct test_tls_tofu_store
{
    int calls;
    int first_use;
    int repeat;
    int changed;
    char fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
} test_tls_tofu_store;

static librdp_tls_certificate_decision test_tls_certificate_callback(const librdp_tls_certificate_info* certificate,
                                                                    void* user_data)
{
    test_tls_callback_state* state = (test_tls_callback_state*)user_data;

    if (!certificate || !state || certificate->version != LIBRDP_TLS_CERTIFICATE_INFO_VERSION ||
        certificate->size < sizeof(*certificate) || !certificate->host || !certificate->der ||
        certificate->der_len == 0 || certificate->sha256_fingerprint[0] == '\0')
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    state->calls += 1;
    state->verify_status = certificate->verify_status;
    memcpy(state->fingerprint,
           certificate->sha256_fingerprint,
           LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u);
    if (state->reject)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    if (state->accept)
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    return LIBRDP_TLS_CERTIFICATE_DECISION_DEFAULT;
}

/*
 * Models an application-owned TOFU store across independent connections.
 * First use persists the fingerprint, an exact repeat is accepted, and a
 * changed certificate is rejected without replacing trusted state.
 */
static librdp_tls_certificate_decision test_tls_tofu_store_callback(
  const librdp_tls_certificate_info* certificate,
  void* user_data)
{
    test_tls_tofu_store* store = (test_tls_tofu_store*)user_data;

    if (!certificate || !store || certificate->version != LIBRDP_TLS_CERTIFICATE_INFO_VERSION ||
        certificate->size < sizeof(*certificate) || certificate->sha256_fingerprint[0] == '\0')
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    store->calls++;
    if (store->fingerprint[0] == '\0')
    {
        memcpy(store->fingerprint,
               certificate->sha256_fingerprint,
               LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u);
        store->first_use++;
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    if (strcmp(store->fingerprint, certificate->sha256_fingerprint) == 0)
    {
        store->repeat++;
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    store->changed++;
    return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
}

/*
 * Fixture: runs a local TLS peer for deterministic read/write coverage. It
 * validates TLS shutdown and descriptor lifetime without external network
 * dependencies.
 */
static int run_tls_server(int fd, EVP_PKEY* key, X509* cert, int expect_success)
{
    SSL_CTX* context = NULL;
    SSL* tls = NULL;
    char input[4];
    int ok = 0;
    int do_shutdown = 0;

    (void)signal(SIGPIPE, SIG_IGN);
    context = SSL_CTX_new(TLS_server_method());
    if (!context)
        goto out;
    if (SSL_CTX_use_certificate(context, cert) != 1 || SSL_CTX_use_PrivateKey(context, key) != 1)
        goto out;
    tls = SSL_new(context);
    if (!tls)
        goto out;
    if (SSL_set_fd(tls, fd) != 1)
        goto out;
    if (SSL_accept(tls) != 1)
    {
        ok = expect_success ? 0 : 1;
        goto out;
    }
    if (!expect_success)
    {
        ok = 1;
        goto out;
    }
    if (SSL_read(tls, input, sizeof(input)) != (int)sizeof(input))
        goto out;
    if (memcmp(input, "ping", 4) != 0)
        goto out;
    if (SSL_write(tls, "pong", 4) != 4)
        goto out;
    do_shutdown = 1;
    ok = 1;

out:
    if (tls)
    {
        if (do_shutdown)
        {
            SSL_set_quiet_shutdown(tls, 1);
            (void)SSL_shutdown(tls);
        }
        SSL_free(tls);
    }
    if (context)
        SSL_CTX_free(context);
    close(fd);
    return ok;
}

/*
 * A peer that accepts TCP but never speaks TLS must not block the caller.
 * The timeout path also restores the descriptor mode expected by later plain
 * transport cleanup.
 */
static int test_tls_handshake_timeout(void)
{
    int pair[2] = {-1, -1};
    int nonblocking = 1;
    rdp_transport transport;
    rdp_transport_tls_config config;

    rdp_transport_init(&transport);
    memset(&config, 0, sizeof(config));
    config.host = "localhost";
    config.timeout_ms = 25;
    config.policy_mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
    TCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    rdp_transport_attach_fd(&transport, pair[0], 1);
    pair[0] = -1;
    TCHECK(rdp_transport_start_tls_with_config(&transport, &config) == LIBRDP_STATUS_TIMEOUT);
    TCHECK(rdp_socket_get_nonblocking(transport.fd, &nonblocking) == 0);
    TCHECK(nonblocking == 0);
    rdp_transport_close(&transport);
    close(pair[1]);
    return 0;
}

/*
 * A descriptor that never becomes connect-writable must consume the requested
 * timeout and return TIMEOUT without consulting SO_ERROR or external routing.
 * A loopback listener supplies that deterministic non-writable socket state.
 */
static int test_tcp_connect_wait_timeout(void)
{
    struct sockaddr_in address;
    int listener = -1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    TCHECK(listener >= 0);
    TCHECK(bind(listener,
                (const struct sockaddr*)&address,
                (socklen_t)sizeof(address)) == 0);
    TCHECK(listen(listener, 1) == 0);
    TCHECK(rdp_tcp_wait_connected(listener, 25) == LIBRDP_STATUS_TIMEOUT);
    close(listener);
    return 0;
}

static int test_transport_timeout_boundaries(void)
{
    TCHECK(test_tcp_connect_wait_timeout() == 0);
    TCHECK(test_tls_handshake_timeout() == 0);
    return 0;
}

static int run_tls_client_case(EVP_PKEY* key,
                               X509* cert,
                               X509* trust_anchor,
                               const char* host,
                               librdp_tls_policy_mode policy_mode,
                               int use_system_store,
                               const char* pinned_sha256,
                               librdp_tls_certificate_callback callback,
                               void* callback_user_data,
                               librdp_status expected_status,
                               int exchange_data,
                               rdp_buffer* public_key)
{
    int tls_pair[2] = {-1, -1};
    int child_status = 0;
    int ok = 0;
    pid_t child = -1;
    rdp_transport transport;
    rdp_transport_tls_config tls_config;
    char data[4];
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_transport_init(&transport);
    memset(&tls_config, 0, sizeof(tls_config));
    tls_config.host = host;
    tls_config.use_system_store = use_system_store;
    tls_config.trust_anchor = trust_anchor;
    tls_config.policy_mode = policy_mode;
    tls_config.pinned_sha256 = pinned_sha256;
    tls_config.certificate_callback = callback;
    tls_config.certificate_callback_user_data = callback_user_data;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, tls_pair) != 0)
        goto out;
    child = fork();
    if (child < 0)
        goto out;
    if (child == 0)
    {
        close(tls_pair[0]);
        _exit(run_tls_server(tls_pair[1], key, cert, expected_status == LIBRDP_STATUS_OK) ? 0 : 1);
    }
    close(tls_pair[1]);
    tls_pair[1] = -1;
    rdp_transport_attach_fd(&transport, tls_pair[0], 1);
    tls_pair[0] = -1;

    status = rdp_transport_start_tls_with_config(&transport, &tls_config);
    if (status != expected_status)
    {
        fprintf(stderr,
                "tls case status=%s expected=%s policy=%d use_system_store=%d\n",
                librdp_status_string(status),
                librdp_status_string(expected_status),
                (int)policy_mode,
                use_system_store);
        goto out;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (public_key && rdp_transport_get_tls_public_key(&transport, public_key) != LIBRDP_STATUS_OK)
            goto out;
        if (exchange_data)
        {
            if (rdp_transport_write_all(&transport, "ping", 4) != LIBRDP_STATUS_OK ||
                rdp_transport_read_exact(&transport, data, sizeof(data)) != LIBRDP_STATUS_OK ||
                memcmp(data, "pong", sizeof(data)) != 0)
                goto out;
        }
    }
    rdp_transport_close(&transport);
    if (child > 0)
    {
        if (waitpid(child, &child_status, 0) != child)
            goto out;
        child = -1;
        if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
        {
            fprintf(stderr,
                    "tls server exited abnormally status=%d policy=%d expected_success=%d\n",
                    child_status,
                    (int)policy_mode,
                    expected_status == LIBRDP_STATUS_OK);
            goto out;
        }
    }
    ok = 1;

out:
    rdp_transport_close(&transport);
    if (tls_pair[0] >= 0)
        close(tls_pair[0]);
    if (tls_pair[1] >= 0)
        close(tls_pair[1]);
    if (child > 0)
        (void)waitpid(child, &child_status, 0);
    return ok;
}

typedef struct test_tls_trace_case
{
    EVP_PKEY* key;
    X509* cert;
    const char* wrong_fingerprint;
    int ok;
} test_tls_trace_case;

static void run_tls_wrong_pin_trace(void* user_data)
{
    test_tls_trace_case* test = (test_tls_trace_case*)user_data;

    if (!test)
        return;
    setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
    unsetenv("LIBRDP_TRACE_LEVEL");
    rdp_trace_reset_for_tests();
    test->ok = run_tls_client_case(test->key,
                                   test->cert,
                                   NULL,
                                   "localhost",
                                   LIBRDP_TLS_POLICY_PINNED_FINGERPRINT,
                                   0,
                                   test->wrong_fingerprint,
                                   NULL,
                                   NULL,
                                   LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                                   0,
                                   NULL);
    unsetenv("LIBRDP_TRACE_TRANSPORT");
    rdp_trace_reset_for_tests();
}

static void run_tls_insecure_trace(void* user_data)
{
    test_tls_trace_case* test = (test_tls_trace_case*)user_data;

    if (!test)
        return;
    setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
    unsetenv("LIBRDP_TRACE_LEVEL");
    rdp_trace_reset_for_tests();
    test->ok = run_tls_client_case(test->key,
                                   test->cert,
                                   NULL,
                                   "localhost",
                                   LIBRDP_TLS_POLICY_INSECURE_LAB,
                                   0,
                                   NULL,
                                   NULL,
                                   NULL,
                                   LIBRDP_STATUS_OK,
                                   1,
                                   NULL);
    unsetenv("LIBRDP_TRACE_TRANSPORT");
    rdp_trace_reset_for_tests();
}

/*
 * Coverage: validates low-level UDP and UDP2 packet parser/writer vectors with
 * malformed padding, ACK, correlation, and sequence fields.
 */
static int test_udp_transport_protocols(void)
{
    const uint8_t payload[] = {0xaa, 0xbb, 0xcc, 0xdd};
    const uint8_t wire_example[] = {0x73, 0x30, 0x35, 0x56, 0x78, 0xa2, 0x36, 0x10, 0xee, 0x68, 0xf2};
    const uint8_t layout_example[] = {0x30, 0x35, 0x56, 0x78, 0xa2, 0x36, 0x73, 0xee, 0x68, 0xf2};
    const uint8_t udp2_empty_data_packet[] = {0x04u, 0x40u, 0x34u, 0x12u};
    rdp_buffer buffer;
    rdp_buffer wire;
    rdp_buffer unwrapped;
    rdp_udp_fec_header fec_header;
    rdp_udp_fec_payload_header fec_payload;
    rdp_udp_payload_prefix payload_prefix;
    rdp_udp_source_payload_header source_header;
    rdp_udp_syn_data syn;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_ack_vector_entry ack_entry;
    rdp_udp_correlation_id correlation;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp2_header udp2_header;
    rdp_udp2_packet udp2_packet;
    rdp_udp2_prefix udp2_prefix;
    rdp_udp2_packet_kind udp2_kind;
    rdp_udp2_ack_vector_entry udp2_ack_entry;
    uint8_t cookie_hash[32];
    uint8_t correlation_id[16];
    uint8_t ack_vec_bytes[16];
    uint32_t received_count = 0;
    uint32_t pending_count = 0;
    uint32_t lost_count = 0;
    size_t i = 0;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&unwrapped);
    memset(cookie_hash, 0x5a, sizeof(cookie_hash));
    memset(ack_vec_bytes, 0, sizeof(ack_vec_bytes));
    for (i = 0; i < sizeof(correlation_id); i++)
        correlation_id[i] = (uint8_t)(i + 1u);

    fec_header.source_ack = 0x11223344u;
    fec_header.receive_window_size = 64;
    fec_header.flags = RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SYNEX;
    TCHECK(rdp_udp_write_fec_header(&buffer, &fec_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_fec_header(buffer.data, buffer.length, &fec_header) == LIBRDP_STATUS_OK);
    TCHECK(fec_header.source_ack == 0x11223344u);
    {
        rdp_udp_fec_header valid_fec_header = fec_header;

        buffer.data[7] = 0x80u;
        TCHECK(rdp_udp_parse_fec_header(buffer.data, buffer.length, &fec_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&fec_header, &valid_fec_header, sizeof(fec_header)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    fec_payload.coded_sequence = 1;
    fec_payload.source_start = 2;
    fec_payload.range = 3;
    fec_payload.fec_index = 4;
    fec_payload.padding = 0;
    TCHECK(rdp_udp_write_fec_payload_header(&buffer, &fec_payload) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_fec_payload_header(buffer.data, buffer.length, &fec_payload) ==
           LIBRDP_STATUS_OK);
    TCHECK(fec_payload.coded_sequence == 1 && fec_payload.source_start == 2);
    {
        rdp_udp_fec_payload_header valid_fec_payload = fec_payload;

        buffer.data[10] = 1;
        TCHECK(rdp_udp_parse_fec_payload_header(buffer.data, buffer.length, &fec_payload) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&fec_payload, &valid_fec_payload, sizeof(fec_payload)) == 0);
    }
    buffer.data[10] = 0;
    fec_payload.padding = 1;
    TCHECK(rdp_udp_write_fec_payload_header(&buffer, &fec_payload) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_payload_prefix(&buffer, sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_payload_prefix(buffer.data, buffer.length, &payload_prefix) == LIBRDP_STATUS_OK);
    TCHECK(payload_prefix.payload_size == sizeof(payload));
    {
        rdp_udp_payload_prefix valid_payload_prefix = payload_prefix;

        TCHECK(rdp_udp_parse_payload_prefix(buffer.data,
                                            buffer.length - 1u,
                                            &payload_prefix) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&payload_prefix, &valid_payload_prefix, sizeof(payload_prefix)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    source_header.coded_sequence = 5;
    source_header.source_start = 6;
    TCHECK(rdp_udp_write_source_payload_header(&buffer, &source_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_source_payload_header(buffer.data, buffer.length, &source_header) ==
           LIBRDP_STATUS_OK);
    TCHECK(source_header.coded_sequence == 5 && source_header.source_start == 6);
    {
        rdp_udp_source_payload_header valid_source_header = source_header;

        TCHECK(rdp_udp_parse_source_payload_header(buffer.data,
                                                   buffer.length - 1u,
                                                   &source_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&source_header, &valid_source_header, sizeof(source_header)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    syn.initial_sequence_number = 7;
    syn.upstream_mtu = RDP_UDP_MIN_MTU;
    syn.downstream_mtu = RDP_UDP_MAX_MTU;
    TCHECK(rdp_udp_write_syn_data(&buffer, &syn) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_syn_data(buffer.data, buffer.length, &syn) == LIBRDP_STATUS_OK);
    TCHECK(syn.upstream_mtu == RDP_UDP_MIN_MTU && syn.downstream_mtu == RDP_UDP_MAX_MTU);
    {
        rdp_udp_syn_data valid_syn = syn;

        buffer.data[4] = 1;
        buffer.data[5] = 0;
        TCHECK(rdp_udp_parse_syn_data(buffer.data, buffer.length, &syn) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&syn, &valid_syn, sizeof(syn)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    ack_of_ack.reset_sequence_number = 99;
    TCHECK(rdp_udp_write_ack_of_ack_vector(&buffer, &ack_of_ack) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_ack_of_ack_vector(buffer.data, buffer.length, &ack_of_ack) ==
           LIBRDP_STATUS_OK);
    TCHECK(ack_of_ack.reset_sequence_number == 99);
    {
        rdp_udp_ack_of_ack_vector valid_ack_of_ack = ack_of_ack;

        TCHECK(rdp_udp_parse_ack_of_ack_vector(buffer.data,
                                               buffer.length - 1u,
                                               &ack_of_ack) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&ack_of_ack, &valid_ack_of_ack, sizeof(ack_of_ack)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_ack_vector(&buffer, payload, 3) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) == LIBRDP_STATUS_OK);
    TCHECK(ack_vector.size == 3 && ack_vector.padding_len == 3);
    TCHECK(rdp_udp_ack_vector_decode_entry(0x00u, &ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(ack_entry.state == RDP_UDP_ACK_VECTOR_STATE_RECEIVED && ack_entry.run_length == 0);
    TCHECK(rdp_udp_ack_vector_decode_entry(0xc2u, &ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(ack_entry.state == RDP_UDP_ACK_VECTOR_STATE_PENDING && ack_entry.run_length == 2);
    {
        rdp_udp_ack_vector_entry valid_ack_entry = ack_entry;
        rdp_udp_ack_vector valid_ack_vector = ack_vector;

        TCHECK(rdp_udp_ack_vector_decode_entry(0x40u, &ack_entry) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&ack_entry, &valid_ack_entry, sizeof(ack_entry)) == 0);
        buffer.data[0] = 0x01;
        buffer.data[1] = 0x08;
        TCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&ack_vector, &valid_ack_vector, sizeof(ack_vector)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp_write_correlation_id(&buffer, correlation_id) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) == LIBRDP_STATUS_OK);
    TCHECK(correlation.correlation_id[0] == 1);
    {
        rdp_udp_correlation_id valid_correlation = correlation;

        buffer.data[31] = 1;
        TCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&correlation, &valid_correlation, sizeof(correlation)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    syn_ex.flags = RDP_UDP_SYNEX_VERSION_INFO_VALID;
    syn_ex.udp_version = RDP_UDP_PROTOCOL_VERSION_3;
    syn_ex.has_cookie_hash = 1;
    memcpy(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash));
    TCHECK(rdp_udp_write_syn_data_ex(&buffer, &syn_ex) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp_parse_syn_data_ex(buffer.data, buffer.length, &syn_ex) == LIBRDP_STATUS_OK);
    TCHECK(syn_ex.has_cookie_hash && memcmp(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash)) == 0);
    {
        rdp_udp_syn_data_ex valid_syn_ex = syn_ex;

        buffer.data[0] = 0u;
        TCHECK(rdp_udp_parse_syn_data_ex(buffer.data, buffer.length, &syn_ex) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&syn_ex, &valid_syn_ex, sizeof(syn_ex)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    udp2_header.flags = RDP_UDP2_FLAG_DATA;
    udp2_header.log_window_size = 4;
    TCHECK(rdp_udp2_write_header(&buffer, &udp2_header) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_header(buffer.data, buffer.length, &udp2_header) == LIBRDP_STATUS_OK);
    TCHECK(udp2_header.flags == RDP_UDP2_FLAG_DATA && udp2_header.log_window_size == 4);
    {
        rdp_udp2_header valid_udp2_header = udp2_header;
        const uint8_t invalid_udp2_header[] = {
            (uint8_t)(RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_ACKVEC),
            0x00u
        };

        TCHECK(rdp_udp2_parse_header(invalid_udp2_header,
                                     sizeof(invalid_udp2_header),
                                     &udp2_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&udp2_header, &valid_udp2_header, sizeof(udp2_header)) == 0);
    }
    TCHECK(rdp_udp2_parse_prefix((uint8_t)(RDP_UDP2_PACKET_TYPE_DUMMY << 1), &udp2_prefix) ==
           LIBRDP_STATUS_OK);
    {
        rdp_udp2_prefix valid_udp2_prefix = udp2_prefix;

        TCHECK(rdp_udp2_parse_prefix(0x00u, &udp2_prefix) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&udp2_prefix, &valid_udp2_prefix, sizeof(udp2_prefix)) == 0);
    }
    TCHECK(rdp_udp2_wrap_packet(&buffer, NULL, 0, RDP_UDP2_PACKET_TYPE_DATA) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_udp2_write_data_packet(&buffer, 4, 0x1234u, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    memset(&udp2_packet, 0x5a, sizeof(udp2_packet));
    udp2_packet.header.flags = 0x777u;
    {
        rdp_udp2_packet udp2_before = udp2_packet;

        TCHECK(rdp_udp2_parse_packet(udp2_empty_data_packet,
                                     sizeof(udp2_empty_data_packet),
                                     &udp2_packet) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&udp2_packet, &udp2_before, sizeof(udp2_packet)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_write_data_packet(&buffer, 4, 0x1234u, payload, sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_data && udp2_packet.data_sequence_number == 0x1234u);
    TCHECK(udp2_packet.data_body_len == sizeof(payload));
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_DATA);
    TCHECK(rdp_udp2_wrap_packet(&wire,
                                buffer.data,
                                buffer.length,
                                RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_unwrap_packet(&unwrapped, wire.data, wire.length, &udp2_prefix) == LIBRDP_STATUS_OK);
    TCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA);
    TCHECK(unwrapped.length == buffer.length && memcmp(unwrapped.data, buffer.data, buffer.length) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&wire);
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&unwrapped);

    TCHECK(rdp_udp2_write_ack_packet(&buffer, 5, 0x1010u, 0x00aabbccu, 12, payload, 2, 1) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack && udp2_packet.ack.sequence_number == 0x1010u);
    TCHECK(udp2_packet.ack.delayed_ack_count == 2 && udp2_packet.ack.delayed_ack_time_scale == 1);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&udp2_packet, 0, sizeof(udp2_packet));
    udp2_packet.header.flags = RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_OVERHEADSIZE |
                               RDP_UDP2_FLAG_DELAYACKINFO | RDP_UDP2_FLAG_AOA |
                               RDP_UDP2_FLAG_DATA;
    udp2_packet.header.log_window_size = 3;
    udp2_packet.has_ack = 1;
    udp2_packet.ack.sequence_number = 0x1111u;
    udp2_packet.ack.received_timestamp = 0x00010203u;
    udp2_packet.ack.send_ack_time_gap_ms = 7;
    udp2_packet.has_overhead_size = 1;
    udp2_packet.overhead_size = 9;
    udp2_packet.has_delay_ack_info = 1;
    udp2_packet.max_delayed_acks = 4;
    udp2_packet.delayed_ack_timeout_ms = 50;
    udp2_packet.has_ack_of_acks = 1;
    udp2_packet.ack_of_acks_sequence_number = 0x2222u;
    udp2_packet.has_data = 1;
    udp2_packet.data_sequence_number = 0x3333u;
    udp2_packet.data_body = payload;
    udp2_packet.data_body_len = sizeof(payload);
    TCHECK(rdp_udp2_write_packet(&buffer, &udp2_packet) == LIBRDP_STATUS_OK);
    udp2_packet.has_data = 0;
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_PROTOCOL_ERROR);
    TCHECK(rdp_udp2_write_packet(&wire, &udp2_packet) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack && udp2_packet.has_overhead_size &&
           udp2_packet.has_delay_ack_info && udp2_packet.has_ack_of_acks && udp2_packet.has_data);
    TCHECK(udp2_packet.data_body_len == sizeof(payload) &&
           memcmp(udp2_packet.data_body, payload, sizeof(payload)) == 0);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&wire);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&wire);

    memset(&udp2_packet, 0, sizeof(udp2_packet));
    udp2_packet.header.flags = RDP_UDP2_FLAG_ACKVEC | RDP_UDP2_FLAG_DATA;
    udp2_packet.header.log_window_size = 2;
    udp2_packet.has_ack_vector = 1;
    udp2_packet.ack_vector.base_sequence_number = 0x4444u;
    udp2_packet.ack_vector.coded_ack_vector = ack_vec_bytes;
    udp2_packet.ack_vector.coded_ack_vector_size = 2;
    udp2_packet.has_data = 1;
    udp2_packet.data_sequence_number = 0x5555u;
    udp2_packet.data_body = payload;
    udp2_packet.data_body_len = sizeof(payload);
    TCHECK(rdp_udp2_write_packet(&buffer, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK);
    TCHECK(udp2_packet.has_ack_vector &&
           udp2_packet.has_data &&
           udp2_packet.ack_vector.base_sequence_number == 0x4444u &&
           udp2_packet.data_sequence_number == 0x5555u &&
           udp2_packet.data_body_len == sizeof(payload));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    ack_vec_bytes[0] = 0x02u;
    ack_vec_bytes[1] = 0xc2u;
    ack_vector.size = 2;
    ack_vector.vector = ack_vec_bytes;
    TCHECK(rdp_udp_ack_vector_count(&ack_vector, &received_count, &pending_count) == LIBRDP_STATUS_OK);
    TCHECK(received_count == 3 && pending_count == 3);

    TCHECK(rdp_udp2_write_ack_vector_packet(&buffer, 4, 0x2020u, 1, 0x00030201u, 4, payload, 2) ==
           LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack_vector && udp2_packet.ack_vector.timestamp_present);
    TCHECK(udp2_packet.ack_vector.coded_ack_vector_size == 2);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK_VECTOR);
    TCHECK(rdp_udp2_ack_vector_decode_entry(0x55u, &udp2_ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(udp2_ack_entry.mode == RDP_UDP2_ACK_VECTOR_MODE_BITMAP && udp2_ack_entry.bitmap == 0x55u);
    TCHECK(rdp_udp2_ack_vector_decode_entry(0xc2u, &udp2_ack_entry) == LIBRDP_STATUS_OK);
    TCHECK(udp2_ack_entry.mode == RDP_UDP2_ACK_VECTOR_MODE_RLE &&
           udp2_ack_entry.state == RDP_UDP2_ACK_VECTOR_STATE_RECEIVED &&
           udp2_ack_entry.run_length == 2);
    ack_vec_bytes[0] = 0x7fu;
    ack_vec_bytes[1] = 0xc2u;
    ack_vec_bytes[2] = 0x80u;
    ack_vec_bytes[3] = 0xffu;
    udp2_packet.ack_vector.coded_ack_vector = ack_vec_bytes;
    udp2_packet.ack_vector.coded_ack_vector_size = 4;
    TCHECK(rdp_udp2_ack_vector_count(&udp2_packet.ack_vector, &received_count, &lost_count) ==
           LIBRDP_STATUS_OK);
    TCHECK(received_count == 74 && lost_count == 1);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_write_ack_of_acks_packet(&buffer, 4, 0x3030u) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_validate_packet(&udp2_packet) == LIBRDP_STATUS_OK);
    TCHECK(udp2_packet.has_ack_of_acks && udp2_packet.ack_of_acks_sequence_number == 0x3030u);
    TCHECK(!udp2_packet.has_ack && !udp2_packet.has_data && !udp2_packet.has_ack_vector);
    TCHECK(rdp_udp2_classify_packet(&udp2_packet, &udp2_kind) == LIBRDP_STATUS_OK);
    TCHECK(udp2_kind == RDP_UDP2_PACKET_KIND_ACK_OF_ACKS);
    TCHECK(rdp_udp2_write_ack_of_acks_packet(NULL, 4, 0x3030u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_udp2_wrap_packet(&buffer, NULL, 0, RDP_UDP2_PACKET_TYPE_DUMMY) == LIBRDP_STATUS_OK);
    TCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &udp2_prefix) == LIBRDP_STATUS_OK);
    TCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DUMMY &&
           udp2_prefix.short_packet_length == 0u &&
           unwrapped.length == 0u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&unwrapped);

    TCHECK(rdp_udp2_unwrap_packet(&unwrapped,
                                  wire_example,
                                  sizeof(wire_example),
                                  &udp2_prefix) == LIBRDP_STATUS_OK);
    TCHECK(udp2_prefix.packet_type == RDP_UDP2_PACKET_TYPE_DUMMY);
    TCHECK(unwrapped.length == sizeof(layout_example));
    TCHECK(memcmp(unwrapped.data, layout_example, sizeof(layout_example)) == 0);

    rdp_buffer_free(&unwrapped);
    rdp_buffer_free(&wire);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates multitransport protocol records, request IDs, security
 * fields, and malformed packet rejection.
 */
static int test_multitransport_protocol(void)
{
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
    const uint8_t autodetect[] = {0xaa, 0xbb};
    const uint8_t payload[] = {1, 2, 3, 4, 5};
    const uint8_t bad_subheader[] = {0x01u, RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST};
    rdp_buffer buffer;
    rdp_buffer subheader;
    rdp_multitransport_header header;
    rdp_multitransport_subheader parsed_subheader;
    rdp_multitransport_create_request request;
    rdp_multitransport_create_response response;
    rdp_multitransport_data tunnel_data;
    uint16_t subheader_count = 0;
    size_t i = 0;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&subheader);
    for (i = 0; i < sizeof(cookie); i++)
        cookie[i] = (uint8_t)i;

    TCHECK(rdp_multitransport_write_create_request(&buffer, 7, cookie) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    TCHECK(header.action == RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST);
    TCHECK(rdp_multitransport_parse_create_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    TCHECK(request.request_id == 7 && memcmp(request.security_cookie, cookie, sizeof(cookie)) == 0);
    {
        rdp_multitransport_create_request request_before = request;

        buffer.data[8] = 1;
        TCHECK(rdp_multitransport_parse_create_request(buffer.data, buffer.length, &request) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&request, &request_before, sizeof(request)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_multitransport_write_create_response(&buffer, 0) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_create_response(buffer.data, buffer.length, &response) ==
           LIBRDP_STATUS_OK);
    TCHECK(response.hresult == 0);
    {
        rdp_multitransport_create_response response_before = response;

        buffer.data[1] = 3u;
        TCHECK(rdp_multitransport_parse_create_response(buffer.data, buffer.length, &response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&response, &response_before, sizeof(response)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    TCHECK(rdp_multitransport_write_subheader(&subheader,
                                              RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST,
                                              autodetect,
                                              sizeof(autodetect)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_write_subheader(&subheader,
                                              RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_RESPONSE,
                                              autodetect,
                                              sizeof(autodetect)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_subheader(subheader.data, subheader.length, &parsed_subheader) ==
           LIBRDP_STATUS_OK);
    TCHECK(parsed_subheader.length == sizeof(autodetect) + 2u);
    TCHECK(parsed_subheader.data_len == 2);
    TCHECK(memcmp(parsed_subheader.data, autodetect, sizeof(autodetect)) == 0);
    {
        rdp_multitransport_subheader subheader_before = parsed_subheader;
        uint16_t count_before = subheader_count;

        subheader.data[1] = 0xffu;
        TCHECK(rdp_multitransport_parse_subheader(subheader.data,
                                                  subheader.length,
                                                  &parsed_subheader) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&parsed_subheader, &subheader_before, sizeof(parsed_subheader)) == 0);
        TCHECK(rdp_multitransport_count_subheaders(subheader.data,
                                                   subheader.length,
                                                   &subheader_count) == LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(subheader_count == count_before);
        subheader.data[1] = RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST;
    }
    TCHECK(rdp_multitransport_count_subheaders(subheader.data,
                                               subheader.length,
                                               &subheader_count) == LIBRDP_STATUS_OK);
    TCHECK(subheader_count == 2u);
    TCHECK(rdp_multitransport_write_subheader(&buffer, 0xffu, autodetect, sizeof(autodetect)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_multitransport_write_data(&buffer,
                                         bad_subheader,
                                         sizeof(bad_subheader),
                                         payload,
                                         sizeof(payload)) == LIBRDP_STATUS_INVALID_ARGUMENT);

    TCHECK(rdp_multitransport_write_data(&buffer,
                                         subheader.data,
                                         subheader.length,
                                         payload,
                                         sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) == LIBRDP_STATUS_OK);
    TCHECK(tunnel_data.header.header_length == RDP_MULTITRANSPORT_HEADER_LENGTH + subheader.length);
    TCHECK(tunnel_data.data_len == sizeof(payload));
    TCHECK(memcmp(tunnel_data.data, payload, sizeof(payload)) == 0);
    buffer.data[0] = 0xf2u;
    TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = RDP_MULTITRANSPORT_ACTION_DATA;
    buffer.data[RDP_MULTITRANSPORT_HEADER_LENGTH + parsed_subheader.length + 1u] = 0xffu;
    memset(&header, 0x5a, sizeof(header));
    header.action = 0x77u;
    {
        rdp_multitransport_header header_before = header;

        TCHECK(rdp_multitransport_parse_header(buffer.data, buffer.length, &header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    }
    memset(&tunnel_data, 0x5a, sizeof(tunnel_data));
    tunnel_data.header.action = 0x77u;
    {
        rdp_multitransport_data tunnel_before = tunnel_data;

        TCHECK(rdp_multitransport_parse_data(buffer.data, buffer.length, &tunnel_data) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        TCHECK(memcmp(&tunnel_data, &tunnel_before, sizeof(tunnel_data)) == 0);
    }

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&subheader);
    return 0;
}

/*
 * Coverage: validates TCP/TLS transport setup, local socket I/O, timeout
 * handling, EOF behavior, and transport-owned resource lifetime.
 */
int test_transport(void)
{
    int pair[2] = {-1, -1};
    int tcp_fd = -1;
    EVP_PKEY* ca_key = NULL;
    EVP_PKEY* server_key = NULL;
    EVP_PKEY* self_signed_key = NULL;
    EVP_PKEY* rotated_key = NULL;
    EVP_PKEY* wrong_host_key = NULL;
    EVP_PKEY* expired_key = NULL;
    EVP_PKEY* not_yet_valid_key = NULL;
    X509* ca_cert = NULL;
    X509* server_cert = NULL;
    X509* self_signed_cert = NULL;
    X509* rotated_cert = NULL;
    X509* wrong_host_cert = NULL;
    X509* expired_cert = NULL;
    X509* not_yet_valid_cert = NULL;
    test_tls_callback_state tofu_accept;
    test_tls_callback_state tofu_reject;
    test_tls_tofu_store tofu_store;
    test_tls_trace_case trace_case;
    char self_signed_fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
    char wrong_fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
    char trace_output[4096];
    rdp_transport transport;
    char data[8];
    size_t got = 0;
    int nonblocking = 0;
    rdp_buffer packet;
    rdp_buffer wire;
    rdp_buffer tls_public_key;
    const uint8_t payload[] = {0xaa, 0xbb, 0xcc};
    unsigned char* expected_public_key = NULL;
    unsigned char* expected_public_key_ptr = NULL;
    int expected_public_key_len = 0;

    rdp_transport_init(&transport);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&wire);
    rdp_buffer_init(&tls_public_key);

    TCHECK(test_udp_transport_protocols() == 0);
    TCHECK(test_multitransport_protocol() == 0);
    TCHECK(test_rdg_packet_parser() == 0);
    TCHECK(test_rdg_bounded_queues() == 0);
    TCHECK(test_gateway_connect_transport() == 0);

    TCHECK(rdp_socket_close(-1) == 0);
    TCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    TCHECK(rdp_socket_set_nonblocking(pair[0], 1) == 0);
    TCHECK(rdp_socket_get_nonblocking(pair[0], &nonblocking) == 0);
    TCHECK(nonblocking == 1);
    TCHECK(rdp_socket_set_nonblocking(pair[0], 0) == 0);
    TCHECK(rdp_socket_get_nonblocking(pair[0], &nonblocking) == 0);
    TCHECK(nonblocking == 0);
    TCHECK(rdp_socket_get_nonblocking(pair[0], NULL) != 0);
    TCHECK(rdp_socket_close(pair[0]) == 0);
    TCHECK(rdp_socket_close(pair[1]) == 0);
    pair[0] = -1;
    pair[1] = -1;

    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    TCHECK(tcp_fd >= 0);
    TCHECK(rdp_socket_set_nodelay(tcp_fd) == 0);
    TCHECK(rdp_socket_close(tcp_fd) == 0);
    tcp_fd = -1;

    TCHECK(rdp_tcp_connect(NULL, 3389, 1, &tcp_fd) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_tcp_connect("127.0.0.1", 0, 1, &tcp_fd) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_tcp_connect("127.0.0.1", 3389, -1, &tcp_fd) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_tcp_connect("127.0.0.1", 3389, 1, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_transport_connect(NULL, "127.0.0.1", 3389, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_transport_connect(&transport, NULL, 3389, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(transport.fd < 0);
    TCHECK(rdp_transport_write(NULL, "x", 1, &got) == LIBRDP_STATUS_INVALID_ARGUMENT);
    TCHECK(rdp_transport_write(&transport, "x", 1, &got) == LIBRDP_STATUS_INVALID_ARGUMENT);

    TCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    rdp_transport_attach_fd(&transport, pair[0], 1);

    TCHECK(rdp_transport_wait(&transport, 0, POLLIN, NULL) == LIBRDP_STATUS_TIMEOUT);
    TCHECK(write(pair[1], "abc", 3) == 3);
    TCHECK(rdp_transport_wait(&transport, 1000, POLLIN, NULL) == LIBRDP_STATUS_OK);
    TCHECK(rdp_transport_peek(&transport, data, 2, &got) == LIBRDP_STATUS_OK);
    TCHECK(got == 2 && memcmp(data, "ab", 2) == 0);
    TCHECK(rdp_transport_read_exact(&transport, data, 3) == LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "abc", 3) == 0);
    TCHECK(rdp_socket_set_nonblocking(transport.fd, 1) == 0);
    memset(data, 0xa5, sizeof(data));
    TCHECK(write(pair[1], "de", 2) == 2);
    TCHECK(rdp_transport_read_exact(&transport, data, 4) ==
           LIBRDP_STATUS_AGAIN);
    TCHECK(data[0] == (char)0xa5 && data[1] == (char)0xa5 &&
           data[2] == (char)0xa5 && data[3] == (char)0xa5);
    TCHECK(rdp_transport_peek(&transport, data, 4, &got) ==
           LIBRDP_STATUS_OK);
    TCHECK(got == 2 && memcmp(data, "de", 2) == 0);
    TCHECK(write(pair[1], "fg", 2) == 2);
    TCHECK(rdp_transport_read_exact(&transport, data, 4) ==
           LIBRDP_STATUS_OK);
    TCHECK(memcmp(data, "defg", 4) == 0);
    TCHECK(rdp_tpkt_write(&wire,
                          payload,
                          sizeof(payload)) ==
           LIBRDP_STATUS_OK);
    TCHECK(write(pair[1], wire.data, 5u) == 5);
    TCHECK(rdp_transport_read_tpkt(&transport, &packet) ==
           LIBRDP_STATUS_AGAIN);
    TCHECK(packet.length == 0u);
    TCHECK(write(pair[1],
                 wire.data + 5u,
                 wire.length - 5u) ==
           (ssize_t)(wire.length - 5u));
    TCHECK(rdp_transport_read_tpkt(&transport, &packet) ==
           LIBRDP_STATUS_OK);
    TCHECK(packet.length == wire.length);
    TCHECK(memcmp(packet.data,
                  wire.data,
                  wire.length) == 0);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    rdp_buffer_free(&wire);
    rdp_buffer_init(&wire);
    TCHECK(rdp_socket_set_nonblocking(transport.fd, 0) == 0);
    TCHECK(rdp_transport_read_exact_timeout(&transport, data, 1, 25) == LIBRDP_STATUS_TIMEOUT);
    TCHECK(rdp_socket_get_nonblocking(transport.fd, &nonblocking) == 0);
    TCHECK(nonblocking == 0);

    TCHECK(rdp_transport_write(&transport, "xy", 2, &got) == LIBRDP_STATUS_OK);
    TCHECK(got == 2);
    TCHECK(read(pair[1], data, sizeof(data)) == 2);
    TCHECK(memcmp(data, "xy", 2) == 0);

    TCHECK(rdp_tpkt_write(&wire, payload, sizeof(payload)) == LIBRDP_STATUS_OK);
    TCHECK(write(pair[1], wire.data, wire.length) == (ssize_t)wire.length);
    TCHECK(rdp_transport_read_tpkt_timeout(&transport, &packet, 1000) == LIBRDP_STATUS_OK);
    TCHECK(packet.length == wire.length);
    TCHECK(memcmp(packet.data, wire.data, wire.length) == 0);

    shutdown(pair[1], SHUT_RDWR);
    close(pair[1]);
    pair[1] = -1;
    TCHECK(rdp_transport_read(&transport, data, 1, &got) == LIBRDP_STATUS_CLOSED);

    rdp_buffer_free(&wire);
    rdp_buffer_free(&packet);
    rdp_transport_close(&transport);

    rdp_transport_init(&transport);
    TCHECK(test_transport_timeout_boundaries() == 0);
    TCHECK(make_test_ca_certificate(&ca_key, &ca_cert));
    TCHECK(make_test_server_certificate(&server_key,
                                        &server_cert,
                                        ca_key,
                                        ca_cert,
                                        2,
                                        "localhost",
                                        "DNS:localhost",
                                        0,
                                        3600));
    TCHECK(make_test_server_certificate(&wrong_host_key,
                                        &wrong_host_cert,
                                        ca_key,
                                        ca_cert,
                                        3,
                                        "wronghost",
                                        "DNS:wronghost",
                                        0,
                                        3600));
    TCHECK(make_test_server_certificate(&expired_key,
                                        &expired_cert,
                                        ca_key,
                                        ca_cert,
                                        4,
                                        "localhost",
                                        "DNS:localhost",
                                        -7200,
                                        -3600));
    TCHECK(make_test_server_certificate(&not_yet_valid_key,
                                        &not_yet_valid_cert,
                                        ca_key,
                                        ca_cert,
                                        5,
                                        "localhost",
                                        "DNS:localhost",
                                        3600,
                                        7200));
    TCHECK(make_test_self_signed_server_certificate(&self_signed_key, &self_signed_cert));
    TCHECK(make_test_self_signed_server_certificate(&rotated_key, &rotated_cert));
    TCHECK(test_certificate_fingerprint(self_signed_cert, self_signed_fingerprint));
    memcpy(wrong_fingerprint, self_signed_fingerprint, sizeof(wrong_fingerprint));
    wrong_fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH - 1u] =
        wrong_fingerprint[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH - 1u] == '0' ? '1' : '0';
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_STRICT,
                              1,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    TCHECK(run_tls_client_case(wrong_host_key,
                              wrong_host_cert,
                              ca_cert,
                              "localhost",
                              LIBRDP_TLS_POLICY_STRICT,
                              0,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH,
                              0,
                              NULL));
    TCHECK(run_tls_client_case(expired_key,
                              expired_cert,
                              ca_cert,
                              "localhost",
                              LIBRDP_TLS_POLICY_STRICT,
                              0,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    TCHECK(run_tls_client_case(not_yet_valid_key,
                              not_yet_valid_cert,
                              ca_cert,
                              "localhost",
                              LIBRDP_TLS_POLICY_STRICT,
                              0,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    TCHECK(run_tls_client_case(server_key,
                              server_cert,
                              ca_cert,
                              "localhost",
                              LIBRDP_TLS_POLICY_STRICT,
                              0,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_OK,
                              1,
                              &tls_public_key));
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_PINNED_FINGERPRINT,
                              0,
                              self_signed_fingerprint,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_OK,
                              1,
                              NULL));
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_PINNED_FINGERPRINT,
                              0,
                              wrong_fingerprint,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    memset(&trace_case, 0, sizeof(trace_case));
    memset(trace_output, 0, sizeof(trace_output));
    trace_case.key = self_signed_key;
    trace_case.cert = self_signed_cert;
    trace_case.wrong_fingerprint = wrong_fingerprint;
    TCHECK(capture_stderr_fn(run_tls_wrong_pin_trace, &trace_case, trace_output, sizeof(trace_output)));
    TCHECK(trace_case.ok);
    TCHECK(strstr(trace_output, "transport.tls.connect.start") != NULL);
    TCHECK(strstr(trace_output, "tls_certificate_rejected") != NULL);
    TCHECK(strstr(trace_output, self_signed_fingerprint) == NULL);
    TCHECK(strstr(trace_output, wrong_fingerprint) == NULL);
    TCHECK(strstr(trace_output, "BEGIN CERTIFICATE") == NULL);
    memset(&tofu_accept, 0, sizeof(tofu_accept));
    tofu_accept.accept = 1;
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_TOFU,
                              1,
                              NULL,
                              test_tls_certificate_callback,
                              &tofu_accept,
                              LIBRDP_STATUS_OK,
                              1,
                              NULL));
    TCHECK(tofu_accept.calls == 1);
    TCHECK(strcmp(tofu_accept.fingerprint, self_signed_fingerprint) == 0);
    memset(&tofu_reject, 0, sizeof(tofu_reject));
    tofu_reject.reject = 1;
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_TOFU,
                              1,
                              NULL,
                              test_tls_certificate_callback,
                              &tofu_reject,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    TCHECK(tofu_reject.calls == 1);
    memset(&tofu_store, 0, sizeof(tofu_store));
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_TOFU,
                              1,
                              NULL,
                              test_tls_tofu_store_callback,
                              &tofu_store,
                              LIBRDP_STATUS_OK,
                              1,
                              NULL));
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_TOFU,
                              1,
                              NULL,
                              test_tls_tofu_store_callback,
                              &tofu_store,
                              LIBRDP_STATUS_OK,
                              1,
                              NULL));
    TCHECK(run_tls_client_case(rotated_key,
                              rotated_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_TOFU,
                              1,
                              NULL,
                              test_tls_tofu_store_callback,
                              &tofu_store,
                              LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
                              0,
                              NULL));
    TCHECK(tofu_store.calls == 3);
    TCHECK(tofu_store.first_use == 1 && tofu_store.repeat == 1 && tofu_store.changed == 1);
    TCHECK(strcmp(tofu_store.fingerprint, self_signed_fingerprint) == 0);
    TCHECK(run_tls_client_case(self_signed_key,
                              self_signed_cert,
                              NULL,
                              "localhost",
                              LIBRDP_TLS_POLICY_INSECURE_LAB,
                              0,
                              NULL,
                              NULL,
                              NULL,
                              LIBRDP_STATUS_OK,
                              1,
                              NULL));
    memset(&trace_case, 0, sizeof(trace_case));
    memset(trace_output, 0, sizeof(trace_output));
    trace_case.key = self_signed_key;
    trace_case.cert = self_signed_cert;
    TCHECK(capture_stderr_fn(run_tls_insecure_trace, &trace_case, trace_output, sizeof(trace_output)));
    TCHECK(trace_case.ok);
    TCHECK(strstr(trace_output, "transport.tls.insecure_lab.warning") != NULL);
    TCHECK(strstr(trace_output, self_signed_fingerprint) == NULL);
    TCHECK(strstr(trace_output, "BEGIN CERTIFICATE") == NULL);
    expected_public_key_len = i2d_PublicKey(server_key, NULL);
    TCHECK(expected_public_key_len > 0);
    expected_public_key = (unsigned char*)malloc((size_t)expected_public_key_len);
    TCHECK(expected_public_key != NULL);
    expected_public_key_ptr = expected_public_key;
    TCHECK(i2d_PublicKey(server_key, &expected_public_key_ptr) == expected_public_key_len);
    TCHECK(tls_public_key.length == (size_t)expected_public_key_len);
    TCHECK(memcmp(tls_public_key.data, expected_public_key, tls_public_key.length) == 0);

    X509_free(expired_cert);
    X509_free(not_yet_valid_cert);
    X509_free(wrong_host_cert);
    X509_free(rotated_cert);
    X509_free(self_signed_cert);
    X509_free(server_cert);
    X509_free(ca_cert);
    EVP_PKEY_free(expired_key);
    EVP_PKEY_free(not_yet_valid_key);
    EVP_PKEY_free(wrong_host_key);
    EVP_PKEY_free(rotated_key);
    EVP_PKEY_free(self_signed_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(ca_key);
    free(expected_public_key);
    rdp_buffer_free(&tls_public_key);
    return 0;
}

#ifdef LIBRDP_TEST_TRANSPORT_MAIN
int main(int argc, char** argv)
{
    if (argc == 2)
    {
        if (strcmp(argv[1], "timeouts") == 0)
            return test_transport_timeout_boundaries();
        if (strcmp(argv[1], "smoke-gateway") != 0)
            return 2;
#ifdef RDP_HAVE_CURL
        return test_gateway_connect_transport();
#else
        return 77;
#endif
    }
    if (argc != 1)
        return 2;
    return test_transport();
}
#endif
