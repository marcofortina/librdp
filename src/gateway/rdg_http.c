/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Microsoft RD Gateway HTTP runtime.
 * Invariants: the OUT request is started before the IN request, all incoming
 * HTTP entity bytes are packet-length validated, and RDP payload bytes are
 * released to the core only from valid data packets.
 * Ownership: libcurl handles, queued packets, credentials, and wake pipes are
 * owned by the RDG context until rdp_transport_close() calls the backend close
 * operation.
 * Threading: libcurl progress is isolated in one worker thread; public
 * transport entry points use a mutex and condition variable around queues.
 * Trust boundary: gateway URLs and credentials are local configuration, while
 * gateway HTTP responses and RDG packets are remote input and remain untrusted
 * until bounds and state checks pass.
 */

#include "gateway/rdg_http.h"

#include "common/buffer.h"
#include "common/charset.h"
#include "common/trace.h"
#include "transport/transport.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#ifdef RDP_HAVE_CURL
#include <curl/curl.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RDP_RDG_URL_MAX 4096u
#define RDP_RDG_TARGET_MAX 512u
#define RDP_RDG_PACKET_HEADER_LEN 8u
#define RDP_RDG_MAX_PACKET 1048576u
#define RDP_RDG_MAX_DATA 65535u
#define RDP_RDG_DEFAULT_TIMEOUT_MS 15000u

#define RDP_RDG_PKT_HANDSHAKE_REQUEST 0x0001u
#define RDP_RDG_PKT_HANDSHAKE_RESPONSE 0x0002u
#define RDP_RDG_PKT_EXTENDED_AUTH_MSG 0x0003u
#define RDP_RDG_PKT_TUNNEL_CREATE 0x0004u
#define RDP_RDG_PKT_TUNNEL_RESPONSE 0x0005u
#define RDP_RDG_PKT_TUNNEL_AUTH 0x0006u
#define RDP_RDG_PKT_TUNNEL_AUTH_RESPONSE 0x0007u
#define RDP_RDG_PKT_CHANNEL_CREATE 0x0008u
#define RDP_RDG_PKT_CHANNEL_RESPONSE 0x0009u
#define RDP_RDG_PKT_DATA 0x000au
#define RDP_RDG_PKT_SERVICE_MESSAGE 0x000bu
#define RDP_RDG_PKT_REAUTH_MESSAGE 0x000cu
#define RDP_RDG_PKT_KEEPALIVE 0x000du
#define RDP_RDG_PKT_CLOSE_CHANNEL 0x0010u
#define RDP_RDG_PKT_CLOSE_CHANNEL_RESPONSE 0x0011u

#define RDP_RDG_TUNNEL_RESPONSE_FIELD_TUNNEL_ID 0x0001u
#define RDP_RDG_TUNNEL_RESPONSE_FIELD_CAPS 0x0002u
#define RDP_RDG_TUNNEL_RESPONSE_FIELD_SOH_REQ 0x0004u
#define RDP_RDG_TUNNEL_RESPONSE_FIELD_CONSENT_MSG 0x0010u
#define RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS 0x0001u
#define RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT 0x0002u
#define RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE 0x0004u
#define RDP_RDG_CHANNEL_RESPONSE_FIELD_CHANNELID 0x0001u
#define RDP_RDG_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE 0x0002u
#define RDP_RDG_CHANNEL_RESPONSE_FIELD_UDPPORT 0x0004u

typedef struct rdp_rdg_queue_node
{
    uint8_t* data;
    size_t length;
    size_t offset;
    struct rdp_rdg_queue_node* next;
} rdp_rdg_queue_node;

typedef struct rdp_rdg_control_packet
{
    uint16_t type;
    rdp_buffer payload;
    struct rdp_rdg_control_packet* next;
} rdp_rdg_control_packet;

typedef struct rdp_rdg_http_context
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_t worker;
    int worker_started;
    int closing;
    int active;
    int in_paused;
    int control_pipe[2];
    int event_pipe[2];
    librdp_status error;
    rdp_buffer incoming;
    rdp_rdg_queue_node* out_head;
    rdp_rdg_queue_node* out_tail;
    rdp_rdg_queue_node* data_head;
    rdp_rdg_queue_node* data_tail;
    rdp_rdg_control_packet* packet_head;
    rdp_rdg_control_packet* packet_tail;
    char* url;
    char* username;
    char* password;
    char* connection_id;
    char* target_host;
    uint16_t target_port;
    uint32_t timeout_ms;
    uint32_t tunnel_id;
    uint32_t channel_id;
#ifdef RDP_HAVE_CURL
    CURLM* multi;
    CURL* in_easy;
    CURL* out_easy;
    struct curl_slist* in_headers;
    struct curl_slist* out_headers;
#endif
} rdp_rdg_http_context;

static uint16_t rdp_rdg_read_u16_le(const uint8_t* data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t rdp_rdg_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

librdp_status rdp_rdg_parse_packet(const uint8_t* data,
                                   size_t length,
                                   rdp_rdg_packet_view* packet)
{
    uint32_t packet_len = 0;

    if ((!data && length > 0) || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(packet, 0, sizeof(*packet));
    if (length < RDP_RDG_PACKET_HEADER_LEN)
        return LIBRDP_STATUS_AGAIN;
    packet_len = rdp_rdg_read_u32_le(data + 4u);
    if (packet_len < RDP_RDG_PACKET_HEADER_LEN || packet_len > RDP_RDG_MAX_PACKET)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length < packet_len)
        return LIBRDP_STATUS_AGAIN;

    packet->type = rdp_rdg_read_u16_le(data);
    packet->payload = data + RDP_RDG_PACKET_HEADER_LEN;
    packet->payload_len = (size_t)packet_len - RDP_RDG_PACKET_HEADER_LEN;
    packet->packet_len = packet_len;
    if (packet->type == RDP_RDG_PKT_DATA)
    {
        uint16_t data_len = 0;

        if (packet->payload_len < 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        data_len = rdp_rdg_read_u16_le(packet->payload);
        if ((size_t)data_len > packet->payload_len - 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        packet->data = packet->payload + 2u;
        packet->data_len = data_len;
    }
    return LIBRDP_STATUS_OK;
}

static int rdp_rdg_valid_text(const char* text, size_t max_len)
{
    size_t len = 0;

    if (!text || text[0] == '\0')
        return 0;
    len = strlen(text);
    return len <= max_len;
}

static int rdp_rdg_loopback_http_url(const char* url)
{
    if (!url || strncmp(url, "http://", 7u) != 0)
        return 0;
    return strncmp(url + 7u, "127.", 4u) == 0 || strncmp(url + 7u, "localhost", 9u) == 0 ||
           strncmp(url + 7u, "[::1]", 5u) == 0;
}

/*
 * Accept plain HTTP only for deterministic loopback tests; configured gateway
 * URLs otherwise must use HTTPS before credentials or RDP payloads are sent.
 */
static int rdp_rdg_valid_url(const char* url)
{
    return rdp_rdg_valid_text(url, RDP_RDG_URL_MAX) &&
           (strncmp(url, "https://", 8u) == 0 || rdp_rdg_loopback_http_url(url));
}

static char* rdp_rdg_strdup(const char* text)
{
    size_t len = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    len = strlen(text);
    copy = (char*)malloc(len + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, len + 1u);
    return copy;
}

static void rdp_rdg_secure_free(char* text)
{
    if (!text)
        return;
    OPENSSL_cleanse(text, strlen(text));
    free(text);
}

static int rdp_rdg_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int rdp_rdg_make_pipe(int fds[2])
{
    fds[0] = -1;
    fds[1] = -1;
    if (pipe(fds) != 0)
        return 0;
    if (!rdp_rdg_set_nonblocking(fds[0]) || !rdp_rdg_set_nonblocking(fds[1]))
    {
        close(fds[0]);
        close(fds[1]);
        fds[0] = -1;
        fds[1] = -1;
        return 0;
    }
    return 1;
}

/*
 * Wake the worker or transport waiter without caring about coalesced bytes:
 * one readable byte is enough to force the receiver to re-check shared state.
 */
static void rdp_rdg_signal_pipe(int fd)
{
    const uint8_t byte = 1u;
    ssize_t rc = 0;

    if (fd < 0)
        return;
    do
    {
        rc = write(fd, &byte, sizeof(byte));
    } while (rc < 0 && errno == EINTR);
}

/*
 * Clear all pending wake bytes after poll() reports readiness. The pipe is
 * non-blocking, so EOF/EAGAIN both mean the consumer has caught up.
 */
static void rdp_rdg_drain_pipe(int fd)
{
    uint8_t bytes[64];

    if (fd < 0)
        return;
    for (;;)
    {
        ssize_t rc = read(fd, bytes, sizeof(bytes));

        if (rc > 0)
            continue;
        if (rc < 0 && errno == EINTR)
            continue;
        break;
    }
}

static void rdp_rdg_queue_free(rdp_rdg_queue_node* node)
{
    while (node)
    {
        rdp_rdg_queue_node* next = node->next;

        free(node->data);
        free(node);
        node = next;
    }
}

static void rdp_rdg_control_free(rdp_rdg_control_packet* packet)
{
    while (packet)
    {
        rdp_rdg_control_packet* next = packet->next;

        rdp_buffer_free(&packet->payload);
        free(packet);
        packet = next;
    }
}

static librdp_status rdp_rdg_queue_copy(rdp_rdg_queue_node** head,
                                        rdp_rdg_queue_node** tail,
                                        const void* data,
                                        size_t length)
{
    rdp_rdg_queue_node* node = NULL;

    if (!head || !tail || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    node = (rdp_rdg_queue_node*)calloc(1u, sizeof(*node));
    if (!node)
        return LIBRDP_STATUS_NO_MEMORY;
    if (length > 0)
    {
        node->data = (uint8_t*)malloc(length);
        if (!node->data)
        {
            free(node);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        memcpy(node->data, data, length);
    }
    node->length = length;
    if (*tail)
        (*tail)->next = node;
    else
        *head = node;
    *tail = node;
    return LIBRDP_STATUS_OK;
}

static int rdp_rdg_queue_has_bytes(const rdp_rdg_queue_node* node)
{
    return node && node->offset < node->length;
}

static size_t rdp_rdg_queue_peek_copy(const rdp_rdg_queue_node* node, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t copied = 0;

    while (node && copied < length)
    {
        size_t available = node->length - node->offset;
        size_t chunk = length - copied;

        if (chunk > available)
            chunk = available;
        if (chunk > 0)
            memcpy(out + copied, node->data + node->offset, chunk);
        copied += chunk;
        node = node->next;
    }
    return copied;
}

/*
 * Copy queued RDP bytes to the caller and retire fully consumed nodes while
 * preserving the remaining head node offset for short reads.
 */
static size_t rdp_rdg_queue_read_copy(rdp_rdg_queue_node** head,
                                      rdp_rdg_queue_node** tail,
                                      void* data,
                                      size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t copied = 0;

    while (*head && copied < length)
    {
        rdp_rdg_queue_node* node = *head;
        size_t available = node->length - node->offset;
        size_t chunk = length - copied;

        if (chunk > available)
            chunk = available;
        if (chunk > 0)
            memcpy(out + copied, node->data + node->offset, chunk);
        copied += chunk;
        node->offset += chunk;
        if (node->offset < node->length)
            break;
        *head = node->next;
        if (*tail == node)
            *tail = NULL;
        free(node->data);
        free(node);
    }
    return copied;
}

/*
 * Bound synchronous startup waits with the gateway timeout. CLOCK_REALTIME is
 * used because pthread_cond_timedwait() requires an absolute time on POSIX.
 */
static int rdp_rdg_timed_wait_locked(rdp_rdg_http_context* context)
{
    struct timespec deadline;
    uint32_t timeout_ms = context->timeout_ms ? context->timeout_ms : RDP_RDG_DEFAULT_TIMEOUT_MS;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
        return pthread_cond_wait(&context->cond, &context->mutex);
    deadline.tv_sec += (time_t)(timeout_ms / 1000u);
    deadline.tv_nsec += (long)((timeout_ms % 1000u) * 1000000u);
    if (deadline.tv_nsec >= 1000000000L)
    {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    return pthread_cond_timedwait(&context->cond, &context->mutex, &deadline);
}

/*
 * Serialize one RDG packet header and optional body. The caller chooses the
 * control or data packet type; this helper owns only framing and size limits.
 */
static librdp_status rdp_rdg_make_packet(uint16_t type, const rdp_buffer* body, rdp_buffer* packet)
{
    uint32_t packet_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!packet || (body && body->length > RDP_RDG_MAX_PACKET - RDP_RDG_PACKET_HEADER_LEN))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(packet);
    packet_len = (uint32_t)(RDP_RDG_PACKET_HEADER_LEN + (body ? body->length : 0u));
    status = rdp_buffer_append_u16_le(packet, type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(packet, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(packet, packet_len);
    if (status == LIBRDP_STATUS_OK && body && body->length > 0)
        status = rdp_buffer_append(packet, body->data, body->length);
    if (status != LIBRDP_STATUS_OK)
        rdp_buffer_free(packet);
    return status;
}

static librdp_status rdp_rdg_queue_packet(rdp_rdg_http_context* context, uint16_t type, const rdp_buffer* body)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_rdg_make_packet(type, body, &packet);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pthread_mutex_lock(&context->mutex);
    if (context->closing || context->error != LIBRDP_STATUS_OK)
        status = context->error != LIBRDP_STATUS_OK ? context->error : LIBRDP_STATUS_CLOSED;
    else
    {
        status = rdp_rdg_queue_copy(&context->out_head, &context->out_tail, packet.data, packet.length);
        pthread_cond_broadcast(&context->cond);
        rdp_rdg_signal_pipe(context->control_pipe[1]);
    }
    pthread_mutex_unlock(&context->mutex);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_rdg_append_unicode_string(rdp_buffer* buffer, const char* text)
{
    rdp_buffer utf16;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&utf16);
    status = rdp_charset_utf8_to_utf16le_buffer(text, 1, &utf16);
    if (status == LIBRDP_STATUS_OK && utf16.length > UINT16_MAX)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, utf16.data, utf16.length);
    rdp_buffer_free(&utf16);
    return status;
}

static librdp_status rdp_rdg_build_handshake(rdp_buffer* body)
{
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(body);
    status = rdp_buffer_append_u8(body, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 0u);
    return status;
}

static librdp_status rdp_rdg_build_tunnel_create(rdp_buffer* body)
{
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(body);
    status = rdp_buffer_append_u32_le(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 0u);
    return status;
}

/*
 * Authenticate the tunnel with workstation identity only. User credentials are
 * handled by HTTP authentication, so this packet must not duplicate secrets.
 */
static librdp_status rdp_rdg_build_tunnel_auth(rdp_buffer* body)
{
    char host[256];
    rdp_buffer name;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(body);
    rdp_buffer_init(&name);
    if (gethostname(host, sizeof(host)) != 0)
        memcpy(host, "librdp", 7u);
    host[sizeof(host) - 1u] = '\0';
    status = rdp_charset_utf8_to_utf16le_buffer(host, 1, &name);
    if (status == LIBRDP_STATUS_OK && name.length > UINT16_MAX)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, (uint16_t)name.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(body, name.data, name.length);
    rdp_buffer_free(&name);
    return status;
}

static librdp_status rdp_rdg_build_channel_create(rdp_rdg_http_context* context, rdp_buffer* body)
{
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(body);
    status = rdp_buffer_append_u8(body, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(body, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, context->target_port);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(body, 3u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_append_unicode_string(body, context->target_host);
    return status;
}

static librdp_status rdp_rdg_build_data_packet(const uint8_t* data, size_t length, rdp_buffer* packet)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && length > 0) || length > RDP_RDG_MAX_DATA)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append_u16_le(&body, (uint16_t)length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&body, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_make_packet(RDP_RDG_PKT_DATA, &body, packet);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_rdg_build_close_packet(rdp_buffer* body)
{
    rdp_buffer_init(body);
    return rdp_buffer_append_u32_le(body, 0u);
}

#ifdef RDP_HAVE_CURL
static void rdp_rdg_set_error_locked(rdp_rdg_http_context* context, librdp_status status)
{
    if (!context || status == LIBRDP_STATUS_OK)
        return;
    if (context->error == LIBRDP_STATUS_OK)
        context->error = status;
    pthread_cond_broadcast(&context->cond);
    rdp_rdg_signal_pipe(context->event_pipe[1]);
    rdp_rdg_signal_pipe(context->control_pipe[1]);
}

static librdp_status rdp_rdg_control_enqueue_locked(rdp_rdg_http_context* context,
                                                    uint16_t type,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_rdg_control_packet* packet = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    packet = (rdp_rdg_control_packet*)calloc(1u, sizeof(*packet));
    if (!packet)
        return LIBRDP_STATUS_NO_MEMORY;
    packet->type = type;
    rdp_buffer_init(&packet->payload);
    status = rdp_buffer_append(&packet->payload, payload, payload_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&packet->payload);
        free(packet);
        return status;
    }
    if (context->packet_tail)
        context->packet_tail->next = packet;
    else
        context->packet_head = packet;
    context->packet_tail = packet;
    pthread_cond_broadcast(&context->cond);
    return LIBRDP_STATUS_OK;
}

/*
 * Split remote HTTP entity bytes into complete RDG packets under the context
 * lock. Data packets feed the transport queue; control packets feed startup
 * state and service handling.
 */
static librdp_status rdp_rdg_parse_incoming_locked(rdp_rdg_http_context* context)
{
    while (context->incoming.length >= RDP_RDG_PACKET_HEADER_LEN)
    {
        const uint8_t* data = context->incoming.data;
        rdp_rdg_packet_view packet;
        librdp_status status = LIBRDP_STATUS_OK;

        status = rdp_rdg_parse_packet(data, context->incoming.length, &packet);
        if (status == LIBRDP_STATUS_AGAIN)
            break;
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (packet.type == RDP_RDG_PKT_DATA)
        {
            status = rdp_rdg_queue_copy(&context->data_head,
                                        &context->data_tail,
                                        packet.data,
                                        packet.data_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_rdg_signal_pipe(context->event_pipe[1]);
        }
        else if (packet.type == RDP_RDG_PKT_KEEPALIVE)
        {
            rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "transport.gateway.rdg.keepalive",
                                  "length=%u",
                                  (unsigned)packet.packet_len);
        }
        else if (packet.type == RDP_RDG_PKT_SERVICE_MESSAGE)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT,
                            "transport.gateway.rdg.service_message",
                            "payload_len=%llu",
                            (unsigned long long)packet.payload_len);
        }
        else if (packet.type == RDP_RDG_PKT_REAUTH_MESSAGE)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT,
                            "transport.gateway.rdg.reauth",
                            "payload_len=%llu",
                            (unsigned long long)packet.payload_len);
            rdp_rdg_set_error_locked(context, LIBRDP_STATUS_UNSUPPORTED);
        }
        else if (packet.type == RDP_RDG_PKT_CLOSE_CHANNEL)
        {
            status = rdp_rdg_control_enqueue_locked(context,
                                                    packet.type,
                                                    packet.payload,
                                                    packet.payload_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_rdg_set_error_locked(context, LIBRDP_STATUS_CLOSED);
        }
        else
        {
            status = rdp_rdg_control_enqueue_locked(context,
                                                    packet.type,
                                                    packet.payload,
                                                    packet.payload_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        status = rdp_buffer_consume(&context->incoming, packet.packet_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}
#endif

static librdp_status rdp_rdg_receive_control(rdp_rdg_http_context* context,
                                             uint16_t expected_type,
                                             rdp_buffer* payload)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(payload);
    pthread_mutex_lock(&context->mutex);
    for (;;)
    {
        rdp_rdg_control_packet* packet = context->packet_head;

        if (packet)
        {
            if (packet->type != expected_type)
            {
                rdp_trace_event(RDP_TRACE_TRANSPORT,
                                "transport.gateway.rdg.unexpected_packet",
                                "expected=%u actual=%u",
                                (unsigned)expected_type,
                                (unsigned)packet->type);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            context->packet_head = packet->next;
            if (context->packet_tail == packet)
                context->packet_tail = NULL;
            status = rdp_buffer_append(payload, packet->payload.data, packet->payload.length);
            rdp_buffer_free(&packet->payload);
            free(packet);
            break;
        }
        if (context->error != LIBRDP_STATUS_OK)
        {
            status = context->error;
            break;
        }
        if (context->closing)
        {
            status = LIBRDP_STATUS_CLOSED;
            break;
        }
        if (rdp_rdg_timed_wait_locked(context) == ETIMEDOUT)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT,
                            "transport.gateway.rdg.timeout",
                            "expected=%u",
                            (unsigned)expected_type);
            status = LIBRDP_STATUS_TIMEOUT;
            break;
        }
    }
    pthread_mutex_unlock(&context->mutex);
    if (status != LIBRDP_STATUS_OK)
        rdp_buffer_free(payload);
    return status;
}

static librdp_status rdp_rdg_send_simple(rdp_rdg_http_context* context,
                                         uint16_t packet_type,
                                         librdp_status (*builder)(rdp_buffer*))
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    status = builder(&body);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_queue_packet(context, packet_type, &body);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_rdg_parse_unicode_skip(const uint8_t* payload, size_t payload_len, size_t* offset)
{
    uint16_t length = 0;

    if (!payload || !offset || *offset > payload_len || payload_len - *offset < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    length = rdp_rdg_read_u16_le(payload + *offset);
    *offset += 2u;
    if ((size_t)length > payload_len - *offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *offset += (size_t)length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_rdg_parse_blob_skip(const uint8_t* payload, size_t payload_len, size_t* offset)
{
    return rdp_rdg_parse_unicode_skip(payload, payload_len, offset);
}

static librdp_status rdp_rdg_expect_handshake(rdp_rdg_http_context* context)
{
    rdp_buffer payload;
    librdp_status status = rdp_rdg_receive_control(context, RDP_RDG_PKT_HANDSHAKE_RESPONSE, &payload);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (payload.length < 10u || rdp_rdg_read_u32_le(payload.data) != 0u || payload.data[4] != 1u)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_rdg_expect_tunnel_response(rdp_rdg_http_context* context)
{
    rdp_buffer payload;
    uint16_t fields = 0;
    size_t offset = 10u;
    librdp_status status = rdp_rdg_receive_control(context, RDP_RDG_PKT_TUNNEL_RESPONSE, &payload);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (payload.length < 10u || rdp_rdg_read_u32_le(payload.data + 2u) != 0u)
    {
        rdp_buffer_free(&payload);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    fields = rdp_rdg_read_u16_le(payload.data + 6u);
    if ((fields & RDP_RDG_TUNNEL_RESPONSE_FIELD_TUNNEL_ID) != 0u)
    {
        if (payload.length - offset < 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
        {
            context->tunnel_id = rdp_rdg_read_u32_le(payload.data + offset);
            offset += 4u;
        }
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_TUNNEL_RESPONSE_FIELD_CAPS) != 0u)
    {
        if (payload.length - offset < 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            offset += 4u;
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_TUNNEL_RESPONSE_FIELD_SOH_REQ) != 0u)
    {
        if (payload.length - offset < 16u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
        {
            offset += 16u;
            status = rdp_rdg_parse_unicode_skip(payload.data, payload.length, &offset);
        }
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_TUNNEL_RESPONSE_FIELD_CONSENT_MSG) != 0u)
        status = rdp_rdg_parse_unicode_skip(payload.data, payload.length, &offset);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_rdg_expect_auth_response(rdp_rdg_http_context* context)
{
    rdp_buffer payload;
    uint16_t fields = 0;
    size_t offset = 8u;
    librdp_status status = rdp_rdg_receive_control(context, RDP_RDG_PKT_TUNNEL_AUTH_RESPONSE, &payload);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (payload.length < 8u || rdp_rdg_read_u32_le(payload.data) != 0u)
    {
        rdp_buffer_free(&payload);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    fields = rdp_rdg_read_u16_le(payload.data + 4u);
    if ((fields & RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS) != 0u)
    {
        if (payload.length - offset < 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            offset += 4u;
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT) != 0u)
    {
        if (payload.length - offset < 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            offset += 4u;
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_TUNNEL_AUTH_RESPONSE_FIELD_SOH_RESPONSE) != 0u)
        status = rdp_rdg_parse_blob_skip(payload.data, payload.length, &offset);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_rdg_expect_channel_response(rdp_rdg_http_context* context)
{
    rdp_buffer payload;
    uint16_t fields = 0;
    size_t offset = 8u;
    librdp_status status = rdp_rdg_receive_control(context, RDP_RDG_PKT_CHANNEL_RESPONSE, &payload);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (payload.length < 8u || rdp_rdg_read_u32_le(payload.data) != 0u)
    {
        rdp_buffer_free(&payload);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    fields = rdp_rdg_read_u16_le(payload.data + 4u);
    if ((fields & RDP_RDG_CHANNEL_RESPONSE_FIELD_CHANNELID) != 0u)
    {
        if (payload.length - offset < 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
        {
            context->channel_id = rdp_rdg_read_u32_le(payload.data + offset);
            offset += 4u;
        }
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_CHANNEL_RESPONSE_FIELD_UDPPORT) != 0u)
    {
        if (payload.length - offset < 2u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            offset += 2u;
    }
    if (status == LIBRDP_STATUS_OK && (fields & RDP_RDG_CHANNEL_RESPONSE_FIELD_AUTHNCOOKIE) != 0u)
        status = rdp_rdg_parse_blob_skip(payload.data, payload.length, &offset);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_rdg_send_channel_create(rdp_rdg_http_context* context)
{
    rdp_buffer body;
    librdp_status status = rdp_rdg_build_channel_create(context, &body);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_queue_packet(context, RDP_RDG_PKT_CHANNEL_CREATE, &body);
    rdp_buffer_free(&body);
    return status;
}

#ifdef RDP_HAVE_CURL
static pthread_once_t rdp_rdg_curl_once = PTHREAD_ONCE_INIT;

static void rdp_rdg_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t rdp_rdg_out_write(char* ptr, size_t size, size_t nmemb, void* user_data)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    size_t length = size * nmemb;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!ptr && length > 0))
        return 0;
    pthread_mutex_lock(&context->mutex);
    status = rdp_buffer_append(&context->incoming, ptr, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_parse_incoming_locked(context);
    if (status != LIBRDP_STATUS_OK)
        rdp_rdg_set_error_locked(context, status);
    pthread_cond_broadcast(&context->cond);
    pthread_mutex_unlock(&context->mutex);
    return status == LIBRDP_STATUS_OK ? length : 0u;
}

static size_t rdp_rdg_in_write(char* ptr, size_t size, size_t nmemb, void* user_data)
{
    (void)ptr;
    (void)user_data;
    return size * nmemb;
}

static size_t rdp_rdg_in_read(char* ptr, size_t size, size_t nmemb, void* user_data)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    size_t length = size * nmemb;
    size_t copied = 0;

    if (!context || !ptr)
        return CURL_READFUNC_ABORT;
    if (length == 0)
        return 0;
    pthread_mutex_lock(&context->mutex);
    if (context->closing || context->error != LIBRDP_STATUS_OK)
    {
        pthread_mutex_unlock(&context->mutex);
        return CURL_READFUNC_ABORT;
    }
    if (!context->out_head)
    {
        context->in_paused = 1;
        pthread_mutex_unlock(&context->mutex);
        return CURL_READFUNC_PAUSE;
    }
    copied = rdp_rdg_queue_read_copy(&context->out_head, &context->out_tail, ptr, length);
    pthread_mutex_unlock(&context->mutex);
    return copied;
}

static void rdp_rdg_worker_set_error(rdp_rdg_http_context* context, librdp_status status)
{
    pthread_mutex_lock(&context->mutex);
    rdp_rdg_set_error_locked(context, status);
    pthread_mutex_unlock(&context->mutex);
}

static void rdp_rdg_worker_unpause_if_needed(rdp_rdg_http_context* context)
{
    int unpause = 0;

    pthread_mutex_lock(&context->mutex);
    unpause = context->in_paused && context->out_head && !context->closing;
    if (unpause)
        context->in_paused = 0;
    pthread_mutex_unlock(&context->mutex);
    if (unpause)
        (void)curl_easy_pause(context->in_easy, CURLPAUSE_CONT);
}

static void* rdp_rdg_worker_main(void* user_data)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    int running = 0;
    CURLMcode multi_code = CURLM_OK;

    (void)curl_multi_add_handle(context->multi, context->out_easy);
    (void)curl_multi_perform(context->multi, &running);
    (void)curl_multi_add_handle(context->multi, context->in_easy);
    while (!context->closing)
    {
        int messages = 0;
        CURLMsg* message = NULL;
        struct curl_waitfd waitfd;
        int events = 0;

        do
        {
            multi_code = curl_multi_perform(context->multi, &running);
        } while (multi_code == CURLM_CALL_MULTI_PERFORM);
        if (multi_code != CURLM_OK)
        {
            rdp_rdg_worker_set_error(context, LIBRDP_STATUS_IO_ERROR);
            break;
        }
        while ((message = curl_multi_info_read(context->multi, &messages)) != NULL)
        {
            if (message->msg == CURLMSG_DONE && message->data.result != CURLE_OK && !context->closing)
            {
                rdp_trace_event(RDP_TRACE_TRANSPORT,
                                "transport.gateway.rdg.curl_failed",
                                "curl_code=%u",
                                (unsigned)message->data.result);
                rdp_rdg_worker_set_error(context, LIBRDP_STATUS_IO_ERROR);
                break;
            }
        }
        memset(&waitfd, 0, sizeof(waitfd));
        waitfd.fd = context->control_pipe[0];
        waitfd.events = CURL_WAIT_POLLIN;
        waitfd.revents = 0;
        (void)curl_multi_wait(context->multi, &waitfd, 1u, 1000, &events);
        if ((waitfd.revents & CURL_WAIT_POLLIN) != 0)
            rdp_rdg_drain_pipe(context->control_pipe[0]);
        rdp_rdg_worker_unpause_if_needed(context);
        if (running == 0 && !context->closing)
        {
            rdp_rdg_worker_set_error(context, LIBRDP_STATUS_CLOSED);
            break;
        }
    }
    (void)curl_multi_remove_handle(context->multi, context->in_easy);
    (void)curl_multi_remove_handle(context->multi, context->out_easy);
    return NULL;
}

static int rdp_rdg_append_header(struct curl_slist** headers, const char* text)
{
    struct curl_slist* next = NULL;

    next = curl_slist_append(*headers, text);
    if (!next)
        return 0;
    *headers = next;
    return 1;
}

static int rdp_rdg_append_connection_header(struct curl_slist** headers, const char* connection_id)
{
    char header[96];
    int written = snprintf(header, sizeof(header), "RDG-Connection-Id: %s", connection_id);

    if (written <= 0 || (size_t)written >= sizeof(header))
        return 0;
    return rdp_rdg_append_header(headers, header);
}

/*
 * Configure one RDG HTTP request handle without starting network I/O. OUT and
 * IN handles share authentication policy and TLS verification but intentionally
 * require fresh HTTP/1.1 connections so libcurl cannot multiplex or serialize
 * the two protocol streams onto a single socket.
 */
static librdp_status rdp_rdg_configure_easy(rdp_rdg_http_context* context,
                                            CURL* easy,
                                            const char* method,
                                            struct curl_slist* headers,
                                            int upload)
{
    CURLcode code = CURLE_OK;

    if (!context || !easy || !method)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    code = curl_easy_setopt(easy, CURLOPT_URL, context->url);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_FRESH_CONNECT, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)context->timeout_ms);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANYSAFE);
#if LIBCURL_VERSION_NUM >= 0x075500
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    if (code == CURLE_OK && context->username)
        code = curl_easy_setopt(easy, CURLOPT_USERNAME, context->username);
    if (code == CURLE_OK && context->password)
        code = curl_easy_setopt(easy, CURLOPT_PASSWORD, context->password);
    if (code == CURLE_OK && upload)
        code = curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);
    if (code == CURLE_OK && upload)
        code = curl_easy_setopt(easy, CURLOPT_READFUNCTION, rdp_rdg_in_read);
    if (code == CURLE_OK && upload)
        code = curl_easy_setopt(easy, CURLOPT_READDATA, context);
    if (code == CURLE_OK && upload)
        code = curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE, (curl_off_t)-1);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, upload ? rdp_rdg_in_write : rdp_rdg_out_write);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_WRITEDATA, context);
    return code == CURLE_OK ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
}

static librdp_status rdp_rdg_prepare_curl(rdp_rdg_http_context* context)
{
    librdp_status status = LIBRDP_STATUS_OK;

    pthread_once(&rdp_rdg_curl_once, rdp_rdg_curl_init_once);
    context->multi = curl_multi_init();
    context->out_easy = curl_easy_init();
    context->in_easy = curl_easy_init();
    if (!context->multi || !context->out_easy || !context->in_easy)
        return LIBRDP_STATUS_NO_MEMORY;
    (void)curl_multi_setopt(context->multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 2L);
    (void)curl_multi_setopt(context->multi, CURLMOPT_MAX_HOST_CONNECTIONS, 2L);
#ifdef CURLMOPT_PIPELINING
    (void)curl_multi_setopt(context->multi, CURLMOPT_PIPELINING, 0L);
#endif
    if (!rdp_rdg_append_connection_header(&context->out_headers, context->connection_id) ||
        !rdp_rdg_append_header(&context->out_headers, "Accept: */*") ||
        !rdp_rdg_append_header(&context->out_headers, "Cache-Control: no-cache") ||
        !rdp_rdg_append_header(&context->out_headers, "Pragma: no-cache") ||
        !rdp_rdg_append_connection_header(&context->in_headers, context->connection_id) ||
        !rdp_rdg_append_header(&context->in_headers, "Accept: */*") ||
        !rdp_rdg_append_header(&context->in_headers, "Cache-Control: no-cache") ||
        !rdp_rdg_append_header(&context->in_headers, "Pragma: no-cache") ||
        !rdp_rdg_append_header(&context->in_headers, "Expect:"))
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_rdg_configure_easy(context, context->out_easy, "RDG_OUT_DATA", context->out_headers, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_configure_easy(context, context->in_easy, "RDG_IN_DATA", context->in_headers, 1);
    return status;
}
#endif

static librdp_status rdp_rdg_generate_connection_id(char** out)
{
    uint8_t bytes[16];
    char* text = NULL;
    int written = 0;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    text = (char*)malloc(39u);
    if (!text)
        return LIBRDP_STATUS_NO_MEMORY;
    written = snprintf(text,
                       39u,
                       "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                       bytes[0],
                       bytes[1],
                       bytes[2],
                       bytes[3],
                       bytes[4],
                       bytes[5],
                       bytes[6],
                       bytes[7],
                       bytes[8],
                       bytes[9],
                       bytes[10],
                       bytes[11],
                       bytes[12],
                       bytes[13],
                       bytes[14],
                       bytes[15]);
    if (written != 38)
    {
        free(text);
        return LIBRDP_STATUS_IO_ERROR;
    }
    *out = text;
    return LIBRDP_STATUS_OK;
}

static rdp_rdg_http_context* rdp_rdg_context_new(void)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)calloc(1u, sizeof(*context));

    if (!context)
        return NULL;
    context->control_pipe[0] = -1;
    context->control_pipe[1] = -1;
    context->event_pipe[0] = -1;
    context->event_pipe[1] = -1;
    context->error = LIBRDP_STATUS_OK;
    rdp_buffer_init(&context->incoming);
    if (pthread_mutex_init(&context->mutex, NULL) != 0 || pthread_cond_init(&context->cond, NULL) != 0 ||
        !rdp_rdg_make_pipe(context->control_pipe) || !rdp_rdg_make_pipe(context->event_pipe))
    {
        if (context->control_pipe[0] >= 0)
            close(context->control_pipe[0]);
        if (context->control_pipe[1] >= 0)
            close(context->control_pipe[1]);
        if (context->event_pipe[0] >= 0)
            close(context->event_pipe[0]);
        if (context->event_pipe[1] >= 0)
            close(context->event_pipe[1]);
        pthread_cond_destroy(&context->cond);
        pthread_mutex_destroy(&context->mutex);
        free(context);
        return NULL;
    }
    return context;
}

static void rdp_rdg_context_stop(rdp_rdg_http_context* context)
{
    if (!context)
        return;
    pthread_mutex_lock(&context->mutex);
    context->closing = 1;
    pthread_cond_broadcast(&context->cond);
    pthread_mutex_unlock(&context->mutex);
    rdp_rdg_signal_pipe(context->control_pipe[1]);
    if (context->worker_started)
    {
        (void)pthread_join(context->worker, NULL);
        context->worker_started = 0;
    }
}

static void rdp_rdg_context_free(rdp_rdg_http_context* context)
{
    if (!context)
        return;
    rdp_rdg_context_stop(context);
#ifdef RDP_HAVE_CURL
    if (context->in_easy)
        curl_easy_cleanup(context->in_easy);
    if (context->out_easy)
        curl_easy_cleanup(context->out_easy);
    if (context->multi)
        curl_multi_cleanup(context->multi);
    curl_slist_free_all(context->in_headers);
    curl_slist_free_all(context->out_headers);
#endif
    rdp_buffer_free(&context->incoming);
    rdp_rdg_queue_free(context->out_head);
    rdp_rdg_queue_free(context->data_head);
    rdp_rdg_control_free(context->packet_head);
    free(context->url);
    free(context->username);
    rdp_rdg_secure_free(context->password);
    free(context->connection_id);
    free(context->target_host);
    if (context->control_pipe[0] >= 0)
        close(context->control_pipe[0]);
    if (context->control_pipe[1] >= 0)
        close(context->control_pipe[1]);
    if (context->event_pipe[0] >= 0)
        close(context->event_pipe[0]);
    if (context->event_pipe[1] >= 0)
        close(context->event_pipe[1]);
    pthread_cond_destroy(&context->cond);
    pthread_mutex_destroy(&context->mutex);
    free(context);
}

static librdp_status rdp_rdg_copy_config(rdp_rdg_http_context* context,
                                         const rdp_gateway_connect_config* config)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !config || !rdp_rdg_valid_url(config->gateway_url) ||
        !rdp_rdg_valid_text(config->target_host, RDP_RDG_TARGET_MAX) || config->target_port == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context->url = rdp_rdg_strdup(config->gateway_url);
    context->target_host = rdp_rdg_strdup(config->target_host);
    context->target_port = config->target_port;
    context->timeout_ms = config->timeout_ms ? config->timeout_ms : RDP_RDG_DEFAULT_TIMEOUT_MS;
    if (!context->url || !context->target_host)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_gateway_user_name(config->domain, config->username, &context->username);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (config->password)
    {
        context->password = rdp_rdg_strdup(config->password);
        if (!context->password)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    return rdp_rdg_generate_connection_id(&context->connection_id);
}

static librdp_status rdp_rdg_start(rdp_rdg_http_context* context)
{
#ifndef RDP_HAVE_CURL
    (void)context;
    return LIBRDP_STATUS_UNSUPPORTED;
#else
    librdp_status status = rdp_rdg_prepare_curl(context);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (pthread_create(&context->worker, NULL, rdp_rdg_worker_main, context) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    context->worker_started = 1;
    return LIBRDP_STATUS_OK;
#endif
}

static librdp_status rdp_rdg_handshake(rdp_rdg_http_context* context)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_rdg_expect_handshake(context);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.gateway.rdg.handshake.done", "version=1.0");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_send_simple(context, RDP_RDG_PKT_TUNNEL_CREATE, rdp_rdg_build_tunnel_create);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_expect_tunnel_response(context);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.gateway.rdg.tunnel.done",
                        "tunnel_id=%u",
                        context->tunnel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_send_simple(context, RDP_RDG_PKT_TUNNEL_AUTH, rdp_rdg_build_tunnel_auth);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_expect_auth_response(context);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_TRANSPORT, "transport.gateway.rdg.auth.done", "status=ok");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_send_channel_create(context);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_expect_channel_response(context);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.gateway.rdg.channel.done",
                        "channel_id=%u",
                        context->channel_id);
    if (status == LIBRDP_STATUS_OK)
    {
        pthread_mutex_lock(&context->mutex);
        context->active = 1;
        pthread_mutex_unlock(&context->mutex);
    }
    return status;
}

static librdp_status rdp_rdg_backend_wait(void* user_data, int timeout_ms, short events, short* revents)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    struct pollfd pfd;
    int rc = 0;
    short ready = 0;

    if (!context || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pthread_mutex_lock(&context->mutex);
    if ((events & POLLOUT) != 0 && context->error == LIBRDP_STATUS_OK && !context->closing)
        ready |= POLLOUT;
    if ((events & POLLIN) != 0 && rdp_rdg_queue_has_bytes(context->data_head))
        ready |= POLLIN;
    if (ready || context->error != LIBRDP_STATUS_OK || context->closing)
    {
        if (revents)
            *revents = ready;
        pthread_mutex_unlock(&context->mutex);
        return context->error != LIBRDP_STATUS_OK ? context->error : LIBRDP_STATUS_OK;
    }
    pthread_mutex_unlock(&context->mutex);

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = context->event_pipe[0];
    pfd.events = POLLIN;
    rc = poll(&pfd, 1u, timeout_ms);
    if (rc == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (rc < 0)
        return errno == EINTR ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_IO_ERROR;
    rdp_rdg_drain_pipe(context->event_pipe[0]);
    pthread_mutex_lock(&context->mutex);
    if ((events & POLLIN) != 0 && rdp_rdg_queue_has_bytes(context->data_head))
        ready |= POLLIN;
    if ((events & POLLOUT) != 0 && context->error == LIBRDP_STATUS_OK && !context->closing)
        ready |= POLLOUT;
    if (revents)
        *revents = ready;
    rc = context->error;
    pthread_mutex_unlock(&context->mutex);
    return rc != LIBRDP_STATUS_OK ? (librdp_status)rc : LIBRDP_STATUS_OK;
}

static librdp_status rdp_rdg_backend_peek(void* user_data, void* data, size_t length, size_t* read_len)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    size_t copied = 0;

    if (!context || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pthread_mutex_lock(&context->mutex);
    if (context->error != LIBRDP_STATUS_OK)
    {
        librdp_status status = context->error;

        pthread_mutex_unlock(&context->mutex);
        return status;
    }
    copied = rdp_rdg_queue_peek_copy(context->data_head, data, length);
    pthread_mutex_unlock(&context->mutex);
    if (read_len)
        *read_len = copied;
    return copied == 0 && length > 0 ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_OK;
}

static librdp_status rdp_rdg_backend_read(void* user_data, void* data, size_t length, size_t* read_len)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    size_t copied = 0;

    if (!context || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pthread_mutex_lock(&context->mutex);
    while (!rdp_rdg_queue_has_bytes(context->data_head) && context->error == LIBRDP_STATUS_OK && !context->closing)
        (void)pthread_cond_wait(&context->cond, &context->mutex);
    if (context->error != LIBRDP_STATUS_OK)
    {
        librdp_status status = context->error;

        pthread_mutex_unlock(&context->mutex);
        return status;
    }
    if (context->closing && !rdp_rdg_queue_has_bytes(context->data_head))
    {
        pthread_mutex_unlock(&context->mutex);
        return LIBRDP_STATUS_CLOSED;
    }
    copied = rdp_rdg_queue_read_copy(&context->data_head, &context->data_tail, data, length);
    if (!rdp_rdg_queue_has_bytes(context->data_head))
        rdp_rdg_drain_pipe(context->event_pipe[0]);
    pthread_mutex_unlock(&context->mutex);
    if (read_len)
        *read_len = copied;
    return copied == 0 && length > 0 ? LIBRDP_STATUS_AGAIN : LIBRDP_STATUS_OK;
}

static librdp_status rdp_rdg_backend_write(void* user_data,
                                           const void* data,
                                           size_t length,
                                           size_t* written_len)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    const uint8_t* cursor = (const uint8_t*)data;
    size_t remaining = length;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (remaining > 0 && status == LIBRDP_STATUS_OK)
    {
        size_t chunk = remaining > RDP_RDG_MAX_DATA ? RDP_RDG_MAX_DATA : remaining;
        rdp_buffer packet;

        status = rdp_rdg_build_data_packet(cursor, chunk, &packet);
        if (status == LIBRDP_STATUS_OK)
        {
            pthread_mutex_lock(&context->mutex);
            if (context->error != LIBRDP_STATUS_OK)
                status = context->error;
            else if (context->closing || !context->active)
                status = LIBRDP_STATUS_CLOSED;
            else
            {
                status = rdp_rdg_queue_copy(&context->out_head, &context->out_tail, packet.data, packet.length);
                pthread_cond_broadcast(&context->cond);
                rdp_rdg_signal_pipe(context->control_pipe[1]);
            }
            pthread_mutex_unlock(&context->mutex);
        }
        rdp_buffer_free(&packet);
        if (status == LIBRDP_STATUS_OK)
        {
            cursor += chunk;
            remaining -= chunk;
        }
    }
    if (written_len)
        *written_len = length - remaining;
    return status;
}

static void rdp_rdg_backend_close(void* user_data)
{
    rdp_rdg_http_context* context = (rdp_rdg_http_context*)user_data;
    rdp_buffer body;

    if (!context)
        return;
    pthread_mutex_lock(&context->mutex);
    if (context->active && !context->closing)
    {
        pthread_mutex_unlock(&context->mutex);
        if (rdp_rdg_build_close_packet(&body) == LIBRDP_STATUS_OK)
        {
            (void)rdp_rdg_queue_packet(context, RDP_RDG_PKT_CLOSE_CHANNEL, &body);
            rdp_buffer_free(&body);
        }
    }
    else
        pthread_mutex_unlock(&context->mutex);
    rdp_rdg_context_free(context);
}

static const rdp_transport_backend_ops rdp_rdg_backend_ops = {
    rdp_rdg_backend_wait,
    rdp_rdg_backend_peek,
    rdp_rdg_backend_read,
    rdp_rdg_backend_write,
    rdp_rdg_backend_close
};

librdp_status rdp_gateway_connect_rdg_http(rdp_transport* transport,
                                           const rdp_gateway_connect_config* config)
{
    rdp_rdg_http_context* context = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!transport || !config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context = rdp_rdg_context_new();
    if (!context)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_rdg_copy_config(context, config);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.gateway.rdg.connect.start",
                        "target=\"%s\" port=%u",
                        context->target_host,
                        (unsigned)context->target_port);
        status = rdp_rdg_send_simple(context, RDP_RDG_PKT_HANDSHAKE_REQUEST, rdp_rdg_build_handshake);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_start(context);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rdg_handshake(context);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_TRANSPORT,
                        "transport.gateway.rdg.connect.failed",
                        "status=%s",
                        librdp_status_name(status));
        rdp_rdg_context_free(context);
        return status;
    }
    rdp_transport_attach_backend(transport, context, &rdp_rdg_backend_ops);
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.gateway.rdg.connect.done",
                    "target=\"%s\" port=%u tunnel_id=%u channel_id=%u",
                    context->target_host,
                    (unsigned)context->target_port,
                    context->tunnel_id,
                    context->channel_id);
    return LIBRDP_STATUS_OK;
}
