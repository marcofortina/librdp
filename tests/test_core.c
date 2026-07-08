#include <librdp/librdp.h>

#include "common/buffer.h"
#include "common/stream.h"
#include "common/trace.h"
#include "input/input.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "security/security.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

typedef struct event_counter
{
    int states;
    int surfaces;
    int keys;
    int mouse;
    int pointer;
    int disconnected;
} event_counter;

int test_protocol(void);
int test_transport(void);

static void on_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    event_counter* counter = (event_counter*)user_data;
    (void)session;

    if (!event || !counter)
        return;

    switch (event->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            counter->states++;
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            counter->surfaces++;
            break;
        case LIBRDP_EVENT_KEY_SENT:
            counter->keys++;
            break;
        case LIBRDP_EVENT_MOUSE_SENT:
            counter->mouse++;
            break;
        case LIBRDP_EVENT_POINTER:
            counter->pointer++;
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            counter->disconnected++;
            break;
        default:
            break;
    }
}

static int capture_stderr(void (*fn)(void), char* out, size_t out_len)
{
    int pipe_fds[2] = {-1, -1};
    int saved = -1;
    ssize_t got = 0;

    if (pipe(pipe_fds) != 0)
        return 0;
    saved = dup(STDERR_FILENO);
    if (saved < 0)
        return 0;
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0)
        return 0;
    close(pipe_fds[1]);

    fn();
    fflush(stderr);

    if (dup2(saved, STDERR_FILENO) < 0)
        return 0;
    close(saved);

    got = read(pipe_fds[0], out, out_len - 1);
    close(pipe_fds[0]);
    if (got < 0)
        got = 0;
    out[got] = '\0';
    return 1;
}

static int read_exact_fd(int fd, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t got = read(fd, out + offset, length - offset);
        if (got <= 0)
            return 0;
        offset += (size_t)got;
    }

    return 1;
}

static int write_exact_fd(int fd, const void* data, size_t length)
{
    const uint8_t* in = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t wrote = write(fd, in + offset, length - offset);
        if (wrote <= 0)
            return 0;
        offset += (size_t)wrote;
    }

    return 1;
}

static int append_ber_length(rdp_buffer* buffer, size_t length)
{
    if (length < 0x80u)
        return rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
    if (length <= 0xffu)
        return rdp_buffer_append_u8(buffer, 0x81) == LIBRDP_STATUS_OK &&
               rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
    if (length <= 0xffffu)
        return rdp_buffer_append_u8(buffer, 0x82) == LIBRDP_STATUS_OK &&
               rdp_buffer_append_u16_be(buffer, (uint16_t)length) == LIBRDP_STATUS_OK;
    return 0;
}

static int append_per_length(rdp_buffer* buffer, size_t length)
{
    if (length > 0x7fffu)
        return 0;
    if (length > 0x7fu)
        return rdp_buffer_append_u16_be(buffer, (uint16_t)(length | 0x8000u)) == LIBRDP_STATUS_OK;
    return rdp_buffer_append_u8(buffer, (uint8_t)length) == LIBRDP_STATUS_OK;
}

static int append_gcc_block(rdp_buffer* buffer, uint16_t type, const rdp_buffer* payload)
{
    size_t total = 0;

    if (!buffer || !payload)
        return 0;
    total = payload->length + 4u;
    if (total > 0xffffu)
        return 0;
    return rdp_buffer_append_u16_le(buffer, type) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(buffer, (uint16_t)total) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(buffer, payload->data, payload->length) == LIBRDP_STATUS_OK;
}

static int build_server_connect_response(rdp_buffer* out, int encrypted)
{
    static const uint8_t oid[] = {5, 0, 20, 124, 0, 1};
    static const uint8_t key[] = {'M', 'c', 'D', 'n'};
    static const uint8_t server_random[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    static const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    rdp_buffer core;
    rdp_buffer security;
    rdp_buffer network;
    rdp_buffer blocks;
    rdp_buffer gcc;
    rdp_buffer content;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&core);
    rdp_buffer_init(&security);
    rdp_buffer_init(&network);
    rdp_buffer_init(&blocks);
    rdp_buffer_init(&gcc);
    rdp_buffer_init(&content);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u32_le(&core, 0x00080004u) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&core, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&core, 0) == LIBRDP_STATUS_OK &&
         append_gcc_block(&blocks, 0x0c01u, &core);
    if (ok)
    {
        ok = rdp_buffer_append_u32_le(&security, encrypted ? RDP_SECURITY_METHOD_128BIT : 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&security, encrypted ? 3u : 0) == LIBRDP_STATUS_OK;
        if (ok && encrypted)
            ok = rdp_buffer_append_u32_le(&security, (uint32_t)sizeof(server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append_u32_le(&security, (uint32_t)sizeof(server_certificate)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security, server_random, sizeof(server_random)) == LIBRDP_STATUS_OK &&
                 rdp_buffer_append(&security, server_certificate, sizeof(server_certificate)) == LIBRDP_STATUS_OK;
        if (ok)
            ok = append_gcc_block(&blocks, 0x0c02u, &security);
    }
    if (ok)
        ok = rdp_buffer_append_u16_le(&network, 1003) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&network, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&network, 1004) == LIBRDP_STATUS_OK &&
             append_gcc_block(&blocks, 0x0c03u, &network);

    if (ok)
        ok = rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&gcc, oid, sizeof(oid)) == LIBRDP_STATUS_OK &&
             append_per_length(&gcc, blocks.length + 14u) &&
             rdp_buffer_append_u8(&gcc, 0x14) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&gcc, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 42) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0xc0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&gcc, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&gcc, key, sizeof(key)) == LIBRDP_STATUS_OK &&
             append_per_length(&gcc, blocks.length) &&
             rdp_buffer_append(&gcc, blocks.data, blocks.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&content, 0x0a) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x01) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&content, 0x04) == LIBRDP_STATUS_OK &&
             append_ber_length(&content, gcc.length) &&
             rdp_buffer_append(&content, gcc.data, gcc.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x7f) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x66) == LIBRDP_STATUS_OK &&
             append_ber_length(&mcs, content.length) &&
             rdp_buffer_append(&mcs, content.data, content.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok && total <= 0xffffu)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&content);
    rdp_buffer_free(&gcc);
    rdp_buffer_free(&blocks);
    rdp_buffer_free(&network);
    rdp_buffer_free(&security);
    rdp_buffer_free(&core);
    return ok;
}

static int read_security_payload(const uint8_t* input, size_t input_len, const uint8_t** payload, size_t* payload_len)
{
    size_t pos = 0;
    size_t length = 0;

    if (!input || input_len < 14 || !payload || !payload_len)
        return 0;
    pos = 4;
    if (input[pos++] != 0x02 || input[pos++] != 0xf0 || input[pos++] != 0x80)
        return 0;
    if (input[pos++] != 0x64)
        return 0;
    pos += 5;
    if (pos >= input_len)
        return 0;
    length = input[pos++];
    if ((length & 0x80u) != 0)
    {
        if (pos >= input_len)
            return 0;
        length = ((length & 0x7fu) << 8) | input[pos++];
    }
    if (length > input_len - pos)
        return 0;
    *payload = input + pos;
    *payload_len = length;
    return 1;
}

static int validate_security_exchange(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint32_t random_len = 0;

    if (!read_security_payload(input, input_len, &payload, &payload_len) || payload_len < 16)
        return 0;
    random_len = (uint32_t)payload[4] | ((uint32_t)payload[5] << 8) | ((uint32_t)payload[6] << 16) |
                 ((uint32_t)payload[7] << 24);
    return ((uint16_t)payload[0] | ((uint16_t)payload[1] << 8)) ==
               (RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC) &&
           payload[2] == 0 && payload[3] == 0 &&
           random_len == 136u && payload_len == 144u;
}

static int validate_encrypted_client_info(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint8_t flags = (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT);

    if (!read_security_payload(input, input_len, &payload, &payload_len) || payload_len < 20)
        return 0;
    return payload[0] == flags && payload[1] == 0 && payload[2] == 0 && payload[3] == 0;
}

static int build_demand_active_packet(rdp_buffer* out)
{
    rdp_buffer caps;
    rdp_buffer slow;
    rdp_buffer mcs;
    const char source[] = {'s', 'r', 'v'};
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&caps);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u16_le(&caps, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&caps, 8) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&caps, 0) == LIBRDP_STATUS_OK;
    total = 6u + 4u + 2u + 2u + sizeof(source) + caps.length;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1002) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)sizeof(source)) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)caps.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, source, sizeof(source)) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, caps.data, caps.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&caps);
    return ok;
}

static int validate_confirm_active(const uint8_t* input, size_t input_len)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    rdp_slowpath_share_control_header header;

    if (!read_security_payload(input, input_len, &payload, &payload_len))
        return 0;
    if (rdp_slowpath_parse_share_control_header(payload, payload_len, &header) != LIBRDP_STATUS_OK)
        return 0;
    return (header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE && header.channel_id == 1004 &&
           payload_len >= 16 && payload[6] == 0x40 && payload[7] == 0x30 && payload[8] == 0x20 &&
           payload[9] == 0x10;
}

static int build_bitmap_update_packet(rdp_buffer* out)
{
    static const uint8_t pixels[] = {
        1,  2,  3,  4,  5,  6,  7,  8,
        9,  10, 11, 12, 13, 14, 15, 16
    };
    rdp_buffer payload;
    rdp_buffer slow;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 1) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 2) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 32) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u16_le(&payload, 0) == LIBRDP_STATUS_OK &&
         rdp_buffer_append_u32_le(&payload, (uint32_t)sizeof(pixels)) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(&payload, pixels, sizeof(pixels)) == LIBRDP_STATUS_OK;
    total = payload.length + 18u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1004) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, RDP_SLOWPATH_DATA_PDU_UPDATE) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&payload);
    return ok;
}

static int build_set_error_info_packet(rdp_buffer* out, uint32_t error_info)
{
    rdp_buffer payload;
    rdp_buffer slow;
    rdp_buffer mcs;
    size_t total = 0;
    int ok = 0;

    rdp_buffer_init(&payload);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&mcs);

    ok = rdp_buffer_append_u32_le(&payload, error_info) == LIBRDP_STATUS_OK;
    total = payload.length + 18u;
    if (ok)
        ok = rdp_buffer_append_u16_le(&slow, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA)) ==
                 LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 1004) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u32_le(&slow, 0x10203040u) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 1) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, (uint16_t)payload.length) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_le(&slow, 0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(&slow, payload.data, payload.length) == LIBRDP_STATUS_OK;
    if (ok)
        ok = rdp_buffer_append_u8(&mcs, 0x68) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, 3) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(&mcs, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(&mcs, 0x70) == LIBRDP_STATUS_OK &&
             append_per_length(&mcs, slow.length) &&
             rdp_buffer_append(&mcs, slow.data, slow.length) == LIBRDP_STATUS_OK;
    total = mcs.length + 7u;
    if (ok)
        ok = rdp_buffer_append_u8(out, 0x03) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x00) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u16_be(out, (uint16_t)total) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x02) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0xf0) == LIBRDP_STATUS_OK &&
             rdp_buffer_append_u8(out, 0x80) == LIBRDP_STATUS_OK &&
             rdp_buffer_append(out, mcs.data, mcs.length) == LIBRDP_STATUS_OK;

    rdp_buffer_free(&mcs);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&payload);
    return ok;
}

static int read_tpkt_fd(int fd, uint8_t* data, size_t capacity, size_t* length)
{
    uint16_t total = 0;

    if (!data || capacity < 4 || !length)
        return 0;
    if (!read_exact_fd(fd, data, 4))
        return 0;
    total = (uint16_t)(((uint16_t)data[2] << 8) | data[3]);
    if (data[0] != 3 || data[1] != 0 || total < 4 || total > capacity)
        return 0;
    if (!read_exact_fd(fd, data + 4, (size_t)total - 4u))
        return 0;
    *length = total;
    return 1;
}

static int start_handshake_server(uint16_t* port, pid_t* child_pid, int encrypted, uint32_t error_info)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port || !child_pid)
        return 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(fd, 1) != 0)
    {
        close(fd);
        return 0;
    }

    *port = ntohs(addr.sin_port);
    *child_pid = fork();
    if (*child_pid < 0)
    {
        close(fd);
        return 0;
    }

    if (*child_pid == 0)
    {
        uint8_t input[4096];
        size_t input_len = 0;
        rdp_buffer mcs_response;
        rdp_buffer demand_active;
        rdp_buffer bitmap_update;
        rdp_buffer error_update;
        const uint8_t response[] = {
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        const uint8_t attach_confirm[] = {
            0x03, 0x00, 0x00, 0x0b,
            0x02, 0xf0, 0x80,
            0x2e, 0x00, 0x00, 0x03
        };
        const uint8_t join_user_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xec, 0x03, 0xec
        };
        const uint8_t join_global_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xeb, 0x03, 0xeb
        };
        struct timespec ts;
        int client = accept(fd, NULL, NULL);
        rdp_buffer_init(&mcs_response);
        rdp_buffer_init(&demand_active);
        rdp_buffer_init(&bitmap_update);
        rdp_buffer_init(&error_update);
        if (client >= 0)
        {
            if (!build_server_connect_response(&mcs_response, encrypted))
                _exit(1);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, response, sizeof(response));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, mcs_response.data, mcs_response.length);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, attach_confirm, sizeof(attach_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_user_confirm, sizeof(join_user_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_global_confirm, sizeof(join_global_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            if (encrypted)
            {
                if (!validate_security_exchange(input, input_len))
                    _exit(2);
                if (!read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                    !validate_encrypted_client_info(input, input_len))
                    _exit(3);
            }
            else
            {
                if (!build_demand_active_packet(&demand_active) ||
                    !write_exact_fd(client, demand_active.data, demand_active.length) ||
                    !read_tpkt_fd(client, input, sizeof(input), &input_len) ||
                    !validate_confirm_active(input, input_len))
                    _exit(4);
                if (error_info != 0)
                {
                    if (!build_set_error_info_packet(&error_update, error_info) ||
                        !write_exact_fd(client, error_update.data, error_update.length))
                        _exit(5);
                }
                else if (!build_bitmap_update_packet(&bitmap_update) ||
                         !write_exact_fd(client, bitmap_update.data, bitmap_update.length))
                    _exit(5);
            }
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            (void)nanosleep(&ts, NULL);
            close(client);
        }
        rdp_buffer_free(&error_update);
        rdp_buffer_free(&bitmap_update);
        rdp_buffer_free(&demand_active);
        rdp_buffer_free(&mcs_response);
        close(fd);
        _exit(0);
    }

    close(fd);
    return 1;
}

static void trace_default_event(void)
{
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
}

static void trace_enabled_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "yes", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
}

static void trace_protocol_hexdump(void)
{
    const uint8_t bytes[] = {0x41, 0x42, 0x00, 0x43};
    setenv("LIBRDP_TRACE_PROTOCOL", "ON", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "2", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.fastpath.pdu", bytes, sizeof(bytes));
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static void trace_level_filtered_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "info", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

static void trace_level_debug_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

static int test_trace(void)
{
    char output[2048];

    CHECK(rdp_trace_parse_bool_value("1"));
    CHECK(rdp_trace_parse_bool_value("true"));
    CHECK(rdp_trace_parse_bool_value("TRUE"));
    CHECK(rdp_trace_parse_bool_value("yes"));
    CHECK(rdp_trace_parse_bool_value("YES"));
    CHECK(rdp_trace_parse_bool_value("on"));
    CHECK(rdp_trace_parse_bool_value("ON"));
    CHECK(!rdp_trace_parse_bool_value("0"));
    CHECK(!rdp_trace_parse_bool_value("maybe"));
    CHECK(rdp_trace_parse_hex_limit_value("32") == 32);
    CHECK(rdp_trace_parse_hex_limit_value("bad") == 0);
    CHECK(rdp_trace_parse_hex_limit_value("") == 0);
    CHECK(rdp_trace_parse_level_value(NULL) == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("error") == RDP_TRACE_LEVEL_ERROR);
    CHECK(rdp_trace_parse_level_value("WARN") == RDP_TRACE_LEVEL_WARN);
    CHECK(rdp_trace_parse_level_value("info") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("debug") == RDP_TRACE_LEVEL_DEBUG);
    CHECK(rdp_trace_parse_level_value("TRACE") == RDP_TRACE_LEVEL_TRACE);
    CHECK(rdp_trace_parse_level_value("bad") == RDP_TRACE_LEVEL_INFO);

    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
    CHECK(capture_stderr(trace_default_event, output, sizeof(output)));
    CHECK(output[0] == '\0');

    CHECK(capture_stderr(trace_enabled_event, output, sizeof(output)));
    CHECK(strstr(output, "librdp trace seq=1 ") != NULL);
    CHECK(strstr(output, "category=client event=client.test") != NULL);
    CHECK(strstr(output, "message=\"value=1\"") != NULL);

    setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
    rdp_trace_reset_for_tests();
    CHECK(rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_INFO));
    CHECK(!rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_DEBUG));
    unsetenv("LIBRDP_TRACE_TRANSPORT");

    CHECK(capture_stderr(trace_level_filtered_event, output, sizeof(output)));
    CHECK(output[0] == '\0');
    CHECK(capture_stderr(trace_level_debug_event, output, sizeof(output)));
    CHECK(strstr(output, "category=client event=client.debug level=debug") != NULL);

    CHECK(capture_stderr(trace_protocol_hexdump, output, sizeof(output)));
    CHECK(strstr(output, "category=protocol event=rdp.fastpath.pdu") != NULL);
    CHECK(strstr(output, "level=trace") != NULL);
    CHECK(strstr(output, "payload_len=4 dumped=2 hex=4142 ascii=\"AB\"") != NULL);
    return 0;
}

static int test_buffer_stream(void)
{
    rdp_buffer buffer;
    rdp_stream stream;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    const uint8_t* raw = NULL;

    rdp_buffer_init(&buffer);
    CHECK(rdp_buffer_append_u8(&buffer, 0x11) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&buffer, 0x2233) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_be(&buffer, 0x4455) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&buffer, 0x66778899u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_be(&buffer, 0xaabbccddu) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 13);

    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_OK && u8 == 0x11);
    CHECK(rdp_stream_read_u16_le(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x2233);
    CHECK(rdp_stream_read_u16_be(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x4455);
    CHECK(rdp_stream_read_u32_le(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0x66778899u);
    CHECK(rdp_stream_read_u32_be(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0xaabbccddu);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_PROTOCOL_ERROR);

    CHECK(rdp_buffer_consume(&buffer, 3) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 10);
    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_bytes(&stream, &raw, 2) == LIBRDP_STATUS_OK);
    CHECK(raw[0] == 0x44 && raw[1] == 0x55);
    CHECK(rdp_stream_skip(&stream, 100) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    return 0;
}

static int test_pointer_decode(void)
{
    rdp_pointer_update update;
    rdp_buffer output;
    size_t stride = 0;
    const uint8_t xor_mask[12] = {
        0, 0, 0, 0,
        0xff, 0xff, 0xff, 0,
        0, 0, 0, 0
    };
    const uint8_t and_mask[2] = {0xe0, 0};

    memset(&update, 0, sizeof(update));
    rdp_buffer_init(&output);
    update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update.width = 3;
    update.height = 1;
    update.xor_bpp = 32;
    update.xor_mask = xor_mask;
    update.xor_mask_len = sizeof(xor_mask);
    update.and_mask = and_mask;
    update.and_mask_len = sizeof(and_mask);

    CHECK(rdp_pointer_decode_bgra32(&update, &output, &stride) == LIBRDP_STATUS_OK);
    CHECK(stride == 12);
    CHECK(output.length == 12);
    CHECK(output.data[0] == 0 && output.data[1] == 0 && output.data[2] == 0 && output.data[3] == 0);
    CHECK(output.data[4] == 0xff && output.data[5] == 0xff && output.data[6] == 0xff && output.data[7] == 0);
    CHECK(output.data[8] == 0 && output.data[9] == 0 && output.data[10] == 0 && output.data[11] == 0);
    rdp_buffer_free(&output);
    return 0;
}

static int test_settings_surface_input_session(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_surface* surface = NULL;
    librdp_session* session = NULL;
    const librdp_surface* session_surface = NULL;
    uint8_t pixels[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    };
    const uint8_t* out = NULL;
    uint16_t flags = 0;
    librdp_key_event key = {30, LIBRDP_KEY_PRESSED};
    librdp_mouse_event mouse = {10, 11, LIBRDP_MOUSE_BUTTON_LEFT, LIBRDP_MOUSE_PRESSED};
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    memset(&counter, 0, sizeof(counter));

    CHECK(strcmp(librdp_status_string(LIBRDP_STATUS_OK), "ok") == 0);
    CHECK(strcmp(librdp_status_string((librdp_status)-1000), "unknown") == 0);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_port(settings) == 3389);
    CHECK(librdp_settings_width(settings) == 1024);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_username(settings, "user") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_password(settings, "secret") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_domain(settings, "domain") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 3390) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_TLS) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_desktop_size(settings, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_security_mode(settings, (librdp_security_mode)99) == LIBRDP_STATUS_INVALID_ARGUMENT);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(strcmp(librdp_settings_target(copy), "127.0.0.1") == 0);
    CHECK(strcmp(librdp_settings_username(copy), "user") == 0);
    CHECK(strcmp(librdp_settings_domain(copy), "domain") == 0);
    CHECK(librdp_settings_security_mode(copy) == LIBRDP_SECURITY_TLS);

    surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);
    CHECK(librdp_surface_stride(surface) == 16);
    CHECK(librdp_surface_blit_bgra32(surface, 1, 1, 2, 2, pixels, 8) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_blit_bgra32(surface, 3, 3, 2, 2, pixels, 8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    out = librdp_surface_pixels(surface);
    CHECK(out[((size_t)1 * 16) + 4] == 1);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_width(surface) == 2);
    CHECK(librdp_surface_pixels_mut(surface) != NULL);
    librdp_surface_free(surface);

    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0);
    key.flags = LIBRDP_KEY_FLAG_EXTENDED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x0100u);
    key.flags = 0;
    key.state = LIBRDP_KEY_RELEASED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x8000u);
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x9000u);
    mouse.state = LIBRDP_MOUSE_RELEASED;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x1000u);
    mouse.state = LIBRDP_MOUSE_MOVED;
    mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0800u);
    mouse.state = LIBRDP_MOUSE_PRESSED;
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_DOWN;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0388u);
    mouse.button = LIBRDP_MOUSE_BUTTON_WHEEL_LEFT;
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x0588u);
    mouse.button = LIBRDP_MOUSE_BUTTON_X1;
    CHECK(rdp_input_mouse_uses_extended(&mouse));
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && flags == 0x8001u);
    mouse.button = LIBRDP_MOUSE_BUTTON_LEFT;

    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(librdp_session_refresh(session, 0, 0, 1, 1) == LIBRDP_STATUS_STATE);
    CHECK(start_handshake_server(&test_port, &server_pid, 0, 0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    librdp_session_free(session);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(counter.states == 2);
    CHECK(counter.surfaces == 1);
    CHECK(counter.pointer >= 1);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 2);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    out = librdp_surface_pixels(session_surface);
    CHECK(out[0] == 9 && out[1] == 10 && out[2] == 11 && out[3] == 12);
    CHECK(librdp_session_refresh(session, 0, 0, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_refresh(session, 0, 0, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    key.state = LIBRDP_KEY_PRESSED;
    CHECK(librdp_session_send_key(session, &key) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_send_mouse(session, &mouse) == LIBRDP_STATUS_OK);
    CHECK(counter.keys == 1);
    CHECK(counter.mouse == 1);
    CHECK(librdp_session_resize(session, 80, 60) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 2);
    CHECK(counter.pointer >= 1);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_surface_height(session_surface) == 48);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(counter.disconnected == 1);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    memset(&counter, 0, sizeof(counter));
    server_pid = -1;
    child_status = 0;
    CHECK(start_handshake_server(&test_port, &server_pid, 0, 0x1234u));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    memset(&counter, 0, sizeof(counter));
    server_pid = -1;
    child_status = 0;
    CHECK(start_handshake_server(&test_port, &server_pid, 1, 0));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(counter.states == 2);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    librdp_session_free(session);
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    }

    librdp_settings_free(copy);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    if (test_trace() != 0)
        return 1;
    if (test_buffer_stream() != 0)
        return 1;
    if (test_pointer_decode() != 0)
        return 1;
    if (test_protocol() != 0)
        return 1;
    if (test_transport() != 0)
        return 1;
    if (test_settings_surface_input_session() != 0)
        return 1;
    return 0;
}
