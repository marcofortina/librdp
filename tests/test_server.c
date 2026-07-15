/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public server API tests.
 * Coverage: versioned server config defaults, invalid metadata rejection, and
 * ownership of copied listener configuration.
 * Bug classes: ABI metadata drift, invalid size/version acceptance, bounds
 * mistakes, and cleanup of partially copied strings.
 * Determinism: runtime coverage binds only to loopback on an ephemeral port
 * and exchanges one synthetic connection request.
 */

#include <librdp/librdp.h>

#include "common/buffer.h"
#include "graphics/bitmap.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCHECK(condition)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(condition))                                                                                             \
        {                                                                                                             \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition);                              \
            return 1;                                                                                                 \
        }                                                                                                             \
    } while (0)

static int test_server_config_defaults(void)
{
    librdp_server_config config;
    librdp_server_input_event input_event;
    librdp_server_static_channel_info channel_info;

    SCHECK(librdp_server_config_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    SCHECK(config.version == LIBRDP_SERVER_CONFIG_VERSION);
    SCHECK(config.size == sizeof(config));
    SCHECK(config.bind_address == NULL);
    SCHECK(config.port == 0);
    SCHECK(config.backlog == 4);
    SCHECK(config.max_peers == 16);
    SCHECK(config.width == 1024);
    SCHECK(config.height == 768);
    SCHECK(config.server_name == NULL);
    SCHECK(librdp_server_input_event_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_input_event_init(&input_event) == LIBRDP_STATUS_OK);
    SCHECK(input_event.version == LIBRDP_SERVER_INPUT_EVENT_VERSION);
    SCHECK(input_event.size == sizeof(input_event));
    SCHECK(librdp_server_static_channel_info_init(NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_static_channel_info_init(&channel_info) == LIBRDP_STATUS_OK);
    SCHECK(channel_info.version == LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION);
    SCHECK(channel_info.size == sizeof(channel_info));
    return 0;
}

static int test_server_new_validates_metadata(void)
{
    librdp_server_config config;
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.version = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.size = 1;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 1024;
    config.height = 0;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.width = 9000;
    config.height = 9000;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.backlog = 129;
    SCHECK(librdp_server_new(&config) == NULL);
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    librdp_server_free(server);
    librdp_server_free(NULL);
    return 0;
}

static int test_server_new_copies_strings(void)
{
    librdp_server_config config;
    char bind_address[16] = "127.0.0.1";
    char server_name[16] = "test";
    librdp_server* server = NULL;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = bind_address;
    config.server_name = server_name;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    memset(bind_address, 'x', sizeof(bind_address) - 1u);
    bind_address[sizeof(bind_address) - 1u] = '\0';
    memset(server_name, 'y', sizeof(server_name) - 1u);
    server_name[sizeof(server_name) - 1u] = '\0';
    librdp_server_free(server);
    return 0;
}

static int test_server_connect_loopback(uint16_t port)
{
    struct sockaddr_in address;
    int fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr*)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int test_server_read_response(int fd, uint8_t* response, size_t response_len)
{
    struct pollfd pfd;
    ssize_t count = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    count = recv(fd, response, response_len, 0);
    return count > 0 ? (int)count : 0;
}

static int test_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, 0);

        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

typedef struct test_server_runtime_context
{
    uint32_t input_count;
    uint32_t control_count;
    uint32_t font_list_count;
    uint32_t key_count;
    uint32_t channel_count;
    uint16_t last_channel_id;
    uint8_t channel_payload[16];
    size_t channel_payload_len;
} test_server_runtime_context;

static void test_server_input_callback(librdp_server_peer* peer,
                                       const librdp_server_input_event* event,
                                       void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;

    (void)peer;
    if (!context || !event)
        return;
    context->input_count++;
    if (event->type == LIBRDP_SERVER_INPUT_CONTROL)
        context->control_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_FONT_LIST)
        context->font_list_count++;
    else if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
        context->key_count++;
}

static void test_server_channel_callback(librdp_server_peer* peer,
                                         const librdp_server_channel_event* event,
                                         void* user_data)
{
    test_server_runtime_context* context = (test_server_runtime_context*)user_data;
    size_t copy_len = 0;

    (void)peer;
    if (!context || !event)
        return;
    context->channel_count++;
    context->last_channel_id = event->channel_id;
    copy_len = event->data_len > sizeof(context->channel_payload) ? sizeof(context->channel_payload) : event->data_len;
    if (copy_len > 0)
        memcpy(context->channel_payload, event->data, copy_len);
    context->channel_payload_len = copy_len;
}

static int test_server_send_client_mcs_connect_initial(int fd)
{
    static const rdp_gcc_channel_definition extra_channels[1] = {
        {{'t', 'e', 's', 't', 'v', 'c', 0, 0}, 0xc0800000u}
    };
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs_initial;
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    rdp_gcc_client_config config;
    int ok = 0;

    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    memset(&config, 0, sizeof(config));
    config.desktop_width = 800;
    config.desktop_height = 600;
    config.requested_protocols = RDP_X224_PROTOCOL_STANDARD;
    config.client_name = "server-test";
    config.extra_channels = extra_channels;
    config.extra_channel_count = 1;
    if (rdp_gcc_write_client_data_blocks(&gcc_blocks, &config) == LIBRDP_STATUS_OK &&
        rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length) ==
            LIBRDP_STATUS_OK &&
        rdp_mcs_write_connect_initial(&mcs_initial, gcc_request.data, gcc_request.length) ==
            LIBRDP_STATUS_OK &&
        rdp_x224_wrap_data(&x224_data, mcs_initial.data, mcs_initial.length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    return ok;
}

static int test_server_send_mcs_pdu(int fd, const rdp_buffer* mcs_pdu)
{
    rdp_buffer x224_data;
    rdp_buffer tpkt;
    int ok = 0;

    if (!mcs_pdu)
        return 0;
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&tpkt);
    if (rdp_x224_wrap_data(&x224_data, mcs_pdu->data, mcs_pdu->length) == LIBRDP_STATUS_OK &&
        rdp_tpkt_write(&tpkt, x224_data.data, x224_data.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_all(fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224_data);
    return ok;
}

static int test_server_send_simple_mcs(int fd, librdp_status (*writer)(rdp_buffer*))
{
    rdp_buffer pdu;
    int ok = 0;

    if (!writer)
        return 0;
    rdp_buffer_init(&pdu);
    if (writer(&pdu) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

static int test_server_send_channel_join(int fd, uint16_t user_id, uint16_t channel_id)
{
    rdp_buffer pdu;
    int ok = 0;

    rdp_buffer_init(&pdu);
    if (rdp_mcs_write_channel_join_request(&pdu, user_id, channel_id) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &pdu);
    rdp_buffer_free(&pdu);
    return ok;
}

static int test_server_send_confirm_active(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer confirm;
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&confirm);
    rdp_buffer_init(&send_data);
    if (rdp_slowpath_write_confirm_active(&confirm, share_id, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, 800, 600, "test") ==
            LIBRDP_STATUS_OK &&
        rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             confirm.data,
                                             confirm.length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&confirm);
    return ok;
}

static int test_server_send_slowpath(int fd, uint16_t user_id, const rdp_buffer* slowpath)
{
    rdp_buffer send_data;
    int ok = 0;

    if (!slowpath)
        return 0;
    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data,
                                             user_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             slowpath->data,
                                             slowpath->length) == LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_send_client_synchronize(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_synchronize(&slowpath,
                                              share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_control(int fd, uint32_t share_id, uint16_t user_id, uint16_t action)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_control(&slowpath,
                                          share_id,
                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                          action) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_client_font_list(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_font_list(&slowpath,
                                            share_id,
                                            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_keyboard_input(int fd, uint32_t share_id, uint16_t user_id)
{
    rdp_buffer slowpath;
    int ok = 0;

    rdp_buffer_init(&slowpath);
    if (rdp_slowpath_write_client_keyboard_input(&slowpath,
                                                 share_id,
                                                 (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                 0,
                                                 30) == LIBRDP_STATUS_OK)
        ok = test_server_send_slowpath(fd, user_id, &slowpath);
    rdp_buffer_free(&slowpath);
    return ok;
}

static int test_server_send_static_channel_data(int fd, uint16_t user_id, uint16_t channel_id)
{
    static const uint8_t payload[] = {1, 2, 3, 4};
    rdp_buffer send_data;
    int ok = 0;

    rdp_buffer_init(&send_data);
    if (rdp_security_write_send_data_request(&send_data, user_id, channel_id, payload, sizeof(payload)) ==
        LIBRDP_STATUS_OK)
        ok = test_server_send_mcs_pdu(fd, &send_data);
    rdp_buffer_free(&send_data);
    return ok;
}

static int test_server_read_tpkt_x224_data(int fd, uint8_t* buffer, size_t buffer_len, rdp_tpkt* tpkt)
{
    struct pollfd pfd;
    size_t total = 0;
    size_t offset = 0;

    if (!buffer || buffer_len < 4 || !tpkt)
        return 0;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 1000) <= 0)
        return 0;
    while (offset < 4u)
    {
        ssize_t count = recv(fd, buffer + offset, 4u - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    total = ((size_t)buffer[2] << 8) | buffer[3];
    if (total < 4u || total > buffer_len)
        return 0;
    while (offset < total)
    {
        ssize_t count = recv(fd, buffer + offset, total - offset, 0);

        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return rdp_tpkt_parse(buffer, total, tpkt) == LIBRDP_STATUS_OK;
}

static int test_server_read_slowpath_data_pdu(int fd,
                                              uint8_t* response,
                                              size_t response_len,
                                              rdp_slowpath_data_pdu* data_pdu)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;

    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK)
        return 0;
    return rdp_slowpath_parse_data_pdu(indication.payload, indication.payload_len, data_pdu) == LIBRDP_STATUS_OK;
}

static int test_server_read_static_channel_data(int fd,
                                                uint8_t* response,
                                                size_t response_len,
                                                uint16_t* channel_id,
                                                const uint8_t** data,
                                                size_t* data_len)
{
    rdp_tpkt tpkt;
    rdp_mcs_send_data_indication indication;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;

    if (!channel_id || !data || !data_len)
        return 0;
    if (!test_server_read_tpkt_x224_data(fd, response, response_len, &tpkt))
        return 0;
    if (rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) != LIBRDP_STATUS_OK)
        return 0;
    if (rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &indication) != LIBRDP_STATUS_OK)
        return 0;
    *channel_id = indication.channel_id;
    *data = indication.payload;
    *data_len = indication.payload_len;
    return 1;
}

static int test_server_loopback_negotiation_failure(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    uint8_t response[64];
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    config.port = 0;
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_accept(server, 0, &peer) == LIBRDP_STATUS_STATE);
    SCHECK(peer == NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_STATE);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    SCHECK(librdp_server_accept(server, 1, &peer) == LIBRDP_STATUS_TIMEOUT);
    SCHECK(peer == NULL);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    status = librdp_server_accept(server, 1000, &peer);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(send(client_fd, request, sizeof(request), 0) == (ssize_t)sizeof(request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 19);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x13);
    SCHECK(response[4] == 0x0e && response[5] == 0xd0);
    SCHECK(response[11] == 0x03 && response[13] == 0x08 && response[15] == 0x02);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    SCHECK(librdp_server_local_port(server) == 0);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

/*
 * Drives one in-process client/server pair through the server activation path.
 * The sequence catches truncated or misordered X.224/MCS/GCC wrapping,
 * channel-join accounting, Demand Active framing, and Confirm Active state
 * transition regressions without requiring a real desktop server.
 */
static int test_server_loopback_standard_activation_sequence(void)
{
    static const uint8_t request[] = {
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t response[8192];
    rdp_tpkt tpkt;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_mcs_channel_join_confirm join_confirm;
    rdp_mcs_send_data_indication demand_indication;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_bitmap_update bitmap_update;
    librdp_server_static_channel_info static_info;
    test_server_runtime_context runtime_context;
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    const uint8_t* static_payload = NULL;
    size_t static_payload_len = 0;
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;
    uint16_t static_channel_id = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t response_channel_id = 0;
    uint8_t pixels[4u * 4u * 4u];

    memset(&runtime_context, 0, sizeof(runtime_context));
    memset(pixels, 0, sizeof(pixels));
    for (size_t pixel_index = 0; pixel_index < sizeof(pixels); pixel_index++)
        pixels[pixel_index] = (uint8_t)pixel_index;
    SCHECK(librdp_server_config_init(&config) == LIBRDP_STATUS_OK);
    config.bind_address = "127.0.0.1";
    server = librdp_server_new(&config);
    SCHECK(server != NULL);
    SCHECK(librdp_server_listen(server) == LIBRDP_STATUS_OK);
    port = librdp_server_local_port(server);
    SCHECK(port != 0);
    client_fd = test_server_connect_loopback(port);
    SCHECK(client_fd >= 0);
    SCHECK(librdp_server_accept(server, 1000, &peer) == LIBRDP_STATUS_OK);
    SCHECK(peer != NULL);
    SCHECK(librdp_server_peer_set_input_callback(peer, test_server_input_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_channel_callback(peer, test_server_channel_callback, &runtime_context) ==
           LIBRDP_STATUS_OK);
    SCHECK(test_server_send_all(client_fd, request, sizeof(request)));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_X224_CONFIRMED);
    response_len = test_server_read_response(client_fd, response, sizeof(response));
    SCHECK(response_len == 11);
    SCHECK(response[0] == 0x03 && response[1] == 0x00 && response[2] == 0x00 && response[3] == 0x0b);
    SCHECK(response[4] == 0x06 && response[5] == 0xd0);
    SCHECK(test_server_send_client_mcs_connect_initial(client_fd));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_MCS_CONNECTED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_connect_response(x224_data, x224_data_len, &mcs_response) == LIBRDP_STATUS_OK);
    SCHECK(mcs_response.result == 0);
    SCHECK(rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                    mcs_response.user_data_len,
                                                    &gcc_response) == LIBRDP_STATUS_OK);
    SCHECK(gcc_response.result == 0);
    SCHECK(rdp_gcc_parse_server_data_blocks(gcc_response.user_data,
                                            gcc_response.user_data_len,
                                            &server_data) == LIBRDP_STATUS_OK);
    SCHECK(server_data.has_core && server_data.has_security && server_data.has_network);
    SCHECK(server_data.mcs_channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    SCHECK(librdp_server_peer_static_channel_count(peer) == 1);
    SCHECK(librdp_server_static_channel_info_init(&static_info) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.channel_id == static_channel_id);
    SCHECK(static_info.joined == 0);
    SCHECK(strcmp(static_info.name, "testvc") == 0);
    SCHECK(librdp_server_peer_static_channel_at(peer, 1, &static_info) == LIBRDP_STATUS_INVALID_ARGUMENT);

    SCHECK(test_server_send_simple_mcs(client_fd, rdp_mcs_write_erect_domain_request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_DOMAIN_READY);

    SCHECK(test_server_send_simple_mcs(client_fd, rdp_mcs_write_attach_user_request));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_USER_ATTACHED);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_attach_user_confirm(x224_data, x224_data_len, &attach_confirm) == LIBRDP_STATUS_OK);
    SCHECK(attach_confirm.result == 0 && attach_confirm.user_id == RDP_MCS_BASE_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == attach_confirm.user_id);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, RDP_MCS_GLOBAL_CHANNEL_ID));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);

    SCHECK(test_server_send_channel_join(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == static_channel_id);
    SCHECK(librdp_server_peer_static_channel_at(peer, 0, &static_info) == LIBRDP_STATUS_OK);
    SCHECK(static_info.joined != 0);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_send_data_indication(x224_data, x224_data_len, &demand_indication) == LIBRDP_STATUS_OK);
    SCHECK(rdp_slowpath_parse_demand_active(demand_indication.payload,
                                            demand_indication.payload_len,
                                            &demand) == LIBRDP_STATUS_OK);
    SCHECK(demand.share_id == 0x00010001u);

    SCHECK(test_server_send_confirm_active(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 4);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           data_pdu.payload[0] == 2);

    SCHECK(test_server_send_client_synchronize(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 4));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_control(client_fd, demand.share_id, attach_confirm.user_id, 1));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(test_server_send_client_font_list(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE);
    SCHECK(runtime_context.control_count == 2);
    SCHECK(runtime_context.font_list_count == 1);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP &&
           data_pdu.payload_len == 8);

    SCHECK(librdp_server_peer_surface_blit_bgra32(peer, 0, 0, 4, 4, 16, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_present(peer, 0, 0, 4, 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_slowpath_data_pdu(client_fd, response, sizeof(response), &data_pdu));
    SCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    SCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    SCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 4 &&
           bitmap_update.rects[0].height == 4 &&
           bitmap_update.rects[0].bits_per_pixel == 32);

    SCHECK(test_server_send_keyboard_input(client_fd, demand.share_id, attach_confirm.user_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.key_count == 1);

    SCHECK(test_server_send_static_channel_data(client_fd, attach_confirm.user_id, static_channel_id));
    status = librdp_server_peer_run_once(peer, 1000);
    SCHECK(status == LIBRDP_STATUS_OK);
    SCHECK(runtime_context.channel_count == 1);
    SCHECK(runtime_context.last_channel_id == static_channel_id);
    SCHECK(runtime_context.channel_payload_len == 4 &&
           runtime_context.channel_payload[0] == 1 &&
           runtime_context.channel_payload[3] == 4);
    SCHECK(librdp_server_peer_send_channel_data(peer, static_channel_id, pixels, 4) == LIBRDP_STATUS_OK);
    SCHECK(test_server_read_static_channel_data(client_fd,
                                                response,
                                                sizeof(response),
                                                &response_channel_id,
                                                &static_payload,
                                                &static_payload_len));
    SCHECK(response_channel_id == static_channel_id &&
           static_payload_len == 4 &&
           static_payload[0] == pixels[0] &&
           static_payload[3] == pixels[3]);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    librdp_server_free(server);
    close(client_fd);
    return 0;
}

int main(void)
{
    if (test_server_config_defaults() != 0)
        return 1;
    if (test_server_new_validates_metadata() != 0)
        return 1;
    if (test_server_new_copies_strings() != 0)
        return 1;
    if (test_server_loopback_negotiation_failure() != 0)
        return 1;
    if (test_server_loopback_standard_activation_sequence() != 0)
        return 1;
    return 0;
}
