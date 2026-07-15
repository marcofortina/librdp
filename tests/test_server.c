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

static int test_server_send_client_mcs_connect_initial(int fd)
{
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
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    int client_fd = -1;
    int response_len = 0;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0;

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
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVATING);
    SCHECK(test_server_read_tpkt_x224_data(client_fd, response, sizeof(response), &tpkt));
    SCHECK(rdp_x224_parse_data(tpkt.payload, tpkt.payload_len, &x224_data, &x224_data_len) == LIBRDP_STATUS_OK);
    SCHECK(rdp_mcs_parse_channel_join_confirm(x224_data, x224_data_len, &join_confirm) == LIBRDP_STATUS_OK);
    SCHECK(join_confirm.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
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
    SCHECK(librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE);
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
