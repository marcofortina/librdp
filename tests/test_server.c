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

#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SCHECK(condition)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(condition))                                                                                             \
            return 1;                                                                                                 \
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
    SCHECK(response[11] == 0x03 && response[13] == 0x08 && response[15] == 0x01);
    librdp_server_peer_free(peer);
    librdp_server_close(server);
    SCHECK(librdp_server_local_port(server) == 0);
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
    return 0;
}
