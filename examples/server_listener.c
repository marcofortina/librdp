/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: minimal public server API exercise.
 * Invariants: the example never reaches into internal server state, accepts at
 * most one peer, and reports the public status returned by each dispatch step.
 * Ownership: the server owns copied bind settings and accepted peers are freed
 * before exit.
 * Threading: single-threaded listener loop.
 * Trust boundary: remote client bytes are processed only by librdp_server APIs.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <librdp/librdp.h>

typedef struct server_listener_options
{
    const char* bind_address;
    uint16_t port;
    int timeout_ms;
} server_listener_options;

static void server_listener_usage(FILE* stream, const char* program)
{
    fprintf(stream, "usage: %s [--bind address] [--port port] [--timeout ms]\n", program);
}

static int server_listener_need_value(int argc, char** argv, int* index)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", argv[*index]);
    return 0;
}

static int server_listener_parse_u16(const char* value, uint16_t* out)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!value || !out)
        return 0;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > UINT16_MAX)
        return 0;
    *out = (uint16_t)parsed;
    return 1;
}

static int server_listener_parse_timeout(const char* value, int* out)
{
    char* end = NULL;
    long parsed = 0;

    if (!value || !out)
        return 0;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < 0 || parsed > 60000)
        return 0;
    *out = (int)parsed;
    return 1;
}

static int server_listener_parse_args(int argc, char** argv, server_listener_options* options)
{
    int i = 0;

    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    options->bind_address = "127.0.0.1";
    options->timeout_ms = 10000;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            server_listener_usage(stdout, argv[0]);
            exit(0);
        }
        if (strcmp(argv[i], "--bind") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i))
                return 0;
            options->bind_address = argv[i];
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_u16(argv[i], &options->port))
                return 0;
        }
        else if (strcmp(argv[i], "--timeout") == 0)
        {
            if (!server_listener_need_value(argc, argv, &i) ||
                !server_listener_parse_timeout(argv[i], &options->timeout_ms))
                return 0;
        }
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    return 1;
}

static int server_listener_run_peer(librdp_server_peer* peer, int timeout_ms)
{
    librdp_status status = LIBRDP_STATUS_OK;

    while (librdp_server_peer_get_state(peer) != LIBRDP_SERVER_PEER_CLOSED &&
           librdp_server_peer_get_state(peer) != LIBRDP_SERVER_PEER_FAILED)
    {
        status = librdp_server_peer_run_once(peer, timeout_ms);
        printf("peer status=%s state=%d\n",
               librdp_status_name(status),
               (int)librdp_server_peer_get_state(peer));
        if (status == LIBRDP_STATUS_TIMEOUT &&
            librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_ACTIVE)
            return 0;
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
            return status == LIBRDP_STATUS_UNSUPPORTED ? 3 : 2;
    }
    return librdp_server_peer_get_state(peer) == LIBRDP_SERVER_PEER_CLOSED ? 0 : 2;
}

int main(int argc, char** argv)
{
    server_listener_options options;
    librdp_server_config config;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

    if (!server_listener_parse_args(argc, argv, &options))
    {
        server_listener_usage(stderr, argv[0]);
        return 2;
    }
    if (librdp_server_config_init(&config) != LIBRDP_STATUS_OK)
        return 2;
    config.bind_address = options.bind_address;
    config.port = options.port;
    server = librdp_server_new(&config);
    if (!server)
        return 2;
    status = librdp_server_listen(server);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "listen failed: %s\n", librdp_status_name(status));
        librdp_server_free(server);
        return 2;
    }
    printf("listening address=%s port=%u\n",
           options.bind_address,
           (unsigned)librdp_server_local_port(server));
    fflush(stdout);
    status = librdp_server_accept(server, options.timeout_ms, &peer);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "accept failed: %s\n", librdp_status_name(status));
        librdp_server_free(server);
        return status == LIBRDP_STATUS_TIMEOUT ? 3 : 2;
    }
    rc = server_listener_run_peer(peer, options.timeout_ms);
    librdp_server_peer_free(peer);
    librdp_server_free(server);
    return rc;
}
