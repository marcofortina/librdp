/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server transport backpressure tests.
 * Coverage: a joined static channel writing to a non-reading peer.
 * Bug classes: unbounded output retention, blocked dispatch and committed
 * channel metrics after a partial transport write.
 * Determinism: one nonblocking local socket pair provides bounded pressure.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

#include "server/server_internal.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SERVER_BACKPRESSURE_PAYLOAD_BYTES (8u * 1024u * 1024u)

/* Read the monotonic clock used to bound the deliberately stalled send. */
static uint64_t server_backpressure_now_ns(void)
{
    struct timespec timestamp;

    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0)
        return 0u;
    return (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
           (uint64_t)timestamp.tv_nsec;
}

/*
 * Fill the transport without reading from its peer. The synchronous send path
 * must stop at its bounded poll deadline, release every fragment buffer and
 * avoid committing the logical channel message as delivered.
 */
int test_server_backpressure_focused(void)
{
    static const char channel_name[] = "testvc";
    librdp_server_peer peer;
    uint8_t* payload = NULL;
    uint64_t started_ns = 0u;
    uint64_t elapsed_ns = 0u;
    int descriptors[2] = {-1, -1};
    int socket_buffer = 4096;
    int flags = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&peer, 0, sizeof(peer));
    SCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) == 0);
    flags = fcntl(descriptors[0], F_GETFL, 0);
    SCHECK(flags >= 0);
    SCHECK(fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0);
    SCHECK(setsockopt(descriptors[0],
                      SOL_SOCKET,
                      SO_SNDBUF,
                      &socket_buffer,
                      (socklen_t)sizeof(socket_buffer)) == 0);
    SCHECK(setsockopt(descriptors[1],
                      SOL_SOCKET,
                      SO_RCVBUF,
                      &socket_buffer,
                      (socklen_t)sizeof(socket_buffer)) == 0);

    payload = (uint8_t*)malloc(SERVER_BACKPRESSURE_PAYLOAD_BYTES);
    SCHECK(payload != NULL);
    memset(payload, 0x5au, SERVER_BACKPRESSURE_PAYLOAD_BYTES);
    peer.fd = descriptors[0];
    peer.state = LIBRDP_SERVER_PEER_ACTIVE;
    peer.user_id = (uint16_t)RDP_MCS_BASE_CHANNEL_ID;
    peer.advertised_channel_count = 1u;
    peer.advertised_channel_ids[0] =
        (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    peer.advertised_channel_joined[0] = 1u;
    memcpy(peer.advertised_channels[0].name,
           channel_name,
           sizeof(channel_name));
    SCHECK(librdp_server_metrics_init(&peer.metrics) == LIBRDP_STATUS_OK);

    started_ns = server_backpressure_now_ns();
    SCHECK(started_ns != 0u);
    status = librdp_server_peer_send_channel_data(
        &peer,
        peer.advertised_channel_ids[0],
        payload,
        SERVER_BACKPRESSURE_PAYLOAD_BYTES);
    elapsed_ns = server_backpressure_now_ns() - started_ns;
    SCHECK(status == LIBRDP_STATUS_TIMEOUT);
    SCHECK(elapsed_ns < UINT64_C(3000000000));
    SCHECK(peer.metrics.static_channel_out == 0u);
    SCHECK(peer.metrics.static_channel_bytes_out == 0u);
    SCHECK(peer.metrics.bytes_written < SERVER_BACKPRESSURE_PAYLOAD_BYTES);

    free(payload);
    close(descriptors[0]);
    close(descriptors[1]);
    return 0;
}
