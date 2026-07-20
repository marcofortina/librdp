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

#ifndef LIBRDP_TEST_RDG_GATEWAY_H
#define LIBRDP_TEST_RDG_GATEWAY_H

#include <librdp/error.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

typedef struct test_rdg_gateway_config
{
    const char* target_host;
    uint16_t target_port;
    const char* certificate_path;
    const char* private_key_path;
} test_rdg_gateway_config;

typedef struct test_rdg_gateway
{
    test_rdg_gateway_config config;
    pthread_t thread;
    pthread_mutex_t lock;
    atomic_uint stop;
    atomic_uint out_stream;
    atomic_uint in_stream;
    atomic_uint handshake;
    atomic_uint tunnel;
    atomic_uint authorized;
    atomic_uint channel;
    atomic_uint downstream_sent;
    atomic_uint downstream_received;
    int listener_fd;
    int out_fd;
    int in_fd;
    int target_fd;
    uint16_t port;
    int thread_started;
    librdp_status status;
} test_rdg_gateway;

int test_rdg_gateway_start(test_rdg_gateway* gateway,
                           const test_rdg_gateway_config* config);

void test_rdg_gateway_cancel(test_rdg_gateway* gateway);

int test_rdg_gateway_join(test_rdg_gateway* gateway);

void test_rdg_gateway_clear(test_rdg_gateway* gateway);

#endif
