/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic HTTP CONNECT proxy fixture.
 * Coverage: Digest authentication, credential separation, CONNECT routing,
 * and bidirectional forwarding for client gateway smoke tests.
 * Bug classes: credential leakage, wrong target routing, partial I/O, and
 * tunnel teardown races.
 * Determinism: the proxy listens only on loopback and forwards to one
 * loopback target selected by the test.
 */

#ifndef LIBRDP_TEST_HTTP_PROXY_H
#define LIBRDP_TEST_HTTP_PROXY_H

#include <librdp/error.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

typedef struct test_http_proxy_config
{
    const char* target_host;
    uint16_t target_port;
    const char* gateway_username;
    const char* gateway_password;
    const char* gateway_domain;
    const char* forbidden_username;
    const char* forbidden_password;
    const char* forbidden_domain;
} test_http_proxy_config;

typedef struct test_http_proxy
{
    test_http_proxy_config config;
    pthread_t thread;
    pthread_mutex_t lock;
    atomic_uint authenticated;
    atomic_uint forwarded;
    atomic_uint credential_leak;
    atomic_uint stop;
    int listener_fd;
    int client_fd;
    int target_fd;
    uint16_t port;
    int thread_started;
    librdp_status status;
} test_http_proxy;

int test_http_proxy_start(test_http_proxy* proxy,
                          const test_http_proxy_config* config);

void test_http_proxy_cancel(test_http_proxy* proxy);

int test_http_proxy_join(test_http_proxy* proxy);

void test_http_proxy_clear(test_http_proxy* proxy);

#endif
