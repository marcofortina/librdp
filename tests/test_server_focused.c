/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused server peer lifecycle, channel, and graphics tests.
 * Coverage: accepted-peer ownership, pre-activation state gates, surface
 * storage, provider state, and idempotent shutdown.
 * Bug classes: invalid state, stale channel state, framebuffer bounds, and
 * resource cleanup.
 * Determinism: every peer uses an ephemeral loopback listener.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

#include <string.h>
#include <unistd.h>

typedef struct test_server_peer_fixture
{
    librdp_server* server;
    librdp_server_peer* peer;
    int client_fd;
} test_server_peer_fixture;

static int test_server_peer_fixture_open(test_server_peer_fixture* fixture)
{
    librdp_server_config config;
    uint16_t port = 0;

    if (!fixture)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
    if (librdp_server_config_init(&config) != LIBRDP_STATUS_OK)
        return 0;
    config.bind_address = "127.0.0.1";
    fixture->server = librdp_server_new(&config);
    if (!fixture->server || librdp_server_listen(fixture->server) != LIBRDP_STATUS_OK)
        return 0;
    port = librdp_server_local_port(fixture->server);
    fixture->client_fd = test_server_connect_loopback(port);
    if (fixture->client_fd < 0 ||
        librdp_server_accept(fixture->server, 1000, &fixture->peer) != LIBRDP_STATUS_OK)
        return 0;
    return 1;
}

static void test_server_peer_fixture_close(test_server_peer_fixture* fixture)
{
    if (!fixture)
        return;
    librdp_server_peer_free(fixture->peer);
    if (fixture->client_fd >= 0)
        close(fixture->client_fd);
    librdp_server_close(fixture->server);
    librdp_server_free(fixture->server);
    memset(fixture, 0, sizeof(*fixture));
    fixture->client_fd = -1;
}

int test_server_lifecycle_focused(void)
{
    test_server_peer_fixture fixture;
    struct pollfd pollfd;
    size_t count = 0;

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_NEW);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, &pollfd, 1, &count) == LIBRDP_STATUS_OK);
    SCHECK(count == 1);
    SCHECK(pollfd.fd >= 0);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_state(fixture.peer) == LIBRDP_SERVER_PEER_CLOSED);
    SCHECK(librdp_server_peer_close(fixture.peer) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_pollfds(fixture.peer, NULL, 0, &count) == LIBRDP_STATUS_STATE);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

int test_server_channels_focused(void)
{
    test_server_peer_fixture fixture;
    librdp_server_dynamic_channel_info channel_info;
    int provider_enabled = 0;
    static const uint8_t payload[] = { 0x11, 0x22 };

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_set_channel_callback(fixture.peer, test_server_channel_callback, NULL) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_set_dynamic_channel_accept_callback(
               fixture.peer, test_server_dynamic_channel_accept_callback, NULL) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_dynamic_channel_count(fixture.peer) == 0);
    SCHECK(librdp_server_peer_dynamic_channel_at(fixture.peer, 0, &channel_info) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_send_channel_data(fixture.peer, 1003, payload, sizeof(payload)) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_open_dynamic_channel(fixture.peer, 1, 0, "test") ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 1) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 1);
    SCHECK(librdp_server_peer_enable_extension_provider(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, 0) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_extension_provider_status(
               fixture.peer, LIBRDP_SERVER_EXTENSION_CLIPBOARD, &provider_enabled) == LIBRDP_STATUS_OK);
    SCHECK(provider_enabled == 0);
    test_server_peer_fixture_close(&fixture);
    return 0;
}

int test_server_graphics_focused(void)
{
    test_server_peer_fixture fixture;
    static const uint8_t pixels[] = {
        0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff,
        0x70, 0x80, 0x90, 0xff, 0xa0, 0xb0, 0xc0, 0xff,
    };

    SCHECK(test_server_peer_fixture_open(&fixture));
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) == 1024);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) == 768);
    SCHECK(librdp_server_peer_surface_resize(fixture.peer, 8, 6) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_desktop_width(fixture.peer) == 8);
    SCHECK(librdp_server_peer_desktop_height(fixture.peer) == 6);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer, 2, 1, 2, 2, 8, pixels) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_surface_blit_bgra32(
               fixture.peer, 7, 5, 2, 2, 8, pixels) == LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_surface_present(fixture.peer, 2, 1, 2, 2) ==
           LIBRDP_STATUS_STATE);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    SCHECK(librdp_server_peer_set_graphics_frame_queue_limit(fixture.peer, 4) ==
           LIBRDP_STATUS_OK);
    test_server_peer_fixture_close(&fixture);
    return 0;
}
