/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic pointer-update server for the real X11 viewer smoke.
 * Coverage: public server lifecycle and normalized default, hidden, position,
 * shape, and cached pointer updates over an activated RDP connection.
 * Bug classes: dropped updates, invalid cache sequencing, wire conversion
 * errors, premature teardown, blocked dispatch, and acknowledgement races.
 * Determinism: fixed pointer pixels and stage acknowledgements make every
 * observed server transition reproducible.
 * Synchronization: every update waits for an atomic acknowledgement from the
 * observing X11 process while peer input continues to be dispatched.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "test_process_state.h"
#include "test_viewer_pointer_fixture.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POINTER_SERVER_WAIT_STEPS 750u

static librdp_status pointer_server_accept_active(
    librdp_server* server,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!server || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS && !*peer;
         attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status != LIBRDP_STATUS_TIMEOUT &&
            status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!*peer)
        return LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        if (librdp_server_peer_get_state(*peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(*peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status pointer_server_wait_ack(
    librdp_server_peer* peer,
    const char* ack_path,
    uint16_t port,
    uint32_t expected_stage)
{
    unsigned int attempt = 0u;

    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        uint16_t ack_port = 0u;
        uint32_t ack_stage = 0u;
        librdp_status status = LIBRDP_STATUS_OK;

        if (test_process_state_read(ack_path,
                                    &ack_port,
                                    &ack_stage) &&
            ack_port == port &&
            ack_stage >= expected_stage)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status pointer_server_send(
    librdp_server_peer* peer,
    const char* state_path,
    const char* ack_path,
    uint16_t port,
    librdp_server_pointer_update* update,
    uint32_t stage)
{
    librdp_status status =
        librdp_server_peer_send_pointer_update(peer, update);

    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!test_process_state_write(state_path, port, stage))
        return LIBRDP_STATUS_IO_ERROR;
    return pointer_server_wait_ack(peer,
                                   ack_path,
                                   port,
                                   stage);
}

static void pointer_server_fill_shape(
    uint8_t pixels[TEST_VIEWER_POINTER_WIDTH *
                   TEST_VIEWER_POINTER_HEIGHT * 4u])
{
    uint16_t y = 0u;
    uint16_t x = 0u;

    for (y = 0u; y < TEST_VIEWER_POINTER_HEIGHT; y++)
    {
        for (x = 0u; x < TEST_VIEWER_POINTER_WIDTH; x++)
        {
            uint32_t argb = test_viewer_pointer_argb(x, y);
            size_t offset =
                ((size_t)y * TEST_VIEWER_POINTER_WIDTH + x) * 4u;

            pixels[offset] = (uint8_t)(argb & 0xffu);
            pixels[offset + 1u] =
                (uint8_t)((argb >> 8u) & 0xffu);
            pixels[offset + 2u] =
                (uint8_t)((argb >> 16u) & 0xffu);
            pixels[offset + 3u] =
                (uint8_t)((argb >> 24u) & 0xffu);
        }
    }
}

static librdp_status pointer_server_wait_close(
    librdp_server_peer* peer)
{
    unsigned int attempt = 0u;

    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);

        if (status == LIBRDP_STATUS_CLOSED ||
            status == LIBRDP_STATUS_IO_ERROR ||
            librdp_server_peer_get_state(peer) ==
                LIBRDP_SERVER_PEER_CLOSED)
            return LIBRDP_STATUS_OK;
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

int main(int argc, char** argv)
{
    uint8_t shape[TEST_VIEWER_POINTER_WIDTH *
                  TEST_VIEWER_POINTER_HEIGHT * 4u];
    librdp_server_config config;
    librdp_server_pointer_update update;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    int result = 1;

    memset(shape, 0, sizeof(shape));
    if (argc != 3)
    {
        fprintf(stderr,
                "usage: test_viewer_pointer_server state-file ack-file\n");
        return 2;
    }
    status = librdp_server_config_init(&config);
    if (status != LIBRDP_STATUS_OK)
        return 1;
    config.bind_address = "127.0.0.1";
    config.security_mode = LIBRDP_SECURITY_STANDARD;
    config.width = TEST_VIEWER_POINTER_DESKTOP_WIDTH;
    config.height = TEST_VIEWER_POINTER_DESKTOP_HEIGHT;
    server = librdp_server_new(&config);
    if (!server)
        return 1;
    status = librdp_server_listen(server);
    if (status != LIBRDP_STATUS_OK)
        goto cleanup;
    port = librdp_server_local_port(server);
    if (!test_process_state_write(
            argv[1],
            port,
            TEST_VIEWER_POINTER_LISTENING))
    {
        status = LIBRDP_STATUS_IO_ERROR;
        goto cleanup;
    }
    status = pointer_server_accept_active(server, &peer);
    if (status != LIBRDP_STATUS_OK)
        goto cleanup;

    status = librdp_server_pointer_update_init(&update);
    if (status == LIBRDP_STATUS_OK)
    {
        update.type = LIBRDP_SERVER_POINTER_DEFAULT;
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_DEFAULT);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        pointer_server_fill_shape(shape);
        status = librdp_server_pointer_update_init(&update);
        update.type = LIBRDP_SERVER_POINTER_SHAPE;
        update.cache_index = TEST_VIEWER_POINTER_CACHE_INDEX;
        update.hotspot_x = TEST_VIEWER_POINTER_HOTSPOT_X;
        update.hotspot_y = TEST_VIEWER_POINTER_HOTSPOT_Y;
        update.width = TEST_VIEWER_POINTER_WIDTH;
        update.height = TEST_VIEWER_POINTER_HEIGHT;
        update.stride = TEST_VIEWER_POINTER_WIDTH * 4u;
        update.pixels = shape;
        update.pixels_len = sizeof(shape);
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_SHAPE);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_pointer_update_init(&update);
        update.type = LIBRDP_SERVER_POINTER_POSITION;
        update.x = TEST_VIEWER_POINTER_POSITION_X;
        update.y = TEST_VIEWER_POINTER_POSITION_Y;
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_POSITION);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_pointer_update_init(&update);
        update.type = LIBRDP_SERVER_POINTER_CACHED;
        update.cache_index = TEST_VIEWER_POINTER_CACHE_INDEX;
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_CACHED);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_pointer_update_init(&update);
        update.type = LIBRDP_SERVER_POINTER_HIDDEN;
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_HIDDEN);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_pointer_update_init(&update);
        update.type = LIBRDP_SERVER_POINTER_DEFAULT;
        status = pointer_server_send(
            peer,
            argv[1],
            argv[2],
            port,
            &update,
            TEST_VIEWER_POINTER_RESTORED);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_COMPLETE))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_close(peer);
    }
    result = status == LIBRDP_STATUS_OK ? 0 : 1;

cleanup:
    if (result != 0)
        fprintf(stderr,
                "pointer server failed status=%s\n",
                librdp_status_name(status));
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        librdp_server_close(server);
        librdp_server_free(server);
    }
    return result;
}
