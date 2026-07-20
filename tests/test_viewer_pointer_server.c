/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic pointer-update server for the real X11 viewer smoke.
 * Coverage: public server lifecycle, normalized pointer updates, and ordered
 * classic/extended mouse input over an activated RDP connection.
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

#include "protocol/pointer.h"
#include "server/server_extensions.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POINTER_SERVER_WAIT_STEPS 750u

typedef struct pointer_server_wire_shape
{
    rdp_pointer_update update;
    uint8_t* xor_mask;
    uint8_t* and_mask;
} pointer_server_wire_shape;

typedef struct pointer_server_expected_input
{
    librdp_server_input_type type;
    uint16_t flags;
    uint16_t param1;
} pointer_server_expected_input;

typedef struct pointer_server_input_context
{
    size_t mouse_received;
    size_t keyboard_received;
    size_t focus_received;
    int mouse_armed;
    int keyboard_armed;
    int focus_armed;
    int failed;
} pointer_server_input_context;

static const pointer_server_expected_input pointer_server_mouse_sequence[] = {
    { LIBRDP_SERVER_INPUT_MOUSE, 0x0800u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x9000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x1000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0xa000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x2000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0xc000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x4000u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x0278u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x0388u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x0588u, 0u },
    { LIBRDP_SERVER_INPUT_MOUSE, 0x0478u, 0u },
    { LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x8001u, 0u },
    { LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x0001u, 0u },
    { LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x8002u, 0u },
    { LIBRDP_SERVER_INPUT_EXTENDED_MOUSE, 0x0002u, 0u },
};

static const pointer_server_expected_input
    pointer_server_keyboard_sequence[] = {
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0000u, 0x001eu },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8000u, 0x001eu },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0100u, 0x004du },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8100u, 0x004du },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0000u, 0x002au },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0000u, 0x001eu },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8000u, 0x001eu },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8000u, 0x002au },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0000u, 0x001eu },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8000u, 0x001eu },
};

static const pointer_server_expected_input
    pointer_server_focus_sequence[] = {
        { LIBRDP_SERVER_INPUT_MOUSE, 0x9000u, 0u },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x0000u, 0x002au },
        { LIBRDP_SERVER_INPUT_SCANCODE_KEY, 0x8000u, 0x002au },
        { LIBRDP_SERVER_INPUT_MOUSE, 0x1000u, 0u },
};

static int pointer_server_input_matches(
    const librdp_server_input_event* event,
    const pointer_server_expected_input* expected)
{
    if (!event || !expected ||
        event->type != expected->type ||
        event->flags != expected->flags)
        return 0;
    if (event->type == LIBRDP_SERVER_INPUT_MOUSE ||
        event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE)
        return event->x == TEST_VIEWER_POINTER_MOUSE_X &&
               event->y == TEST_VIEWER_POINTER_MOUSE_Y;
    return event->param1 == expected->param1 &&
           event->param2 == 0u;
}

static void pointer_server_input_callback(
    librdp_server_peer* peer,
    const librdp_server_input_event* event,
    void* user_data)
{
    pointer_server_input_context* context =
        (pointer_server_input_context*)user_data;
    const pointer_server_expected_input* expected = NULL;

    (void)peer;
    if (!context || !event)
        return;
    if (context->focus_armed)
    {
        if (context->focus_received >=
            sizeof(pointer_server_focus_sequence) /
                sizeof(pointer_server_focus_sequence[0]))
        {
            context->failed = 1;
            return;
        }
        expected =
            &pointer_server_focus_sequence[
                context->focus_received];
        if (!pointer_server_input_matches(event,
                                          expected))
        {
            fprintf(stderr,
                    "focus input mismatch index=%lu type=%u flags=0x%04x param1=0x%04x x=%u y=%u expected_type=%u expected_flags=0x%04x expected_param1=0x%04x\n",
                    (unsigned long)context->focus_received,
                    (unsigned int)event->type,
                    event->flags,
                    event->param1,
                    event->x,
                    event->y,
                    (unsigned int)expected->type,
                    expected->flags,
                    expected->param1);
            context->failed = 1;
            return;
        }
        context->focus_received++;
        return;
    }
    if (context->mouse_armed &&
        (event->type == LIBRDP_SERVER_INPUT_MOUSE ||
         event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE))
    {
        if (context->mouse_received >=
            sizeof(pointer_server_mouse_sequence) /
                sizeof(pointer_server_mouse_sequence[0]))
        {
            context->failed = 1;
            return;
        }
        expected =
            &pointer_server_mouse_sequence[
                context->mouse_received];
        if (event->type != expected->type ||
            event->flags != expected->flags ||
            event->x != TEST_VIEWER_POINTER_MOUSE_X ||
            event->y != TEST_VIEWER_POINTER_MOUSE_Y)
        {
            fprintf(stderr,
                    "mouse event mismatch index=%lu type=%u flags=0x%04x x=%u y=%u expected_type=%u expected_flags=0x%04x\n",
                    (unsigned long)context->mouse_received,
                    (unsigned int)event->type,
                    event->flags,
                    event->x,
                    event->y,
                    (unsigned int)expected->type,
                    expected->flags);
            context->failed = 1;
            return;
        }
        context->mouse_received++;
        return;
    }
    if (!context->keyboard_armed ||
        (event->type != LIBRDP_SERVER_INPUT_SCANCODE_KEY &&
         event->type != LIBRDP_SERVER_INPUT_UNICODE_KEY))
        return;
    if (context->keyboard_received >=
        sizeof(pointer_server_keyboard_sequence) /
            sizeof(pointer_server_keyboard_sequence[0]))
    {
        context->failed = 1;
        return;
    }
    expected =
        &pointer_server_keyboard_sequence[
            context->keyboard_received];
    if (event->type != expected->type ||
        event->flags != expected->flags ||
        event->param1 != expected->param1 ||
        event->param2 != 0u)
    {
        fprintf(stderr,
                "keyboard event mismatch index=%lu type=%u flags=0x%04x param1=0x%04x param2=0x%04x expected_type=%u expected_flags=0x%04x expected_param1=0x%04x\n",
                (unsigned long)context->keyboard_received,
                (unsigned int)event->type,
                event->flags,
                event->param1,
                event->param2,
                (unsigned int)expected->type,
                expected->flags,
                expected->param1);
        context->failed = 1;
        return;
    }
    context->keyboard_received++;
}

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

static size_t pointer_server_mask_stride(uint16_t width)
{
    return (((size_t)width + 15u) / 16u) * 2u;
}

static size_t pointer_server_xor_stride(uint16_t width,
                                        uint16_t bpp)
{
    return ((((size_t)width * bpp) + 15u) / 16u) * 2u;
}

static void pointer_server_set_mask_bit(uint8_t* mask,
                                        size_t stride,
                                        uint16_t height,
                                        uint16_t x,
                                        uint16_t y)
{
    size_t row = (size_t)(height - 1u - y);

    mask[row * stride + (size_t)x / 8u] |=
        (uint8_t)(0x80u >> (x % 8u));
}

static librdp_status pointer_server_wire_shape_init(
    enum test_viewer_pointer_shape shape,
    pointer_server_wire_shape* wire)
{
    size_t xor_stride = 0u;
    size_t and_stride = 0u;
    size_t xor_length = 0u;
    size_t and_length = 0u;
    uint16_t y = 0u;
    uint16_t x = 0u;

    if (!wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(wire, 0, sizeof(*wire));
    wire->update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    switch (shape)
    {
        case TEST_VIEWER_POINTER_SHAPE_MONOCHROME:
            wire->update.shape_format =
                RDP_POINTER_SHAPE_FORMAT_NEW;
            wire->update.cache_index =
                TEST_VIEWER_POINTER_MONOCHROME_CACHE_INDEX;
            wire->update.hot_x =
                TEST_VIEWER_POINTER_MONOCHROME_HOTSPOT_X;
            wire->update.hot_y =
                TEST_VIEWER_POINTER_MONOCHROME_HOTSPOT_Y;
            wire->update.width =
                TEST_VIEWER_POINTER_MONOCHROME_WIDTH;
            wire->update.height =
                TEST_VIEWER_POINTER_MONOCHROME_HEIGHT;
            wire->update.xor_bpp = 1u;
            break;
        case TEST_VIEWER_POINTER_SHAPE_COLOR:
            wire->update.shape_format =
                RDP_POINTER_SHAPE_FORMAT_COLOR;
            wire->update.cache_index =
                TEST_VIEWER_POINTER_COLOR_CACHE_INDEX;
            wire->update.hot_x =
                TEST_VIEWER_POINTER_COLOR_HOTSPOT_X;
            wire->update.hot_y =
                TEST_VIEWER_POINTER_COLOR_HOTSPOT_Y;
            wire->update.width = TEST_VIEWER_POINTER_COLOR_WIDTH;
            wire->update.height =
                TEST_VIEWER_POINTER_COLOR_HEIGHT;
            wire->update.xor_bpp = 24u;
            break;
        case TEST_VIEWER_POINTER_SHAPE_ALPHA:
            wire->update.shape_format =
                RDP_POINTER_SHAPE_FORMAT_NEW;
            wire->update.cache_index =
                TEST_VIEWER_POINTER_ALPHA_CACHE_INDEX;
            wire->update.hot_x =
                TEST_VIEWER_POINTER_ALPHA_HOTSPOT_X;
            wire->update.hot_y =
                TEST_VIEWER_POINTER_ALPHA_HOTSPOT_Y;
            wire->update.width = TEST_VIEWER_POINTER_ALPHA_WIDTH;
            wire->update.height =
                TEST_VIEWER_POINTER_ALPHA_HEIGHT;
            wire->update.xor_bpp = 32u;
            break;
        case TEST_VIEWER_POINTER_SHAPE_LARGE:
            wire->update.shape_format =
                RDP_POINTER_SHAPE_FORMAT_LARGE;
            wire->update.cache_index =
                TEST_VIEWER_POINTER_LARGE_CACHE_INDEX;
            wire->update.hot_x =
                TEST_VIEWER_POINTER_LARGE_HOTSPOT_X;
            wire->update.hot_y =
                TEST_VIEWER_POINTER_LARGE_HOTSPOT_Y;
            wire->update.width = TEST_VIEWER_POINTER_LARGE_WIDTH;
            wire->update.height =
                TEST_VIEWER_POINTER_LARGE_HEIGHT;
            wire->update.xor_bpp = 32u;
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    xor_stride = pointer_server_xor_stride(
        wire->update.width,
        wire->update.xor_bpp);
    and_stride = pointer_server_mask_stride(wire->update.width);
    if (xor_stride == 0u || and_stride == 0u ||
        (size_t)wire->update.height > SIZE_MAX / xor_stride ||
        (size_t)wire->update.height > SIZE_MAX / and_stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    xor_length = xor_stride * wire->update.height;
    and_length = and_stride * wire->update.height;
    wire->xor_mask = (uint8_t*)calloc(1u, xor_length);
    wire->and_mask = (uint8_t*)calloc(1u, and_length);
    if (!wire->xor_mask || !wire->and_mask)
    {
        free(wire->and_mask);
        free(wire->xor_mask);
        memset(wire, 0, sizeof(*wire));
        return LIBRDP_STATUS_NO_MEMORY;
    }
    wire->update.xor_mask = wire->xor_mask;
    wire->update.xor_mask_len = xor_length;
    wire->update.and_mask = wire->and_mask;
    wire->update.and_mask_len = and_length;
    for (y = 0u; y < wire->update.height; y++)
    {
        size_t row =
            (size_t)(wire->update.height - 1u - y);

        for (x = 0u; x < wire->update.width; x++)
        {
            if (shape == TEST_VIEWER_POINTER_SHAPE_MONOCHROME)
            {
                uint32_t mode =
                    (((uint32_t)x / 4u) +
                     ((uint32_t)y / 4u)) % 4u;

                if (mode == 1u || mode == 3u)
                {
                    pointer_server_set_mask_bit(
                        wire->xor_mask,
                        xor_stride,
                        wire->update.height,
                        x,
                        y);
                }
                if (mode == 2u || mode == 3u)
                {
                    pointer_server_set_mask_bit(
                        wire->and_mask,
                        and_stride,
                        wire->update.height,
                        x,
                        y);
                }
            }
            else
            {
                uint32_t argb =
                    test_viewer_pointer_shape_argb(shape, x, y);
                size_t bytes_per_pixel =
                    (size_t)wire->update.xor_bpp / 8u;
                size_t offset =
                    row * xor_stride +
                    (size_t)x * bytes_per_pixel;

                wire->xor_mask[offset] =
                    (uint8_t)(argb & 0xffu);
                wire->xor_mask[offset + 1u] =
                    (uint8_t)((argb >> 8u) & 0xffu);
                wire->xor_mask[offset + 2u] =
                    (uint8_t)((argb >> 16u) & 0xffu);
                if (bytes_per_pixel == 4u)
                {
                    wire->xor_mask[offset + 3u] =
                        (uint8_t)((argb >> 24u) & 0xffu);
                }
            }
        }
    }
    return LIBRDP_STATUS_OK;
}

static void pointer_server_wire_shape_clear(
    pointer_server_wire_shape* wire)
{
    if (!wire)
        return;
    free(wire->and_mask);
    free(wire->xor_mask);
    memset(wire, 0, sizeof(*wire));
}

static librdp_status pointer_server_send_wire_shape(
    librdp_server_peer* peer,
    const char* state_path,
    const char* ack_path,
    uint16_t port,
    enum test_viewer_pointer_shape shape,
    uint32_t stage)
{
    pointer_server_wire_shape wire;
    librdp_status status =
        pointer_server_wire_shape_init(shape, &wire);

    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_peer_send_pointer_wire_update(
            peer,
            &wire.update);
    }
    if (status == LIBRDP_STATUS_OK &&
        !test_process_state_write(state_path, port, stage))
        status = LIBRDP_STATUS_IO_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = pointer_server_wait_ack(peer,
                                         ack_path,
                                         port,
                                         stage);
    pointer_server_wire_shape_clear(&wire);
    return status;
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

static librdp_status pointer_server_wait_mouse(
    librdp_server_peer* peer,
    pointer_server_input_context* context)
{
    unsigned int attempt = 0u;
    const size_t expected_count =
        sizeof(pointer_server_mouse_sequence) /
        sizeof(pointer_server_mouse_sequence[0]);

    if (!peer || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (context->failed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (context->mouse_received == expected_count)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status pointer_server_wait_keyboard(
    librdp_server_peer* peer,
    pointer_server_input_context* context)
{
    unsigned int attempt = 0u;
    const size_t expected_count =
        sizeof(pointer_server_keyboard_sequence) /
        sizeof(pointer_server_keyboard_sequence[0]);

    if (!peer || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (context->failed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (context->keyboard_received == expected_count)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status pointer_server_wait_focus(
    librdp_server_peer* peer,
    pointer_server_input_context* context)
{
    unsigned int attempt = 0u;
    const size_t expected_count =
        sizeof(pointer_server_focus_sequence) /
        sizeof(pointer_server_focus_sequence[0]);

    if (!peer || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        librdp_status status = LIBRDP_STATUS_OK;

        if (context->failed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (context->focus_received == expected_count)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

static librdp_status pointer_server_wait_focus_settle(
    librdp_server_peer* peer,
    pointer_server_input_context* context,
    const char* ack_path,
    uint16_t port)
{
    unsigned int attempt = 0u;
    int acknowledged = 0;

    if (!peer || !context || !ack_path)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u;
         attempt < POINTER_SERVER_WAIT_STEPS;
         attempt++)
    {
        uint16_t ack_port = 0u;
        uint32_t ack_stage = 0u;
        librdp_status status = LIBRDP_STATUS_OK;

        if (context->failed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (test_process_state_read(ack_path,
                                    &ack_port,
                                    &ack_stage) &&
            ack_port == port &&
            ack_stage >=
                TEST_VIEWER_POINTER_FOCUS_RELEASED)
        {
            acknowledged = 1;
            break;
        }
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    if (!acknowledged)
        return LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u; attempt < 20u; attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);

        if (context->failed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return context->failed
               ? LIBRDP_STATUS_PROTOCOL_ERROR
               : LIBRDP_STATUS_OK;
}

int main(int argc, char** argv)
{
    uint8_t shape[TEST_VIEWER_POINTER_WIDTH *
                  TEST_VIEWER_POINTER_HEIGHT * 4u];
    librdp_server_config config;
    librdp_server_pointer_update update;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    pointer_server_input_context input_context;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    int result = 1;

    memset(shape, 0, sizeof(shape));
    memset(&input_context, 0, sizeof(input_context));
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
    status = librdp_server_peer_set_input_callback(
        peer,
        pointer_server_input_callback,
        &input_context);
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
        status = pointer_server_send_wire_shape(
            peer,
            argv[1],
            argv[2],
            port,
            TEST_VIEWER_POINTER_SHAPE_MONOCHROME,
            TEST_VIEWER_POINTER_MONOCHROME);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = pointer_server_send_wire_shape(
            peer,
            argv[1],
            argv[2],
            port,
            TEST_VIEWER_POINTER_SHAPE_COLOR,
            TEST_VIEWER_POINTER_COLOR);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = pointer_server_send_wire_shape(
            peer,
            argv[1],
            argv[2],
            port,
            TEST_VIEWER_POINTER_SHAPE_ALPHA,
            TEST_VIEWER_POINTER_ALPHA);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = pointer_server_send_wire_shape(
            peer,
            argv[1],
            argv[2],
            port,
            TEST_VIEWER_POINTER_SHAPE_LARGE,
            TEST_VIEWER_POINTER_LARGE);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_RESIZE_FOCUS))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_ack(
                peer,
                argv[2],
                port,
                TEST_VIEWER_POINTER_RESIZE_FOCUS);
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
        input_context.mouse_armed = 1;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_MOUSE_READY))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_mouse(
                peer,
                &input_context);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        input_context.mouse_armed = 0;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_MOUSE_COMPLETE))
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        input_context.keyboard_armed = 1;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_KEYBOARD_READY))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_keyboard(
                peer,
                &input_context);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        input_context.keyboard_armed = 0;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_KEYBOARD_COMPLETE))
            status = LIBRDP_STATUS_IO_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        input_context.focus_armed = 1;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_FOCUS_READY))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_focus(
                peer,
                &input_context);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_FOCUS_RELEASED))
            status = LIBRDP_STATUS_IO_ERROR;
        else
            status = pointer_server_wait_focus_settle(
                peer,
                &input_context,
                argv[2],
                port);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        input_context.focus_armed = 0;
        if (!test_process_state_write(
                argv[1],
                port,
                TEST_VIEWER_POINTER_FOCUS_COMPLETE))
            status = LIBRDP_STATUS_IO_ERROR;
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
