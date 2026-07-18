/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: pointer shape decoder declaration contract.
 * Invariants: wire lengths, tags, and stream offsets must remain synchronized
 * across parse and write helpers.
 * Ownership: parsed views borrow input bytes and serialized buffers are
 * caller-owned.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: all network bytes are untrusted until parsed by the declared
 * helper.
 */


#ifndef RDP_PROTOCOL_POINTER_H
#define RDP_PROTOCOL_POINTER_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_UPDATE_TYPE_POINTER 0x0009u
#define RDP_POINTER_MESSAGE_TYPE_SYSTEM 0x0001u
#define RDP_POINTER_MESSAGE_TYPE_POSITION 0x0003u
#define RDP_POINTER_MESSAGE_TYPE_COLOR 0x0006u
#define RDP_POINTER_MESSAGE_TYPE_CACHED 0x0007u
#define RDP_POINTER_MESSAGE_TYPE_POINTER 0x0008u
#define RDP_POINTER_MESSAGE_TYPE_LARGE 0x0009u
#define RDP_POINTER_SYSTEM_NULL 0x00000000u
#define RDP_POINTER_SYSTEM_DEFAULT 0x00007f00u
#define RDP_POINTER_MAX_DIMENSION 512u

typedef enum rdp_pointer_update_kind
{
    RDP_POINTER_UPDATE_KIND_NULL = 0,
    RDP_POINTER_UPDATE_KIND_DEFAULT = 1,
    RDP_POINTER_UPDATE_KIND_POSITION = 2,
    RDP_POINTER_UPDATE_KIND_CACHED = 3,
    RDP_POINTER_UPDATE_KIND_SHAPE = 4
} rdp_pointer_update_kind;

typedef struct rdp_pointer_update
{
    rdp_pointer_update_kind kind;
    uint16_t cache_index;
    uint16_t x;
    uint16_t y;
    uint16_t hot_x;
    uint16_t hot_y;
    uint16_t width;
    uint16_t height;
    uint16_t xor_bpp;
    const uint8_t* xor_mask;
    size_t xor_mask_len;
    const uint8_t* and_mask;
    size_t and_mask_len;
} rdp_pointer_update;

librdp_status rdp_pointer_parse_fastpath(uint8_t update_code,
                                         const void* data,
                                         size_t length,
                                         rdp_pointer_update* update);
librdp_status rdp_pointer_parse_slowpath(const void* data, size_t length, rdp_pointer_update* update);
librdp_status rdp_pointer_write_slowpath(rdp_buffer* buffer,
                                         const rdp_pointer_update* update);
librdp_status rdp_pointer_decode_bgra32(const rdp_pointer_update* update, rdp_buffer* output, size_t* stride);

#endif
