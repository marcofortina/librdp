/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bulk compression declaration contract.
 * Invariants: wire lengths, tags, and stream offsets must remain synchronized
 * across parse and write helpers.
 * Ownership: parsed views borrow input bytes and serialized buffers are
 * caller-owned.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: all network bytes are untrusted until parsed by the declared
 * helper.
 */


#ifndef RDP_PROTOCOL_BULK_H
#define RDP_PROTOCOL_BULK_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_BULK_PACKET_COMPRESSED 0x20u
#define RDP_BULK_PACKET_AT_FRONT 0x40u
#define RDP_BULK_PACKET_FLUSHED 0x80u
#define RDP_BULK_TYPE_MASK 0x0fu
#define RDP_BULK_FLAGS_MASK 0xe0u
#define RDP_BULK_TYPE_8K 0x00u
#define RDP_BULK_TYPE_64K 0x01u
#define RDP_BULK_TYPE_RDP6 0x02u
#define RDP_BULK_TYPE_RDP61 0x03u
#define RDP_BULK_TYPE_RDP8 0x04u
#define RDP_BULK_RDP6_HISTORY_SIZE 65536u
#define RDP_BULK_RDP61_HISTORY_SIZE 2000000u

typedef struct rdp_bulk_mppc_state
{
    uint8_t* history;
    size_t history_size;
    size_t write_offset;
    uint8_t level;
} rdp_bulk_mppc_state;

typedef struct rdp_bulk_rdp61_state
{
    uint8_t* history;
    size_t write_offset;
} rdp_bulk_rdp61_state;

typedef struct rdp_bulk_rdp6_decode_entry
{
    uint16_t symbol;
    uint8_t bit_count;
    uint8_t reserved;
} rdp_bulk_rdp6_decode_entry;

typedef struct rdp_bulk_rdp6_state
{
    uint8_t history[RDP_BULK_RDP6_HISTORY_SIZE];
    size_t write_offset;
    uint32_t offset_cache[4];
    rdp_bulk_rdp6_decode_entry literal_offset[8192];
    rdp_bulk_rdp6_decode_entry match_length[512];
    uint8_t tables_ready;
} rdp_bulk_rdp6_state;

typedef struct rdp_bulk_decompressor
{
    rdp_bulk_mppc_state mppc8k;
    rdp_bulk_mppc_state mppc64k;
    rdp_bulk_rdp6_state rdp6;
    rdp_bulk_mppc_state rdp61_level2;
    rdp_bulk_rdp61_state rdp61;
} rdp_bulk_decompressor;

void rdp_bulk_decompressor_init(rdp_bulk_decompressor* decompressor);
void rdp_bulk_decompressor_reset(rdp_bulk_decompressor* decompressor);
void rdp_bulk_decompressor_free(rdp_bulk_decompressor* decompressor);
librdp_status rdp_bulk_decompress(rdp_bulk_decompressor* decompressor,
                                  uint8_t flags,
                                  const void* data,
                                  size_t data_len,
                                  rdp_buffer* decoded);

#endif
