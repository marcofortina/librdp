/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: TPKT framing declaration contract.
 * Invariants: wire lengths, tags, and stream offsets must remain synchronized
 * across parse and write helpers.
 * Ownership: parsed views borrow input bytes and serialized buffers are
 * caller-owned.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: all network bytes are untrusted until parsed by the declared
 * helper.
 */


#ifndef RDP_PROTOCOL_TPKT_H
#define RDP_PROTOCOL_TPKT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

typedef struct rdp_tpkt
{
    const uint8_t* payload;
    size_t payload_len;
    uint16_t total_len;
} rdp_tpkt;

librdp_status rdp_tpkt_write(rdp_buffer* buffer, const void* payload, size_t payload_len);
librdp_status rdp_tpkt_parse(const void* data, size_t length, rdp_tpkt* packet);

#endif
