/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for TPKT frame parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "protocol/tpkt.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises TPKT frame parser and writer paths with one arbitrary
 * input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_tpkt packet;
    rdp_buffer buffer;
    size_t bounded = size < 4096u ? size : 4096u;

    (void)rdp_tpkt_parse(data, size, &packet);
    rdp_buffer_init(&buffer);
    (void)rdp_tpkt_write(&buffer, data, bounded);
    if (buffer.length > 0)
        (void)rdp_tpkt_parse(buffer.data, buffer.length, &packet);
    rdp_buffer_free(&buffer);
    return 0;
}
