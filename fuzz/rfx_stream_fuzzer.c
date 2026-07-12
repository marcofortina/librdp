/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for RemoteFX stream container parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "graphics/rfx_stream.h"

#include <stdint.h>
#include <stddef.h>

static librdp_status fuzz_rfx_stream_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    (void)tile;
    (void)user;
    return LIBRDP_STATUS_OK;
}

/*
 * Fuzz target: exercises RemoteFX stream container parser paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_rfx_stream_summary summary;

    (void)rdp_rfx_stream_decode(data, size, fuzz_rfx_stream_tile, NULL, &summary);
    return 0;
}
