/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for fast-path update parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "protocol/fastpath.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises fast-path update parser and writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_buffer buffer;
    rdp_fastpath_header header;
    rdp_fastpath_update update;
    rdp_fastpath_update_list updates;
    size_t bounded = size < 64u ? size : 64u;

    (void)rdp_fastpath_parse_header(data, size, &header);
    (void)rdp_fastpath_parse_updates(data, size, &updates);
    rdp_buffer_init(&buffer);
    (void)rdp_fastpath_write_header(&buffer,
                                    RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                    0,
                                    bounded);
    buffer.length = 0;
    update.update_code = RDP_FASTPATH_UPDATE_BITMAP;
    update.fragmentation = RDP_FASTPATH_FRAGMENT_SINGLE;
    update.compression = 0;
    update.compression_flags = 0;
    update.data = data;
    update.data_len = bounded;
    (void)rdp_fastpath_write_updates(&buffer, &update, 1);
    buffer.length = 0;
    update.update_code = RDP_FASTPATH_UPDATE_POINTER_DEFAULT;
    update.data = NULL;
    update.data_len = 0;
    (void)rdp_fastpath_write_updates(&buffer, &update, 1);
    rdp_buffer_free(&buffer);
    return 0;
}
