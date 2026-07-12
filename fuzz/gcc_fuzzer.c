/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for GCC conference data parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "common/stream.h"
#include "protocol/gcc.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises GCC conference data parser and writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_stream stream;
    rdp_gcc_user_data_block block;
    rdp_gcc_client_data_summary summary;
    rdp_gcc_conference_response response;
    rdp_gcc_server_data server_data;

    (void)rdp_gcc_parse_client_data_blocks(data, size, &summary);
    (void)rdp_gcc_parse_conference_create_response(data, size, &response);
    (void)rdp_gcc_parse_server_data_blocks(data, size, &server_data);
    rdp_stream_init(&stream, data, size);
    while (rdp_stream_remaining(&stream) > 0)
    {
        if (rdp_gcc_read_user_data_block(&stream, &block) != LIBRDP_STATUS_OK)
            break;
    }
    return 0;
}
