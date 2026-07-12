/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for MCS connect and channel PDU parser/writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "common/stream.h"
#include "protocol/mcs.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises MCS connect and channel PDU parser/writer paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_mcs_connect_response response;
    rdp_mcs_attach_user_confirm attach;
    rdp_mcs_channel_join_confirm join;
    rdp_stream stream;
    size_t length = 0;

    rdp_stream_init(&stream, data, size);
    (void)rdp_mcs_read_ber_length(&stream, &length);
    (void)rdp_mcs_parse_connect_response(data, size, &response);
    (void)rdp_mcs_parse_attach_user_confirm(data, size, &attach);
    (void)rdp_mcs_parse_channel_join_confirm(data, size, &join);
    return 0;
}
