/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for echo channel parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/echo_channel.h"

#include <stdint.h>
#include <stddef.h>

/*
 * Fuzz target: exercises echo channel parser and writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_echo_channel_pdu pdu;
    rdp_buffer buffer;
    size_t bounded = size > RDP_ECHO_CHANNEL_MAX_PAYLOAD ? RDP_ECHO_CHANNEL_MAX_PAYLOAD : size;

    (void)rdp_echo_channel_parse_request(data, size, &pdu);
    (void)rdp_echo_channel_parse_response(data, size, &pdu);
    rdp_buffer_init(&buffer);
    (void)rdp_echo_channel_write_request(&buffer, data, bounded);
    buffer.length = 0;
    (void)rdp_echo_channel_write_response(&buffer, data, bounded);
    rdp_buffer_free(&buffer);
    return 0;
}
