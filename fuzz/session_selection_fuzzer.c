/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for session selection routing-token parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "protocol/session_selection.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Fuzz target: exercises session selection routing-token parser paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_session_selection_pdu pdu;
    rdp_server_redirection_packet redirection;
    rdp_buffer buffer;
    uint16_t chars = size > RDP_SESSION_SELECTION_MAX_TEXT_CHARS * 2u ?
        RDP_SESSION_SELECTION_MAX_TEXT_CHARS :
        (uint16_t)(size / 2u);

    (void)rdp_session_selection_parse_pdu(data, size, &pdu);
    (void)rdp_server_redirection_parse_packet(data, size, &redirection);
    (void)rdp_server_redirection_parse_enhanced(data, size, &redirection);
    rdp_buffer_init(&buffer);
    (void)rdp_session_selection_write_v1(&buffer, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_session_selection_write_v2(&buffer, (uint32_t)size, data, chars);
    memset(&redirection, 0, sizeof(redirection));
    if (size > 0u && size <= UINT32_MAX)
    {
        redirection.redirection_flags =
            RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO;
        redirection.load_balance_info.data = data;
        redirection.load_balance_info.length = (uint32_t)size;
    }
    buffer.length = 0;
    (void)rdp_server_redirection_write_packet(&buffer, &redirection, 1);
    buffer.length = 0;
    (void)rdp_server_redirection_write_enhanced(
        &buffer,
        1003u,
        &redirection,
        1,
        1);
    rdp_buffer_free(&buffer);
    return 0;
}
