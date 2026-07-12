/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for telemetry channel parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/telemetry.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises telemetry channel parser and writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_telemetry_pdu pdu;
    rdp_buffer buffer;

    (void)rdp_telemetry_parse_pdu(data, size, &pdu);
    rdp_buffer_init(&buffer);
    rdp_telemetry_pdu_init(&pdu,
                           (uint32_t)size,
                           (uint32_t)(size >> 1),
                           (uint32_t)(size >> 2),
                           (uint32_t)(size >> 3));
    (void)rdp_telemetry_write_pdu(&buffer, &pdu);
    (void)rdp_telemetry_write_metrics(&buffer,
                                      (uint32_t)(size >> 4),
                                      (uint32_t)(size >> 5),
                                      (uint32_t)(size >> 6),
                                      (uint32_t)(size >> 7));
    rdp_buffer_free(&buffer);
    return 0;
}
