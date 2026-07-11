/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/telemetry.h"

#include <stddef.h>
#include <stdint.h>

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
