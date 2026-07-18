/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for RD Gateway packet framing.
 * Coverage: validates complete, partial, oversized, control, and data packets
 * through the parser used by the HTTP gateway transport.
 * Bug classes: header truncation, length disagreement, oversized packets,
 * nested data lengths, and borrowed-view bounds.
 * Determinism: no HTTP request, socket, credential, clock, or worker thread is
 * used by the fuzz entrypoint.
 */

#include "gateway/rdg_http.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: parses one gateway HTTP entity prefix as an RDG packet and
 * verifies that successful borrowed views remain inside the supplied buffer.
 * Bug classes: parser over-read, nested payload overflow, inconsistent packet
 * lengths, and data view escaping its validated outer frame.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_rdg_packet_view packet;

    if (rdp_rdg_parse_packet(data, size, &packet) == LIBRDP_STATUS_OK)
    {
        if (packet.packet_len > size || packet.payload_len > packet.packet_len ||
            packet.data_len > packet.payload_len)
            __builtin_trap();
    }
    return 0;
}
