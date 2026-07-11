/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/virtual_channel.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_virtual_channel_packet packet;
    (void)rdp_virtual_channel_parse_packet(data, size, &packet);
    return 0;
}
