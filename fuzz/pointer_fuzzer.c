/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "protocol/fastpath.h"
#include "protocol/pointer.h"

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_pointer_update update;
    rdp_buffer decoded;
    size_t stride = 0;

    rdp_buffer_init(&decoded);
    if (size > 0)
    {
        static const uint8_t codes[] = {
            RDP_FASTPATH_UPDATE_POINTER_NULL,
            RDP_FASTPATH_UPDATE_POINTER_DEFAULT,
            RDP_FASTPATH_UPDATE_POINTER_POSITION,
            RDP_FASTPATH_UPDATE_POINTER_COLOR,
            RDP_FASTPATH_UPDATE_POINTER_CACHED,
            RDP_FASTPATH_UPDATE_POINTER_NEW,
            RDP_FASTPATH_UPDATE_POINTER_LARGE
        };
        uint8_t code = codes[data[0] % (sizeof(codes) / sizeof(codes[0]))];
        if (rdp_pointer_parse_fastpath(code, data + 1, size - 1u, &update) == LIBRDP_STATUS_OK)
            (void)rdp_pointer_decode_bgra32(&update, &decoded, &stride);
    }
    if (rdp_pointer_parse_slowpath(data, size, &update) == LIBRDP_STATUS_OK)
        (void)rdp_pointer_decode_bgra32(&update, &decoded, &stride);
    rdp_buffer_free(&decoded);
    return 0;
}
