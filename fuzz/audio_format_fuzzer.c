/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/audio_format.h"

int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size)
{
    rdp_audio_format format;
    rdp_buffer out;
    size_t consumed = 0;

    if (!data && size > 0)
        return 0;

    rdp_buffer_init(&out);
    if (rdp_audio_format_parse(data, (size_t)size, &format, &consumed) == LIBRDP_STATUS_OK)
        (void)rdp_audio_format_write(&out, &format);
    if (size >= 1u)
    {
        uint32_t count = data[0] % 8u;
        (void)rdp_audio_format_validate_list(data + 1, (size_t)size - 1u, count, &consumed);
        if (count > 0)
            (void)rdp_audio_format_get_from_list(data + 1, (size_t)size - 1u, count, 0, &format);
    }
    rdp_buffer_free(&out);
    return 0;
}
