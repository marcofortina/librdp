/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for audio format negotiation parser and writer.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/audio_format.h"

/*
 * Fuzz target: exercises audio format negotiation parser and writer with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
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
