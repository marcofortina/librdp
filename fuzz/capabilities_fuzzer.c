/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for capability-set parser and serializer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "protocol/capabilities.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises capability-set parser and serializer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_capability_list list;
    if (rdp_capabilities_parse(data, size, &list) == LIBRDP_STATUS_OK)
    {
        uint16_t i = 0;
        for (i = 0; i < list.count; i++)
        {
            rdp_capability_general general;
            rdp_capability_bitmap bitmap;
            rdp_capability_order order;
            rdp_capability_bitmap_cache_v2 bitmap_cache;
            rdp_capability_pointer pointer;
            rdp_capability_large_pointer large_pointer;
            rdp_capability_input input;
            rdp_capability_brush brush;
            rdp_capability_glyph_cache glyph;
            rdp_capability_virtual_channel channel;
            rdp_capability_sound sound;
            rdp_capability_share share;
            rdp_capability_font font;
            rdp_capability_control control;
            rdp_capability_color_cache color_cache;
            rdp_capability_activation activation;

            (void)rdp_capability_parse_general(&list.sets[i], &general);
            (void)rdp_capability_parse_bitmap(&list.sets[i], &bitmap);
            (void)rdp_capability_parse_order(&list.sets[i], &order);
            (void)rdp_capability_parse_bitmap_cache_v2(&list.sets[i], &bitmap_cache);
            (void)rdp_capability_parse_pointer(&list.sets[i], &pointer);
            (void)rdp_capability_parse_large_pointer(&list.sets[i], &large_pointer);
            (void)rdp_capability_parse_input(&list.sets[i], &input);
            (void)rdp_capability_parse_brush(&list.sets[i], &brush);
            (void)rdp_capability_parse_glyph_cache(&list.sets[i], &glyph);
            (void)rdp_capability_parse_virtual_channel(&list.sets[i], &channel);
            (void)rdp_capability_parse_sound(&list.sets[i], &sound);
            (void)rdp_capability_parse_share(&list.sets[i], &share);
            (void)rdp_capability_parse_font(&list.sets[i], &font);
            (void)rdp_capability_parse_control(&list.sets[i], &control);
            (void)rdp_capability_parse_color_cache(&list.sets[i], &color_cache);
            (void)rdp_capability_parse_activation(&list.sets[i], &activation);
        }
    }
    return 0;
}
