/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "graphics/avc.h"

#include <stdint.h>
#include <string.h>

static uint8_t fuzz_byte(const uint8_t* data, size_t size, size_t index)
{
    return size == 0 ? 0 : data[index % size];
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t aux_y[16u * 16u];
    uint8_t aux_u[8u * 8u];
    uint8_t aux_v[8u * 8u];
    uint8_t dst_u[16u * 16u];
    uint8_t dst_v[16u * 16u];
    uint32_t width = (uint32_t)(1u + (fuzz_byte(data, size, 0) % 16u));
    uint32_t height = (uint32_t)(1u + (fuzz_byte(data, size, 1) % 16u));
    uint32_t left = width > 1u ? (uint32_t)(fuzz_byte(data, size, 2) % width) : 0;
    uint32_t top = height > 1u ? (uint32_t)(fuzz_byte(data, size, 3) % height) : 0;
    uint32_t right = left + 1u + (uint32_t)(fuzz_byte(data, size, 4) % (width - left));
    uint32_t bottom = top + 1u + (uint32_t)(fuzz_byte(data, size, 5) % (height - top));
    size_t i = 0;
    rdp_avc_444_chroma_view v1;
    rdp_avc_444v2_chroma_view v2;

    for (i = 0; i < sizeof(aux_y); i++)
        aux_y[i] = (uint8_t)(fuzz_byte(data, size, i) + i);
    for (i = 0; i < sizeof(aux_u); i++)
        aux_u[i] = (uint8_t)(fuzz_byte(data, size, i + 11u) ^ (uint8_t)i);
    for (i = 0; i < sizeof(aux_v); i++)
        aux_v[i] = (uint8_t)(fuzz_byte(data, size, i + 23u) + (uint8_t)(i * 3u));
    memset(dst_u, fuzz_byte(data, size, 7), sizeof(dst_u));
    memset(dst_v, fuzz_byte(data, size, 8), sizeof(dst_v));

    memset(&v1, 0, sizeof(v1));
    v1.aux_y = aux_y;
    v1.aux_y_stride = 16;
    v1.aux_u = aux_u;
    v1.aux_u_stride = 8;
    v1.aux_v = aux_v;
    v1.aux_v_stride = 8;
    v1.aux_width = width;
    v1.aux_height = height;
    v1.rect.left = (uint16_t)left;
    v1.rect.top = (uint16_t)top;
    v1.rect.right = (uint16_t)right;
    v1.rect.bottom = (uint16_t)bottom;
    v1.dst_u = dst_u;
    v1.dst_u_stride = 16;
    v1.dst_v = dst_v;
    v1.dst_v_stride = 16;
    v1.dst_width = width;
    v1.dst_height = height;
    (void)rdp_avc_reconstruct_444_chroma(&v1);
    v1.aux_u_stride = fuzz_byte(data, size, 9) % 9u;
    v1.aux_v_stride = fuzz_byte(data, size, 10) % 9u;
    (void)rdp_avc_reconstruct_444_chroma(&v1);

    memset(&v2, 0, sizeof(v2));
    v2.aux_y = aux_y;
    v2.aux_y_stride = 16;
    v2.aux_u = aux_u;
    v2.aux_u_stride = 8;
    v2.aux_v = aux_v;
    v2.aux_v_stride = 8;
    v2.aux_width = width;
    v2.aux_height = height;
    v2.rect = v1.rect;
    v2.dst_u = dst_u;
    v2.dst_u_stride = 16;
    v2.dst_v = dst_v;
    v2.dst_v_stride = 16;
    v2.dst_width = width;
    v2.dst_height = height;
    (void)rdp_avc_reconstruct_444v2_chroma(&v2);
    v2.aux_u_stride = fuzz_byte(data, size, 11) % 9u;
    v2.aux_v_stride = fuzz_byte(data, size, 12) % 9u;
    (void)rdp_avc_reconstruct_444v2_chroma(&v2);

#if defined(RDP_HAVE_FFMPEG_AVC) || defined(RDP_HAVE_OPENH264_AVC)
    {
        rdp_avc_frame frame;

        rdp_avc_frame_init(&frame);
        (void)rdp_avc_yuv444_planes_to_bgra(aux_y,
                                            16,
                                            dst_u,
                                            16,
                                            dst_v,
                                            16,
                                            width,
                                            height,
                                            fuzz_byte(data, size, 13) & 1u,
                                            &frame);
        rdp_avc_frame_free(&frame);
    }
#endif
    return 0;
}
