/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: fast-path, slow-path, bitmap, and pointer conformance vectors.
 * Bug classes: framing, truncation, decompression bounds, pixel conversion, and pointer masks.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "common/buffer.h"
#include "graphics/bitmap.h"
#include "graphics/surface_commands.h"
#include "protocol/bulk.h"
#include "protocol/capabilities.h"
#include "protocol/fastpath.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "security/security.h"

#include <librdp/session.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/*
 * Runs fast-path, slow-path, bitmap, and pointer conformance vectors.
 */
int test_protocol_update_vectors(void)
{
    const uint8_t fast_short[] = {0x00, 0x06, 1, 2, 3, 4};
    const uint8_t fast_long[] = {0x40, 0x80, 0x08, 1, 2, 3, 4, 5};
    const uint8_t fast_bad_update_compression[] = {0x00, 0x05, 0x40, 0x00, 0x00};
    const uint8_t slow[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03};
    const uint8_t slow_trailing[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03, 0xff};
    const uint8_t demand_active[] = {
        0x21, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x44,
        0x33, 0x22, 0x11
    };
    const uint8_t demand_active_trailing[] = {
        0x22, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x44,
        0x33, 0x22, 0x11, 0xff
    };
    const uint8_t capability_list_trailing[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0xff};
    const uint8_t bitmap_data_pdu[] = {
        0x38, 0x00, 0x17, 0x00, 0xec, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x26, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t bitmap_24_data[] = {
        1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12
    };
    const uint8_t bitmap_24_padded_data[] = {
        1, 2, 3, 0,
        4, 5, 6, 0
    };
    const uint8_t bitmap_15_data[] = {0x00, 0x7c, 0xe0, 0x03};
    const uint8_t bitmap_16_data[] = {0x00, 0xf8, 0xe0, 0x07};
    const uint8_t bitmap_8_data[] = {0, 1, 2, 3};
    const uint8_t bitmap_4_data[] = {0x12, 0x30, 0x01, 0x20};
    const uint8_t bitmap_1_data[] = {0xb0, 0x40};
    const uint8_t bitmap_8_rle_color_image[] = {0x84, 0, 1, 2, 3};
    const uint8_t palette_update_data[] = {
        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        10,   20,   30,   200,  100,  50,   1,    2,
        3,    9,    8,    7
    };
    const uint8_t palette_fastpath_data[] = {
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        10,   20,   30,   200,  100,  50,   1,
        2,    3,    9,    8,    7
    };
    const uint8_t palette_invalid_count[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00};
    const uint8_t bitmap_24_rle_color_image[] = {
        0x84,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t bitmap_24_rle_bg_run_cross_row[] = {
        0x82,
        0, 0, 255,
        0, 255, 0,
        0x06
    };
    const uint8_t bitmap_24_rle_fg_run_cross_row[] = {0x26, 0x02};
    const uint8_t bitmap_24_rle_fgbg_cross_row[] = {0x41, 0xff};
    const uint8_t bitmap_16_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0xf8
    };
    const uint8_t bitmap_15_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0x7c
    };
    const uint8_t fast_bitmap_update[] = {
        0x00, 0x29, 0x01, 0x24, 0x00,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t surface_command_payload[] = {
        0x01, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16,
        0x04, 0x00,
        0x01, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t surface_command_short_frame_marker[] = {
        0x04, 0x00,
        0x01, 0x00
    };
    const uint8_t surface_command_extended[] = {
        0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x00, 0x01,
        0x01, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0xef, 0xcd, 0xab, 0x90,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0xaa, 0xbb, 0xcc, 0xdd
    };
    const uint8_t pointer_shape_32[] = {
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t pointer_shape_16[] = {
        0x10, 0x00,
        0x08, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0xf8,
        0xe0, 0x07,
        0x00, 0x00
    };
    const uint8_t pointer_shape_15[] = {
        0x0f, 0x00,
        0x09, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x7c,
        0xe0, 0x03,
        0x00, 0x00
    };
    const uint8_t pointer_shape_1bpp_invert[] = {
        0x01, 0x00,
        0x06, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x80, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_shape_1bpp_transparent[] = {
        0x01, 0x00,
        0x07, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_slow_position[] = {
        0x03, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t pointer_slow_system_default[] = {
        0x01, 0x00,
        0x00, 0x7f, 0x00, 0x00
    };
    const uint8_t pointer_slow_large[] = {
        0x09, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    uint8_t fast_payload[130] = {0};
    uint8_t malformed_slowpath[sizeof(bitmap_data_pdu)];
    uint8_t trailing_slowpath[sizeof(bitmap_data_pdu) + 1u];
    rdp_fastpath_header fast;
    rdp_fastpath_update_list fast_updates;
    rdp_bulk_decompressor bulk_decompressor;
    rdp_slowpath_share_control_header slow_header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_bitmap_update bitmap_update;
    rdp_bitmap_update_header bitmap_header;
    rdp_bitmap_rect bitmap_rect;
    rdp_palette_update palette_update;
    rdp_palette_update palette_roundtrip;
    rdp_pointer_update pointer_update;
    rdp_surface_command_list surface_commands;
    rdp_surface_bits surface_bits;
    rdp_buffer decoded_fastpath;
    rdp_buffer bulk_decoded;
    rdp_buffer client_refresh_rect;
    rdp_buffer decoded_bitmap;
    rdp_buffer decoded_pointer;
    rdp_buffer dyn_response;
    rdp_capability_list confirm_caps;
    size_t decoded_stride = 0;
    size_t pointer_stride = 0;

    rdp_buffer_init(&decoded_fastpath);
    rdp_buffer_init(&bulk_decoded);
    rdp_bulk_decompressor_init(&bulk_decompressor);
    rdp_buffer_init(&client_refresh_rect);
    rdp_buffer_init(&decoded_bitmap);
    rdp_buffer_init(&decoded_pointer);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    {
        const rdp_fastpath_header valid_fast_header = fast;

        PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast, &valid_fast_header, sizeof(fast)) == 0);
    }
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     130) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, sizeof(fast_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 133 && fast.header_length == 3 && fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath, 2, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 && fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE &&
           fast_updates.updates[0].compression == 0 && fast_updates.updates[0].data_len == 36);
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      fast_updates.count) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 &&
           fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].data_len == 36);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    fast_updates.updates[0].compression = RDP_FASTPATH_OUTPUT_COMPRESSION_USED;
    fast_updates.updates[0].compression_flags = 0x20u;
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.updates[0].compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED &&
           fast_updates.updates[0].compression_flags == 0x20u);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                               0,
                               "raw",
                               3,
                               &bulk_decoded) == LIBRDP_STATUS_OK);
    PCHECK(bulk_decoded.length == 3 && memcmp(bulk_decoded.data, "raw", 3) == 0);
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_literal[] = {0x41};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_8K,
                                   mppc_literal,
                                   sizeof(mppc_literal),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 1 && bulk_decoded.data[0] == 'A');
    }
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_match[] = {0x41, 0x42, 0x43, 0xf0, 0xc0};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_8K,
                                   mppc_match,
                                   sizeof(mppc_match),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 6 && memcmp(bulk_decoded.data, "ABCABC", 6) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t mppc_literal64[] = {0x58};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_64K,
                                   mppc_literal64,
                                   sizeof(mppc_literal64),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 1 && bulk_decoded.data[0] == 'X');
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp6_literals[] = {
            0x47, 0xee, 0x33, 0x63, 0xfd, 0xff, 0x0b, 0x00
        };
        const uint8_t rdp6_match[] = {
            0x7b, 0xee, 0xb5, 0xf7, 0x7f, 0xfc, 0x5f, 0x00
        };
        const uint8_t rdp6_short[] = {0x47, 0xee, 0x33};

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_literals,
                                   sizeof(rdp6_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 4 && memcmp(bulk_decoded.data, "rdp6", 4) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_match,
                                   sizeof(rdp6_match),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 6 && memcmp(bulk_decoded.data, "abcabc", 6) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_PACKET_FLUSHED | RDP_BULK_TYPE_RDP6,
                                   rdp6_short,
                                   sizeof(rdp6_short),
                                   &bulk_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    bulk_decoded.length = 0;
    rdp_bulk_decompressor_reset(&bulk_decompressor);
    {
        const uint8_t rdp61_literals[] = {
            0x06, 0x00,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'
        };
        const uint8_t rdp61_matches[] = {
            0x01, 0x00,
            0x02, 0x00,
            0x09, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
            'k', 'l', 'm', 'n', 'o', 'u'
        };
        const char expected[] = "klmnodefghijklabcdu";

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_literals,
                                   sizeof(rdp61_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 10 && memcmp(bulk_decoded.data, "abcdefghij", 10) == 0);
        bulk_decoded.length = 0;
        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_matches,
                                   sizeof(rdp61_matches),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == sizeof(expected) - 1u &&
               memcmp(bulk_decoded.data, expected, sizeof(expected) - 1u) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp61_inner_literals[] = {
            0x12, RDP_BULK_TYPE_64K,
            'i', 'n', 'n', 'e', 'r'
        };

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_inner_literals,
                                   sizeof(rdp61_inner_literals),
                                   &bulk_decoded) == LIBRDP_STATUS_OK);
        PCHECK(bulk_decoded.length == 5 && memcmp(bulk_decoded.data, "inner", 5) == 0);
    }
    bulk_decoded.length = 0;
    {
        const uint8_t rdp61_bad_match_order[] = {
            0x01, 0x00,
            0x02, 0x00,
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            'x', 'y'
        };

        PCHECK(rdp_bulk_decompress(&bulk_decompressor,
                                   RDP_BULK_PACKET_COMPRESSED | RDP_BULK_TYPE_RDP61,
                                   rdp61_bad_match_order,
                                   sizeof(rdp61_bad_match_order),
                                   &bulk_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                     0x0fu,
                                     RDP_FASTPATH_FRAGMENT_SINGLE,
                                     0,
                                     0,
                                     NULL,
                                     0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, 0x0fu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&decoded_fastpath, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    {
        rdp_fastpath_update sync_update;
        uint8_t sync_payload = 0;

        memset(&sync_update, 0, sizeof(sync_update));
        sync_update.update_code = RDP_FASTPATH_UPDATE_SYNCHRONIZE;
        sync_update.fragmentation = RDP_FASTPATH_FRAGMENT_SINGLE;
        PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                          &sync_update,
                                          1) == LIBRDP_STATUS_OK);
        PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                          decoded_fastpath.length,
                                          &fast_updates) == LIBRDP_STATUS_OK);
        PCHECK(fast_updates.count == 1 &&
               fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE &&
               fast_updates.updates[0].data_len == 0);
        PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                         RDP_FASTPATH_UPDATE_SYNCHRONIZE,
                                         RDP_FASTPATH_FRAGMENT_FIRST,
                                         0,
                                         0,
                                         NULL,
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                         RDP_FASTPATH_UPDATE_SYNCHRONIZE,
                                         RDP_FASTPATH_FRAGMENT_SINGLE,
                                         0,
                                         0,
                                         &sync_payload,
                                         1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, RDP_FASTPATH_UPDATE_SYNCHRONIZE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&decoded_fastpath, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&decoded_fastpath, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(fast_updates.updates[0].data,
                                            fast_updates.updates[0].data_len,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    {
        const rdp_fastpath_update_list valid_fast_updates = fast_updates;

        PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update,
                                          sizeof(fast_bitmap_update) - 1u,
                                          &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates(fast_bad_update_compression,
                                          sizeof(fast_bad_update_compression),
                                          &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates(fast_long, sizeof(fast_long), &fast_updates) ==
               LIBRDP_STATUS_STATE);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
        PCHECK(rdp_fastpath_parse_updates_payload(fast_long + 3u,
                                                  sizeof(fast_long) - 3u,
                                                  &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&fast_updates, &valid_fast_updates, sizeof(fast_updates)) == 0);
    }
    PCHECK(rdp_surface_commands_parse(surface_command_payload,
                                      sizeof(surface_command_payload),
                                      &surface_commands) == LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 2 &&
           surface_commands.commands[0].kind == RDP_SURFACE_COMMAND_KIND_BITS &&
           surface_commands.commands[0].bits.command_type == RDP_SURFACE_COMMAND_SET_BITS &&
           surface_commands.commands[0].bits.dest_left == 1 &&
           surface_commands.commands[0].bits.dest_top == 2 &&
           surface_commands.commands[0].bits.width == 2 &&
           surface_commands.commands[0].bits.height == 2 &&
           surface_commands.commands[0].bits.codec_id == RDP_SURFACE_CODEC_NONE &&
           surface_commands.commands[0].bits.bitmap_data_length == 16 &&
           surface_commands.commands[0].bits.bitmap_data[15] == 16 &&
           surface_commands.commands[1].kind == RDP_SURFACE_COMMAND_KIND_FRAME_MARKER &&
           surface_commands.commands[1].frame_marker.action == 1 &&
           surface_commands.commands[1].frame_marker.frame_id == 0x11223344u);
    {
        rdp_surface_command_list valid_surface_commands = surface_commands;

        PCHECK(rdp_surface_commands_parse(surface_command_payload,
                                          sizeof(surface_command_payload) - 1u,
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surface_commands,
                      &valid_surface_commands,
                      sizeof(surface_commands)) == 0);
        PCHECK(rdp_surface_commands_parse(surface_command_short_frame_marker,
                                          sizeof(surface_command_short_frame_marker),
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&surface_commands,
                      &valid_surface_commands,
                      sizeof(surface_commands)) == 0);
    }
    PCHECK(rdp_surface_commands_parse(surface_command_extended,
                                      sizeof(surface_command_extended),
                                      &surface_commands) == LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 1 &&
           surface_commands.commands[0].bits.command_type == RDP_SURFACE_COMMAND_STREAM_BITS &&
           surface_commands.commands[0].bits.has_extended_header == 1 &&
           surface_commands.commands[0].bits.codec_id == RDP_SURFACE_CODEC_NSCODEC &&
           surface_commands.commands[0].bits.high_unique_id == 0x12345678u &&
           surface_commands.commands[0].bits.low_unique_id == 0x90abcdefu &&
           surface_commands.commands[0].bits.timestamp_ms == 0x0102030405060708ull &&
           surface_commands.commands[0].bits.timestamp_s == 0x1112131415161718ull);
    surface_bits = surface_commands.commands[0].bits;
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_surface_commands_write_bits(&dyn_response, &surface_bits) == LIBRDP_STATUS_OK);
    PCHECK(rdp_surface_commands_write_frame_marker(&dyn_response, 0, 0x01020304u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_surface_commands_parse(dyn_response.data, dyn_response.length, &surface_commands) ==
           LIBRDP_STATUS_OK);
    PCHECK(surface_commands.count == 2 &&
           surface_commands.commands[0].bits.bitmap_data[3] == 0xdd &&
           surface_commands.commands[1].frame_marker.frame_id == 0x01020304u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    {
        size_t command_index = 0;

        for (command_index = 0; command_index < RDP_SURFACE_COMMAND_MAX_COMMANDS + 1u; command_index++)
        {
            PCHECK(rdp_surface_commands_write_frame_marker(&dyn_response,
                                                           1,
                                                           (uint32_t)command_index) == LIBRDP_STATUS_OK);
        }
        PCHECK(rdp_surface_commands_parse(dyn_response.data,
                                          dyn_response.length,
                                          &surface_commands) == LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NULL, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_DEFAULT, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_POSITION,
                                      pointer_slow_position + 2,
                                      sizeof(pointer_slow_position) - 2u,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_CACHED,
                                      pointer_shape_32 + 2,
                                      2,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_32,
                                      sizeof(pointer_shape_32),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 16 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[3] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00 &&
           decoded_pointer.data[7] == 0xff &&
           decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_16,
                                      sizeof(pointer_shape_16),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 16 &&
           pointer_update.cache_index == 8);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_15,
                                      sizeof(pointer_shape_15),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 15 &&
           pointer_update.cache_index == 9);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_invert,
                                      sizeof(pointer_shape_1bpp_invert),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 1 &&
           pointer_update.cache_index == 6);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0x00 &&
           decoded_pointer.data[3] == 0xff);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_transparent,
                                      sizeof(pointer_shape_1bpp_transparent),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[3] == 0x00);
    {
        const rdp_pointer_update valid_pointer_update = pointer_update;

        PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                          pointer_shape_32,
                                          sizeof(pointer_shape_32) - 1u,
                                          &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update, &valid_pointer_update, sizeof(pointer_update)) == 0);
    }
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_position,
                                      sizeof(pointer_slow_position),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_system_default,
                                      sizeof(pointer_slow_system_default),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_large,
                                      sizeof(pointer_slow_large),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    {
        rdp_pointer_update written = pointer_update;
        rdp_pointer_update parsed;

        PCHECK(rdp_pointer_write_slowpath(&dyn_response, &written) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_pointer_parse_slowpath(dyn_response.data,
                                          dyn_response.length,
                                          &parsed) == LIBRDP_STATUS_OK);
        PCHECK(parsed.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
               parsed.cache_index == written.cache_index &&
               parsed.width == written.width &&
               parsed.height == written.height &&
               parsed.xor_mask_len == written.xor_mask_len &&
               parsed.and_mask_len == written.and_mask_len &&
               memcmp(parsed.xor_mask,
                      written.xor_mask,
                      written.xor_mask_len) == 0 &&
               memcmp(parsed.and_mask,
                      written.and_mask,
                      written.and_mask_len) == 0);
        dyn_response.length = 0u;
        memset(&written, 0, sizeof(written));
        written.kind = RDP_POINTER_UPDATE_KIND_POSITION;
        written.x = 0x1234u;
        written.y = 0x5678u;
        PCHECK(rdp_pointer_write_slowpath(&dyn_response, &written) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_pointer_parse_slowpath(dyn_response.data,
                                          dyn_response.length,
                                          &parsed) == LIBRDP_STATUS_OK);
        PCHECK(parsed.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
               parsed.x == written.x && parsed.y == written.y);
        written.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
        written.width = 0u;
        PCHECK(rdp_pointer_write_slowpath(&dyn_response, &written) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(dyn_response.length == 6u);
    }
    {
        const rdp_pointer_update valid_pointer_update = pointer_update;

        PCHECK(rdp_pointer_parse_slowpath(pointer_slow_large,
                                          sizeof(pointer_slow_large) - 1u,
                                          &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&pointer_update, &valid_pointer_update, sizeof(pointer_update)) == 0);
    }

    PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow), &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 && slow_header.pdu_type == 0x13);
    {
        const rdp_slowpath_share_control_header valid_slow_header = slow_header;

        PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow) - 1u, &slow_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&slow_header, &valid_slow_header, sizeof(slow_header)) == 0);
        PCHECK(rdp_slowpath_parse_share_control_header(slow_trailing,
                                                       sizeof(slow_trailing),
                                                       &slow_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&slow_header, &valid_slow_header, sizeof(slow_header)) == 0);
    }
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   6,
                                                   (uint16_t)(RDP_SLOWPATH_PDU_VERSION |
                                                              RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE),
                                                   1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(client_refresh_rect.data,
                                                   client_refresh_rect.length,
                                                   &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 &&
           slow_header.pdu_type == (RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE) &&
           slow_header.channel_id == 1004);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   5,
                                                   RDP_SLOWPATH_PDU_VERSION,
                                                   1004) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active), &demand) == LIBRDP_STATUS_OK);
    PCHECK(demand.share_id == 0x12345678u);
    PCHECK(demand.session_id == 0x11223344u);
    PCHECK(demand.source_descriptor_len == 3 && memcmp(demand.source_descriptor, "srv", 3) == 0);
    PCHECK(demand.capabilities.count == 1 && demand.capabilities.sets[0].type == 1);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_GENERAL) == &demand.capabilities.sets[0]);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BITMAP) == NULL);
    {
        const rdp_slowpath_demand_active valid_demand = demand;

        PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active) - 1u, &demand) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&demand, &valid_demand, sizeof(demand)) == 0);
        PCHECK(rdp_slowpath_parse_demand_active(demand_active_trailing,
                                                sizeof(demand_active_trailing),
                                                &demand) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&demand, &valid_demand, sizeof(demand)) == 0);
    }
    PCHECK(rdp_capabilities_parse(capability_list_trailing,
                                  sizeof(capability_list_trailing),
                                  &confirm_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u && data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    PCHECK(data_pdu.payload_len == 38);
    {
        const rdp_slowpath_data_pdu valid_data_pdu = data_pdu;

        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[10] = 1;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[11] = 0;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(malformed_slowpath, bitmap_data_pdu, sizeof(malformed_slowpath));
        malformed_slowpath[15] = 0x20;
        PCHECK(rdp_slowpath_parse_data_pdu(malformed_slowpath,
                                           sizeof(malformed_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
        memcpy(trailing_slowpath, bitmap_data_pdu, sizeof(bitmap_data_pdu));
        trailing_slowpath[sizeof(bitmap_data_pdu)] = 0xffu;
        PCHECK(rdp_slowpath_parse_data_pdu(trailing_slowpath,
                                           sizeof(trailing_slowpath),
                                           &data_pdu) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&data_pdu, &valid_data_pdu, sizeof(data_pdu)) == 0);
    }
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                data_pdu.stream_id,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                data_pdu.compressed_type,
                                                data_pdu.compressed_length) == LIBRDP_STATUS_OK);
    PCHECK(client_refresh_rect.length == 12 &&
           test_read_u32_le(client_refresh_rect.data) == data_pdu.share_id &&
           client_refresh_rect.data[5] == data_pdu.stream_id &&
           client_refresh_rect.data[8] == data_pdu.pdu_type2);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                0,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                0,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                data_pdu.stream_id,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                0x20,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, data_pdu.payload_len, &bitmap_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_header.update_type == RDP_UPDATE_TYPE_BITMAP && bitmap_header.count == 1);
    {
        const rdp_bitmap_update_header valid_bitmap_header = bitmap_header;

        PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, 3, &bitmap_header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_header, &valid_bitmap_header, sizeof(bitmap_header)) == 0);
    }
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1);
    PCHECK(bitmap_update.rects[0].width == 2 && bitmap_update.rects[0].height == 2);
    PCHECK(bitmap_update.rects[0].bits_per_pixel == 32 && bitmap_update.rects[0].data_len == 16);
    {
        const rdp_bitmap_update valid_bitmap_update = bitmap_update;

        PCHECK(rdp_bitmap_parse_update(data_pdu.payload,
                                       data_pdu.payload_len - 1u,
                                       &bitmap_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_update, &valid_bitmap_update, sizeof(bitmap_update)) == 0);
    }
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_update.rects[0], &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 9 &&
           decoded_bitmap.data[1] == 10 && decoded_bitmap.data[2] == 11 && decoded_bitmap.data[3] == 12);
    bitmap_rect = bitmap_update.rects[0];
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_update(decoded_bitmap.data, decoded_bitmap.length, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 2 &&
           bitmap_update.rects[0].height == 2 &&
           bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                            decoded_bitmap.length,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].bits_per_pixel == 32 &&
           bitmap_update.rects[0].data_len == 16);
    {
        const rdp_bitmap_update valid_bitmap_update = bitmap_update;

        PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                                decoded_bitmap.length - 1u,
                                                &bitmap_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&bitmap_update, &valid_bitmap_update, sizeof(bitmap_update)) == 0);
    }
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_data_pdu(&client_refresh_rect,
                                       data_pdu.share_id,
                                       data_pdu.header.channel_id,
                                       RDP_SLOWPATH_DATA_PDU_UPDATE,
                                       decoded_bitmap.data,
                                       decoded_bitmap.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE &&
           data_pdu.payload_len == decoded_bitmap.length);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_fastpath_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                            decoded_bitmap.length,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].bits_per_pixel == 32 &&
           bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_parse_palette_update(palette_update_data, sizeof(palette_update_data), &palette_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(palette_update.count == 4 && palette_update.entries[1].red == 200 &&
           palette_update.entries[1].green == 100 && palette_update.entries[1].blue == 50);
    PCHECK(rdp_bitmap_parse_fastpath_palette_update(palette_fastpath_data,
                                                    sizeof(palette_fastpath_data),
                                                    &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[3].red == 9 &&
           palette_roundtrip.entries[3].green == 8 && palette_roundtrip.entries[3].blue == 7);
    {
        const rdp_palette_update valid_palette_update = palette_roundtrip;

        PCHECK(rdp_bitmap_parse_palette_update(palette_fastpath_data,
                                               sizeof(palette_fastpath_data),
                                               &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
        PCHECK(rdp_bitmap_parse_palette_update(palette_invalid_count,
                                               sizeof(palette_invalid_count),
                                               &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
        PCHECK(rdp_bitmap_parse_fastpath_palette_update(palette_fastpath_data,
                                                        sizeof(palette_fastpath_data) - 1u,
                                                        &palette_roundtrip) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&palette_roundtrip, &valid_palette_update, sizeof(palette_roundtrip)) == 0);
    }
    PCHECK(rdp_bitmap_write_palette_update(&decoded_bitmap, &palette_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_palette_update(decoded_bitmap.data,
                                           decoded_bitmap.length,
                                           &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[0].red == 10 &&
           palette_roundtrip.entries[2].blue == 3);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_fastpath_palette_update(&decoded_bitmap, &palette_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_palette_update(decoded_bitmap.data,
                                                    decoded_bitmap.length,
                                                    &palette_roundtrip) == LIBRDP_STATUS_OK);
    PCHECK(palette_roundtrip.count == 4 && palette_roundtrip.entries[1].green == 100);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_OK);
    PCHECK(decoded_bitmap.length == 34);
    bitmap_rect.width = 0;
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_data;
    bitmap_rect.data_len = sizeof(bitmap_24_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 7 &&
           decoded_bitmap.data[1] == 8 && decoded_bitmap.data[2] == 9 && decoded_bitmap.data[3] == 0xff);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 1;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 0;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_padded_data;
    bitmap_rect.data_len = sizeof(bitmap_24_padded_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           decoded_bitmap.length == 8 &&
           decoded_bitmap.data[0] == 4 &&
           decoded_bitmap.data[1] == 5 &&
           decoded_bitmap.data[2] == 6 &&
           decoded_bitmap.data[4] == 1 &&
           decoded_bitmap.data[5] == 2 &&
           decoded_bitmap.data[6] == 3);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data = bitmap_16_data;
    bitmap_rect.data_len = sizeof(bitmap_16_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.data = bitmap_15_data;
    bitmap_rect.data_len = sizeof(bitmap_15_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 8;
    bitmap_rect.data = bitmap_8_data;
    bitmap_rect.data_len = sizeof(bitmap_8_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_STATE);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 &&
           decoded_bitmap.data[0] == 3 && decoded_bitmap.data[1] == 2 &&
           decoded_bitmap.data[2] == 1 && decoded_bitmap.data[4] == 7 &&
           decoded_bitmap.data[5] == 8 && decoded_bitmap.data[6] == 9 &&
           decoded_bitmap.data[8] == 30 && decoded_bitmap.data[9] == 20 &&
           decoded_bitmap.data[10] == 10);
    bitmap_rect.data_len = 3;
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 3;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 2;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 4;
    bitmap_rect.data = bitmap_4_data;
    bitmap_rect.data_len = sizeof(bitmap_4_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_STATE);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 && decoded_bitmap.length == 24 &&
           decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[8] == 3 && decoded_bitmap.data[9] == 2 &&
           decoded_bitmap.data[10] == 1);
    bitmap_rect.data_len = sizeof(bitmap_4_data) - 1u;
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 3;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 1;
    bitmap_rect.data = bitmap_1_data;
    bitmap_rect.data_len = sizeof(bitmap_1_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[16] == 50 && decoded_bitmap.data[17] == 100 &&
           decoded_bitmap.data[18] == 200);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_24_rle_color_image;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_color_image);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 1 &&
           decoded_bitmap.data[1] == 2 && decoded_bitmap.data[2] == 3 && decoded_bitmap.data[12] == 10 &&
           decoded_bitmap.data[13] == 11 && decoded_bitmap.data[14] == 12);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 3;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_24_rle_bg_run_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_bg_run_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[16] == 0 && decoded_bitmap.data[17] == 0 &&
           decoded_bitmap.data[18] == 255 && decoded_bitmap.data[20] == 0 &&
           decoded_bitmap.data[21] == 255 && decoded_bitmap.data[22] == 0 &&
           decoded_bitmap.data[24] == 0 && decoded_bitmap.data[25] == 0 &&
           decoded_bitmap.data[26] == 0);
    bitmap_rect.data = bitmap_24_rle_fg_run_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_fg_run_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 255 && decoded_bitmap.data[1] == 255 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[16] == 0 &&
           decoded_bitmap.data[17] == 0 && decoded_bitmap.data[18] == 0 &&
           decoded_bitmap.data[24] == 255 && decoded_bitmap.data[25] == 255 &&
           decoded_bitmap.data[26] == 255);
    bitmap_rect.data = bitmap_24_rle_fgbg_cross_row;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_fgbg_cross_row);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.length == 32 &&
           decoded_bitmap.data[0] == 255 && decoded_bitmap.data[1] == 255 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[16] == 0 &&
           decoded_bitmap.data[17] == 0 && decoded_bitmap.data[18] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 8;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_8_rle_color_image;
    bitmap_rect.data_len = sizeof(bitmap_8_rle_color_image);
    PCHECK(rdp_bitmap_decode_rect_bgra32_with_palette(&bitmap_rect,
                                                      &palette_update,
                                                      &decoded_bitmap,
                                                      &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 30 && decoded_bitmap.data[1] == 20 &&
           decoded_bitmap.data[2] == 10 && decoded_bitmap.data[4] == 50 &&
           decoded_bitmap.data[5] == 100 && decoded_bitmap.data[6] == 200 &&
           decoded_bitmap.data[12] == 7 && decoded_bitmap.data[13] == 8 &&
           decoded_bitmap.data[14] == 9);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_16_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_16_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_15_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_15_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    bitmap_rect.bits_per_pixel = 14;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data_len = 7;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&dyn_response);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_free(&decoded_pointer);
    rdp_bulk_decompressor_free(&bulk_decompressor);
    rdp_buffer_free(&bulk_decoded);
    rdp_buffer_free(&decoded_fastpath);
    return 0;
}
