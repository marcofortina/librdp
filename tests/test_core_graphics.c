/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client graphics tests.
 * Coverage: GDI, GDI+, surface updates, and activation ordering.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>

#include "graphics/gdi_image.h"

static int append_gdiplus_record(rdp_buffer* stream, uint16_t type, uint16_t flags, const rdp_buffer* payload)
{
    size_t size = 0;

    if (!stream || !payload || payload->length > UINT32_MAX - 12u)
        return 0;
    size = payload->length + 12u;
    return rdp_buffer_append_u16_le(stream, type) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(stream, flags) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(stream, (uint32_t)size) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(stream, (uint32_t)payload->length) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(stream, payload->data, payload->length) == LIBRDP_STATUS_OK;
}

static int append_gdiplus_continued_object_record(rdp_buffer* stream,
                                                  uint16_t flags,
                                                  uint32_t total_object_size,
                                                  const rdp_buffer* payload)
{
    size_t size = 0;

    if (!stream || !payload || payload->length > UINT32_MAX - 16u)
        return 0;
    size = payload->length + 16u;
    return rdp_buffer_append_u16_le(stream, 0x4008u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(stream, (uint16_t)(flags | 0x8000u)) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(stream, (uint32_t)size) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(stream, total_object_size) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(stream, (uint32_t)payload->length) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(stream, payload->data, payload->length) == LIBRDP_STATUS_OK;
}

static int append_gdiplus_compressed_rect(rdp_buffer* payload,
                                          uint16_t x,
                                          uint16_t y,
                                          uint16_t width,
                                          uint16_t height)
{
    return rdp_buffer_append_u16_le(payload, x) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, y) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, width) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, height) == LIBRDP_STATUS_OK;
}

static int append_gdiplus_compressed_point(rdp_buffer* payload, uint16_t x, uint16_t y)
{
    return rdp_buffer_append_u16_le(payload, x) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, y) == LIBRDP_STATUS_OK;
}

static int append_gdiplus_float(rdp_buffer* payload, float value)
{
    uint32_t bits = 0;

    memcpy(&bits, &value, sizeof(bits));
    return rdp_buffer_append_u32_le(payload, bits) == LIBRDP_STATUS_OK;
}

static rdp_gdi_backend_kind gdiplus_test_backend(void)
{
    const char* name = getenv("LIBRDP_TEST_GDIPLUS_BACKEND");

    if (name && strcmp(name, "cairo") == 0)
        return RDP_GDI_BACKEND_CAIRO;
    if (name && strcmp(name, "quartz") == 0)
        return RDP_GDI_BACKEND_QUARTZ;
    return RDP_GDI_BACKEND_SOFTWARE;
}

/*
 * Coverage: exercises EMF+ object-table solid brushes, continued object
 * records, and solid pens referenced by vector draw records.
 */
int test_gdiplus_object_table_solid_brush_and_pen(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(16, 16, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff112233u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0103u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40400000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40800000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40a00000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x0000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_continued_object_record(&stream, 0x0105u, 12u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffaabbccu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0105u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 5u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x41200000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x3f800000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40000000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x0000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x3f800000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff445566u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0204u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 4u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x3f800000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x41400000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x40800000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x41400000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x400du, 0x0000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 7u);
    CHECK(rasterized == 3u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL);
    CHECK(stride >= 16u * 4u);
    CHECK(pixels[(3u * stride) + (2u * 4u)] == 0x33u);
    CHECK(pixels[(3u * stride) + (2u * 4u) + 1u] == 0x22u);
    CHECK(pixels[(3u * stride) + (2u * 4u) + 2u] == 0x11u);
    CHECK(pixels[(1u * stride) + (10u * 4u)] == 0xccu);
    CHECK(pixels[(1u * stride) + (10u * 4u) + 1u] == 0xbbu);
    CHECK(pixels[(1u * stride) + (10u * 4u) + 2u] == 0xaau);
    CHECK(pixels[(12u * stride) + (1u * 4u)] == 0x66u);
    CHECK(pixels[(12u * stride) + (1u * 4u) + 1u] == 0x55u);
    CHECK(pixels[(12u * stride) + (1u * 4u) + 2u] == 0x44u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: locks EMF+ visual records to concrete raster paths. The test builds
 * valid object-table path,
 * region, image and text records, then checks that no visual family increments
 * the unsupported counter.
 */
int test_gdiplus_known_record_families_render_visuals(void)
{
    static const uint16_t pie_arc_records[] = {0x4010u, 0x4011u, 0x4012u};
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;
    uint32_t expected_records = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(16, 16, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 4) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x4000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 1));
    CHECK(append_gdiplus_compressed_point(&payload, 6, 1));
    CHECK(append_gdiplus_compressed_point(&payload, 6, 6));
    CHECK(append_gdiplus_compressed_point(&payload, 1, 6));
    CHECK(rdp_buffer_append_u8(&payload, 0x00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&payload, 0x01u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&payload, 0x01u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&payload, 0x81u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0303u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x10000002u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0404u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 8) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x0026200au) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ff00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffffffffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff405060u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0106u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff405060u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0207u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff102030u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4013u, 0x8004u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff405060u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4014u, 0x8003u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff708090u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4015u, 0x8003u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xffa0b0c0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff010203u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4037u, 0x8003u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 9, 7, 3, 3));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 3) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 15.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_record(&stream, 0x401bu, 0x0005u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xffcc8844u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(rdp_buffer_append_u16_le(&payload, 'H') == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&payload, 'i') == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x401cu, 0x8000u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ccffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&payload, 'A') == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&payload, 'B') == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(append_gdiplus_record(&stream, 0x4036u, 0x8000u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0x12345678u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x90abcdefu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x11223344u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x55667788u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4038u, 0x0000u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff112233u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 1, 1, 3, 3));
    CHECK(append_gdiplus_record(&stream, 0x400bu, 0xc000u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    for (size_t i = 0; i < sizeof(pie_arc_records) / sizeof(pie_arc_records[0]); i++)
    {
        CHECK(rdp_buffer_append_u32_le(&payload, 0xff102030u) == LIBRDP_STATUS_OK);
        CHECK(rdp_buffer_append_u32_le(&payload, 0x00000000u) == LIBRDP_STATUS_OK);
        CHECK(rdp_buffer_append_u32_le(&payload, 0x42b40000u) == LIBRDP_STATUS_OK);
        CHECK(append_gdiplus_compressed_rect(&payload, 2, 2, 4, 4));
        CHECK(append_gdiplus_record(&stream, pie_arc_records[i], 0xc000u, &payload));
        expected_records++;
        rdp_buffer_free(&payload);
        rdp_buffer_init(&payload);
    }

    CHECK(rdp_buffer_append_u32_le(&payload, 6u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.5f));
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 10));
    CHECK(append_gdiplus_compressed_point(&payload, 5, 12));
    CHECK(append_gdiplus_compressed_point(&payload, 10, 10));
    CHECK(append_gdiplus_record(&stream, 0x4016u, 0x4000u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_float(&payload, 0.5f));
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 10));
    CHECK(append_gdiplus_compressed_point(&payload, 5, 12));
    CHECK(append_gdiplus_compressed_point(&payload, 10, 10));
    CHECK(append_gdiplus_record(&stream, 0x4017u, 0x4007u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_float(&payload, 0.5f));
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 10));
    CHECK(append_gdiplus_compressed_point(&payload, 5, 12));
    CHECK(append_gdiplus_compressed_point(&payload, 10, 10));
    CHECK(append_gdiplus_record(&stream, 0x4018u, 0x4007u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 4u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 10));
    CHECK(append_gdiplus_compressed_point(&payload, 5, 12));
    CHECK(append_gdiplus_compressed_point(&payload, 10, 10));
    CHECK(append_gdiplus_compressed_point(&payload, 14, 12));
    CHECK(append_gdiplus_record(&stream, 0x4019u, 0x4007u, &payload));
    expected_records++;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == expected_records);
    CHECK(rasterized >= 17u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 16u * 4u);
    CHECK(pixels[(1u * stride) + (8u * 4u)] == 0x30u &&
          pixels[(1u * stride) + (8u * 4u) + 1u] == 0x20u &&
          pixels[(1u * stride) + (8u * 4u) + 2u] == 0x10u);
    CHECK(pixels[(3u * stride) + (3u * 4u)] != 0u ||
          pixels[(3u * stride) + (3u * 4u) + 1u] != 0u ||
          pixels[(3u * stride) + (3u * 4u) + 2u] != 0u);
    CHECK(pixels[(7u * stride) + (9u * 4u) + 2u] == 0xffu);
    CHECK(pixels[(8u * stride) + (2u * 4u)] == 0x44u &&
          pixels[(8u * stride) + (2u * 4u) + 1u] == 0x88u &&
          pixels[(8u * stride) + (2u * 4u) + 2u] == 0xccu);

    stream.data[1] = 0x7fu;
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: proves that compressed EMF+ Image objects reach a real image
 * decoder for both DrawImage forms. The golden pixels catch placeholder
 * rendering, channel-order mistakes and incorrect destination scaling.
 */
int test_gdiplus_compressed_images_render_pixels(void)
{
    static const uint8_t png_2x2[] = {
        0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
        0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
        0x00u, 0x00u, 0x00u, 0x02u, 0x00u, 0x00u, 0x00u, 0x02u,
        0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x72u, 0xb6u, 0x0du,
        0x24u, 0x00u, 0x00u, 0x00u, 0x12u, 0x49u, 0x44u, 0x41u,
        0x54u, 0x78u, 0x9cu, 0x63u, 0xf8u, 0xcfu, 0xc0u, 0xf0u,
        0x1fu, 0x0cu, 0x81u, 0x34u, 0x18u, 0x00u, 0x00u, 0x49u,
        0xc8u, 0x09u, 0xf7u, 0xf9u, 0xabu, 0xb6u, 0x0du, 0x00u,
        0x00u, 0x00u, 0x00u, 0x49u, 0x45u, 0x4eu, 0x44u, 0xaeu,
        0x42u, 0x60u, 0x82u
    };
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_QUARTZ)
    const uint8_t* pixels = NULL;
    size_t stride = 0u;
#endif
    uint32_t records = 0u;
    uint32_t rasterized = 0u;
    uint32_t unsupported = 0u;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(8u, 4u, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append(&payload, png_2x2, sizeof(png_2x2)) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0u, 0u, 4u, 4u));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_float(&payload, 4.0f));
    CHECK(append_gdiplus_record(&stream, 0x401bu, 0x0005u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 3u);
#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_QUARTZ)
    CHECK(rasterized == 2u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 8u * 4u);
    CHECK(pixels[0u] == 0x00u && pixels[1u] == 0x00u && pixels[2u] == 0xffu);
    CHECK(pixels[(3u * 4u) + 0u] == 0x00u &&
          pixels[(3u * 4u) + 1u] == 0xffu &&
          pixels[(3u * 4u) + 2u] == 0x00u);
    CHECK(pixels[(3u * stride) + 0u] == 0xffu &&
          pixels[(3u * stride) + 1u] == 0x00u &&
          pixels[(3u * stride) + 2u] == 0x00u);
    CHECK(pixels[(3u * stride) + (7u * 4u) + 0u] == 0xffu &&
          pixels[(3u * stride) + (7u * 4u) + 1u] == 0xffu &&
          pixels[(3u * stride) + (7u * 4u) + 2u] == 0xffu);
#else
    CHECK(rasterized == 0u);
    CHECK(unsupported == 2u);
#endif

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    records = 0u;
    rasterized = 0u;
    unsupported = 0u;

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x0026200au) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ff00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffffffffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0u, 0u, 2u, 2u));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(rasterized == 0u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    records = 0u;
    rasterized = 0u;
    unsupported = 0u;

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 8u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x0026200au) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ff00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffffffffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 3.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0u, 0u, 2u, 2u));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(rasterized == 0u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: verifies that every compressed-image backend returns top-down,
 * straight-alpha BGRA pixels. It catches backend-specific channel ordering and
 * premultiplication differences before GDI+ scaling blends the decoded image.
 */
int test_gdiplus_compressed_image_pixel_contract(void)
{
    static const uint8_t png_red_half_alpha[] = {
        0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
        0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
        0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x01u,
        0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x1fu, 0x15u, 0xc4u,
        0x89u, 0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x44u, 0x41u,
        0x54u, 0x08u, 0xd7u, 0x63u, 0xf8u, 0xcfu, 0xc0u, 0xd0u,
        0x00u, 0x00u, 0x04u, 0x81u, 0x01u, 0x80u, 0xd7u, 0x50u,
        0xa1u, 0xcau, 0x00u, 0x00u, 0x00u, 0x00u, 0x49u, 0x45u,
        0x4eu, 0x44u, 0xaeu, 0x42u, 0x60u, 0x82u
    };
    rdp_gdi_image image;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_gdi_image_init(&image);
    status = rdp_gdi_image_decode(png_red_half_alpha,
                                  sizeof(png_red_half_alpha),
                                  &image);
#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_QUARTZ)
    CHECK(status == LIBRDP_STATUS_OK);
    CHECK(image.width == 1u && image.height == 1u && image.stride >= 4u);
    CHECK(image.pixels != NULL);
    CHECK(image.pixels[0] == 0u);
    CHECK(image.pixels[1] == 0u);
    CHECK(image.pixels[2] == 255u);
    CHECK(image.pixels[3] == 128u);
#else
    CHECK(status == LIBRDP_STATUS_UNSUPPORTED);
#endif
    rdp_gdi_image_clear(&image);
    return 0;
}

/*
 * Coverage: separates malformed compressed input from well-formed image types
 * for which no rasterizer exists. It prevents either path from incrementing
 * the successful-rasterization counter.
 */
int test_gdiplus_image_failure_accounting(void)
{
    static const uint8_t truncated_png[] = {
        0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
        0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u
    };
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    uint32_t records = 0u;
    uint32_t rasterized = 0u;
    uint32_t unsupported = 0u;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(4u, 4u, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0u, 0u, 2u, 2u));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 2u && rasterized == 0u && unsupported == 1u);

    rdp_buffer_free(&stream);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    records = 0u;
    rasterized = 0u;
    unsupported = 0u;

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append(&payload, truncated_png, sizeof(truncated_png)) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0u, 0u, 2u, 2u));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_QUARTZ)
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_PROTOCOL_ERROR);
#else
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(rasterized == 0u && unsupported == 1u);
#endif

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: verifies EMF+ state records whose effect is visible through later
 * drawing. Page transform must affect geometry, compositing mode must affect
 * alpha handling, and save/restore must preserve the expanded state snapshot.
 */
int test_gdiplus_graphics_state_affects_rendering(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(10, 10, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 1, 1, 1, 1));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_record(&stream, 0x4023u, 0x0001u, &payload));
    CHECK(rdp_buffer_append_u32_le(&payload, 0x8000ff00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 1, 1, 1, 1));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_record(&stream, 0x4030u, 0x0002u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_record(&stream, 0x4025u, 0x0000u, &payload));
    CHECK(append_gdiplus_float(&payload, 3.0f));
    CHECK(append_gdiplus_record(&stream, 0x4030u, 0x0002u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 1, 1, 1, 1));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_record(&stream, 0x4026u, 0x0000u, &payload));
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ffffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 2, 2, 1, 1));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 9u);
    CHECK(rasterized == 4u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 10u * 4u);
    CHECK(pixels[(1u * stride) + (1u * 4u)] == 0x00u &&
          pixels[(1u * stride) + (1u * 4u) + 1u] == 0xffu &&
          pixels[(1u * stride) + (1u * 4u) + 2u] == 0x00u);
    CHECK(pixels[(3u * stride) + (3u * 4u)] == 0xffu &&
          pixels[(3u * stride) + (3u * 4u) + 1u] == 0x00u &&
          pixels[(3u * stride) + (3u * 4u) + 2u] == 0x00u);
    CHECK(pixels[(4u * stride) + (4u * 4u)] == 0xffu &&
          pixels[(4u * stride) + (4u * 4u) + 1u] == 0xffu &&
          pixels[(4u * stride) + (4u * 4u) + 2u] == 0x00u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: exercises non-solid EMF+ brush objects through real per-pixel
 * sampling. The hatch checks rendering-origin phase, and the gradient/texture
 * checks catch regressions where complex brushes collapse back to one
 * representative color.
 */
int test_gdiplus_complex_brushes_sample_pixels(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(10, 10, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0101u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x401du, 0x0000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 0, 0, 8, 2));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x4000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 4u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 3.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(append_gdiplus_float(&payload, 1.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffffffffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0102u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 0, 3, 8, 1));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x4000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ff00u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff00ffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0103u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 0, 5, 4, 2));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x4000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff0000ffu) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 5.0f));
    CHECK(append_gdiplus_float(&payload, 8.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0104u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 4u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 4, 7, 4, 2));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0x4000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 9u);
    CHECK(rasterized == 4u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 10u * 4u);
    CHECK(pixels[0u * stride + 0u * 4u + 2u] != pixels[0u * stride + 3u * 4u + 2u]);
    CHECK(pixels[3u * stride + 0u * 4u] < pixels[3u * stride + 7u * 4u]);
    CHECK(pixels[5u * stride + 0u * 4u + 1u] != pixels[5u * stride + 1u * 4u + 1u] ||
          pixels[5u * stride + 0u * 4u + 2u] != pixels[5u * stride + 1u * 4u + 2u]);
    CHECK(pixels[8u * stride + 5u * 4u] > pixels[8u * stride + 7u * 4u]);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: verifies that SetInterpolationMode changes image sampling instead
 * of being a state-only no-op, and that font/string-format/image-attribute
 * objects are validated and retained without inflating unsupported counts.
 */
int test_gdiplus_interpolation_and_metadata_objects(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(8, 8, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 6u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 12.0f));
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0606u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 7u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000800u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0707u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x00000001u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0808u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, (uint32_t)-8) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0x0026200au) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff000000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffffffffu) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0xff00ff00u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4008u, 0x0505u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_record(&stream, 0x4021u, 0x0003u, &payload));

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 0, 0, 4, 4));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(append_gdiplus_record(&stream, 0x4021u, 0x0000u, &payload));
    CHECK(append_gdiplus_record(&stream, 0x4024u, 0x0004u, &payload));

    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 0.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_float(&payload, 2.0f));
    CHECK(append_gdiplus_compressed_rect(&payload, 4, 0, 4, 4));
    CHECK(append_gdiplus_record(&stream, 0x401au, 0x4005u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 9u);
    CHECK(rasterized == 2u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 8u * 4u);
    CHECK(pixels[1u * stride + 1u * 4u] != 0xffu);
    CHECK(pixels[1u * stride + 1u * 4u + 1u] != 0x00u ||
          pixels[1u * stride + 1u * 4u + 2u] != 0x00u);
    CHECK(pixels[1u * stride + 5u * 4u] != 0xffu);
    CHECK(pixels[1u * stride + 5u * 4u + 1u] != 0x00u ||
          pixels[1u * stride + 5u * 4u + 2u] != 0x00u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: verifies GDI+ antialias state through a visible alpha edge on a
 * direct-color line. It catches regressions where SetAntiAliasMode is parsed
 * and saved but never influences rasterization.
 */
int test_gdiplus_antialias_affects_line_edges(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(8, 8, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(append_gdiplus_record(&stream, 0x401eu, 0x0001u, &payload));
    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 2u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1, 1));
    CHECK(append_gdiplus_compressed_point(&payload, 6, 1));
    CHECK(append_gdiplus_record(&stream, 0x400du, 0xc000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 2u);
    CHECK(rasterized == 1u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 8u * 4u);
    CHECK(pixels[1u * stride + 1u * 4u + 2u] == 0xffu);
    CHECK(pixels[2u * stride + 1u * 4u + 2u] > 0u &&
          pixels[2u * stride + 1u * 4u + 2u] < 0xffu);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

/*
 * Coverage: verifies that EMF+ clip state restricts later visual records to
 * the clipped area. It catches regressions where SetClipRect updates parser
 * state but FillRects still writes outside the active clip bounds.
 */
int test_gdiplus_clip_limits_visual_output(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* surface = NULL;
    const uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t records = 0;
    uint32_t rasterized = 0;
    uint32_t unsupported = 0;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    surface = librdp_surface_new(6, 6, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);

    CHECK(append_gdiplus_compressed_rect(&payload, 1, 1, 2, 2));
    CHECK(append_gdiplus_record(&stream, 0x4032u, 0x0000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xffff0000u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 0, 0, 5, 5));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_OK);
    CHECK(records == 2u);
    CHECK(rasterized == 1u);
    CHECK(unsupported == 0u);
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    CHECK(pixels != NULL && stride >= 6u * 4u);
    CHECK(pixels[1u * stride + 1u * 4u + 2u] == 0xffu);
    CHECK(pixels[0u * stride + 0u * 4u + 2u] == 0x00u);
    CHECK(pixels[4u * stride + 4u * 4u + 2u] == 0x00u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(surface);
    return 0;
}

static int gdiplus_pixels_match(const librdp_surface* reference,
                                const librdp_surface* candidate,
                                uint8_t channel_tolerance,
                                uint32_t differing_channel_limit_per_mille,
                                uint32_t absolute_error_limit_per_mille)
{
    const uint8_t* reference_pixels = librdp_surface_pixels(reference);
    const uint8_t* candidate_pixels = librdp_surface_pixels(candidate);
    size_t reference_stride = librdp_surface_stride(reference);
    size_t candidate_stride = librdp_surface_stride(candidate);
    uint32_t width = librdp_surface_width(reference);
    uint32_t height = librdp_surface_height(reference);
    uint32_t y = 0u;
    uint32_t differing_channels = 0u;
    uint64_t absolute_error = 0u;
    uint64_t channel_count = (uint64_t)width * height * 4u;
    uint8_t maximum_error = 0u;

    if (!reference_pixels || !candidate_pixels ||
        width != librdp_surface_width(candidate) ||
        height != librdp_surface_height(candidate))
        return 0;
    for (y = 0u; y < height; y++)
    {
        uint32_t x = 0u;

        for (x = 0u; x < width * 4u; x++)
        {
            uint8_t a = reference_pixels[((size_t)y * reference_stride) + x];
            uint8_t b = candidate_pixels[((size_t)y * candidate_stride) + x];
            uint8_t difference = a > b ? (uint8_t)(a - b) : (uint8_t)(b - a);

            absolute_error += difference;
            if (difference > maximum_error)
                maximum_error = difference;
            if (difference > channel_tolerance)
                differing_channels++;
        }
    }
    if (((uint64_t)differing_channels * 1000u >
         channel_count * differing_channel_limit_per_mille) ||
        (absolute_error * 1000u >
         channel_count * 255u * absolute_error_limit_per_mille))
    {
        fprintf(stderr,
                "GDI+ backend difference channels=%u absolute_error=%llu maximum_error=%u channel_tolerance=%u\n",
                differing_channels,
                (unsigned long long)absolute_error,
                maximum_error,
                channel_tolerance);
        return 0;
    }
    return 1;
}

/*
 * Coverage: compares opaque GDI+ primitives rendered by the software and
 * requested native backends. Per-channel rounding and a bounded aggregate
 * raster difference account for native edge coverage while still detecting
 * geometry, clipping, channel-order and alpha regressions.
 */
static int test_gdiplus_native_pixel_parity(void)
{
    rdp_buffer stream;
    rdp_buffer payload;
    librdp_surface* reference = NULL;
    librdp_surface* candidate = NULL;
    uint32_t reference_records = 0u;
    uint32_t candidate_records = 0u;
    uint32_t reference_rasterized = 0u;
    uint32_t candidate_rasterized = 0u;
    uint32_t reference_unsupported = 0u;
    uint32_t candidate_unsupported = 0u;

    rdp_buffer_init(&stream);
    rdp_buffer_init(&payload);
    reference = librdp_surface_new(16u, 16u, LIBRDP_PIXEL_FORMAT_BGRA32);
    candidate = librdp_surface_new(16u, 16u, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(reference != NULL && candidate != NULL);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff102030u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_record(&stream, 0x4009u, 0u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff204080u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 1u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 1u, 1u, 6u, 4u));
    CHECK(append_gdiplus_record(&stream, 0x400au, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xff80c020u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&payload, 3u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_point(&payload, 1u, 7u));
    CHECK(append_gdiplus_compressed_point(&payload, 7u, 7u));
    CHECK(append_gdiplus_compressed_point(&payload, 7u, 12u));
    CHECK(append_gdiplus_record(&stream, 0x400du, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xffc04080u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 9u, 1u, 5u, 5u));
    CHECK(append_gdiplus_record(&stream, 0x400eu, 0xc000u, &payload));
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);

    CHECK(rdp_buffer_append_u32_le(&payload, 0xfff0e0d0u) == LIBRDP_STATUS_OK);
    CHECK(append_gdiplus_compressed_rect(&payload, 9u, 8u, 5u, 5u));
    CHECK(append_gdiplus_record(&stream, 0x400fu, 0xc000u, &payload));

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
                                                reference,
                                                stream.data,
                                                stream.length,
                                                &reference_records,
                                                &reference_rasterized,
                                                &reference_unsupported) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_gdi_backend_render_gdiplus_stream(gdiplus_test_backend(),
                                                candidate,
                                                stream.data,
                                                stream.length,
                                                &candidate_records,
                                                &candidate_rasterized,
                                                &candidate_unsupported) ==
          LIBRDP_STATUS_OK);
    CHECK(reference_records == 5u && candidate_records == reference_records);
    CHECK(reference_rasterized == 5u &&
          candidate_rasterized == reference_rasterized);
    CHECK(reference_unsupported == 0u && candidate_unsupported == 0u);
    CHECK(gdiplus_pixels_match(reference, candidate, 1u, 150u, 100u));

    rdp_buffer_free(&payload);
    rdp_buffer_free(&stream);
    librdp_surface_free(candidate);
    librdp_surface_free(reference);
    return 0;
}

/*
 * Coverage: replays the complete GDI+ graphics suite through a requested
 * native raster backend. CTest selects Cairo or Quartz explicitly so backend
 * discovery cannot silently fall back to the software renderer.
 */
int test_gdiplus_native_backend(void)
{
    const char* requested = getenv("LIBRDP_TEST_GDIPLUS_BACKEND");
    rdp_gdi_backend_kind backend = gdiplus_test_backend();
    rdp_gdi_backend_caps caps;

    CHECK(requested != NULL);
    CHECK((strcmp(requested, "cairo") == 0 && backend == RDP_GDI_BACKEND_CAIRO) ||
          (strcmp(requested, "quartz") == 0 && backend == RDP_GDI_BACKEND_QUARTZ));
    CHECK(rdp_gdi_backend_query(backend, &caps) == LIBRDP_STATUS_OK);
    CHECK(caps.name != NULL && strcmp(caps.name, requested) == 0);
    CHECK((caps.caps & RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM) != 0u);
    if (test_gdiplus_native_pixel_parity() != 0 ||
        test_gdiplus_object_table_solid_brush_and_pen() != 0 ||
        test_gdiplus_known_record_families_render_visuals() != 0 ||
        test_gdiplus_compressed_images_render_pixels() != 0 ||
        test_gdiplus_compressed_image_pixel_contract() != 0 ||
        test_gdiplus_image_failure_accounting() != 0 ||
        test_gdiplus_graphics_state_affects_rendering() != 0 ||
        test_gdiplus_complex_brushes_sample_pixels() != 0 ||
        test_gdiplus_interpolation_and_metadata_objects() != 0 ||
        test_gdiplus_antialias_affects_line_edges() != 0)
        return 1;
    return test_gdiplus_clip_limits_visual_output();
}

static int append_cache_bitmap_v1_payload(rdp_buffer* payload,
                                          uint8_t width,
                                          uint8_t height,
                                          uint8_t bits_per_pixel,
                                          uint16_t cache_index,
                                          const void* data,
                                          uint16_t data_len)
{
    return payload && data && data_len > 0 &&
           rdp_buffer_append_u8(payload, 1u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, 0u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, width) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, height) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, bits_per_pixel) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, data_len) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, cache_index) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(payload, data, data_len) == LIBRDP_STATUS_OK;
}

static int append_cache_bitmap_v3_payload(rdp_buffer* payload,
                                          uint8_t codec_id,
                                          uint16_t width,
                                          uint16_t height,
                                          uint16_t cache_index,
                                          const void* data,
                                          uint32_t data_len)
{
    return payload && data && data_len > 0 &&
           rdp_buffer_append_u16_le(payload, cache_index) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(payload, 0x11223344u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(payload, 0x55667788u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, 32u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, 0u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, 0u) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u8(payload, codec_id) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, width) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u16_le(payload, height) == LIBRDP_STATUS_OK &&
           rdp_buffer_append_u32_le(payload, data_len) == LIBRDP_STATUS_OK &&
           rdp_buffer_append(payload, data, data_len) == LIBRDP_STATUS_OK;
}

static librdp_status apply_cache_bitmap_order(librdp_session* session,
                                              uint16_t extra_flags,
                                              uint8_t order_type,
                                              const rdp_buffer* payload)
{
    rdp_buffer encoded;
    rdp_gdi_orders_update update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&encoded);
    status = rdp_gdi_write_secondary_order(&encoded,
                                           extra_flags,
                                           order_type,
                                           payload->data,
                                           payload->length);
    if (status == LIBRDP_STATUS_OK)
    {
        memset(&update, 0, sizeof(update));
        update.update_type = RDP_GDI_UPDATE_TYPE_ORDERS;
        update.number_orders = 1u;
        update.order_data = encoded.data;
        update.order_data_len = encoded.length;
        status = rdp_session_apply_gdi_orders_update(session, &update);
    }
    rdp_buffer_free(&encoded);
    return status;
}

static rdp_session_gdi_bitmap_cache_entry* find_test_bitmap_cache_entry(librdp_session* session,
                                                                        uint32_t cache_id,
                                                                        uint32_t cache_index)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_bitmap_cache_entry* entry = &session->gdi_bitmap_cache[i];

        if (entry->active && entry->cache_id == cache_id && entry->cache_index == cache_index)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_offscreen_bitmap* find_test_offscreen_surface(librdp_session* session,
                                                                     uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_offscreen_bitmap* entry = &session->gdi_offscreen_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_saved_bitmap* find_test_saved_bitmap(librdp_session* session,
                                                            uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
    {
        rdp_session_gdi_saved_bitmap* entry = &session->gdi_saved_bitmaps[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_ninegrid_cache_entry* find_test_ninegrid(librdp_session* session,
                                                                uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_ninegrid_cache_entry* entry = &session->gdi_ninegrid_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static int append_test_secondary_order(rdp_buffer* orders,
                                       uint16_t extra_flags,
                                       uint8_t order_type,
                                       const void* payload,
                                       size_t payload_len)
{
    rdp_buffer encoded;
    int ok = 0;

    if (!orders || (!payload && payload_len > 0))
        return 0;
    rdp_buffer_init(&encoded);
    ok = rdp_gdi_write_secondary_order(&encoded,
                                       extra_flags,
                                       order_type,
                                       payload,
                                       payload_len) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(orders, encoded.data, encoded.length) == LIBRDP_STATUS_OK;
    rdp_buffer_free(&encoded);
    return ok;
}

static int append_test_altsec_order(rdp_buffer* orders,
                                    uint8_t order_type,
                                    const rdp_buffer* payload)
{
    rdp_buffer encoded;
    int ok = 0;

    if (!orders || !payload)
        return 0;
    rdp_buffer_init(&encoded);
    ok = rdp_gdi_write_altsec_order(&encoded,
                                    order_type,
                                    payload->data,
                                    payload->length) == LIBRDP_STATUS_OK &&
         rdp_buffer_append(orders, encoded.data, encoded.length) == LIBRDP_STATUS_OK;
    rdp_buffer_free(&encoded);
    return ok;
}

static librdp_status apply_test_gdi_orders(librdp_session* session,
                                           const rdp_buffer* orders,
                                           uint16_t order_count)
{
    rdp_gdi_orders_update update;

    if (!session || !orders)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&update, 0, sizeof(update));
    update.update_type = RDP_GDI_UPDATE_TYPE_ORDERS;
    update.number_orders = order_count;
    update.order_data = orders->data;
    update.order_data_len = orders->length;
    return rdp_session_apply_gdi_orders_update(session, &update);
}

/*
 * Coverage: proves raw, RLE, NSCodec, and RemoteFX cache orders are bounded
 * before decoder allocation. Every rejected replacement targets an existing
 * cache key so the fixture also locks transactional cache ownership.
 */
int test_gdi_bitmap_cache_limits(void)
{
    const uint8_t valid_pixel[] = {0x10u, 0x20u, 0x30u, 0xffu};
    const uint8_t invalid_payload[] = {0x80u};
    const uint16_t rev3_flags =
        (uint16_t)(1u | (6u << 3u) | (RDP_GDI_CBR3_IGNORABLE_FLAG << 7u));
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_metrics metrics;
    rdp_buffer payload;
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;
    uint8_t* saved_pixels = NULL;
    size_t saved_length = 0;
    size_t saved_cache_bytes = 0;
    uint64_t saved_clock = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_desktop_size(
              settings,
              LIBRDP_DESKTOP_MIN_DIMENSION,
              LIBRDP_DESKTOP_MIN_DIMENSION) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    session->limits.surface_max_dimension = 1u;

    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v1_payload(&payload,
                                         1u,
                                         1u,
                                         32u,
                                         5u,
                                         valid_pixel,
                                         (uint16_t)sizeof(valid_pixel)));
    CHECK(apply_cache_bitmap_order(session,
                                   0u,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                   &payload) == LIBRDP_STATUS_OK);
    entry = find_test_bitmap_cache_entry(session, 1u, 5u);
    CHECK(entry != NULL && entry->pixels.length == sizeof(valid_pixel));
    saved_pixels = entry->pixels.data;
    saved_length = entry->pixels.length;
    saved_cache_bytes = session->gdi_bitmap_cache_bytes;
    saved_clock = session->gdi_bitmap_cache_clock;

    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v1_payload(&payload,
                                         2u,
                                         2u,
                                         32u,
                                         5u,
                                         invalid_payload,
                                         (uint16_t)sizeof(invalid_payload)));
    CHECK(apply_cache_bitmap_order(session,
                                   0u,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                   &payload) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v1_payload(&payload,
                                         2u,
                                         2u,
                                         32u,
                                         5u,
                                         invalid_payload,
                                         (uint16_t)sizeof(invalid_payload)));
    CHECK(apply_cache_bitmap_order(session,
                                   RDP_GDI_NO_BITMAP_COMPRESSION_HEADER,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                   &payload) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v3_payload(&payload,
                                         RDP_SURFACE_CODEC_NSCODEC,
                                         2u,
                                         2u,
                                         5u,
                                         invalid_payload,
                                         (uint32_t)sizeof(invalid_payload)));
    CHECK(apply_cache_bitmap_order(session,
                                   rev3_flags,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                   &payload) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v3_payload(&payload,
                                         RDP_SURFACE_CODEC_REMOTEFX,
                                         2u,
                                         2u,
                                         5u,
                                         invalid_payload,
                                         (uint32_t)sizeof(invalid_payload)));
    CHECK(apply_cache_bitmap_order(session,
                                   rev3_flags,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                   &payload) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    session->limits.surface_max_dimension = RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION;
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    CHECK(append_cache_bitmap_v3_payload(&payload,
                                         RDP_SURFACE_CODEC_NSCODEC,
                                         (uint16_t)RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION,
                                         (uint16_t)RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION,
                                         5u,
                                         invalid_payload,
                                         (uint32_t)sizeof(invalid_payload)));
    CHECK(apply_cache_bitmap_order(session,
                                   rev3_flags,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3,
                                   &payload) == LIBRDP_STATUS_LIMIT_EXCEEDED);

    entry = find_test_bitmap_cache_entry(session, 1u, 5u);
    CHECK(entry != NULL);
    CHECK(entry->pixels.data == saved_pixels && entry->pixels.length == saved_length);
    CHECK(memcmp(entry->pixels.data, valid_pixel, sizeof(valid_pixel)) == 0);
    CHECK(session->gdi_bitmap_cache_bytes == saved_cache_bytes);
    CHECK(session->gdi_bitmap_cache_clock == saved_clock);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) == LIBRDP_STATUS_OK);
    CHECK(metrics.limits_rejected == 5u);

    rdp_buffer_free(&payload);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: fills the bitmap cache, refreshes one entry through a render
 * lookup, and inserts one more bitmap. The oldest untouched entry must be
 * evicted while byte accounting and recently used data remain intact.
 */
int test_gdi_bitmap_cache_eviction(void)
{
    const uint8_t pixel[] = {0x10u, 0x20u, 0x30u, 0xffu};
    const uint8_t touch_first[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x01u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x01u, 0x00u,
        0x01u, 0x00u,
        0xccu,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_buffer payload;
    rdp_buffer primary;
    size_t i = 0;
    size_t active = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_desktop_size(
              settings,
              LIBRDP_DESKTOP_MIN_DIMENSION,
              LIBRDP_DESKTOP_MIN_DIMENSION) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&primary);

    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        payload.length = 0;
        CHECK(append_cache_bitmap_v1_payload(&payload,
                                             1u,
                                             1u,
                                             32u,
                                             (uint16_t)i,
                                             pixel,
                                             (uint16_t)sizeof(pixel)));
        CHECK(apply_cache_bitmap_order(session,
                                       0u,
                                       RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                       &payload) == LIBRDP_STATUS_OK);
    }
    CHECK(find_test_bitmap_cache_entry(session, 1u, 0u) != NULL);
    CHECK(find_test_bitmap_cache_entry(session, 1u, 1u) != NULL);

    CHECK(rdp_buffer_append(&primary, touch_first, sizeof(touch_first)) == LIBRDP_STATUS_OK);
    CHECK(apply_test_gdi_orders(session, &primary, 1u) == LIBRDP_STATUS_OK);

    payload.length = 0;
    CHECK(append_cache_bitmap_v1_payload(&payload,
                                         1u,
                                         1u,
                                         32u,
                                         (uint16_t)RDP_SESSION_GDI_BITMAP_CACHE_SLOTS,
                                         pixel,
                                         (uint16_t)sizeof(pixel)));
    CHECK(apply_cache_bitmap_order(session,
                                   0u,
                                   RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                   &payload) == LIBRDP_STATUS_OK);
    CHECK(find_test_bitmap_cache_entry(session, 1u, 0u) != NULL);
    CHECK(find_test_bitmap_cache_entry(session, 1u, 1u) == NULL);
    CHECK(find_test_bitmap_cache_entry(session,
                                       1u,
                                       RDP_SESSION_GDI_BITMAP_CACHE_SLOTS) != NULL);
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        if (session->gdi_bitmap_cache[i].active)
            active++;
    }
    CHECK(active == RDP_SESSION_GDI_BITMAP_CACHE_SLOTS);
    CHECK(session->gdi_bitmap_cache_bytes ==
          RDP_SESSION_GDI_BITMAP_CACHE_SLOTS * sizeof(pixel));

    rdp_buffer_free(&primary);
    rdp_buffer_free(&payload);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Coverage: drives cache insertion and lookup, offscreen rendering, cached
 * brushes and glyphs, save/restore, nine-grid scaling, and deliberate misses
 * through one runtime order stream. Assertions cover both cache ownership and
 * the resulting primary/offscreen pixels.
 */
int test_gdi_cache_lifecycle(void)
{
    static const uint8_t bitmap_pixels[] = {
        0x01u, 0x02u, 0x03u, 0xffu, 0x11u, 0x12u, 0x13u, 0xffu,
        0x21u, 0x22u, 0x23u, 0xffu, 0x31u, 0x32u, 0x33u, 0xffu,
        0x41u, 0x42u, 0x43u, 0xffu, 0x51u, 0x52u, 0x53u, 0xffu,
        0x61u, 0x62u, 0x63u, 0xffu, 0x71u, 0x72u, 0x73u, 0xffu,
        0x81u, 0x82u, 0x83u, 0xffu, 0x91u, 0x92u, 0x93u, 0xffu,
        0xa1u, 0xa2u, 0xa3u, 0xffu, 0xb1u, 0xb2u, 0xb3u, 0xffu,
        0xc1u, 0xc2u, 0xc3u, 0xffu, 0xd1u, 0xd2u, 0xd3u, 0xffu,
        0xe1u, 0xe2u, 0xe3u, 0xffu, 0xf1u, 0xf2u, 0xf3u, 0xffu
    };
    static const uint8_t brush_payload[] = {
        3u, RDP_GDI_BMF_1BPP, 8u, 8u, 0u, 8u,
        0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u
    };
    static const uint8_t glyph_payload[] = {
        1u, 1u,
        2u, 0u, 0u, 0u, 0u, 0u, 8u, 0u, 2u, 0u,
        0x80u, 0x40u, 0u, 0u,
        'A', 0u
    };
    static const uint8_t offscreen_fill[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x1fu,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x04u, 0x00u, 0x04u, 0x00u,
        0x11u, 0x22u, 0x33u
    };
    static const uint8_t bitmap_hit[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x01u, 0x00u,
        0x0au, 0x00u, 0x0au, 0x00u,
        0x04u, 0x00u, 0x04u, 0x00u,
        0xccu,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x05u, 0x00u
    };
    static const uint8_t brush_hit[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_PATBLT,
        0xffu, 0x0fu,
        0x14u, 0x00u, 0x14u, 0x00u,
        0x08u, 0x00u, 0x08u, 0x00u,
        0xf0u,
        0x10u, 0x20u, 0x30u,
        0x40u, 0x50u, 0x60u,
        0x00u, 0x00u, 0x00u, 0x00u,
        RDP_GDI_CACHED_BRUSH | RDP_GDI_BMF_1BPP,
        3u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u
    };
    static const uint8_t glyph_hit_and_miss[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_GLYPH_INDEX,
        0xffu, 0x3fu, 0x38u,
        1u, RDP_GDI_GLYPH_SO_HORIZONTAL, 1u, 0u,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u,
        60u, 0u, 60u, 0u, 80u, 0u, 70u, 0u,
        60u, 0u, 60u, 0u, 80u, 0u, 70u, 0u,
        61u, 0u, 62u, 0u,
        2u, 2u, 99u
    };
    static const uint8_t save_source[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x1fu,
        0x28u, 0x00u, 0x28u, 0x00u,
        0x04u, 0x00u, 0x04u, 0x00u,
        0x10u, 0x20u, 0x30u
    };
    static const uint8_t save_store[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SAVEBITMAP,
        0x3fu,
        0x11u, 0x11u, 0x11u, 0x11u,
        0x28u, 0x00u, 0x28u, 0x00u,
        0x2bu, 0x00u, 0x2bu, 0x00u,
        0u
    };
    static const uint8_t save_overwrite[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x1fu,
        0x28u, 0x00u, 0x28u, 0x00u,
        0x04u, 0x00u, 0x04u, 0x00u,
        0xaau, 0xbbu, 0xccu
    };
    static const uint8_t save_restore[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SAVEBITMAP,
        0x3fu,
        0x11u, 0x11u, 0x11u, 0x11u,
        0x28u, 0x00u, 0x28u, 0x00u,
        0x2bu, 0x00u, 0x2bu, 0x00u,
        1u
    };
    static const uint8_t save_miss[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_SAVEBITMAP,
        0x3fu,
        0x22u, 0x22u, 0x22u, 0x22u,
        0x30u, 0x00u, 0x30u, 0x00u,
        0x33u, 0x00u, 0x33u, 0x00u,
        1u
    };
    static const uint8_t ninegrid_hit[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_DRAWNINEGRID,
        0x1fu, 0x0fu,
        0x50u, 0x00u, 0x14u, 0x00u,
        0x57u, 0x00u, 0x1bu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x03u, 0x00u, 0x03u, 0x00u,
        0x05u, 0x00u
    };
    static const uint8_t ninegrid_miss[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_DRAWNINEGRID,
        0x1fu, 0x0fu,
        0x60u, 0x00u, 0x14u, 0x00u,
        0x67u, 0x00u, 0x1bu, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x03u, 0x00u, 0x03u, 0x00u,
        0x63u, 0x00u
    };
    static const uint8_t bitmap_miss[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_MEMBLT,
        0xffu, 0x01u,
        0x01u, 0x00u,
        0x70u, 0x00u, 0x14u, 0x00u,
        0x02u, 0x00u, 0x02u, 0x00u,
        0xccu,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x63u, 0x00u
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    rdp_session_gdi_offscreen_bitmap* offscreen = NULL;
    rdp_gdi_create_offscreen_bitmap_order create_offscreen;
    rdp_gdi_create_ninegrid_bitmap_order create_ninegrid;
    rdp_gdi_switch_surface_order switch_surface;
    rdp_buffer orders;
    rdp_buffer payload;
    const uint8_t* primary_pixels = NULL;
    const uint8_t* offscreen_pixels = NULL;
    size_t primary_stride = 0;
    size_t offscreen_stride = 0;
    uint16_t order_count = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_desktop_size(
              settings,
              LIBRDP_DESKTOP_MIN_DIMENSION,
              LIBRDP_DESKTOP_MIN_DIMENSION) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    rdp_buffer_init(&orders);
    rdp_buffer_init(&payload);

    CHECK(append_cache_bitmap_v1_payload(&payload,
                                         4u,
                                         4u,
                                         32u,
                                         5u,
                                         bitmap_pixels,
                                         (uint16_t)sizeof(bitmap_pixels)));
    CHECK(append_test_secondary_order(&orders,
                                      0u,
                                      RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED,
                                      payload.data,
                                      payload.length));
    order_count++;
    CHECK(append_test_secondary_order(&orders,
                                      0u,
                                      RDP_GDI_SECONDARY_CACHE_BRUSH,
                                      brush_payload,
                                      sizeof(brush_payload)));
    order_count++;
    CHECK(append_test_secondary_order(&orders,
                                      RDP_GDI_CACHE_GLYPH_UNICODE_PRESENT,
                                      RDP_GDI_SECONDARY_CACHE_GLYPH,
                                      glyph_payload,
                                      sizeof(glyph_payload)));
    order_count++;

    memset(&create_offscreen, 0, sizeof(create_offscreen));
    create_offscreen.bitmap_id = 7u;
    create_offscreen.width = 8u;
    create_offscreen.height = 8u;
    payload.length = 0;
    CHECK(rdp_gdi_write_create_offscreen_bitmap_order(&payload,
                                                      &create_offscreen) == LIBRDP_STATUS_OK);
    CHECK(append_test_altsec_order(&orders,
                                   RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP,
                                   &payload));
    order_count++;
    memset(&switch_surface, 0, sizeof(switch_surface));
    switch_surface.bitmap_id = create_offscreen.bitmap_id;
    payload.length = 0;
    CHECK(rdp_gdi_write_switch_surface_order(&payload,
                                             &switch_surface) == LIBRDP_STATUS_OK);
    CHECK(append_test_altsec_order(&orders,
                                   RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                   &payload));
    order_count++;
    CHECK(rdp_buffer_append(&orders, offscreen_fill, sizeof(offscreen_fill)) ==
          LIBRDP_STATUS_OK);
    order_count++;
    switch_surface.bitmap_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    payload.length = 0;
    CHECK(rdp_gdi_write_switch_surface_order(&payload,
                                             &switch_surface) == LIBRDP_STATUS_OK);
    CHECK(append_test_altsec_order(&orders,
                                   RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                   &payload));
    order_count++;

    CHECK(rdp_buffer_append(&orders, bitmap_hit, sizeof(bitmap_hit)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, brush_hit, sizeof(brush_hit)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders,
                            glyph_hit_and_miss,
                            sizeof(glyph_hit_and_miss)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, save_source, sizeof(save_source)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, save_store, sizeof(save_store)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders,
                            save_overwrite,
                            sizeof(save_overwrite)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, save_restore, sizeof(save_restore)) == LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, save_miss, sizeof(save_miss)) == LIBRDP_STATUS_OK);
    order_count++;

    memset(&create_ninegrid, 0, sizeof(create_ninegrid));
    create_ninegrid.bits_per_pixel = 32u;
    create_ninegrid.bitmap_id = 5u;
    create_ninegrid.info.left_width = 1u;
    create_ninegrid.info.right_width = 1u;
    create_ninegrid.info.top_height = 1u;
    create_ninegrid.info.bottom_height = 1u;
    payload.length = 0;
    CHECK(rdp_gdi_write_create_ninegrid_bitmap_order(&payload,
                                                      &create_ninegrid) == LIBRDP_STATUS_OK);
    CHECK(append_test_altsec_order(&orders,
                                   RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP,
                                   &payload));
    order_count++;
    CHECK(rdp_buffer_append(&orders, ninegrid_hit, sizeof(ninegrid_hit)) ==
          LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, ninegrid_miss, sizeof(ninegrid_miss)) ==
          LIBRDP_STATUS_OK);
    order_count++;
    CHECK(rdp_buffer_append(&orders, bitmap_miss, sizeof(bitmap_miss)) ==
          LIBRDP_STATUS_OK);
    order_count++;

    CHECK(apply_test_gdi_orders(session, &orders, order_count) == LIBRDP_STATUS_OK);
    CHECK(session->gdi_current_surface_id == RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE);
    CHECK(find_test_bitmap_cache_entry(session, 1u, 5u) != NULL);
    CHECK(session->gdi_brush_cache[3].active);
    CHECK(session->gdi_glyph_cache[1][2].active);
    CHECK(find_test_saved_bitmap(session, 0x11111111u) != NULL);
    CHECK(find_test_ninegrid(session, 5u) != NULL);

    offscreen = find_test_offscreen_surface(session, 7u);
    CHECK(offscreen != NULL && offscreen->surface != NULL);
    primary_pixels = librdp_surface_pixels(session->surface);
    primary_stride = librdp_surface_stride(session->surface);
    offscreen_pixels = librdp_surface_pixels(offscreen->surface);
    offscreen_stride = librdp_surface_stride(offscreen->surface);
    CHECK(primary_pixels != NULL && offscreen_pixels != NULL);
    CHECK(primary_pixels[0] == 0u && primary_pixels[1] == 0u && primary_pixels[2] == 0u);
    CHECK(offscreen_pixels[0] == 0x11u &&
          offscreen_pixels[1] == 0x22u &&
          offscreen_pixels[2] == 0x33u &&
          offscreen_pixels[3] == 0xffu);
    CHECK(primary_stride > 40u * 4u && offscreen_stride >= 8u * 4u);
    CHECK(primary_pixels[40u * primary_stride + 40u * 4u] == 0x10u);
    CHECK(primary_pixels[40u * primary_stride + 40u * 4u + 1u] == 0x20u);
    CHECK(primary_pixels[40u * primary_stride + 40u * 4u + 2u] == 0x30u);
    CHECK(primary_pixels[10u * primary_stride + 10u * 4u] != 0u);
    CHECK(primary_pixels[20u * primary_stride + 20u * 4u] != 0u);
    CHECK(primary_pixels[20u * primary_stride + 80u * 4u] != 0u);
    CHECK(primary_pixels[20u * primary_stride + 96u * 4u] == 0u);
    CHECK(primary_pixels[20u * primary_stride + 112u * 4u] == 0u);

    rdp_buffer_free(&payload);
    rdp_buffer_free(&orders);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Exercise primary, secondary and alternate-secondary orders through a real
 * loopback session. The whole-surface digest catches changes in order state,
 * bitmap orientation, cache lookup, clipping and dirty-frame commit.
 */
int test_gdi_orders_runtime_golden(void)
{
    static const uint8_t expected_digest[32] = {
        0x66u, 0x22u, 0x77u, 0x58u, 0xe0u, 0x26u, 0xc8u, 0x93u,
        0x59u, 0xbau, 0x57u, 0xbfu, 0xc6u, 0x17u, 0xf4u, 0x28u,
        0x2au, 0x6fu, 0x83u, 0x24u, 0x3cu, 0x3bu, 0x0eu, 0xf7u,
        0xefu, 0x44u, 0x93u, 0xf9u, 0xd1u, 0xa0u, 0x8fu, 0x4cu
    };
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    const librdp_surface* surface = NULL;
    graphics_update_capture graphics;
    librdp_metrics metrics;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;
    uint16_t test_port = 0u;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t surface_bytes = 0u;
    size_t i = 0u;

    memset(&graphics, 0, sizeof(graphics));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(
              settings,
              LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 640u, 480u) ==
          LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_full(
        &test_port,
        &server_pid,
        0,
        0,
        0,
        0,
        1,
        DVC_SCENARIO_NORMAL,
        GDI_SCENARIO_GOLDEN_RUNTIME,
        0,
        CLIPBOARD_SCENARIO_NONE,
        HANDSHAKE_SCENARIO_NORMAL));
    CHECK(librdp_settings_set_port(settings, test_port) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_graphics_update_callback(
        session,
        on_graphics_update,
        &graphics);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0u; i < 8u && graphics.frame_end == 0; i++)
    {
        status = librdp_session_run_once(session, 1000);
        CHECK(status == LIBRDP_STATUS_OK ||
              status == LIBRDP_STATUS_TIMEOUT);
    }
    CHECK(graphics.invalid == 0);
    CHECK(graphics.frame_begin == 1);
    CHECK(graphics.frame_end == 1);
    CHECK(graphics.pixel_rect >= 2);
    CHECK(graphics.borrowed_pixels == graphics.pixel_rect);
    surface = librdp_session_get_surface(session);
    CHECK(surface != NULL);
    CHECK(librdp_surface_width(surface) == 640u);
    CHECK(librdp_surface_height(surface) == 480u);
    surface_bytes = librdp_surface_stride(surface) *
                    librdp_surface_height(surface);
    CHECK(EVP_Digest(librdp_surface_pixels(surface),
                     surface_bytes,
                     digest,
                     &digest_len,
                     EVP_sha256(),
                     NULL) == 1);
    CHECK(digest_len == sizeof(expected_digest));
    if (CRYPTO_memcmp(digest,
                      expected_digest,
                      sizeof(expected_digest)) != 0)
    {
        fprintf(stderr, "GDI framebuffer SHA-256:");
        for (i = 0u; i < sizeof(expected_digest); i++)
            fprintf(stderr, "%02x", digest[i]);
        fputc('\n', stderr);
    }
    CHECK(CRYPTO_memcmp(digest,
                        expected_digest,
                        sizeof(expected_digest)) == 0);
    CHECK(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_metrics(session, &metrics) ==
          LIBRDP_STATUS_OK);
    CHECK(metrics.frames == 1u);
    CHECK(metrics.surface_updates >= 2u);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that complex GDI alternate secondary orders have a
 * bounded runtime path. The client parses GDI+ draw/cache chunks, rasterizes
 * direct EMF+ vector records, preserves window metadata and records desktop
 * composition markers without corrupting the active surface.
 */
int test_gdi_altsec_runtime_orders(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t i = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_full(&test_port,
                                      &server_pid,
                                      0,
                                      0,
                                      0,
                                      0,
                                      1,
                                      DVC_SCENARIO_NORMAL,
                                      GDI_SCENARIO_ALTSEC_RUNTIME,
                                      0,
                                      CLIPBOARD_SCENARIO_NONE,
                                      HANDSHAKE_SCENARIO_NORMAL));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (i = 0; i < 4u && status == LIBRDP_STATUS_OK; i++)
        status = librdp_session_run_once(session, 10);
    CHECK(status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT);
    CHECK(librdp_session_get_state(session) != LIBRDP_SESSION_FAILED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: validates that slow-path graphics updates are rejected until the
 * Demand Active/Confirm Active activation exchange succeeds. It catches
 * lifecycle regressions where run_once marks a session active before the
 * protocol state machine has a negotiated share id.
 */
int test_graphics_update_before_activation(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_full(&test_port,
                                      &server_pid,
                                      0,
                                      0,
                                      0,
                                      0,
                                      1,
                                      DVC_SCENARIO_NORMAL,
                                      GDI_SCENARIO_UPDATE_BEFORE_ACTIVATION,
                                      0,
                                      CLIPBOARD_SCENARIO_NONE,
                                      HANDSHAKE_SCENARIO_NORMAL));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(librdp_session_get_lifecycle(session) == LIBRDP_LIFECYCLE_ACTIVATING);
    CHECK(librdp_session_run_once(session, 1000) == LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);

    librdp_session_free(session);
    librdp_settings_free(settings);
    CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    return 0;
}

/*
 * Coverage: drives an in-process Deactivate All/Demand Active epoch change.
 * It verifies graphics and pointer invalidation, fragment cleanup, channel
 * identity preservation and negotiated desktop resizing without transport
 * loss.
 */
int test_activation_epoch_reset(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    event_counter events;
    graphics_update_capture graphics;
    rdp_buffer deactivate;
    rdp_buffer demand;
    rdp_dynamic_channel_create_request dynamic_request;
    uint8_t* pixels = NULL;
    int sockets[2] = {-1, -1};
    size_t i = 0u;

    memset(&events, 0, sizeof(events));
    memset(&graphics, 0, sizeof(graphics));
    memset(&dynamic_request, 0, sizeof(dynamic_request));
    rdp_buffer_init(&deactivate);
    rdp_buffer_init(&demand);
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_desktop_size(settings, 640u, 480u) ==
          LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    rdp_transport_attach_fd(&session->transport, sockets[0], 1);
    sockets[0] = -1;
    session->mcs_user_id = 1004u;
    session->share_id = 0x12345678u;
    session->state = LIBRDP_SESSION_ACTIVE;
    session->lifecycle = LIBRDP_LIFECYCLE_ACTIVE;
    librdp_session_set_event_callback(session, on_event, &events);
    librdp_session_set_graphics_update_callback(session,
                                                on_graphics_update,
                                                &graphics);

    pixels = librdp_surface_pixels_mut(session->surface);
    CHECK(pixels != NULL);
    memset(pixels,
           0x5au,
           librdp_surface_stride(session->surface) *
               librdp_surface_height(session->surface));
    session->pointer_cache[2].active = 1u;
    CHECK(rdp_buffer_append_u8(&session->pointer_cache[2].pixels, 0xa5u) ==
          LIBRDP_STATUS_OK);
    session->graphics_surfaces[0].active = 1u;
    session->graphics_surfaces[0].surface_id = 7u;
    CHECK(rdp_buffer_append_u8(&session->graphics_surfaces[0].pixels, 0x5au) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_static_channel_configure(session,
                                               0u,
                                               "test",
                                               0u,
                                               1005u) ==
          LIBRDP_STATUS_OK);
    session->static_channels[0].joined = 1u;
    session->static_channels[0].fragmenting = 1u;
    session->static_channels[0].fragment_expected = 4u;
    CHECK(rdp_buffer_append_u8(&session->static_channels[0].fragment, 1u) ==
          LIBRDP_STATUS_OK);
    dynamic_request.channel_id = 9u;
    dynamic_request.channel_id_bytes = 1u;
    dynamic_request.priority = 1u;
    dynamic_request.name = "test.dvc";
    dynamic_request.name_len = strlen(dynamic_request.name);
    CHECK(rdp_session_dynamic_channel_add(session, &dynamic_request) ==
          LIBRDP_STATUS_OK);
    session->dynamic_channels[0].fragmenting = 1u;
    session->dynamic_channels[0].fragment_expected = 4u;
    CHECK(rdp_buffer_append_u8(&session->dynamic_channels[0].fragment, 2u) ==
          LIBRDP_STATUS_OK);

    CHECK(rdp_slowpath_write_deactivate_all(&deactivate,
                                            session->share_id + 1u,
                                            RDP_MCS_GLOBAL_CHANNEL_ID) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_deactivate_all(session,
                                            deactivate.data,
                                            deactivate.length) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(session->state == LIBRDP_SESSION_ACTIVE);
    CHECK(session->pointer_cache[2].active == 1u);
    deactivate.length = 0u;
    CHECK(rdp_slowpath_write_deactivate_all(&deactivate,
                                            session->share_id,
                                            RDP_MCS_GLOBAL_CHANNEL_ID) ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_deactivate_all(session,
                                            deactivate.data,
                                            deactivate.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->state == LIBRDP_SESSION_CONNECTED);
    CHECK(session->lifecycle == LIBRDP_LIFECYCLE_ACTIVATING);
    CHECK(session->reactivating == 1u);
    CHECK(events.pointer == 1);
    CHECK(session->pointer_cache[2].active == 0u);
    CHECK(session->graphics_surfaces[0].active == 0u);
    CHECK(session->static_channels[0].active == 1u);
    CHECK(session->static_channels[0].channel_id == 1005u);
    CHECK(session->static_channels[0].fragmenting == 0u);
    CHECK(session->static_channels[0].fragment.length == 0u);
    CHECK(session->dynamic_channels[0].active == 1u);
    CHECK(session->dynamic_channels[0].channel_id == 9u);
    CHECK(session->dynamic_channels[0].fragmenting == 0u);
    CHECK(session->dynamic_channels[0].fragment.length == 0u);
    pixels = librdp_surface_pixels_mut(session->surface);
    CHECK(pixels != NULL);
    for (i = 0u;
         i < librdp_surface_stride(session->surface) *
                 librdp_surface_height(session->surface);
         i++)
        CHECK(pixels[i] == 0u);
    CHECK(rdp_session_handle_deactivate_all(session,
                                            deactivate.data,
                                            deactivate.length) ==
          LIBRDP_STATUS_PROTOCOL_ERROR);
    CHECK(session->state == LIBRDP_SESSION_CONNECTED);

    CHECK(rdp_slowpath_write_demand_active(&demand,
                                           session->share_id,
                                           RDP_MCS_GLOBAL_CHANNEL_ID,
                                           800u,
                                           600u,
                                           "server") ==
          LIBRDP_STATUS_OK);
    CHECK(rdp_session_handle_demand_active(session,
                                          demand.data,
                                          demand.length) ==
          LIBRDP_STATUS_OK);
    CHECK(session->state == LIBRDP_SESSION_ACTIVE);
    CHECK(session->lifecycle == LIBRDP_LIFECYCLE_ACTIVE);
    CHECK(session->reactivating == 0u);
    CHECK(librdp_surface_width(session->surface) == 800u);
    CHECK(librdp_surface_height(session->surface) == 600u);
    CHECK(graphics.desktop_resize == 1);
    CHECK(events.pointer == 2);
    pixels = librdp_surface_pixels_mut(session->surface);
    CHECK(pixels != NULL);
    for (i = 0u;
         i < librdp_surface_stride(session->surface) *
                 librdp_surface_height(session->surface);
         i++)
        CHECK(pixels[i] == 0u);
    CHECK(session->static_channels[0].active == 1u);
    CHECK(session->dynamic_channels[0].active == 1u);

    rdp_buffer_free(&demand);
    rdp_buffer_free(&deactivate);
    librdp_session_free(session);
    librdp_settings_free(settings);
    close(sockets[1]);
    return 0;
}
