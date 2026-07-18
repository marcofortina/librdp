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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
                                                surface,
                                                stream.data,
                                                stream.length,
                                                &records,
                                                &rasterized,
                                                &unsupported) == LIBRDP_STATUS_PROTOCOL_ERROR);
#else
    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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

    CHECK(rdp_gdi_backend_render_gdiplus_stream(RDP_GDI_BACKEND_SOFTWARE,
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
                                      CLIPBOARD_SCENARIO_NONE));
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
                                      CLIPBOARD_SCENARIO_NONE));
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
