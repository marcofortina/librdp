#include "graphics/rfx_codec.h"

#include <limits.h>
#include <string.h>

#define RDP_RFX_RLGR_KP_MAX 80
#define RDP_RFX_RLGR_LS 3
#define RDP_RFX_RLGR_UP_GR 4
#define RDP_RFX_RLGR_DN_GR 6
#define RDP_RFX_RLGR_UQ_GR 3
#define RDP_RFX_RLGR_DQ_GR 3

typedef struct rdp_rfx_bit_reader
{
    const uint8_t* data;
    size_t length;
    size_t bit_pos;
} rdp_rfx_bit_reader;

static librdp_status rdp_rfx_read_bits(rdp_rfx_bit_reader* reader, uint8_t count, uint32_t* value)
{
    uint32_t output = 0;
    uint8_t i = 0;
    size_t max_bits = 0;

    if (!reader || !value || count > 31u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (reader->length > SIZE_MAX / 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    max_bits = reader->length * 8u;
    if (count == 0)
    {
        *value = 0;
        return LIBRDP_STATUS_OK;
    }
    if (reader->bit_pos > max_bits || count > max_bits - reader->bit_pos)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        size_t byte_index = reader->bit_pos / 8u;
        uint8_t bit_index = (uint8_t)(7u - (reader->bit_pos % 8u));

        output = (output << 1) | ((reader->data[byte_index] >> bit_index) & 1u);
        reader->bit_pos++;
    }
    *value = output;
    return LIBRDP_STATUS_OK;
}

static int rdp_rfx_update_param(int* param, int delta)
{
    *param += delta;
    if (*param > RDP_RFX_RLGR_KP_MAX)
        *param = RDP_RFX_RLGR_KP_MAX;
    if (*param < 0)
        *param = 0;
    return *param >> RDP_RFX_RLGR_LS;
}

static uint8_t rdp_rfx_min_bits(uint32_t value)
{
    uint8_t bits = 0;

    while (value > 0)
    {
        bits++;
        value >>= 1;
    }
    return bits;
}

static int32_t rdp_rfx_from_2mag_sign(uint32_t value)
{
    int32_t magnitude = (int32_t)((value + 1u) >> 1);

    if (value == 0)
        return 0;
    return (value & 1u) != 0 ? -magnitude : magnitude;
}

static int32_t rdp_rfx_clamp_i32(int64_t value)
{
    if (value < INT32_MIN)
        return INT32_MIN;
    if (value > INT32_MAX)
        return INT32_MAX;
    return (int32_t)value;
}

static uint8_t rdp_rfx_clamp_u8(int64_t value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return (uint8_t)value;
}

static void rdp_rfx_component_quant_from_values(rdp_rfx_component_quant* quant, const uint8_t values[10])
{
    quant->ll3 = values[0];
    quant->hl3 = values[1];
    quant->lh3 = values[2];
    quant->hh3 = values[3];
    quant->hl2 = values[4];
    quant->lh2 = values[5];
    quant->hh2 = values[6];
    quant->hl1 = values[7];
    quant->lh1 = values[8];
    quant->hh1 = values[9];
}

static void rdp_rfx_component_quant_to_values(const rdp_rfx_component_quant* quant, uint8_t values[10])
{
    values[0] = quant->ll3;
    values[1] = quant->hl3;
    values[2] = quant->lh3;
    values[3] = quant->hh3;
    values[4] = quant->hl2;
    values[5] = quant->lh2;
    values[6] = quant->hh2;
    values[7] = quant->hl1;
    values[8] = quant->lh1;
    values[9] = quant->hh1;
}

static int rdp_rfx_component_quant_in_range(const rdp_rfx_component_quant* quant, uint8_t max_value)
{
    uint8_t values[10];
    size_t i = 0;

    if (!quant)
        return 0;
    rdp_rfx_component_quant_to_values(quant, values);
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        if (values[i] > max_value)
            return 0;
    }
    return 1;
}

static librdp_status rdp_rfx_write_value(int32_t* coefficients,
                                         size_t coefficient_count,
                                         size_t* written,
                                         int32_t value)
{
    if (!coefficients || !written || *written >= coefficient_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    coefficients[*written] = value;
    (*written)++;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_parse_component_quant(const void* data,
                                            size_t length,
                                            rdp_rfx_component_quant* quant)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint8_t values[10];
    size_t i = 0;

    if (!data || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 5u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(quant, 0, sizeof(*quant));
    for (i = 0; i < 5u; i++)
    {
        values[i * 2u] = (uint8_t)(bytes[i] & 0x0fu);
        values[(i * 2u) + 1u] = (uint8_t)(bytes[i] >> 4);
    }
    rdp_rfx_component_quant_from_values(quant, values);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_parse_progressive_quant(const void* data,
                                              size_t length,
                                              rdp_rfx_progressive_quant* quant)
{
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(quant, 0, sizeof(*quant));
    quant->quality = bytes[0];
    if (rdp_rfx_parse_component_quant(bytes + 1u, 5u, &quant->y) != LIBRDP_STATUS_OK ||
        rdp_rfx_parse_component_quant(bytes + 6u, 5u, &quant->cb) != LIBRDP_STATUS_OK ||
        rdp_rfx_parse_component_quant(bytes + 11u, 5u, &quant->cr) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_rfx_component_quant_in_range(&quant->y, 8) ||
        !rdp_rfx_component_quant_in_range(&quant->cb, 8) ||
        !rdp_rfx_component_quant_in_range(&quant->cr, 8))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_add_component_quant(const rdp_rfx_component_quant* base,
                                          const rdp_rfx_component_quant* delta,
                                          rdp_rfx_component_quant* output)
{
    uint8_t base_values[10];
    uint8_t delta_values[10];
    uint8_t output_values[10];
    size_t i = 0;

    if (!base || !delta || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_rfx_component_quant_in_range(base, 15) || !rdp_rfx_component_quant_in_range(delta, 8))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_rfx_component_quant_to_values(base, base_values);
    rdp_rfx_component_quant_to_values(delta, delta_values);
    for (i = 0; i < sizeof(output_values) / sizeof(output_values[0]); i++)
    {
        uint8_t value = (uint8_t)(base_values[i] + delta_values[i]);

        if (value > 15u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        output_values[i] = value;
    }
    rdp_rfx_component_quant_from_values(output, output_values);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_differential_decode(int32_t* coefficients, size_t coefficient_count)
{
    size_t i = 0;

    if (!coefficients || coefficient_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 1u; i < coefficient_count; i++)
        coefficients[i] = rdp_rfx_clamp_i32((int64_t)coefficients[i - 1u] + coefficients[i]);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_rfx_shift_band(int32_t* coefficients,
                                        size_t offset,
                                        size_t count,
                                        uint8_t quant)
{
    size_t i = 0;
    uint8_t shift = 0;

    if (!coefficients || quant == 0 || offset > RDP_RFX_TILE_COEFFICIENTS ||
        count > RDP_RFX_TILE_COEFFICIENTS - offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    shift = (uint8_t)(quant - 1u);
    if (shift == 0)
        return LIBRDP_STATUS_OK;
    for (i = 0; i < count; i++)
        coefficients[offset + i] = rdp_rfx_clamp_i32((int64_t)coefficients[offset + i] << shift);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_inverse_quantize(int32_t* coefficients,
                                       size_t coefficient_count,
                                       const rdp_rfx_component_quant* quant)
{
    if (!coefficients || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (coefficient_count != RDP_RFX_TILE_COEFFICIENTS || !rdp_rfx_component_quant_in_range(quant, 15))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (quant->ll3 == 0 || quant->hl3 == 0 || quant->lh3 == 0 || quant->hh3 == 0 ||
        quant->hl2 == 0 || quant->lh2 == 0 || quant->hh2 == 0 ||
        quant->hl1 == 0 || quant->lh1 == 0 || quant->hh1 == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_rfx_shift_band(coefficients, 0u, 1024u, quant->hl1) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 1024u, 1024u, quant->lh1) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 2048u, 1024u, quant->hh1) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3072u, 256u, quant->hl2) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3328u, 256u, quant->lh2) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3584u, 256u, quant->hh2) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3840u, 64u, quant->hl3) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3904u, 64u, quant->lh3) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 3968u, 64u, quant->hh3) != LIBRDP_STATUS_OK ||
        rdp_rfx_shift_band(coefficients, 4032u, 64u, quant->ll3) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static void rdp_rfx_inverse_dwt_block(int32_t* coefficients, int32_t* work, size_t subband_width)
{
    size_t y = 0;
    size_t x = 0;
    size_t total_width = subband_width * 2u;
    const int32_t* ll = coefficients + (subband_width * subband_width * 3u);
    const int32_t* hl = coefficients;
    const int32_t* lh = coefficients + (subband_width * subband_width);
    const int32_t* hh = coefficients + (subband_width * subband_width * 2u);
    int32_t* low = work;
    int32_t* high = work + (subband_width * total_width);

    for (y = 0; y < subband_width; y++)
    {
        size_t n = 0;

        low[0] = rdp_rfx_clamp_i32((int64_t)ll[0] - (((int64_t)hl[0] + hl[0] + 1) >> 1));
        high[0] = rdp_rfx_clamp_i32((int64_t)lh[0] - (((int64_t)hh[0] + hh[0] + 1) >> 1));
        for (n = 1u; n < subband_width; n++)
        {
            x = n * 2u;
            low[x] = rdp_rfx_clamp_i32((int64_t)ll[n] - (((int64_t)hl[n - 1u] + hl[n] + 1) >> 1));
            high[x] = rdp_rfx_clamp_i32((int64_t)lh[n] - (((int64_t)hh[n - 1u] + hh[n] + 1) >> 1));
        }
        for (n = 0; n + 1u < subband_width; n++)
        {
            x = n * 2u;
            low[x + 1u] = rdp_rfx_clamp_i32(((int64_t)hl[n] * 2) + (((int64_t)low[x] + low[x + 2u]) >> 1));
            high[x + 1u] = rdp_rfx_clamp_i32(((int64_t)hh[n] * 2) + (((int64_t)high[x] + high[x + 2u]) >> 1));
        }
        x = n * 2u;
        low[x + 1u] = rdp_rfx_clamp_i32(((int64_t)hl[n] * 2) + low[x]);
        high[x + 1u] = rdp_rfx_clamp_i32(((int64_t)hh[n] * 2) + high[x]);

        ll += subband_width;
        hl += subband_width;
        lh += subband_width;
        hh += subband_width;
        low += total_width;
        high += total_width;
    }

    for (x = 0; x < total_width; x++)
    {
        const int32_t* low_src = work + x;
        const int32_t* high_src = work + x + (subband_width * total_width);
        int32_t* dest = coefficients + x;
        size_t n = 0;

        *dest = rdp_rfx_clamp_i32((int64_t)*low_src - (((int64_t)*high_src * 2 + 1) >> 1));
        for (n = 1u; n < subband_width; n++)
        {
            low_src += total_width;
            high_src += total_width;
            dest[2u * total_width] =
                rdp_rfx_clamp_i32((int64_t)*low_src - (((int64_t)*(high_src - total_width) + *high_src + 1) >> 1));
            dest[total_width] =
                rdp_rfx_clamp_i32(((int64_t)*(high_src - total_width) * 2) +
                                  (((int64_t)*dest + dest[2u * total_width]) >> 1));
            dest += 2u * total_width;
        }
        dest[total_width] = rdp_rfx_clamp_i32(((int64_t)*high_src * 2) + *dest);
    }
}

librdp_status rdp_rfx_inverse_dwt_2d(int32_t* coefficients, size_t coefficient_count)
{
    int32_t work[RDP_RFX_TILE_COEFFICIENTS];

    if (!coefficients)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (coefficient_count != RDP_RFX_TILE_COEFFICIENTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(work, 0, sizeof(work));
    rdp_rfx_inverse_dwt_block(coefficients + 3840u, work, 8u);
    rdp_rfx_inverse_dwt_block(coefficients + 3072u, work, 16u);
    rdp_rfx_inverse_dwt_block(coefficients, work, 32u);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_ycbcr_to_bgra(const int32_t* y,
                                    const int32_t* cb,
                                    const int32_t* cr,
                                    uint8_t* bgra,
                                    size_t stride)
{
    size_t row = 0;

    if (!y || !cb || !cr || !bgra || stride < 64u * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (row = 0; row < 64u; row++)
    {
        size_t column = 0;
        uint8_t* dest = bgra + (row * stride);

        for (column = 0; column < 64u; column++)
        {
            size_t index = (row * 64u) + column;
            int64_t base = ((int64_t)y[index] + 4096) << 16;
            int64_t r = (base + ((int64_t)cr[index] * 91916)) >> 21;
            int64_t g = (base - ((int64_t)cr[index] * 46819) - ((int64_t)cb[index] * 22527)) >> 21;
            int64_t b = (base + ((int64_t)cb[index] * 115992)) >> 21;

            dest[0] = rdp_rfx_clamp_u8(b);
            dest[1] = rdp_rfx_clamp_u8(g);
            dest[2] = rdp_rfx_clamp_u8(r);
            dest[3] = 0xffu;
            dest += 4u;
        }
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_decode_component(rdp_rfx_rlgr_mode mode,
                                       const void* data,
                                       size_t length,
                                       const rdp_rfx_component_quant* quant,
                                       int32_t* coefficients,
                                       size_t coefficient_count)
{
    size_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !quant || !coefficients)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (coefficient_count != RDP_RFX_TILE_COEFFICIENTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_rlgr_decode(mode, data, length, coefficients, coefficient_count, &written);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (written != coefficient_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_differential_decode(coefficients + 4032u, 64u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rfx_inverse_quantize(coefficients, coefficient_count, quant);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rfx_inverse_dwt_2d(coefficients, coefficient_count);
    return status;
}

librdp_status rdp_rfx_decode_tile(rdp_rfx_rlgr_mode mode,
                                  const void* y_data,
                                  size_t y_len,
                                  const void* cb_data,
                                  size_t cb_len,
                                  const void* cr_data,
                                  size_t cr_len,
                                  const rdp_rfx_component_quant* y_quant,
                                  const rdp_rfx_component_quant* cb_quant,
                                  const rdp_rfx_component_quant* cr_quant,
                                  rdp_rfx_tile_pixels* pixels)
{
    int32_t y_coefficients[RDP_RFX_TILE_COEFFICIENTS];
    int32_t cb_coefficients[RDP_RFX_TILE_COEFFICIENTS];
    int32_t cr_coefficients[RDP_RFX_TILE_COEFFICIENTS];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!y_data || !cb_data || !cr_data || !y_quant || !cb_quant || !cr_quant || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pixels, 0, sizeof(*pixels));
    status = rdp_rfx_decode_component(mode,
                                      y_data,
                                      y_len,
                                      y_quant,
                                      y_coefficients,
                                      RDP_RFX_TILE_COEFFICIENTS);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rfx_decode_component(mode,
                                          cb_data,
                                          cb_len,
                                          cb_quant,
                                          cb_coefficients,
                                          RDP_RFX_TILE_COEFFICIENTS);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_rfx_decode_component(mode,
                                          cr_data,
                                          cr_len,
                                          cr_quant,
                                          cr_coefficients,
                                          RDP_RFX_TILE_COEFFICIENTS);
    if (status == LIBRDP_STATUS_OK)
    {
        pixels->stride = 64u * 4u;
        status = rdp_rfx_ycbcr_to_bgra(y_coefficients,
                                       cb_coefficients,
                                       cr_coefficients,
                                       pixels->bgra,
                                       pixels->stride);
    }
    return status;
}

static librdp_status rdp_rfx_write_zeroes(int32_t* coefficients,
                                          size_t coefficient_count,
                                          size_t* written,
                                          uint32_t count)
{
    uint32_t i = 0;

    if (!coefficients || !written || count > coefficient_count - *written)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        coefficients[*written] = 0;
        (*written)++;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_rfx_get_gr_code(rdp_rfx_bit_reader* reader, int* krp, int* kr, uint32_t* magnitude)
{
    uint32_t prefix = 0;
    uint32_t bit = 0;
    uint32_t suffix = 0;

    if (!reader || !krp || !kr || !magnitude || *kr < 0 || *kr > 10)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (;;)
    {
        if (rdp_rfx_read_bits(reader, 1, &bit) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (bit == 0)
            break;
        if (prefix > 0x001fffffu)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        prefix++;
    }
    if (rdp_rfx_read_bits(reader, (uint8_t)*kr, &suffix) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *magnitude = (prefix << (uint8_t)*kr) | suffix;
    if (prefix == 0)
        *kr = rdp_rfx_update_param(krp, -2);
    else if (prefix != 1)
        *kr = rdp_rfx_update_param(krp, (int)prefix);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_rfx_rlgr_decode(rdp_rfx_rlgr_mode mode,
                                  const void* data,
                                  size_t length,
                                  int32_t* coefficients,
                                  size_t coefficient_count,
                                  size_t* coefficients_written)
{
    rdp_rfx_bit_reader reader;
    size_t written = 0;
    int k = 1;
    int kp = 1 << RDP_RFX_RLGR_LS;
    int kr = 1;
    int krp = 1 << RDP_RFX_RLGR_LS;

    if ((mode != RDP_RFX_RLGR1 && mode != RDP_RFX_RLGR3) || !data || !coefficients ||
        coefficient_count == 0 || coefficient_count > SIZE_MAX / sizeof(coefficients[0]))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(coefficients, 0, coefficient_count * sizeof(coefficients[0]));
    reader.data = (const uint8_t*)data;
    reader.length = length;
    reader.bit_pos = 0;

    while (written < coefficient_count)
    {
        if (k > 0)
        {
            uint32_t bit = 0;
            uint32_t run = 0;
            uint32_t sign = 0;
            uint32_t mag = 0;

            for (;;)
            {
                if (rdp_rfx_read_bits(&reader, 1, &bit) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                if (bit != 0)
                    break;
                if (rdp_rfx_write_zeroes(coefficients,
                                         coefficient_count,
                                         &written,
                                         (uint32_t)1u << (uint8_t)k) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                k = rdp_rfx_update_param(&kp, RDP_RFX_RLGR_UP_GR);
                if (written == coefficient_count)
                {
                    if (coefficients_written)
                        *coefficients_written = written;
                    return LIBRDP_STATUS_OK;
                }
            }
            if (rdp_rfx_read_bits(&reader, (uint8_t)k, &run) != LIBRDP_STATUS_OK ||
                rdp_rfx_write_zeroes(coefficients, coefficient_count, &written, run) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (written == coefficient_count)
            {
                if (coefficients_written)
                    *coefficients_written = written;
                return LIBRDP_STATUS_OK;
            }
            if (rdp_rfx_read_bits(&reader, 1, &sign) != LIBRDP_STATUS_OK ||
                rdp_rfx_get_gr_code(&reader, &krp, &kr, &mag) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            mag++;
            if (rdp_rfx_write_value(coefficients,
                                    coefficient_count,
                                    &written,
                                    sign != 0 ? -(int32_t)mag : (int32_t)mag) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            k = rdp_rfx_update_param(&kp, -RDP_RFX_RLGR_DN_GR);
        }
        else if (mode == RDP_RFX_RLGR1)
        {
            uint32_t mag = 0;

            if (rdp_rfx_get_gr_code(&reader, &krp, &kr, &mag) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (mag == 0)
            {
                if (rdp_rfx_write_value(coefficients, coefficient_count, &written, 0) !=
                    LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                k = rdp_rfx_update_param(&kp, RDP_RFX_RLGR_UQ_GR);
            }
            else
            {
                if (rdp_rfx_write_value(coefficients,
                                        coefficient_count,
                                        &written,
                                        rdp_rfx_from_2mag_sign(mag)) != LIBRDP_STATUS_OK)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                k = rdp_rfx_update_param(&kp, -RDP_RFX_RLGR_DQ_GR);
            }
        }
        else
        {
            uint32_t sum = 0;
            uint32_t value1 = 0;
            uint32_t value2 = 0;
            uint8_t bits = 0;

            if (rdp_rfx_get_gr_code(&reader, &krp, &kr, &sum) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            bits = rdp_rfx_min_bits(sum);
            if (rdp_rfx_read_bits(&reader, bits, &value1) != LIBRDP_STATUS_OK || value1 > sum)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            value2 = sum - value1;
            if (value1 != 0 && value2 != 0)
                k = rdp_rfx_update_param(&kp, -2 * RDP_RFX_RLGR_DQ_GR);
            else if (value1 == 0 && value2 == 0)
                k = rdp_rfx_update_param(&kp, 2 * RDP_RFX_RLGR_UQ_GR);
            if (rdp_rfx_write_value(coefficients,
                                    coefficient_count,
                                    &written,
                                    rdp_rfx_from_2mag_sign(value1)) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (written < coefficient_count &&
                rdp_rfx_write_value(coefficients,
                                    coefficient_count,
                                    &written,
                                    rdp_rfx_from_2mag_sign(value2)) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }

    if (coefficients_written)
        *coefficients_written = written;
    return LIBRDP_STATUS_OK;
}
