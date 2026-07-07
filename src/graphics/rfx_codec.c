#include "graphics/rfx_codec.h"

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
