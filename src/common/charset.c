/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: UTF-8 and UTF-16LE conversion helpers used at protocol boundaries.
 * Invariants: publicly observable state is updated only after local validation
 * succeeds.
 * Ownership: converted strings are caller-owned and malformed input fails
 * before partial public output is committed.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "common/charset.h"

#include <errno.h>
#include <iconv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static librdp_status rdp_charset_convert(const char* to,
                                         const char* from,
                                         const uint8_t* input,
                                         size_t input_len,
                                         uint8_t** out,
                                         size_t* out_len)
{
    iconv_t cd = (iconv_t)-1;
    uint8_t* output = NULL;
    char* in_ptr = NULL;
    char* out_ptr = NULL;
    size_t in_left = input_len;
    size_t out_left = 0;
    size_t capacity = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!to || !from || (!input && input_len > 0) || !out || !out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    *out_len = 0;
    capacity = input_len > 0 ? input_len * 4u + 16u : 16u;
    if (capacity < input_len)
        return LIBRDP_STATUS_NO_MEMORY;
    output = (uint8_t*)calloc(1u, capacity);
    if (!output)
        return LIBRDP_STATUS_NO_MEMORY;
    cd = iconv_open(to, from);
    if (cd == (iconv_t)-1)
    {
        free(output);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    in_ptr = (char*)input;
    out_ptr = (char*)output;
    out_left = capacity;
    while (1)
    {
        size_t converted = iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left);

        if (converted != (size_t)-1)
        {
            status = LIBRDP_STATUS_OK;
            break;
        }
        if (errno != E2BIG)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        {
            size_t used = (size_t)((uint8_t*)out_ptr - output);
            uint8_t* resized = NULL;
            size_t next = capacity * 2u;

            if (next <= capacity)
            {
                status = LIBRDP_STATUS_NO_MEMORY;
                break;
            }
            resized = (uint8_t*)realloc(output, next);
            if (!resized)
            {
                status = LIBRDP_STATUS_NO_MEMORY;
                break;
            }
            output = resized;
            memset(output + capacity, 0, next - capacity);
            capacity = next;
            out_ptr = (char*)output + used;
            out_left = capacity - used;
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        *out_len = (size_t)((uint8_t*)out_ptr - output);
        *out = output;
        output = NULL;
    }
    iconv_close(cd);
    free(output);
    return status;
}

librdp_status rdp_charset_utf8_bytes_to_utf16le_alloc(const uint8_t* data,
                                                      size_t length,
                                                      int append_null,
                                                      uint8_t** out,
                                                      size_t* out_len)
{
    uint8_t* converted = NULL;
    size_t converted_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && length > 0) || !out || !out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_charset_convert("UTF-16LE", "UTF-8", data, length, &converted, &converted_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (append_null)
    {
        uint8_t* resized = NULL;

        if (converted_len > SIZE_MAX - 2u)
        {
            free(converted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        resized = (uint8_t*)realloc(converted, converted_len + 2u);
        if (!resized)
        {
            free(converted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        converted = resized;
        converted[converted_len++] = 0;
        converted[converted_len++] = 0;
    }
    *out = converted;
    *out_len = converted_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_charset_utf8_to_utf16le_buffer(const char* text, int append_null, rdp_buffer* out)
{
    const char* input = text ? text : "";
    uint8_t* converted = NULL;
    size_t converted_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_charset_utf8_bytes_to_utf16le_alloc((const uint8_t*)input,
                                                     strlen(input),
                                                     append_null,
                                                     &converted,
                                                     &converted_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, converted, converted_len);
    free(converted);
    return status;
}

librdp_status rdp_charset_utf16le_to_utf8_alloc(const uint8_t* data,
                                                size_t length,
                                                int stop_at_null,
                                                char** out,
                                                size_t* out_len)
{
    uint8_t* converted = NULL;
    size_t converted_len = 0;
    size_t input_len = length;
    char* text = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && length > 0) || (length & 1u) != 0 || !out || !out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    *out_len = 0;
    if (stop_at_null)
    {
        size_t i = 0;

        while (i + 1u < length)
        {
            if (data[i] == 0 && data[i + 1u] == 0)
            {
                input_len = i;
                break;
            }
            i += 2u;
        }
    }
    status = rdp_charset_convert("UTF-8", "UTF-16LE", data, input_len, &converted, &converted_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    text = (char*)realloc(converted, converted_len + 1u);
    if (!text)
    {
        free(converted);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    text[converted_len] = '\0';
    *out = text;
    *out_len = converted_len;
    return LIBRDP_STATUS_OK;
}
