/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_COMMON_CHARSET_H
#define RDP_COMMON_CHARSET_H

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

librdp_status rdp_charset_utf8_to_utf16le_buffer(const char* text, int append_null, rdp_buffer* out);
librdp_status rdp_charset_utf8_bytes_to_utf16le_alloc(const uint8_t* data,
                                                      size_t length,
                                                      int append_null,
                                                      uint8_t** out,
                                                      size_t* out_len);
librdp_status rdp_charset_utf16le_to_utf8_alloc(const uint8_t* data,
                                                size_t length,
                                                int stop_at_null,
                                                char** out,
                                                size_t* out_len);

#endif
