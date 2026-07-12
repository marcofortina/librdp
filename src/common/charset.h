/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: UTF-8 and UTF-16LE conversion contract used at protocol boundaries.
 * Invariants: declarations preserve explicit bounds, ownership, and error
 * propagation across module boundaries.
 * Ownership: converted buffers are caller-owned and input slices remain
 * borrowed.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
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
