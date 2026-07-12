/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: mouse cursor channel parser declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_MOUSE_CURSOR_H
#define RDP_CHANNELS_MOUSE_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "protocol/pointer.h"

#define RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE 0x01u
#define RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM 0x02u
#define RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE 0x03u
#define RDP_MOUSE_CURSOR_UPDATE_NULL 0x05u
#define RDP_MOUSE_CURSOR_UPDATE_DEFAULT 0x06u
#define RDP_MOUSE_CURSOR_UPDATE_POSITION 0x08u
#define RDP_MOUSE_CURSOR_UPDATE_CACHED 0x0au
#define RDP_MOUSE_CURSOR_UPDATE_POINTER 0x0bu
#define RDP_MOUSE_CURSOR_UPDATE_LARGE_POINTER 0x0cu
#define RDP_MOUSE_CURSOR_CAPSET_SIGNATURE 0x53504143u
#define RDP_MOUSE_CURSOR_CAPSET_VERSION1 1u
#define RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1 12u

typedef struct rdp_mouse_cursor_header
{
    uint8_t pdu_type;
    uint8_t update_type;
    uint16_t reserved;
} rdp_mouse_cursor_header;

typedef struct rdp_mouse_cursor_capset
{
    uint32_t signature;
    uint32_t version;
    uint32_t size;
} rdp_mouse_cursor_capset;

librdp_status rdp_mouse_cursor_write_caps_advertise(rdp_buffer* buffer);
librdp_status rdp_mouse_cursor_parse_header(const void* data, size_t length, rdp_mouse_cursor_header* header);
librdp_status rdp_mouse_cursor_parse_caps_confirm(const void* data,
                                                  size_t length,
                                                  rdp_mouse_cursor_capset* capset);
librdp_status rdp_mouse_cursor_parse_update(const void* data, size_t length, rdp_pointer_update* update);

#endif
