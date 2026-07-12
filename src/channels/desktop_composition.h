/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: desktop composition channel declaration set.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_DESKTOP_COMPOSITION_H
#define RDP_CHANNELS_DESKTOP_COMPOSITION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_DESKTOP_COMPOSITION_ALTSEC_HEADER 0x0cu
#define RDP_DESKTOP_COMPOSITION_OP_TOGGLE 0x01u
#define RDP_DESKTOP_COMPOSITION_OP_LSURFACE 0x02u
#define RDP_DESKTOP_COMPOSITION_OP_SURFOBJ 0x03u
#define RDP_DESKTOP_COMPOSITION_OP_ASSOC 0x04u
#define RDP_DESKTOP_COMPOSITION_OP_COMPREF 0x05u
#define RDP_DESKTOP_COMPOSITION_OP_SWITCH_SURFOBJ 0x06u
#define RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE 0x07u
#define RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_OFF 0x00u
#define RDP_DESKTOP_COMPOSITION_EVENT_RESERVED_00 0x01u
#define RDP_DESKTOP_COMPOSITION_EVENT_RESERVED_01 0x02u
#define RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON 0x03u
#define RDP_DESKTOP_COMPOSITION_EVENT_DWM_DESK_ENTER 0x04u
#define RDP_DESKTOP_COMPOSITION_EVENT_DWM_DESK_LEAVE 0x05u
#define RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE 0x01u
#define RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION 0x04u

typedef struct rdp_desktop_composition_header
{
    uint8_t altsec_header;
    uint8_t operation;
    uint16_t size;
} rdp_desktop_composition_header;

typedef struct rdp_desktop_composition_toggle
{
    rdp_desktop_composition_header header;
    uint8_t event_type;
} rdp_desktop_composition_toggle;

typedef struct rdp_desktop_composition_lsurface
{
    rdp_desktop_composition_header header;
    uint8_t create;
    uint8_t flags;
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
    uint64_t window_id;
    uint64_t luid;
} rdp_desktop_composition_lsurface;

typedef struct rdp_desktop_composition_surfobj
{
    rdp_desktop_composition_header header;
    uint32_t cache_id;
    uint8_t surface_bpp;
    uint8_t flags;
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
} rdp_desktop_composition_surfobj;

typedef struct rdp_desktop_composition_assoc
{
    rdp_desktop_composition_header header;
    uint8_t associate;
    uint64_t logical_surface_id;
    uint64_t redirection_surface_id;
} rdp_desktop_composition_assoc;

typedef struct rdp_desktop_composition_u64_order
{
    rdp_desktop_composition_header header;
    uint64_t value;
} rdp_desktop_composition_u64_order;

typedef struct rdp_desktop_composition_u32_order
{
    rdp_desktop_composition_header header;
    uint32_t value;
} rdp_desktop_composition_u32_order;

typedef struct rdp_desktop_composition_opaque
{
    rdp_desktop_composition_header header;
    const uint8_t* payload;
    size_t payload_len;
} rdp_desktop_composition_opaque;

int rdp_desktop_composition_operation_valid(uint8_t operation);
librdp_status rdp_desktop_composition_parse_header(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_header* header);
librdp_status rdp_desktop_composition_write_header(rdp_buffer* buffer,
                                                   uint8_t operation,
                                                   uint16_t size);
librdp_status rdp_desktop_composition_parse_toggle(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_toggle* order);
librdp_status rdp_desktop_composition_write_toggle(rdp_buffer* buffer, uint8_t event_type);
librdp_status rdp_desktop_composition_parse_lsurface(const void* data,
                                                     size_t length,
                                                     rdp_desktop_composition_lsurface* order);
librdp_status rdp_desktop_composition_write_lsurface(rdp_buffer* buffer,
                                                     uint8_t create,
                                                     uint8_t flags,
                                                     uint64_t surface_id,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     uint64_t window_id,
                                                     uint64_t luid);
librdp_status rdp_desktop_composition_parse_surfobj(const void* data,
                                                    size_t length,
                                                    rdp_desktop_composition_surfobj* order);
librdp_status rdp_desktop_composition_write_surfobj(rdp_buffer* buffer,
                                                    uint32_t cache_id,
                                                    uint8_t surface_bpp,
                                                    uint64_t surface_id,
                                                    uint32_t width,
                                                    uint32_t height);
librdp_status rdp_desktop_composition_parse_assoc(const void* data,
                                                  size_t length,
                                                  rdp_desktop_composition_assoc* order);
librdp_status rdp_desktop_composition_write_assoc(rdp_buffer* buffer,
                                                  uint8_t associate,
                                                  uint64_t logical_surface_id,
                                                  uint64_t redirection_surface_id);
librdp_status rdp_desktop_composition_parse_compref(const void* data,
                                                    size_t length,
                                                    rdp_desktop_composition_u64_order* order);
librdp_status rdp_desktop_composition_write_compref(rdp_buffer* buffer, uint64_t logical_surface_id);
librdp_status rdp_desktop_composition_parse_switch_surfobj(const void* data,
                                                           size_t length,
                                                           rdp_desktop_composition_u32_order* order);
librdp_status rdp_desktop_composition_write_switch_surfobj(rdp_buffer* buffer, uint32_t cache_id);
librdp_status rdp_desktop_composition_parse_opaque(const void* data,
                                                   size_t length,
                                                   rdp_desktop_composition_opaque* order);
librdp_status rdp_desktop_composition_write_opaque(rdp_buffer* buffer,
                                                   uint8_t operation,
                                                   const void* payload,
                                                   uint16_t payload_len);

#endif
