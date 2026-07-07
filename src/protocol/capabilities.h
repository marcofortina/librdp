#ifndef RDP_PROTOCOL_CAPABILITIES_H
#define RDP_PROTOCOL_CAPABILITIES_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#define RDP_CAPABILITY_MAX_SETS 64u
#define RDP_CAPABILITY_TYPE_GENERAL 0x0001u
#define RDP_CAPABILITY_TYPE_BITMAP 0x0002u
#define RDP_CAPABILITY_TYPE_ORDER 0x0003u
#define RDP_CAPABILITY_TYPE_CONTROL 0x0005u
#define RDP_CAPABILITY_TYPE_ACTIVATION 0x0007u
#define RDP_CAPABILITY_TYPE_POINTER 0x0008u
#define RDP_CAPABILITY_TYPE_SHARE 0x0009u
#define RDP_CAPABILITY_TYPE_COLOR_CACHE 0x000au
#define RDP_CAPABILITY_TYPE_SOUND 0x000cu
#define RDP_CAPABILITY_TYPE_INPUT 0x000du
#define RDP_CAPABILITY_TYPE_FONT 0x000eu
#define RDP_CAPABILITY_TYPE_BRUSH 0x000fu
#define RDP_CAPABILITY_TYPE_GLYPH_CACHE 0x0010u
#define RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2 0x0013u
#define RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL 0x0014u

typedef struct rdp_capability_set
{
    uint16_t type;
    uint16_t length;
    const uint8_t* data;
    size_t data_len;
} rdp_capability_set;

typedef struct rdp_capability_list
{
    uint16_t count;
    rdp_capability_set sets[RDP_CAPABILITY_MAX_SETS];
} rdp_capability_list;

librdp_status rdp_capabilities_parse(const void* data, size_t length, rdp_capability_list* list);

#endif
