#ifndef RDP_PROTOCOL_CAPABILITIES_H
#define RDP_PROTOCOL_CAPABILITIES_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#define RDP_CAPABILITY_MAX_SETS 64u

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
