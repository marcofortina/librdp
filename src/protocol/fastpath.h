#ifndef RDP_PROTOCOL_FASTPATH_H
#define RDP_PROTOCOL_FASTPATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#define RDP_FASTPATH_OUTPUT_ACTION_FASTPATH 0x00u
#define RDP_FASTPATH_OUTPUT_ACTION_X224 0x03u
#define RDP_FASTPATH_OUTPUT_COMPRESSION_USED 0x02u
#define RDP_FASTPATH_FRAGMENT_SINGLE 0x00u
#define RDP_FASTPATH_FRAGMENT_LAST 0x01u
#define RDP_FASTPATH_FRAGMENT_FIRST 0x02u
#define RDP_FASTPATH_FRAGMENT_NEXT 0x03u
#define RDP_FASTPATH_UPDATE_ORDERS 0x00u
#define RDP_FASTPATH_UPDATE_BITMAP 0x01u
#define RDP_FASTPATH_UPDATE_PALETTE 0x02u
#define RDP_FASTPATH_UPDATE_SYNCHRONIZE 0x03u
#define RDP_FASTPATH_UPDATE_SURFACE_COMMANDS 0x04u
#define RDP_FASTPATH_UPDATE_POINTER_NULL 0x05u
#define RDP_FASTPATH_UPDATE_POINTER_DEFAULT 0x06u
#define RDP_FASTPATH_UPDATE_POINTER_POSITION 0x08u
#define RDP_FASTPATH_UPDATE_POINTER_COLOR 0x09u
#define RDP_FASTPATH_UPDATE_POINTER_CACHED 0x0au
#define RDP_FASTPATH_UPDATE_POINTER_NEW 0x0bu
#define RDP_FASTPATH_UPDATE_POINTER_LARGE 0x0cu
#define RDP_FASTPATH_MAX_UPDATES 64u

typedef struct rdp_fastpath_header
{
    uint8_t action;
    uint8_t security_flags;
    uint16_t length;
    size_t header_length;
    bool long_length;
} rdp_fastpath_header;

typedef struct rdp_fastpath_update
{
    uint8_t update_code;
    uint8_t fragmentation;
    uint8_t compression;
    uint8_t compression_flags;
    const uint8_t* data;
    size_t data_len;
} rdp_fastpath_update;

typedef struct rdp_fastpath_update_list
{
    uint16_t count;
    rdp_fastpath_update updates[RDP_FASTPATH_MAX_UPDATES];
} rdp_fastpath_update_list;

librdp_status rdp_fastpath_parse_header(const void* data, size_t length, rdp_fastpath_header* header);
librdp_status rdp_fastpath_parse_updates(const void* data, size_t length, rdp_fastpath_update_list* updates);

#endif
