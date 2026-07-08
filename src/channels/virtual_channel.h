#ifndef RDP_CHANNELS_VIRTUAL_CHANNEL_H
#define RDP_CHANNELS_VIRTUAL_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_VIRTUAL_CHANNEL_FLAG_FIRST 0x00000001u
#define RDP_VIRTUAL_CHANNEL_FLAG_LAST 0x00000002u
#define RDP_VIRTUAL_CHANNEL_FLAG_SHOW_PROTOCOL 0x00000010u

typedef struct rdp_virtual_channel_packet
{
    uint32_t length;
    uint32_t flags;
    const uint8_t* payload;
    size_t payload_len;
} rdp_virtual_channel_packet;

librdp_status rdp_virtual_channel_parse_packet(const void* data, size_t length, rdp_virtual_channel_packet* packet);
librdp_status rdp_virtual_channel_write_packet(rdp_buffer* buffer,
                                               const void* payload,
                                               size_t payload_len,
                                               uint32_t flags);

#endif
