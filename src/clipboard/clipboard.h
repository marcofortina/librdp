#ifndef RDP_CLIPBOARD_CLIPBOARD_H
#define RDP_CLIPBOARD_CLIPBOARD_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_clipboard_packet
{
    uint16_t type;
    uint16_t flags;
    uint32_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_clipboard_packet;

librdp_status rdp_clipboard_parse_packet(const void* data, size_t length, rdp_clipboard_packet* packet);

#endif
