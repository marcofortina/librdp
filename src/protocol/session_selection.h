#ifndef RDP_PROTOCOL_SESSION_SELECTION_H
#define RDP_PROTOCOL_SESSION_SELECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_SESSION_SELECTION_VERSION1 0x00000001u
#define RDP_SESSION_SELECTION_VERSION2 0x00000002u
#define RDP_SESSION_SELECTION_V1_LENGTH 16u
#define RDP_SESSION_SELECTION_V2_HEADER_LENGTH 18u
#define RDP_SESSION_SELECTION_MAX_TEXT_CHARS 4096u

typedef struct rdp_session_selection_pdu
{
    uint32_t cb_size;
    uint32_t flags;
    uint32_t version;
    uint32_t id;
    uint16_t text_chars;
    const uint8_t* text_utf16le;
} rdp_session_selection_pdu;

librdp_status rdp_session_selection_parse_pdu(const void* data,
                                              size_t length,
                                              rdp_session_selection_pdu* pdu);
librdp_status rdp_session_selection_write_v1(rdp_buffer* buffer, uint32_t id);
librdp_status rdp_session_selection_write_v2(rdp_buffer* buffer,
                                             uint32_t id,
                                             const void* text_utf16le,
                                             uint16_t text_chars);

#endif
