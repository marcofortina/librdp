#ifndef RDP_CHANNELS_CORE_INPUT_H
#define RDP_CHANNELS_CORE_INPUT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_CORE_INPUT_SIGNATURE 0x03u
#define RDP_CORE_INPUT_PDU_CS_INIT_REQUEST 0x01u
#define RDP_CORE_INPUT_PDU_SC_INIT_RESPONSE 0x02u
#define RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE 0x03u
#define RDP_CORE_INPUT_PROTOCOL_VERSION_100 0x0100u
#define RDP_CORE_INPUT_EVENT_SCANCODE 0x00u
#define RDP_CORE_INPUT_EVENT_MOUSE 0x01u
#define RDP_CORE_INPUT_KBDFLAGS_RELEASE 0x01u

typedef struct rdp_core_input_header
{
    uint8_t signature;
    uint8_t pdu_type;
    uint8_t event_count;
    uint8_t padding;
} rdp_core_input_header;

typedef struct rdp_core_input_init_response
{
    uint16_t selected_protocol_version;
    uint16_t protocol_version_max;
} rdp_core_input_init_response;

librdp_status rdp_core_input_parse_header(const void* data,
                                          size_t length,
                                          rdp_core_input_header* header);
librdp_status rdp_core_input_write_init_request(rdp_buffer* buffer);
librdp_status rdp_core_input_parse_init_response(const void* data,
                                                 size_t length,
                                                 rdp_core_input_init_response* response);
librdp_status rdp_core_input_write_keyboard_event(rdp_buffer* buffer, uint8_t scancode, uint8_t released);
librdp_status rdp_core_input_write_mouse_event(rdp_buffer* buffer, uint16_t pointer_flags, uint16_t x, uint16_t y);

#endif
