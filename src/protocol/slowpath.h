#ifndef RDP_PROTOCOL_SLOWPATH_H
#define RDP_PROTOCOL_SLOWPATH_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "protocol/capabilities.h"

#define RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE 0x0001u
#define RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE 0x0003u
#define RDP_SLOWPATH_PDU_TYPE_DATA 0x0007u
#define RDP_SLOWPATH_PDU_VERSION 0x0010u
#define RDP_SLOWPATH_DATA_PDU_UPDATE 0x02u
#define RDP_SLOWPATH_DATA_PDU_CONTROL 0x14u
#define RDP_SLOWPATH_DATA_PDU_INPUT 0x1cu
#define RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE 0x1fu
#define RDP_SLOWPATH_DATA_PDU_REFRESH_RECT 0x21u
#define RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT 0x23u
#define RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO 0x26u
#define RDP_SLOWPATH_DATA_PDU_FONT_LIST 0x27u
#define RDP_SLOWPATH_DATA_PDU_FONT_MAP 0x28u
#define RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST 0x2bu
#define RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO 0x2fu

typedef struct rdp_slowpath_share_control_header
{
    uint16_t total_length;
    uint16_t pdu_type;
    uint16_t channel_id;
} rdp_slowpath_share_control_header;

typedef struct rdp_slowpath_demand_active
{
    rdp_slowpath_share_control_header header;
    uint32_t share_id;
    const uint8_t* source_descriptor;
    uint16_t source_descriptor_len;
    rdp_capability_list capabilities;
} rdp_slowpath_demand_active;

typedef struct rdp_slowpath_data_pdu
{
    rdp_slowpath_share_control_header header;
    uint32_t share_id;
    uint8_t stream_id;
    uint16_t uncompressed_length;
    uint8_t pdu_type2;
    uint8_t compressed_type;
    uint16_t compressed_length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_slowpath_data_pdu;

typedef struct rdp_slowpath_font_map
{
    uint16_t number_entries;
    uint16_t total_entries;
    uint16_t map_flags;
    uint16_t entry_size;
} rdp_slowpath_font_map;

typedef struct rdp_slowpath_save_session_info
{
    uint32_t info_type;
    const uint8_t* data;
    size_t data_len;
} rdp_slowpath_save_session_info;

librdp_status rdp_slowpath_parse_share_control_header(const void* data,
                                                      size_t length,
                                                      rdp_slowpath_share_control_header* header);
librdp_status rdp_slowpath_parse_demand_active(const void* data,
                                               size_t length,
                                               rdp_slowpath_demand_active* demand);
librdp_status rdp_slowpath_write_confirm_active(rdp_buffer* buffer,
                                                uint32_t share_id,
                                                uint16_t channel_id,
                                                uint16_t width,
                                                uint16_t height,
                                                const char* source_descriptor);
librdp_status rdp_slowpath_write_client_synchronize(rdp_buffer* buffer,
                                                    uint32_t share_id,
                                                    uint16_t channel_id);
librdp_status rdp_slowpath_write_client_control(rdp_buffer* buffer,
                                                uint32_t share_id,
                                                uint16_t channel_id,
                                                uint16_t action);
librdp_status rdp_slowpath_write_client_font_list(rdp_buffer* buffer,
                                                  uint32_t share_id,
                                                  uint16_t channel_id);
librdp_status rdp_slowpath_write_client_persistent_key_list(rdp_buffer* buffer,
                                                            uint32_t share_id,
                                                            uint16_t channel_id);
librdp_status rdp_slowpath_write_client_keyboard_input(rdp_buffer* buffer,
                                                       uint32_t share_id,
                                                       uint16_t channel_id,
                                                       uint16_t flags,
                                                       uint16_t scancode);
librdp_status rdp_slowpath_write_client_unicode_keyboard_input(rdp_buffer* buffer,
                                                               uint32_t share_id,
                                                               uint16_t channel_id,
                                                               uint16_t flags,
                                                               uint16_t code);
librdp_status rdp_slowpath_write_client_mouse_input(rdp_buffer* buffer,
                                                    uint32_t share_id,
                                                    uint16_t channel_id,
                                                    uint16_t flags,
                                                    uint16_t x,
                                                    uint16_t y);
librdp_status rdp_slowpath_write_client_extended_mouse_input(rdp_buffer* buffer,
                                                             uint32_t share_id,
                                                             uint16_t channel_id,
                                                             uint16_t flags,
                                                             uint16_t x,
                                                             uint16_t y);
librdp_status rdp_slowpath_write_client_refresh_rect(rdp_buffer* buffer,
                                                     uint32_t share_id,
                                                     uint16_t channel_id,
                                                     uint16_t x,
                                                     uint16_t y,
                                                     uint16_t width,
                                                     uint16_t height);
librdp_status rdp_slowpath_write_client_suppress_output(rdp_buffer* buffer,
                                                        uint32_t share_id,
                                                        uint16_t channel_id,
                                                        int allow_updates,
                                                        uint16_t x,
                                                        uint16_t y,
                                                        uint16_t width,
                                                        uint16_t height);
librdp_status rdp_slowpath_parse_data_pdu(const void* data, size_t length, rdp_slowpath_data_pdu* pdu);
librdp_status rdp_slowpath_parse_font_map(const void* data, size_t length, rdp_slowpath_font_map* font_map);
librdp_status rdp_slowpath_parse_set_error_info(const void* data, size_t length, uint32_t* error_info);
librdp_status rdp_slowpath_parse_save_session_info(const void* data,
                                                   size_t length,
                                                   rdp_slowpath_save_session_info* info);

#endif
