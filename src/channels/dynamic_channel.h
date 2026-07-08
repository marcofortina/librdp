#ifndef RDP_CHANNELS_DYNAMIC_CHANNEL_H
#define RDP_CHANNELS_DYNAMIC_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_DYNAMIC_CHANNEL_CMD_CREATE 0x01u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST 0x02u
#define RDP_DYNAMIC_CHANNEL_CMD_DATA 0x03u
#define RDP_DYNAMIC_CHANNEL_CMD_CLOSE 0x04u
#define RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES 0x05u
#define RDP_DYNAMIC_CHANNEL_STATUS_OK 0x00000000u
#define RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE 1600u

typedef struct rdp_dynamic_channel_header
{
    uint8_t command;
    uint8_t priority;
    uint8_t length_bytes;
    uint8_t channel_id_bytes;
    uint8_t raw;
} rdp_dynamic_channel_header;

typedef struct rdp_dynamic_channel_capabilities
{
    uint16_t version;
} rdp_dynamic_channel_capabilities;

typedef struct rdp_dynamic_channel_create_request
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    const char* name;
    size_t name_len;
} rdp_dynamic_channel_create_request;

typedef struct rdp_dynamic_channel_data_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_data_pdu;

typedef struct rdp_dynamic_channel_data_first_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint32_t total_length;
    const uint8_t* data;
    size_t data_len;
} rdp_dynamic_channel_data_first_pdu;

typedef struct rdp_dynamic_channel_close_pdu
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
} rdp_dynamic_channel_close_pdu;

uint16_t rdp_dynamic_channel_select_version(uint16_t server_version);
librdp_status rdp_dynamic_channel_parse_header(const void* data,
                                               size_t length,
                                               rdp_dynamic_channel_header* header);
librdp_status rdp_dynamic_channel_parse_capabilities(const void* data,
                                                     size_t length,
                                                     rdp_dynamic_channel_capabilities* capabilities);
librdp_status rdp_dynamic_channel_write_capabilities_response(rdp_buffer* buffer, uint16_t version);
librdp_status rdp_dynamic_channel_parse_create_request(const void* data,
                                                       size_t length,
                                                       rdp_dynamic_channel_create_request* request);
librdp_status rdp_dynamic_channel_write_create_response(rdp_buffer* buffer,
                                                       uint32_t channel_id,
                                                       uint8_t channel_id_bytes,
                                                       uint32_t status_code);
librdp_status rdp_dynamic_channel_parse_data(const void* data,
                                             size_t length,
                                             rdp_dynamic_channel_data_pdu* pdu);
librdp_status rdp_dynamic_channel_write_data(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes,
                                             const void* data,
                                             size_t data_len);
librdp_status rdp_dynamic_channel_parse_data_first(const void* data,
                                                   size_t length,
                                                   rdp_dynamic_channel_data_first_pdu* pdu);
librdp_status rdp_dynamic_channel_write_data_first(rdp_buffer* buffer,
                                                  uint32_t channel_id,
                                                  uint8_t channel_id_bytes,
                                                  uint32_t total_length,
                                                  const void* data,
                                                  size_t data_len);
librdp_status rdp_dynamic_channel_parse_close(const void* data,
                                              size_t length,
                                              rdp_dynamic_channel_close_pdu* pdu);
librdp_status rdp_dynamic_channel_write_close(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes);

#endif
