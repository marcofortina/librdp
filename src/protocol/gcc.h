#ifndef RDP_PROTOCOL_GCC_H
#define RDP_PROTOCOL_GCC_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "common/stream.h"

#define RDP_GCC_CS_CORE 0xc001u
#define RDP_GCC_CS_SECURITY 0xc002u
#define RDP_GCC_CS_NETWORK 0xc003u

typedef struct rdp_gcc_user_data_block
{
    uint16_t type;
    uint16_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_gcc_user_data_block;

typedef struct rdp_gcc_client_config
{
    uint16_t desktop_width;
    uint16_t desktop_height;
    uint32_t requested_protocols;
    const char* client_name;
} rdp_gcc_client_config;

typedef struct rdp_gcc_client_data_summary
{
    uint8_t has_core;
    uint8_t has_security;
    uint8_t has_network;
    uint16_t desktop_width;
    uint16_t desktop_height;
    uint32_t version;
    uint32_t requested_protocols;
    uint16_t channel_count;
} rdp_gcc_client_data_summary;

librdp_status rdp_gcc_write_client_data_blocks(rdp_buffer* buffer, const rdp_gcc_client_config* config);
librdp_status rdp_gcc_write_conference_create_request(rdp_buffer* buffer, const void* user_data, size_t user_data_len);
librdp_status rdp_gcc_parse_client_data_blocks(const void* data, size_t length, rdp_gcc_client_data_summary* summary);
librdp_status rdp_gcc_read_user_data_block(rdp_stream* stream, rdp_gcc_user_data_block* block);

#endif
