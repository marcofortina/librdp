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
#define RDP_GCC_SC_CORE 0x0c01u
#define RDP_GCC_SC_SECURITY 0x0c02u
#define RDP_GCC_SC_NETWORK 0x0c03u
#define RDP_GCC_MAX_SERVER_CHANNELS 64u
#define RDP_GCC_CLIENT_VERSION_5 0x00080004u
#define RDP_GCC_CLIENT_VERSION_10_12 0x00080011u
#define RDP_GCC_EARLY_SUPPORT_ERRINFO 0x0001u
#define RDP_GCC_EARLY_WANT_32BPP 0x0002u
#define RDP_GCC_EARLY_SUPPORT_STATUSINFO 0x0004u
#define RDP_GCC_EARLY_SUPPORT_MONITOR_LAYOUT 0x0040u
#define RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT 0x0080u
#define RDP_GCC_EARLY_SUPPORT_DYNVC_GFX 0x0100u
#define RDP_GCC_CONNECTION_TYPE_LAN 0x06u

typedef struct rdp_gcc_user_data_block
{
    uint16_t type;
    uint16_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_gcc_user_data_block;

typedef struct rdp_gcc_client_config
{
    uint32_t client_version;
    uint16_t desktop_width;
    uint16_t desktop_height;
    uint32_t requested_protocols;
    uint16_t early_capability_flags;
    uint8_t connection_type;
    const char* client_name;
    uint8_t enable_dynamic_channels;
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
    uint16_t early_capability_flags;
    uint8_t connection_type;
    uint16_t channel_count;
} rdp_gcc_client_data_summary;

typedef struct rdp_gcc_conference_response
{
    uint16_t node_id;
    uint32_t tag;
    uint8_t result;
    const uint8_t* user_data;
    size_t user_data_len;
} rdp_gcc_conference_response;

typedef struct rdp_gcc_server_data
{
    uint8_t has_core;
    uint8_t has_security;
    uint8_t has_network;
    uint32_t version;
    uint32_t requested_protocols;
    uint32_t early_capability_flags;
    uint32_t encryption_method;
    uint32_t encryption_level;
    const uint8_t* server_random;
    uint32_t server_random_len;
    const uint8_t* server_certificate;
    uint32_t server_certificate_len;
    uint16_t mcs_channel_id;
    uint16_t channel_count;
    uint16_t channel_ids[RDP_GCC_MAX_SERVER_CHANNELS];
} rdp_gcc_server_data;

librdp_status rdp_gcc_write_client_data_blocks(rdp_buffer* buffer, const rdp_gcc_client_config* config);
librdp_status rdp_gcc_write_conference_create_request(rdp_buffer* buffer, const void* user_data, size_t user_data_len);
librdp_status rdp_gcc_parse_client_data_blocks(const void* data, size_t length, rdp_gcc_client_data_summary* summary);
librdp_status rdp_gcc_parse_conference_create_response(const void* data,
                                                       size_t length,
                                                       rdp_gcc_conference_response* response);
librdp_status rdp_gcc_parse_server_data_blocks(const void* data, size_t length, rdp_gcc_server_data* server_data);
librdp_status rdp_gcc_read_user_data_block(rdp_stream* stream, rdp_gcc_user_data_block* block);

#endif
