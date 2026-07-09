#ifndef RDP_CHANNELS_AUTH_REDIRECTION_H
#define RDP_CHANNELS_AUTH_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_AUTH_REDIRECTION_MAGIC 0x4eacc3c8u
#define RDP_AUTH_REDIRECTION_VERSION 0x00000000u
#define RDP_AUTH_REDIRECTION_OUTER_HEADER_LENGTH 24u
#define RDP_AUTH_REDIRECTION_INNER_HEADER_LENGTH 16u
#define RDP_AUTH_REDIRECTION_INNER_REVISION 0x0001u

#define RDP_AUTH_REDIRECTION_CALL_GENERIC_MINIMUM 0x00000000u
#define RDP_AUTH_REDIRECTION_CALL_GENERIC_MAXIMUM 0x000000ffu
#define RDP_AUTH_REDIRECTION_CALL_KERB_MINIMUM 0x00000100u
#define RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION 0x00000100u
#define RDP_AUTH_REDIRECTION_CALL_KERB_MAXIMUM 0x000001ffu
#define RDP_AUTH_REDIRECTION_CALL_NTLM_MINIMUM 0x00000200u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION 0x00000200u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS 0x00000204u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_MAXIMUM 0x000002ffu
#define RDP_AUTH_REDIRECTION_CALL_INVALID 0x0000ffffu

typedef struct rdp_auth_redirection_outer_packet
{
    uint32_t protocol_magic;
    uint32_t length;
    uint32_t version;
    uint32_t reserved;
    uint64_t ts_pkg_context;
    const uint8_t* payload;
    size_t payload_len;
} rdp_auth_redirection_outer_packet;

typedef struct rdp_auth_redirection_inner_buffer
{
    uint16_t revision;
    uint8_t reserved[14];
    const uint8_t* payload;
    size_t payload_len;
} rdp_auth_redirection_inner_buffer;

typedef struct rdp_auth_redirection_call
{
    uint32_t call_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_auth_redirection_call;

typedef struct rdp_auth_redirection_response
{
    uint32_t call_id;
    uint32_t status;
    const uint8_t* payload;
    size_t payload_len;
} rdp_auth_redirection_response;

typedef struct rdp_auth_redirection_negotiate_version
{
    uint32_t version;
} rdp_auth_redirection_negotiate_version;

int rdp_auth_redirection_call_id_valid(uint32_t call_id);
int rdp_auth_redirection_negotiate_call_id_valid(uint32_t call_id);
librdp_status rdp_auth_redirection_parse_outer_packet(
    const void* data,
    size_t length,
    rdp_auth_redirection_outer_packet* packet);
librdp_status rdp_auth_redirection_write_outer_packet(
    rdp_buffer* buffer,
    const void* payload,
    size_t payload_len);
librdp_status rdp_auth_redirection_parse_inner_buffer(
    const void* data,
    size_t length,
    rdp_auth_redirection_inner_buffer* inner);
librdp_status rdp_auth_redirection_write_inner_buffer(
    rdp_buffer* buffer,
    const void* payload,
    size_t payload_len);
librdp_status rdp_auth_redirection_parse_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_call* call);
librdp_status rdp_auth_redirection_write_call(
    rdp_buffer* buffer,
    uint32_t call_id,
    const void* payload,
    size_t payload_len);
librdp_status rdp_auth_redirection_parse_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response);
librdp_status rdp_auth_redirection_write_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    const void* payload,
    size_t payload_len);
librdp_status rdp_auth_redirection_parse_negotiate_version_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_negotiate_version* version);
librdp_status rdp_auth_redirection_write_negotiate_version_call(
    rdp_buffer* buffer,
    uint32_t call_id);
librdp_status rdp_auth_redirection_parse_negotiate_version_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_negotiate_version* version);
librdp_status rdp_auth_redirection_write_negotiate_version_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status);

#endif
