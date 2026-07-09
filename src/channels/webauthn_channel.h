#ifndef RDP_CHANNELS_WEBAUTHN_CHANNEL_H
#define RDP_CHANNELS_WEBAUTHN_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_WEBAUTHN_COMMAND_WEB_AUTHN 5u
#define RDP_WEBAUTHN_COMMAND_IUVPAA 6u
#define RDP_WEBAUTHN_COMMAND_CANCEL 7u
#define RDP_WEBAUTHN_COMMAND_API_VERSION 8u
#define RDP_WEBAUTHN_COMMAND_GET_CREDENTIALS 9u
#define RDP_WEBAUTHN_COMMAND_GET_AUTHENTICATOR_LIST 12u
#define RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL 0x01u
#define RDP_WEBAUTHN_CMD_GET_ASSERTION 0x02u
#define RDP_WEBAUTHN_FLAG_U2F 0x00020000u
#define RDP_WEBAUTHN_FLAG_DUAL 0x00040000u
#define RDP_WEBAUTHN_FLAG_SELECT_CREDENTIAL_ALLOW_UV 0x00008000u
#define RDP_WEBAUTHN_FLAG_CLIENT_PIN_REQUIRED 0x00100000u
#define RDP_WEBAUTHN_FLAG_UV_REQUIRED 0x00400000u
#define RDP_WEBAUTHN_FLAG_UV_PREFERRED 0x00800000u
#define RDP_WEBAUTHN_FLAG_UV_NOT_REQUIRED 0x01000000u
#define RDP_WEBAUTHN_FLAG_HMAC_SECRET_EXTENSION 0x04000000u
#define RDP_WEBAUTHN_FLAG_FORCE_U2F_V2 0x08000000u
#define RDP_WEBAUTHN_FLAG_KNOWN_MASK                                                                                   \
    (RDP_WEBAUTHN_FLAG_U2F | RDP_WEBAUTHN_FLAG_DUAL | RDP_WEBAUTHN_FLAG_SELECT_CREDENTIAL_ALLOW_UV |                   \
     RDP_WEBAUTHN_FLAG_CLIENT_PIN_REQUIRED | RDP_WEBAUTHN_FLAG_UV_REQUIRED |                                           \
     RDP_WEBAUTHN_FLAG_UV_PREFERRED | RDP_WEBAUTHN_FLAG_UV_NOT_REQUIRED |                                             \
     RDP_WEBAUTHN_FLAG_HMAC_SECRET_EXTENSION | RDP_WEBAUTHN_FLAG_FORCE_U2F_V2)
#define RDP_WEBAUTHN_GUID_LENGTH 16u
#define RDP_WEBAUTHN_MAX_MESSAGE 1048576u

typedef struct rdp_webauthn_request
{
    uint32_t command;
    uint32_t flags;
    uint8_t has_flags;
    const uint8_t* request;
    size_t request_len;
    const uint8_t* rp_id;
    size_t rp_id_len;
    const uint8_t* transaction_id;
    size_t transaction_id_len;
} rdp_webauthn_request;

typedef struct rdp_webauthn_response
{
    uint32_t hresult;
    const uint8_t* payload;
    size_t payload_len;
} rdp_webauthn_response;

int rdp_webauthn_command_valid(uint32_t command);
int rdp_webauthn_flags_valid(uint32_t flags);
librdp_status rdp_webauthn_parse_request(const void* data,
                                         size_t length,
                                         rdp_webauthn_request* request);
librdp_status rdp_webauthn_write_request(rdp_buffer* buffer,
                                         uint32_t command,
                                         uint32_t flags,
                                         const void* request_data,
                                         size_t request_len,
                                         const char* rp_id,
                                         const void* transaction_id);
librdp_status rdp_webauthn_parse_response(const void* data,
                                          size_t length,
                                          rdp_webauthn_response* response);
librdp_status rdp_webauthn_write_response(rdp_buffer* buffer,
                                          uint32_t hresult,
                                          const void* payload,
                                          size_t payload_len);
librdp_status rdp_webauthn_parse_u32_response(const rdp_webauthn_response* response,
                                              uint32_t* value);
librdp_status rdp_webauthn_write_u32_response(rdp_buffer* buffer, uint32_t hresult, uint32_t value);

#endif
