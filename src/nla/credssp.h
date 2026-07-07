#ifndef RDP_NLA_CREDSSP_H
#define RDP_NLA_CREDSSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

typedef enum rdp_credssp_state
{
    RDP_CREDSSP_DISABLED = 0,
    RDP_CREDSSP_NEGOTIATING = 1,
    RDP_CREDSSP_COMPLETE = 2,
    RDP_CREDSSP_FAILED = 3
} rdp_credssp_state;

typedef struct rdp_credssp_ts_request
{
    uint32_t version;
    const uint8_t* nego_token;
    size_t nego_token_len;
    const uint8_t* auth_info;
    size_t auth_info_len;
    const uint8_t* pub_key_auth;
    size_t pub_key_auth_len;
    uint32_t error_code;
    int has_error_code;
} rdp_credssp_ts_request;

typedef struct rdp_ntlm_challenge
{
    uint32_t flags;
    uint8_t server_challenge[8];
    const uint8_t* target_name;
    size_t target_name_len;
    const uint8_t* target_info;
    size_t target_info_len;
} rdp_ntlm_challenge;

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state);
librdp_status rdp_credssp_write_ntlm_negotiate(rdp_buffer* buffer, const char* workstation, const char* domain);
librdp_status rdp_credssp_write_spnego_ntlm_negotiate(rdp_buffer* buffer,
                                                      const uint8_t* ntlm_token,
                                                      size_t ntlm_token_len);
librdp_status rdp_credssp_write_ts_request(rdp_buffer* buffer,
                                           uint32_t version,
                                           const uint8_t* nego_token,
                                           size_t nego_token_len,
                                           const uint8_t* auth_info,
                                           size_t auth_info_len,
                                           const uint8_t* pub_key_auth,
                                           size_t pub_key_auth_len);
librdp_status rdp_credssp_write_negotiate_request(rdp_buffer* buffer,
                                                  const char* workstation,
                                                  const char* domain);
librdp_status rdp_credssp_parse_ts_request(const void* data, size_t length, rdp_credssp_ts_request* request);
librdp_status rdp_credssp_extract_ntlm_challenge(const void* token,
                                                 size_t token_len,
                                                 const uint8_t** ntlm,
                                                 size_t* ntlm_len);
librdp_status rdp_credssp_parse_ntlm_challenge(const void* data,
                                               size_t length,
                                               rdp_ntlm_challenge* challenge);

#endif
