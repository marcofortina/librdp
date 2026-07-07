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
    const uint8_t* client_nonce;
    size_t client_nonce_len;
    uint32_t error_code;
    int has_error_code;
} rdp_credssp_ts_request;

typedef struct rdp_ntlm_rc4_context
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} rdp_ntlm_rc4_context;

typedef struct rdp_ntlm_security_context
{
    uint32_t flags;
    uint32_t send_seq;
    uint32_t recv_seq;
    uint8_t client_signing_key[16];
    uint8_t server_signing_key[16];
    uint8_t client_sealing_key[16];
    uint8_t server_sealing_key[16];
    rdp_ntlm_rc4_context send_rc4;
    rdp_ntlm_rc4_context recv_rc4;
} rdp_ntlm_security_context;

typedef struct rdp_ntlm_challenge
{
    uint32_t flags;
    uint8_t server_challenge[8];
    const uint8_t* target_name;
    size_t target_name_len;
    const uint8_t* target_info;
    size_t target_info_len;
} rdp_ntlm_challenge;

typedef struct rdp_ntlm_authenticate_result
{
    uint32_t flags;
    uint8_t session_key[16];
} rdp_ntlm_authenticate_result;

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state);
librdp_status rdp_credssp_write_ntlm_negotiate(rdp_buffer* buffer, const char* workstation, const char* domain);
librdp_status rdp_credssp_write_spnego_ntlm_negotiate(rdp_buffer* buffer,
                                                      const uint8_t* ntlm_token,
                                                      size_t ntlm_token_len);
librdp_status rdp_credssp_write_ntlm_authenticate(rdp_buffer* buffer,
                                                  const rdp_ntlm_challenge* challenge,
                                                  const char* username,
                                                  const char* password,
                                                  const char* domain,
                                                  const char* workstation,
                                                  uint64_t timestamp,
                                                  const uint8_t client_challenge[8],
                                                  const uint8_t exported_session_key[16],
                                                  rdp_ntlm_authenticate_result* result);
librdp_status rdp_credssp_write_spnego_ntlm_authenticate(rdp_buffer* buffer,
                                                         const uint8_t* ntlm_token,
                                                         size_t ntlm_token_len);
librdp_status rdp_credssp_write_ts_request(rdp_buffer* buffer,
                                           uint32_t version,
                                           const uint8_t* nego_token,
                                           size_t nego_token_len,
                                           const uint8_t* auth_info,
                                           size_t auth_info_len,
                                           const uint8_t* pub_key_auth,
                                           size_t pub_key_auth_len,
                                           const uint8_t* client_nonce,
                                           size_t client_nonce_len);
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
librdp_status rdp_credssp_ntlm_security_init(rdp_ntlm_security_context* context,
                                             const rdp_ntlm_authenticate_result* authenticate);
librdp_status rdp_credssp_ntlm_wrap(rdp_ntlm_security_context* context,
                                    const void* data,
                                    size_t length,
                                    rdp_buffer* wrapped);
librdp_status rdp_credssp_ntlm_unwrap(rdp_ntlm_security_context* context,
                                      const void* data,
                                      size_t length,
                                      rdp_buffer* plain);
librdp_status rdp_credssp_encrypt_public_key_hash(rdp_ntlm_security_context* context,
                                                  const void* client_nonce,
                                                  size_t client_nonce_len,
                                                  const void* public_key,
                                                  size_t public_key_len,
                                                  rdp_buffer* encrypted);
librdp_status rdp_credssp_verify_public_key_hash(rdp_ntlm_security_context* context,
                                                 const void* client_nonce,
                                                 size_t client_nonce_len,
                                                 const void* public_key,
                                                 size_t public_key_len,
                                                 const void* encrypted,
                                                 size_t encrypted_len);

#endif
