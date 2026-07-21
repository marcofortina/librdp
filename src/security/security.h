/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: standard security key, signing, encryption, and legacy crypto
 * contract.
 * Invariants: secret material and authentication tokens stay bounded and are
 * never trace-visible.
 * Ownership: security contexts own keys and exported secret material until
 * reset or free.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: remote certificates, tokens, and ASN.1/security-buffer data
 * are untrusted; credentials are sensitive local input.
 */


#ifndef RDP_SECURITY_SECURITY_H
#define RDP_SECURITY_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/settings.h>

#include "common/buffer.h"
#include "security/certificate.h"

#include <openssl/types.h>

#define RDP_SEC_EXCHANGE_PKT 0x0001u
#define RDP_SEC_ENCRYPT 0x0008u
#define RDP_SEC_INFO_PKT 0x0040u
#define RDP_SEC_LICENSE_PKT 0x0080u
#define RDP_SEC_LICENSE_ENCRYPT_SC 0x0200u
#define RDP_SEC_REDIRECTION_PKT 0x0400u
#define RDP_SEC_SECURE_CHECKSUM 0x0800u
#define RDP_SEC_AUTODETECT_REQ 0x1000u
#define RDP_SEC_AUTODETECT_RSP 0x2000u
#define RDP_SECURITY_PREMASTER_SECRET_LEN 48u
#define RDP_SECURITY_LICENSE_KEY_LEN 16u
#define RDP_SECURITY_METHOD_40BIT 0x00000001u
#define RDP_SECURITY_METHOD_128BIT 0x00000002u
#define RDP_SECURITY_METHOD_56BIT 0x00000008u
#define RDP_SECURITY_METHOD_FIPS 0x00000010u

typedef struct rdp_rc4_context
{
    EVP_CIPHER_CTX* cipher;
    uint8_t initialized;
} rdp_rc4_context;

typedef struct rdp_standard_security_context
{
    uint8_t sign_key[16];
    uint8_t encrypt_key[16];
    uint8_t decrypt_key[16];
    uint8_t encrypt_update_key[16];
    uint8_t decrypt_update_key[16];
    size_t key_len;
    uint32_t method;
    uint32_t encrypt_count;
    uint32_t decrypt_count;
    rdp_rc4_context encrypt_rc4;
    rdp_rc4_context decrypt_rc4;
} rdp_standard_security_context;

typedef struct rdp_client_info
{
    const char* domain;
    const char* username;
    const char* password;
    const char* alternate_shell;
    const char* working_dir;
} rdp_client_info;

typedef struct rdp_client_info_summary
{
    uint32_t code_page;
    uint32_t flags;
    uint16_t domain_bytes;
    uint16_t username_bytes;
    uint16_t password_bytes;
    uint16_t alternate_shell_bytes;
    uint16_t working_dir_bytes;
} rdp_client_info_summary;

uint32_t rdp_security_protocol_mask(librdp_security_mode mode);
bool rdp_security_protocol_supported(uint32_t selected_protocol);
bool rdp_security_protocol_allowed(librdp_security_mode mode, bool negotiation_present, uint32_t selected_protocol);
librdp_status rdp_security_write_header(rdp_buffer* buffer, uint16_t flags);
librdp_status rdp_security_write_exchange_pdu(rdp_buffer* buffer,
                                              const uint8_t* encrypted_client_random,
                                              size_t encrypted_client_random_len);
librdp_status rdp_security_write_client_info_pdu(rdp_buffer* buffer, const rdp_client_info* info);
librdp_status rdp_security_write_client_info_body(rdp_buffer* buffer, const rdp_client_info* info);
librdp_status rdp_security_parse_client_info_pdu(const void* data,
                                                 size_t length,
                                                 rdp_client_info_summary* summary);
librdp_status rdp_security_write_send_data_request(rdp_buffer* buffer,
                                                   uint16_t user_id,
                                                   uint16_t channel_id,
                                                   const void* payload,
                                                   size_t payload_len);
librdp_status rdp_security_standard_client_init(rdp_standard_security_context* context,
                                                uint32_t method,
                                                const uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                                const uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN]);
librdp_status rdp_security_standard_server_init(rdp_standard_security_context* context,
                                                uint32_t method,
                                                const uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                                const uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN]);
void rdp_security_standard_clear(rdp_standard_security_context* context);
librdp_status rdp_security_license_keys(const uint8_t premaster_secret[RDP_SECURITY_PREMASTER_SECRET_LEN],
                                        const uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                        const uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                        uint8_t mac_salt_key[RDP_SECURITY_LICENSE_KEY_LEN],
                                        uint8_t encryption_key[RDP_SECURITY_LICENSE_KEY_LEN]);
librdp_status rdp_security_license_mac(const uint8_t mac_salt_key[RDP_SECURITY_LICENSE_KEY_LEN],
                                       const void* data,
                                       size_t length,
                                       uint8_t mac[RDP_SECURITY_LICENSE_KEY_LEN]);
librdp_status rdp_security_license_crypt(const uint8_t encryption_key[RDP_SECURITY_LICENSE_KEY_LEN],
                                         const void* input,
                                         size_t length,
                                         rdp_buffer* output);
librdp_status rdp_security_mac_signature(const rdp_standard_security_context* context,
                                         const void* data,
                                         size_t length,
                                         uint8_t signature[8]);
librdp_status rdp_security_salted_mac_signature(const rdp_standard_security_context* context,
                                                const void* data,
                                                size_t length,
                                                uint32_t use_count,
                                                uint8_t signature[8]);
librdp_status rdp_security_encrypt_payload(rdp_standard_security_context* context, void* data, size_t length);
librdp_status rdp_security_decrypt_payload(rdp_standard_security_context* context, void* data, size_t length);
librdp_status rdp_security_write_encrypted_pdu(rdp_buffer* buffer,
                                               rdp_standard_security_context* context,
                                               uint16_t flags,
                                               const void* payload,
                                               size_t payload_len);
librdp_status rdp_security_unwrap_pdu(rdp_standard_security_context* context,
                                      const void* data,
                                      size_t length,
                                      rdp_buffer* payload,
                                      uint16_t* flags);
librdp_status rdp_security_write_encrypted_client_info_pdu(rdp_buffer* buffer,
                                                           rdp_standard_security_context* context,
                                                           const rdp_client_info* info);

#endif
