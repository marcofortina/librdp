/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

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
#define RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_AS_REQ_AUTHENTICATOR 0x00000101u
#define RDP_AUTH_REDIRECTION_CALL_KERB_VERIFY_SERVICE_TICKET 0x00000102u
#define RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_AP_REQ_AUTHENTICATOR 0x00000103u
#define RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY 0x00000104u
#define RDP_AUTH_REDIRECTION_CALL_KERB_UNPACK_KDC_REPLY_BODY 0x00000105u
#define RDP_AUTH_REDIRECTION_CALL_KERB_COMPUTE_TGS_CHECKSUM 0x00000106u
#define RDP_AUTH_REDIRECTION_CALL_KERB_BUILD_ENCRYPTED_AUTH_DATA 0x00000107u
#define RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY 0x00000108u
#define RDP_AUTH_REDIRECTION_CALL_KERB_HASH_S4U_PREAUTH 0x00000109u
#define RDP_AUTH_REDIRECTION_CALL_KERB_SIGN_S4U_PREAUTH_DATA 0x0000010au
#define RDP_AUTH_REDIRECTION_CALL_KERB_VERIFY_CHECKSUM 0x0000010bu
#define RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_PAC_CREDENTIALS 0x00000113u
#define RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_ECDH_KEY_AGREEMENT 0x00000114u
#define RDP_AUTH_REDIRECTION_CALL_KERB_CREATE_DH_KEY_AGREEMENT 0x00000115u
#define RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT 0x00000116u
#define RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE 0x00000117u
#define RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT 0x00000118u
#define RDP_AUTH_REDIRECTION_CALL_KERB_MAXIMUM 0x000001ffu
#define RDP_AUTH_REDIRECTION_CALL_NTLM_MINIMUM 0x00000200u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION 0x00000200u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_LM20_GET_NTLM3_CHALLENGE_RESPONSE 0x00000201u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE 0x00000202u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT 0x00000203u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS 0x00000204u
#define RDP_AUTH_REDIRECTION_CALL_NTLM_MAXIMUM 0x000002ffu
#define RDP_AUTH_REDIRECTION_CALL_INVALID 0x0000ffffu

#define RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P256 256u
#define RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384 384u
#define RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P521 521u
#define RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH 24u
#define RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH 16u
#define RDP_AUTH_REDIRECTION_BLOB_MAX_LENGTH 16777216u
#define RDP_AUTH_REDIRECTION_ASN1_PDU_IGNORED 0u
#define RDP_AUTH_REDIRECTION_ASN1_PDU_COMPAT_AS_REP 69u
#define RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP 70u
#define RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP 71u
#define RDP_AUTH_REDIRECTION_MESSAGE_RAW 0u
#define RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION 1u
#define RDP_AUTH_REDIRECTION_MESSAGE_ECDH_KEY_AGREEMENT 2u
#define RDP_AUTH_REDIRECTION_MESSAGE_DH_KEY_AGREEMENT 3u
#define RDP_AUTH_REDIRECTION_MESSAGE_KEY_AGREEMENT_HANDLE 4u
#define RDP_AUTH_REDIRECTION_MESSAGE_FINALIZE_KEY_AGREEMENT 5u
#define RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE 6u
#define RDP_AUTH_REDIRECTION_MESSAGE_COMPARE_CREDENTIALS 7u
#define RDP_AUTH_REDIRECTION_MESSAGE_ASN1_RESPONSE 8u
#define RDP_AUTH_REDIRECTION_MESSAGE_OCTET_RESPONSE 9u
#define RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN 0u
#define RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS 1u
#define RDP_AUTH_REDIRECTION_PACKAGE_NTLM 2u

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

typedef struct rdp_auth_redirection_encoded_payload
{
    uint32_t package;
    const uint8_t* package_name;
    size_t package_name_len;
    const uint8_t* payload;
    size_t payload_len;
} rdp_auth_redirection_encoded_payload;

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

typedef struct rdp_auth_redirection_ecdh_key_agreement_call
{
    uint32_t key_bits;
} rdp_auth_redirection_ecdh_key_agreement_call;

typedef struct rdp_auth_redirection_dh_key_agreement_call
{
    uint8_t ignored;
} rdp_auth_redirection_dh_key_agreement_call;

typedef struct rdp_auth_redirection_key_agreement_handle_call
{
    int64_t handle;
} rdp_auth_redirection_key_agreement_handle_call;

typedef struct rdp_auth_redirection_fixed_response
{
    rdp_auth_redirection_response response;
    const uint8_t* data;
    size_t data_len;
} rdp_auth_redirection_fixed_response;

typedef struct rdp_auth_redirection_compare_credentials_result
{
    uint32_t nt_equal;
    uint32_t lm_equal;
    uint32_t sha_equal;
} rdp_auth_redirection_compare_credentials_result;

typedef struct rdp_auth_redirection_octet_string
{
    uint32_t length;
    const uint8_t* value;
} rdp_auth_redirection_octet_string;

typedef struct rdp_auth_redirection_asn1_data
{
    uint32_t pdu;
    uint32_t length;
    const uint8_t* value;
} rdp_auth_redirection_asn1_data;

typedef struct rdp_auth_redirection_finalize_key_agreement_call
{
    int64_t handle;
    uint32_t kerb_etype;
    uint32_t remote_nonce_len;
    const uint8_t* remote_nonce;
    uint32_t x509_public_key_len;
    const uint8_t* x509_public_key;
} rdp_auth_redirection_finalize_key_agreement_call;

typedef struct rdp_auth_redirection_call_message
{
    uint32_t kind;
    rdp_auth_redirection_call call;
    union
    {
        rdp_auth_redirection_negotiate_version negotiate_version;
        rdp_auth_redirection_ecdh_key_agreement_call ecdh;
        rdp_auth_redirection_dh_key_agreement_call dh;
        rdp_auth_redirection_key_agreement_handle_call key_handle;
        rdp_auth_redirection_finalize_key_agreement_call finalize_key_agreement;
    } body;
} rdp_auth_redirection_call_message;

typedef struct rdp_auth_redirection_response_message
{
    uint32_t kind;
    rdp_auth_redirection_response response;
    union
    {
        rdp_auth_redirection_negotiate_version negotiate_version;
        rdp_auth_redirection_fixed_response fixed;
        rdp_auth_redirection_compare_credentials_result compare_credentials;
        rdp_auth_redirection_asn1_data asn1;
        rdp_auth_redirection_octet_string octet;
    } body;
} rdp_auth_redirection_response_message;

int rdp_auth_redirection_call_id_valid(uint32_t call_id);
int rdp_auth_redirection_kerb_call_id_valid(uint32_t call_id);
int rdp_auth_redirection_ntlm_call_id_valid(uint32_t call_id);
int rdp_auth_redirection_negotiate_call_id_valid(uint32_t call_id);
int rdp_auth_redirection_ecdh_key_bits_valid(uint32_t key_bits);
int rdp_auth_redirection_asn1_pdu_valid(uint32_t pdu);
librdp_status rdp_auth_redirection_parse_octet_string(
    const void* data,
    size_t length,
    rdp_auth_redirection_octet_string* string);
librdp_status rdp_auth_redirection_write_octet_string(
    rdp_buffer* buffer,
    const void* value,
    uint32_t length);
librdp_status rdp_auth_redirection_parse_octet_response(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_octet_string* string);
librdp_status rdp_auth_redirection_write_octet_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    const void* value,
    uint32_t length);
librdp_status rdp_auth_redirection_parse_asn1_data(
    const void* data,
    size_t length,
    rdp_auth_redirection_asn1_data* asn1);
librdp_status rdp_auth_redirection_write_asn1_data(
    rdp_buffer* buffer,
    uint32_t pdu,
    const void* value,
    uint32_t length);
librdp_status rdp_auth_redirection_parse_asn1_response(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_asn1_data* asn1);
librdp_status rdp_auth_redirection_write_asn1_response(
    rdp_buffer* buffer,
    uint32_t call_id,
    uint32_t status,
    uint32_t pdu,
    const void* value,
    uint32_t length);
librdp_status rdp_auth_redirection_parse_outer_packet(
    const void* data,
    size_t length,
    rdp_auth_redirection_outer_packet* packet);
librdp_status rdp_auth_redirection_write_outer_packet(
    rdp_buffer* buffer,
    const void* payload,
    size_t payload_len);
librdp_status rdp_auth_redirection_parse_encoded_payload(
    const void* data,
    size_t length,
    rdp_auth_redirection_encoded_payload* payload);
librdp_status rdp_auth_redirection_write_encoded_payload(
    rdp_buffer* buffer,
    uint32_t package,
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
librdp_status rdp_auth_redirection_parse_call_message(
    const void* data,
    size_t length,
    rdp_auth_redirection_call_message* message);
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
librdp_status rdp_auth_redirection_parse_response_message(
    const void* data,
    size_t length,
    rdp_auth_redirection_response_message* message);
librdp_status rdp_auth_redirection_write_default_response(
    rdp_buffer* buffer,
    const rdp_auth_redirection_call_message* call,
    uint32_t status);
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
librdp_status rdp_auth_redirection_parse_ecdh_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_ecdh_key_agreement_call* call);
librdp_status rdp_auth_redirection_write_ecdh_key_agreement_call(
    rdp_buffer* buffer,
    uint32_t key_bits);
librdp_status rdp_auth_redirection_parse_dh_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_dh_key_agreement_call* call);
librdp_status rdp_auth_redirection_write_dh_key_agreement_call(
    rdp_buffer* buffer,
    uint8_t ignored);
librdp_status rdp_auth_redirection_parse_key_agreement_handle_call(
    const void* data,
    size_t length,
    uint32_t expected_call_id,
    rdp_auth_redirection_key_agreement_handle_call* call);
librdp_status rdp_auth_redirection_write_key_agreement_handle_call(
    rdp_buffer* buffer,
    uint32_t call_id,
    int64_t handle);
librdp_status rdp_auth_redirection_parse_finalize_key_agreement_call(
    const void* data,
    size_t length,
    rdp_auth_redirection_finalize_key_agreement_call* call);
librdp_status rdp_auth_redirection_write_finalize_key_agreement_call(
    rdp_buffer* buffer,
    int64_t handle,
    uint32_t kerb_etype,
    const void* remote_nonce,
    uint32_t remote_nonce_len,
    const void* x509_public_key,
    uint32_t x509_public_key_len);
librdp_status rdp_auth_redirection_parse_nt_response_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_fixed_response* fixed);
librdp_status rdp_auth_redirection_parse_user_session_key_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_fixed_response* fixed);
librdp_status rdp_auth_redirection_parse_compare_credentials_response(
    const void* data,
    size_t length,
    rdp_auth_redirection_response* response,
    rdp_auth_redirection_compare_credentials_result* result);
librdp_status rdp_auth_redirection_write_compare_credentials_response(
    rdp_buffer* buffer,
    uint32_t status,
    const rdp_auth_redirection_compare_credentials_result* result);

#endif
