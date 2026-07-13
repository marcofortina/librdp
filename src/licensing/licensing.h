/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: licensing PDU parser and writer declaration contract.
 * Invariants: declarations preserve explicit bounds, ownership, and error
 * propagation across module boundaries.
 * Ownership: licensing state is caller-owned and transitions only after
 * validated PDUs.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_LICENSING_LICENSING_H
#define RDP_LICENSING_LICENSING_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_LICENSE_MESSAGE_REQUEST 0x01u
#define RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE 0x02u
#define RDP_LICENSE_MESSAGE_NEW_LICENSE 0x03u
#define RDP_LICENSE_MESSAGE_UPGRADE_LICENSE 0x04u
#define RDP_LICENSE_MESSAGE_INFO 0x12u
#define RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST 0x13u
#define RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE 0x15u
#define RDP_LICENSE_MESSAGE_ERROR_ALERT 0xffu

#define RDP_LICENSE_VERSION_2 0x02u
#define RDP_LICENSE_VERSION_3 0x03u
#define RDP_LICENSE_VERSION_EXTENDED_ERROR 0x80u

#define RDP_LICENSE_BLOB_DATA 0x0001u
#define RDP_LICENSE_BLOB_RANDOM 0x0002u
#define RDP_LICENSE_BLOB_CERTIFICATE 0x0003u
#define RDP_LICENSE_BLOB_ERROR 0x0004u
#define RDP_LICENSE_BLOB_ENCRYPTED_DATA 0x0009u
#define RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG 0x000du
#define RDP_LICENSE_BLOB_SCOPE 0x000eu
#define RDP_LICENSE_BLOB_CLIENT_USER_NAME 0x000fu
#define RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME 0x0010u

#define RDP_LICENSE_ERROR_STATUS_VALID_CLIENT 0x00000007u
#define RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION 0x00000002u

#define RDP_LICENSE_KEY_EXCHANGE_RSA 0x00000001u
#define RDP_LICENSE_SCOPE_MAX_COUNT 32u
#define RDP_LICENSE_PRODUCT_INFO_LICENSE_ENFORCED 0x00008000u
#define RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE 0x00800000u
#define RDP_LICENSE_PRODUCT_INFO_TEMPORARY_LICENSE 0x80000000u
#define RDP_LICENSE_SERVER_INFO_VERSION_1 0x00010000u
#define RDP_LICENSE_SERVER_INFO_VERSION_2 0x00030000u

typedef struct rdp_license_preamble
{
    uint8_t message_type;
    uint8_t version;
    uint16_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_license_preamble;

typedef struct rdp_license_binary_blob
{
    uint16_t type;
    uint16_t length;
    const uint8_t* data;
} rdp_license_binary_blob;

typedef struct rdp_license_product_info
{
    uint32_t version;
    uint32_t company_name_len;
    const uint8_t* company_name;
    uint32_t product_id_len;
    const uint8_t* product_id;
} rdp_license_product_info;

typedef struct rdp_license_scope_list
{
    uint32_t count;
    rdp_license_binary_blob scopes[RDP_LICENSE_SCOPE_MAX_COUNT];
} rdp_license_scope_list;

typedef struct rdp_license_server_request
{
    rdp_license_preamble preamble;
    uint8_t server_random[32];
    rdp_license_product_info product_info;
    rdp_license_binary_blob key_exchange_list;
    rdp_license_binary_blob server_certificate;
    rdp_license_scope_list scope_list;
} rdp_license_server_request;

typedef struct rdp_license_platform_challenge
{
    rdp_license_preamble preamble;
    uint32_t connect_flags;
    rdp_license_binary_blob encrypted_challenge;
    uint8_t mac[16];
} rdp_license_platform_challenge;

typedef struct rdp_license_new_or_upgrade
{
    rdp_license_preamble preamble;
    rdp_license_binary_blob encrypted_license_info;
    uint8_t mac[16];
} rdp_license_new_or_upgrade;

typedef struct rdp_license_new_license_info
{
    uint32_t version;
    uint32_t scope_len;
    const uint8_t* scope;
    uint32_t company_name_len;
    const uint8_t* company_name;
    uint32_t product_id_len;
    const uint8_t* product_id;
    uint32_t license_info_len;
    const uint8_t* license_info;
} rdp_license_new_license_info;

typedef struct rdp_license_version_info
{
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t flags;
} rdp_license_version_info;

typedef struct rdp_license_product_certificate_info
{
    uint32_t version;
    uint32_t license_count;
    uint32_t platform_id;
    uint32_t language_id;
    const uint8_t* requested_product_id;
    uint16_t requested_product_id_len;
    const uint8_t* adjusted_product_id;
    uint16_t adjusted_product_id_len;
    rdp_license_version_info version_info;
} rdp_license_product_certificate_info;

typedef struct rdp_license_server_info
{
    uint32_t version;
    const uint8_t* issuer_name;
    uint16_t issuer_name_len;
    const uint8_t* issuer_id;
    uint16_t issuer_id_len;
    const uint8_t* scope;
    uint16_t scope_len;
    uint8_t has_issuer_id;
} rdp_license_server_info;

typedef struct rdp_license_hardware_id
{
    uint32_t platform_id;
    uint32_t data1;
    uint32_t data2;
    uint32_t data3;
    uint32_t data4;
} rdp_license_hardware_id;

typedef struct rdp_license_platform_challenge_response_data
{
    uint16_t version;
    uint16_t client_type;
    uint16_t license_detail_level;
    uint16_t challenge_len;
    const uint8_t* challenge;
} rdp_license_platform_challenge_response_data;

typedef struct rdp_license_error_alert
{
    uint8_t message_type;
    uint8_t flags;
    uint16_t length;
    uint32_t error_code;
    uint32_t state_transition;
    uint16_t blob_type;
    uint16_t blob_length;
    const uint8_t* blob;
} rdp_license_error_alert;

typedef struct rdp_license_client_new_license_request
{
    rdp_license_preamble preamble;
    uint32_t preferred_key_exchange_alg;
    uint32_t platform_id;
    uint8_t client_random[32];
    rdp_license_binary_blob encrypted_pre_master;
    rdp_license_binary_blob user_name;
    rdp_license_binary_blob machine_name;
} rdp_license_client_new_license_request;

typedef struct rdp_license_client_info
{
    rdp_license_preamble preamble;
    uint32_t preferred_key_exchange_alg;
    uint32_t platform_id;
    uint8_t client_random[32];
    rdp_license_binary_blob encrypted_pre_master;
    rdp_license_binary_blob license_info;
    rdp_license_binary_blob encrypted_hardware_id;
    uint8_t mac[16];
} rdp_license_client_info;

typedef struct rdp_license_platform_challenge_response
{
    rdp_license_preamble preamble;
    rdp_license_binary_blob encrypted_response;
    rdp_license_binary_blob encrypted_hardware_id;
    uint8_t mac[16];
} rdp_license_platform_challenge_response;

typedef enum rdp_license_direction
{
    RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT = 0,
    RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER = 1
} rdp_license_direction;

typedef enum rdp_license_client_state_id
{
    RDP_LICENSE_CLIENT_STATE_INITIAL = 0,
    RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED = 1,
    RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT = 2,
    RDP_LICENSE_CLIENT_STATE_CLIENT_INFO_SENT = 3,
    RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED = 4,
    RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT = 5,
    RDP_LICENSE_CLIENT_STATE_COMPLETED = 6,
    RDP_LICENSE_CLIENT_STATE_FAILED = 7
} rdp_license_client_state_id;

typedef struct rdp_license_client_state
{
    rdp_license_client_state_id state;
    uint8_t last_message_type;
    uint8_t last_direction;
} rdp_license_client_state;

void rdp_license_client_state_init(rdp_license_client_state* state);
librdp_status rdp_license_classify_message(const void* data, size_t length, uint8_t* message_type);
librdp_status rdp_license_client_state_step(rdp_license_client_state* state,
                                            rdp_license_direction direction,
                                            uint8_t message_type);
librdp_status rdp_license_client_state_step_error_alert(rdp_license_client_state* state,
                                                        const rdp_license_error_alert* alert);
librdp_status rdp_license_parse_preamble(const void* data, size_t length, rdp_license_preamble* preamble);
librdp_status rdp_license_write_preamble(rdp_buffer* buffer,
                                         uint8_t message_type,
                                         uint8_t version,
                                         uint16_t payload_len);
librdp_status rdp_license_parse_binary_blob(const void* data,
                                            size_t length,
                                            rdp_license_binary_blob* blob);
librdp_status rdp_license_write_binary_blob(rdp_buffer* buffer,
                                            uint16_t type,
                                            const void* data,
                                            uint16_t length);
librdp_status rdp_license_parse_product_info(const void* data,
                                             size_t length,
                                             rdp_license_product_info* product);
librdp_status rdp_license_parse_server_request(const void* data,
                                               size_t length,
                                               rdp_license_server_request* request);
librdp_status rdp_license_parse_platform_challenge(const void* data,
                                                   size_t length,
                                                   rdp_license_platform_challenge* challenge);
librdp_status rdp_license_parse_new_or_upgrade(const void* data,
                                               size_t length,
                                               rdp_license_new_or_upgrade* license);
librdp_status rdp_license_parse_new_license_info(const void* data,
                                                 size_t length,
                                                 rdp_license_new_license_info* info);
librdp_status rdp_license_parse_product_certificate_info(
    const void* data,
    size_t length,
    rdp_license_product_certificate_info* info);
librdp_status rdp_license_write_product_certificate_info(
    rdp_buffer* buffer,
    const rdp_license_product_certificate_info* info);
librdp_status rdp_license_parse_server_info(const void* data,
                                            size_t length,
                                            rdp_license_server_info* info);
librdp_status rdp_license_write_server_info(rdp_buffer* buffer,
                                            const rdp_license_server_info* info);
librdp_status rdp_license_parse_hardware_id(const void* data,
                                            size_t length,
                                            rdp_license_hardware_id* hardware_id);
librdp_status rdp_license_write_hardware_id(rdp_buffer* buffer,
                                            const rdp_license_hardware_id* hardware_id);
librdp_status rdp_license_parse_platform_challenge_response_data(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response_data* response);
librdp_status rdp_license_write_platform_challenge_response_data(
    rdp_buffer* buffer,
    const rdp_license_platform_challenge_response_data* response);
librdp_status rdp_license_parse_error_alert(const void* data, size_t length, rdp_license_error_alert* alert);
int rdp_license_error_alert_is_terminal_success(const rdp_license_error_alert* alert);
librdp_status rdp_license_write_error_alert(rdp_buffer* buffer,
                                            uint8_t version,
                                            uint32_t error_code,
                                            uint32_t state_transition,
                                            uint16_t blob_type,
                                            const void* blob,
                                            uint16_t blob_len);
librdp_status rdp_license_parse_client_new_license_request(
    const void* data,
    size_t length,
    rdp_license_client_new_license_request* request);
librdp_status rdp_license_write_client_new_license_request(rdp_buffer* buffer,
                                                           uint8_t version,
                                                           uint32_t preferred_key_exchange_alg,
                                                           uint32_t platform_id,
                                                           const uint8_t client_random[32],
                                                           const rdp_license_binary_blob* encrypted_pre_master,
                                                           const rdp_license_binary_blob* user_name,
                                                           const rdp_license_binary_blob* machine_name);
librdp_status rdp_license_parse_client_info(const void* data,
                                            size_t length,
                                            rdp_license_client_info* info);
librdp_status rdp_license_write_client_info(rdp_buffer* buffer,
                                            uint8_t version,
                                            uint32_t preferred_key_exchange_alg,
                                            uint32_t platform_id,
                                            const uint8_t client_random[32],
                                            const rdp_license_binary_blob* encrypted_pre_master,
                                            const rdp_license_binary_blob* license_info,
                                            const rdp_license_binary_blob* encrypted_hardware_id,
                                            const uint8_t mac[16]);
librdp_status rdp_license_parse_platform_challenge_response(
    const void* data,
    size_t length,
    rdp_license_platform_challenge_response* response);
librdp_status rdp_license_write_platform_challenge_response(
    rdp_buffer* buffer,
    uint8_t version,
    const rdp_license_binary_blob* encrypted_response,
    const rdp_license_binary_blob* encrypted_hardware_id,
    const uint8_t mac[16]);

#endif
