/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for licensing PDU parser and client state machine paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "licensing/licensing.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises licensing PDU parser and client state machine paths
 * with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_license_preamble preamble;
    rdp_license_binary_blob blob;
    rdp_license_product_info product;
    rdp_license_server_request request;
    rdp_license_platform_challenge challenge;
    rdp_license_new_or_upgrade license;
    rdp_license_new_license_info info;
    rdp_license_product_certificate_info product_certificate;
    rdp_license_server_info server_info;
    rdp_license_hardware_id hardware_id;
    rdp_license_platform_challenge_response_data challenge_data;
    rdp_license_error_alert alert;
    rdp_license_client_new_license_request client_request;
    rdp_license_client_info client_info;
    rdp_license_platform_challenge_response challenge_response;
    rdp_license_client_state state;
    rdp_buffer buffer;
    rdp_license_binary_blob encrypted;
    uint8_t random[32] = {0};
    uint8_t message_type = 0;

    (void)rdp_license_parse_preamble(data, size, &preamble);
    (void)rdp_license_parse_binary_blob(data, size, &blob);
    (void)rdp_license_parse_product_info(data, size, &product);
    (void)rdp_license_parse_server_request(data, size, &request);
    (void)rdp_license_parse_platform_challenge(data, size, &challenge);
    (void)rdp_license_parse_new_or_upgrade(data, size, &license);
    (void)rdp_license_parse_new_license_info(data, size, &info);
    (void)rdp_license_parse_product_certificate_info(data, size, &product_certificate);
    (void)rdp_license_parse_server_info(data, size, &server_info);
    (void)rdp_license_parse_hardware_id(data, size, &hardware_id);
    (void)rdp_license_parse_platform_challenge_response_data(data, size, &challenge_data);
    if (rdp_license_parse_error_alert(data, size, &alert) == LIBRDP_STATUS_OK)
    {
        rdp_license_client_state_init(&state);
        (void)rdp_license_client_state_step_error_alert(&state, &alert);
    }
    (void)rdp_license_parse_client_new_license_request(data, size, &client_request);
    (void)rdp_license_parse_client_info(data, size, &client_info);
    (void)rdp_license_parse_platform_challenge_response(data, size, &challenge_response);
    if (rdp_license_classify_message(data, size, &message_type) == LIBRDP_STATUS_OK)
    {
        rdp_license_client_state_init(&state);
        (void)rdp_license_client_state_step(&state, RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT, message_type);
        (void)rdp_license_client_state_step(&state, RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER, message_type);
    }

    rdp_buffer_init(&buffer);
    (void)rdp_license_write_error_alert(&buffer,
                                        RDP_LICENSE_VERSION_3,
                                        1,
                                        2,
                                        RDP_LICENSE_BLOB_DATA,
                                        data,
                                        size > UINT16_MAX ? UINT16_MAX : (uint16_t)size);
    buffer.length = 0;
    encrypted.type = RDP_LICENSE_BLOB_ENCRYPTED_DATA;
    encrypted.length = size > 32u ? 32u : (uint16_t)size;
    encrypted.data = data;
    (void)rdp_license_write_platform_challenge_response(&buffer,
                                                        RDP_LICENSE_VERSION_3,
                                                        &encrypted,
                                                        &encrypted,
                                                        random);
    buffer.length = 0;
    product_certificate.version = 1;
    product_certificate.license_count = 1;
    product_certificate.platform_id = 0x03010000u;
    product_certificate.language_id = 0x0409u;
    product_certificate.requested_product_id = (const uint8_t*)"A";
    product_certificate.requested_product_id_len = 1;
    product_certificate.adjusted_product_id = (const uint8_t*)"B";
    product_certificate.adjusted_product_id_len = 1;
    product_certificate.version_info.major_version = 10;
    product_certificate.version_info.flags = RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE;
    (void)rdp_license_write_product_certificate_info(&buffer, &product_certificate);
    buffer.length = 0;
    server_info.issuer_name = (const uint8_t*)"\x4c\x00\x00\x00";
    server_info.issuer_name_len = 4;
    server_info.scope = (const uint8_t*)"\x44\x00\x00\x00";
    server_info.scope_len = 4;
    server_info.issuer_id = NULL;
    server_info.issuer_id_len = 0;
    server_info.has_issuer_id = 0;
    (void)rdp_license_write_server_info(&buffer, &server_info);
    rdp_buffer_free(&buffer);
    return 0;
}
