/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: standard security, client information, certificate, licensing, and protected PDU conformance vectors.
 * Bug classes: downgrade policy, signature mismatch, key updates, certificate bounds, and licensing state.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "common/buffer.h"
#include "licensing/licensing.h"
#include "protocol/fastpath.h"
#include "protocol/mcs.h"
#include "protocol/x224.h"
#include "security/security.h"

#include <librdp/session.h>

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}
static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}
static librdp_status test_append_zeroes(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeroes[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    while (count > 0)
    {
        size_t chunk = count > sizeof(zeroes) ? sizeof(zeroes) : count;
        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}
/*
 * Fixture: creates encrypted fast-path output packets with legacy or salted
 * signatures. It catches integrity regressions where altered ciphertext,
 * signatures, or sequence counters are accepted by the unwrap path.
 */
static int test_build_encrypted_fastpath(rdp_buffer* out,
                                         rdp_standard_security_context* sender,
                                         uint8_t security_flags,
                                         const uint8_t* plaintext,
                                         size_t plaintext_len)
{
    rdp_buffer encrypted;
    uint8_t signature[8];
    librdp_status status = LIBRDP_STATUS_OK;
    int ok = 0;

    if (!out || !sender || (!plaintext && plaintext_len > 0) ||
        (security_flags & RDP_FASTPATH_OUTPUT_ENCRYPTED) == 0)
        return 0;

    rdp_buffer_init(&encrypted);
    if ((security_flags & RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM) != 0)
        status = rdp_security_salted_mac_signature(sender, plaintext, plaintext_len, sender->decrypt_count, signature);
    else
        status = rdp_security_mac_signature(sender, plaintext, plaintext_len, signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&encrypted, plaintext, plaintext_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_payload(sender, encrypted.data, encrypted.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_header(out,
                                           RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                           security_flags,
                                           encrypted.length + sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(out, encrypted.data, encrypted.length);
    ok = status == LIBRDP_STATUS_OK;
    rdp_buffer_free(&encrypted);
    return ok;
}

/*
 * Runs standard security, client information, certificate, licensing, and protected PDU conformance vectors.
 */
int test_protocol_security_vectors(void)
{
    const uint8_t license[] = {
        0xff, 0x03, 0x12, 0x00,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 2, 0,
        9, 8
    };
    const uint8_t license_company[] = {'C', 0, 0, 0};
    const uint8_t license_product[] = {'A', 0, '0', 0, '2', 0, 0, 0};
    const uint8_t license_scope[] = {'s', 'c', 'o', 'p', 'e', 0};
    const uint8_t license_cal[] = {'c', 'a', 'l'};
    const uint8_t license_requested_id[] = {'R', 'D', 'S', 0};
    const uint8_t license_adjusted_id[] = {'R', 'D', 'S', '-', 'A', 0};
    const uint8_t license_issuer_name[] = {'L', 0, 'S', 0, 0, 0};
    const uint8_t license_issuer_id[] = {'I', 0, 'D', 0, 0, 0};
    const uint8_t license_issuer_scope[] = {'D', 0, 0, 0};
    const uint8_t encrypted_random[] = {1, 2, 3, 4, 5};
    const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t x509_der[] = {
        0x30, 0x82, 0x02, 0x08, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x2b, 0x77, 0x94, 0x65, 0x7e, 0xcb, 0xa0, 0x19, 0xd9,
        0xec, 0x74, 0x9b, 0x9a, 0xd1, 0xd1, 0x83, 0x77, 0x7f, 0x9e, 0x5a, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0b, 0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x30, 0x37,
        0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x37, 0x30, 0x38, 0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x6c,
        0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xb8, 0x2d, 0xf1, 0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6,
        0x99, 0xf8, 0x74, 0x2e, 0xc3, 0x89, 0xab, 0x17, 0x5c, 0xb6, 0xd2, 0x7f,
        0xbd, 0x88, 0x48, 0x3f, 0x16, 0x3f, 0x94, 0x9d, 0x6a, 0xd1, 0x38, 0x5b,
        0xe8, 0x53, 0xb4, 0x1c, 0x61, 0x80, 0xef, 0xa9, 0x8c, 0xf7, 0xeb, 0x01,
        0xad, 0x87, 0xc8, 0x70, 0x55, 0x98, 0x64, 0xce, 0x24, 0x07, 0x09, 0x59,
        0x4e, 0xdf, 0x44, 0x2c, 0x4c, 0xe4, 0x44, 0xb4, 0xb1, 0x10, 0x75, 0x0e,
        0x1e, 0x38, 0xda, 0x26, 0xf4, 0x9e, 0xef, 0xec, 0x15, 0xaa, 0x2f, 0x26,
        0x35, 0xb0, 0x17, 0x9d, 0x34, 0x7e, 0x58, 0xa0, 0xeb, 0x22, 0xb3, 0xf0,
        0xff, 0x1c, 0x87, 0x7f, 0xb0, 0xf4, 0xd4, 0x3c, 0x3d, 0x59, 0xe0, 0x10,
        0x77, 0x46, 0x94, 0xa5, 0x90, 0xcf, 0x1d, 0x2c, 0xf0, 0xd7, 0x44, 0x8f,
        0x9e, 0xaa, 0x60, 0x0b, 0x16, 0x6d, 0x79, 0x5c, 0xe4, 0xdd, 0xcd, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f,
        0xc0, 0x07, 0x93, 0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd,
        0x00, 0xc8, 0x15, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f, 0xc0, 0x07, 0x93,
        0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd, 0x00, 0xc8, 0x15,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x70, 0x99, 0xde, 0x9e, 0x51, 0xf6, 0x5a, 0x1d, 0x33, 0xab, 0xf4, 0x7b,
        0x4a, 0xa5, 0x9f, 0xf2, 0xda, 0x3a, 0xe3, 0x4d, 0x66, 0xb6, 0xfe, 0x68,
        0x44, 0x29, 0xb3, 0xe4, 0x8d, 0x8e, 0xef, 0xb4, 0x0e, 0xfc, 0xae, 0x74,
        0xb3, 0x2a, 0xf9, 0x90, 0x0c, 0x0c, 0xd6, 0xb1, 0x12, 0x6c, 0x7e, 0x6a,
        0x34, 0xb5, 0xe7, 0xc8, 0xb0, 0xee, 0x56, 0xb8, 0x02, 0xab, 0xf3, 0xe2,
        0x5e, 0xd6, 0xca, 0x4f, 0xa6, 0x3d, 0x10, 0xb1, 0x49, 0x32, 0x75, 0x07,
        0x00, 0x54, 0xa7, 0x9e, 0x65, 0xd0, 0xc4, 0x2b, 0xc4, 0xad, 0xc7, 0x3a,
        0xb9, 0xe5, 0x44, 0xdf, 0xed, 0xb8, 0x91, 0xea, 0xcc, 0x23, 0x16, 0xd3,
        0xa6, 0x23, 0x83, 0x62, 0x2d, 0x4e, 0xe4, 0x1c, 0xb8, 0x6c, 0x75, 0x61,
        0xde, 0xe6, 0x0e, 0xc8, 0xd5, 0x25, 0xc7, 0x69, 0x5a, 0xba, 0x06, 0xa3,
        0x30, 0xdb, 0xdf, 0xd2, 0xd8, 0xdc, 0xa0, 0x3f
    };
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    rdp_fastpath_update_list fast_updates;
    int fastpath_used_decoded = 0;
    rdp_license_error_alert alert;
    rdp_license_preamble license_preamble;
    rdp_license_binary_blob license_blob;
    rdp_license_binary_blob license_bad_blob;
    rdp_license_server_request license_request;
    rdp_license_platform_challenge license_challenge;
    rdp_license_new_or_upgrade license_new;
    rdp_license_new_license_info license_info;
    rdp_license_product_certificate_info license_cert_info;
    rdp_license_product_certificate_info parsed_license_cert_info;
    rdp_license_server_info license_server_info;
    rdp_license_server_info parsed_license_server_info;
    rdp_license_hardware_id hardware_id;
    rdp_license_hardware_id parsed_hardware_id;
    rdp_license_platform_challenge_response_data challenge_response_data;
    rdp_license_platform_challenge_response_data parsed_challenge_response_data;
    rdp_license_client_new_license_request client_license_request;
    rdp_license_client_info client_license_info;
    rdp_license_platform_challenge_response client_challenge_response;
    rdp_license_client_state license_state;
    uint8_t license_message_type = 0;
    librdp_status standard_security_status;
    rdp_security_public_key public_key;
    rdp_standard_security_context secure_a;
    rdp_standard_security_context secure_b;
    EVP_PKEY* generated_server_key = NULL;
    rdp_buffer security;
    rdp_buffer send_data;
    rdp_buffer encrypted;
    rdp_buffer encrypted_info;
    rdp_buffer plain_info_body;
    rdp_buffer expected_cipher;
    rdp_buffer protected_pdu;
    rdp_buffer unwrapped_pdu;
    rdp_buffer plain_security;
    rdp_buffer encrypted_fastpath;
    rdp_buffer decoded_fastpath;
    rdp_buffer x509_chain;
    rdp_buffer generated_server_certificate;
    rdp_buffer license_packet;
    rdp_buffer license_payload;
    rdp_client_info info;
    rdp_client_info no_password_info;
    rdp_client_info_summary info_summary;
    uint16_t security_flags = 0;
    uint8_t signature[8];
    uint8_t decrypted_client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t standard_work1[16];
    uint8_t standard_work2[8];
    uint8_t standard_update_work[4];
    size_t i = 0;
    const uint8_t orders_update_payload[] = {0, 0, 0, 0};
    const uint8_t fastpath_sync_payload[] = {RDP_FASTPATH_UPDATE_SYNCHRONIZE, 0, 0};
    const uint8_t standard_plain1[] = {
        0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40,
        0x55, 0xaa, 0xff, 0x7e, 0x80, 0x90, 0xfe, 0xdc
    };
    const uint8_t standard_plain2[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
    const uint8_t standard_update_plain[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t standard_cipher1[] = {
        0x06, 0x5b, 0xef, 0xa9, 0x84, 0xe0, 0xbb, 0x46,
        0x51, 0x7f, 0xa7, 0xf4, 0xff, 0x0c, 0xb1, 0x12
    };
    const uint8_t standard_cipher2[] = {0x68, 0xec, 0x7e, 0xa5, 0xf2, 0x04, 0xad, 0x55};
    const uint8_t standard_update_cipher[] = {0xc6, 0x08, 0x84, 0xfe};

    rdp_buffer_init(&security);
    rdp_buffer_init(&send_data);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&encrypted_info);
    rdp_buffer_init(&plain_info_body);
    rdp_buffer_init(&expected_cipher);
    rdp_buffer_init(&protected_pdu);
    rdp_buffer_init(&unwrapped_pdu);
    rdp_buffer_init(&plain_security);
    rdp_buffer_init(&encrypted_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    rdp_buffer_init(&x509_chain);
    rdp_buffer_init(&generated_server_certificate);
    rdp_buffer_init(&license_packet);
    rdp_buffer_init(&license_payload);

    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_STANDARD) == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_TLS) == RDP_X224_PROTOCOL_TLS);
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_NLA));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_NLA));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, true, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO, false, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, false, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, true, RDP_X224_PROTOCOL_STANDARD));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_TLS, true, RDP_X224_PROTOCOL_NLA));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_NLA, true, RDP_X224_PROTOCOL_TLS));
    PCHECK(!rdp_security_protocol_allowed(LIBRDP_SECURITY_TLS, true, 0x80000000u));

    memset(&info, 0, sizeof(info));
    info.domain = "D";
    info.username = "user";
    info.password = "secret";
    PCHECK(rdp_security_write_client_info_pdu(&security, &info) == LIBRDP_STATUS_OK);
    PCHECK(security.length > 200u);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.domain_bytes == 2);
    PCHECK(info_summary.username_bytes == 8);
    PCHECK(info_summary.password_bytes == 12);
    PCHECK((info_summary.flags & 0x00000010u) != 0);
    PCHECK((info_summary.flags & 0x00000008u) != 0);
    security.length = 0;
    no_password_info = info;
    no_password_info.password = NULL;
    PCHECK(rdp_security_write_client_info_pdu(&security, &no_password_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.password_bytes == 0);
    PCHECK((info_summary.flags & 0x00000008u) == 0);
    for (i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(i + 1u);
        server_random[i] = (uint8_t)(0xa0u + i);
    }
    standard_security_status = rdp_security_standard_client_init(&secure_a,
                                                                 RDP_SECURITY_METHOD_128BIT,
                                                                 client_random,
                                                                 server_random);
    if (standard_security_status == LIBRDP_STATUS_OK)
    {
    PCHECK(secure_a.key_len == 16);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    memcpy(standard_work1, standard_plain1, sizeof(standard_work1));
    memcpy(standard_work2, standard_plain2, sizeof(standard_work2));
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_work1, sizeof(standard_work1)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_work2, sizeof(standard_work2)) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(standard_work1, standard_cipher1, sizeof(standard_cipher1)) == 0);
    PCHECK(memcmp(standard_work2, standard_cipher2, sizeof(standard_cipher2)) == 0);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    memcpy(standard_update_work, standard_update_plain, sizeof(standard_update_work));
    secure_a.encrypt_count = 4096;
    PCHECK(rdp_security_encrypt_payload(&secure_a, standard_update_work, sizeof(standard_update_work)) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(standard_update_work, standard_update_cipher, sizeof(standard_update_cipher)) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_client_info_body(&plain_info_body, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_mac_signature(&secure_b, plain_info_body.data, plain_info_body.length, signature) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_client_info_pdu(&encrypted_info, &secure_a, &info) == LIBRDP_STATUS_OK);
    PCHECK(encrypted_info.length == plain_info_body.length + 12u);
    PCHECK(encrypted_info.data[0] == (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(memcmp(encrypted_info.data + 4, signature, sizeof(signature)) == 0);
    PCHECK(memcmp(encrypted_info.data + 12, plain_info_body.data, plain_info_body.length) != 0);
    PCHECK(rdp_buffer_append(&expected_cipher, plain_info_body.data, plain_info_body.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(encrypted_info.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_server_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    unwrapped_pdu.length = 0;
    security_flags = 0;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   encrypted_info.data,
                                   encrypted_info.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK(security_flags == (RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(unwrapped_pdu.length == plain_info_body.length);
    PCHECK(memcmp(unwrapped_pdu.data, plain_info_body.data, plain_info_body.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_pdu(&protected_pdu,
                                            &secure_a,
                                            0,
                                            orders_update_payload,
                                            sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(protected_pdu.length == sizeof(orders_update_payload) + 12u);
    PCHECK((test_read_u16_le(protected_pdu.data) & RDP_SEC_ENCRYPT) != 0);
    expected_cipher.length = 0;
    PCHECK(rdp_buffer_append(&expected_cipher, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(protected_pdu.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK((security_flags & RDP_SEC_ENCRYPT) != 0);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    protected_pdu.data[4] ^= 0x80u;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    protected_pdu.data[protected_pdu.length - 1u] ^= 0x40u;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_salted_mac_signature(&secure_a,
                                             orders_update_payload,
                                             sizeof(orders_update_payload),
                                             secure_a.decrypt_count,
                                             signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT | RDP_SEC_SECURE_CHECKSUM) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK((security_flags & RDP_SEC_SECURE_CHECKSUM) != 0);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_salted_mac_signature(&secure_a,
                                             orders_update_payload,
                                             sizeof(orders_update_payload),
                                             secure_a.decrypt_count,
                                             signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT | RDP_SEC_SECURE_CHECKSUM) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    secure_b.decrypt_count = 1;
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(unwrapped_pdu.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 0;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_OK);
    PCHECK(fastpath_used_decoded == 1);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data, decoded_fastpath.length, &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 &&
           fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    encrypted_fastpath.data[3] ^= 0x20u;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    encrypted_fastpath.data[encrypted_fastpath.length - 1u] ^= 0x08u;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    encrypted_fastpath.length = 0;
    decoded_fastpath.length = 0;
    fastpath_used_decoded = 1;
    PCHECK(test_build_encrypted_fastpath(&encrypted_fastpath,
                                         &secure_a,
                                         RDP_FASTPATH_OUTPUT_ENCRYPTED | RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM,
                                         fastpath_sync_payload,
                                         sizeof(fastpath_sync_payload)));
    secure_b.decrypt_count = 1;
    PCHECK(rdp_fastpath_unwrap_security(&secure_b,
                                        1,
                                        encrypted_fastpath.data,
                                        encrypted_fastpath.length,
                                        &decoded_fastpath,
                                        &fastpath_used_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(fastpath_used_decoded == 0 && decoded_fastpath.length == 0);

    PCHECK(rdp_security_write_header(&plain_security, RDP_SEC_LICENSE_PKT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&plain_security, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    security_flags = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_unwrap_pdu(NULL,
                                   plain_security.data,
                                   plain_security.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK(security_flags == RDP_SEC_LICENSE_PKT);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_40BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1 && secure_a.sign_key[2] == 0x9e);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_56BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1);
    rdp_security_standard_clear(&secure_a);
    }
    else
    {
        PCHECK(standard_security_status == LIBRDP_STATUS_UNSUPPORTED);
    }
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_FIPS,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_security_write_send_data_request(&send_data, 1004, RDP_MCS_GLOBAL_CHANNEL_ID, security.data,
                                                security.length) == LIBRDP_STATUS_OK);
    PCHECK(send_data.length > security.length);
    PCHECK(send_data.data[0] == 0x64);
    PCHECK(send_data.data[1] == 0x00 && send_data.data[2] == 0x03);
    PCHECK(send_data.data[3] == 0x03 && send_data.data[4] == 0xeb);
    rdp_buffer_free(&security);
    rdp_buffer_init(&security);
    PCHECK(rdp_security_write_exchange_pdu(&security, encrypted_random, sizeof(encrypted_random)) ==
           LIBRDP_STATUS_OK);
    PCHECK(security.length == sizeof(encrypted_random) + 16u);
    PCHECK(test_read_u16_le(security.data) == (RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    PCHECK(security.data[4] == (uint8_t)(sizeof(encrypted_random) + 8u));
    memset(client_random, 0x4a, sizeof(client_random));
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate), &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(public_key.modulus_le[0] == 0xeb && public_key.modulus_le[127] == 0xb2);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(memcmp(encrypted.data, client_random, sizeof(client_random)) != 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);
    security.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 6) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 284) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 0x31415352u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 264) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 2048) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 255) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 65537) == LIBRDP_STATUS_OK);
    for (i = 0; i < 256u; i++)
        PCHECK(rdp_buffer_append_u8(&security, (uint8_t)(1u + (i & 0x7fu))) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u; i++)
        PCHECK(rdp_buffer_append_u8(&security, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(security.data, security.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 2048u && public_key.modulus_len == 256u);
    PCHECK(public_key.modulus_le[0] == 1 && public_key.modulus_le[255] == 128);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, (uint32_t)sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&x509_chain, x509_der, sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate) - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(client_random, 0x7c, sizeof(client_random));
    memset(decrypted_client_random, 0, sizeof(decrypted_client_random));
    encrypted.length = 0;
    PCHECK(rdp_security_generate_server_certificate(&generated_server_key, &generated_server_certificate) ==
           LIBRDP_STATUS_OK);
    PCHECK(generated_server_key != NULL && generated_server_certificate.length > 64u);
    PCHECK(test_read_u32_le(generated_server_certificate.data) == 1u);
    PCHECK(test_read_u16_le(generated_server_certificate.data + 12u) == 6u);
    PCHECK(test_read_u32_le(generated_server_certificate.data + 16u) == 0x31415352u);
    PCHECK(test_read_u32_le(generated_server_certificate.data + 28u) ==
           test_read_u32_le(generated_server_certificate.data + 20u) - 9u);
    PCHECK(generated_server_certificate.length >=
           40u + test_read_u32_le(generated_server_certificate.data + 20u));
    PCHECK(test_read_u16_le(generated_server_certificate.data + 36u +
                            test_read_u32_le(generated_server_certificate.data + 20u)) == 8u);
    PCHECK(test_read_u16_le(generated_server_certificate.data + 38u +
                            test_read_u32_le(generated_server_certificate.data + 20u)) == 72u);
    PCHECK(rdp_security_parse_server_certificate(generated_server_certificate.data,
                                                 generated_server_certificate.length,
                                                 &public_key) == LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.modulus_len >= 256u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(rdp_security_decrypt_private_secret(generated_server_key,
                                               encrypted.data,
                                               encrypted.length,
                                               decrypted_client_random,
                                               sizeof(decrypted_client_random)) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(decrypted_client_random, client_random, sizeof(client_random)) == 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);

    PCHECK(rdp_license_parse_error_alert(license, sizeof(license), &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 1 && alert.state_transition == 2 && alert.blob_length == 2 && alert.blob[1] == 8);
    {
        rdp_license_error_alert valid_alert = alert;

        PCHECK(rdp_license_parse_error_alert(license, 15, &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&alert, &valid_alert, sizeof(alert)) == 0);
    }
    PCHECK(rdp_license_parse_preamble(license, sizeof(license), &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_preamble.payload_len == 14u);
    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         7,
                                         8,
                                         RDP_LICENSE_BLOB_DATA,
                                         "ok",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data, license_packet.length, &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 7 && alert.state_transition == 8 &&
           alert.blob_type == RDP_LICENSE_BLOB_DATA && alert.blob_length == 2);
    PCHECK(!rdp_license_error_alert_is_terminal_success(&alert));
    {
        rdp_license_error_alert valid_alert = alert;
        rdp_license_preamble valid_license_preamble = license_preamble;

        PCHECK(rdp_buffer_append_u8(&license_packet, 0x7f) == LIBRDP_STATUS_OK);
        PCHECK(rdp_license_parse_preamble(license_packet.data,
                                          license_packet.length,
                                          &license_preamble) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_preamble,
                      &valid_license_preamble,
                      sizeof(license_preamble)) == 0);
        license_packet.data[2] = (uint8_t)license_packet.length;
        license_packet.data[3] = 0;
        PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                             license_packet.length,
                                             &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&alert, &valid_alert, sizeof(alert)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_ERROR_STATUS_VALID_CLIENT,
                                         RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION,
                                         RDP_LICENSE_BLOB_ERROR,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                         license_packet.length,
                                         &alert) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_error_alert_is_terminal_success(&alert));
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED &&
           license_state.last_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_state.last_direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_packet,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_binary_blob(license_packet.data,
                                         license_packet.length,
                                         &license_blob) == LIBRDP_STATUS_OK);
    PCHECK(license_blob.type == RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG &&
           license_blob.length == 4 &&
           license_blob.data[0] == 1);
    {
        rdp_license_binary_blob valid_license_blob = license_blob;

        PCHECK(rdp_license_parse_binary_blob(license_packet.data,
                                             license_packet.length - 1u,
                                             &license_blob) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_blob, &valid_license_blob, sizeof(license_blob)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      0x00u,
                                      RDP_LICENSE_VERSION_3,
                                      0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    PCHECK(rdp_license_write_binary_blob(&license_packet,
                                         0xffffu,
                                         NULL,
                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    PCHECK(rdp_license_write_hardware_id(&license_packet, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(test_append_zeroes(&license_payload, 32u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0x00060002u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_CERTIFICATE,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_SCOPE,
                                         license_scope,
                                         (uint16_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_REQUEST,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_request(license_packet.data,
                                            license_packet.length,
                                            &license_request) == LIBRDP_STATUS_OK);
    PCHECK(license_request.product_info.version == 0x00060002u &&
           license_request.key_exchange_list.length == 4 &&
           license_request.scope_list.count == 1 &&
           license_request.scope_list.scopes[0].length == sizeof(license_scope));
    {
        rdp_license_server_request valid_license_request = license_request;

        PCHECK(rdp_license_parse_server_request(license_packet.data,
                                                license_packet.length - 1u,
                                                &license_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_request,
                      &valid_license_request,
                      sizeof(license_request)) == 0);
    }
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_classify_message(license_packet.data,
                                        license_packet.length,
                                        &license_message_type) == LIBRDP_STATUS_OK);
    PCHECK(license_message_type == RDP_LICENSE_MESSAGE_REQUEST);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         license_message_type) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_SERVER_REQUEST_RECEIVED);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\xaa\xbb",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                license_packet.length,
                                                &license_challenge) == LIBRDP_STATUS_OK);
    PCHECK(license_challenge.encrypted_challenge.length == 2 &&
           license_challenge.encrypted_challenge.data[1] == 0xbb);
    {
        rdp_license_platform_challenge valid_license_challenge = license_challenge;

        PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                    license_packet.length - 1u,
                                                    &license_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_challenge,
                      &valid_license_challenge,
                      sizeof(license_challenge)) == 0);
    }
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\x11\x22",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_NEW_LICENSE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_or_upgrade(license_packet.data,
                                            license_packet.length,
                                            &license_new) == LIBRDP_STATUS_OK);
    PCHECK(license_new.encrypted_license_info.type == RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_INFO) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_INITIAL);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RECEIVED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_UPGRADE_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    {
        rdp_license_new_or_upgrade valid_license_new = license_new;

        PCHECK(rdp_license_parse_new_or_upgrade(license_packet.data,
                                                license_packet.length - 1u,
                                                &license_new) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_new, &valid_license_new, sizeof(license_new)) == 0);
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_packet, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_scope, sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_cal, sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_license_info(license_packet.data,
                                              license_packet.length,
                                              &license_info) == LIBRDP_STATUS_OK);
    PCHECK(license_info.scope_len == sizeof(license_scope) &&
           license_info.license_info_len == sizeof(license_cal));
    {
        rdp_license_new_license_info valid_license_info = license_info;

        PCHECK(rdp_buffer_append_u8(&license_packet, 0xaau) == LIBRDP_STATUS_OK);
        PCHECK(rdp_license_parse_new_license_info(license_packet.data,
                                                  license_packet.length,
                                                  &license_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&license_info, &valid_license_info, sizeof(license_info)) == 0);
        license_packet.length--;
    }
    memset(&license_cert_info, 0, sizeof(license_cert_info));
    license_cert_info.version = 1;
    license_cert_info.license_count = 2;
    license_cert_info.platform_id = 0x03010002u;
    license_cert_info.language_id = 0x0410u;
    license_cert_info.requested_product_id = license_requested_id;
    license_cert_info.requested_product_id_len = sizeof(license_requested_id);
    license_cert_info.adjusted_product_id = license_adjusted_id;
    license_cert_info.adjusted_product_id_len = sizeof(license_adjusted_id);
    license_cert_info.version_info.major_version = 10;
    license_cert_info.version_info.minor_version = 0;
    license_cert_info.version_info.flags = RDP_LICENSE_PRODUCT_INFO_LICENSE_ENFORCED |
                                           RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE;
    license_packet.length = 0;
    PCHECK(rdp_license_write_product_certificate_info(&license_packet,
                                                      &license_cert_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                      license_packet.length,
                                                      &parsed_license_cert_info) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_license_cert_info.license_count == 2 &&
           parsed_license_cert_info.requested_product_id_len == sizeof(license_requested_id) &&
           parsed_license_cert_info.adjusted_product_id[4] == 'A' &&
           parsed_license_cert_info.version_info.major_version == 10 &&
           (parsed_license_cert_info.version_info.flags & RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE));
    {
        rdp_license_product_certificate_info valid_license_cert_info = parsed_license_cert_info;

        license_packet.data[27] = 2;
        PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                          license_packet.length,
                                                          &parsed_license_cert_info) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_cert_info,
                      &valid_license_cert_info,
                      sizeof(parsed_license_cert_info)) == 0);
    }
    license_packet.length = 0;

    memset(&license_server_info, 0, sizeof(license_server_info));
    license_server_info.issuer_name = license_issuer_name;
    license_server_info.issuer_name_len = sizeof(license_issuer_name);
    license_server_info.scope = license_issuer_scope;
    license_server_info.scope_len = sizeof(license_issuer_scope);
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_1 &&
           parsed_license_server_info.issuer_name_len == sizeof(license_issuer_name) &&
           parsed_license_server_info.scope_len == sizeof(license_issuer_scope) &&
           !parsed_license_server_info.has_issuer_id);
    {
        rdp_license_server_info valid_license_server_info = parsed_license_server_info;

        license_packet.data[6] = 0;
        PCHECK(rdp_license_parse_server_info(license_packet.data,
                                             license_packet.length,
                                             &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_server_info,
                      &valid_license_server_info,
                      sizeof(parsed_license_server_info)) == 0);
    }
    license_packet.length = 0;

    license_server_info.issuer_id = license_issuer_id;
    license_server_info.issuer_id_len = sizeof(license_issuer_id);
    license_server_info.has_issuer_id = 1;
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_2 &&
           parsed_license_server_info.has_issuer_id &&
           parsed_license_server_info.issuer_id_len == sizeof(license_issuer_id));
    {
        rdp_license_server_info valid_license_server_info = parsed_license_server_info;

        license_packet.data[10 + sizeof(license_issuer_name) - 1u] = 1;
        PCHECK(rdp_license_parse_server_info(license_packet.data,
                                             license_packet.length,
                                             &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_license_server_info,
                      &valid_license_server_info,
                      sizeof(parsed_license_server_info)) == 0);
    }
    license_packet.length = 0;

    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         9,
                                         0,
                                         RDP_LICENSE_BLOB_ERROR,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                         license_packet.length,
                                         &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.blob_type == RDP_LICENSE_BLOB_ERROR && alert.blob_length == 0);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step_error_alert(&license_state,
                                                     &alert) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_FAILED &&
           license_state.last_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_state.last_direction == RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_FAILED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    hardware_id.platform_id = 0x01020304u;
    hardware_id.data1 = 1;
    hardware_id.data2 = 2;
    hardware_id.data3 = 3;
    hardware_id.data4 = 4;
    license_packet.length = 0;
    PCHECK(rdp_license_write_hardware_id(&license_packet, &hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_hardware_id(license_packet.data,
                                         license_packet.length,
                                         &parsed_hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(parsed_hardware_id.platform_id == 0x01020304u && parsed_hardware_id.data4 == 4);
    {
        rdp_license_hardware_id valid_hardware_id = parsed_hardware_id;

        PCHECK(rdp_license_parse_hardware_id(license_packet.data,
                                             license_packet.length - 1u,
                                             &parsed_hardware_id) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_hardware_id,
                      &valid_hardware_id,
                      sizeof(parsed_hardware_id)) == 0);
    }
    challenge_response_data.version = 0x0100u;
    challenge_response_data.client_type = 0x0100u;
    challenge_response_data.license_detail_level = 3u;
    challenge_response_data.challenge_len = 2u;
    challenge_response_data.challenge = (const uint8_t*)"\x55\x66";
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response_data(&license_packet,
                                                              &challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge_response_data(license_packet.data,
                                                              license_packet.length,
                                                              &parsed_challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_challenge_response_data.challenge_len == 2 &&
           parsed_challenge_response_data.challenge[0] == 0x55);
    {
        rdp_license_platform_challenge_response_data valid_challenge_response_data =
            parsed_challenge_response_data;

        PCHECK(rdp_license_parse_platform_challenge_response_data(
                   license_packet.data,
                   license_packet.length - 1u,
                   &parsed_challenge_response_data) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&parsed_challenge_response_data,
                      &valid_challenge_response_data,
                      sizeof(parsed_challenge_response_data)) == 0);
    }
    license_blob.type = RDP_LICENSE_BLOB_RANDOM;
    license_blob.length = 2;
    license_blob.data = (const uint8_t*)"\x01\x02";
    license_request.key_exchange_list.type = RDP_LICENSE_BLOB_CLIENT_USER_NAME;
    license_request.key_exchange_list.length = 5;
    license_request.key_exchange_list.data = (const uint8_t*)"user";
    license_request.server_certificate.type = RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME;
    license_request.server_certificate.length = 5;
    license_request.server_certificate.data = (const uint8_t*)"host";
    memset(client_random, 0x5a, sizeof(client_random));
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_blob;
    license_bad_blob.type = RDP_LICENSE_BLOB_DATA;
    PCHECK(rdp_license_write_client_new_license_request(&license_packet,
                                                        RDP_LICENSE_VERSION_3,
                                                        RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                        0x03000000u,
                                                        client_random,
                                                        &license_bad_blob,
                                                        &license_request.key_exchange_list,
                                                        &license_request.server_certificate) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_new_license_request(&license_packet,
                                                        RDP_LICENSE_VERSION_3,
                                                        RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                        0x03000000u,
                                                        client_random,
                                                        &license_blob,
                                                        &license_request.key_exchange_list,
                                                        &license_request.server_certificate) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST);
    PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                        license_packet.length,
                                                        &client_license_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_license_request.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_request.platform_id == 0x03000000u &&
           client_license_request.encrypted_pre_master.length == 2 &&
           client_license_request.user_name.length == 5 &&
           client_license_request.machine_name.type == RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME);
    rdp_license_client_state_init(&license_state);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_CLIENT_REQUEST_SENT);
    {
        rdp_license_client_new_license_request valid_client_license_request =
            client_license_request;

        license_packet.data[44] = 0xff;
        PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                            license_packet.length,
                                                            &client_license_request) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_license_request,
                      &valid_client_license_request,
                      sizeof(client_license_request)) == 0);
        license_packet.data[44] = RDP_LICENSE_BLOB_RANDOM;
    }
    license_request.scope_list.scopes[0].type = RDP_LICENSE_BLOB_DATA;
    license_request.scope_list.scopes[0].length = (uint16_t)sizeof(license_cal);
    license_request.scope_list.scopes[0].data = license_cal;
    license_challenge.encrypted_challenge.type = RDP_LICENSE_BLOB_ENCRYPTED_DATA;
    license_challenge.encrypted_challenge.length = 20;
    license_challenge.encrypted_challenge.data = client_random;
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_request.scope_list.scopes[0];
    license_bad_blob.type = RDP_LICENSE_BLOB_SCOPE;
    PCHECK(rdp_license_write_client_info(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_KEY_EXCHANGE_RSA,
                                         0x03000000u,
                                         client_random,
                                         &license_blob,
                                         &license_bad_blob,
                                         &license_challenge.encrypted_challenge,
                                         client_random) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_info(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_KEY_EXCHANGE_RSA,
                                         0x03000000u,
                                         client_random,
                                         &license_blob,
                                         &license_request.scope_list.scopes[0],
                                         &license_challenge.encrypted_challenge,
                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_INFO);
    PCHECK(rdp_license_parse_client_info(license_packet.data,
                                         license_packet.length,
                                         &client_license_info) == LIBRDP_STATUS_OK);
    PCHECK(client_license_info.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_info.license_info.length == sizeof(license_cal) &&
           client_license_info.encrypted_hardware_id.length == 20 &&
           client_license_info.mac[15] == 0x5a);
    {
        rdp_license_client_info valid_client_license_info = client_license_info;

        license_packet.data[48 + license_blob.length] = 0xff;
        PCHECK(rdp_license_parse_client_info(license_packet.data,
                                             license_packet.length,
                                             &client_license_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_license_info,
                      &valid_client_license_info,
                      sizeof(client_license_info)) == 0);
        license_packet.data[48 + license_blob.length] = RDP_LICENSE_BLOB_DATA;
    }
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u8(&license_packet, 0xa5) == LIBRDP_STATUS_OK);
    license_bad_blob = license_challenge.encrypted_challenge;
    license_bad_blob.type = RDP_LICENSE_BLOB_DATA;
    PCHECK(rdp_license_write_platform_challenge_response(&license_packet,
                                                         RDP_LICENSE_VERSION_3,
                                                         &license_bad_blob,
                                                         &license_challenge.encrypted_challenge,
                                                         client_random) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(license_packet.length == 1 && license_packet.data[0] == 0xa5);
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response(&license_packet,
                                                         RDP_LICENSE_VERSION_3,
                                                         &license_challenge.encrypted_challenge,
                                                         &license_challenge.encrypted_challenge,
                                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE);
    PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                         license_packet.length,
                                                         &client_challenge_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_challenge_response.encrypted_response.length == 20 &&
           client_challenge_response.encrypted_hardware_id.length == 20 &&
           client_challenge_response.mac[0] == 0x5a);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                         RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE) ==
           LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_PLATFORM_CHALLENGE_RESPONSE_SENT);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_NEW_LICENSE) == LIBRDP_STATUS_OK);
    PCHECK(license_state.state == RDP_LICENSE_CLIENT_STATE_COMPLETED);
    PCHECK(rdp_license_client_state_step(&license_state,
                                         RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                         RDP_LICENSE_MESSAGE_ERROR_ALERT) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    {
        rdp_license_platform_challenge_response valid_client_challenge_response =
            client_challenge_response;

        license_packet.data[4] = 0;
        PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                             license_packet.length,
                                                             &client_challenge_response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&client_challenge_response,
                      &valid_client_challenge_response,
                      sizeof(client_challenge_response)) == 0);
    }
    {
        const uint8_t challenge_plain[] = {0x31, 0x32, 0x33, 0x34};
        rdp_license_crypto_context license_crypto;
        rdp_buffer encrypted_challenge;
        rdp_buffer response_plain;
        rdp_buffer hardware_plain;
        rdp_buffer response_mac_input;
        uint8_t challenge_mac[RDP_LICENSE_MAC_LEN];
        uint8_t response_mac[RDP_LICENSE_MAC_LEN];
        librdp_status license_crypto_status;

        memset(&license_crypto, 0, sizeof(license_crypto));
        rdp_buffer_init(&encrypted_challenge);
        rdp_buffer_init(&response_plain);
        rdp_buffer_init(&hardware_plain);
        rdp_buffer_init(&response_mac_input);
        license_crypto.ready = 1;
        for (i = 0; i < RDP_LICENSE_MAC_LEN; i++)
        {
            license_crypto.encryption_key[i] = (uint8_t)(0x20u + i);
            license_crypto.mac_salt_key[i] = (uint8_t)(0x80u + i);
        }
        for (i = 0; i < RDP_LICENSE_HARDWARE_ID_LEN; i++)
            license_crypto.hardware_id[i] = (uint8_t)(0xc0u + i);

        license_crypto_status = rdp_security_license_crypt(license_crypto.encryption_key,
                                                           challenge_plain,
                                                           sizeof(challenge_plain),
                                                           &encrypted_challenge);
        if (license_crypto_status == LIBRDP_STATUS_UNSUPPORTED)
        {
            PCHECK(encrypted_challenge.length == 0);
        }
        else
        {
            PCHECK(license_crypto_status == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_mac(license_crypto.mac_salt_key,
                                            challenge_plain,
                                            sizeof(challenge_plain),
                                            challenge_mac) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            license_packet.length = 0;
            PCHECK(rdp_buffer_append_u32_le(&license_payload, 0u) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_write_binary_blob(&license_payload,
                                                 RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                                 encrypted_challenge.data,
                                                 (uint16_t)encrypted_challenge.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&license_payload, challenge_mac, sizeof(challenge_mac)) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_write_preamble(&license_packet,
                                              RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                              RDP_LICENSE_VERSION_3,
                                              (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
                   LIBRDP_STATUS_OK);
            PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                        license_packet.length,
                                                        &license_challenge) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            PCHECK(rdp_license_build_platform_challenge_response(&license_crypto,
                                                                 &license_challenge,
                                                                 &license_payload) == LIBRDP_STATUS_OK);
            PCHECK(rdp_license_parse_platform_challenge_response(license_payload.data,
                                                                 license_payload.length,
                                                                 &client_challenge_response) ==
                   LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_crypt(license_crypto.encryption_key,
                                              client_challenge_response.encrypted_response.data,
                                              client_challenge_response.encrypted_response.length,
                                              &response_plain) == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_crypt(license_crypto.encryption_key,
                                              client_challenge_response.encrypted_hardware_id.data,
                                              client_challenge_response.encrypted_hardware_id.length,
                                              &hardware_plain) == LIBRDP_STATUS_OK);
            PCHECK(hardware_plain.length == RDP_LICENSE_HARDWARE_ID_LEN &&
                   memcmp(hardware_plain.data,
                          license_crypto.hardware_id,
                          RDP_LICENSE_HARDWARE_ID_LEN) == 0);
            PCHECK(rdp_license_parse_platform_challenge_response_data(
                       response_plain.data,
                       response_plain.length,
                       &parsed_challenge_response_data) == LIBRDP_STATUS_OK);
            PCHECK(parsed_challenge_response_data.version ==
                       RDP_LICENSE_PLATFORM_CHALLENGE_RESPONSE_VERSION &&
                   parsed_challenge_response_data.client_type == RDP_LICENSE_CLIENT_TYPE_OTHER &&
                   parsed_challenge_response_data.license_detail_level == RDP_LICENSE_DETAIL_LEVEL_DETAIL &&
                   parsed_challenge_response_data.challenge_len == sizeof(challenge_plain) &&
                   memcmp(parsed_challenge_response_data.challenge,
                          challenge_plain,
                          sizeof(challenge_plain)) == 0);
            PCHECK(rdp_buffer_append(&response_mac_input,
                                     response_plain.data,
                                     response_plain.length) == LIBRDP_STATUS_OK);
            PCHECK(rdp_buffer_append(&response_mac_input,
                                     license_crypto.hardware_id,
                                     RDP_LICENSE_HARDWARE_ID_LEN) == LIBRDP_STATUS_OK);
            PCHECK(rdp_security_license_mac(license_crypto.mac_salt_key,
                                            response_mac_input.data,
                                            response_mac_input.length,
                                            response_mac) == LIBRDP_STATUS_OK);
            PCHECK(memcmp(response_mac, client_challenge_response.mac, sizeof(response_mac)) == 0);
            license_packet.data[license_packet.length - 1u] ^= 0x01u;
            PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                        license_packet.length,
                                                        &license_challenge) == LIBRDP_STATUS_OK);
            license_payload.length = 0;
            PCHECK(rdp_license_build_platform_challenge_response(&license_crypto,
                                                                 &license_challenge,
                                                                 &license_payload) ==
                   LIBRDP_STATUS_PROTOCOL_ERROR);
        }
        rdp_buffer_free(&response_mac_input);
        rdp_buffer_free(&hardware_plain);
        rdp_buffer_free(&response_plain);
        rdp_buffer_free(&encrypted_challenge);
        rdp_license_crypto_context_clear(&license_crypto);
    }


    rdp_buffer_free(&license_payload);
    rdp_buffer_free(&license_packet);
    rdp_buffer_free(&x509_chain);
    rdp_buffer_free(&generated_server_certificate);
    EVP_PKEY_free(generated_server_key);
    rdp_buffer_free(&expected_cipher);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_free(&encrypted_fastpath);
    rdp_buffer_free(&plain_security);
    rdp_buffer_free(&unwrapped_pdu);
    rdp_buffer_free(&protected_pdu);
    rdp_buffer_free(&plain_info_body);
    rdp_buffer_free(&encrypted_info);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security);
    return 0;
}
