/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: CredSSP, SPNEGO, NTLM, and credential wrapping conformance vectors.
 * Bug classes: ASN.1 truncation, authentication state, integrity, replay sequence, and secret wrapping.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "common/buffer.h"
#include "nla/credssp.h"
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
static int test_sha256_three(const uint8_t* a,
                             size_t a_len,
                             const uint8_t* b,
                             size_t b_len,
                             const uint8_t* c,
                             size_t c_len,
                             uint8_t out[32])
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    unsigned int got = 0;
    int ok = 0;

    if (!context)
        return 0;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto out;
    if (EVP_DigestUpdate(context, a, a_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, b, b_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, c, c_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, out, &got) != 1 || got != 32u)
        goto out;
    ok = 1;

out:
    EVP_MD_CTX_free(context);
    return ok;
}

/*
 * Runs CredSSP, SPNEGO, NTLM, and credential wrapping conformance vectors.
 */
int test_protocol_authentication_vectors(void)
{
    const uint8_t ntlm_challenge_token[] = {
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t wrapped_ntlm_challenge[] = {
        0xa1, 0x4c, 0x30, 0x4a, 0xa2, 0x48, 0x04, 0x46,
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t ntlm_v2_target_name[] = {'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0};
    const uint8_t ntlm_v2_target_info[] = {
        0x02, 0x00, 0x0c, 0x00, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0,
        0x01, 0x00, 0x0c, 0x00, 'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0,
        0x04, 0x00, 0x14, 0x00, 'd', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0,
        '.', 0,    'c', 0,    'o', 0,    'm', 0,
        0x03, 0x00, 0x22, 0x00, 's', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0,
        '.', 0,    'd', 0,    'o', 0,    'm', 0, 'a', 0, 'i', 0, 'n', 0, '.', 0,
        'c', 0,    'o', 0,    'm', 0,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t ntlm_v2_server_challenge[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const uint8_t ntlm_v2_client_challenge[] = {0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44};
    const uint8_t ntlm_v2_session_key[] = {
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x99, 0x88
    };
    const uint8_t credssp_client_nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t credssp_public_key[] = {
        0x30, 0x13, 0x02, 0x0f, 0x00, 0xb8, 0x2d, 0xf1,
        0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6, 0x99, 0xf8,
        0x74, 0x2e, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    const uint8_t credssp_windows_logon_failure[] = {
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x6d
    };
    const uint8_t ntlm_v2_expected_lm[] = {
        0xd6, 0xe6, 0x15, 0x2e, 0xa2, 0x5d, 0x03, 0xb7,
        0xc6, 0xba, 0x66, 0x29, 0xc2, 0xd6, 0xaa, 0xf0,
        0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44
    };
    const uint8_t ntlm_v2_expected_proof[] = {
        0x29, 0x15, 0x7f, 0x79, 0xa3, 0x08, 0x93, 0x53,
        0x78, 0x3e, 0x24, 0x4f, 0xad, 0x52, 0x8a, 0x5c
    };
    const uint8_t ntlm_v2_expected_encrypted_key[] = {
        0x89, 0x7f, 0x84, 0x0c, 0x2b, 0x3c, 0xcc, 0xa4,
        0xbd, 0x38, 0x95, 0x03, 0x54, 0xe8, 0x31, 0x05
    };
    const uint8_t ntlm_expected_wrapped_data[] = {
        0x01, 0x00, 0x00, 0x00, 0x47, 0xea, 0xc4, 0xa7,
        0x26, 0xe2, 0x57, 0xb3, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x8d, 0x3d, 0x6c
    };
    librdp_status ntlm_auth_status;
    rdp_credssp_state cred_state;
    rdp_buffer ntlm_negotiate;
    rdp_buffer ntlm_challenge_written;
    rdp_buffer spnego_challenge_written;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_negotiate;
    rdp_buffer spnego_authenticate;
    rdp_buffer ntlm_wrapped;
    rdp_buffer ntlm_unwrapped;
    rdp_buffer corrupt_wrapped;
    rdp_buffer corrupt_plain;
    rdp_buffer pub_key_auth;
    rdp_buffer server_pub_key_auth;
    rdp_buffer client_sequence_pub_key_auth;
    rdp_buffer server_sequence_pub_key_auth;
    rdp_buffer client_sequence_auth_info;
    rdp_buffer ts_credentials;
    rdp_buffer auth_info;
    rdp_buffer ts_request;
    rdp_buffer nla_request;
    rdp_credssp_ts_request parsed_ts;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_challenge ntlm_v2_challenge;
    rdp_ntlm_authenticate parsed_ntlm_authenticate;
    rdp_ntlm_authenticate_result ntlm_auth_result;
    rdp_ntlm_authenticate_result server_auth_result;
    rdp_ntlm_authenticate_result failed_auth_result;
    rdp_ntlm_security_context ntlm_security;
    rdp_ntlm_security_context server_security;
    rdp_ntlm_security_context corrupt_client_security;
    rdp_ntlm_security_context corrupt_server_security;
    rdp_ntlm_security_context client_sequence_security;
    rdp_ntlm_security_context server_sequence_security;
    const uint8_t* extracted_ntlm = NULL;
    size_t extracted_ntlm_len = 0;
    uint8_t server_hash[32];
    uint16_t lm_len = 0;
    uint16_t nt_len = 0;
    uint16_t key_len = 0;
    uint32_t lm_offset = 0;
    uint32_t nt_offset = 0;
    uint32_t key_offset = 0;

    memset(&parsed_ntlm_authenticate, 0, sizeof(parsed_ntlm_authenticate));
    memset(&ntlm_auth_result, 0, sizeof(ntlm_auth_result));
    memset(&server_auth_result, 0, sizeof(server_auth_result));
    memset(&failed_auth_result, 0, sizeof(failed_auth_result));
    memset(&ntlm_security, 0, sizeof(ntlm_security));
    memset(&server_security, 0, sizeof(server_security));
    memset(&corrupt_client_security, 0, sizeof(corrupt_client_security));
    memset(&corrupt_server_security, 0, sizeof(corrupt_server_security));
    memset(&client_sequence_security, 0, sizeof(client_sequence_security));
    memset(&server_sequence_security, 0, sizeof(server_sequence_security));
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&ntlm_challenge_written);
    rdp_buffer_init(&spnego_challenge_written);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&ntlm_wrapped);
    rdp_buffer_init(&ntlm_unwrapped);
    rdp_buffer_init(&corrupt_wrapped);
    rdp_buffer_init(&corrupt_plain);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&server_pub_key_auth);
    rdp_buffer_init(&client_sequence_pub_key_auth);
    rdp_buffer_init(&server_sequence_pub_key_auth);
    rdp_buffer_init(&client_sequence_auth_info);
    rdp_buffer_init(&ts_credentials);
    rdp_buffer_init(&auth_info);
    rdp_buffer_init(&ts_request);
    rdp_buffer_init(&nla_request);

    PCHECK(rdp_credssp_begin(false, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_DISABLED);
    PCHECK(rdp_credssp_begin(true, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_NEGOTIATING);
    PCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(ntlm_negotiate.length == 47);
    PCHECK(memcmp(ntlm_negotiate.data, "NTLMSSP", 7) == 0);
    PCHECK(ntlm_negotiate.data[8] == 1 && ntlm_negotiate.data[16] == 3 && ntlm_negotiate.data[24] == 4);
    PCHECK(memcmp(ntlm_negotiate.data + 40, "DOMHOST", 7) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_negotiate.length > ntlm_negotiate.length && spnego_negotiate.data[0] == 0x60);
    PCHECK(rdp_credssp_write_ts_request(&ts_request,
                                        6,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        credssp_client_nonce,
                                        sizeof(credssp_client_nonce)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len == spnego_negotiate.length);
    PCHECK(memcmp(parsed_ts.nego_token, spnego_negotiate.data, spnego_negotiate.length) == 0);
    PCHECK(parsed_ts.client_nonce_len == sizeof(credssp_client_nonce));
    PCHECK(memcmp(parsed_ts.client_nonce, credssp_client_nonce, sizeof(credssp_client_nonce)) == 0);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length - 1u, &parsed_ts) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_credssp_parse_ts_request(credssp_windows_logon_failure,
                                        sizeof(credssp_windows_logon_failure),
                                        &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.has_error_code && parsed_ts.error_code == 0xc000006du);
    PCHECK(rdp_credssp_status_from_error_code(parsed_ts.error_code) ==
           LIBRDP_STATUS_AUTHENTICATION_FAILED);
    ts_request.length = 0;
    PCHECK(rdp_credssp_write_ts_error(&ts_request, 6u, 0xc0000071u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data,
                                        ts_request.length,
                                        &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.has_error_code && parsed_ts.error_code == 0xc0000071u);
    PCHECK(rdp_credssp_status_from_error_code(parsed_ts.error_code) ==
           LIBRDP_STATUS_CREDENTIALS_EXPIRED);
    PCHECK(rdp_credssp_status_from_error_code(0xc0000224u) ==
           LIBRDP_STATUS_CREDENTIALS_EXPIRED);
    PCHECK(rdp_credssp_status_from_error_code(0xc0000234u) ==
           LIBRDP_STATUS_ACCOUNT_LOCKED);
    PCHECK(rdp_credssp_status_from_error_code(0xc0000072u) ==
           LIBRDP_STATUS_AUTHENTICATION_FAILED);
    PCHECK(rdp_credssp_status_from_error_code(0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_error_code_from_status(
               LIBRDP_STATUS_AUTHENTICATION_FAILED) == 0xc000006du);
    PCHECK(rdp_credssp_error_code_from_status(
               LIBRDP_STATUS_CREDENTIALS_EXPIRED) == 0xc0000071u);
    PCHECK(rdp_credssp_error_code_from_status(
               LIBRDP_STATUS_ACCOUNT_LOCKED) == 0xc0000234u);
    PCHECK(rdp_credssp_write_ts_error(&ts_request, 6u, 0u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_credssp_write_negotiate_request(&nla_request, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(nla_request.data, nla_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len > 0);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token),
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == 0x04030201u);
    PCHECK(ntlm_challenge.server_challenge[0] == 0x10 && ntlm_challenge.server_challenge[7] == 0x17);
    PCHECK(ntlm_challenge.target_name_len == 4 && ntlm_challenge.target_info_len == 8);
    PCHECK(rdp_credssp_extract_ntlm_challenge(wrapped_ntlm_challenge,
                                              sizeof(wrapped_ntlm_challenge),
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == sizeof(ntlm_challenge_token));
    PCHECK(rdp_credssp_parse_ntlm_challenge(extracted_ntlm, extracted_ntlm_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token) - 1u,
                                            &ntlm_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&ntlm_v2_challenge, 0, sizeof(ntlm_v2_challenge));
    ntlm_v2_challenge.flags = 0xe2888235u;
    memcpy(ntlm_v2_challenge.server_challenge, ntlm_v2_server_challenge, sizeof(ntlm_v2_server_challenge));
    ntlm_v2_challenge.target_name = ntlm_v2_target_name;
    ntlm_v2_challenge.target_name_len = sizeof(ntlm_v2_target_name);
    ntlm_v2_challenge.target_info = ntlm_v2_target_info;
    ntlm_v2_challenge.target_info_len = sizeof(ntlm_v2_target_info);
    PCHECK(rdp_credssp_write_ntlm_challenge(&ntlm_challenge_written, &ntlm_v2_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_written.data,
                                            ntlm_challenge_written.length,
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == ntlm_v2_challenge.flags);
    PCHECK(memcmp(ntlm_challenge.server_challenge,
                  ntlm_v2_challenge.server_challenge,
                  sizeof(ntlm_challenge.server_challenge)) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_challenge(&spnego_challenge_written,
                                                   ntlm_challenge_written.data,
                                                   ntlm_challenge_written.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_extract_ntlm_challenge(spnego_challenge_written.data,
                                              spnego_challenge_written.length,
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == ntlm_challenge_written.length);
    ntlm_auth_status = rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                                           &ntlm_v2_challenge,
                                                           "user",
                                                           "SecREt01",
                                                           "DOMAIN",
                                                           "COMPUTER",
                                                           0x01c334b736d39000ull,
                                                           ntlm_v2_client_challenge,
                                                           ntlm_v2_session_key,
                                                           &ntlm_auth_result);
    if (ntlm_auth_status == LIBRDP_STATUS_UNSUPPORTED)
    {
        PCHECK(ntlm_authenticate.length == 0);
    }
    else
    {
        PCHECK(ntlm_auth_status == LIBRDP_STATUS_OK);
        PCHECK(ntlm_authenticate.length > 88);
        PCHECK(memcmp(ntlm_authenticate.data, "NTLMSSP", 7) == 0);
        PCHECK(test_read_u32_le(ntlm_authenticate.data + 8) == 3);
        lm_len = test_read_u16_le(ntlm_authenticate.data + 12);
        lm_offset = test_read_u32_le(ntlm_authenticate.data + 16);
        nt_len = test_read_u16_le(ntlm_authenticate.data + 20);
        nt_offset = test_read_u32_le(ntlm_authenticate.data + 24);
        key_len = test_read_u16_le(ntlm_authenticate.data + 52);
        key_offset = test_read_u32_le(ntlm_authenticate.data + 56);
        PCHECK(test_read_u32_le(ntlm_authenticate.data + 60) == ntlm_auth_result.flags);
        PCHECK(lm_len == sizeof(ntlm_v2_expected_lm));
        PCHECK(nt_len > sizeof(ntlm_v2_expected_proof));
        PCHECK(key_len == sizeof(ntlm_v2_session_key));
        PCHECK((size_t)lm_offset + lm_len <= ntlm_authenticate.length);
        PCHECK((size_t)nt_offset + nt_len <= ntlm_authenticate.length);
        PCHECK((size_t)key_offset + key_len <= ntlm_authenticate.length);
        PCHECK(memcmp(ntlm_authenticate.data + lm_offset, ntlm_v2_expected_lm, sizeof(ntlm_v2_expected_lm)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + nt_offset,
                      ntlm_v2_expected_proof,
                      sizeof(ntlm_v2_expected_proof)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + key_offset,
                      ntlm_v2_expected_encrypted_key,
                      sizeof(ntlm_v2_expected_encrypted_key)) == 0);
        PCHECK(memcmp(ntlm_auth_result.session_key, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) == 0);
        PCHECK(memcmp(ntlm_authenticate.data + key_offset, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) != 0);
        PCHECK(rdp_credssp_parse_ntlm_authenticate(ntlm_authenticate.data,
                                                   ntlm_authenticate.length,
                                                   &parsed_ntlm_authenticate) == LIBRDP_STATUS_OK);
        PCHECK(parsed_ntlm_authenticate.nt_response_len == nt_len);
        PCHECK(rdp_credssp_verify_ntlm_authenticate(ntlm_authenticate.data,
                                                    ntlm_authenticate.length,
                                                    &ntlm_v2_challenge,
                                                    "USER",
                                                    "SecREt01",
                                                    &server_auth_result) == LIBRDP_STATUS_OK);
        PCHECK(memcmp(server_auth_result.session_key,
                      ntlm_v2_session_key,
                      sizeof(ntlm_v2_session_key)) == 0);
        PCHECK(rdp_credssp_verify_ntlm_authenticate(ntlm_authenticate.data,
                                                    ntlm_authenticate.length,
                                                    &ntlm_v2_challenge,
                                                    "other",
                                                    "SecREt01",
                                                    &failed_auth_result) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                          ntlm_authenticate.data,
                                                          ntlm_authenticate.length) == LIBRDP_STATUS_OK);
        PCHECK(spnego_authenticate.length > ntlm_authenticate.length && spnego_authenticate.data[0] == 0xa1);
        PCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_wrap(&ntlm_security, "data", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
        PCHECK(ntlm_wrapped.length == 20);
        PCHECK(test_read_u32_le(ntlm_wrapped.data) == 1);
        PCHECK(test_read_u32_le(ntlm_wrapped.data + 12) == 0);
        PCHECK(memcmp(ntlm_wrapped.data, ntlm_expected_wrapped_data, sizeof(ntlm_expected_wrapped_data)) == 0);
        PCHECK(memcmp(ntlm_wrapped.data + 16, "data", 4) != 0);
        PCHECK(ntlm_security.send_seq == 1);
        PCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                                   credssp_client_nonce,
                                                   sizeof(credssp_client_nonce),
                                                   credssp_public_key,
                                                   sizeof(credssp_public_key),
                                                   &pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(pub_key_auth.length == 48 && ntlm_security.send_seq == 2);
        server_security = ntlm_security;
        memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
        server_security.send_rc4 = ntlm_security.recv_rc4;
        server_security.send_seq = 0;
        PCHECK(test_sha256_three((const uint8_t*)"CredSSP Server-To-Client Binding Hash",
                                 sizeof("CredSSP Server-To-Client Binding Hash"),
                                 credssp_client_nonce,
                                 sizeof(credssp_client_nonce),
                                 credssp_public_key,
                                 sizeof(credssp_public_key),
                                 server_hash));
        PCHECK(rdp_credssp_ntlm_wrap(&server_security,
                                     server_hash,
                                     sizeof(server_hash),
                                     &server_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                                  credssp_client_nonce,
                                                  sizeof(credssp_client_nonce),
                                                  credssp_public_key,
                                                  sizeof(credssp_public_key),
                                                  server_pub_key_auth.data,
                                                  server_pub_key_auth.length) == LIBRDP_STATUS_OK);
        server_security = ntlm_security;
        memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
        server_security.send_rc4 = ntlm_security.recv_rc4;
        server_security.send_seq = ntlm_security.recv_seq;
        corrupt_client_security = ntlm_security;
        corrupt_server_security = server_security;
        PCHECK(rdp_buffer_append(&corrupt_plain, "keep", 4u) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_wrap(&corrupt_server_security, "peer", 4u, &corrupt_wrapped) ==
               LIBRDP_STATUS_OK);
        corrupt_wrapped.data[4] ^= 0x80u;
        PCHECK(rdp_credssp_ntlm_unwrap(&corrupt_client_security,
                                       corrupt_wrapped.data,
                                       corrupt_wrapped.length,
                                       &corrupt_plain) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(corrupt_plain.length == 4u && memcmp(corrupt_plain.data, "keep", 4u) == 0);
        PCHECK(corrupt_plain.data[4] == 0u && corrupt_plain.data[5] == 0u &&
               corrupt_plain.data[6] == 0u && corrupt_plain.data[7] == 0u);
        PCHECK(corrupt_client_security.recv_seq == ntlm_security.recv_seq);
        PCHECK(rdp_credssp_ntlm_wrap(&server_security, "peer", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_unwrap(&ntlm_security,
                                       ntlm_wrapped.data + 20,
                                       ntlm_wrapped.length - 20,
                                       &ntlm_unwrapped) == LIBRDP_STATUS_OK);
        PCHECK(ntlm_unwrapped.length == 4 && memcmp(ntlm_unwrapped.data, "peer", 4) == 0);
        PCHECK(rdp_credssp_write_password_credentials(&ts_credentials,
                                                      "DOMAIN",
                                                      "user",
                                                      "SecREt01") == LIBRDP_STATUS_OK);
        PCHECK(ts_credentials.length > 32 && ts_credentials.data[0] == 0x30);
        PCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                        "DOMAIN",
                                                        "user",
                                                        "SecREt01",
                                                        &auth_info) == LIBRDP_STATUS_OK);
        PCHECK(auth_info.length == ts_credentials.length + 16u);
        PCHECK(test_read_u32_le(auth_info.data) == 1);
        PCHECK(test_read_u32_le(auth_info.data + 12) == 2);
        PCHECK(memcmp(auth_info.data + 16, ts_credentials.data, ts_credentials.length < 8u ? ts_credentials.length : 8u) !=
               0);
        PCHECK(rdp_credssp_ntlm_security_init(&client_sequence_security, &ntlm_auth_result) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_ntlm_server_security_init(&server_sequence_security, &server_auth_result) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_public_key_hash(&client_sequence_security,
                                                   credssp_client_nonce,
                                                   sizeof(credssp_client_nonce),
                                                   credssp_public_key,
                                                   sizeof(credssp_public_key),
                                                   &client_sequence_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_client_public_key_hash(&server_sequence_security,
                                                         credssp_client_nonce,
                                                         sizeof(credssp_client_nonce),
                                                         credssp_public_key,
                                                         sizeof(credssp_public_key),
                                                         client_sequence_pub_key_auth.data,
                                                         client_sequence_pub_key_auth.length) ==
               LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_server_public_key_hash(&server_sequence_security,
                                                          credssp_client_nonce,
                                                          sizeof(credssp_client_nonce),
                                                          credssp_public_key,
                                                          sizeof(credssp_public_key),
                                                          &server_sequence_pub_key_auth) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_verify_public_key_hash(&client_sequence_security,
                                                  credssp_client_nonce,
                                                  sizeof(credssp_client_nonce),
                                                  credssp_public_key,
                                                  sizeof(credssp_public_key),
                                                  server_sequence_pub_key_auth.data,
                                                  server_sequence_pub_key_auth.length) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_encrypt_password_credentials(&client_sequence_security,
                                                        "DOMAIN",
                                                        "user",
                                                        "SecREt01",
                                                        &client_sequence_auth_info) == LIBRDP_STATUS_OK);
        PCHECK(rdp_credssp_decrypt_password_credentials(&server_sequence_security,
                                                        client_sequence_auth_info.data,
                                                        client_sequence_auth_info.length) == LIBRDP_STATUS_OK);
    }

    rdp_buffer_free(&nla_request);
    rdp_buffer_free(&ts_request);
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&ts_credentials);
    rdp_buffer_free(&client_sequence_auth_info);
    rdp_buffer_free(&server_sequence_pub_key_auth);
    rdp_buffer_free(&client_sequence_pub_key_auth);
    rdp_buffer_free(&server_pub_key_auth);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&corrupt_plain);
    rdp_buffer_free(&corrupt_wrapped);
    rdp_buffer_free(&ntlm_unwrapped);
    rdp_buffer_free(&ntlm_wrapped);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&spnego_challenge_written);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&ntlm_challenge_written);
    rdp_buffer_free(&ntlm_negotiate);
    OPENSSL_cleanse(&failed_auth_result, sizeof(failed_auth_result));
    OPENSSL_cleanse(&server_auth_result, sizeof(server_auth_result));
    OPENSSL_cleanse(&corrupt_client_security, sizeof(corrupt_client_security));
    OPENSSL_cleanse(&corrupt_server_security, sizeof(corrupt_server_security));
    OPENSSL_cleanse(&client_sequence_security, sizeof(client_sequence_security));
    OPENSSL_cleanse(&server_sequence_security, sizeof(server_sequence_security));
    return 0;
}
