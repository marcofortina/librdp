#include "channels/auth_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_auth_redirection_outer_packet outer;
    rdp_auth_redirection_inner_buffer inner;
    rdp_auth_redirection_call call;
    rdp_auth_redirection_response response;
    rdp_auth_redirection_negotiate_version version;
    rdp_auth_redirection_ecdh_key_agreement_call ecdh;
    rdp_auth_redirection_dh_key_agreement_call dh;
    rdp_auth_redirection_key_agreement_handle_call handle;
    rdp_auth_redirection_fixed_response fixed;
    rdp_auth_redirection_compare_credentials_result compare;
    rdp_auth_redirection_octet_string octet;
    rdp_auth_redirection_asn1_data asn1;
    rdp_auth_redirection_finalize_key_agreement_call finalize_call;
    rdp_auth_redirection_call_message call_message;
    rdp_auth_redirection_response_message response_message;
    rdp_auth_redirection_encoded_payload encoded_payload;
    rdp_buffer buffer;
    uint32_t blob_len = 0;

    blob_len = (uint32_t)(size > 32u ? 32u : size);
    (void)rdp_auth_redirection_parse_outer_packet(data, size, &outer);
    (void)rdp_auth_redirection_parse_encoded_payload(data, size, &encoded_payload);
    (void)rdp_auth_redirection_parse_inner_buffer(data, size, &inner);
    (void)rdp_auth_redirection_parse_call(data, size, &call);
    (void)rdp_auth_redirection_parse_call_message(data, size, &call_message);
    (void)rdp_auth_redirection_parse_response(data, size, &response);
    (void)rdp_auth_redirection_parse_response_message(data, size, &response_message);
    (void)rdp_auth_redirection_parse_octet_string(data, size, &octet);
    (void)rdp_auth_redirection_parse_octet_response(
        data,
        size,
        RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY,
        &response,
        &octet);
    (void)rdp_auth_redirection_parse_asn1_data(data, size, &asn1);
    (void)rdp_auth_redirection_parse_asn1_response(
        data,
        size,
        RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY,
        &response,
        &asn1);
    (void)rdp_auth_redirection_parse_negotiate_version_call(data, size, &version);
    (void)rdp_auth_redirection_parse_negotiate_version_response(data, size, &response, &version);
    (void)rdp_auth_redirection_parse_ecdh_key_agreement_call(data, size, &ecdh);
    (void)rdp_auth_redirection_parse_dh_key_agreement_call(data, size, &dh);
    (void)rdp_auth_redirection_parse_key_agreement_handle_call(
        data,
        size,
        RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT,
        &handle);
    (void)rdp_auth_redirection_parse_key_agreement_handle_call(
        data,
        size,
        RDP_AUTH_REDIRECTION_CALL_KERB_KEY_AGREEMENT_GENERATE_NONCE,
        &handle);
    (void)rdp_auth_redirection_parse_finalize_key_agreement_call(data, size, &finalize_call);
    (void)rdp_auth_redirection_parse_nt_response_response(data, size, &fixed);
    (void)rdp_auth_redirection_parse_user_session_key_response(data, size, &fixed);
    (void)rdp_auth_redirection_parse_compare_credentials_response(data, size, &response, &compare);

    rdp_buffer_init(&buffer);
    (void)rdp_auth_redirection_write_outer_packet(&buffer, data, size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_encoded_payload(&buffer,
                                                     RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS,
                                                     data,
                                                     size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_encoded_payload(&buffer,
                                                     RDP_AUTH_REDIRECTION_PACKAGE_NTLM,
                                                     data,
                                                     size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_inner_buffer(&buffer, data, size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_call(&buffer,
                                          RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
                                          data,
                                          size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_response(&buffer,
                                              RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                              0,
                                              data,
                                              size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_octet_string(&buffer, data, blob_len);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_octet_response(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY,
        0,
        data,
        blob_len);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_asn1_data(&buffer,
                                               RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP,
                                               data,
                                               blob_len);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_asn1_response(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY,
        0,
        RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP,
        data,
        blob_len);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_negotiate_version_call(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_negotiate_version_response(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
        0);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_ecdh_key_agreement_call(
        &buffer,
        size > 0 && (data[0] & 1u) ? RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384 :
                                     RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P256);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_dh_key_agreement_call(&buffer, size > 0 ? data[0] : 0);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_key_agreement_handle_call(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT,
        (int64_t)size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_finalize_key_agreement_call(&buffer,
                                                                 (int64_t)size,
                                                                 18,
                                                                 data,
                                                                 blob_len,
                                                                 data,
                                                                 blob_len);
    buffer.length = 0;
    compare.nt_equal = size > 0 ? (uint32_t)(data[0] & 1u) : 0;
    compare.lm_equal = size > 1 ? (uint32_t)(data[1] & 1u) : 0;
    compare.sha_equal = size > 2 ? (uint32_t)(data[2] & 1u) : 0;
    (void)rdp_auth_redirection_write_compare_credentials_response(&buffer, 0, &compare);
    rdp_buffer_free(&buffer);
    return 0;
}
