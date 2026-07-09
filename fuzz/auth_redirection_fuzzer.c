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
    rdp_buffer buffer;

    (void)rdp_auth_redirection_parse_outer_packet(data, size, &outer);
    (void)rdp_auth_redirection_parse_inner_buffer(data, size, &inner);
    (void)rdp_auth_redirection_parse_call(data, size, &call);
    (void)rdp_auth_redirection_parse_response(data, size, &response);
    (void)rdp_auth_redirection_parse_negotiate_version_call(data, size, &version);
    (void)rdp_auth_redirection_parse_negotiate_version_response(data, size, &response, &version);

    rdp_buffer_init(&buffer);
    (void)rdp_auth_redirection_write_outer_packet(&buffer, data, size);
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
    (void)rdp_auth_redirection_write_negotiate_version_call(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_negotiate_version_response(
        &buffer,
        RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
        0);
    rdp_buffer_free(&buffer);
    return 0;
}
