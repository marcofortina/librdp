#include "channels/auth_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_auth_redirection_outer_packet outer;
    rdp_auth_redirection_inner_buffer inner;
    rdp_auth_redirection_call call;
    rdp_buffer buffer;

    (void)rdp_auth_redirection_parse_outer_packet(data, size, &outer);
    (void)rdp_auth_redirection_parse_inner_buffer(data, size, &inner);
    (void)rdp_auth_redirection_parse_call(data, size, &call);

    rdp_buffer_init(&buffer);
    (void)rdp_auth_redirection_write_outer_packet(&buffer, data, size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_inner_buffer(&buffer, data, size);
    buffer.length = 0;
    (void)rdp_auth_redirection_write_call(&buffer,
                                          RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
                                          data,
                                          size);
    rdp_buffer_free(&buffer);
    return 0;
}
