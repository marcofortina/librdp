#include "channels/smartcard_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_smartcard_redirection_device_control_request request;
    rdp_smartcard_redirection_device_control_response response;
    rdp_smartcard_redirection_establish_context_call call;
    rdp_smartcard_redirection_context context;
    rdp_smartcard_redirection_handle handle;
    rdp_smartcard_redirection_connect_common connect;
    rdp_smartcard_redirection_reconnect_call reconnect;
    rdp_smartcard_redirection_handle_disposition_call disposition;
    rdp_smartcard_redirection_long_return result;
    rdp_buffer buffer;

    (void)rdp_smartcard_redirection_parse_device_control_request(data, size, &request);
    (void)rdp_smartcard_redirection_parse_device_control_response(data, size, &response);
    (void)rdp_smartcard_redirection_parse_establish_context_call(data, size, &call);
    (void)rdp_smartcard_redirection_parse_context(data, size, &context);
    (void)rdp_smartcard_redirection_parse_handle(data, size, &handle);
    (void)rdp_smartcard_redirection_parse_connect_common(data, size, &connect);
    (void)rdp_smartcard_redirection_parse_reconnect_call(data, size, &reconnect);
    (void)rdp_smartcard_redirection_parse_handle_disposition_call(data, size, &disposition);
    (void)rdp_smartcard_redirection_parse_long_return(data, size, &result);

    rdp_buffer_init(&buffer);
    (void)rdp_smartcard_redirection_write_device_control_request(
        &buffer,
        0,
        RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT,
        data,
        size > UINT32_MAX ? UINT32_MAX : (uint32_t)size);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_device_control_response(
        &buffer,
        data,
        size > UINT32_MAX ? UINT32_MAX : (uint32_t)size);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_context(
        &buffer,
        data,
        size > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ?
            RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH :
            (uint32_t)size);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_handle(&buffer, data, 0, data, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_connect_common(
        &buffer,
        data,
        0,
        RDP_SMARTCARD_REDIRECTION_SHARE_SHARED,
        RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_reconnect_call(
        &buffer,
        data,
        0,
        data,
        0,
        RDP_SMARTCARD_REDIRECTION_SHARE_SHARED,
        RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
        RDP_SMARTCARD_REDIRECTION_LEAVE_CARD);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_handle_disposition_call(
        &buffer,
        data,
        0,
        data,
        0,
        RDP_SMARTCARD_REDIRECTION_LEAVE_CARD);
    rdp_buffer_free(&buffer);
    return 0;
}
