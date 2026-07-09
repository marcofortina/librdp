#include "channels/smartcard_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_smartcard_redirection_device_control_request request;
    rdp_smartcard_redirection_device_control_response response;
    rdp_smartcard_redirection_request_message message;
    rdp_smartcard_redirection_establish_context_call call;
    rdp_smartcard_redirection_context context;
    rdp_smartcard_redirection_handle handle;
    rdp_smartcard_redirection_scard_io_request scard_io;
    rdp_smartcard_redirection_atr_mask atr_mask;
    rdp_smartcard_redirection_reader_state_common reader_state;
    rdp_smartcard_redirection_connect_common connect;
    rdp_smartcard_redirection_reconnect_call reconnect;
    rdp_smartcard_redirection_handle_disposition_call disposition;
    rdp_smartcard_redirection_state_call state_call;
    rdp_smartcard_redirection_status_call status_call;
    rdp_smartcard_redirection_transmit_call transmit_call;
    rdp_smartcard_redirection_control_call control_call;
    rdp_smartcard_redirection_attrib_call attrib_call;
    rdp_smartcard_redirection_set_attrib_call set_attrib_call;
    rdp_smartcard_redirection_long_return result;
    rdp_smartcard_redirection_count_return count;
    rdp_smartcard_redirection_buffer_return buffer_return;
    rdp_buffer buffer;
    uint32_t bounded_extra = size > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA ?
        RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA :
        (uint32_t)size;
    uint32_t bounded_buffer = size > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ?
        RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH :
        (uint32_t)size;
    uint32_t bounded_transmit = size > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ?
        RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH :
        (uint32_t)size;
    uint8_t fixed_mask[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {0};

    (void)rdp_smartcard_redirection_parse_device_control_request(data, size, &request);
    (void)rdp_smartcard_redirection_parse_device_control_request_message(data, size, &message);
    (void)rdp_smartcard_redirection_parse_device_control_response(data, size, &response);
    (void)rdp_smartcard_redirection_parse_establish_context_call(data, size, &call);
    (void)rdp_smartcard_redirection_parse_context(data, size, &context);
    (void)rdp_smartcard_redirection_parse_handle(data, size, &handle);
    (void)rdp_smartcard_redirection_parse_scard_io_request(data, size, &scard_io);
    (void)rdp_smartcard_redirection_parse_atr_mask(data, size, &atr_mask);
    (void)rdp_smartcard_redirection_parse_reader_state_common(data, size, &reader_state);
    (void)rdp_smartcard_redirection_parse_connect_common(data, size, &connect);
    (void)rdp_smartcard_redirection_parse_reconnect_call(data, size, &reconnect);
    (void)rdp_smartcard_redirection_parse_handle_disposition_call(data, size, &disposition);
    (void)rdp_smartcard_redirection_parse_state_call(data, size, &state_call);
    (void)rdp_smartcard_redirection_parse_status_call(data, size, &status_call);
    (void)rdp_smartcard_redirection_parse_transmit_call(data, size, &transmit_call);
    (void)rdp_smartcard_redirection_parse_control_call(data, size, &control_call);
    (void)rdp_smartcard_redirection_parse_attrib_call(data, size, &attrib_call);
    (void)rdp_smartcard_redirection_parse_set_attrib_call(data, size, &set_attrib_call);
    (void)rdp_smartcard_redirection_parse_long_return(data, size, &result);
    (void)rdp_smartcard_redirection_parse_count_return(data, size, &count);
    (void)rdp_smartcard_redirection_parse_buffer_return(
        data,
        size,
        RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH,
        &buffer_return);

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
    (void)rdp_smartcard_redirection_write_establish_context_call(
        &buffer,
        RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM);
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
    (void)rdp_smartcard_redirection_write_scard_io_request(
        &buffer,
        RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
        data,
        bounded_extra);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_atr_mask(&buffer, data, bounded_extra > 36u ? 36u : bounded_extra, fixed_mask);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_reader_state_common(&buffer, 0, 0, data, bounded_extra > 36u ? 36u : bounded_extra);
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
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_state_call(&buffer, data, 0, data, 0, 1, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_status_call(&buffer, data, 0, data, 0, 1, 0, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_transmit_call(
        &buffer,
        data,
        0,
        data,
        0,
        RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
        data,
        bounded_extra,
        data,
        bounded_transmit,
        0,
        RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0,
        NULL,
        0,
        1,
        0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_control_call(&buffer, data, 0, data, 0, 0, data, bounded_transmit, 1, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_attrib_call(&buffer, data, 0, data, 0, 0, 1, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_set_attrib_call(&buffer, data, 0, data, 0, 0, data, bounded_extra);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_long_return(&buffer, 0);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_count_return(&buffer, 0, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_smartcard_redirection_write_buffer_return(&buffer, 0, data, bounded_buffer);
    rdp_buffer_free(&buffer);
    return 0;
}
