#include "channels/port_redirection.h"

#include <string.h>

int rdp_port_redirection_device_type_valid(uint32_t device_type)
{
    return device_type == RDP_DEVICE_REDIRECTION_TYPE_SERIAL ||
           device_type == RDP_DEVICE_REDIRECTION_TYPE_PARALLEL;
}

int rdp_port_redirection_ioctl_serial(uint32_t io_control_code)
{
    switch (io_control_code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_BAUD_RATE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_LINE_CONTROL:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_LINE_CONTROL:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_TIMEOUTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_TIMEOUTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_CHARS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_CHARS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_DTR:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_DTR:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_RESET_DEVICE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_RTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_RTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XOFF:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XON:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_ON:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_OFF:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_QUEUE_SIZE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_WAIT_MASK:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_WAIT_MASK:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_WAIT_ON_MASK:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_IMMEDIATE_CHAR:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_PURGE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_HANDFLOW:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_HANDFLOW:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEMSTATUS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_DTRRTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_COMMSTATUS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_PROPERTIES:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_XOFF_COUNTER:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_LSRMST_INSERT:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CONFIG_SIZE:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_STATS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLEAR_STATS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEM_CONTROL:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_MODEM_CONTROL:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_FIFO_CONTROL:
            return 1;
        default:
            return 0;
    }
}

int rdp_port_redirection_ioctl_parallel(uint32_t io_control_code)
{
    switch (io_control_code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_INFORMATION:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_INFORMATION:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID_SIZE:
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_GET_MODE:
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_NEGOTIATE:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_WRITE_ADDRESS:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_READ_ADDRESS:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEVICE_CAPS:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEFAULT_MODES:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_RAW_DEVICE_ID:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_IS_PORT_FREE:
            return 1;
        default:
            return 0;
    }
}

int rdp_port_redirection_ioctl_known(uint32_t io_control_code)
{
    return rdp_port_redirection_ioctl_serial(io_control_code) ||
           rdp_port_redirection_ioctl_parallel(io_control_code);
}

uint32_t rdp_port_redirection_serial_wait_result(uint32_t wait_mask, uint32_t available_events)
{
    return wait_mask & available_events;
}

librdp_status rdp_port_redirection_make_announce(rdp_device_redirection_device_announce* device,
                                                 rdp_port_redirection_type type,
                                                 uint32_t device_id,
                                                 const char preferred_name[8])
{
    if (!device || !preferred_name || !rdp_port_redirection_device_type_valid((uint32_t)type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(device, 0, sizeof(*device));
    device->device_type = (uint32_t)type;
    device->device_id = device_id;
    memcpy(device->preferred_dos_name, preferred_name, sizeof(device->preferred_dos_name));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_port_redirection_write_device_list_announce(
    rdp_buffer* buffer,
    const rdp_device_redirection_device_announce* devices,
    uint32_t count)
{
    uint32_t i = 0;

    if (!buffer || (!devices && count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        if (!rdp_port_redirection_device_type_valid(devices[i].device_type) ||
            devices[i].data_len != 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return rdp_device_redirection_write_device_list_announce(buffer, devices, count);
}

librdp_status rdp_port_redirection_parse_device_list_announce(
    const void* data,
    size_t length,
    rdp_device_redirection_device_list* list)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_parse_device_list_announce(data, length, list);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < list->count; i++)
    {
        if (!rdp_port_redirection_device_type_valid(list->devices[i].device_type) ||
            list->devices[i].data_len != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_port_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_request* request)
{
    return rdp_filesystem_redirection_parse_create_request(data, length, request);
}

librdp_status rdp_port_redirection_parse_close_request(
    const void* data,
    size_t length,
    rdp_device_redirection_io_request* request)
{
    return rdp_filesystem_redirection_parse_close_request(data, length, request);
}

librdp_status rdp_port_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_read_request* request)
{
    return rdp_filesystem_redirection_parse_read_request(data, length, request);
}

librdp_status rdp_port_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_write_request* request)
{
    return rdp_filesystem_redirection_parse_write_request(data, length, request);
}

librdp_status rdp_port_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_control_request* request)
{
    return rdp_filesystem_redirection_parse_control_request(data, length, request);
}

librdp_status rdp_port_redirection_write_control_request(rdp_buffer* buffer,
                                                         uint32_t device_id,
                                                         uint32_t file_id,
                                                         uint32_t completion_id,
                                                         uint32_t output_buffer_length,
                                                         uint32_t io_control_code,
                                                         const void* input,
                                                         uint32_t input_len)
{
    return rdp_filesystem_redirection_write_control_request(buffer,
                                                            device_id,
                                                            file_id,
                                                            completion_id,
                                                            output_buffer_length,
                                                            io_control_code,
                                                            input,
                                                            input_len);
}

librdp_status rdp_port_redirection_write_control_response(rdp_buffer* buffer,
                                                          uint32_t device_id,
                                                          uint32_t completion_id,
                                                          uint32_t io_status,
                                                          const void* output,
                                                          uint32_t output_len)
{
    return rdp_filesystem_redirection_write_buffer_response(buffer,
                                                            device_id,
                                                            completion_id,
                                                            io_status,
                                                            output,
                                                            output_len);
}
