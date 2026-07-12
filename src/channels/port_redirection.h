/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: serial and parallel port redirection declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_PORT_REDIRECTION_H
#define RDP_CHANNELS_PORT_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/device_redirection.h"
#include "channels/filesystem_redirection.h"
#include "common/buffer.h"

#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE 0x001b0004u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_BAUD_RATE 0x001b0050u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_LINE_CONTROL 0x001b000cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_LINE_CONTROL 0x001b0054u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_TIMEOUTS 0x001b001cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_TIMEOUTS 0x001b0020u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_CHARS 0x001b0058u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_CHARS 0x001b005cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_DTR 0x001b0024u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_DTR 0x001b0028u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_RESET_DEVICE 0x001b002cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_RTS 0x001b0030u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_RTS 0x001b0034u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XOFF 0x001b0038u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XON 0x001b003cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_ON 0x001b0010u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_OFF 0x001b0014u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_QUEUE_SIZE 0x001b0008u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_WAIT_MASK 0x001b0040u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_WAIT_MASK 0x001b0044u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_WAIT_ON_MASK 0x001b0048u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_IMMEDIATE_CHAR 0x001b0018u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_PURGE 0x001b004cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_HANDFLOW 0x001b0060u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_HANDFLOW 0x001b0064u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEMSTATUS 0x001b0068u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_DTRRTS 0x001b0078u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_COMMSTATUS 0x001b006cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_PROPERTIES 0x001b0074u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_XOFF_COUNTER 0x001b0070u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_LSRMST_INSERT 0x001b007cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_CONFIG_SIZE 0x001b0080u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_STATS 0x001b008cu
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLEAR_STATS 0x001b0090u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEM_CONTROL 0x001b0094u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_MODEM_CONTROL 0x001b0098u
#define RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_FIFO_CONTROL 0x001b009cu
#define RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR 0x00000001u
#define RDP_PORT_REDIRECTION_SERIAL_EV_TXEMPTY 0x00000004u
#define RDP_PORT_REDIRECTION_SERIAL_EV_CTS 0x00000008u
#define RDP_PORT_REDIRECTION_SERIAL_EV_DSR 0x00000010u
#define RDP_PORT_REDIRECTION_SERIAL_EV_RLSD 0x00000020u
#define RDP_PORT_REDIRECTION_SERIAL_EV_BREAK 0x00000040u
#define RDP_PORT_REDIRECTION_SERIAL_EV_ERR 0x00000080u
#define RDP_PORT_REDIRECTION_SERIAL_EV_RING 0x00000100u
#define RDP_PORT_REDIRECTION_SERIAL_EV_RX80FULL 0x00000400u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_INFORMATION 0x00160004u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_SET_INFORMATION 0x00160008u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID 0x0016000cu
#define RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID_SIZE 0x00160010u
#define RDP_PORT_REDIRECTION_IOCTL_IEEE1284_GET_MODE 0x00160014u
#define RDP_PORT_REDIRECTION_IOCTL_IEEE1284_NEGOTIATE 0x00160018u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_SET_WRITE_ADDRESS 0x0016001cu
#define RDP_PORT_REDIRECTION_IOCTL_PAR_SET_READ_ADDRESS 0x00160020u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEVICE_CAPS 0x00160024u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEFAULT_MODES 0x00160028u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_RAW_DEVICE_ID 0x00160030u
#define RDP_PORT_REDIRECTION_IOCTL_PAR_IS_PORT_FREE 0x00160054u

typedef enum rdp_port_redirection_type
{
    RDP_PORT_REDIRECTION_SERIAL = RDP_DEVICE_REDIRECTION_TYPE_SERIAL,
    RDP_PORT_REDIRECTION_PARALLEL = RDP_DEVICE_REDIRECTION_TYPE_PARALLEL
} rdp_port_redirection_type;

int rdp_port_redirection_device_type_valid(uint32_t device_type);
int rdp_port_redirection_ioctl_serial(uint32_t io_control_code);
int rdp_port_redirection_ioctl_parallel(uint32_t io_control_code);
int rdp_port_redirection_ioctl_known(uint32_t io_control_code);
uint32_t rdp_port_redirection_serial_wait_result(uint32_t wait_mask, uint32_t available_events);
librdp_status rdp_port_redirection_make_announce(rdp_device_redirection_device_announce* device,
                                                 rdp_port_redirection_type type,
                                                 uint32_t device_id,
                                                 const char preferred_name[8]);
librdp_status rdp_port_redirection_write_device_list_announce(
    rdp_buffer* buffer,
    const rdp_device_redirection_device_announce* devices,
    uint32_t count);
librdp_status rdp_port_redirection_parse_device_list_announce(
    const void* data,
    size_t length,
    rdp_device_redirection_device_list* list);
librdp_status rdp_port_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_request* request);
librdp_status rdp_port_redirection_parse_close_request(
    const void* data,
    size_t length,
    rdp_device_redirection_io_request* request);
librdp_status rdp_port_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_read_request* request);
librdp_status rdp_port_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_write_request* request);
librdp_status rdp_port_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_control_request* request);
librdp_status rdp_port_redirection_write_control_request(rdp_buffer* buffer,
                                                         uint32_t device_id,
                                                         uint32_t file_id,
                                                         uint32_t completion_id,
                                                         uint32_t output_buffer_length,
                                                         uint32_t io_control_code,
                                                         const void* input,
                                                         uint32_t input_len);
librdp_status rdp_port_redirection_write_control_response(rdp_buffer* buffer,
                                                          uint32_t device_id,
                                                          uint32_t completion_id,
                                                          uint32_t io_status,
                                                          const void* output,
                                                          uint32_t output_len);

#endif
