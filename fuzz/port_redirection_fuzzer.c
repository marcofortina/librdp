/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for serial and parallel port redirection parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/port_redirection.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises serial and parallel port redirection parser paths
 * with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_device_redirection_device_list list;
    rdp_filesystem_redirection_create_request create_request;
    rdp_device_redirection_io_request close_request;
    rdp_filesystem_redirection_read_request read_request;
    rdp_filesystem_redirection_write_request write_request;
    rdp_filesystem_redirection_control_request control_request;
    rdp_device_redirection_device_announce device;
    rdp_buffer buffer;
    char name[8] = {'C', 'O', 'M', '1', ':', 0, 0, 0};
    uint32_t bounded = size > 65536u ? 65536u : (uint32_t)size;

    (void)rdp_port_redirection_parse_device_list_announce(data, size, &list);
    (void)rdp_port_redirection_parse_create_request(data, size, &create_request);
    (void)rdp_port_redirection_parse_close_request(data, size, &close_request);
    (void)rdp_port_redirection_parse_read_request(data, size, &read_request);
    (void)rdp_port_redirection_parse_write_request(data, size, &write_request);
    (void)rdp_port_redirection_parse_control_request(data, size, &control_request);
    (void)rdp_port_redirection_ioctl_known((uint32_t)size);

    rdp_buffer_init(&buffer);
    (void)rdp_port_redirection_make_announce(&device, RDP_PORT_REDIRECTION_SERIAL, 1, name);
    (void)rdp_port_redirection_write_device_list_announce(&buffer, &device, 1);
    buffer.length = 0;
    (void)rdp_port_redirection_write_control_request(&buffer,
                                                     1,
                                                     2,
                                                     3,
                                                     bounded,
                                                     RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE,
                                                     data,
                                                     bounded);
    buffer.length = 0;
    (void)rdp_port_redirection_write_control_response(&buffer, 1, 3, 0, data, bounded);
    rdp_buffer_free(&buffer);
    return 0;
}
