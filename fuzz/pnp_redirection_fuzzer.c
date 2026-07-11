/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/pnp_redirection.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_pnp_redirection_info_header info;
    rdp_pnp_redirection_version version;
    rdp_pnp_redirection_device_description description;
    rdp_pnp_redirection_device_addition addition;
    rdp_pnp_redirection_device_removal removal;
    rdp_pnp_redirection_server_io_header server_header;
    rdp_pnp_redirection_client_io_header client_header;
    rdp_pnp_redirection_io_version io_version;
    rdp_pnp_redirection_create_request create_request;
    rdp_pnp_redirection_read_request read_request;
    rdp_pnp_redirection_write_request write_request;
    rdp_pnp_redirection_control_request control_request;
    rdp_pnp_redirection_cancel_request cancel_request;
    rdp_pnp_redirection_custom_event event;
    rdp_buffer buffer;
    uint8_t guid[16] = {0};
    const uint8_t name[] = {'D', 0, 'e', 0, 'v', 0};

    (void)rdp_pnp_redirection_parse_info_header(data, size, &info);
    (void)rdp_pnp_redirection_parse_version(data, size, &version);
    (void)rdp_pnp_redirection_parse_authenticated(data, size, &info);
    (void)rdp_pnp_redirection_parse_device_description(data, size, &description);
    (void)rdp_pnp_redirection_parse_device_addition(data, size, &addition);
    (void)rdp_pnp_redirection_parse_device_removal(data, size, &removal);
    (void)rdp_pnp_redirection_parse_server_io_header(data, size, &server_header);
    (void)rdp_pnp_redirection_parse_client_io_header(data, size, &client_header);
    (void)rdp_pnp_redirection_parse_capabilities_request(data, size, &io_version);
    (void)rdp_pnp_redirection_parse_create_request(data, size, &create_request);
    (void)rdp_pnp_redirection_parse_read_request(data, size, &read_request);
    (void)rdp_pnp_redirection_parse_write_request(data, size, &write_request);
    (void)rdp_pnp_redirection_parse_control_request(data, size, &control_request);
    (void)rdp_pnp_redirection_parse_cancel_request(data, size, &cancel_request);
    (void)rdp_pnp_redirection_parse_custom_event(data, size, &event);

    rdp_buffer_init(&buffer);
    (void)rdp_pnp_redirection_write_version(&buffer, 1, 0, RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_authenticated(&buffer);
    buffer.length = 0;
    description.client_device_id = 1;
    description.interface_guids = NULL;
    description.interface_guids_len = 0;
    description.hardware_id = name;
    description.hardware_id_len = (uint32_t)sizeof(name);
    description.compatibility_id = name;
    description.compatibility_id_len = (uint32_t)sizeof(name);
    description.device_description = name;
    description.device_description_len = (uint32_t)sizeof(name);
    description.custom_flag = RDP_PNP_REDIRECTION_CUSTOM_FLAG_REDIRECTABLE;
    description.container_id = guid;
    description.container_id_len = 16;
    description.has_container_id = 1;
    description.device_caps = RDP_PNP_REDIRECTION_DEVCAPS_REMOVABLE;
    description.has_device_caps = 1;
    (void)rdp_pnp_redirection_write_device_addition(&buffer, &description, 1);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_device_removal(&buffer, 1);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_capabilities_request(&buffer,
                                                         2,
                                                         0,
                                                         RDP_PNP_REDIRECTION_IO_VERSION_6);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_capabilities_reply(&buffer, 2, RDP_PNP_REDIRECTION_IO_VERSION_6);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_create_request(&buffer, 3, 0, 1, 0xc0000000u, 3, 3, 0x40);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_status_reply(&buffer, 3, 0);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_read_request(&buffer, 4, 0, 64, 0, 0);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_read_reply(&buffer, 4, 0, data, size < 32u ? (uint32_t)size : 32u);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_write_request(&buffer,
                                                  5,
                                                  0,
                                                  0,
                                                  0,
                                                  data,
                                                  size < 32u ? (uint32_t)size : 32u);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_write_reply(&buffer, 5, 0, size < 32u ? (uint32_t)size : 32u);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_control_request(&buffer,
                                                    6,
                                                    0,
                                                    0x1020,
                                                    data,
                                                    size < 16u ? (uint32_t)size : 16u,
                                                    16,
                                                    data,
                                                    size < 16u ? (uint32_t)size : 16u);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_control_reply(&buffer, 6, 0, data, size < 32u ? (uint32_t)size : 32u);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_cancel_request(&buffer, 7, 0, 0, 5);
    buffer.length = 0;
    (void)rdp_pnp_redirection_write_custom_event(&buffer, guid, data, size < 32u ? (uint32_t)size : 32u);
    rdp_buffer_free(&buffer);
    return 0;
}
