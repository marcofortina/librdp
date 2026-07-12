/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for device redirection capability and IRP parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/device_redirection.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises device redirection capability and IRP parser paths
 * with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_device_redirection_header header;
    rdp_device_redirection_announce announce;
    rdp_device_redirection_client_name name;
    rdp_device_redirection_capability_list capabilities;
    rdp_device_redirection_general_capability general;
    rdp_device_redirection_capability_config config;
    rdp_device_redirection_capability generic_capability;
    rdp_device_redirection_device_list devices;
    rdp_device_redirection_device_remove remove;
    rdp_device_redirection_device_reply reply;
    rdp_device_redirection_io_request request;
    rdp_device_redirection_io_completion completion;
    rdp_buffer buffer;
    uint32_t ids[2] = {1, 2};

    if (!data && size > 0)
        return 0;

    (void)rdp_device_redirection_parse_header(data, size, &header);
    (void)rdp_device_redirection_parse_server_announce(data, size, &announce);
    (void)rdp_device_redirection_parse_client_id_confirm(data, size, &announce);
    (void)rdp_device_redirection_parse_client_name(data, size, &name);
    (void)rdp_device_redirection_parse_user_loggedon(data, size);
    if (rdp_device_redirection_parse_capability_list(data,
                                                     size,
                                                     RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
                                                     &capabilities) == LIBRDP_STATUS_OK)
    {
        for (uint16_t i = 0; i < capabilities.count; i++)
            (void)rdp_device_redirection_parse_general_capability(&capabilities.capabilities[i], &general);
    }
    (void)rdp_device_redirection_parse_capability_list(data,
                                                       size,
                                                       RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
                                                       &capabilities);
    (void)rdp_device_redirection_parse_device_list_announce(data, size, &devices);
    (void)rdp_device_redirection_parse_device_remove(data, size, &remove);
    (void)rdp_device_redirection_parse_device_reply(data, size, &reply);
    (void)rdp_device_redirection_parse_io_request(data, size, &request);
    (void)rdp_device_redirection_parse_io_completion(data, size, &completion);

    rdp_buffer_init(&buffer);
    (void)rdp_device_redirection_write_server_announce(&buffer,
                                                       RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
                                                       size > 0 ? data[0] : 0);
    buffer.length = 0;
    (void)rdp_device_redirection_write_client_announce(&buffer,
                                                       RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
                                                       size > 0 ? data[0] : 0);
    buffer.length = 0;
    (void)rdp_device_redirection_write_user_loggedon(&buffer);
    buffer.length = 0;
    (void)rdp_device_redirection_make_default_capability_config(&config);
    config.include_drive = (uint8_t)(size & 1u);
    config.include_smartcard = (uint8_t)((size >> 1u) & 1u);
    (void)rdp_device_redirection_write_general_capability(&buffer, &config.general);
    buffer.length = 0;
    (void)rdp_device_redirection_write_client_capability_response(&buffer, &config);
    buffer.length = 0;
    generic_capability.type = RDP_DEVICE_REDIRECTION_CAP_DRIVE;
    generic_capability.length = 8u;
    generic_capability.version = RDP_DEVICE_REDIRECTION_CAP_VERSION_2;
    generic_capability.data = NULL;
    generic_capability.data_len = 0;
    (void)rdp_device_redirection_write_capability_list(
        &buffer,
        RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
        &generic_capability,
        1);
    buffer.length = 0;
    (void)rdp_device_redirection_write_device_list_announce(&buffer, NULL, 0);
    buffer.length = 0;
    (void)rdp_device_redirection_write_device_remove(&buffer, ids, 2);
    buffer.length = 0;
    (void)rdp_device_redirection_write_device_reply(&buffer, 1, RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    buffer.length = 0;
    (void)rdp_device_redirection_write_io_request(&buffer,
                                                  1,
                                                  2,
                                                  3,
                                                  RDP_DEVICE_REDIRECTION_IRP_READ,
                                                  0,
                                                  data,
                                                  size < 64u ? size : 64u);
    buffer.length = 0;
    (void)rdp_device_redirection_write_io_completion(&buffer,
                                                     1,
                                                     2,
                                                     RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                     data,
                                                     size < 64u ? size : 64u);
    rdp_buffer_free(&buffer);
    return 0;
}
