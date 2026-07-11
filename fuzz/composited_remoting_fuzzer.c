/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/composited_remoting.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_composited_control control;
    rdp_composited_channel_message message;
    rdp_composited_batch_reader reader;
    rdp_composited_version_reply version_reply;
    rdp_composited_resource_order resource_order;
    rdp_composited_duplicate_handle duplicate;
    rdp_composited_u32_target_order u32_order;
    rdp_composited_window_node_create window_node;
    rdp_composited_target_create target;
    rdp_composited_glyph_run glyph_run;
    rdp_composited_gdi_sprite_bitmap sprite;
    rdp_composited_gdi_surface_update surface_update;
    rdp_composited_texture_set textures;
    rdp_composited_meta_target meta;
    rdp_buffer buffer;
    uint32_t versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
    uint32_t glyphs[2] = {1, 2};
    uint8_t color[16] = {0};
    uint8_t surfaces[RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES] = {0};

    (void)rdp_composited_parse_control(data, size, &control);
    (void)rdp_composited_parse_channel_message(data, size, &message);
    (void)rdp_composited_parse_version_reply(data, size, &version_reply);
    (void)rdp_composited_parse_resource_order(data, size, RDP_COMPOSITED_CMD_CREATE_RESOURCE, &resource_order);
    (void)rdp_composited_parse_resource_order(data, size, RDP_COMPOSITED_CMD_DELETE_RESOURCE, &resource_order);
    (void)rdp_composited_parse_duplicate_handle(data, size, &duplicate);
    (void)rdp_composited_parse_u32_target_order(data,
                                                size,
                                                RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                &u32_order);
    (void)rdp_composited_parse_window_node_create(data, size, &window_node);
    (void)rdp_composited_parse_target_create(data, size, &target);
    (void)rdp_composited_parse_glyph_run(data, size, &glyph_run);
    (void)rdp_composited_parse_gdi_sprite_bitmap(data, size, &sprite);
    (void)rdp_composited_parse_gdi_surface_update(data, size, &surface_update);
    (void)rdp_composited_parse_texture_set(data, size, &textures);
    (void)rdp_composited_parse_meta_target(data, size, RDP_COMPOSITED_CMD_META_TARGET_CREATE, &meta);
    (void)rdp_composited_parse_meta_target(data, size, RDP_COMPOSITED_CMD_META_TARGET_UPDATE, &meta);
    if (rdp_composited_batch_init(&reader, data, size) == LIBRDP_STATUS_OK)
    {
        while (rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_OK)
        {
        }
    }

    rdp_buffer_init(&buffer);
    (void)rdp_composited_write_control_fixed(&buffer, RDP_COMPOSITED_CONTROL_VERSION_REQUEST, 0, 0);
    buffer.length = 0;
    (void)rdp_composited_write_version_reply(&buffer, versions, 1);
    buffer.length = 0;
    (void)rdp_composited_write_resource_order(&buffer,
                                              RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                              1,
                                              RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
    buffer.length = 0;
    (void)rdp_composited_write_duplicate_handle(&buffer, 1, 2, 3);
    buffer.length = 0;
    (void)rdp_composited_write_window_node_create(&buffer, 1, 2, 3, 0);
    buffer.length = 0;
    (void)rdp_composited_write_u32_target_order(&buffer,
                                                RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                1,
                                                2);
    buffer.length = 0;
    (void)rdp_composited_write_target_create(&buffer, 1, 800, 600, color);
    buffer.length = 0;
    (void)rdp_composited_write_glyph_run(&buffer, 1, 2, 1, glyphs, 2);
    buffer.length = 0;
    (void)rdp_composited_write_gdi_sprite_bitmap(&buffer, 1, 2, 3);
    buffer.length = 0;
    (void)rdp_composited_write_gdi_surface_update(&buffer, 1, 0x57);
    buffer.length = 0;
    (void)rdp_composited_write_meta_target(&buffer,
                                           RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                           1,
                                           1,
                                           0x57,
                                           800,
                                           600,
                                           surfaces);
    rdp_buffer_free(&buffer);
    return 0;
}
