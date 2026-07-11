/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "clipboard/clipboard.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_clipboard_packet packet;
    rdp_clipboard_capabilities caps;
    rdp_clipboard_format_list list;
    rdp_clipboard_format_entry entry;
    rdp_clipboard_format_data_request data_request;
    rdp_clipboard_format_data_response data_response;
    rdp_clipboard_file_contents_request file_request;
    rdp_clipboard_file_contents_response file_response;
    rdp_clipboard_file_descriptor file_desc;
    rdp_clipboard_lock lock;
    rdp_buffer out;
    const uint8_t file_name[] = {'a', 0};
    uint32_t count = 0;

    file_desc.name_utf16 = file_name;
    file_desc.name_utf16_len = sizeof(file_name);
    file_desc.size = size;
    file_desc.attributes = RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL;
    rdp_buffer_init(&out);
    if (rdp_clipboard_parse_packet(data, size, &packet) == LIBRDP_STATUS_OK)
    {
        (void)rdp_clipboard_parse_capabilities(&packet, &caps);
        if (rdp_clipboard_parse_format_list(&packet, &list) == LIBRDP_STATUS_OK)
        {
            if (rdp_clipboard_format_list_entry_count(&list, 0, &count) == LIBRDP_STATUS_OK && count > 0)
                (void)rdp_clipboard_format_list_get_entry(&list, 0, 0, &entry);
            if (rdp_clipboard_format_list_entry_count(&list, 1, &count) == LIBRDP_STATUS_OK && count > 0)
                (void)rdp_clipboard_format_list_get_entry(&list, 1, 0, &entry);
        }
        (void)rdp_clipboard_parse_format_data_request(&packet, &data_request);
        (void)rdp_clipboard_parse_format_data_response(&packet, &data_response);
        (void)rdp_clipboard_parse_file_contents_request(&packet, &file_request);
        (void)rdp_clipboard_parse_file_contents_response(&packet, &file_response);
        (void)rdp_clipboard_parse_lock(&packet, &lock);
        (void)rdp_clipboard_parse_unlock(&packet, &lock);
    }
    (void)rdp_clipboard_write_monitor_ready(&out);
    out.length = 0;
    (void)rdp_clipboard_write_capabilities(&out, (uint32_t)(size & 0x3fu));
    out.length = 0;
    (void)rdp_clipboard_write_format_list_response(&out, size & 1u);
    out.length = 0;
    (void)rdp_clipboard_write_format_data_request(&out, (uint32_t)size);
    out.length = 0;
    (void)rdp_clipboard_write_format_data_response(&out, 1, data, size > 32u ? 32u : size);
    out.length = 0;
    (void)rdp_clipboard_write_file_contents_response(&out, 1, (uint32_t)size, data, size > 32u ? 32u : size);
    out.length = 0;
    (void)rdp_clipboard_write_file_contents_request(&out,
                                                    (uint32_t)size,
                                                    (int32_t)(size & 7u),
                                                    RDP_CLIPBOARD_FILECONTENTS_RANGE,
                                                    size,
                                                    (uint32_t)(size > 4096u ? 4096u : size),
                                                    NULL);
    out.length = 0;
    (void)rdp_clipboard_write_hdrop(&out, &file_desc, 1);
    out.length = 0;
    (void)rdp_clipboard_write_file_group_descriptor_w(&out, &file_desc, 1);
    out.length = 0;
    (void)rdp_clipboard_write_lock(&out, (uint32_t)size);
    out.length = 0;
    (void)rdp_clipboard_write_unlock(&out, (uint32_t)size);
    rdp_buffer_free(&out);
    return 0;
}
