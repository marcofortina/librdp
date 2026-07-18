/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: focused protocol conformance suite.
 * Coverage: clipboard and MCS indication conformance vectors.
 * Bug classes: format bounds, request correlation, file descriptor validation, malformed payloads, and response framing.
 * Determinism: all vectors and state are synthetic and remain local to this suite.
 */

#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "protocol/mcs.h"

#include <librdp/session.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}
static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/*
 * Runs clipboard and MCS indication conformance vectors.
 */
int test_protocol_clipboard_vectors(void)
{
    const uint8_t clip[] = {1, 0, 2, 0, 3, 0, 0, 0, 4, 5, 6};
    const uint8_t clip_caps[] = {
        0x07, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x0c, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00
    };
    const uint8_t clip_format_long[] = {
        0x02, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0x04, 0xc0, 0x00, 0x00,
        'N', 0x00, 'a', 0x00, 't', 0x00, 'i', 0x00, 'v', 0x00, 'e', 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x11, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    const uint8_t clip_format_short_ascii[] = {
        0x02, 0x00, 0x04, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0xaa, 0xc0, 0x00, 0x00,
        'C', 'u', 's', 't', 'o', 'm', 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    const uint8_t clip_data_request[] = {
        0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_size_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_range_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x33, 0x22, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x99, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_bad_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t indication_pdu[] = {0x68, 0x00, 0x03, 0x03, 0xeb, 0x70, 0x04, 1, 2, 3, 4};
    rdp_clipboard_packet cb;
    rdp_clipboard_capabilities cb_caps;
    rdp_clipboard_format_list cb_list;
    rdp_clipboard_format_entry cb_entry;
    rdp_clipboard_format_data_request cb_data_request;
    rdp_clipboard_format_data_response cb_data_response;
    rdp_clipboard_file_contents_request cb_file_request;
    rdp_clipboard_file_contents_response cb_file_response;
    rdp_clipboard_lock cb_lock;
    rdp_mcs_send_data_indication indication;
    rdp_buffer dyn_response;
    uint32_t error_info = 0;

    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_clipboard_parse_packet(clip, sizeof(clip), &cb) == LIBRDP_STATUS_OK);
    PCHECK(cb.type == 1 && cb.flags == 2 && cb.payload_len == 3 && cb.payload[0] == 4);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_header(&dyn_response,
                                      RDP_CLIPBOARD_CB_MONITOR_READY,
                                      0,
                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) ==
           LIBRDP_STATUS_OK);
    PCHECK(cb.type == RDP_CLIPBOARD_CB_MONITOR_READY && cb.payload_len == 0);
    PCHECK(rdp_clipboard_write_header(NULL, RDP_CLIPBOARD_CB_MONITOR_READY, 0, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_caps, sizeof(clip_caps), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_capabilities(&cb, &cb_caps) == LIBRDP_STATUS_OK);
    PCHECK(cb_caps.count == 1 && cb_caps.has_general &&
           cb_caps.general.version == RDP_CLIPBOARD_CAPS_VERSION_2 &&
           cb_caps.general.general_flags == (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                             RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                                             RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA));
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_capabilities(&dyn_response,
                                            RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                            RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_caps) &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_CLIP_CAPS &&
           test_read_u32_le(dyn_response.data + 4) == 16 &&
           test_read_u32_le(dyn_response.data + 20) ==
               (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES | RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED));
    PCHECK(rdp_clipboard_parse_packet(clip_format_long, sizeof(clip_format_long), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 4);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc004u && cb_entry.name_len == 12 &&
           memcmp(cb_entry.name, "N\0a\0t\0i\0v\0e\0", 12) == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 3, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0x11u && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 4, &cb_entry) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_format_short_ascii,
                                      sizeof(clip_format_short_ascii),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 0, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 0, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc0aau && cb_entry.name_len == 6 &&
           memcmp(cb_entry.name, "Custom", 6) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_list_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE &&
           test_read_u16_le(dyn_response.data + 2) == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    dyn_response.length = 0;
    cb_entry.format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    cb_entry.name = NULL;
    cb_entry.name_len = 0;
    PCHECK(rdp_clipboard_write_format_list(&dyn_response, &cb_entry, 1, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_parse_packet(clip_data_request, sizeof(clip_data_request), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_request(&cb, &cb_data_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_request.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_request(&dyn_response,
                                                   RDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_data_request) &&
           memcmp(dyn_response.data, clip_data_request, sizeof(clip_data_request)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 1, "abc", 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_data_response.data_len == 3 &&
           memcmp(cb_data_response.data, "abc", 3) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_data_response.data_len == 0);
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, "x", 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_file_size_request,
                                      sizeof(clip_file_size_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x1122u &&
           cb_file_request.lindex == -1 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_SIZE &&
           cb_file_request.position == 0 &&
           cb_file_request.requested == 8 &&
           !cb_file_request.has_clip_data_id);
    PCHECK(rdp_clipboard_parse_packet(clip_file_range_request,
                                      sizeof(clip_file_range_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x2233u &&
           cb_file_request.lindex == 2 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
           cb_file_request.position == 0x0000000112345678ull &&
           cb_file_request.requested == 0x40 &&
           cb_file_request.has_clip_data_id &&
           cb_file_request.clip_data_id == 0x99);
    dyn_response.length = 0;
    error_info = 0x99u;
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x2233u,
                                                     2,
                                                     RDP_CLIPBOARD_FILECONTENTS_RANGE,
                                                     0x0000000112345678ull,
                                                     0x40,
                                                     &error_info) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data, clip_file_range_request, sizeof(clip_file_range_request)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x1122u,
                                                     -1,
                                                     RDP_CLIPBOARD_FILECONTENTS_SIZE,
                                                     0,
                                                     8,
                                                     NULL) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data, clip_file_size_request, sizeof(clip_file_size_request)) == 0);
    PCHECK(rdp_clipboard_write_file_contents_request(&dyn_response,
                                                     0x1122u,
                                                     -1,
                                                     RDP_CLIPBOARD_FILECONTENTS_SIZE,
                                                     1,
                                                     8,
                                                     NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_file_bad_request,
                                      sizeof(clip_file_bad_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 1, 0x1122u, "data", 4) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 4 &&
           memcmp(cb_file_response.data, "data", 4) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 0, 0x1122u, NULL, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 0);
    {
        const uint8_t file_name[] = {'c', 0, 'l', 0, 'i', 0, 'p', 0, '.', 0, 't', 0, 'x', 0, 't', 0};
        rdp_clipboard_file_descriptor file_desc;

        memset(&file_desc, 0, sizeof(file_desc));
        file_desc.name_utf16 = file_name;
        file_desc.name_utf16_len = sizeof(file_name);
        file_desc.size = 0x0000000212345678ull;
        file_desc.attributes = RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL;
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_hdrop(&dyn_response, &file_desc, 1) == LIBRDP_STATUS_OK);
        PCHECK(dyn_response.length == RDP_CLIPBOARD_DROPFILES_HEADER_SIZE + sizeof(file_name) + 4u);
        PCHECK(test_read_u32_le(dyn_response.data) == RDP_CLIPBOARD_DROPFILES_HEADER_SIZE &&
               test_read_u32_le(dyn_response.data + 16) == 1 &&
               memcmp(dyn_response.data + RDP_CLIPBOARD_DROPFILES_HEADER_SIZE,
                      file_name,
                      sizeof(file_name)) == 0);
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_file_group_descriptor_w(&dyn_response, &file_desc, 1) ==
               LIBRDP_STATUS_OK);
        PCHECK(dyn_response.length == 4u + RDP_CLIPBOARD_FILE_DESCRIPTORW_SIZE);
        PCHECK(test_read_u32_le(dyn_response.data) == 1 &&
               test_read_u32_le(dyn_response.data + 4) ==
                   (RDP_CLIPBOARD_FD_ATTRIBUTES | RDP_CLIPBOARD_FD_FILESIZE) &&
               test_read_u32_le(dyn_response.data + 40) == RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL &&
               test_read_u32_le(dyn_response.data + 68) == 2u &&
               test_read_u32_le(dyn_response.data + 72) == 0x12345678u &&
               memcmp(dyn_response.data + 76, file_name, sizeof(file_name)) == 0);
        file_desc.name_utf16_len--;
        dyn_response.length = 0;
        PCHECK(rdp_clipboard_write_hdrop(&dyn_response, &file_desc, 1) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_lock(&dyn_response, 0x99887766u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_lock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x99887766u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_unlock(&dyn_response, 0x66554433u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_unlock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x66554433u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_monitor_ready(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_MONITOR_READY &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu), &indication) ==
           LIBRDP_STATUS_OK);
    PCHECK(indication.initiator == 1004 && indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    PCHECK(indication.payload_len == 4 && indication.payload[0] == 1 && indication.payload[3] == 4);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu) - 1u, &indication) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);


    rdp_buffer_free(&dyn_response);
    return 0;
}
