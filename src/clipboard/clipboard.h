/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_CLIPBOARD_CLIPBOARD_H
#define RDP_CLIPBOARD_CLIPBOARD_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_CLIPBOARD_CB_MONITOR_READY 0x0001u
#define RDP_CLIPBOARD_CB_FORMAT_LIST 0x0002u
#define RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE 0x0003u
#define RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST 0x0004u
#define RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE 0x0005u
#define RDP_CLIPBOARD_CB_TEMP_DIRECTORY 0x0006u
#define RDP_CLIPBOARD_CB_CLIP_CAPS 0x0007u
#define RDP_CLIPBOARD_CB_FILECONTENTS_REQUEST 0x0008u
#define RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE 0x0009u
#define RDP_CLIPBOARD_CB_LOCK_CLIPDATA 0x000au
#define RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA 0x000bu

#define RDP_CLIPBOARD_CB_RESPONSE_OK 0x0001u
#define RDP_CLIPBOARD_CB_RESPONSE_FAIL 0x0002u
#define RDP_CLIPBOARD_CB_ASCII_NAMES 0x0004u

#define RDP_CLIPBOARD_CAPSTYPE_GENERAL 0x0001u
#define RDP_CLIPBOARD_CAPS_VERSION_1 0x00000001u
#define RDP_CLIPBOARD_CAPS_VERSION_2 0x00000002u
#define RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES 0x00000002u
#define RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED 0x00000004u
#define RDP_CLIPBOARD_CAP_FILECLIP_NO_FILE_PATHS 0x00000008u
#define RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA 0x00000010u
#define RDP_CLIPBOARD_CAP_HUGE_FILE_SUPPORT_ENABLED 0x00000020u

#define RDP_CLIPBOARD_FILECONTENTS_SIZE 0x00000001u
#define RDP_CLIPBOARD_FILECONTENTS_RANGE 0x00000002u

#define RDP_CLIPBOARD_FORMAT_TEXT 1u
#define RDP_CLIPBOARD_FORMAT_BITMAP 2u
#define RDP_CLIPBOARD_FORMAT_DIB 8u
#define RDP_CLIPBOARD_FORMAT_UNICODETEXT 13u
#define RDP_CLIPBOARD_FORMAT_HDROP 15u
#define RDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW 0xc001u
#define RDP_CLIPBOARD_FORMAT_FILECONTENTS 0xc002u
#define RDP_CLIPBOARD_FILE_DESCRIPTORW_SIZE 592u
#define RDP_CLIPBOARD_DROPFILES_HEADER_SIZE 20u
#define RDP_CLIPBOARD_FD_ATTRIBUTES 0x00000004u
#define RDP_CLIPBOARD_FD_FILESIZE 0x00000040u
#define RDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL 0x00000080u

typedef struct rdp_clipboard_packet
{
    uint16_t type;
    uint16_t flags;
    uint32_t length;
    const uint8_t* payload;
    size_t payload_len;
} rdp_clipboard_packet;

typedef struct rdp_clipboard_general_capability
{
    uint32_t version;
    uint32_t general_flags;
} rdp_clipboard_general_capability;

typedef struct rdp_clipboard_capabilities
{
    uint16_t count;
    uint8_t has_general;
    rdp_clipboard_general_capability general;
} rdp_clipboard_capabilities;

typedef struct rdp_clipboard_format_list
{
    uint16_t flags;
    const uint8_t* data;
    size_t data_len;
} rdp_clipboard_format_list;

typedef struct rdp_clipboard_format_entry
{
    uint32_t format_id;
    const uint8_t* name;
    size_t name_len;
} rdp_clipboard_format_entry;

typedef struct rdp_clipboard_format_data_request
{
    uint32_t format_id;
} rdp_clipboard_format_data_request;

typedef struct rdp_clipboard_format_data_response
{
    uint16_t response_flags;
    const uint8_t* data;
    size_t data_len;
} rdp_clipboard_format_data_response;

typedef struct rdp_clipboard_file_contents_request
{
    uint32_t stream_id;
    int32_t lindex;
    uint32_t flags;
    uint64_t position;
    uint32_t requested;
    uint8_t has_clip_data_id;
    uint32_t clip_data_id;
} rdp_clipboard_file_contents_request;

typedef struct rdp_clipboard_file_contents_response
{
    uint16_t response_flags;
    uint32_t stream_id;
    const uint8_t* data;
    size_t data_len;
} rdp_clipboard_file_contents_response;

typedef struct rdp_clipboard_lock
{
    uint32_t clip_data_id;
} rdp_clipboard_lock;

typedef struct rdp_clipboard_file_descriptor
{
    const uint8_t* name_utf16;
    size_t name_utf16_len;
    uint64_t size;
    uint32_t attributes;
} rdp_clipboard_file_descriptor;

librdp_status rdp_clipboard_parse_packet(const void* data, size_t length, rdp_clipboard_packet* packet);
librdp_status rdp_clipboard_write_header(rdp_buffer* buffer, uint16_t type, uint16_t flags, uint32_t data_len);
librdp_status rdp_clipboard_write_monitor_ready(rdp_buffer* buffer);
librdp_status rdp_clipboard_parse_capabilities(const rdp_clipboard_packet* packet,
                                               rdp_clipboard_capabilities* capabilities);
librdp_status rdp_clipboard_write_capabilities(rdp_buffer* buffer, uint32_t general_flags);
librdp_status rdp_clipboard_parse_format_list(const rdp_clipboard_packet* packet,
                                              rdp_clipboard_format_list* list);
librdp_status rdp_clipboard_write_format_list(rdp_buffer* buffer,
                                              const rdp_clipboard_format_entry* entries,
                                              uint32_t count,
                                              int long_names);
librdp_status rdp_clipboard_format_list_entry_count(const rdp_clipboard_format_list* list,
                                                    int long_names,
                                                    uint32_t* count);
librdp_status rdp_clipboard_format_list_get_entry(const rdp_clipboard_format_list* list,
                                                  int long_names,
                                                  uint32_t index,
                                                  rdp_clipboard_format_entry* entry);
librdp_status rdp_clipboard_write_format_list_response(rdp_buffer* buffer, int ok);
librdp_status rdp_clipboard_write_format_data_request(rdp_buffer* buffer, uint32_t format_id);
librdp_status rdp_clipboard_parse_format_data_request(const rdp_clipboard_packet* packet,
                                                      rdp_clipboard_format_data_request* request);
librdp_status rdp_clipboard_write_format_data_response(rdp_buffer* buffer,
                                                       int ok,
                                                       const void* data,
                                                       size_t data_len);
librdp_status rdp_clipboard_parse_format_data_response(const rdp_clipboard_packet* packet,
                                                       rdp_clipboard_format_data_response* response);
librdp_status rdp_clipboard_parse_file_contents_request(const rdp_clipboard_packet* packet,
                                                        rdp_clipboard_file_contents_request* request);
librdp_status rdp_clipboard_write_file_contents_request(rdp_buffer* buffer,
                                                        uint32_t stream_id,
                                                        int32_t lindex,
                                                        uint32_t flags,
                                                        uint64_t position,
                                                        uint32_t requested,
                                                        const uint32_t* clip_data_id);
librdp_status rdp_clipboard_write_file_contents_response(rdp_buffer* buffer,
                                                        int ok,
                                                        uint32_t stream_id,
                                                        const void* data,
                                                        size_t data_len);
librdp_status rdp_clipboard_parse_file_contents_response(const rdp_clipboard_packet* packet,
                                                         rdp_clipboard_file_contents_response* response);
librdp_status rdp_clipboard_write_lock(rdp_buffer* buffer, uint32_t clip_data_id);
librdp_status rdp_clipboard_write_unlock(rdp_buffer* buffer, uint32_t clip_data_id);
librdp_status rdp_clipboard_parse_lock(const rdp_clipboard_packet* packet, rdp_clipboard_lock* lock);
librdp_status rdp_clipboard_parse_unlock(const rdp_clipboard_packet* packet, rdp_clipboard_lock* lock);
librdp_status rdp_clipboard_write_hdrop(rdp_buffer* buffer,
                                        const rdp_clipboard_file_descriptor* files,
                                        uint32_t count);
librdp_status rdp_clipboard_write_file_group_descriptor_w(rdp_buffer* buffer,
                                                          const rdp_clipboard_file_descriptor* files,
                                                          uint32_t count);

#endif
