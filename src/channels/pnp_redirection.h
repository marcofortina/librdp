/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: plug-and-play redirection device declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_PNP_REDIRECTION_H
#define RDP_CHANNELS_PNP_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_PNP_REDIRECTION_INFO_VERSION 0x00000065u
#define RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES 0x00000066u
#define RDP_PNP_REDIRECTION_INFO_SERVER_LOGON 0x00000067u
#define RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE 0x00000068u

#define RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES 0x00000001u
#define RDP_PNP_REDIRECTION_IO_VERSION_4 0x0004u
#define RDP_PNP_REDIRECTION_IO_VERSION_6 0x0006u

#define RDP_PNP_REDIRECTION_IO_READ_REQUEST 0x00000000u
#define RDP_PNP_REDIRECTION_IO_WRITE_REQUEST 0x00000001u
#define RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST 0x00000002u
#define RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST 0x00000004u
#define RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST 0x00000005u
#define RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST 0x00000006u

#define RDP_PNP_REDIRECTION_PACKET_RESPONSE 0x00u
#define RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT 0x01u

#define RDP_PNP_REDIRECTION_CUSTOM_FLAG_REDIRECTABLE 0x00000000u
#define RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_1 0x00000001u
#define RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_2 0x00000002u

#define RDP_PNP_REDIRECTION_DEVCAPS_LOCKSUPPORTED 0x00000001u
#define RDP_PNP_REDIRECTION_DEVCAPS_EJECTSUPPORTED 0x00000002u
#define RDP_PNP_REDIRECTION_DEVCAPS_REMOVABLE 0x00000004u
#define RDP_PNP_REDIRECTION_DEVCAPS_SURPRISEREMOVALOK 0x00000008u

#define RDP_PNP_REDIRECTION_MAX_DEVICES 32u

typedef struct rdp_pnp_redirection_info_header
{
    uint32_t size;
    uint32_t packet_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_pnp_redirection_info_header;

typedef struct rdp_pnp_redirection_version
{
    rdp_pnp_redirection_info_header header;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t capabilities;
} rdp_pnp_redirection_version;

typedef struct rdp_pnp_redirection_device_description
{
    uint32_t client_device_id;
    uint32_t data_size;
    const uint8_t* interface_guids;
    uint32_t interface_guids_len;
    const uint8_t* hardware_id;
    uint32_t hardware_id_len;
    const uint8_t* compatibility_id;
    uint32_t compatibility_id_len;
    const uint8_t* device_description;
    uint32_t device_description_len;
    uint32_t custom_flag;
    const uint8_t* container_id;
    uint32_t container_id_len;
    uint8_t has_container_id;
    uint32_t device_caps;
    uint8_t has_device_caps;
} rdp_pnp_redirection_device_description;

typedef struct rdp_pnp_redirection_device_addition
{
    rdp_pnp_redirection_info_header header;
    uint32_t device_count;
    rdp_pnp_redirection_device_description devices[RDP_PNP_REDIRECTION_MAX_DEVICES];
} rdp_pnp_redirection_device_addition;

typedef struct rdp_pnp_redirection_device_removal
{
    rdp_pnp_redirection_info_header header;
    uint32_t client_device_id;
} rdp_pnp_redirection_device_removal;

typedef struct rdp_pnp_redirection_server_io_header
{
    uint32_t request_id;
    uint8_t unused;
    uint32_t function_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_pnp_redirection_server_io_header;

typedef struct rdp_pnp_redirection_client_io_header
{
    uint32_t request_id;
    uint8_t packet_type;
    const uint8_t* payload;
    size_t payload_len;
} rdp_pnp_redirection_client_io_header;

typedef struct rdp_pnp_redirection_io_version
{
    rdp_pnp_redirection_server_io_header header;
    uint16_t version;
} rdp_pnp_redirection_io_version;

typedef struct rdp_pnp_redirection_create_request
{
    rdp_pnp_redirection_server_io_header header;
    uint32_t device_id;
    uint32_t desired_access;
    uint32_t share_mode;
    uint32_t creation_disposition;
    uint32_t flags_and_attributes;
} rdp_pnp_redirection_create_request;

typedef struct rdp_pnp_redirection_read_request
{
    rdp_pnp_redirection_server_io_header header;
    uint32_t bytes_to_read;
    uint32_t offset_high;
    uint32_t offset_low;
} rdp_pnp_redirection_read_request;

typedef struct rdp_pnp_redirection_write_request
{
    rdp_pnp_redirection_server_io_header header;
    uint32_t bytes_to_write;
    uint32_t offset_high;
    uint32_t offset_low;
    const uint8_t* data;
} rdp_pnp_redirection_write_request;

typedef struct rdp_pnp_redirection_control_request
{
    rdp_pnp_redirection_server_io_header header;
    uint32_t io_code;
    uint32_t input_len;
    uint32_t output_len;
    const uint8_t* input;
    const uint8_t* output;
    uint32_t actual_output_len;
} rdp_pnp_redirection_control_request;

typedef struct rdp_pnp_redirection_cancel_request
{
    rdp_pnp_redirection_server_io_header header;
    uint8_t unused;
    uint32_t id_to_cancel;
} rdp_pnp_redirection_cancel_request;

typedef struct rdp_pnp_redirection_custom_event
{
    rdp_pnp_redirection_client_io_header header;
    uint8_t event_guid[16];
    const uint8_t* data;
    uint32_t data_len;
} rdp_pnp_redirection_custom_event;

typedef struct rdp_pnp_redirection_status_reply
{
    rdp_pnp_redirection_client_io_header header;
    uint32_t result;
} rdp_pnp_redirection_status_reply;

typedef struct rdp_pnp_redirection_read_reply
{
    rdp_pnp_redirection_client_io_header header;
    uint32_t result;
    uint32_t data_len;
    const uint8_t* data;
} rdp_pnp_redirection_read_reply;

typedef struct rdp_pnp_redirection_write_reply
{
    rdp_pnp_redirection_client_io_header header;
    uint32_t result;
    uint32_t bytes_written;
} rdp_pnp_redirection_write_reply;

typedef struct rdp_pnp_redirection_control_reply
{
    rdp_pnp_redirection_client_io_header header;
    uint32_t result;
    uint32_t data_len;
    const uint8_t* data;
} rdp_pnp_redirection_control_reply;

librdp_status rdp_pnp_redirection_parse_info_header(const void* data,
                                                    size_t length,
                                                    rdp_pnp_redirection_info_header* header);
librdp_status rdp_pnp_redirection_write_version(rdp_buffer* buffer,
                                                uint32_t major_version,
                                                uint32_t minor_version,
                                                uint32_t capabilities);
librdp_status rdp_pnp_redirection_parse_version(const void* data,
                                                size_t length,
                                                rdp_pnp_redirection_version* version);
librdp_status rdp_pnp_redirection_parse_authenticated(const void* data,
                                                      size_t length,
                                                      rdp_pnp_redirection_info_header* header);
librdp_status rdp_pnp_redirection_write_authenticated(rdp_buffer* buffer);
librdp_status rdp_pnp_redirection_parse_device_description(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_description* description);
librdp_status rdp_pnp_redirection_write_device_addition(
    rdp_buffer* buffer,
    const rdp_pnp_redirection_device_description* devices,
    uint32_t device_count);
librdp_status rdp_pnp_redirection_parse_device_addition(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_addition* addition);
librdp_status rdp_pnp_redirection_write_device_removal(rdp_buffer* buffer,
                                                       uint32_t client_device_id);
librdp_status rdp_pnp_redirection_parse_device_removal(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_removal* removal);
librdp_status rdp_pnp_redirection_parse_server_io_header(
    const void* data,
    size_t length,
    rdp_pnp_redirection_server_io_header* header);
librdp_status rdp_pnp_redirection_parse_client_io_header(
    const void* data,
    size_t length,
    rdp_pnp_redirection_client_io_header* header);
librdp_status rdp_pnp_redirection_write_server_io_header(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t unused,
                                                        uint32_t function_id);
librdp_status rdp_pnp_redirection_write_client_io_header(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t packet_type);
librdp_status rdp_pnp_redirection_parse_capabilities_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_io_version* version);
librdp_status rdp_pnp_redirection_write_capabilities_request(rdp_buffer* buffer,
                                                             uint32_t request_id,
                                                             uint8_t unused,
                                                             uint16_t version);
librdp_status rdp_pnp_redirection_write_capabilities_reply(rdp_buffer* buffer,
                                                           uint32_t request_id,
                                                           uint16_t version);
librdp_status rdp_pnp_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_create_request* request);
librdp_status rdp_pnp_redirection_write_create_request(rdp_buffer* buffer,
                                                       uint32_t request_id,
                                                       uint8_t unused,
                                                       uint32_t device_id,
                                                       uint32_t desired_access,
                                                       uint32_t share_mode,
                                                       uint32_t creation_disposition,
                                                       uint32_t flags_and_attributes);
librdp_status rdp_pnp_redirection_write_status_reply(rdp_buffer* buffer,
                                                     uint32_t request_id,
                                                     uint32_t result);
librdp_status rdp_pnp_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_read_request* request);
librdp_status rdp_pnp_redirection_write_read_request(rdp_buffer* buffer,
                                                     uint32_t request_id,
                                                     uint8_t unused,
                                                     uint32_t bytes_to_read,
                                                     uint32_t offset_high,
                                                     uint32_t offset_low);
librdp_status rdp_pnp_redirection_write_read_reply(rdp_buffer* buffer,
                                                   uint32_t request_id,
                                                   uint32_t result,
                                                   const uint8_t* data,
                                                   uint32_t data_len);
librdp_status rdp_pnp_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_write_request* request);
librdp_status rdp_pnp_redirection_write_write_request(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      uint8_t unused,
                                                      uint32_t offset_high,
                                                      uint32_t offset_low,
                                                      const uint8_t* data,
                                                      uint32_t data_len);
librdp_status rdp_pnp_redirection_write_write_reply(rdp_buffer* buffer,
                                                    uint32_t request_id,
                                                    uint32_t result,
                                                    uint32_t bytes_written);
librdp_status rdp_pnp_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_control_request* request);
librdp_status rdp_pnp_redirection_write_control_request(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t unused,
                                                        uint32_t io_code,
                                                        const uint8_t* input,
                                                        uint32_t input_len,
                                                        uint32_t output_len,
                                                        const uint8_t* output,
                                                        uint32_t actual_output_len);
librdp_status rdp_pnp_redirection_write_control_reply(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      uint32_t result,
                                                      const uint8_t* data,
                                                      uint32_t data_len);
librdp_status rdp_pnp_redirection_parse_cancel_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_cancel_request* request);
librdp_status rdp_pnp_redirection_write_cancel_request(rdp_buffer* buffer,
                                                       uint32_t request_id,
                                                       uint8_t unused,
                                                       uint8_t cancel_unused,
                                                       uint32_t id_to_cancel);
librdp_status rdp_pnp_redirection_write_custom_event(rdp_buffer* buffer,
                                                     const uint8_t event_guid[16],
                                                     const uint8_t* data,
                                                     uint32_t data_len);
librdp_status rdp_pnp_redirection_parse_custom_event(const void* data,
                                                     size_t length,
                                                     rdp_pnp_redirection_custom_event* event);
librdp_status rdp_pnp_redirection_parse_status_reply(const void* data,
                                                     size_t length,
                                                     rdp_pnp_redirection_status_reply* reply);
librdp_status rdp_pnp_redirection_parse_read_reply(const void* data,
                                                   size_t length,
                                                   rdp_pnp_redirection_read_reply* reply);
librdp_status rdp_pnp_redirection_parse_write_reply(const void* data,
                                                    size_t length,
                                                    rdp_pnp_redirection_write_reply* reply);
librdp_status rdp_pnp_redirection_parse_control_reply(const void* data,
                                                      size_t length,
                                                      rdp_pnp_redirection_control_reply* reply);

#endif
