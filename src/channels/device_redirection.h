#ifndef RDP_CHANNELS_DEVICE_REDIRECTION_H
#define RDP_CHANNELS_DEVICE_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_DEVICE_REDIRECTION_COMPONENT_CORE 0x4472u
#define RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER 0x5052u

#define RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_ANNOUNCE 0x496eu
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM 0x4343u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_NAME 0x434eu
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE 0x4441u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY 0x6472u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST 0x4952u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION 0x4943u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY 0x5350u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY 0x4350u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE 0x444du
#define RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA 0x5043u
#define RDP_DEVICE_REDIRECTION_PAKID_CORE_USER_LOGGEDON 0x554cu
#define RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS 0x5543u

#define RDP_DEVICE_REDIRECTION_VERSION_MAJOR 0x0001u
#define RDP_DEVICE_REDIRECTION_VERSION_MINOR_2 0x0002u
#define RDP_DEVICE_REDIRECTION_VERSION_MINOR_5 0x0005u
#define RDP_DEVICE_REDIRECTION_VERSION_MINOR_10 0x000au
#define RDP_DEVICE_REDIRECTION_VERSION_MINOR_12 0x000cu
#define RDP_DEVICE_REDIRECTION_VERSION_MINOR_13 0x000du

#define RDP_DEVICE_REDIRECTION_CAP_GENERAL 0x0001u
#define RDP_DEVICE_REDIRECTION_CAP_PRINTER 0x0002u
#define RDP_DEVICE_REDIRECTION_CAP_PORT 0x0003u
#define RDP_DEVICE_REDIRECTION_CAP_DRIVE 0x0004u
#define RDP_DEVICE_REDIRECTION_CAP_SMARTCARD 0x0005u

#define RDP_DEVICE_REDIRECTION_CAP_VERSION_1 0x00000001u
#define RDP_DEVICE_REDIRECTION_CAP_VERSION_2 0x00000002u

#define RDP_DEVICE_REDIRECTION_TYPE_SERIAL 0x00000001u
#define RDP_DEVICE_REDIRECTION_TYPE_PARALLEL 0x00000002u
#define RDP_DEVICE_REDIRECTION_TYPE_PRINTER 0x00000004u
#define RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM 0x00000008u
#define RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD 0x00000020u

#define RDP_DEVICE_REDIRECTION_IRP_CREATE 0x00000000u
#define RDP_DEVICE_REDIRECTION_IRP_CLOSE 0x00000002u
#define RDP_DEVICE_REDIRECTION_IRP_READ 0x00000003u
#define RDP_DEVICE_REDIRECTION_IRP_WRITE 0x00000004u
#define RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION 0x00000005u
#define RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION 0x00000006u
#define RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION 0x0000000au
#define RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION 0x0000000bu
#define RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL 0x0000000cu
#define RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL 0x0000000eu
#define RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL 0x00000011u

#define RDP_DEVICE_REDIRECTION_IRP_MASK_CREATE 0x00000001u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_CLEANUP 0x00000002u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_CLOSE 0x00000004u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_READ 0x00000008u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_WRITE 0x00000010u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_FLUSH_BUFFERS 0x00000020u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_SHUTDOWN 0x00000040u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_DEVICE_CONTROL 0x00000080u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_VOLUME_INFORMATION 0x00000100u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_SET_VOLUME_INFORMATION 0x00000200u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_INFORMATION 0x00000400u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_SET_INFORMATION 0x00000800u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_DIRECTORY_CONTROL 0x00001000u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_LOCK_CONTROL 0x00002000u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_SECURITY 0x00004000u
#define RDP_DEVICE_REDIRECTION_IRP_MASK_SET_SECURITY 0x00008000u

#define RDP_DEVICE_REDIRECTION_EXT_DEVICE_REMOVE 0x00000001u
#define RDP_DEVICE_REDIRECTION_EXT_CLIENT_DISPLAY_NAME 0x00000002u
#define RDP_DEVICE_REDIRECTION_EXT_USER_LOGGEDON 0x00000004u
#define RDP_DEVICE_REDIRECTION_EXTRA_ASYNCIO 0x00000001u

#define RDP_DEVICE_REDIRECTION_STATUS_SUCCESS 0x00000000u
#define RDP_DEVICE_REDIRECTION_MAX_CAPABILITIES 16u
#define RDP_DEVICE_REDIRECTION_MAX_DEVICES 64u

typedef struct rdp_device_redirection_header
{
    uint16_t component;
    uint16_t packet_id;
} rdp_device_redirection_header;

typedef struct rdp_device_redirection_announce
{
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t client_id;
} rdp_device_redirection_announce;

typedef struct rdp_device_redirection_client_name
{
    uint32_t unicode;
    uint32_t code_page;
    const uint8_t* name;
    uint32_t name_len;
} rdp_device_redirection_client_name;

typedef struct rdp_device_redirection_capability
{
    uint16_t type;
    uint16_t length;
    uint32_t version;
    const uint8_t* data;
    size_t data_len;
} rdp_device_redirection_capability;

typedef struct rdp_device_redirection_capability_list
{
    uint16_t count;
    rdp_device_redirection_capability capabilities[RDP_DEVICE_REDIRECTION_MAX_CAPABILITIES];
} rdp_device_redirection_capability_list;

typedef struct rdp_device_redirection_general_capability
{
    uint32_t version;
    uint32_t os_type;
    uint32_t os_version;
    uint16_t protocol_major_version;
    uint16_t protocol_minor_version;
    uint32_t io_code1;
    uint32_t io_code2;
    uint32_t extended_pdu;
    uint32_t extra_flags1;
    uint32_t extra_flags2;
    uint32_t special_type_device_cap;
} rdp_device_redirection_general_capability;

typedef struct rdp_device_redirection_capability_config
{
    rdp_device_redirection_general_capability general;
    uint8_t include_printer;
    uint8_t include_port;
    uint8_t include_drive;
    uint8_t include_smartcard;
} rdp_device_redirection_capability_config;

typedef struct rdp_device_redirection_device_announce
{
    uint32_t device_type;
    uint32_t device_id;
    char preferred_dos_name[8];
    uint32_t data_len;
    const uint8_t* data;
} rdp_device_redirection_device_announce;

typedef struct rdp_device_redirection_device_list
{
    uint32_t count;
    rdp_device_redirection_device_announce devices[RDP_DEVICE_REDIRECTION_MAX_DEVICES];
} rdp_device_redirection_device_list;

typedef struct rdp_device_redirection_device_remove
{
    uint32_t count;
    uint32_t device_ids[RDP_DEVICE_REDIRECTION_MAX_DEVICES];
} rdp_device_redirection_device_remove;

typedef struct rdp_device_redirection_device_reply
{
    uint32_t device_id;
    uint32_t result_code;
} rdp_device_redirection_device_reply;

typedef struct rdp_device_redirection_io_request
{
    uint32_t device_id;
    uint32_t file_id;
    uint32_t completion_id;
    uint32_t major_function;
    uint32_t minor_function;
    const uint8_t* payload;
    size_t payload_len;
} rdp_device_redirection_io_request;

typedef struct rdp_device_redirection_io_completion
{
    uint32_t device_id;
    uint32_t completion_id;
    uint32_t io_status;
    const uint8_t* payload;
    size_t payload_len;
} rdp_device_redirection_io_completion;

librdp_status rdp_device_redirection_parse_header(const void* data,
                                                  size_t length,
                                                  rdp_device_redirection_header* header);
librdp_status rdp_device_redirection_write_header(rdp_buffer* buffer, uint16_t component, uint16_t packet_id);
librdp_status rdp_device_redirection_parse_server_announce(const void* data,
                                                           size_t length,
                                                           rdp_device_redirection_announce* announce);
librdp_status rdp_device_redirection_write_server_announce(rdp_buffer* buffer,
                                                            uint16_t version_minor,
                                                            uint32_t client_id);
librdp_status rdp_device_redirection_parse_client_id_confirm(const void* data,
                                                             size_t length,
                                                             rdp_device_redirection_announce* confirm);
librdp_status rdp_device_redirection_write_client_announce(rdp_buffer* buffer,
                                                           uint16_t version_minor,
                                                           uint32_t client_id);
librdp_status rdp_device_redirection_parse_client_name(const void* data,
                                                       size_t length,
                                                       rdp_device_redirection_client_name* name);
librdp_status rdp_device_redirection_write_client_name_utf16le(rdp_buffer* buffer,
                                                               const void* name,
                                                               uint32_t name_len);
librdp_status rdp_device_redirection_parse_user_loggedon(const void* data, size_t length);
librdp_status rdp_device_redirection_write_user_loggedon(rdp_buffer* buffer);
librdp_status rdp_device_redirection_parse_capability_list(const void* data,
                                                           size_t length,
                                                           uint16_t expected_packet_id,
                                                           rdp_device_redirection_capability_list* list);
librdp_status rdp_device_redirection_write_capability_list(
    rdp_buffer* buffer,
    uint16_t packet_id,
    const rdp_device_redirection_capability* capabilities,
    uint16_t count);
librdp_status rdp_device_redirection_parse_general_capability(
    const rdp_device_redirection_capability* capability,
    rdp_device_redirection_general_capability* general);
librdp_status rdp_device_redirection_write_general_capability(
    rdp_buffer* buffer,
    const rdp_device_redirection_general_capability* general);
librdp_status rdp_device_redirection_make_default_capability_config(
    rdp_device_redirection_capability_config* config);
librdp_status rdp_device_redirection_write_client_capability_response(
    rdp_buffer* buffer,
    const rdp_device_redirection_capability_config* config);
librdp_status rdp_device_redirection_parse_device_list_announce(
    const void* data,
    size_t length,
    rdp_device_redirection_device_list* list);
librdp_status rdp_device_redirection_write_device_list_announce(
    rdp_buffer* buffer,
    const rdp_device_redirection_device_announce* devices,
    uint32_t count);
librdp_status rdp_device_redirection_parse_device_remove(const void* data,
                                                         size_t length,
                                                         rdp_device_redirection_device_remove* remove);
librdp_status rdp_device_redirection_write_device_remove(rdp_buffer* buffer,
                                                         const uint32_t* device_ids,
                                                         uint32_t count);
librdp_status rdp_device_redirection_parse_device_reply(const void* data,
                                                        size_t length,
                                                        rdp_device_redirection_device_reply* reply);
librdp_status rdp_device_redirection_write_device_reply(rdp_buffer* buffer,
                                                        uint32_t device_id,
                                                        uint32_t result_code);
librdp_status rdp_device_redirection_parse_io_request(const void* data,
                                                      size_t length,
                                                      rdp_device_redirection_io_request* request);
librdp_status rdp_device_redirection_write_io_request(rdp_buffer* buffer,
                                                      uint32_t device_id,
                                                      uint32_t file_id,
                                                      uint32_t completion_id,
                                                      uint32_t major_function,
                                                      uint32_t minor_function,
                                                      const void* payload,
                                                      size_t payload_len);
librdp_status rdp_device_redirection_parse_io_completion(const void* data,
                                                         size_t length,
                                                         rdp_device_redirection_io_completion* completion);
librdp_status rdp_device_redirection_write_io_completion(rdp_buffer* buffer,
                                                         uint32_t device_id,
                                                         uint32_t completion_id,
                                                         uint32_t io_status,
                                                         const void* payload,
                                                         size_t payload_len);

#endif
