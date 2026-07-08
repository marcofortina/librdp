#include "channels/device_redirection.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

#define RDP_DEVICE_REDIRECTION_GENERAL_CAPABILITY_V1_LENGTH 40u
#define RDP_DEVICE_REDIRECTION_GENERAL_CAPABILITY_V2_LENGTH 44u
#define RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH 8u
#define RDP_DEVICE_REDIRECTION_DEVICE_ANNOUNCE_HEADER_LENGTH 20u

static uint32_t rdp_device_redirection_default_io_code1(void)
{
    return RDP_DEVICE_REDIRECTION_IRP_MASK_CREATE |
           RDP_DEVICE_REDIRECTION_IRP_MASK_CLEANUP |
           RDP_DEVICE_REDIRECTION_IRP_MASK_CLOSE |
           RDP_DEVICE_REDIRECTION_IRP_MASK_READ |
           RDP_DEVICE_REDIRECTION_IRP_MASK_WRITE |
           RDP_DEVICE_REDIRECTION_IRP_MASK_FLUSH_BUFFERS |
           RDP_DEVICE_REDIRECTION_IRP_MASK_SHUTDOWN |
           RDP_DEVICE_REDIRECTION_IRP_MASK_DEVICE_CONTROL |
           RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_VOLUME_INFORMATION |
           RDP_DEVICE_REDIRECTION_IRP_MASK_SET_VOLUME_INFORMATION |
           RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_INFORMATION |
           RDP_DEVICE_REDIRECTION_IRP_MASK_SET_INFORMATION |
           RDP_DEVICE_REDIRECTION_IRP_MASK_DIRECTORY_CONTROL |
           RDP_DEVICE_REDIRECTION_IRP_MASK_LOCK_CONTROL;
}

static int rdp_device_redirection_valid_version_minor(uint16_t version_minor)
{
    return version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_2 ||
           version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_5 ||
           version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_10 ||
           version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_12 ||
           version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_13;
}

static librdp_status rdp_device_redirection_expect_header(const void* data,
                                                          size_t length,
                                                          uint16_t expected_component,
                                                          uint16_t expected_packet_id,
                                                          rdp_stream* stream)
{
    rdp_device_redirection_header header;

    if (!data || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_device_redirection_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.component != expected_component || header.packet_id != expected_packet_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, data, length);
    if (rdp_stream_skip(stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_device_redirection_parse_announce_common(const void* data,
                                                                  size_t length,
                                                                  uint16_t expected_packet_id,
                                                                  rdp_device_redirection_announce* announce)
{
    rdp_stream stream;

    if (!data || !announce)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(announce, 0, sizeof(*announce));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             expected_packet_id,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_le(&stream, &announce->version_major) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &announce->version_minor) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->client_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (announce->version_major != RDP_DEVICE_REDIRECTION_VERSION_MAJOR ||
        !rdp_device_redirection_valid_version_minor(announce->version_minor))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_device_redirection_write_capability_header(rdp_buffer* buffer,
                                                                    uint16_t type,
                                                                    uint16_t length,
                                                                    uint32_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || length < RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, version);
}

static librdp_status rdp_device_redirection_write_headered_capability(rdp_buffer* buffer,
                                                                      uint16_t type,
                                                                      uint32_t version)
{
    return rdp_device_redirection_write_capability_header(buffer,
                                                          type,
                                                          RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH,
                                                          version);
}

static int rdp_device_redirection_valid_device_type(uint32_t device_type)
{
    return device_type == RDP_DEVICE_REDIRECTION_TYPE_SERIAL ||
           device_type == RDP_DEVICE_REDIRECTION_TYPE_PARALLEL ||
           device_type == RDP_DEVICE_REDIRECTION_TYPE_PRINTER ||
           device_type == RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM ||
           device_type == RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD;
}

static int rdp_device_redirection_valid_preferred_name(uint32_t device_type, const char name[8])
{
    size_t i = 0;
    size_t end = 8u;

    if (!name)
        return 0;
    for (i = 0; i < 8u; i++)
    {
        if (name[i] == '\0')
        {
            end = i;
            break;
        }
        if (name[i] == '<' || name[i] == '>' || name[i] == '"' ||
            name[i] == '/' || name[i] == '\\' || name[i] == '|')
            return 0;
    }
    if (end == 8u)
        return 0;
    for (i = 0; i < end; i++)
    {
        if (name[i] == ':' && i + 1u != end)
            return 0;
    }
    if (device_type == RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD)
        return end == 5u && memcmp(name, "SCARD", 5u) == 0;
    return 1;
}

static librdp_status rdp_device_redirection_append_device(rdp_buffer* buffer,
                                                          const rdp_device_redirection_device_announce* device)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !device || (device->data_len > 0 && !device->data) ||
        !rdp_device_redirection_valid_device_type(device->device_type) ||
        !rdp_device_redirection_valid_preferred_name(device->device_type, device->preferred_dos_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (device->data_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, device->device_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device->device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, device->preferred_dos_name, sizeof(device->preferred_dos_name));
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device->data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, device->data, device->data_len);
}

librdp_status rdp_device_redirection_parse_header(const void* data,
                                                  size_t length,
                                                  rdp_device_redirection_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->component) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->packet_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_header(rdp_buffer* buffer, uint16_t component, uint16_t packet_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, component);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, packet_id);
}

librdp_status rdp_device_redirection_parse_server_announce(const void* data,
                                                           size_t length,
                                                           rdp_device_redirection_announce* announce)
{
    return rdp_device_redirection_parse_announce_common(data,
                                                        length,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_ANNOUNCE,
                                                        announce);
}

librdp_status rdp_device_redirection_parse_client_id_confirm(const void* data,
                                                             size_t length,
                                                             rdp_device_redirection_announce* confirm)
{
    return rdp_device_redirection_parse_announce_common(data,
                                                        length,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM,
                                                        confirm);
}

librdp_status rdp_device_redirection_write_client_announce(rdp_buffer* buffer,
                                                           uint16_t version_minor,
                                                           uint32_t client_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_device_redirection_valid_version_minor(version_minor))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, RDP_DEVICE_REDIRECTION_VERSION_MAJOR);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, version_minor);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, client_id);
}

librdp_status rdp_device_redirection_parse_client_name(const void* data,
                                                       size_t length,
                                                       rdp_device_redirection_client_name* name)
{
    rdp_stream stream;

    if (!data || !name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(name, 0, sizeof(*name));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_NAME,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &name->unicode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &name->code_page) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &name->name_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (name->name_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &name->name, name->name_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_client_name_utf16le(rdp_buffer* buffer,
                                                               const void* name,
                                                               uint32_t name_len)
{
    const uint8_t* bytes = (const uint8_t*)name;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !bytes || name_len < 2u || (name_len & 1u) != 0 ||
        bytes[name_len - 1u] != 0 || bytes[name_len - 2u] != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_NAME);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, bytes, name_len);
}

librdp_status rdp_device_redirection_parse_capability_list(const void* data,
                                                           size_t length,
                                                           uint16_t expected_packet_id,
                                                           rdp_device_redirection_capability_list* list)
{
    rdp_stream stream;
    uint16_t padding = 0;
    uint16_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             expected_packet_id,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_le(&stream, &list->count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &padding) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)padding;
    if (list->count > RDP_DEVICE_REDIRECTION_MAX_CAPABILITIES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < list->count; i++)
    {
        rdp_device_redirection_capability* capability = &list->capabilities[i];
        size_t remaining_before = rdp_stream_remaining(&stream);

        if (remaining_before < RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH ||
            rdp_stream_read_u16_le(&stream, &capability->type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &capability->length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &capability->version) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (capability->length < RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH ||
            capability->length > remaining_before)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        capability->data_len = (size_t)capability->length - RDP_DEVICE_REDIRECTION_CAPABILITY_HEADER_LENGTH;
        if (rdp_stream_read_bytes(&stream, &capability->data, capability->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_parse_general_capability(
    const rdp_device_redirection_capability* capability,
    rdp_device_redirection_general_capability* general)
{
    rdp_stream stream;

    if (!capability || !general)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capability->type != RDP_DEVICE_REDIRECTION_CAP_GENERAL)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((capability->version == RDP_DEVICE_REDIRECTION_CAP_VERSION_1 &&
         capability->length != RDP_DEVICE_REDIRECTION_GENERAL_CAPABILITY_V1_LENGTH) ||
        (capability->version == RDP_DEVICE_REDIRECTION_CAP_VERSION_2 &&
         capability->length != RDP_DEVICE_REDIRECTION_GENERAL_CAPABILITY_V2_LENGTH))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(general, 0, sizeof(*general));
    general->version = capability->version;
    rdp_stream_init(&stream, capability->data, capability->data_len);
    if (rdp_stream_read_u32_le(&stream, &general->os_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->os_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->protocol_major_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &general->protocol_minor_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->io_code1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->io_code2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->extended_pdu) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->extra_flags1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &general->extra_flags2) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (general->version == RDP_DEVICE_REDIRECTION_CAP_VERSION_2 &&
        rdp_stream_read_u32_le(&stream, &general->special_type_device_cap) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (general->protocol_major_version != RDP_DEVICE_REDIRECTION_VERSION_MAJOR ||
        !rdp_device_redirection_valid_version_minor(general->protocol_minor_version))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_make_default_capability_config(
    rdp_device_redirection_capability_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->general.version = RDP_DEVICE_REDIRECTION_CAP_VERSION_2;
    config->general.protocol_major_version = RDP_DEVICE_REDIRECTION_VERSION_MAJOR;
    config->general.protocol_minor_version = RDP_DEVICE_REDIRECTION_VERSION_MINOR_13;
    config->general.io_code1 = rdp_device_redirection_default_io_code1();
    config->general.extended_pdu = RDP_DEVICE_REDIRECTION_EXT_DEVICE_REMOVE |
                                   RDP_DEVICE_REDIRECTION_EXT_CLIENT_DISPLAY_NAME |
                                   RDP_DEVICE_REDIRECTION_EXT_USER_LOGGEDON;
    config->general.extra_flags1 = RDP_DEVICE_REDIRECTION_EXTRA_ASYNCIO;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_client_capability_response(
    rdp_buffer* buffer,
    const rdp_device_redirection_capability_config* config)
{
    uint16_t count = 1u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !config ||
        config->general.version != RDP_DEVICE_REDIRECTION_CAP_VERSION_2 ||
        config->general.protocol_major_version != RDP_DEVICE_REDIRECTION_VERSION_MAJOR ||
        !rdp_device_redirection_valid_version_minor(config->general.protocol_minor_version))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (config->include_printer)
        count++;
    if (config->include_port)
        count++;
    if (config->include_drive)
        count++;
    if (config->include_smartcard)
        count++;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_device_redirection_write_capability_header(
        buffer,
        RDP_DEVICE_REDIRECTION_CAP_GENERAL,
        RDP_DEVICE_REDIRECTION_GENERAL_CAPABILITY_V2_LENGTH,
        RDP_DEVICE_REDIRECTION_CAP_VERSION_2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.os_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.os_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, config->general.protocol_major_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, config->general.protocol_minor_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.io_code1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.io_code2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.extended_pdu);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.extra_flags1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.extra_flags2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, config->general.special_type_device_cap);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (config->include_printer)
    {
        status = rdp_device_redirection_write_headered_capability(buffer,
                                                                  RDP_DEVICE_REDIRECTION_CAP_PRINTER,
                                                                  RDP_DEVICE_REDIRECTION_CAP_VERSION_1);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (config->include_port)
    {
        status = rdp_device_redirection_write_headered_capability(buffer,
                                                                  RDP_DEVICE_REDIRECTION_CAP_PORT,
                                                                  RDP_DEVICE_REDIRECTION_CAP_VERSION_1);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (config->include_drive)
    {
        status = rdp_device_redirection_write_headered_capability(buffer,
                                                                  RDP_DEVICE_REDIRECTION_CAP_DRIVE,
                                                                  RDP_DEVICE_REDIRECTION_CAP_VERSION_2);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (config->include_smartcard)
    {
        status = rdp_device_redirection_write_headered_capability(buffer,
                                                                  RDP_DEVICE_REDIRECTION_CAP_SMARTCARD,
                                                                  RDP_DEVICE_REDIRECTION_CAP_VERSION_1);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_parse_device_list_announce(
    const void* data,
    size_t length,
    rdp_device_redirection_device_list* list)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(list, 0, sizeof(*list));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &list->count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (list->count > RDP_DEVICE_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < list->count; i++)
    {
        rdp_device_redirection_device_announce* device = &list->devices[i];
        const uint8_t* name = NULL;

        if (rdp_stream_remaining(&stream) < RDP_DEVICE_REDIRECTION_DEVICE_ANNOUNCE_HEADER_LENGTH ||
            rdp_stream_read_u32_le(&stream, &device->device_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &device->device_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_bytes(&stream, &name, 8u) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &device->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        memcpy(device->preferred_dos_name, name, sizeof(device->preferred_dos_name));
        if (device->data_len > rdp_stream_remaining(&stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(&stream, &device->data, device->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_device_list_announce(
    rdp_buffer* buffer,
    const rdp_device_redirection_device_announce* devices,
    uint32_t count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (count > 0 && !devices) || count > RDP_DEVICE_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        status = rdp_device_redirection_append_device(buffer, &devices[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_parse_device_remove(const void* data,
                                                         size_t length,
                                                         rdp_device_redirection_device_remove* remove)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !remove)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(remove, 0, sizeof(*remove));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &remove->count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (remove->count > RDP_DEVICE_REDIRECTION_MAX_DEVICES ||
        rdp_stream_remaining(&stream) != (size_t)remove->count * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < remove->count; i++)
    {
        if (rdp_stream_read_u32_le(&stream, &remove->device_ids[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_device_remove(rdp_buffer* buffer,
                                                         const uint32_t* device_ids,
                                                         uint32_t count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (count > 0 && !device_ids) || count > RDP_DEVICE_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < count; i++)
    {
        status = rdp_buffer_append_u32_le(buffer, device_ids[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_parse_device_reply(const void* data,
                                                        size_t length,
                                                        rdp_device_redirection_device_reply* reply)
{
    rdp_stream stream;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(reply, 0, sizeof(*reply));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &reply->device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reply->result_code) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_device_reply(rdp_buffer* buffer,
                                                        uint32_t device_id,
                                                        uint32_t result_code)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result_code);
}

librdp_status rdp_device_redirection_parse_io_request(const void* data,
                                                      size_t length,
                                                      rdp_device_redirection_io_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &request->device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->file_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->completion_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->major_function) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->minor_function) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &request->payload, request->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_parse_io_completion(const void* data,
                                                         size_t length,
                                                         rdp_device_redirection_io_completion* completion)
{
    rdp_stream stream;

    if (!data || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(completion, 0, sizeof(*completion));
    if (rdp_device_redirection_expect_header(data,
                                             length,
                                             RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION,
                                             &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &completion->device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &completion->completion_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &completion->io_status) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    completion->payload_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &completion->payload, completion->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_device_redirection_write_io_completion(rdp_buffer* buffer,
                                                         uint32_t device_id,
                                                         uint32_t completion_id,
                                                         uint32_t io_status,
                                                         const void* payload,
                                                         size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, io_status);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}
