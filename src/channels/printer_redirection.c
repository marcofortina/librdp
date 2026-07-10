#include "channels/printer_redirection.h"

#include "channels/device_redirection.h"
#include "common/stream.h"

#include <string.h>

#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FIXED_LENGTH 24u
#define RDP_PRINTER_REDIRECTION_KNOWN_FLAGS 0x0000001fu

static int rdp_printer_redirection_valid_utf16le(const uint8_t* data, uint32_t length)
{
    if (length == 0)
        return 1;
    if (!data || length < 2u || (length & 1u) != 0)
        return 0;
    return data[length - 2u] == 0 && data[length - 1u] == 0;
}

static librdp_status rdp_printer_redirection_read_blob(rdp_stream* stream,
                                                       uint32_t length,
                                                       const uint8_t** data)
{
    if (!stream || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    if (length == 0)
        return LIBRDP_STATUS_OK;
    if (rdp_stream_read_bytes(stream, data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_printer_redirection_expect_header(const void* data,
                                                           size_t length,
                                                           uint16_t expected_packet_id,
                                                           rdp_stream* stream)
{
    rdp_device_redirection_header header;

    if (!data || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_device_redirection_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER ||
        header.packet_id != expected_packet_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, data, length);
    if (rdp_stream_skip(stream, 4u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_printer_redirection_write_packet_header(rdp_buffer* buffer, uint16_t packet_id)
{
    return rdp_device_redirection_write_header(buffer, RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER, packet_id);
}

static librdp_status rdp_printer_redirection_parse_response_stream(
    const void* data,
    size_t length,
    size_t payload_len,
    rdp_device_redirection_io_completion* response,
    rdp_stream* stream)
{
    if (!data || !response || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u + payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    if (rdp_device_redirection_parse_io_completion(data, length, response) != LIBRDP_STATUS_OK ||
        response->payload_len != payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, response->payload, response->payload_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_printer_redirection_parse_padding_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response)
{
    rdp_stream stream;
    const uint8_t* padding = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_printer_redirection_parse_response_stream(data, length, 4u, response, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_bytes(&stream, &padding, 4u) != LIBRDP_STATUS_OK ||
        padding[0] != 0 || padding[1] != 0 || padding[2] != 0 || padding[3] != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_announce_data(
    rdp_buffer* buffer,
    const rdp_printer_redirection_announce* announce)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !announce ||
        (announce->flags & ~RDP_PRINTER_REDIRECTION_KNOWN_FLAGS) != 0 ||
        !rdp_printer_redirection_valid_utf16le(announce->pnp_name, announce->pnp_name_len) ||
        !rdp_printer_redirection_valid_utf16le(announce->driver_name, announce->driver_name_len) ||
        !rdp_printer_redirection_valid_utf16le(announce->printer_name, announce->printer_name_len) ||
        (!announce->cached_fields && announce->cached_fields_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u32_le(buffer, announce->flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, announce->code_page);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, announce->pnp_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, announce->driver_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, announce->printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, announce->cached_fields_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, announce->pnp_name, announce->pnp_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, announce->driver_name, announce->driver_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, announce->printer_name, announce->printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, announce->cached_fields, announce->cached_fields_len);
}

librdp_status rdp_printer_redirection_detect_document_format(
    const void* data,
    size_t length,
    const char** format)
{
    const uint8_t* bytes = (const uint8_t*)data;
    const uint8_t* text = bytes;
    size_t text_len = length;

    if (!format)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *format = RDP_PRINTER_REDIRECTION_FORMAT_RAW;
    if (!bytes || length == 0)
        return LIBRDP_STATUS_OK;
    if (text_len >= 3u && text[0] == 0xefu && text[1] == 0xbbu && text[2] == 0xbfu)
    {
        text += 3u;
        text_len -= 3u;
    }
    while (text_len > 0 &&
           (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n' || *text == '\f'))
    {
        text++;
        text_len--;
    }
    if (text_len >= 4u && memcmp(text, "%PDF", 4u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PDF;
    else if (text_len >= 2u && memcmp(text, "%!", 2u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_POSTSCRIPT;
    else if (length >= 4u && memcmp(bytes, "PK\003\004", 4u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_XPS;
    else if (length >= 8u && memcmp(bytes, "\211PNG\r\n\032\n", 8u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PNG;
    else if (length >= 3u && bytes[0] == 0xffu && bytes[1] == 0xd8u && bytes[2] == 0xffu)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_JPEG;
    else if (length >= 2u && bytes[0] == 0x1bu && bytes[1] == 'E')
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PCL;
    else if (text_len >= 4u && memcmp(text, "@PJL", 4u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PCL;
    else if (length >= 9u && memcmp(bytes, "\033%-12345X", 9u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PCL;
    else if (length >= 11u && memcmp(bytes, ") HP-PCL XL", 11u) == 0)
        *format = RDP_PRINTER_REDIRECTION_FORMAT_PCL;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_parse_announce_data(
    const void* data,
    size_t length,
    rdp_printer_redirection_announce* announce)
{
    rdp_stream stream;

    if (!data || !announce)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_PRINTER_REDIRECTION_ANNOUNCE_FIXED_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(announce, 0, sizeof(*announce));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &announce->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->code_page) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->pnp_name_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->driver_name_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->printer_name_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &announce->cached_fields_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((announce->flags & ~RDP_PRINTER_REDIRECTION_KNOWN_FLAGS) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)announce->pnp_name_len + announce->driver_name_len + announce->printer_name_len +
            announce->cached_fields_len !=
        rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_printer_redirection_read_blob(&stream,
                                          announce->pnp_name_len,
                                          &announce->pnp_name) != LIBRDP_STATUS_OK ||
        rdp_printer_redirection_read_blob(&stream,
                                          announce->driver_name_len,
                                          &announce->driver_name) != LIBRDP_STATUS_OK ||
        rdp_printer_redirection_read_blob(&stream,
                                          announce->printer_name_len,
                                          &announce->printer_name) != LIBRDP_STATUS_OK ||
        rdp_printer_redirection_read_blob(&stream,
                                          announce->cached_fields_len,
                                          &announce->cached_fields) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_printer_redirection_valid_utf16le(announce->pnp_name, announce->pnp_name_len) ||
        !rdp_printer_redirection_valid_utf16le(announce->driver_name, announce->driver_name_len) ||
        !rdp_printer_redirection_valid_utf16le(announce->printer_name, announce->printer_name_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_parse_cache_event(
    const void* data,
    size_t length,
    rdp_printer_redirection_cache_event* event)
{
    rdp_stream stream;
    const uint8_t* port = NULL;

    if (!data || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    if (rdp_printer_redirection_expect_header(data,
                                              length,
                                              RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA,
                                              &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &event->event_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    switch (event->event_id)
    {
        case RDP_PRINTER_REDIRECTION_CACHE_ADD:
            if (rdp_stream_remaining(&stream) < 24u ||
                rdp_stream_read_bytes(&stream, &port, 8u) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->pnp_name_len) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->driver_name_len) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->printer_name_len) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->cached_fields_len) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            memcpy(event->port_name, port, sizeof(event->port_name));
            if ((size_t)event->pnp_name_len + event->driver_name_len + event->printer_name_len +
                    event->cached_fields_len !=
                rdp_stream_remaining(&stream))
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_printer_redirection_read_blob(&stream, event->pnp_name_len, &event->pnp_name) !=
                    LIBRDP_STATUS_OK ||
                rdp_printer_redirection_read_blob(&stream, event->driver_name_len, &event->driver_name) !=
                    LIBRDP_STATUS_OK ||
                rdp_printer_redirection_read_blob(&stream, event->printer_name_len, &event->printer_name) !=
                    LIBRDP_STATUS_OK ||
                rdp_printer_redirection_read_blob(&stream, event->cached_fields_len, &event->cached_fields) !=
                    LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_UPDATE:
            if (rdp_stream_read_u32_le(&stream, &event->printer_name_len) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->cached_fields_len) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if ((size_t)event->printer_name_len + event->cached_fields_len != rdp_stream_remaining(&stream))
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_printer_redirection_read_blob(&stream, event->printer_name_len, &event->printer_name) !=
                    LIBRDP_STATUS_OK ||
                rdp_printer_redirection_read_blob(&stream, event->cached_fields_len, &event->cached_fields) !=
                    LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_DELETE:
            if (rdp_stream_read_u32_le(&stream, &event->printer_name_len) != LIBRDP_STATUS_OK ||
                event->printer_name_len != rdp_stream_remaining(&stream) ||
                rdp_printer_redirection_read_blob(&stream, event->printer_name_len, &event->printer_name) !=
                    LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        case RDP_PRINTER_REDIRECTION_CACHE_RENAME:
            if (rdp_stream_read_u32_le(&stream, &event->old_printer_name_len) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &event->new_printer_name_len) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if ((size_t)event->old_printer_name_len + event->new_printer_name_len != rdp_stream_remaining(&stream))
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_printer_redirection_read_blob(&stream,
                                                  event->old_printer_name_len,
                                                  &event->old_printer_name) != LIBRDP_STATUS_OK ||
                rdp_printer_redirection_read_blob(&stream,
                                                  event->new_printer_name_len,
                                                  &event->new_printer_name) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        default:
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (!rdp_printer_redirection_valid_utf16le(event->pnp_name, event->pnp_name_len) ||
        !rdp_printer_redirection_valid_utf16le(event->driver_name, event->driver_name_len) ||
        !rdp_printer_redirection_valid_utf16le(event->printer_name, event->printer_name_len) ||
        !rdp_printer_redirection_valid_utf16le(event->old_printer_name, event->old_printer_name_len) ||
        !rdp_printer_redirection_valid_utf16le(event->new_printer_name, event->new_printer_name_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_printer_redirection_write_cache_add(
    rdp_buffer* buffer,
    const char port_name[8],
    const void* pnp_name,
    uint32_t pnp_name_len,
    const void* driver_name,
    uint32_t driver_name_len,
    const void* printer_name,
    uint32_t printer_name_len,
    const void* cached_fields,
    uint32_t cached_fields_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !port_name ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)pnp_name, pnp_name_len) ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)driver_name, driver_name_len) ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)printer_name, printer_name_len) ||
        (!cached_fields && cached_fields_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_write_packet_header(buffer,
                                                         RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_PRINTER_REDIRECTION_CACHE_ADD);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, port_name, 8u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, pnp_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, driver_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, cached_fields_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, pnp_name, pnp_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, driver_name, driver_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, printer_name, printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, cached_fields, cached_fields_len);
}

librdp_status rdp_printer_redirection_write_cache_update(
    rdp_buffer* buffer,
    const void* printer_name,
    uint32_t printer_name_len,
    const void* cached_fields,
    uint32_t cached_fields_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)printer_name, printer_name_len) ||
        (!cached_fields && cached_fields_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_write_packet_header(buffer,
                                                         RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_PRINTER_REDIRECTION_CACHE_UPDATE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, cached_fields_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, printer_name, printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, cached_fields, cached_fields_len);
}

librdp_status rdp_printer_redirection_write_cache_delete(
    rdp_buffer* buffer,
    const void* printer_name,
    uint32_t printer_name_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_printer_redirection_valid_utf16le((const uint8_t*)printer_name, printer_name_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_write_packet_header(buffer,
                                                         RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_PRINTER_REDIRECTION_CACHE_DELETE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, printer_name, printer_name_len);
}

librdp_status rdp_printer_redirection_write_cache_rename(
    rdp_buffer* buffer,
    const void* old_printer_name,
    uint32_t old_printer_name_len,
    const void* new_printer_name,
    uint32_t new_printer_name_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)old_printer_name, old_printer_name_len) ||
        !rdp_printer_redirection_valid_utf16le((const uint8_t*)new_printer_name, new_printer_name_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_write_packet_header(buffer,
                                                         RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_PRINTER_REDIRECTION_CACHE_RENAME);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, old_printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, new_printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, old_printer_name, old_printer_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, new_printer_name, new_printer_name_len);
}

librdp_status rdp_printer_redirection_parse_xps_mode(
    const void* data,
    size_t length,
    rdp_printer_redirection_xps_mode* mode)
{
    rdp_stream stream;

    if (!data || !mode)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(mode, 0, sizeof(*mode));
    if (rdp_printer_redirection_expect_header(data,
                                              length,
                                              RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS,
                                              &stream) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &mode->printer_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &mode->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_xps_mode(
    rdp_buffer* buffer,
    uint32_t printer_id,
    uint32_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_printer_redirection_write_packet_header(buffer,
                                                         RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, printer_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, flags);
}

librdp_status rdp_printer_redirection_write_create_response(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status,
                                                            uint32_t file_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, file_id);
}

librdp_status rdp_printer_redirection_parse_create_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* file_id)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!file_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_parse_response_stream(data, length, 4u, response, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_u32_le(&stream, file_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_close_response(rdp_buffer* buffer,
                                                           uint32_t device_id,
                                                           uint32_t completion_id,
                                                           uint32_t io_status)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, 0);
}

librdp_status rdp_printer_redirection_parse_close_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response)
{
    return rdp_printer_redirection_parse_padding_response(data, length, response);
}

librdp_status rdp_printer_redirection_write_read_response(rdp_buffer* buffer,
                                                          uint32_t device_id,
                                                          uint32_t completion_id,
                                                          uint32_t io_status,
                                                          const void* data,
                                                          uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_printer_redirection_parse_read_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    const uint8_t** payload,
    uint32_t* payload_len)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || !payload_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_parse_response_stream(data, length, length >= 20u ? length - 16u : 0u,
                                                           response, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_u32_le(&stream, payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (*payload_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *payload = NULL;
    if (*payload_len > 0 &&
        rdp_stream_read_bytes(&stream, payload, *payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_write_response(rdp_buffer* buffer,
                                                           uint32_t device_id,
                                                           uint32_t completion_id,
                                                           uint32_t io_status,
                                                           uint32_t written)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, written);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_printer_redirection_parse_write_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* written)
{
    rdp_stream stream;
    uint8_t padding = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!written)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_parse_response_stream(data, length, 5u, response, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_u32_le(&stream, written) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &padding) != LIBRDP_STATUS_OK ||
        padding != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_buffer_response(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status,
                                                            const void* data,
                                                            uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_printer_redirection_parse_buffer_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    const uint8_t** payload,
    uint32_t* payload_len)
{
    return rdp_printer_redirection_parse_read_response(data,
                                                       length,
                                                       response,
                                                       payload,
                                                       payload_len);
}

librdp_status rdp_printer_redirection_write_length_response(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status,
                                                            uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, value);
}

librdp_status rdp_printer_redirection_parse_length_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* value)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_printer_redirection_parse_response_stream(data, length, 4u, response, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_read_u32_le(&stream, value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_printer_redirection_write_device_control_response(rdp_buffer* buffer,
                                                                    uint32_t device_id,
                                                                    uint32_t completion_id,
                                                                    uint32_t io_status)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_io_completion(buffer,
                                                        device_id,
                                                        completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, 0);
}

librdp_status rdp_printer_redirection_parse_device_control_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response)
{
    return rdp_printer_redirection_parse_padding_response(data, length, response);
}
