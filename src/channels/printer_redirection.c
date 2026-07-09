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
