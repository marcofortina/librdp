#include "channels/input_channel.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_input_channel_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32));
    return status;
}

static librdp_status rdp_input_channel_read_u64_le(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = ((uint64_t)high << 32) | low;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_input_channel_read_i32_le(rdp_stream* stream, int32_t* value)
{
    uint32_t raw = 0;

    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (int32_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_input_channel_read_i16_le(rdp_stream* stream, int16_t* value)
{
    uint16_t raw = 0;

    if (!value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u16_le(stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (int16_t)raw;
    return LIBRDP_STATUS_OK;
}

static int rdp_input_channel_valid_contact_flags(uint32_t flags)
{
    switch (flags)
    {
        case RDP_INPUT_CHANNEL_CONTACT_UP:
        case RDP_INPUT_CHANNEL_CONTACT_UP | RDP_INPUT_CHANNEL_CONTACT_CANCELED:
        case RDP_INPUT_CHANNEL_CONTACT_UPDATE:
        case RDP_INPUT_CHANNEL_CONTACT_UPDATE | RDP_INPUT_CHANNEL_CONTACT_CANCELED:
        case RDP_INPUT_CHANNEL_CONTACT_DOWN | RDP_INPUT_CHANNEL_CONTACT_INRANGE |
            RDP_INPUT_CHANNEL_CONTACT_INCONTACT:
        case RDP_INPUT_CHANNEL_CONTACT_UPDATE | RDP_INPUT_CHANNEL_CONTACT_INRANGE |
            RDP_INPUT_CHANNEL_CONTACT_INCONTACT:
        case RDP_INPUT_CHANNEL_CONTACT_UP | RDP_INPUT_CHANNEL_CONTACT_INRANGE:
        case RDP_INPUT_CHANNEL_CONTACT_UPDATE | RDP_INPUT_CHANNEL_CONTACT_INRANGE:
            return 1;
        default:
            return 0;
    }
}

static int rdp_input_channel_valid_protocol(uint32_t version)
{
    return version == RDP_INPUT_CHANNEL_PROTOCOL_V100 ||
           version == RDP_INPUT_CHANNEL_PROTOCOL_V101 ||
           version == RDP_INPUT_CHANNEL_PROTOCOL_V200 ||
           version == RDP_INPUT_CHANNEL_PROTOCOL_V300;
}

librdp_status rdp_input_channel_parse_header(const void* data, size_t length, rdp_input_channel_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->event_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->pdu_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->pdu_length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->event_id != RDP_INPUT_CHANNEL_EVENT_SC_READY &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_CS_READY &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_TOUCH &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT &&
        header->event_id != RDP_INPUT_CHANNEL_EVENT_PEN)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_write_header(rdp_buffer* buffer, uint16_t event_id, uint32_t pdu_length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || pdu_length < 6u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, event_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, pdu_length);
    return status;
}

librdp_status rdp_input_channel_parse_sc_ready(const void* data, size_t length, rdp_input_channel_sc_ready* ready)
{
    rdp_stream stream;
    rdp_input_channel_header header;

    if (!ready)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_id != RDP_INPUT_CHANNEL_EVENT_SC_READY || (length != 10u && length != 14u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(ready, 0, sizeof(*ready));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &ready->protocol_version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_input_channel_valid_protocol(ready->protocol_version))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) == 4u)
    {
        if (rdp_stream_read_u32_le(&stream, &ready->supported_features) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((ready->supported_features & ~RDP_INPUT_CHANNEL_SC_READY_MULTIPEN) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        ready->has_supported_features = 1;
    }
    if (ready->protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 && !ready->has_supported_features)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_write_sc_ready(rdp_buffer* buffer,
                                               uint32_t protocol_version,
                                               uint32_t supported_features,
                                               uint8_t has_supported_features)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t length = has_supported_features ? 14u : 10u;

    if (!buffer || !rdp_input_channel_valid_protocol(protocol_version) ||
        (supported_features & ~RDP_INPUT_CHANNEL_SC_READY_MULTIPEN) != 0 ||
        (protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 && !has_supported_features) ||
        (!has_supported_features && supported_features != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_input_channel_write_header(buffer, RDP_INPUT_CHANNEL_EVENT_SC_READY, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, protocol_version);
    if (status == LIBRDP_STATUS_OK && has_supported_features)
        status = rdp_buffer_append_u32_le(buffer, supported_features);
    return status;
}

librdp_status rdp_input_channel_write_cs_ready(rdp_buffer* buffer,
                                               uint32_t flags,
                                               uint32_t protocol_version,
                                               uint16_t max_touch_contacts)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_input_channel_valid_protocol(protocol_version) ||
        (flags & ~(RDP_INPUT_CHANNEL_CS_SHOW_TOUCH_VISUALS |
                   RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                   RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN)) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V100 &&
        (flags & RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (protocol_version < RDP_INPUT_CHANNEL_PROTOCOL_V200 &&
        (flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_input_channel_write_header(buffer, RDP_INPUT_CHANNEL_EVENT_CS_READY, 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, protocol_version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, max_touch_contacts);
    return status;
}

librdp_status rdp_input_channel_parse_cs_ready(const void* data, size_t length, rdp_input_channel_cs_ready* ready)
{
    rdp_stream stream;
    rdp_input_channel_header header;

    if (!ready)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_id != RDP_INPUT_CHANNEL_EVENT_CS_READY || length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(ready, 0, sizeof(*ready));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &ready->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &ready->protocol_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &ready->max_touch_contacts) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_input_channel_valid_protocol(ready->protocol_version) ||
        (ready->flags & ~(RDP_INPUT_CHANNEL_CS_SHOW_TOUCH_VISUALS |
                          RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                          RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN)) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_negotiate_client_ready(const rdp_input_channel_sc_ready* server_ready,
                                                       uint16_t max_touch_contacts,
                                                       uint8_t show_touch_visuals,
                                                       rdp_input_channel_negotiation* negotiation)
{
    uint32_t flags = 0;

    if (!server_ready || !negotiation || max_touch_contacts == 0 ||
        !rdp_input_channel_valid_protocol(server_ready->protocol_version) ||
        (server_ready->has_supported_features &&
         (server_ready->supported_features & ~RDP_INPUT_CHANNEL_SC_READY_MULTIPEN) != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (show_touch_visuals)
        flags |= RDP_INPUT_CHANNEL_CS_SHOW_TOUCH_VISUALS;
    if (server_ready->protocol_version >= RDP_INPUT_CHANNEL_PROTOCOL_V101)
        flags |= RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION;
    if (server_ready->protocol_version >= RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
        (server_ready->supported_features & RDP_INPUT_CHANNEL_SC_READY_MULTIPEN) != 0)
        flags |= RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN;
    memset(negotiation, 0, sizeof(*negotiation));
    negotiation->flags = flags;
    negotiation->protocol_version = server_ready->protocol_version;
    negotiation->max_touch_contacts = max_touch_contacts;
    negotiation->supports_touch = 1;
    negotiation->supports_pen = (flags & RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN) != 0 ? 1u : 0u;
    negotiation->disables_timestamp_injection =
        (flags & RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION) != 0 ? 1u : 0u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_write_suspend(rdp_buffer* buffer)
{
    return rdp_input_channel_write_header(buffer, RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT, 6);
}

librdp_status rdp_input_channel_write_resume(rdp_buffer* buffer)
{
    return rdp_input_channel_write_header(buffer, RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT, 6);
}

librdp_status rdp_input_channel_parse_empty(const void* data, size_t length, uint16_t event_id)
{
    rdp_input_channel_header header;

    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return header.event_id == event_id && length == 6u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_input_channel_write_dismiss_hovering(rdp_buffer* buffer, uint8_t contact_id)
{
    librdp_status status = rdp_input_channel_write_header(buffer,
                                                          RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT,
                                                          7);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, contact_id);
    return status;
}

librdp_status rdp_input_channel_parse_dismiss_hovering(const void* data, size_t length, uint8_t* contact_id)
{
    rdp_stream stream;
    rdp_input_channel_header header;

    if (!contact_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_id != RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT || length != 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, contact_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_input_channel_validate_touch_contact(const rdp_input_channel_touch_contact* contact)
{
    if (!contact ||
        (contact->fields_present & ~(RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT |
                                     RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT |
                                     RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT)) != 0 ||
        !rdp_input_channel_valid_contact_flags(contact->contact_flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT) != 0 &&
        contact->orientation > 359u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT) != 0 &&
        contact->pressure > 1024u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_write_touch_contact(rdp_buffer* buffer,
                                                    const rdp_input_channel_touch_contact* contact)
{
    librdp_status status = rdp_input_channel_validate_touch_contact(contact);

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, contact->contact_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, contact->fields_present);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)contact->x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)contact->y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, contact->contact_flags);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT) != 0)
    {
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->contact_rect_left);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->contact_rect_top);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->contact_rect_right);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->contact_rect_bottom);
    }
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT) != 0)
        status = rdp_buffer_append_u32_le(buffer, contact->orientation);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT) != 0)
        status = rdp_buffer_append_u32_le(buffer, contact->pressure);
    return status;
}

librdp_status rdp_input_channel_write_touch_frame(rdp_buffer* buffer,
                                                  uint64_t frame_offset,
                                                  const rdp_input_channel_touch_contact* contacts,
                                                  uint16_t contact_count)
{
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!contacts && contact_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, contact_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_append_u64_le(buffer, frame_offset);
    for (i = 0; status == LIBRDP_STATUS_OK && i < contact_count; i++)
        status = rdp_input_channel_write_touch_contact(buffer, &contacts[i]);
    return status;
}

librdp_status rdp_input_channel_write_touch_event(rdp_buffer* buffer,
                                                  uint32_t encode_time,
                                                  const rdp_input_channel_touch_frame* frames,
                                                  uint16_t frame_count)
{
    rdp_buffer body;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!frames && frame_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, encode_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, frame_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        status = rdp_buffer_append_u16_le(&body, frames[i].contact_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_input_channel_append_u64_le(&body, frames[i].frame_offset);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&body, frames[i].contacts, frames[i].contacts_len);
    }
    if (status == LIBRDP_STATUS_OK && body.length > UINT32_MAX - 6u)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_header(buffer,
                                                RDP_INPUT_CHANNEL_EVENT_TOUCH,
                                                (uint32_t)(6u + body.length));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_input_channel_read_touch_contact(rdp_stream* stream,
                                                          rdp_input_channel_touch_contact* contact)
{
    if (!contact)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(contact, 0, sizeof(*contact));
    if (rdp_stream_read_u8(stream, &contact->contact_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &contact->fields_present) != LIBRDP_STATUS_OK ||
        rdp_input_channel_read_i32_le(stream, &contact->x) != LIBRDP_STATUS_OK ||
        rdp_input_channel_read_i32_le(stream, &contact->y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &contact->contact_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_input_channel_validate_touch_contact(contact) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT) != 0)
    {
        if (rdp_input_channel_read_i16_le(stream, &contact->contact_rect_left) != LIBRDP_STATUS_OK ||
            rdp_input_channel_read_i16_le(stream, &contact->contact_rect_top) != LIBRDP_STATUS_OK ||
            rdp_input_channel_read_i16_le(stream, &contact->contact_rect_right) != LIBRDP_STATUS_OK ||
            rdp_input_channel_read_i16_le(stream, &contact->contact_rect_bottom) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if ((contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT) != 0 &&
        rdp_stream_read_u32_le(stream, &contact->orientation) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT) != 0 &&
        rdp_stream_read_u32_le(stream, &contact->pressure) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_input_channel_validate_touch_contact(contact) == LIBRDP_STATUS_OK ?
               LIBRDP_STATUS_OK :
               LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_input_channel_skip_touch_contacts(rdp_stream* stream,
                                                           uint16_t count,
                                                           size_t* bytes_read)
{
    size_t start = stream->position;
    uint16_t i = 0;

    for (i = 0; i < count; i++)
    {
        rdp_input_channel_touch_contact contact;

        if (rdp_input_channel_read_touch_contact(stream, &contact) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (bytes_read)
        *bytes_read = stream->position - start;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_parse_touch_event(const void* data,
                                                  size_t length,
                                                  rdp_input_channel_touch_event* event)
{
    rdp_stream stream;
    rdp_input_channel_header header;

    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_id != RDP_INPUT_CHANNEL_EVENT_TOUCH || length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(event, 0, sizeof(*event));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &event->encode_time) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &event->frame_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    event->frames_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &event->frames, event->frames_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < event->frame_count; i++)
    {
        rdp_input_channel_touch_frame frame;

        if (rdp_input_channel_touch_event_get_frame(event, i, &frame) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_touch_event_get_frame(const rdp_input_channel_touch_event* event,
                                                      uint16_t index,
                                                      rdp_input_channel_touch_frame* frame)
{
    rdp_stream stream;
    uint16_t i = 0;

    if (!event || !frame || index >= event->frame_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(frame, 0, sizeof(*frame));
    rdp_stream_init(&stream, event->frames, event->frames_len);
    for (i = 0; i <= index; i++)
    {
        uint16_t contact_count = 0;
        uint64_t frame_offset = 0;
        const uint8_t* contacts = NULL;
        size_t contacts_len = 0;
        size_t before = 0;

        if (rdp_stream_read_u16_le(&stream, &contact_count) != LIBRDP_STATUS_OK ||
            rdp_input_channel_read_u64_le(&stream, &frame_offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        before = stream.position;
        if (rdp_input_channel_skip_touch_contacts(&stream, contact_count, &contacts_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        contacts = event->frames + before;
        if (i == index)
        {
            frame->contact_count = contact_count;
            frame->frame_offset = frame_offset;
            frame->contacts = contacts;
            frame->contacts_len = contacts_len;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status rdp_input_channel_touch_frame_get_contact(const rdp_input_channel_touch_frame* frame,
                                                        uint16_t index,
                                                        rdp_input_channel_touch_contact* contact)
{
    rdp_stream stream;
    uint16_t i = 0;

    if (!frame || !contact || index >= frame->contact_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, frame->contacts, frame->contacts_len);
    for (i = 0; i <= index; i++)
    {
        if (rdp_input_channel_read_touch_contact(&stream, contact) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == index)
            return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_input_channel_validate_pen_contact(const rdp_input_channel_pen_contact* contact)
{
    if (!contact ||
        (contact->fields_present & ~(RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT |
                                     RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT |
                                     RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT |
                                     RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT |
                                     RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT)) != 0 ||
        !rdp_input_channel_valid_contact_flags(contact->contact_flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT) != 0 &&
        (contact->pen_flags & ~(RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED |
                                RDP_INPUT_CHANNEL_PEN_ERASER_PRESSED |
                                RDP_INPUT_CHANNEL_PEN_INVERTED)) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT) != 0 &&
        contact->pressure > 1024u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT) != 0 &&
        contact->rotation > 359u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT) != 0 &&
        (contact->tilt_x < -90 || contact->tilt_x > 90))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT) != 0 &&
        (contact->tilt_y < -90 || contact->tilt_y > 90))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_write_pen_contact(rdp_buffer* buffer,
                                                  const rdp_input_channel_pen_contact* contact)
{
    librdp_status status = rdp_input_channel_validate_pen_contact(contact);

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, contact->device_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, contact->fields_present);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)contact->x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)contact->y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, contact->contact_flags);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT) != 0)
        status = rdp_buffer_append_u32_le(buffer, contact->pen_flags);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT) != 0)
        status = rdp_buffer_append_u32_le(buffer, contact->pressure);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT) != 0)
        status = rdp_buffer_append_u16_le(buffer, contact->rotation);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT) != 0)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->tilt_x);
    if (status == LIBRDP_STATUS_OK && (contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT) != 0)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)contact->tilt_y);
    return status;
}

librdp_status rdp_input_channel_write_pen_frame(rdp_buffer* buffer,
                                                uint64_t frame_offset,
                                                const rdp_input_channel_pen_contact* contacts,
                                                uint16_t contact_count)
{
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!contacts && contact_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, contact_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_append_u64_le(buffer, frame_offset);
    for (i = 0; status == LIBRDP_STATUS_OK && i < contact_count; i++)
        status = rdp_input_channel_write_pen_contact(buffer, &contacts[i]);
    return status;
}

librdp_status rdp_input_channel_write_pen_event(rdp_buffer* buffer,
                                                uint32_t encode_time,
                                                const rdp_input_channel_pen_frame* frames,
                                                uint16_t frame_count)
{
    rdp_buffer body;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!frames && frame_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append_u32_le(&body, encode_time);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&body, frame_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        status = rdp_buffer_append_u16_le(&body, frames[i].contact_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_input_channel_append_u64_le(&body, frames[i].frame_offset);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&body, frames[i].contacts, frames[i].contacts_len);
    }
    if (status == LIBRDP_STATUS_OK && body.length > UINT32_MAX - 6u)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_header(buffer,
                                                RDP_INPUT_CHANNEL_EVENT_PEN,
                                                (uint32_t)(6u + body.length));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, body.data, body.length);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_input_channel_read_pen_contact(rdp_stream* stream,
                                                        rdp_input_channel_pen_contact* contact)
{
    if (!contact)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(contact, 0, sizeof(*contact));
    if (rdp_stream_read_u8(stream, &contact->device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &contact->fields_present) != LIBRDP_STATUS_OK ||
        rdp_input_channel_read_i32_le(stream, &contact->x) != LIBRDP_STATUS_OK ||
        rdp_input_channel_read_i32_le(stream, &contact->y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &contact->contact_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_input_channel_validate_pen_contact(contact) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT) != 0 &&
        rdp_stream_read_u32_le(stream, &contact->pen_flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT) != 0 &&
        rdp_stream_read_u32_le(stream, &contact->pressure) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT) != 0 &&
        rdp_stream_read_u16_le(stream, &contact->rotation) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT) != 0 &&
        rdp_input_channel_read_i16_le(stream, &contact->tilt_x) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((contact->fields_present & RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT) != 0 &&
        rdp_input_channel_read_i16_le(stream, &contact->tilt_y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_input_channel_validate_pen_contact(contact) == LIBRDP_STATUS_OK ?
               LIBRDP_STATUS_OK :
               LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_input_channel_skip_pen_contacts(rdp_stream* stream,
                                                         uint16_t count,
                                                         size_t* bytes_read)
{
    size_t start = stream->position;
    uint16_t i = 0;

    for (i = 0; i < count; i++)
    {
        rdp_input_channel_pen_contact contact;

        if (rdp_input_channel_read_pen_contact(stream, &contact) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (bytes_read)
        *bytes_read = stream->position - start;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_parse_pen_event(const void* data,
                                                size_t length,
                                                rdp_input_channel_pen_event* event)
{
    rdp_stream stream;
    rdp_input_channel_header header;

    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_input_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.event_id != RDP_INPUT_CHANNEL_EVENT_PEN || length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(event, 0, sizeof(*event));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &event->encode_time) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &event->frame_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    event->frames_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &event->frames, event->frames_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < event->frame_count; i++)
    {
        rdp_input_channel_pen_frame frame;

        if (rdp_input_channel_pen_event_get_frame(event, i, &frame) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_input_channel_pen_event_get_frame(const rdp_input_channel_pen_event* event,
                                                    uint16_t index,
                                                    rdp_input_channel_pen_frame* frame)
{
    rdp_stream stream;
    uint16_t i = 0;

    if (!event || !frame || index >= event->frame_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(frame, 0, sizeof(*frame));
    rdp_stream_init(&stream, event->frames, event->frames_len);
    for (i = 0; i <= index; i++)
    {
        uint16_t contact_count = 0;
        uint64_t frame_offset = 0;
        const uint8_t* contacts = NULL;
        size_t contacts_len = 0;
        size_t before = 0;

        if (rdp_stream_read_u16_le(&stream, &contact_count) != LIBRDP_STATUS_OK ||
            rdp_input_channel_read_u64_le(&stream, &frame_offset) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        before = stream.position;
        if (rdp_input_channel_skip_pen_contacts(&stream, contact_count, &contacts_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        contacts = event->frames + before;
        if (i == index)
        {
            frame->contact_count = contact_count;
            frame->frame_offset = frame_offset;
            frame->contacts = contacts;
            frame->contacts_len = contacts_len;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status rdp_input_channel_pen_frame_get_contact(const rdp_input_channel_pen_frame* frame,
                                                      uint16_t index,
                                                      rdp_input_channel_pen_contact* contact)
{
    rdp_stream stream;
    uint16_t i = 0;

    if (!frame || !contact || index >= frame->contact_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, frame->contacts, frame->contacts_len);
    for (i = 0; i <= index; i++)
    {
        if (rdp_input_channel_read_pen_contact(&stream, contact) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == index)
            return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}
