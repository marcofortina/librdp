#include "channels/multiparty.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_multiparty_valid_type(uint16_t type)
{
    return type >= RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED &&
           type <= RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE;
}

static int rdp_multiparty_valid_filter_flags(uint8_t flags)
{
    return (flags & ~RDP_MULTIPARTY_FILTER_ENABLED) == 0;
}

static int rdp_multiparty_valid_share_flags(uint16_t flags, uint16_t allowed)
{
    return (flags & (uint16_t)~allowed) == 0;
}

static librdp_status rdp_multiparty_parse_exact_header(const void* data,
                                                       size_t length,
                                                       uint16_t expected_type,
                                                       rdp_multiparty_header* header)
{
    if (rdp_multiparty_parse_header(data, length, header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->type != expected_type || header->length != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_parse_header(const void* data, size_t length, rdp_multiparty_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_multiparty_valid_type(header->type) ||
        header->length < 4u || header->length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload = (const uint8_t*)data + 4u;
    header->payload_len = (size_t)header->length - 4u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_header(rdp_buffer* buffer, uint16_t type, uint16_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_multiparty_valid_type(type) || payload_len > UINT16_MAX - 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, (uint16_t)(payload_len + 4u));
}

librdp_status rdp_multiparty_parse_message(const void* data,
                                           size_t length,
                                           rdp_multiparty_message* message)
{
    rdp_multiparty_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(message, 0, sizeof(*message));
    if (rdp_multiparty_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    message->type = header.type;
    switch (header.type)
    {
        case RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED:
            return rdp_multiparty_parse_filter_state(data, length, &message->body.filter_state);
        case RDP_MULTIPARTY_TYPE_APP_CREATED:
            return rdp_multiparty_parse_app_created(data, length, &message->body.app_created);
        case RDP_MULTIPARTY_TYPE_APP_REMOVED:
        case RDP_MULTIPARTY_TYPE_WND_REMOVED:
        case RDP_MULTIPARTY_TYPE_WND_SHOW:
            return rdp_multiparty_parse_id_message(data,
                                                   length,
                                                   header.type,
                                                   &message->body.id_message);
        case RDP_MULTIPARTY_TYPE_WND_CREATED:
            return rdp_multiparty_parse_window_created(data, length, &message->body.window_created);
        case RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE:
            return rdp_multiparty_parse_region_update(data, length, &message->body.region_update);
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED:
            return rdp_multiparty_parse_participant_created(data,
                                                            length,
                                                            &message->body.participant_created);
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED:
            return rdp_multiparty_parse_participant_removed(data,
                                                            length,
                                                            &message->body.participant_removed);
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED:
            return rdp_multiparty_parse_control_change(data,
                                                       length,
                                                       &message->body.control_change);
        case RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE:
            return rdp_multiparty_parse_control_change_response(
                data,
                length,
                &message->body.control_change_response);
        case RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED:
        case RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED:
            status = rdp_multiparty_parse_empty(data, length, header.type);
            if (status == LIBRDP_STATUS_OK)
                message->body.header = header;
            return status;
        default:
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
}

librdp_status rdp_multiparty_parse_string(const void* data,
                                          size_t length,
                                          rdp_multiparty_string* string,
                                          size_t* consumed)
{
    rdp_stream stream;

    if (!data || !string || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(string, 0, sizeof(*string));
    *consumed = 0;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &string->char_count) != LIBRDP_STATUS_OK ||
        string->char_count > RDP_MULTIPARTY_STRING_MAX_CHARS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    string->utf16_len = (size_t)string->char_count * 2u;
    if (string->utf16_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &string->utf16, string->utf16_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *consumed = 2u + string->utf16_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_string(rdp_buffer* buffer, const uint8_t* utf16, uint16_t char_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t byte_count = (size_t)char_count * 2u;

    if (!buffer || char_count > RDP_MULTIPARTY_STRING_MAX_CHARS || (!utf16 && char_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, char_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, utf16, byte_count);
}

librdp_status rdp_multiparty_parse_filter_state(const void* data,
                                                size_t length,
                                                rdp_multiparty_filter_state* state)
{
    rdp_stream stream;

    if (!data || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(state, 0, sizeof(*state));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED,
                                          &state->header) != LIBRDP_STATUS_OK ||
        state->header.payload_len != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, state->header.payload, state->header.payload_len);
    if (rdp_stream_read_u8(&stream, &state->flags) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_filter_flags(state->flags))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_filter_state(rdp_buffer* buffer, uint8_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_multiparty_valid_filter_flags(flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED, 1u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, flags);
}

librdp_status rdp_multiparty_parse_app_created(const void* data,
                                               size_t length,
                                               rdp_multiparty_app_created* app)
{
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !app)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(app, 0, sizeof(*app));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_APP_CREATED,
                                          &app->header) != LIBRDP_STATUS_OK ||
        app->header.payload_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, app->header.payload, app->header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &app->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &app->app_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(app->flags, RDP_MULTIPARTY_APPLICATION_SHARED) ||
        rdp_multiparty_parse_string(app->header.payload + 6u,
                                    app->header.payload_len - 6u,
                                    &app->name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != app->header.payload_len - 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_app_created(rdp_buffer* buffer,
                                               uint16_t flags,
                                               uint32_t app_id,
                                               const uint8_t* name_utf16,
                                               uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 8u + (size_t)name_chars * 2u;

    if (!buffer || !rdp_multiparty_valid_share_flags(flags, RDP_MULTIPARTY_APPLICATION_SHARED) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_APP_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, app_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_multiparty_write_string(buffer, name_utf16, name_chars);
}

librdp_status rdp_multiparty_parse_id_message(const void* data,
                                              size_t length,
                                              uint16_t expected_type,
                                              rdp_multiparty_id_message* message)
{
    rdp_stream stream;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(message, 0, sizeof(*message));
    if (rdp_multiparty_parse_exact_header(data, length, expected_type, &message->header) !=
            LIBRDP_STATUS_OK ||
        message->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, message->header.payload, message->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &message->id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_id_message(rdp_buffer* buffer, uint16_t type, uint32_t id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (type != RDP_MULTIPARTY_TYPE_APP_REMOVED &&
                    type != RDP_MULTIPARTY_TYPE_WND_REMOVED &&
                    type != RDP_MULTIPARTY_TYPE_WND_SHOW))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer, type, 4u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, id);
}

librdp_status rdp_multiparty_parse_window_created(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_window_created* window)
{
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !window)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(window, 0, sizeof(*window));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_WND_CREATED,
                                          &window->header) != LIBRDP_STATUS_OK ||
        window->header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, window->header.payload, window->header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &window->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &window->app_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &window->window_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(window->flags, RDP_MULTIPARTY_WINDOW_SHARED) ||
        rdp_multiparty_parse_string(window->header.payload + 10u,
                                    window->header.payload_len - 10u,
                                    &window->name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != window->header.payload_len - 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_window_created(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t app_id,
                                                  uint32_t window_id,
                                                  const uint8_t* name_utf16,
                                                  uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 12u + (size_t)name_chars * 2u;

    if (!buffer || !rdp_multiparty_valid_share_flags(flags, RDP_MULTIPARTY_WINDOW_SHARED) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_WND_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, app_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_multiparty_write_string(buffer, name_utf16, name_chars);
}

librdp_status rdp_multiparty_parse_region_update(const void* data,
                                                 size_t length,
                                                 rdp_multiparty_region_update* region)
{
    rdp_stream stream;

    if (!data || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(region, 0, sizeof(*region));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE,
                                          &region->header) != LIBRDP_STATUS_OK ||
        region->header.payload_len != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, region->header.payload, region->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &region->left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &region->top) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &region->right) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &region->bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (region->right < region->left || region->bottom < region->top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_region_update(rdp_buffer* buffer,
                                                 uint32_t left,
                                                 uint32_t top,
                                                 uint32_t right,
                                                 uint32_t bottom)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || right < left || bottom < top)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_WND_REGION_UPDATE, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, left);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, top);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, right);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, bottom);
}

librdp_status rdp_multiparty_parse_participant_created(
    const void* data,
    size_t length,
    rdp_multiparty_participant_created* participant)
{
    rdp_stream stream;
    size_t consumed = 0;

    if (!data || !participant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(participant, 0, sizeof(*participant));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED,
                                          &participant->header) != LIBRDP_STATUS_OK ||
        participant->header.payload_len < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, participant->header.payload, participant->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &participant->participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &participant->group_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &participant->flags) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(participant->flags,
                                          RDP_MULTIPARTY_MAY_VIEW |
                                          RDP_MULTIPARTY_MAY_INTERACT |
                                          RDP_MULTIPARTY_IS_PARTICIPANT) ||
        rdp_multiparty_parse_string(participant->header.payload + 10u,
                                    participant->header.payload_len - 10u,
                                    &participant->friendly_name,
                                    &consumed) != LIBRDP_STATUS_OK ||
        consumed != participant->header.payload_len - 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_participant_created(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t group_id,
                                                       uint16_t flags,
                                                       const uint8_t* name_utf16,
                                                       uint16_t name_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t payload_len = 12u + (size_t)name_chars * 2u;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_MAY_VIEW |
                                          RDP_MULTIPARTY_MAY_INTERACT |
                                          RDP_MULTIPARTY_IS_PARTICIPANT) ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_PARTICIPANT_CREATED,
                                         (uint16_t)payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, group_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_multiparty_write_string(buffer, name_utf16, name_chars);
}

librdp_status rdp_multiparty_parse_participant_removed(
    const void* data,
    size_t length,
    rdp_multiparty_participant_removed* participant)
{
    rdp_stream stream;

    if (!data || !participant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(participant, 0, sizeof(*participant));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED,
                                          &participant->header) != LIBRDP_STATUS_OK ||
        participant->header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, participant->header.payload, participant->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &participant->participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &participant->disconnect_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &participant->disconnect_code) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_participant_removed(rdp_buffer* buffer,
                                                       uint32_t participant_id,
                                                       uint32_t disconnect_type,
                                                       uint32_t disconnect_code)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_PARTICIPANT_REMOVED, 12u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, disconnect_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, disconnect_code);
}

librdp_status rdp_multiparty_parse_control_change(const void* data,
                                                  size_t length,
                                                  rdp_multiparty_control_change* change)
{
    rdp_stream stream;

    if (!data || !change)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(change, 0, sizeof(*change));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED,
                                          &change->header) != LIBRDP_STATUS_OK ||
        change->header.payload_len != 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, change->header.payload, change->header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &change->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &change->participant_id) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(change->flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_control_change(rdp_buffer* buffer,
                                                  uint16_t flags,
                                                  uint32_t participant_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer, RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGED, 6u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, participant_id);
}

librdp_status rdp_multiparty_parse_control_change_response(
    const void* data,
    size_t length,
    rdp_multiparty_control_change_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(response, 0, sizeof(*response));
    if (rdp_multiparty_parse_exact_header(data,
                                          length,
                                          RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE,
                                          &response->header) != LIBRDP_STATUS_OK ||
        response->header.payload_len != 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, response->header.payload, response->header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &response->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &response->participant_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &response->reason_code) != LIBRDP_STATUS_OK ||
        !rdp_multiparty_valid_share_flags(response->flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_control_change_response(rdp_buffer* buffer,
                                                           uint16_t flags,
                                                           uint32_t participant_id,
                                                           uint32_t reason_code)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        !rdp_multiparty_valid_share_flags(flags,
                                          RDP_MULTIPARTY_REQUEST_VIEW |
                                          RDP_MULTIPARTY_REQUEST_INTERACT |
                                          RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_multiparty_write_header(buffer,
                                         RDP_MULTIPARTY_TYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE,
                                         10u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, participant_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, reason_code);
}

librdp_status rdp_multiparty_parse_empty(const void* data, size_t length, uint16_t expected_type)
{
    rdp_multiparty_header header;

    if (!data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_multiparty_parse_exact_header(data, length, expected_type, &header) != LIBRDP_STATUS_OK ||
        header.payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multiparty_write_empty(rdp_buffer* buffer, uint16_t type)
{
    if (!buffer || (type != RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED &&
                    type != RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_RESUMED))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_multiparty_write_header(buffer, type, 0);
}
