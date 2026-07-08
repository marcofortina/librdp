#include "clipboard/clipboard.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

#define RDP_CLIPBOARD_SHORT_FORMAT_NAME_LEN 36u

static int rdp_clipboard_response_flag(uint16_t flags)
{
    return flags == RDP_CLIPBOARD_CB_RESPONSE_OK || flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL;
}

static librdp_status rdp_clipboard_require_packet(const rdp_clipboard_packet* packet,
                                                  uint16_t type,
                                                  uint16_t flags_mask)
{
    if (!packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet->type != type || (packet->flags & ~flags_mask) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static int rdp_clipboard_find_utf16_null(const uint8_t* data, size_t length, size_t* offset)
{
    size_t i = 0;

    if (!data || !offset || (length & 1u) != 0)
        return 0;
    while (i + 1u < length)
    {
        if (data[i] == 0 && data[i + 1u] == 0)
        {
            *offset = i;
            return 1;
        }
        i += 2u;
    }
    return 0;
}

librdp_status rdp_clipboard_parse_packet(const void* data, size_t length, rdp_clipboard_packet* packet)
{
    rdp_stream stream;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(packet, 0, sizeof(*packet));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &packet->type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &packet->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)packet->length != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    packet->payload_len = packet->length;
    return rdp_stream_read_bytes(&stream, &packet->payload, packet->payload_len);
}

librdp_status rdp_clipboard_write_header(rdp_buffer* buffer, uint16_t type, uint16_t flags, uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, data_len);
    return status;
}

librdp_status rdp_clipboard_write_monitor_ready(rdp_buffer* buffer)
{
    return rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_MONITOR_READY, 0, 0);
}

librdp_status rdp_clipboard_parse_capabilities(const rdp_clipboard_packet* packet,
                                               rdp_clipboard_capabilities* capabilities)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_require_packet(packet, RDP_CLIPBOARD_CB_CLIP_CAPS, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet->payload_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(capabilities, 0, sizeof(*capabilities));
    rdp_stream_init(&stream, packet->payload, packet->payload_len);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;
    capabilities->count = count;

    for (i = 0; i < count; i++)
    {
        uint16_t type = 0;
        uint16_t length = 0;
        size_t before = stream.position;

        if (rdp_stream_read_u16_le(&stream, &type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &length) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (length < 4u || (size_t)(length - 4u) > rdp_stream_remaining(&stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (type == RDP_CLIPBOARD_CAPSTYPE_GENERAL)
        {
            if (length < 12u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_stream_read_u32_le(&stream, &capabilities->general.version) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &capabilities->general.general_flags) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            capabilities->has_general = 1;
        }
        stream.position = before + length;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_clipboard_write_capabilities(rdp_buffer* buffer, uint32_t general_flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_CLIP_CAPS, 0, 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, RDP_CLIPBOARD_CAPSTYPE_GENERAL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 12);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, RDP_CLIPBOARD_CAPS_VERSION_2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, general_flags);
    return status;
}

librdp_status rdp_clipboard_parse_format_list(const rdp_clipboard_packet* packet,
                                              rdp_clipboard_format_list* list)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_require_packet(packet,
                                          RDP_CLIPBOARD_CB_FORMAT_LIST,
                                          RDP_CLIPBOARD_CB_ASCII_NAMES);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(list, 0, sizeof(*list));
    list->flags = packet->flags;
    list->data = packet->payload;
    list->data_len = packet->payload_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clipboard_write_format_list(rdp_buffer* buffer,
                                              const rdp_clipboard_format_entry* entries,
                                              uint32_t count,
                                              int long_names)
{
    uint32_t i = 0;
    uint32_t data_len = 0;
    uint16_t flags = long_names ? 0 : RDP_CLIPBOARD_CB_ASCII_NAMES;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!entries && count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        uint32_t item_len = 0;

        if (!entries[i].name && entries[i].name_len > 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (long_names)
        {
            if ((entries[i].name_len & 1u) != 0)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            if (entries[i].name_len > UINT32_MAX - 6u)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            item_len = (uint32_t)entries[i].name_len + 6u;
        }
        else
        {
            if (entries[i].name_len > 32u)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            item_len = RDP_CLIPBOARD_SHORT_FORMAT_NAME_LEN;
        }
        if (data_len > UINT32_MAX - item_len)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        data_len += item_len;
    }

    status = rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_FORMAT_LIST, flags, data_len);
    for (i = 0; status == LIBRDP_STATUS_OK && i < count; i++)
    {
        status = rdp_buffer_append_u32_le(buffer, entries[i].format_id);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (long_names)
        {
            status = rdp_buffer_append(buffer, entries[i].name, entries[i].name_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, 0);
        }
        else
        {
            uint8_t name[32];

            memset(name, 0, sizeof(name));
            if (entries[i].name_len > 0)
                memcpy(name, entries[i].name, entries[i].name_len);
            status = rdp_buffer_append(buffer, name, sizeof(name));
        }
    }
    return status;
}

librdp_status rdp_clipboard_format_list_entry_count(const rdp_clipboard_format_list* list,
                                                    int long_names,
                                                    uint32_t* count)
{
    size_t position = 0;
    uint32_t found = 0;

    if (!list || !count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!long_names)
    {
        if ((list->data_len % RDP_CLIPBOARD_SHORT_FORMAT_NAME_LEN) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *count = (uint32_t)(list->data_len / RDP_CLIPBOARD_SHORT_FORMAT_NAME_LEN);
        return LIBRDP_STATUS_OK;
    }

    while (position < list->data_len)
    {
        size_t name_len = 0;

        if (list->data_len - position < 6u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (!rdp_clipboard_find_utf16_null(list->data + position + 4u,
                                           list->data_len - position - 4u,
                                           &name_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (found == UINT32_MAX)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        found++;
        position += 4u + name_len + 2u;
    }
    *count = found;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clipboard_format_list_get_entry(const rdp_clipboard_format_list* list,
                                                  int long_names,
                                                  uint32_t index,
                                                  rdp_clipboard_format_entry* entry)
{
    size_t position = 0;
    uint32_t current = 0;

    if (!list || !entry)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(entry, 0, sizeof(*entry));

    if (!long_names)
    {
        const uint8_t* item = NULL;
        size_t name_len = 0;
        uint32_t count = 0;

        if (rdp_clipboard_format_list_entry_count(list, long_names, &count) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (index >= count)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        item = list->data + (size_t)index * RDP_CLIPBOARD_SHORT_FORMAT_NAME_LEN;
        entry->format_id = (uint32_t)item[0] | ((uint32_t)item[1] << 8) |
                           ((uint32_t)item[2] << 16) | ((uint32_t)item[3] << 24);
        entry->name = item + 4u;
        if ((list->flags & RDP_CLIPBOARD_CB_ASCII_NAMES) != 0)
        {
            while (name_len < 32u && entry->name[name_len] != 0)
                name_len++;
        }
        else if (!rdp_clipboard_find_utf16_null(entry->name, 32u, &name_len))
        {
            name_len = 32u;
        }
        entry->name_len = name_len;
        return LIBRDP_STATUS_OK;
    }

    while (position < list->data_len)
    {
        size_t name_len = 0;
        const uint8_t* item = list->data + position;

        if (list->data_len - position < 6u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (!rdp_clipboard_find_utf16_null(item + 4u, list->data_len - position - 4u, &name_len))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (current == index)
        {
            entry->format_id = (uint32_t)item[0] | ((uint32_t)item[1] << 8) |
                               ((uint32_t)item[2] << 16) | ((uint32_t)item[3] << 24);
            entry->name = item + 4u;
            entry->name_len = name_len;
            return LIBRDP_STATUS_OK;
        }
        current++;
        position += 4u + name_len + 2u;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status rdp_clipboard_write_format_list_response(rdp_buffer* buffer, int ok)
{
    return rdp_clipboard_write_header(buffer,
                                      RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE,
                                      ok ? RDP_CLIPBOARD_CB_RESPONSE_OK : RDP_CLIPBOARD_CB_RESPONSE_FAIL,
                                      0);
}

librdp_status rdp_clipboard_write_format_data_request(rdp_buffer* buffer, uint32_t format_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, format_id);
    return status;
}

librdp_status rdp_clipboard_parse_format_data_request(const rdp_clipboard_packet* packet,
                                                      rdp_clipboard_format_data_request* request)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_require_packet(packet, RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet->payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, packet->payload, packet->payload_len);
    return rdp_stream_read_u32_le(&stream, &request->format_id);
}

librdp_status rdp_clipboard_write_format_data_response(rdp_buffer* buffer,
                                                       int ok,
                                                       const void* data,
                                                       size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) || data_len > UINT32_MAX || (!ok && data_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_write_header(buffer,
                                        RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE,
                                        ok ? RDP_CLIPBOARD_CB_RESPONSE_OK : RDP_CLIPBOARD_CB_RESPONSE_FAIL,
                                        (uint32_t)data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    return status;
}

librdp_status rdp_clipboard_parse_format_data_response(const rdp_clipboard_packet* packet,
                                                       rdp_clipboard_format_data_response* response)
{
    if (!response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!packet || packet->type != RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE ||
        !rdp_clipboard_response_flag(packet->flags))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL && packet->payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(response, 0, sizeof(*response));
    response->response_flags = packet->flags;
    response->data = packet->payload;
    response->data_len = packet->payload_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clipboard_parse_file_contents_request(const rdp_clipboard_packet* packet,
                                                        rdp_clipboard_file_contents_request* request)
{
    rdp_stream stream;
    uint32_t low = 0;
    uint32_t high = 0;
    uint32_t lindex = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_require_packet(packet, RDP_CLIPBOARD_CB_FILECONTENTS_REQUEST, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet->payload_len != 24u && packet->payload_len != 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, packet->payload, packet->payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->stream_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &lindex) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &high) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->requested) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->lindex = (int32_t)lindex;
    request->position = ((uint64_t)high << 32) | low;
    if (packet->payload_len == 28u)
    {
        if (rdp_stream_read_u32_le(&stream, &request->clip_data_id) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        request->has_clip_data_id = 1;
    }

    if (request->flags != RDP_CLIPBOARD_FILECONTENTS_SIZE &&
        request->flags != RDP_CLIPBOARD_FILECONTENTS_RANGE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (request->flags == RDP_CLIPBOARD_FILECONTENTS_SIZE &&
        (request->position != 0 || request->requested != 8u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clipboard_write_file_contents_response(rdp_buffer* buffer,
                                                        int ok,
                                                        uint32_t stream_id,
                                                        const void* data,
                                                        size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) || data_len > UINT32_MAX - 4u || (!ok && data_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_write_header(buffer,
                                        RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE,
                                        ok ? RDP_CLIPBOARD_CB_RESPONSE_OK : RDP_CLIPBOARD_CB_RESPONSE_FAIL,
                                        (uint32_t)data_len + 4u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, stream_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    return status;
}

librdp_status rdp_clipboard_parse_file_contents_response(const rdp_clipboard_packet* packet,
                                                         rdp_clipboard_file_contents_response* response)
{
    rdp_stream stream;

    if (!response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!packet || packet->type != RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE ||
        !rdp_clipboard_response_flag(packet->flags) || packet->payload_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL && packet->payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(response, 0, sizeof(*response));
    response->response_flags = packet->flags;
    rdp_stream_init(&stream, packet->payload, packet->payload_len);
    if (rdp_stream_read_u32_le(&stream, &response->stream_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->data_len = rdp_stream_remaining(&stream);
    if (response->data_len > 0 &&
        rdp_stream_read_bytes(&stream, &response->data, response->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clipboard_write_lock(rdp_buffer* buffer, uint32_t clip_data_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_LOCK_CLIPDATA, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, clip_data_id);
    return status;
}

librdp_status rdp_clipboard_write_unlock(rdp_buffer* buffer, uint32_t clip_data_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_clipboard_write_header(buffer, RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA, 0, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, clip_data_id);
    return status;
}

static librdp_status rdp_clipboard_parse_clip_data_id(const rdp_clipboard_packet* packet,
                                                      uint16_t type,
                                                      rdp_clipboard_lock* lock)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!lock)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clipboard_require_packet(packet, type, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet->payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(lock, 0, sizeof(*lock));
    rdp_stream_init(&stream, packet->payload, packet->payload_len);
    return rdp_stream_read_u32_le(&stream, &lock->clip_data_id);
}

librdp_status rdp_clipboard_parse_lock(const rdp_clipboard_packet* packet, rdp_clipboard_lock* lock)
{
    return rdp_clipboard_parse_clip_data_id(packet, RDP_CLIPBOARD_CB_LOCK_CLIPDATA, lock);
}

librdp_status rdp_clipboard_parse_unlock(const rdp_clipboard_packet* packet, rdp_clipboard_lock* lock)
{
    return rdp_clipboard_parse_clip_data_id(packet, RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA, lock);
}
