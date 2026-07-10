#include "channels/remote_programs.h"

#include "common/stream.h"

#include <string.h>

static int rdp_remote_programs_handshake_ex_flags_valid(uint32_t flags)
{
    return (flags & ~(RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_SNAP_ARRANGE |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_TEXT_SCALE |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_CARET_BLINK |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI2 |
                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI3)) == 0;
}

int rdp_remote_programs_order_valid(uint16_t order_type)
{
    switch (order_type)
    {
        case RDP_REMOTE_PROGRAMS_ORDER_EXEC:
        case RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND:
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE:
        case RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT:
        case RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE:
        case RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE:
        case RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS:
        case RDP_REMOTE_PROGRAMS_ORDER_SYSMENU:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_REQ:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP:
        case RDP_REMOTE_PROGRAMS_ORDER_TASKBARINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_LANGUAGEIMEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_COMPARTMENTINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX:
        case RDP_REMOTE_PROGRAMS_ORDER_ZORDER_SYNC:
        case RDP_REMOTE_PROGRAMS_ORDER_CLOAK:
        case RDP_REMOTE_PROGRAMS_ORDER_POWER_DISPLAY_REQUEST:
        case RDP_REMOTE_PROGRAMS_ORDER_SNAP_ARRANGE:
        case RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP_EX:
        case RDP_REMOTE_PROGRAMS_ORDER_TEXTSCALEINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_CARETBLINKINFO:
        case RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT:
            return 1;
        default:
            return 0;
    }
}

int rdp_remote_programs_exec_flags_valid(uint16_t flags)
{
    if ((flags & ~RDP_REMOTE_PROGRAMS_EXEC_FLAG_KNOWN_MASK) != 0)
        return 0;
    if ((flags & RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES) != 0 &&
        (flags & RDP_REMOTE_PROGRAMS_EXEC_FLAG_FILE) == 0)
        return 0;
    return 1;
}

int rdp_remote_programs_exec_result_valid(uint16_t result)
{
    return result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_HOOK_NOT_LOADED ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_DECODE_FAILED ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_NOT_IN_ALLOWLIST ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_FILE_NOT_FOUND ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_FAIL ||
           result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_SESSION_LOCKED;
}

librdp_status rdp_remote_programs_parse_header(const void* data,
                                               size_t length,
                                               rdp_remote_programs_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u || length > RDP_REMOTE_PROGRAMS_MAX_PDU_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->order_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->order_length) != LIBRDP_STATUS_OK ||
        !rdp_remote_programs_order_valid(header->order_type) ||
        header->order_length != length ||
        header->order_length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_header(rdp_buffer* buffer,
                                               uint16_t order_type,
                                               uint16_t order_length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_remote_programs_order_valid(order_type) || order_length < 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, order_type);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, order_length);
}

librdp_status rdp_remote_programs_parse_u32_order(const void* data,
                                                  size_t length,
                                                  uint16_t expected_order,
                                                  rdp_remote_programs_u32_order* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != expected_order)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_u32_order(rdp_buffer* buffer,
                                                  uint16_t order_type,
                                                  uint32_t value)
{
    librdp_status status = rdp_remote_programs_write_header(buffer, order_type, 8u);

    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, value);
}

librdp_status rdp_remote_programs_parse_handshake_ex(const void* data,
                                                     size_t length,
                                                     rdp_remote_programs_handshake_ex* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->build_number) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->flags) != LIBRDP_STATUS_OK ||
        !rdp_remote_programs_handshake_ex_flags_valid(order->flags))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_handshake_ex(rdp_buffer* buffer,
                                                     uint32_t build_number,
                                                     uint32_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_remote_programs_handshake_ex_flags_valid(flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(buffer, RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX, 12u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, build_number);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, flags);
}

librdp_status rdp_remote_programs_parse_exec(const void* data,
                                             size_t length,
                                             rdp_remote_programs_exec* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_EXEC)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->exe_or_file_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->working_dir_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->arguments_len) != LIBRDP_STATUS_OK ||
        !rdp_remote_programs_exec_flags_valid(order->flags) ||
        order->exe_or_file_len == 0 ||
        order->exe_or_file_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        order->working_dir_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        order->arguments_len > RDP_REMOTE_PROGRAMS_MAX_ARGUMENT_BYTES ||
        (size_t)order->exe_or_file_len + order->working_dir_len + order->arguments_len !=
            rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &order->exe_or_file, order->exe_or_file_len) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order->working_dir, order->working_dir_len) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &order->arguments, order->arguments_len) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_exec(rdp_buffer* buffer,
                                             uint16_t flags,
                                             const void* exe_or_file,
                                             uint16_t exe_or_file_len,
                                             const void* working_dir,
                                             uint16_t working_dir_len,
                                             const void* arguments,
                                             uint16_t arguments_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t length = 12u + exe_or_file_len + working_dir_len + arguments_len;

    if (!buffer || !exe_or_file || exe_or_file_len == 0 ||
        (!working_dir && working_dir_len > 0) ||
        (!arguments && arguments_len > 0) ||
        exe_or_file_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        working_dir_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        arguments_len > RDP_REMOTE_PROGRAMS_MAX_ARGUMENT_BYTES ||
        length > UINT16_MAX ||
        !rdp_remote_programs_exec_flags_valid(flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(buffer, RDP_REMOTE_PROGRAMS_ORDER_EXEC, (uint16_t)length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, exe_or_file_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, working_dir_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, arguments_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, exe_or_file, exe_or_file_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, working_dir, working_dir_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, arguments, arguments_len);
    return status;
}

librdp_status rdp_remote_programs_parse_exec_result(const void* data,
                                                    size_t length,
                                                    rdp_remote_programs_exec_result* order)
{
    rdp_stream stream;
    uint16_t padding = 0;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->exec_result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->raw_result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &padding) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->exe_or_file_len) != LIBRDP_STATUS_OK ||
        padding != 0 ||
        !rdp_remote_programs_exec_flags_valid(order->flags) ||
        !rdp_remote_programs_exec_result_valid(order->exec_result) ||
        order->exe_or_file_len == 0 ||
        order->exe_or_file_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        order->exe_or_file_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_read_bytes(&stream, &order->exe_or_file, order->exe_or_file_len);
}

librdp_status rdp_remote_programs_write_exec_result(rdp_buffer* buffer,
                                                    uint16_t flags,
                                                    uint16_t exec_result,
                                                    uint32_t raw_result,
                                                    const void* exe_or_file,
                                                    uint16_t exe_or_file_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t length = 16u + exe_or_file_len;

    if (!buffer || !exe_or_file || exe_or_file_len == 0 ||
        exe_or_file_len > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ||
        length > UINT16_MAX ||
        !rdp_remote_programs_exec_flags_valid(flags) ||
        !rdp_remote_programs_exec_result_valid(exec_result))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(buffer, RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT, (uint16_t)length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, exec_result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, raw_result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, exe_or_file_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, exe_or_file, exe_or_file_len);
    return status;
}

librdp_status rdp_remote_programs_parse_activate(const void* data,
                                                 size_t length,
                                                 rdp_remote_programs_activate* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 9u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &order->enabled) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_activate(rdp_buffer* buffer,
                                                 uint32_t window_id,
                                                 uint8_t enabled)
{
    librdp_status status = rdp_remote_programs_write_header(buffer, RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE, 9u);

    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, enabled ? 1u : 0u);
}

static librdp_status rdp_remote_programs_read_i16(rdp_stream* stream, int16_t* value)
{
    uint16_t raw = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_stream_read_u16_le(stream, &raw);
    if (status != LIBRDP_STATUS_OK)
        return status;
    *value = (int16_t)raw;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_remote_programs_write_i16(rdp_buffer* buffer, int16_t value)
{
    return rdp_buffer_append_u16_le(buffer, (uint16_t)value);
}

librdp_status rdp_remote_programs_parse_sysmenu(const void* data,
                                                size_t length,
                                                rdp_remote_programs_sysmenu* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_SYSMENU)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->left) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->top) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_sysmenu(rdp_buffer* buffer,
                                                uint32_t window_id,
                                                int16_t left,
                                                int16_t top)
{
    librdp_status status = rdp_remote_programs_write_header(
        buffer,
        RDP_REMOTE_PROGRAMS_ORDER_SYSMENU,
        12u);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, left);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, top);
    return status;
}

librdp_status rdp_remote_programs_parse_syscommand(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_syscommand* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->command) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_syscommand(rdp_buffer* buffer,
                                                   uint32_t window_id,
                                                   uint16_t command)
{
    librdp_status status = rdp_remote_programs_write_header(
        buffer,
        RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND,
        10u);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, command);
    return status;
}

librdp_status rdp_remote_programs_parse_notify_event(const void* data,
                                                     size_t length,
                                                     rdp_remote_programs_notify_event* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->notify_icon_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->message) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_notify_event(rdp_buffer* buffer,
                                                     uint32_t window_id,
                                                     uint32_t notify_icon_id,
                                                     uint32_t message)
{
    librdp_status status = rdp_remote_programs_write_header(
        buffer,
        RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT,
        16u);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, notify_icon_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, message);
    return status;
}

librdp_status rdp_remote_programs_parse_minmaxinfo(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_minmaxinfo* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_width) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_height) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_pos_x) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_pos_y) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->min_track_width) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->min_track_height) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_track_width) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->max_track_height) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_minmaxinfo(rdp_buffer* buffer,
                                                   const rdp_remote_programs_minmaxinfo* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(buffer, RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO, 24u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, order->window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_pos_x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_pos_y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->min_track_width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->min_track_height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_track_width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->max_track_height);
    return status;
}

librdp_status rdp_remote_programs_parse_localmovesize(const void* data,
                                                      size_t length,
                                                      rdp_remote_programs_localmovesize* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->is_move_size_start) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &order->move_size_type) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->pos_x) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->pos_y) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_localmovesize(rdp_buffer* buffer,
                                                      const rdp_remote_programs_localmovesize* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(
        buffer,
        RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE,
        16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, order->window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, order->is_move_size_start);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, order->move_size_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->pos_x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, order->pos_y);
    return status;
}

librdp_status rdp_remote_programs_parse_windowmove(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_windowmove* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK ||
        order->header.order_type != RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &order->window_id) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->left) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->top) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->right) != LIBRDP_STATUS_OK ||
        rdp_remote_programs_read_i16(&stream, &order->bottom) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_remote_programs_write_windowmove(rdp_buffer* buffer,
                                                   uint32_t window_id,
                                                   int16_t left,
                                                   int16_t top,
                                                   int16_t right,
                                                   int16_t bottom)
{
    librdp_status status = rdp_remote_programs_write_header(
        buffer,
        RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE,
        16u);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, window_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, left);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, top);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, right);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_remote_programs_write_i16(buffer, bottom);
    return status;
}

librdp_status rdp_remote_programs_parse_opaque(const void* data,
                                               size_t length,
                                               rdp_remote_programs_opaque* order)
{
    rdp_stream stream;

    if (!data || !order)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(order, 0, sizeof(*order));
    if (rdp_remote_programs_parse_header(data, length, &order->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order->payload_len = rdp_stream_remaining(&stream);
    return rdp_stream_read_bytes(&stream, &order->payload, order->payload_len);
}

librdp_status rdp_remote_programs_write_opaque(rdp_buffer* buffer,
                                               uint16_t order_type,
                                               const void* payload,
                                               size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t length = 4u + payload_len;

    if (!buffer || (!payload && payload_len > 0) ||
        length > RDP_REMOTE_PROGRAMS_MAX_PDU_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_remote_programs_write_header(buffer, order_type, (uint16_t)length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}
