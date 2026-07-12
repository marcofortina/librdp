/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: smartcard redirection PC/SC request and response helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/smartcard_redirection.h"

#include "common/stream.h"

#include <string.h>

static int rdp_smartcard_redirection_scope_valid(uint32_t scope)
{
    return scope == RDP_SMARTCARD_REDIRECTION_SCOPE_USER ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL ||
           scope == RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM;
}

int rdp_smartcard_redirection_share_mode_valid(uint32_t share_mode)
{
    return share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE ||
           share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_SHARED ||
           share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_DIRECT;
}

int rdp_smartcard_redirection_protocol_mask_valid(uint32_t protocols)
{
    uint32_t base = protocols & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;
    const uint32_t valid_mask = RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 |
                                RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 |
                                RDP_SMARTCARD_REDIRECTION_PROTOCOL_T15 |
                                RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW;

    return (base & ~valid_mask) == 0;
}

int rdp_smartcard_redirection_bool_valid(uint32_t value)
{
    return value <= 1u;
}

int rdp_smartcard_redirection_disposition_valid(uint32_t disposition)
{
    return disposition <= RDP_SMARTCARD_REDIRECTION_EJECT_CARD;
}

int rdp_smartcard_redirection_initialization_valid(uint32_t initialization)
{
    return initialization <= RDP_SMARTCARD_REDIRECTION_UNPOWER_CARD;
}

static int rdp_smartcard_redirection_length_bool_pair_valid(uint32_t is_null, uint32_t length)
{
    if (!rdp_smartcard_redirection_bool_valid(is_null))
        return 0;
    return is_null || length <= RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH;
}

static int rdp_smartcard_redirection_data_string_valid(uint32_t is_null,
                                                       const void* data,
                                                       uint32_t length)
{
    if (!rdp_smartcard_redirection_bool_valid(is_null))
        return 0;
    if (is_null)
        return length == 0 && !data;
    return length <= RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH && (data || length == 0);
}

static librdp_status rdp_smartcard_redirection_read_context(
    rdp_stream* stream,
    rdp_smartcard_redirection_context* context)
{
    if (!stream || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    if (rdp_stream_read_u32_le(stream, &context->length) != LIBRDP_STATUS_OK ||
        context->length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ||
        context->length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &context->data, context->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_read_string(
    rdp_stream* stream,
    rdp_smartcard_redirection_string* value)
{
    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(value, 0, sizeof(*value));
    if (rdp_stream_read_u32_le(stream, &value->is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &value->length) != LIBRDP_STATUS_OK ||
        !rdp_smartcard_redirection_length_bool_pair_valid(value->is_null, value->length) ||
        value->length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (value->is_null && value->length != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &value->data, value->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_read_reader_state_call(
    rdp_stream* stream,
    rdp_smartcard_redirection_reader_state_call* reader)
{
    const uint8_t* state_data = NULL;

    if (!stream || !reader)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(reader, 0, sizeof(*reader));
    if (rdp_stream_read_u32_le(stream, &reader->reader_name_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &reader->reader_name_len) != LIBRDP_STATUS_OK ||
        !rdp_smartcard_redirection_length_bool_pair_valid(reader->reader_name_is_null,
                                                          reader->reader_name_len) ||
        reader->reader_name_len > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, &reader->reader_name, reader->reader_name_len) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (reader->reader_name_is_null && reader->reader_name_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream,
                              &state_data,
                              12u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
            LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_parse_reader_state_common(
            state_data,
            12u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH,
            &reader->state) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_read_handle(
    rdp_stream* stream,
    rdp_smartcard_redirection_handle* handle)
{
    if (!stream || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(handle, 0, sizeof(*handle));
    if (rdp_smartcard_redirection_read_context(stream, &handle->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &handle->length) != LIBRDP_STATUS_OK ||
        handle->length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH ||
        handle->length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &handle->data, handle->length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_read_scard_io_request(
    rdp_stream* stream,
    rdp_smartcard_redirection_scard_io_request* request)
{
    if (!stream || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_stream_read_u32_le(stream, &request->protocol) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &request->extra_bytes_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_protocol_mask_valid(request->protocol) ||
        request->extra_bytes_len > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA ||
        request->extra_bytes_len > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &request->extra_bytes, request->extra_bytes_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_smartcard_redirection_write_opaque(
    rdp_buffer* buffer,
    const void* data,
    uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && length > 0) ||
        length > RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

librdp_status rdp_smartcard_redirection_parse_atr_mask(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_atr_mask* mask)
{
    rdp_stream stream;
    const uint8_t* atr = NULL;
    const uint8_t* value_mask = NULL;

    if (!data || !mask)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u + (RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH * 2u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(mask, 0, sizeof(*mask));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &mask->atr_len) != LIBRDP_STATUS_OK ||
        mask->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ||
        rdp_stream_read_bytes(&stream, &atr, RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &value_mask, RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(mask->atr, atr, sizeof(mask->atr));
    memcpy(mask->mask, value_mask, sizeof(mask->mask));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_atr_mask(
    rdp_buffer* buffer,
    const uint8_t* atr,
    uint32_t atr_len,
    const uint8_t* mask)
{
    uint8_t atr_storage[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {0};
    uint8_t mask_storage[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!atr && atr_len > 0) || !mask ||
        atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (atr_len > 0)
        memcpy(atr_storage, atr, atr_len);
    memcpy(mask_storage, mask, RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH);
    status = rdp_buffer_append_u32_le(buffer, atr_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, atr_storage, sizeof(atr_storage));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, mask_storage, sizeof(mask_storage));
}

librdp_status rdp_smartcard_redirection_parse_reader_state_common(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reader_state_common* state)
{
    rdp_stream stream;
    const uint8_t* atr = NULL;

    if (!data || !state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 12u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(state, 0, sizeof(*state));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &state->current_state) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &state->event_state) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &state->atr_len) != LIBRDP_STATUS_OK ||
        state->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ||
        rdp_stream_read_bytes(&stream, &atr, RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(state->atr, atr, sizeof(state->atr));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_reader_state_common(
    rdp_buffer* buffer,
    uint32_t current_state,
    uint32_t event_state,
    const uint8_t* atr,
    uint32_t atr_len)
{
    uint8_t atr_storage[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!atr && atr_len > 0) ||
        atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (atr_len > 0)
        memcpy(atr_storage, atr, atr_len);
    status = rdp_buffer_append_u32_le(buffer, current_state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, event_state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, atr_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, atr_storage, sizeof(atr_storage));
}

librdp_status rdp_smartcard_redirection_parse_string(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_string* value)
{
    rdp_stream stream;

    if (!data || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_string(&stream, value) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_string(
    rdp_buffer* buffer,
    uint32_t is_null,
    const void* data,
    uint32_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_data_string_valid(is_null, data, length))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, length);
}

int rdp_smartcard_redirection_ioctl_valid(uint32_t io_control_code)
{
    switch (io_control_code)
    {
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RECONNECT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATE:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONTROL:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_SETATTRIB:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ACCESSSTARTEDEVENT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID:
            return 1;
        default:
            return 0;
    }
}

librdp_status rdp_smartcard_redirection_parse_device_control_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SMARTCARD_REDIRECTION_DEVICE_CONTROL_REQUEST_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &request->output_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->input_buffer_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->io_control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_skip(&stream, 20u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_ioctl_valid(request->io_control_code) ||
        request->output_buffer_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        request->input_buffer_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        request->input_buffer_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->input_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &request->input, request->input_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

/*
 * Smartcard device-control payloads reuse the same wire envelope for many
 * PC/SC calls. Parse the envelope first, then specialize by IOCTL so malformed
 * lengths or unsupported calls never reach backend-specific handlers.
 */
librdp_status rdp_smartcard_redirection_parse_device_control_request_message(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_request_message* message)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(message, 0, sizeof(*message));
    status = rdp_smartcard_redirection_parse_device_control_request(data,
                                                                    length,
                                                                    &message->request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_RAW;
    switch (message->request.io_control_code)
    {
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT:
            status = rdp_smartcard_redirection_parse_establish_context_call(
                message->request.input,
                message->request.input_len,
                &message->body.establish_context);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_ESTABLISH_CONTEXT;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW:
            status = rdp_smartcard_redirection_parse_list_reader_groups_call(
                message->request.input,
                message->request.input_len,
                &message->body.list_reader_groups);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READER_GROUPS;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSW:
            status = rdp_smartcard_redirection_parse_list_readers_call(message->request.input,
                                                                       message->request.input_len,
                                                                       &message->body.list_readers);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READERS;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW:
            status = rdp_smartcard_redirection_parse_context_string_call(
                message->request.input,
                message->request.input_len,
                &message->body.context_string);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_STRING;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW:
            status = rdp_smartcard_redirection_parse_context_two_strings_call(
                message->request.input,
                message->request.input_len,
                &message->body.context_two_strings);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_TWO_STRINGS;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW:
            status = rdp_smartcard_redirection_parse_locate_cards_call(
                message->request.input,
                message->request.input_len,
                &message->body.locate_cards);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEW:
            status = rdp_smartcard_redirection_parse_get_status_change_call(
                message->request.input,
                message->request.input_len,
                &message->body.get_status_change);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_GET_STATUS_CHANGE;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL:
            status = rdp_smartcard_redirection_parse_context(message->request.input,
                                                             message->request.input_len,
                                                             &message->body.context);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW:
            status = rdp_smartcard_redirection_parse_connect_common(message->request.input,
                                                                    message->request.input_len,
                                                                    &message->body.connect);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_CONNECT;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION:
            status = rdp_smartcard_redirection_parse_handle(message->request.input,
                                                            message->request.input_len,
                                                            &message->body.handle);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION:
            status = rdp_smartcard_redirection_parse_handle_disposition_call(
                message->request.input,
                message->request.input_len,
                &message->body.handle_disposition);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE_DISPOSITION;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_RECONNECT:
            status = rdp_smartcard_redirection_parse_reconnect_call(message->request.input,
                                                                    message->request.input_len,
                                                                    &message->body.reconnect);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_RECONNECT;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATE:
            status = rdp_smartcard_redirection_parse_state_call(message->request.input,
                                                                message->request.input_len,
                                                                &message->body.state);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_STATE;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSW:
            status = rdp_smartcard_redirection_parse_status_call(message->request.input,
                                                                 message->request.input_len,
                                                                 &message->body.status);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_STATUS;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT:
            status = rdp_smartcard_redirection_parse_transmit_call(message->request.input,
                                                                   message->request.input_len,
                                                                   &message->body.transmit);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_TRANSMIT;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_CONTROL:
            status = rdp_smartcard_redirection_parse_control_call(message->request.input,
                                                                  message->request.input_len,
                                                                  &message->body.control);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTROL;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB:
            status = rdp_smartcard_redirection_parse_attrib_call(message->request.input,
                                                                 message->request.input_len,
                                                                 &message->body.attrib);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_ATTRIB;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_SETATTRIB:
            status = rdp_smartcard_redirection_parse_set_attrib_call(message->request.input,
                                                                     message->request.input_len,
                                                                     &message->body.set_attrib);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_SET_ATTRIB;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_ACCESSSTARTEDEVENT:
            if (message->request.input_len != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_ACCESS_STARTED_EVENT;
            return LIBRDP_STATUS_OK;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW:
            status = rdp_smartcard_redirection_parse_locate_cards_by_atr_call(
                message->request.input,
                message->request.input_len,
                &message->body.locate_cards_by_atr);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS_BY_ATR;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW:
            status = rdp_smartcard_redirection_parse_read_cache_call(message->request.input,
                                                                     message->request.input_len,
                                                                     &message->body.read_cache);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEA:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW:
            status = rdp_smartcard_redirection_parse_write_cache_call(message->request.input,
                                                                      message->request.input_len,
                                                                      &message->body.write_cache);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_WRITE_CACHE;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON:
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID:
            status = rdp_smartcard_redirection_parse_reader_name_call(message->request.input,
                                                                      message->request.input_len,
                                                                      &message->body.reader_name);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_READER_NAME;
            return status;
        case RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT:
            status = rdp_smartcard_redirection_parse_handle(message->request.input,
                                                            message->request.input_len,
                                                            &message->body.handle);
            if (status == LIBRDP_STATUS_OK)
                message->kind = RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE;
            return status;
        default:
            return LIBRDP_STATUS_OK;
    }
}

librdp_status rdp_smartcard_redirection_write_device_control_request(
    rdp_buffer* buffer,
    uint32_t output_buffer_len,
    uint32_t io_control_code,
    const void* input,
    uint32_t input_len)
{
    static const uint8_t padding[20] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!input && input_len > 0) ||
        output_buffer_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        input_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        !rdp_smartcard_redirection_ioctl_valid(io_control_code))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, output_buffer_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, io_control_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, padding, sizeof(padding));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, input, input_len);
}

librdp_status rdp_smartcard_redirection_parse_device_control_response(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_response* response)
{
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(response, 0, sizeof(*response));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &response->output_buffer_len) != LIBRDP_STATUS_OK ||
        response->output_buffer_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        response->output_buffer_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    response->output_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &response->output, response->output_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_device_control_response(
    rdp_buffer* buffer,
    const void* output,
    uint32_t output_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!output && output_len > 0) ||
        output_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, output_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, output, output_len);
}

librdp_status rdp_smartcard_redirection_parse_establish_context_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_establish_context_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &call->scope) != LIBRDP_STATUS_OK ||
        !rdp_smartcard_redirection_scope_valid(call->scope))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_establish_context_call(
    rdp_buffer* buffer,
    uint32_t scope)
{
    if (!buffer || !rdp_smartcard_redirection_scope_valid(scope))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, scope);
}

librdp_status rdp_smartcard_redirection_parse_context(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_context* context)
{
    rdp_stream stream;

    if (!data || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, context) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_context(
    rdp_buffer* buffer,
    const void* data,
    uint32_t length)
{
    return rdp_smartcard_redirection_write_opaque(buffer, data, length);
}

librdp_status rdp_smartcard_redirection_parse_handle(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle* handle)
{
    rdp_stream stream;

    if (!data || !handle)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, handle) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_handle(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_smartcard_redirection_write_opaque(buffer, handle, handle_len);
}

librdp_status rdp_smartcard_redirection_parse_scard_io_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_scard_io_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_scard_io_request(&stream, request) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_scard_io_request(
    rdp_buffer* buffer,
    uint32_t protocol,
    const void* extra_bytes,
    uint32_t extra_bytes_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!extra_bytes && extra_bytes_len > 0) ||
        !rdp_smartcard_redirection_protocol_mask_valid(protocol) ||
        extra_bytes_len > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, protocol);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, extra_bytes_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, extra_bytes, extra_bytes_len);
}

librdp_status rdp_smartcard_redirection_parse_connect_common(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_connect_common* common)
{
    rdp_stream stream;

    if (!data || !common)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(common, 0, sizeof(*common));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &common->context) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) != 8u)
    {
        if (rdp_stream_read_u32_le(&stream, &common->reader_name_is_null) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &common->reader_name_len) != LIBRDP_STATUS_OK ||
            !rdp_smartcard_redirection_length_bool_pair_valid(common->reader_name_is_null,
                                                              common->reader_name_len) ||
            common->reader_name_len > rdp_stream_remaining(&stream) ||
            rdp_stream_remaining(&stream) - common->reader_name_len < 8u ||
            rdp_stream_read_bytes(&stream, &common->reader_name, common->reader_name_len) !=
                LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (common->reader_name_is_null && common->reader_name_len != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
    {
        common->reader_name_is_null = 1;
        common->reader_name_len = 0;
        common->reader_name = NULL;
    }
    if (rdp_stream_read_u32_le(&stream, &common->share_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &common->preferred_protocols) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_share_mode_valid(common->share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(common->preferred_protocols))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_connect_common(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t share_mode,
    uint32_t preferred_protocols)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_share_mode_valid(share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(preferred_protocols))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, share_mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, preferred_protocols);
}

librdp_status rdp_smartcard_redirection_parse_list_reader_groups_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_list_reader_groups_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->groups_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->groups_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->groups_is_null,
                                                          call->groups_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_list_reader_groups_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t groups_is_null,
    uint32_t groups_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_length_bool_pair_valid(groups_is_null, groups_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, groups_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, groups_len);
}

librdp_status rdp_smartcard_redirection_parse_list_readers_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_list_readers_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->groups_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->groups_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->groups_is_null,
                                                          call->groups_len) ||
        call->groups_len > rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (call->groups_is_null && call->groups_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &call->groups, call->groups_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->readers_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->readers_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->readers_is_null,
                                                          call->readers_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_list_readers_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t groups_is_null,
    const void* groups,
    uint32_t groups_len,
    uint32_t readers_is_null,
    uint32_t readers_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!groups && groups_len > 0) ||
        !rdp_smartcard_redirection_length_bool_pair_valid(groups_is_null, groups_len) ||
        !rdp_smartcard_redirection_length_bool_pair_valid(readers_is_null, readers_len) ||
        (groups_is_null && groups_len != 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, groups_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, groups_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, groups, groups_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, readers_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, readers_len);
}

librdp_status rdp_smartcard_redirection_parse_get_status_change_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_get_status_change_call* call)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->timeout) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->reader_count) != LIBRDP_STATUS_OK ||
        call->reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < call->reader_count; i++)
    {
        if (rdp_smartcard_redirection_read_reader_state_call(&stream, &call->readers[i]) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_smartcard_redirection_write_get_status_change_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t timeout,
    const rdp_smartcard_redirection_reader_state_call* readers,
    uint32_t reader_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!readers && reader_count > 0) ||
        reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, timeout);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < reader_count; i++)
    {
        const rdp_smartcard_redirection_reader_state_call* reader = &readers[i];

        if ((!reader->reader_name && reader->reader_name_len > 0) ||
            !rdp_smartcard_redirection_length_bool_pair_valid(reader->reader_name_is_null,
                                                              reader->reader_name_len))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_is_null);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, reader->reader_name, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_smartcard_redirection_write_reader_state_common(buffer,
                                                                     reader->state.current_state,
                                                                     reader->state.event_state,
                                                                     reader->state.atr,
                                                                     reader->state.atr_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_parse_context_string_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_context_string_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->value) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_context_string_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t is_null,
    const void* value,
    uint32_t value_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_smartcard_redirection_write_string(buffer, is_null, value, value_len);
}

librdp_status rdp_smartcard_redirection_parse_context_two_strings_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_context_two_strings_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->first) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->second) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_context_two_strings_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t first_is_null,
    const void* first,
    uint32_t first_len,
    uint32_t second_is_null,
    const void* second,
    uint32_t second_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_string(buffer, first_is_null, first, first_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_smartcard_redirection_write_string(buffer, second_is_null, second, second_len);
}

librdp_status rdp_smartcard_redirection_parse_locate_cards_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_locate_cards_call* call)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->card_names) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->reader_count) != LIBRDP_STATUS_OK ||
        call->reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < call->reader_count; i++)
    {
        if (rdp_smartcard_redirection_read_reader_state_call(&stream, &call->readers[i]) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_smartcard_redirection_write_locate_cards_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t card_names_is_null,
    const void* card_names,
    uint32_t card_names_len,
    const rdp_smartcard_redirection_reader_state_call* readers,
    uint32_t reader_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!readers && reader_count > 0) ||
        reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_string(buffer,
                                                    card_names_is_null,
                                                    card_names,
                                                    card_names_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < reader_count; i++)
    {
        const rdp_smartcard_redirection_reader_state_call* reader = &readers[i];

        if ((!reader->reader_name && reader->reader_name_len > 0) ||
            !rdp_smartcard_redirection_length_bool_pair_valid(reader->reader_name_is_null,
                                                              reader->reader_name_len) ||
            (reader->reader_name_is_null && reader->reader_name_len != 0))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_is_null);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, reader->reader_name, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_smartcard_redirection_write_reader_state_common(buffer,
                                                                     reader->state.current_state,
                                                                     reader->state.event_state,
                                                                     reader->state.atr,
                                                                     reader->state.atr_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_parse_locate_cards_by_atr_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_locate_cards_by_atr_call* call)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->atr_count) != LIBRDP_STATUS_OK ||
        call->atr_count > RDP_SMARTCARD_REDIRECTION_MAX_ATR_MASKS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < call->atr_count; i++)
    {
        const uint8_t* mask_data = NULL;

        if (rdp_stream_read_bytes(&stream,
                                  &mask_data,
                                  4u + (RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH * 2u)) !=
                LIBRDP_STATUS_OK ||
            rdp_smartcard_redirection_parse_atr_mask(
                mask_data,
                4u + (RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH * 2u),
                &call->atr_masks[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_read_u32_le(&stream, &call->reader_count) != LIBRDP_STATUS_OK ||
        call->reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < call->reader_count; i++)
    {
        if (rdp_smartcard_redirection_read_reader_state_call(&stream, &call->readers[i]) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_smartcard_redirection_write_locate_cards_by_atr_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const rdp_smartcard_redirection_atr_mask* atr_masks,
    uint32_t atr_count,
    const rdp_smartcard_redirection_reader_state_call* readers,
    uint32_t reader_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!atr_masks && atr_count > 0) || (!readers && reader_count > 0) ||
        atr_count > RDP_SMARTCARD_REDIRECTION_MAX_ATR_MASKS ||
        reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, atr_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < atr_count; i++)
    {
        status = rdp_smartcard_redirection_write_atr_mask(buffer,
                                                          atr_masks[i].atr,
                                                          atr_masks[i].atr_len,
                                                          atr_masks[i].mask);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    status = rdp_buffer_append_u32_le(buffer, reader_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < reader_count; i++)
    {
        const rdp_smartcard_redirection_reader_state_call* reader = &readers[i];

        if ((!reader->reader_name && reader->reader_name_len > 0) ||
            !rdp_smartcard_redirection_length_bool_pair_valid(reader->reader_name_is_null,
                                                              reader->reader_name_len) ||
            (reader->reader_name_is_null && reader->reader_name_len != 0))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_is_null);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, reader->reader_name, reader->reader_name_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_smartcard_redirection_write_reader_state_common(buffer,
                                                                     reader->state.current_state,
                                                                     reader->state.event_state,
                                                                     reader->state.atr,
                                                                     reader->state.atr_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_parse_reconnect_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reconnect_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->share_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->preferred_protocols) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->initialization) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_share_mode_valid(call->share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(call->preferred_protocols) ||
        !rdp_smartcard_redirection_initialization_valid(call->initialization))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_reconnect_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t share_mode,
    uint32_t preferred_protocols,
    uint32_t initialization)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_share_mode_valid(share_mode) ||
        !rdp_smartcard_redirection_protocol_mask_valid(preferred_protocols) ||
        !rdp_smartcard_redirection_initialization_valid(initialization))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, share_mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, preferred_protocols);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, initialization);
}

librdp_status rdp_smartcard_redirection_parse_handle_disposition_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle_disposition_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->disposition) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_disposition_valid(call->disposition))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_handle_disposition_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t disposition)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_smartcard_redirection_disposition_valid(disposition))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, disposition);
}

librdp_status rdp_smartcard_redirection_parse_state_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_state_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->atr_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->atr_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->atr_is_null, call->atr_len) ||
        call->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_state_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t atr_is_null,
    uint32_t atr_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_length_bool_pair_valid(atr_is_null, atr_len) ||
        atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, atr_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, atr_len);
}

librdp_status rdp_smartcard_redirection_parse_status_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_status_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->reader_names_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->reader_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->atr_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->reader_names_is_null,
                                                          call->reader_len) ||
        call->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_status_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t reader_names_is_null,
    uint32_t reader_len,
    uint32_t atr_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        !rdp_smartcard_redirection_length_bool_pair_valid(reader_names_is_null, reader_len) ||
        atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_names_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, atr_len);
}

librdp_status rdp_smartcard_redirection_parse_transmit_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_transmit_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_scard_io_request(&stream, &call->send_pci) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->send_len) != LIBRDP_STATUS_OK ||
        call->send_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        call->send_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &call->send_data, call->send_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->recv_pci_present) != LIBRDP_STATUS_OK ||
        !rdp_smartcard_redirection_bool_valid(call->recv_pci_present))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (call->recv_pci_present)
    {
        if (rdp_smartcard_redirection_read_scard_io_request(&stream, &call->recv_pci) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_read_u32_le(&stream, &call->recv_buffer_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->recv_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->recv_buffer_is_null,
                                                          call->recv_len) ||
        call->recv_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_transmit_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t send_protocol,
    const void* send_extra,
    uint32_t send_extra_len,
    const void* send_data,
    uint32_t send_len,
    uint32_t recv_pci_present,
    uint32_t recv_protocol,
    const void* recv_extra,
    uint32_t recv_extra_len,
    uint32_t recv_buffer_is_null,
    uint32_t recv_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!send_data && send_len > 0) ||
        send_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        !rdp_smartcard_redirection_bool_valid(recv_pci_present) ||
        !rdp_smartcard_redirection_length_bool_pair_valid(recv_buffer_is_null, recv_len) ||
        recv_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_scard_io_request(buffer,
                                                              send_protocol,
                                                              send_extra,
                                                              send_extra_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, send_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, send_data, send_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, recv_pci_present);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (recv_pci_present)
    {
        status = rdp_smartcard_redirection_write_scard_io_request(buffer,
                                                                  recv_protocol,
                                                                  recv_extra,
                                                                  recv_extra_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    status = rdp_buffer_append_u32_le(buffer, recv_buffer_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, recv_len);
}

librdp_status rdp_smartcard_redirection_parse_control_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_control_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->control_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->input_len) != LIBRDP_STATUS_OK ||
        call->input_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        call->input_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &call->input, call->input_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->output_buffer_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->output_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->output_buffer_is_null,
                                                          call->output_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_control_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t control_code,
    const void* input,
    uint32_t input_len,
    uint32_t output_buffer_is_null,
    uint32_t output_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!input && input_len > 0) ||
        input_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        !rdp_smartcard_redirection_length_bool_pair_valid(output_buffer_is_null, output_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, control_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, input, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, output_buffer_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, output_len);
}

librdp_status rdp_smartcard_redirection_parse_attrib_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_attrib_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->attr_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->attr_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->attr_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->attr_is_null, call->attr_len) ||
        call->attr_len > RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_attrib_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t attr_id,
    uint32_t attr_is_null,
    uint32_t attr_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_length_bool_pair_valid(attr_is_null, attr_len) ||
        attr_len > RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, attr_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, attr_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, attr_len);
}

librdp_status rdp_smartcard_redirection_parse_set_attrib_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_set_attrib_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_handle(&stream, &call->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->attr_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->attr_len) != LIBRDP_STATUS_OK ||
        call->attr_len > RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH ||
        call->attr_len != rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &call->attr, call->attr_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_set_attrib_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t attr_id,
    const void* attr,
    uint32_t attr_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!attr && attr_len > 0) ||
        attr_len > RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, attr_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, attr_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, attr, attr_len);
}

librdp_status rdp_smartcard_redirection_parse_read_cache_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_read_cache_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream,
                              &call->card_identifier,
                              RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->freshness_counter) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->lookup_name) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->data_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->data_is_null, call->data_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_read_cache_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    uint32_t freshness_counter,
    uint32_t lookup_name_is_null,
    const void* lookup_name,
    uint32_t lookup_name_len,
    uint32_t data_is_null,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !card_identifier ||
        !rdp_smartcard_redirection_length_bool_pair_valid(data_is_null, data_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer,
                               card_identifier,
                               RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, freshness_counter);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_string(buffer,
                                                    lookup_name_is_null,
                                                    lookup_name,
                                                    lookup_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, data_len);
}

librdp_status rdp_smartcard_redirection_parse_write_cache_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_write_cache_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream,
                              &call->card_identifier,
                              RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->freshness_counter) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->lookup_name) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->data_len) != LIBRDP_STATUS_OK ||
        call->data_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        call->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &call->data, call->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_write_cache_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    uint32_t freshness_counter,
    uint32_t lookup_name_is_null,
    const void* lookup_name,
    uint32_t lookup_name_len,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !card_identifier || (!data && data_len > 0) ||
        data_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer,
                               card_identifier,
                               RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, freshness_counter);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_string(buffer,
                                                    lookup_name_is_null,
                                                    lookup_name,
                                                    lookup_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_smartcard_redirection_parse_reader_name_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reader_name_call* call)
{
    rdp_stream stream;

    if (!data || !call)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(call, 0, sizeof(*call));
    rdp_stream_init(&stream, data, length);
    if (rdp_smartcard_redirection_read_context(&stream, &call->context) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_string(&stream, &call->reader_name) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->output_is_null) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &call->output_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_length_bool_pair_valid(call->output_is_null,
                                                          call->output_len))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_reader_name_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t reader_name_is_null,
    const void* reader_name,
    uint32_t reader_name_len,
    uint32_t output_is_null,
    uint32_t output_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_length_bool_pair_valid(output_is_null, output_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_string(buffer,
                                                    reader_name_is_null,
                                                    reader_name,
                                                    reader_name_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, output_is_null);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, output_len);
}

librdp_status rdp_smartcard_redirection_parse_long_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_long_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_long_return(
    rdp_buffer* buffer,
    uint32_t return_code)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, return_code);
}

librdp_status rdp_smartcard_redirection_parse_count_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_count_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->value) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_count_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, value);
}

librdp_status rdp_smartcard_redirection_parse_buffer_return(
    const void* data,
    size_t length,
    uint32_t max_data_len,
    rdp_smartcard_redirection_buffer_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (result->data_len > max_data_len || result->data_len != rdp_stream_remaining(&stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &result->data, result->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_buffer_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* data,
    uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0) ||
        data_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, data, data_len);
}

librdp_status rdp_smartcard_redirection_write_establish_context_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* context,
    uint32_t context_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_smartcard_redirection_write_opaque(buffer, context, context_len);
}

librdp_status rdp_smartcard_redirection_parse_establish_context_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_establish_context_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_context(&stream, &result->context) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_connect_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t active_protocol)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_protocol_mask_valid(active_protocol))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_handle(buffer, context, context_len, handle, handle_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, active_protocol);
}

librdp_status rdp_smartcard_redirection_parse_connect_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_connect_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_handle(&stream, &result->handle) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->active_protocol) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_protocol_mask_valid(result->active_protocol))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_reconnect_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t active_protocol)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_smartcard_redirection_protocol_mask_valid(active_protocol))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, active_protocol);
}

librdp_status rdp_smartcard_redirection_write_status_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* reader_names,
    uint32_t reader_names_len,
    uint32_t state,
    uint32_t protocol,
    const void* atr,
    uint32_t atr_len)
{
    uint8_t atr_storage[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!reader_names && reader_names_len > 0) || (!atr && atr_len > 0) ||
        reader_names_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ||
        !rdp_smartcard_redirection_protocol_mask_valid(protocol))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (atr_len > 0)
        memcpy(atr_storage, atr, atr_len);
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_names_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, reader_names, reader_names_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, state);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, protocol);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, atr_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, atr_storage, sizeof(atr_storage));
}

librdp_status rdp_smartcard_redirection_parse_status_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_status_return* result)
{
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 20u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->reader_names_len) != LIBRDP_STATUS_OK ||
        result->reader_names_len > RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH ||
        result->reader_names_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &result->reader_names, result->reader_names_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->state) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->protocol) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->atr_len) != LIBRDP_STATUS_OK ||
        result->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ||
        rdp_stream_remaining(&stream) != RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ||
        rdp_stream_read_bytes(&stream, &result->atr, RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_smartcard_redirection_protocol_mask_valid(result->protocol))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_transmit_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t recv_protocol,
    const void* recv_extra,
    uint32_t recv_extra_len,
    const void* recv_data,
    uint32_t recv_data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!recv_extra && recv_extra_len > 0) || (!recv_data && recv_data_len > 0) ||
        recv_extra_len > RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA ||
        recv_data_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        !rdp_smartcard_redirection_protocol_mask_valid(recv_protocol))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_smartcard_redirection_write_scard_io_request(buffer,
                                                              recv_protocol,
                                                              recv_extra,
                                                              recv_extra_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, recv_data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, recv_data, recv_data_len);
}

librdp_status rdp_smartcard_redirection_parse_transmit_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_transmit_return* result)
{
    rdp_stream stream;
    rdp_smartcard_redirection_scard_io_request io;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(result, 0, sizeof(*result));
    memset(&io, 0, sizeof(io));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_smartcard_redirection_read_scard_io_request(&stream, &io) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->recv_data_len) != LIBRDP_STATUS_OK ||
        result->recv_data_len > RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH ||
        result->recv_data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &result->recv_data, result->recv_data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    result->recv_protocol = io.protocol;
    result->recv_extra = io.extra_bytes;
    result->recv_extra_len = io.extra_bytes_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_write_get_status_change_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const rdp_smartcard_redirection_reader_state_common* readers,
    uint32_t reader_count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!readers && reader_count > 0) ||
        reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, return_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, reader_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < reader_count; i++)
    {
        status = rdp_smartcard_redirection_write_reader_state_common(buffer,
                                                                     readers[i].current_state,
                                                                     readers[i].event_state,
                                                                     readers[i].atr,
                                                                     readers[i].atr_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_smartcard_redirection_parse_get_status_change_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_get_status_change_return* result)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &result->return_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &result->reader_count) != LIBRDP_STATUS_OK ||
        result->reader_count > RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < result->reader_count; i++)
    {
        const uint8_t* state_data = NULL;

        if (rdp_stream_read_bytes(&stream,
                                  &state_data,
                                  12u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) !=
                LIBRDP_STATUS_OK ||
            rdp_smartcard_redirection_parse_reader_state_common(
                state_data,
                12u + RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH,
                &result->readers[i]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}
