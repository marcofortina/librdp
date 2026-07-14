/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: smartcard device redirection and PC/SC request handling.
 * Invariants: remote contexts and card handles are generation-checked before
 * PC/SC calls, and APDU/control payloads are capped by device policy.
 * Ownership: smartcard contexts, handles, cache entries, and reader group state
 * are session-owned and cleared on disconnect or free.
 * Threading: requests execute on the session owner thread through the configured
 * smartcard backend; cancellation boundaries are handled by backend policy.
 * Trust boundary: server-supplied blobs, reader names, ATR masks, and APDUs are
 * parsed and length-checked before backend calls or trace emission.
 */

#include "client/session_internal.h"
#include "client/smartcard_backend.h"
#include "common/charset.h"
#include "common/trace.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static librdp_status rdp_session_send_smartcard_io_completion(librdp_session* session,
                                                              const rdp_device_redirection_io_request* request,
                                                              const rdp_buffer* payload,
                                                              const char* event)
{
    rdp_buffer wrapped;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&wrapped);
    rdp_buffer_init(&response);
    status = rdp_smartcard_redirection_write_device_control_response(&wrapped,
                                                                     payload->data,
                                                                     (uint32_t)payload->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_device_redirection_write_io_completion(&response,
                                                            request->device_id,
                                                            request->completion_id,
                                                            RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                            wrapped.data,
                                                            wrapped.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session, &response, event);
    rdp_buffer_free(&response);
    rdp_buffer_free(&wrapped);
    return status;
}

static librdp_status rdp_session_send_smartcard_simple_completion(librdp_session* session,
                                                                  const rdp_device_redirection_io_request* request,
                                                                  uint32_t io_status,
                                                                  const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request->device_id,
                                                        request->completion_id,
                                                        io_status,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session, &response, event);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_send_smartcard_long_result(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request,
                                                            uint32_t return_code,
                                                            const char* event)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_smartcard_redirection_write_long_return(&payload, return_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session, request, &payload, event);
    rdp_buffer_free(&payload);
    return status;
}

#ifdef RDP_HAVE_PCSC
static void rdp_session_smartcard_write_blob(uint8_t blob[RDP_SESSION_SMARTCARD_BLOB_BYTES],
                                             uint32_t id,
                                             uint32_t generation)
{
    blob[0] = (uint8_t)(id & 0xffu);
    blob[1] = (uint8_t)((id >> 8u) & 0xffu);
    blob[2] = (uint8_t)((id >> 16u) & 0xffu);
    blob[3] = (uint8_t)((id >> 24u) & 0xffu);
    blob[4] = (uint8_t)(generation & 0xffu);
    blob[5] = (uint8_t)((generation >> 8u) & 0xffu);
    blob[6] = (uint8_t)((generation >> 16u) & 0xffu);
    blob[7] = (uint8_t)((generation >> 24u) & 0xffu);
}

static int rdp_session_smartcard_read_blob(const uint8_t* data,
                                           uint32_t length,
                                           uint32_t* id,
                                           uint32_t* generation)
{
    if (!data || length != RDP_SESSION_SMARTCARD_BLOB_BYTES || !id || !generation)
        return 0;
    *id = (uint32_t)data[0] | ((uint32_t)data[1] << 8u) | ((uint32_t)data[2] << 16u) |
          ((uint32_t)data[3] << 24u);
    *generation = (uint32_t)data[4] | ((uint32_t)data[5] << 8u) | ((uint32_t)data[6] << 16u) |
                  ((uint32_t)data[7] << 24u);
    return *id != 0 && *generation != 0;
}

static rdp_session_smartcard_context* rdp_session_smartcard_context_find(librdp_session* session,
                                                                         const uint8_t* data,
                                                                         uint32_t length)
{
    uint32_t id = 0;
    uint32_t generation = 0;

    if (!session || !rdp_session_smartcard_read_blob(data, length, &id, &generation))
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (context->active && context->id == id && context->generation == generation)
            return context;
    }
    return NULL;
}

static rdp_session_smartcard_handle* rdp_session_smartcard_handle_find(librdp_session* session,
                                                                       const uint8_t* data,
                                                                       uint32_t length)
{
    uint32_t id = 0;
    uint32_t generation = 0;

    if (!session || !rdp_session_smartcard_read_blob(data, length, &id, &generation))
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (handle->active && handle->id == id && handle->generation == generation)
            return handle;
    }
    return NULL;
}

static rdp_session_smartcard_context* rdp_session_smartcard_context_for_handle(
    librdp_session* session,
    const rdp_session_smartcard_handle* handle)
{
    if (!session || !handle)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (context->active &&
            context->id == handle->context_id &&
            context->generation == handle->context_generation)
            return context;
    }
    return NULL;
}

static rdp_session_smartcard_context* rdp_session_smartcard_context_alloc(librdp_session* session,
                                                                          SCARDCONTEXT pcsc_context)
{
    if (!session)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (!context->active)
        {
            memset(context, 0, sizeof(*context));
            context->active = 1;
            context->id = ++session->next_smartcard_context_id;
            if (context->id == 0)
                context->id = ++session->next_smartcard_context_id;
            context->generation++;
            if (context->generation == 0)
                context->generation = 1;
            context->context = pcsc_context;
            return context;
        }
    }
    return NULL;
}

static rdp_session_smartcard_handle* rdp_session_smartcard_handle_alloc(
    librdp_session* session,
    const rdp_session_smartcard_context* context,
    SCARDHANDLE pcsc_handle,
    DWORD active_protocol)
{
    if (!session || !context)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (!handle->active)
        {
            memset(handle, 0, sizeof(*handle));
            handle->active = 1;
            handle->id = ++session->next_smartcard_handle_id;
            if (handle->id == 0)
                handle->id = ++session->next_smartcard_handle_id;
            handle->generation++;
            if (handle->generation == 0)
                handle->generation = 1;
            handle->context_id = context->id;
            handle->context_generation = context->generation;
            handle->handle = pcsc_handle;
            handle->active_protocol = active_protocol;
            return handle;
        }
    }
    return NULL;
}

static DWORD rdp_session_smartcard_protocol_to_pcsc(uint32_t protocol)
{
    uint32_t base = protocol & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;
    DWORD pcsc = 0;

    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED)
        pcsc = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    if ((base & RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0) != 0)
        pcsc |= SCARD_PROTOCOL_T0;
    if ((base & RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1) != 0)
        pcsc |= SCARD_PROTOCOL_T1;
#ifdef SCARD_PROTOCOL_T15
    if ((base & RDP_SMARTCARD_REDIRECTION_PROTOCOL_T15) != 0)
        pcsc |= SCARD_PROTOCOL_T15;
#endif
#ifdef SCARD_PROTOCOL_RAW
    if ((base & RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW) != 0)
        pcsc |= SCARD_PROTOCOL_RAW;
#endif
    return pcsc;
}

static uint32_t rdp_session_smartcard_protocol_from_pcsc(DWORD protocol)
{
    uint32_t value = RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED;

    if (protocol & SCARD_PROTOCOL_T1)
        value |= RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1;
    if (protocol & SCARD_PROTOCOL_T0)
        value |= RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0;
#ifdef SCARD_PROTOCOL_T15
    if (protocol & SCARD_PROTOCOL_T15)
        value |= RDP_SMARTCARD_REDIRECTION_PROTOCOL_T15;
#endif
#ifdef SCARD_PROTOCOL_RAW
    if (protocol & SCARD_PROTOCOL_RAW)
        value |= RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW;
#endif
    return value;
}

static uint32_t rdp_session_smartcard_u32_from_dword(DWORD value)
{
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static uint8_t* rdp_session_smartcard_utf8_multisz_to_utf16le(const char* text,
                                                              uint32_t text_len,
                                                              uint32_t* out_len)
{
    uint8_t* output = NULL;
    size_t output_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!text || !out_len)
        return NULL;
    status = rdp_charset_utf8_bytes_to_utf16le_alloc((const uint8_t*)text,
                                                     text_len,
                                                     0,
                                                     &output,
                                                     &output_len);
    if (status != LIBRDP_STATUS_OK || output_len > UINT32_MAX)
    {
        free(output);
        return NULL;
    }
    *out_len = (uint32_t)output_len;
    return output;
}

static char* rdp_session_smartcard_utf16le_to_utf8_multisz(const uint8_t* text, uint32_t text_len)
{
    char* output = NULL;
    size_t output_len = 0;

    if (!text || text_len > (UINT32_MAX / 2u) || (text_len % 2u) != 0)
        return NULL;
    if (rdp_charset_utf16le_to_utf8_alloc(text, text_len, 0, &output, &output_len) != LIBRDP_STATUS_OK)
        return NULL;
    (void)output_len;
    return output;
}

static const SCARD_IO_REQUEST* rdp_session_smartcard_pci_from_protocol(uint32_t protocol)
{
    uint32_t base = protocol & ~RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT;

    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED)
        return NULL;
    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0)
        return SCARD_PCI_T0;
    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1)
        return SCARD_PCI_T1;
#ifdef SCARD_PCI_RAW
    if (base == RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW)
        return SCARD_PCI_RAW;
#endif
    return NULL;
}

static DWORD rdp_session_smartcard_scope_to_pcsc(uint32_t scope)
{
    if (scope == RDP_SMARTCARD_REDIRECTION_SCOPE_USER)
        return SCARD_SCOPE_USER;
    if (scope == RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL)
#ifdef SCARD_SCOPE_TERMINAL
        return SCARD_SCOPE_TERMINAL;
#else
        return SCARD_SCOPE_SYSTEM;
#endif
    return SCARD_SCOPE_SYSTEM;
}

static char* rdp_session_smartcard_connect_reader_name(
    const rdp_smartcard_redirection_request_message* message,
    LONG* pcsc_status)
{
    char* reader_name = NULL;
    int wide = 0;

    if (pcsc_status)
        *pcsc_status = SCARD_S_SUCCESS;
    if (!message || message->body.connect.reader_name_is_null ||
        message->body.connect.reader_name_len == 0 || !message->body.connect.reader_name)
        return NULL;
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW;
    if (wide)
    {
        reader_name = rdp_session_smartcard_utf16le_to_utf8_multisz(
            message->body.connect.reader_name,
            message->body.connect.reader_name_len);
        if (!reader_name && pcsc_status)
            *pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        return reader_name;
    }
    reader_name = (char*)calloc((size_t)message->body.connect.reader_name_len + 1u, 1u);
    if (!reader_name)
    {
        if (pcsc_status)
            *pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        return NULL;
    }
    memcpy(reader_name, message->body.connect.reader_name, message->body.connect.reader_name_len);
    return reader_name;
}

static char* rdp_session_smartcard_string_to_utf8(const rdp_smartcard_redirection_string* value,
                                                  int wide)
{
    char* text = NULL;

    if (!value || value->is_null || value->length == 0 || !value->data)
        return NULL;
    if (wide)
        return rdp_session_smartcard_utf16le_to_utf8_multisz(value->data, value->length);
    text = (char*)calloc((size_t)value->length + 1u, 1u);
    if (!text)
        return NULL;
    memcpy(text, value->data, value->length);
    return text;
}

static char* rdp_session_smartcard_reader_state_name_to_utf8(
    const rdp_smartcard_redirection_reader_state_call* reader,
    int wide)
{
    rdp_smartcard_redirection_string value;

    if (!reader)
        return NULL;
    memset(&value, 0, sizeof(value));
    value.is_null = reader->reader_name_is_null;
    value.length = reader->reader_name_len;
    value.data = reader->reader_name;
    return rdp_session_smartcard_string_to_utf8(&value, wide);
}

static void rdp_session_smartcard_reader_common_from_pcsc(
    rdp_smartcard_redirection_reader_state_common* out,
    uint32_t current_state,
    uint32_t event_state,
    uint32_t atr_len,
    const uint8_t* atr)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->current_state = current_state;
    out->event_state = event_state;
    out->atr_len = atr_len <= RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ? atr_len : 0;
    if (out->atr_len > 0 && atr)
        memcpy(out->atr, atr, out->atr_len);
}

#ifndef RDP_HAVE_WINPR_SMARTCARD
static void rdp_session_smartcard_cache_entry_clear(rdp_session_smartcard_cache_entry* entry)
{
    if (!entry)
        return;
    free(entry->lookup_name);
    free(entry->data);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_smartcard_cache_reset(librdp_session* session)
{
    if (!session)
        return;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CACHE_ENTRIES; i++)
        rdp_session_smartcard_cache_entry_clear(&session->smartcard_cache[i]);
    session->smartcard_cache_clock = 0;
}

static uint64_t rdp_session_smartcard_cache_next_clock(librdp_session* session)
{
    if (!session)
        return 0;
    session->smartcard_cache_clock++;
    if (session->smartcard_cache_clock == 0)
        session->smartcard_cache_clock = 1;
    return session->smartcard_cache_clock;
}

static rdp_session_smartcard_cache_entry* rdp_session_smartcard_cache_find(
    librdp_session* session,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    const char* lookup_name)
{
    if (!session || !card_identifier || !lookup_name)
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CACHE_ENTRIES; i++)
    {
        rdp_session_smartcard_cache_entry* entry = &session->smartcard_cache[i];

        if (entry->active &&
            memcmp(entry->card_identifier,
                   card_identifier,
                   RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH) == 0 &&
            entry->lookup_name && strcmp(entry->lookup_name, lookup_name) == 0)
            return entry;
    }
    return NULL;
}

static rdp_session_smartcard_cache_entry* rdp_session_smartcard_cache_alloc(
    librdp_session* session,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    const char* lookup_name)
{
    rdp_session_smartcard_cache_entry* candidate = NULL;

    if (!session || !card_identifier || !lookup_name)
        return NULL;
    candidate = rdp_session_smartcard_cache_find(session, card_identifier, lookup_name);
    if (candidate)
        return candidate;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CACHE_ENTRIES; i++)
    {
        if (!session->smartcard_cache[i].active)
            return &session->smartcard_cache[i];
        if (!candidate || session->smartcard_cache[i].clock < candidate->clock)
            candidate = &session->smartcard_cache[i];
    }
    rdp_session_smartcard_cache_entry_clear(candidate);
    return candidate;
}

static LONG rdp_session_smartcard_cache_write(
    librdp_session* session,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    uint32_t freshness_counter,
    const char* lookup_name,
    const uint8_t* data,
    uint32_t data_len)
{
    rdp_session_smartcard_cache_entry* entry = NULL;
    char* stored_name = NULL;
    uint8_t* stored_data = NULL;

    if (!session || !card_identifier || !lookup_name || (!data && data_len > 0) ||
        data_len > RDP_SESSION_SMARTCARD_MAX_IO_BYTES)
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    entry = rdp_session_smartcard_cache_alloc(session, card_identifier, lookup_name);
    if (!entry)
        return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
    stored_name = rdp_session_strdup_range(lookup_name, strlen(lookup_name));
    if (!stored_name)
        return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
    if (data_len > 0)
    {
        stored_data = (uint8_t*)malloc(data_len);
        if (!stored_data)
        {
            free(stored_name);
            return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        memcpy(stored_data, data, data_len);
    }
    rdp_session_smartcard_cache_entry_clear(entry);
    entry->active = 1u;
    memcpy(entry->card_identifier,
           card_identifier,
           RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH);
    entry->freshness_counter = freshness_counter;
    entry->lookup_name = stored_name;
    entry->data = stored_data;
    entry->data_len = data_len;
    entry->clock = rdp_session_smartcard_cache_next_clock(session);
    return SCARD_S_SUCCESS;
}

static LONG rdp_session_smartcard_cache_read(
    librdp_session* session,
    const uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH],
    uint32_t freshness_counter,
    const char* lookup_name,
    uint8_t* data,
    DWORD* data_len)
{
    rdp_session_smartcard_cache_entry* entry = NULL;

    if (!session || !card_identifier || !lookup_name || !data_len)
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    entry = rdp_session_smartcard_cache_find(session, card_identifier, lookup_name);
    if (!entry || entry->freshness_counter < freshness_counter)
        return (LONG)RDP_SESSION_SCARD_E_FILE_NOT_FOUND;
    if (*data_len < entry->data_len)
    {
        *data_len = entry->data_len;
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    if (entry->data_len > 0 && data)
        memcpy(data, entry->data, entry->data_len);
    *data_len = entry->data_len;
    entry->clock = rdp_session_smartcard_cache_next_clock(session);
    return SCARD_S_SUCCESS;
}

static void rdp_session_smartcard_group_entry_clear(rdp_session_smartcard_group_entry* entry)
{
    if (!entry)
        return;
    free(entry->name);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_smartcard_reader_group_entry_clear(
    rdp_session_smartcard_reader_group_entry* entry)
{
    if (!entry)
        return;
    free(entry->reader);
    free(entry->group);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_smartcard_groups_reset(librdp_session* session)
{
    if (!session)
        return;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_GROUPS; i++)
        rdp_session_smartcard_group_entry_clear(&session->smartcard_groups[i]);
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
        rdp_session_smartcard_reader_group_entry_clear(&session->smartcard_reader_groups[i]);
}

static char* rdp_session_smartcard_dup_first_string(const char* value)
{
    size_t length = 0;

    if (!value || value[0] == '\0')
        return NULL;
    length = strlen(value);
    while (length > 0 && value[length - 1u] == '\0')
        length--;
    if (length == 0)
        return NULL;
    return rdp_session_strdup_range(value, length);
}

static int rdp_session_smartcard_multisz_contains(const char* data,
                                                  uint32_t data_len,
                                                  const char* value)
{
    uint32_t offset = 0;

    if (!data || !value || value[0] == '\0')
        return 0;
    while (offset < data_len && data[offset] != '\0')
    {
        size_t item_len = strnlen(data + offset, data_len - offset);

        if (item_len == strlen(value) && memcmp(data + offset, value, item_len) == 0)
            return 1;
        offset += (uint32_t)item_len + 1u;
    }
    return 0;
}

static librdp_status rdp_session_smartcard_multisz_append_unique(rdp_buffer* out,
                                                                 const char* value)
{
    if (!out || !value || value[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_session_smartcard_multisz_contains((const char*)out->data,
                                               (uint32_t)out->length,
                                               value))
        return LIBRDP_STATUS_OK;
    return rdp_buffer_append(out, value, strlen(value) + 1u);
}

static rdp_session_smartcard_group_entry* rdp_session_smartcard_group_find(
    librdp_session* session,
    const char* name)
{
    if (!session || !name || name[0] == '\0')
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_GROUPS; i++)
    {
        rdp_session_smartcard_group_entry* entry = &session->smartcard_groups[i];

        if (entry->active && entry->name && strcmp(entry->name, name) == 0)
            return entry;
    }
    return NULL;
}

static LONG rdp_session_smartcard_group_add(librdp_session* session, const char* name)
{
    char* stored = NULL;

    if (!session || !name || name[0] == '\0')
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    if (rdp_session_smartcard_group_find(session, name))
        return SCARD_S_SUCCESS;
    stored = rdp_session_smartcard_dup_first_string(name);
    if (!stored)
        return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_GROUPS; i++)
    {
        rdp_session_smartcard_group_entry* entry = &session->smartcard_groups[i];

        if (!entry->active)
        {
            entry->active = 1u;
            entry->name = stored;
            return SCARD_S_SUCCESS;
        }
    }
    free(stored);
    return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
}

static LONG rdp_session_smartcard_group_remove(librdp_session* session, const char* name)
{
    if (!session || !name || name[0] == '\0')
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_GROUPS; i++)
    {
        rdp_session_smartcard_group_entry* entry = &session->smartcard_groups[i];

        if (entry->active && entry->name && strcmp(entry->name, name) == 0)
            rdp_session_smartcard_group_entry_clear(entry);
    }
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (entry->active && entry->group && strcmp(entry->group, name) == 0)
            rdp_session_smartcard_reader_group_entry_clear(entry);
    }
    return SCARD_S_SUCCESS;
}

static rdp_session_smartcard_reader_group_entry* rdp_session_smartcard_reader_group_find(
    librdp_session* session,
    const char* reader,
    const char* group)
{
    if (!session || !reader || !group || reader[0] == '\0' || group[0] == '\0')
        return NULL;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (entry->active && entry->reader && entry->group &&
            strcmp(entry->reader, reader) == 0 && strcmp(entry->group, group) == 0)
            return entry;
    }
    return NULL;
}

static LONG rdp_session_smartcard_reader_group_add(librdp_session* session,
                                                   const char* reader,
                                                   const char* group)
{
    char* stored_reader = NULL;
    char* stored_group = NULL;
    LONG pcsc_status = SCARD_S_SUCCESS;

    if (!session || !reader || !group || reader[0] == '\0' || group[0] == '\0')
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    if (rdp_session_smartcard_reader_group_find(session, reader, group))
        return SCARD_S_SUCCESS;
    pcsc_status = rdp_session_smartcard_group_add(session, group);
    if (pcsc_status != SCARD_S_SUCCESS)
        return pcsc_status;
    stored_reader = rdp_session_smartcard_dup_first_string(reader);
    stored_group = rdp_session_smartcard_dup_first_string(group);
    if (!stored_reader || !stored_group)
    {
        free(stored_group);
        free(stored_reader);
        return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
    }
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (!entry->active)
        {
            entry->active = 1u;
            entry->reader = stored_reader;
            entry->group = stored_group;
            return SCARD_S_SUCCESS;
        }
    }
    free(stored_group);
    free(stored_reader);
    return (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
}

static LONG rdp_session_smartcard_reader_group_remove(librdp_session* session,
                                                      const char* reader,
                                                      const char* group)
{
    if (!session || !reader || !group || reader[0] == '\0' || group[0] == '\0')
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (entry->active && entry->reader && entry->group &&
            strcmp(entry->reader, reader) == 0 && strcmp(entry->group, group) == 0)
            rdp_session_smartcard_reader_group_entry_clear(entry);
    }
    return SCARD_S_SUCCESS;
}

static LONG rdp_session_smartcard_reader_forget(librdp_session* session, const char* reader)
{
    if (!session || !reader || reader[0] == '\0')
        return (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (entry->active && entry->reader && strcmp(entry->reader, reader) == 0)
            rdp_session_smartcard_reader_group_entry_clear(entry);
    }
    return SCARD_S_SUCCESS;
}

static librdp_status rdp_session_smartcard_build_local_groups(librdp_session* session,
                                                              const char* existing,
                                                              uint32_t existing_len,
                                                              char** out,
                                                              uint32_t* out_len)
{
    rdp_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t offset = 0;

    if (!session || !out || !out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    *out_len = 0;
    rdp_buffer_init(&buffer);
    while (existing && offset < existing_len && existing[offset] != '\0')
    {
        size_t item_len = strnlen(existing + offset, existing_len - offset);

        if (item_len > 0)
            status = rdp_session_smartcard_multisz_append_unique(&buffer, existing + offset);
        if (status != LIBRDP_STATUS_OK)
            break;
        offset += (uint32_t)item_len + 1u;
    }
    for (uint32_t i = 0; status == LIBRDP_STATUS_OK && i < RDP_SESSION_MAX_SMARTCARD_GROUPS; i++)
    {
        rdp_session_smartcard_group_entry* entry = &session->smartcard_groups[i];

        if (entry->active && entry->name)
            status = rdp_session_smartcard_multisz_append_unique(&buffer, entry->name);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&buffer, 0);
    if (status == LIBRDP_STATUS_OK)
    {
        *out = (char*)buffer.data;
        *out_len = (uint32_t)buffer.length;
        memset(&buffer, 0, sizeof(buffer));
    }
    rdp_buffer_free(&buffer);
    return status;
}

static int rdp_session_smartcard_group_filter_allows(const char* groups,
                                                     uint32_t groups_len,
                                                     const char* group)
{
    if (!group || group[0] == '\0')
        return 0;
    if (!groups || groups_len == 0 || groups[0] == '\0')
        return 1;
    return rdp_session_smartcard_multisz_contains(groups, groups_len, group);
}

static librdp_status rdp_session_smartcard_build_local_readers(librdp_session* session,
                                                               const char* existing,
                                                               uint32_t existing_len,
                                                               const char* groups,
                                                               uint32_t groups_len,
                                                               char** out,
                                                               uint32_t* out_len)
{
    rdp_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t offset = 0;

    if (!session || !out || !out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *out = NULL;
    *out_len = 0;
    rdp_buffer_init(&buffer);
    while (existing && offset < existing_len && existing[offset] != '\0')
    {
        size_t item_len = strnlen(existing + offset, existing_len - offset);

        if (item_len > 0)
            status = rdp_session_smartcard_multisz_append_unique(&buffer, existing + offset);
        if (status != LIBRDP_STATUS_OK)
            break;
        offset += (uint32_t)item_len + 1u;
    }
    for (uint32_t i = 0; status == LIBRDP_STATUS_OK && i < RDP_SESSION_MAX_SMARTCARD_READER_GROUPS; i++)
    {
        rdp_session_smartcard_reader_group_entry* entry = &session->smartcard_reader_groups[i];

        if (entry->active && entry->reader && entry->group &&
            rdp_session_smartcard_group_filter_allows(groups, groups_len, entry->group))
            status = rdp_session_smartcard_multisz_append_unique(&buffer, entry->reader);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&buffer, 0);
    if (status == LIBRDP_STATUS_OK)
    {
        *out = (char*)buffer.data;
        *out_len = (uint32_t)buffer.length;
        memset(&buffer, 0, sizeof(buffer));
    }
    rdp_buffer_free(&buffer);
    return status;
}
#endif

void rdp_session_smartcard_reset(librdp_session* session)
{
    if (!session)
        return;
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_HANDLES; i++)
    {
        rdp_session_smartcard_handle* handle = &session->smartcard_handles[i];

        if (handle->active)
        {
            (void)rdp_smartcard_backend_disconnect(&session->smartcard_backend,
                                                   handle->handle,
                                                   SCARD_LEAVE_CARD);
            memset(handle, 0, sizeof(*handle));
        }
    }
    for (uint32_t i = 0; i < RDP_SESSION_MAX_SMARTCARD_CONTEXTS; i++)
    {
        rdp_session_smartcard_context* context = &session->smartcard_contexts[i];

        if (context->active)
        {
            (void)rdp_smartcard_backend_release_context(&session->smartcard_backend,
                                                        context->context);
            memset(context, 0, sizeof(*context));
        }
    }
#ifndef RDP_HAVE_WINPR_SMARTCARD
    rdp_session_smartcard_cache_reset(session);
    rdp_session_smartcard_groups_reset(session);
#endif
}

static librdp_status rdp_session_smartcard_handle_establish(librdp_session* session,
                                                            const rdp_device_redirection_io_request* request,
                                                            const rdp_smartcard_redirection_request_message* message)
{
    rdp_buffer payload;
    uint8_t context_blob[RDP_SESSION_SMARTCARD_BLOB_BYTES];
    SCARDCONTEXT pcsc_context = 0;
    rdp_session_smartcard_context* context = NULL;
    LONG pcsc_status = SCARD_S_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    memset(context_blob, 0, sizeof(context_blob));
    pcsc_status = rdp_smartcard_backend_establish_context(
        &session->smartcard_backend,
        rdp_session_smartcard_scope_to_pcsc(message->body.establish_context.scope),
        &pcsc_context);
    if (pcsc_status == SCARD_S_SUCCESS)
    {
        context = rdp_session_smartcard_context_alloc(session, pcsc_context);
        if (!context)
        {
            (void)rdp_smartcard_backend_release_context(&session->smartcard_backend, pcsc_context);
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        else
        {
            rdp_session_smartcard_write_blob(context_blob, context->id, context->generation);
        }
    }
    status = rdp_smartcard_redirection_write_establish_context_return(&payload,
                                                                      (uint32_t)pcsc_status,
                                                                      context_blob,
                                                                      pcsc_status == SCARD_S_SUCCESS ?
                                                                          sizeof(context_blob) :
                                                                          0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.establish_context");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.establish_context",
                    "device_id=%u completion_id=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_context(librdp_session* session,
                                                          const rdp_device_redirection_io_request* request,
                                                          const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;

    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context.data,
                                                 message->body.context.length);
    if (context)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT)
        {
            pcsc_status = rdp_smartcard_backend_release_context(&session->smartcard_backend,
                                                                context->context);
            if (pcsc_status == SCARD_S_SUCCESS)
                memset(context, 0, sizeof(*context));
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT)
        {
            pcsc_status = rdp_smartcard_backend_is_valid_context(&session->smartcard_backend,
                                                                 context->context);
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL)
        {
            pcsc_status = rdp_smartcard_backend_cancel(&session->smartcard_backend,
                                                       context->context);
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.context",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.context.response");
}

static librdp_status rdp_session_smartcard_send_buffer_result(librdp_session* session,
                                                              const rdp_device_redirection_io_request* request,
                                                              uint32_t return_code,
                                                              const void* data,
                                                              uint32_t data_len,
                                                              const char* event)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_smartcard_redirection_write_buffer_return(&payload, return_code, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session, request, &payload, event);
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Handle the PC/SC list-reader-groups request for smartcard redirection.
 * Backend strings are converted into protocol multistrings without retaining
 * provider-owned memory.
 */
static librdp_status rdp_session_smartcard_handle_list_reader_groups(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    char* groups = NULL;
    char* merged_groups = NULL;
    uint8_t* wide_groups = NULL;
    uint32_t output_len = 0;
    uint32_t merged_groups_len = 0;
    DWORD groups_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    int wide = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.list_reader_groups.context.data,
                                                 message->body.list_reader_groups.context.length);
    if (context)
    {
        pcsc_status = rdp_smartcard_backend_list_reader_groups(&session->smartcard_backend,
                                                               context->context,
                                                               NULL,
                                                               &groups_len);
        if (pcsc_status == SCARD_S_SUCCESS && groups_len > 0)
        {
            groups = (char*)calloc(groups_len, 1u);
            if (!groups)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
            else
                pcsc_status = rdp_smartcard_backend_list_reader_groups(&session->smartcard_backend,
                                                                       context->context,
                                                                       groups,
                                                                       &groups_len);
        }
    }
#ifndef RDP_HAVE_WINPR_SMARTCARD
    if (context && pcsc_status != (LONG)RDP_SESSION_SCARD_E_NO_MEMORY)
    {
        status = rdp_session_smartcard_build_local_groups(
            session,
            pcsc_status == SCARD_S_SUCCESS ? groups : NULL,
            pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(groups_len) : 0,
            &merged_groups,
            &merged_groups_len);
        if (status == LIBRDP_STATUS_OK && (pcsc_status == SCARD_S_SUCCESS || merged_groups_len > 1u))
        {
            free(groups);
            groups = merged_groups;
            groups_len = merged_groups_len;
            merged_groups = NULL;
            pcsc_status = SCARD_S_SUCCESS;
        }
        else if (status == LIBRDP_STATUS_NO_MEMORY)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        free(merged_groups);
    }
#endif
    if (pcsc_status == SCARD_S_SUCCESS && groups_len > 0 && groups)
    {
        if (wide)
        {
            wide_groups = rdp_session_smartcard_utf8_multisz_to_utf16le(
                groups,
                rdp_session_smartcard_u32_from_dword(groups_len),
                &output_len);
            if (!wide_groups)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        else
        {
            output_len = rdp_session_smartcard_u32_from_dword(groups_len);
        }
    }
    if (pcsc_status == SCARD_S_SUCCESS &&
        !message->body.list_reader_groups.groups_is_null &&
        message->body.list_reader_groups.groups_len > 0 &&
        output_len > message->body.list_reader_groups.groups_len)
    {
        pcsc_status = SCARD_E_INSUFFICIENT_BUFFER;
        output_len = 0;
    }
    status = rdp_session_smartcard_send_buffer_result(session,
                                                      request,
                                                      (uint32_t)pcsc_status,
                                                      pcsc_status == SCARD_S_SUCCESS ?
                                                          (wide ? (const void*)wide_groups : (const void*)groups) :
                                                          NULL,
                                                      pcsc_status == SCARD_S_SUCCESS ? output_len : 0,
                                                      "client.rdpdr.smartcard.list_reader_groups.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.list_reader_groups",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld output_len=%u wide=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    output_len,
                    wide ? 1u : 0u);
    free(wide_groups);
    free(merged_groups);
    free(groups);
    return status;
}

/*
 * Handle the PC/SC list-readers request for smartcard redirection. Reader-
 * group filters are parsed from the wire and backend reader names are copied
 * into the response payload.
 */
static librdp_status rdp_session_smartcard_handle_list_readers(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    char* groups = NULL;
    char* readers = NULL;
    char* merged_readers = NULL;
    uint8_t* wide_readers = NULL;
    uint32_t output_len = 0;
    uint32_t merged_readers_len = 0;
    DWORD readers_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    int wide = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.list_readers.context.data,
                                                 message->body.list_readers.context.length);
    if (context)
    {
        if (!message->body.list_readers.groups_is_null && message->body.list_readers.groups_len > 0)
        {
            if (wide)
                groups = rdp_session_smartcard_utf16le_to_utf8_multisz(message->body.list_readers.groups,
                                                                       message->body.list_readers.groups_len);
            else
            {
                groups = (char*)calloc((size_t)message->body.list_readers.groups_len + 1u, 1u);
                if (groups)
                    memcpy(groups, message->body.list_readers.groups, message->body.list_readers.groups_len);
            }
            if (!groups)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        if (pcsc_status != (LONG)RDP_SESSION_SCARD_E_NO_MEMORY)
        {
            pcsc_status = rdp_smartcard_backend_list_readers(&session->smartcard_backend,
                                                             context->context,
                                                             groups,
                                                             NULL,
                                                             &readers_len);
            if (pcsc_status == SCARD_S_SUCCESS && readers_len > 0)
            {
                readers = (char*)calloc(readers_len, 1u);
                if (!readers)
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                else
                    pcsc_status = rdp_smartcard_backend_list_readers(&session->smartcard_backend,
                                                                     context->context,
                                                                     groups,
                                                                     readers,
                                                                     &readers_len);
            }
        }
    }
#ifndef RDP_HAVE_WINPR_SMARTCARD
    if (context && pcsc_status != (LONG)RDP_SESSION_SCARD_E_NO_MEMORY)
    {
        uint32_t groups_filter_len = groups ? (uint32_t)strlen(groups) + 1u : 0;

        status = rdp_session_smartcard_build_local_readers(
            session,
            pcsc_status == SCARD_S_SUCCESS ? readers : NULL,
            pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(readers_len) : 0,
            groups,
            groups_filter_len,
            &merged_readers,
            &merged_readers_len);
        if (status == LIBRDP_STATUS_OK && (pcsc_status == SCARD_S_SUCCESS || merged_readers_len > 1u))
        {
            free(readers);
            readers = merged_readers;
            readers_len = merged_readers_len;
            merged_readers = NULL;
            pcsc_status = SCARD_S_SUCCESS;
        }
        else if (status == LIBRDP_STATUS_NO_MEMORY)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        free(merged_readers);
    }
#endif
    if (pcsc_status == SCARD_S_SUCCESS && readers_len > 0 && readers)
    {
        if (wide)
        {
            wide_readers = rdp_session_smartcard_utf8_multisz_to_utf16le(
                readers,
                rdp_session_smartcard_u32_from_dword(readers_len),
                &output_len);
            if (!wide_readers)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        else
        {
            output_len = rdp_session_smartcard_u32_from_dword(readers_len);
        }
    }
    if (pcsc_status == SCARD_S_SUCCESS &&
        !message->body.list_readers.readers_is_null &&
        message->body.list_readers.readers_len > 0 &&
        output_len > message->body.list_readers.readers_len)
    {
        pcsc_status = SCARD_E_INSUFFICIENT_BUFFER;
        output_len = 0;
    }
    status = rdp_session_smartcard_send_buffer_result(session,
                                                      request,
                                                      (uint32_t)pcsc_status,
                                                      pcsc_status == SCARD_S_SUCCESS ?
                                                          (wide ? (const void*)wide_readers : (const void*)readers) :
                                                          NULL,
                                                      pcsc_status == SCARD_S_SUCCESS ? output_len : 0,
                                                      "client.rdpdr.smartcard.list_readers.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.list_readers",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld groups_len=%u output_len=%u wide=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    message->body.list_readers.groups_len,
                    output_len,
                    wide ? 1u : 0u);
    free(wide_readers);
    free(merged_readers);
    free(readers);
    free(groups);
    return status;
}

/*
 * Handle a PC/SC status-change request. Reader state arrays are bounded,
 * correlated with backend readers, and completed with protocol status even
 * when the provider reports a timeout.
 */
static librdp_status rdp_session_smartcard_handle_get_status_change(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    SCARD_READERSTATE* pcsc_readers = NULL;
    char** reader_names = NULL;
    rdp_smartcard_redirection_reader_state_common out[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
    uint32_t reader_count = 0;
    uint32_t i = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    int wide = 0;

    memset(out, 0, sizeof(out));
    rdp_buffer_init(&payload);
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEW;
    reader_count = message->body.get_status_change.reader_count;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.get_status_change.context.data,
                                                 message->body.get_status_change.context.length);
    if (context)
    {
        pcsc_readers = (SCARD_READERSTATE*)calloc(reader_count ? reader_count : 1u,
                                                  sizeof(SCARD_READERSTATE));
        reader_names = (char**)calloc(reader_count ? reader_count : 1u, sizeof(char*));
        if (!pcsc_readers || !reader_names)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
        }
        else
        {
            pcsc_status = SCARD_S_SUCCESS;
            for (i = 0; i < reader_count; i++)
            {
                const rdp_smartcard_redirection_reader_state_call* in =
                    &message->body.get_status_change.readers[i];

                if (!in->reader_name_is_null && in->reader_name_len > 0)
                {
                    if (wide)
                        reader_names[i] = rdp_session_smartcard_utf16le_to_utf8_multisz(in->reader_name,
                                                                                        in->reader_name_len);
                    else
                    {
                        reader_names[i] = (char*)calloc((size_t)in->reader_name_len + 1u, 1u);
                        if (reader_names[i])
                            memcpy(reader_names[i], in->reader_name, in->reader_name_len);
                    }
                    if (!reader_names[i])
                    {
                        pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                        break;
                    }
                }
                pcsc_readers[i].szReader = reader_names[i];
                pcsc_readers[i].dwCurrentState = in->state.current_state;
                pcsc_readers[i].dwEventState = in->state.event_state;
                pcsc_readers[i].cbAtr = in->state.atr_len;
                if (in->state.atr_len > 0)
                    memcpy(pcsc_readers[i].rgbAtr, in->state.atr, in->state.atr_len);
            }
            if (pcsc_status == SCARD_S_SUCCESS)
                pcsc_status = rdp_smartcard_backend_get_status_change(
                    &session->smartcard_backend,
                    context->context,
                    message->body.get_status_change.timeout,
                    pcsc_readers,
                    reader_count);
        }
    }
    if (pcsc_status == SCARD_S_SUCCESS || pcsc_status == SCARD_E_TIMEOUT)
    {
        for (i = 0; i < reader_count; i++)
        {
            out[i].current_state = pcsc_readers ?
                rdp_session_smartcard_u32_from_dword(pcsc_readers[i].dwCurrentState) :
                0;
            out[i].event_state = pcsc_readers ?
                rdp_session_smartcard_u32_from_dword(pcsc_readers[i].dwEventState) :
                0;
            out[i].atr_len = pcsc_readers && pcsc_readers[i].cbAtr <= RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH ?
                rdp_session_smartcard_u32_from_dword(pcsc_readers[i].cbAtr) :
                0;
            if (out[i].atr_len > 0 && pcsc_readers)
                memcpy(out[i].atr, pcsc_readers[i].rgbAtr, out[i].atr_len);
        }
    }
    status = rdp_smartcard_redirection_write_get_status_change_return(
        &payload,
        (uint32_t)pcsc_status,
        (pcsc_status == SCARD_S_SUCCESS || pcsc_status == SCARD_E_TIMEOUT) ? out : NULL,
        (pcsc_status == SCARD_S_SUCCESS || pcsc_status == SCARD_E_TIMEOUT) ? reader_count : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(
            session,
            request,
            &payload,
            "client.rdpdr.smartcard.get_status_change.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.get_status_change",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld readers=%u timeout=%u wide=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    reader_count,
                    message->body.get_status_change.timeout,
                    wide ? 1u : 0u);
    for (i = 0; reader_names && i < reader_count; i++)
        free(reader_names[i]);
    free(reader_names);
    free(pcsc_readers);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_handle_only(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    DWORD count = 0;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.handle.data,
                                               message->body.handle.length);
    if (handle)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION)
            pcsc_status = rdp_smartcard_backend_begin_transaction(&session->smartcard_backend,
                                                                  handle->handle);
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT)
        {
            pcsc_status = SCARD_S_SUCCESS;
            count = handle->transmit_count;
        }
    }
    if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT)
        status = rdp_smartcard_redirection_write_count_return(&payload,
                                                              (uint32_t)pcsc_status,
                                                              rdp_session_smartcard_u32_from_dword(count));
    else
        status = rdp_smartcard_redirection_write_long_return(&payload, (uint32_t)pcsc_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.handle.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.handle",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Handle a PC/SC connect request. Reader names, share mode, and protocol masks
 * are validated before backend handles become visible to later smartcard
 * calls.
 */
static librdp_status rdp_session_smartcard_handle_connect(librdp_session* session,
                                                          const rdp_device_redirection_io_request* request,
                                                          const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t handle_blob[RDP_SESSION_SMARTCARD_BLOB_BYTES];
    char readers[4096];
    char* requested_reader = NULL;
    const char* connect_reader = NULL;
    DWORD readers_len = sizeof(readers);
    DWORD active_protocol = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(handle_blob, 0, sizeof(handle_blob));
    memset(readers, 0, sizeof(readers));
    rdp_buffer_init(&payload);
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.connect.context.data,
                                                 message->body.connect.context.length);
    if (context)
    {
        requested_reader = rdp_session_smartcard_connect_reader_name(message, &pcsc_status);
        connect_reader = requested_reader;
        if (pcsc_status == SCARD_S_SUCCESS && !connect_reader)
        {
            pcsc_status = rdp_smartcard_backend_list_readers(&session->smartcard_backend,
                                                             context->context,
                                                             NULL,
                                                             readers,
                                                             &readers_len);
            if (pcsc_status == SCARD_S_SUCCESS && readers_len > 1u && readers[0] != '\0')
                connect_reader = readers;
        }
        if (pcsc_status == SCARD_S_SUCCESS && connect_reader && connect_reader[0] != '\0')
        {
            SCARDHANDLE pcsc_handle = 0;
            pcsc_status = rdp_smartcard_backend_connect(
                &session->smartcard_backend,
                context->context,
                connect_reader,
                message->body.connect.share_mode,
                rdp_session_smartcard_protocol_to_pcsc(message->body.connect.preferred_protocols),
                &pcsc_handle,
                &active_protocol);
            if (pcsc_status == SCARD_S_SUCCESS)
            {
                handle = rdp_session_smartcard_handle_alloc(session, context, pcsc_handle, active_protocol);
                if (!handle)
                {
                    (void)rdp_smartcard_backend_disconnect(&session->smartcard_backend,
                                                           pcsc_handle,
                                                           SCARD_LEAVE_CARD);
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                }
                else
                {
                    rdp_session_smartcard_write_blob(handle_blob, handle->id, handle->generation);
                }
            }
        }
        else if (pcsc_status == SCARD_S_SUCCESS)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_FILE_NOT_FOUND;
        }
    }
    status = rdp_smartcard_redirection_write_connect_return(
        &payload,
        (uint32_t)pcsc_status,
        message->body.connect.context.data,
        pcsc_status == SCARD_S_SUCCESS ? message->body.connect.context.length : 0,
        handle_blob,
        pcsc_status == SCARD_S_SUCCESS ? sizeof(handle_blob) : 0,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(active_protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.connect.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.connect",
                    "device_id=%u completion_id=%u status=%ld protocol=%u readers_len=%u requested_reader_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    rdp_session_smartcard_protocol_from_pcsc(active_protocol),
                    (unsigned)readers_len,
                    message->body.connect.reader_name_len);
    free(requested_reader);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_disposition(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;

    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.handle_disposition.handle.data,
                                               message->body.handle_disposition.handle.length);
    if (handle)
    {
        if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT)
        {
            pcsc_status = rdp_smartcard_backend_disconnect(&session->smartcard_backend,
                                                           handle->handle,
                                                           message->body.handle_disposition.disposition);
            if (pcsc_status == SCARD_S_SUCCESS)
                memset(handle, 0, sizeof(*handle));
        }
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION)
        {
            pcsc_status = rdp_smartcard_backend_end_transaction(&session->smartcard_backend,
                                                                handle->handle,
                                                                message->body.handle_disposition.disposition);
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.disposition",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.disposition.response");
}

static librdp_status rdp_session_smartcard_handle_reconnect(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    DWORD active_protocol = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.reconnect.handle.data,
                                               message->body.reconnect.handle.length);
    if (handle)
    {
        active_protocol = handle->active_protocol;
        pcsc_status = rdp_smartcard_backend_reconnect(
            &session->smartcard_backend,
            handle->handle,
            message->body.reconnect.share_mode,
            rdp_session_smartcard_protocol_to_pcsc(message->body.reconnect.preferred_protocols),
            message->body.reconnect.initialization,
            &active_protocol);
        if (pcsc_status == SCARD_S_SUCCESS)
            handle->active_protocol = active_protocol;
    }
    status = rdp_smartcard_redirection_write_reconnect_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(active_protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.reconnect.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.reconnect",
                    "device_id=%u completion_id=%u status=%ld protocol=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    rdp_session_smartcard_protocol_from_pcsc(active_protocol));
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_state(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    DWORD state = 0;
    DWORD protocol = 0;
    DWORD atr_len = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    DWORD reader_names_len = 0;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(atr, 0, sizeof(atr));
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.state.handle.data,
                                               message->body.state.handle.length);
    if (handle)
        pcsc_status = rdp_smartcard_backend_status(&session->smartcard_backend,
                                                   handle->handle,
                                                   NULL,
                                                   &reader_names_len,
                                                   &state,
                                                   &protocol,
                                                   atr,
                                                   &atr_len);
    status = rdp_smartcard_redirection_write_status_return(
        &payload,
        (uint32_t)pcsc_status,
        NULL,
        0,
        rdp_session_smartcard_u32_from_dword(state),
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        atr,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(atr_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.state.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.state",
                    "device_id=%u completion_id=%u status=%ld state=%u protocol=%u atr_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    (unsigned)state,
                    (unsigned)protocol,
                    (unsigned)atr_len);
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Handle the smartcard status IOCTL by allocating only the caller-requested
 * reader-name capacity, preserving ATR bounds, and reporting provider state
 * without retaining backend-owned buffers after completion.
 */
static librdp_status rdp_session_smartcard_handle_status(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    char reader_names_stack[1024];
    char* reader_names = NULL;
    DWORD reader_names_len = 0;
    uint8_t reader_names_allocated = 0;
    DWORD state = 0;
    DWORD protocol = 0;
    DWORD atr_len = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(reader_names_stack, 0, sizeof(reader_names_stack));
    memset(atr, 0, sizeof(atr));
    rdp_buffer_init(&payload);
    if (!message->body.status.reader_names_is_null && message->body.status.reader_len > 0)
    {
        uint32_t requested_len = message->body.status.reader_len;

        if (requested_len > RDP_SESSION_SMARTCARD_MAX_IO_BYTES)
            requested_len = RDP_SESSION_SMARTCARD_MAX_IO_BYTES;
        reader_names_len = requested_len;
        if (requested_len <= sizeof(reader_names_stack))
        {
            reader_names = reader_names_stack;
        }
        else
        {
            reader_names = (char*)calloc(1, requested_len);
            if (!reader_names)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
            else
                reader_names_allocated = 1;
        }
    }
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.status.handle.data,
                                               message->body.status.handle.length);
    if (handle && pcsc_status != (LONG)RDP_SESSION_SCARD_E_NO_MEMORY)
        pcsc_status = rdp_smartcard_backend_status(&session->smartcard_backend,
                                                   handle->handle,
                                                   reader_names,
                                                   &reader_names_len,
                                                   &state,
                                                   &protocol,
                                                   atr,
                                                   &atr_len);
    status = rdp_smartcard_redirection_write_status_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS && reader_names ? reader_names : NULL,
        pcsc_status == SCARD_S_SUCCESS && reader_names ?
            rdp_session_smartcard_u32_from_dword(reader_names_len) :
            0,
        rdp_session_smartcard_u32_from_dword(state),
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(protocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        atr,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(atr_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.status.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.status",
                    "device_id=%u completion_id=%u status=%ld state=%u protocol=%u readers_len=%u atr_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    (unsigned)state,
                    (unsigned)protocol,
                    (unsigned)reader_names_len,
                    (unsigned)atr_len);
    rdp_buffer_free(&payload);
    if (reader_names_allocated)
        free(reader_names);
    return status;
}

static librdp_status rdp_session_smartcard_handle_transmit(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    const SCARD_IO_REQUEST* send_pci = NULL;
    SCARD_IO_REQUEST recv_pci;
    uint8_t recv_buffer[RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH];
    DWORD recv_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&recv_pci, 0, sizeof(recv_pci));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    recv_pci.dwProtocol = rdp_session_smartcard_protocol_to_pcsc(message->body.transmit.recv_pci.protocol);
    recv_pci.cbPciLength = sizeof(recv_pci);
    recv_len = message->body.transmit.recv_len;
    if (recv_len > sizeof(recv_buffer))
        recv_len = sizeof(recv_buffer);
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.transmit.handle.data,
                                               message->body.transmit.handle.length);
    if (handle)
    {
        rdp_session_smartcard_context* context = rdp_session_smartcard_context_for_handle(session, handle);

        send_pci = rdp_session_smartcard_pci_from_protocol(message->body.transmit.send_pci.protocol);
        if (!context)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        else if (send_pci)
        {
            pcsc_status = rdp_smartcard_backend_transmit(&session->smartcard_backend,
                                                         context->context,
                                                         handle->handle,
                                                         send_pci,
                                                         message->body.transmit.send_data,
                                                         message->body.transmit.send_len,
                                                         message->body.transmit.recv_pci_present ? &recv_pci : NULL,
                                                         recv_buffer,
                                                         &recv_len);
            if (pcsc_status == SCARD_S_SUCCESS && handle->transmit_count < UINT32_MAX)
                handle->transmit_count++;
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        }
    }
    status = rdp_smartcard_redirection_write_transmit_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ?
            rdp_session_smartcard_protocol_from_pcsc(recv_pci.dwProtocol) :
            RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED,
        NULL,
        0,
        recv_buffer,
        pcsc_status == SCARD_S_SUCCESS ? rdp_session_smartcard_u32_from_dword(recv_len) : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.transmit.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.transmit",
                    "device_id=%u completion_id=%u status=%ld send_len=%u recv_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    message->body.transmit.send_len,
                    (unsigned)recv_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_control(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t output[RDP_SESSION_SMARTCARD_MAX_IO_BYTES];
    DWORD output_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(output, 0, sizeof(output));
    output_len = message->body.control.output_len;
    if (output_len > sizeof(output))
        output_len = sizeof(output);
    rdp_buffer_init(&payload);
    handle = rdp_session_smartcard_handle_find(session,
                                               message->body.control.handle.data,
                                               message->body.control.handle.length);
    if (handle)
        pcsc_status = rdp_smartcard_backend_control(&session->smartcard_backend,
                                                    handle->handle,
                                                    message->body.control.control_code,
                                                    message->body.control.input,
                                                    message->body.control.input_len,
                                                    output,
                                                    output_len,
                                                    &output_len);
    status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                           (uint32_t)pcsc_status,
                                                           output,
                                                           pcsc_status == SCARD_S_SUCCESS ?
                                                               rdp_session_smartcard_u32_from_dword(output_len) :
                                                               0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.control.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.control",
                    "device_id=%u completion_id=%u status=%ld input_len=%u output_len=%u",
                    request->device_id,
                    request->completion_id,
                    pcsc_status,
                    message->body.control.input_len,
                    (unsigned)output_len);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_attrib(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_handle* handle = NULL;
    uint8_t attr[RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH];
    DWORD attr_len = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(attr, 0, sizeof(attr));
    rdp_buffer_init(&payload);
    if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB)
    {
        attr_len = message->body.attrib.attr_len;
        if (attr_len > sizeof(attr))
            attr_len = sizeof(attr);
        handle = rdp_session_smartcard_handle_find(session,
                                                   message->body.attrib.handle.data,
                                                   message->body.attrib.handle.length);
        if (handle)
            pcsc_status = rdp_smartcard_backend_get_attrib(&session->smartcard_backend,
                                                           handle->handle,
                                                           message->body.attrib.attr_id,
                                                           attr,
                                                           &attr_len);
        status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                               (uint32_t)pcsc_status,
                                                               attr,
                                                               pcsc_status == SCARD_S_SUCCESS ?
                                                                   rdp_session_smartcard_u32_from_dword(attr_len) :
                                                                   0);
    }
    else
    {
        handle = rdp_session_smartcard_handle_find(session,
                                                   message->body.set_attrib.handle.data,
                                                   message->body.set_attrib.handle.length);
        if (handle)
            pcsc_status = rdp_smartcard_backend_set_attrib(&session->smartcard_backend,
                                                           handle->handle,
                                                           message->body.set_attrib.attr_id,
                                                           message->body.set_attrib.attr,
                                                           message->body.set_attrib.attr_len);
        status = rdp_smartcard_redirection_write_long_return(&payload, (uint32_t)pcsc_status);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session,
                                                          request,
                                                          &payload,
                                                          "client.rdpdr.smartcard.attrib.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.attrib",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_session_smartcard_handle_context_string(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    char* value = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    int wide = 0;

#ifdef RDP_HAVE_WINPR_SMARTCARD
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context_string.context.data,
                                                 message->body.context_string.context.length);
    if (context)
    {
        value = rdp_session_smartcard_string_to_utf8(&message->body.context_string.value, wide);
        if (!value)
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW)
            pcsc_status = SCardIntroduceReaderGroupA(context->context, value);
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW)
            pcsc_status = SCardForgetReaderGroupA(context->context, value);
        else
            pcsc_status = SCardForgetReaderA(context->context, value);
    }
#else
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context_string.context.data,
                                                 message->body.context_string.context.length);
    if (context)
    {
        value = rdp_session_smartcard_string_to_utf8(&message->body.context_string.value, wide);
        if (!value)
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW)
            pcsc_status = rdp_session_smartcard_group_add(session, value);
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW)
            pcsc_status = rdp_session_smartcard_group_remove(session, value);
        else
            pcsc_status = rdp_session_smartcard_reader_forget(session, value);
    }
#endif
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.context_string",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    free(value);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.context_string.response");
}

static librdp_status rdp_session_smartcard_handle_context_two_strings(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_session_smartcard_context* context = NULL;
    char* first = NULL;
    char* second = NULL;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    int wide = 0;

#ifdef RDP_HAVE_WINPR_SMARTCARD
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context_two_strings.context.data,
                                                 message->body.context_two_strings.context.length);
    if (context)
    {
        first = rdp_session_smartcard_string_to_utf8(&message->body.context_two_strings.first, wide);
        second = rdp_session_smartcard_string_to_utf8(&message->body.context_two_strings.second, wide);
        if (!first || !second)
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW)
            pcsc_status = SCardIntroduceReaderA(context->context, first, second);
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW)
            pcsc_status = SCardAddReaderToGroupA(context->context, first, second);
        else
            pcsc_status = SCardRemoveReaderFromGroupA(context->context, first, second);
    }
#else
    wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW ||
           message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW;
    context = rdp_session_smartcard_context_find(session,
                                                 message->body.context_two_strings.context.data,
                                                 message->body.context_two_strings.context.length);
    if (context)
    {
        first = rdp_session_smartcard_string_to_utf8(&message->body.context_two_strings.first, wide);
        second = rdp_session_smartcard_string_to_utf8(&message->body.context_two_strings.second, wide);
        if (!first || !second)
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW)
            pcsc_status = rdp_session_smartcard_reader_group_add(session, first, "SCard$DefaultReaders");
        else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA ||
                 message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW)
            pcsc_status = rdp_session_smartcard_reader_group_add(session, first, second);
        else
            pcsc_status = rdp_session_smartcard_reader_group_remove(session, first, second);
    }
#endif
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.context_two_strings",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status);
    free(second);
    free(first);
    return rdp_session_send_smartcard_long_result(session,
                                                  request,
                                                  (uint32_t)pcsc_status,
                                                  "client.rdpdr.smartcard.context_two_strings.response");
}

static librdp_status rdp_session_smartcard_handle_access_started_event(
    librdp_session* session,
    const rdp_device_redirection_io_request* request)
{
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;

#ifdef RDP_HAVE_WINPR_SMARTCARD
    HANDLE handle = SCardAccessStartedEvent();

    pcsc_status = handle ? SCARD_S_SUCCESS : (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
    if (handle)
        SCardReleaseStartedEvent();
#else
    pcsc_status = SCARD_S_SUCCESS;
#endif
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.access_started_event",
                    "device_id=%u completion_id=%u status=%ld",
                    request->device_id,
                    request->completion_id,
                    pcsc_status);
    return rdp_session_send_smartcard_long_result(
        session,
        request,
        (uint32_t)pcsc_status,
        "client.rdpdr.smartcard.access_started_event.response");
}

static librdp_status rdp_session_smartcard_send_reader_states(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    LONG pcsc_status,
    const rdp_smartcard_redirection_reader_state_common* states,
    uint32_t state_count,
    const char* event)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_smartcard_redirection_write_get_status_change_return(
        &payload,
        (uint32_t)pcsc_status,
        pcsc_status == SCARD_S_SUCCESS ? states : NULL,
        pcsc_status == SCARD_S_SUCCESS ? state_count : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(session, request, &payload, event);
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Handle PC/SC locate-cards requests across multiple reader states. Card names
 * and reader arrays are copied out of the wire payload before backend matching
 * and response construction.
 */
static librdp_status rdp_session_smartcard_handle_locate_cards(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;
    rdp_smartcard_redirection_reader_state_common out[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
    uint32_t reader_count = message->body.locate_cards.reader_count;

    memset(out, 0, sizeof(out));
#ifdef RDP_HAVE_WINPR_SMARTCARD
    {
        rdp_session_smartcard_context* context = NULL;
        SCARD_READERSTATEA states[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
        char* reader_names[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
        char* card_names = NULL;
        uint32_t i = 0;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW;

        memset(states, 0, sizeof(states));
        memset(reader_names, 0, sizeof(reader_names));
        context = rdp_session_smartcard_context_find(session,
                                                     message->body.locate_cards.context.data,
                                                     message->body.locate_cards.context.length);
        if (context)
        {
            card_names = rdp_session_smartcard_string_to_utf8(&message->body.locate_cards.card_names,
                                                              wide);
            if (!card_names)
            {
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
            }
            else
            {
                pcsc_status = SCARD_S_SUCCESS;
                for (i = 0; i < reader_count; i++)
                {
                    const rdp_smartcard_redirection_reader_state_call* in =
                        &message->body.locate_cards.readers[i];

                    reader_names[i] = rdp_session_smartcard_reader_state_name_to_utf8(in, wide);
                    if (!reader_names[i] && !in->reader_name_is_null)
                    {
                        pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                        break;
                    }
                    states[i].szReader = reader_names[i];
                    states[i].dwCurrentState = in->state.current_state;
                    states[i].dwEventState = in->state.event_state;
                    states[i].cbAtr = in->state.atr_len;
                    if (in->state.atr_len > 0)
                        memcpy(states[i].rgbAtr, in->state.atr, in->state.atr_len);
                }
                if (pcsc_status == SCARD_S_SUCCESS)
                    pcsc_status = SCardLocateCardsA(context->context, card_names, states, reader_count);
            }
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        if (pcsc_status == SCARD_S_SUCCESS)
        {
            for (i = 0; i < reader_count; i++)
                rdp_session_smartcard_reader_common_from_pcsc(&out[i],
                                                              states[i].dwCurrentState,
                                                              states[i].dwEventState,
                                                              states[i].cbAtr,
                                                              states[i].rgbAtr);
        }
        for (i = 0; i < reader_count; i++)
            free(reader_names[i]);
        free(card_names);
    }
#elif defined(RDP_HAVE_PCSC)
    {
        rdp_session_smartcard_context* context = NULL;
        SCARD_READERSTATE* states = NULL;
        char** reader_names = NULL;
        char* card_names = NULL;
        uint32_t i = 0;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW;

        context = rdp_session_smartcard_context_find(session,
                                                     message->body.locate_cards.context.data,
                                                     message->body.locate_cards.context.length);
        if (!context)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        else
        {
            card_names = rdp_session_smartcard_string_to_utf8(&message->body.locate_cards.card_names,
                                                              wide);
            states = (SCARD_READERSTATE*)calloc(reader_count ? reader_count : 1u,
                                                sizeof(SCARD_READERSTATE));
            reader_names = (char**)calloc(reader_count ? reader_count : 1u, sizeof(char*));
            if (!card_names || !states || !reader_names)
            {
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
            }
            else
            {
                pcsc_status = SCARD_S_SUCCESS;
                for (i = 0; i < reader_count; i++)
                {
                    const rdp_smartcard_redirection_reader_state_call* in =
                        &message->body.locate_cards.readers[i];

                    reader_names[i] = rdp_session_smartcard_reader_state_name_to_utf8(in, wide);
                    if (!reader_names[i] && !in->reader_name_is_null)
                    {
                        pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                        break;
                    }
                    states[i].szReader = reader_names[i];
                    states[i].dwCurrentState = in->state.current_state;
                    states[i].dwEventState = in->state.event_state;
                    states[i].cbAtr = in->state.atr_len;
                    if (in->state.atr_len > 0)
                        memcpy(states[i].rgbAtr, in->state.atr, in->state.atr_len);
                }
                if (pcsc_status == SCARD_S_SUCCESS)
                    pcsc_status = rdp_smartcard_backend_get_status_change(&session->smartcard_backend,
                                                                          context->context,
                                                                          0,
                                                                          states,
                                                                          reader_count);
                if (pcsc_status == SCARD_S_SUCCESS || pcsc_status == SCARD_E_TIMEOUT)
                {
                    pcsc_status = SCARD_S_SUCCESS;
                    for (i = 0; i < reader_count; i++)
                        rdp_session_smartcard_reader_common_from_pcsc(&out[i],
                                                                      rdp_session_smartcard_u32_from_dword(states[i].dwCurrentState),
                                                                      rdp_session_smartcard_u32_from_dword(states[i].dwEventState),
                                                                      rdp_session_smartcard_u32_from_dword(states[i].cbAtr),
                                                                      states[i].rgbAtr);
                }
            }
        }
        for (i = 0; reader_names && i < reader_count; i++)
            free(reader_names[i]);
        free(reader_names);
        free(states);
        free(card_names);
    }
#endif
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.locate_cards",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld readers=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    reader_count);
    return rdp_session_smartcard_send_reader_states(
        session,
        request,
        pcsc_status,
        out,
        reader_count,
        "client.rdpdr.smartcard.locate_cards.response");
}

#if defined(RDP_HAVE_PCSC) && !defined(RDP_HAVE_WINPR_SMARTCARD)
static int rdp_session_smartcard_atr_matches_mask(
    const uint8_t* atr,
    uint32_t atr_len,
    const rdp_smartcard_redirection_atr_mask* mask)
{
    uint32_t i = 0;

    if (!atr || !mask || mask->atr_len == 0 || mask->atr_len > atr_len ||
        mask->atr_len > RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH)
        return 0;
    for (i = 0; i < mask->atr_len; i++)
    {
        if ((atr[i] & mask->mask[i]) != (mask->atr[i] & mask->mask[i]))
            return 0;
    }
    return 1;
}

static int rdp_session_smartcard_atr_matches_any(
    const uint8_t* atr,
    uint32_t atr_len,
    const rdp_smartcard_redirection_atr_mask* masks,
    uint32_t mask_count)
{
    uint32_t i = 0;

    if (!atr || !masks || mask_count == 0)
        return 0;
    for (i = 0; i < mask_count; i++)
    {
        if (rdp_session_smartcard_atr_matches_mask(atr, atr_len, &masks[i]))
            return 1;
    }
    return 0;
}
#endif

static librdp_status rdp_session_smartcard_handle_locate_cards_by_atr(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;
    rdp_smartcard_redirection_reader_state_common out[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
    uint32_t reader_count = message->body.locate_cards_by_atr.reader_count;

    memset(out, 0, sizeof(out));
#ifdef RDP_HAVE_WINPR_SMARTCARD
    {
        rdp_session_smartcard_context* context = NULL;
        SCARD_ATRMASK masks[RDP_SMARTCARD_REDIRECTION_MAX_ATR_MASKS];
        SCARD_READERSTATEA states[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
        char* reader_names[RDP_SMARTCARD_REDIRECTION_MAX_READER_STATES];
        uint32_t i = 0;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW;

        (void)wide;
        memset(masks, 0, sizeof(masks));
        memset(states, 0, sizeof(states));
        memset(reader_names, 0, sizeof(reader_names));
        context = rdp_session_smartcard_context_find(session,
                                                     message->body.locate_cards_by_atr.context.data,
                                                     message->body.locate_cards_by_atr.context.length);
        if (context)
        {
            pcsc_status = SCARD_S_SUCCESS;
            for (i = 0; i < message->body.locate_cards_by_atr.atr_count; i++)
            {
                masks[i].cbAtr = message->body.locate_cards_by_atr.atr_masks[i].atr_len;
                memcpy(masks[i].rgbAtr,
                       message->body.locate_cards_by_atr.atr_masks[i].atr,
                       sizeof(masks[i].rgbAtr));
                memcpy(masks[i].rgbMask,
                       message->body.locate_cards_by_atr.atr_masks[i].mask,
                       sizeof(masks[i].rgbMask));
            }
            for (i = 0; i < reader_count; i++)
            {
                const rdp_smartcard_redirection_reader_state_call* in =
                    &message->body.locate_cards_by_atr.readers[i];

                reader_names[i] = rdp_session_smartcard_reader_state_name_to_utf8(in, wide);
                if (!reader_names[i] && !in->reader_name_is_null)
                {
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                    break;
                }
                states[i].szReader = reader_names[i];
                states[i].dwCurrentState = in->state.current_state;
                states[i].dwEventState = in->state.event_state;
                states[i].cbAtr = in->state.atr_len;
                if (in->state.atr_len > 0)
                    memcpy(states[i].rgbAtr, in->state.atr, in->state.atr_len);
            }
            if (pcsc_status == SCARD_S_SUCCESS)
                pcsc_status = SCardLocateCardsByATRA(context->context,
                                                     masks,
                                                     message->body.locate_cards_by_atr.atr_count,
                                                     states,
                                                     reader_count);
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        if (pcsc_status == SCARD_S_SUCCESS)
        {
            for (i = 0; i < reader_count; i++)
                rdp_session_smartcard_reader_common_from_pcsc(&out[i],
                                                              states[i].dwCurrentState,
                                                              states[i].dwEventState,
                                                              states[i].cbAtr,
                                                              states[i].rgbAtr);
        }
        for (i = 0; i < reader_count; i++)
            free(reader_names[i]);
    }
#elif defined(RDP_HAVE_PCSC)
    {
        rdp_session_smartcard_context* context = NULL;
        SCARD_READERSTATE* states = NULL;
        char** reader_names = NULL;
        uint32_t i = 0;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW;

        context = rdp_session_smartcard_context_find(session,
                                                     message->body.locate_cards_by_atr.context.data,
                                                     message->body.locate_cards_by_atr.context.length);
        if (!context)
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        else
        {
            states = (SCARD_READERSTATE*)calloc(reader_count ? reader_count : 1u,
                                                sizeof(SCARD_READERSTATE));
            reader_names = (char**)calloc(reader_count ? reader_count : 1u, sizeof(char*));
            if (!states || !reader_names)
            {
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
            }
            else
            {
                pcsc_status = SCARD_S_SUCCESS;
                for (i = 0; i < reader_count; i++)
                {
                    const rdp_smartcard_redirection_reader_state_call* in =
                        &message->body.locate_cards_by_atr.readers[i];

                    reader_names[i] = rdp_session_smartcard_reader_state_name_to_utf8(in, wide);
                    if (!reader_names[i] && !in->reader_name_is_null)
                    {
                        pcsc_status = (LONG)RDP_SESSION_SCARD_E_NO_MEMORY;
                        break;
                    }
                    states[i].szReader = reader_names[i];
                    states[i].dwCurrentState = in->state.current_state;
                    states[i].dwEventState = in->state.event_state;
                    states[i].cbAtr = in->state.atr_len;
                    if (in->state.atr_len > 0)
                        memcpy(states[i].rgbAtr, in->state.atr, in->state.atr_len);
                }
                if (pcsc_status == SCARD_S_SUCCESS)
                    pcsc_status = rdp_smartcard_backend_get_status_change(&session->smartcard_backend,
                                                                          context->context,
                                                                          0,
                                                                          states,
                                                                          reader_count);
                if (pcsc_status == SCARD_S_SUCCESS || pcsc_status == SCARD_E_TIMEOUT)
                {
                    pcsc_status = SCARD_S_SUCCESS;
                    for (i = 0; i < reader_count; i++)
                    {
                        uint32_t atr_len = rdp_session_smartcard_u32_from_dword(states[i].cbAtr);

                        if ((states[i].dwEventState & SCARD_STATE_PRESENT) != 0 &&
                            rdp_session_smartcard_atr_matches_any(
                                states[i].rgbAtr,
                                atr_len,
                                message->body.locate_cards_by_atr.atr_masks,
                                message->body.locate_cards_by_atr.atr_count))
                        {
                            states[i].dwEventState |= SCARD_STATE_ATRMATCH;
                        }
                        rdp_session_smartcard_reader_common_from_pcsc(&out[i],
                                                                      rdp_session_smartcard_u32_from_dword(states[i].dwCurrentState),
                                                                      rdp_session_smartcard_u32_from_dword(states[i].dwEventState),
                                                                      rdp_session_smartcard_u32_from_dword(states[i].cbAtr),
                                                                      states[i].rgbAtr);
                    }
                }
            }
        }
        for (i = 0; reader_names && i < reader_count; i++)
            free(reader_names[i]);
        free(reader_names);
        free(states);
    }
#endif
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.locate_cards_by_atr",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld atrs=%u readers=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    message->body.locate_cards_by_atr.atr_count,
                    reader_count);
    return rdp_session_smartcard_send_reader_states(
        session,
        request,
        pcsc_status,
        out,
        reader_count,
        "client.rdpdr.smartcard.locate_cards_by_atr.response");
}

/*
 * Handle smartcard cache IOCTLs. Cache keys, lookup buffers, and update
 * payloads are bounded before session-owned cache state is read or modified.
 */
static librdp_status rdp_session_smartcard_handle_cache(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_buffer payload;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;
    uint8_t data[RDP_SESSION_SMARTCARD_MAX_IO_BYTES];
    DWORD data_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(data, 0, sizeof(data));
    rdp_buffer_init(&payload);
#ifdef RDP_HAVE_WINPR_SMARTCARD
    {
        rdp_session_smartcard_context* context = NULL;
        char* lookup_name = NULL;
        UUID card_identifier;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW ||
                   message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW;

        if (message->kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE)
        {
            context = rdp_session_smartcard_context_find(session,
                                                         message->body.read_cache.context.data,
                                                         message->body.read_cache.context.length);
            if (context)
            {
                memcpy(&card_identifier,
                       message->body.read_cache.card_identifier,
                       sizeof(card_identifier));
                lookup_name =
                    rdp_session_smartcard_string_to_utf8(&message->body.read_cache.lookup_name,
                                                         wide);
                data_len = message->body.read_cache.data_len;
                if (data_len > sizeof(data))
                    data_len = sizeof(data);
                if (!lookup_name)
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
                else
                    pcsc_status = SCardReadCacheA(context->context,
                                                  &card_identifier,
                                                  message->body.read_cache.freshness_counter,
                                                  lookup_name,
                                                  data,
                                                  &data_len);
            }
            else
            {
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
            }
        }
        else
        {
            context = rdp_session_smartcard_context_find(session,
                                                         message->body.write_cache.context.data,
                                                         message->body.write_cache.context.length);
            if (context)
            {
                memcpy(&card_identifier,
                       message->body.write_cache.card_identifier,
                       sizeof(card_identifier));
                lookup_name =
                    rdp_session_smartcard_string_to_utf8(&message->body.write_cache.lookup_name,
                                                         wide);
                if (!lookup_name)
                    pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
                else
                    pcsc_status = SCardWriteCacheA(context->context,
                                                   &card_identifier,
                                                   message->body.write_cache.freshness_counter,
                                                   lookup_name,
                                                   (PBYTE)message->body.write_cache.data,
                                                   message->body.write_cache.data_len);
            }
            else
            {
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
            }
        }
        free(lookup_name);
    }
#else
    {
        rdp_session_smartcard_context* context = NULL;
        char* lookup_name = NULL;
        const uint8_t* card_identifier = NULL;
        uint32_t freshness_counter = 0;
        int wide = message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW ||
                   message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW;

        if (message->kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE)
        {
            context = rdp_session_smartcard_context_find(session,
                                                         message->body.read_cache.context.data,
                                                         message->body.read_cache.context.length);
            card_identifier = message->body.read_cache.card_identifier;
            freshness_counter = message->body.read_cache.freshness_counter;
            data_len = message->body.read_cache.data_len;
            if (data_len > sizeof(data))
                data_len = sizeof(data);
            if (context)
                lookup_name =
                    rdp_session_smartcard_string_to_utf8(&message->body.read_cache.lookup_name,
                                                         wide);
            if (!context)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
            else if (!lookup_name)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
            else
                pcsc_status = rdp_session_smartcard_cache_read(session,
                                                               card_identifier,
                                                               freshness_counter,
                                                               lookup_name,
                                                               data,
                                                               &data_len);
        }
        else
        {
            context = rdp_session_smartcard_context_find(session,
                                                         message->body.write_cache.context.data,
                                                         message->body.write_cache.context.length);
            card_identifier = message->body.write_cache.card_identifier;
            freshness_counter = message->body.write_cache.freshness_counter;
            if (context)
                lookup_name =
                    rdp_session_smartcard_string_to_utf8(&message->body.write_cache.lookup_name,
                                                         wide);
            if (!context)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
            else if (!lookup_name)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
            else
                pcsc_status = rdp_session_smartcard_cache_write(session,
                                                                card_identifier,
                                                                freshness_counter,
                                                                lookup_name,
                                                                message->body.write_cache.data,
                                                                message->body.write_cache.data_len);
        }
        free(lookup_name);
    }
#endif
    if (message->kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE)
        status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                               (uint32_t)pcsc_status,
                                                               data,
                                                               pcsc_status == SCARD_S_SUCCESS ?
                                                                   rdp_session_smartcard_u32_from_dword(data_len) :
                                                                   0);
    else
        status = rdp_smartcard_redirection_write_long_return(&payload, (uint32_t)pcsc_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(
            session,
            request,
            &payload,
            "client.rdpdr.smartcard.cache.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.cache",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld data_len=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    (unsigned)data_len);
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Return the reader name associated with a smartcard context or card handle.
 * The response copies backend strings into protocol storage and maps missing
 * handles to explicit PC/SC status.
 */
static librdp_status rdp_session_smartcard_handle_reader_name(
    librdp_session* session,
    const rdp_device_redirection_io_request* request,
    const rdp_smartcard_redirection_request_message* message)
{
    rdp_buffer payload;
    uint8_t data[RDP_SESSION_SMARTCARD_MAX_IO_BYTES];
    DWORD data_len = message->body.reader_name.output_len;
    DWORD device_type = 0;
    LONG pcsc_status = (LONG)RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_len > sizeof(data))
        data_len = sizeof(data);
    memset(data, 0, sizeof(data));
    rdp_buffer_init(&payload);
#ifdef RDP_HAVE_WINPR_SMARTCARD
    {
        rdp_session_smartcard_context* context = NULL;
        char* reader_name = NULL;
        int wide = 0;

        context = rdp_session_smartcard_context_find(session,
                                                     message->body.reader_name.context.data,
                                                     message->body.reader_name.context.length);
        if (context)
        {
            reader_name = rdp_session_smartcard_string_to_utf8(&message->body.reader_name.reader_name,
                                                               wide);
            if (!reader_name)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
            else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON)
                pcsc_status = SCardGetReaderIconA(context->context, reader_name, data, &data_len);
            else
                pcsc_status = SCardGetDeviceTypeIdA(context->context, reader_name, &device_type);
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        free(reader_name);
    }
#elif defined(RDP_HAVE_PCSC)
    {
        rdp_session_smartcard_context* context = NULL;
        char* reader_name = NULL;
        int wide = 0;

        context = rdp_session_smartcard_context_find(session,
                                                     message->body.reader_name.context.data,
                                                     message->body.reader_name.context.length);
        if (context)
        {
            reader_name = rdp_session_smartcard_string_to_utf8(&message->body.reader_name.reader_name,
                                                               wide);
            if (!reader_name)
                pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_PARAMETER;
            else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON)
            {
                data_len = 0;
                pcsc_status = SCARD_S_SUCCESS;
            }
            else if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID)
            {
                device_type = RDP_SESSION_SCARD_READER_TYPE_USB;
                pcsc_status = SCARD_S_SUCCESS;
            }
        }
        else
        {
            pcsc_status = (LONG)RDP_SESSION_SCARD_E_INVALID_HANDLE;
        }
        free(reader_name);
    }
#endif
    if (message->request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID)
        status = rdp_smartcard_redirection_write_count_return(&payload,
                                                              (uint32_t)pcsc_status,
                                                              rdp_session_smartcard_u32_from_dword(device_type));
    else
        status = rdp_smartcard_redirection_write_buffer_return(&payload,
                                                               (uint32_t)pcsc_status,
                                                               data,
                                                               pcsc_status == SCARD_S_SUCCESS ?
                                                                   rdp_session_smartcard_u32_from_dword(data_len) :
                                                                   0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_smartcard_io_completion(
            session,
            request,
            &payload,
            "client.rdpdr.smartcard.reader_name.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.reader_name",
                    "device_id=%u completion_id=%u ioctl=%u status=%ld data_len=%u device_type=%u",
                    request->device_id,
                    request->completion_id,
                    message->request.io_control_code,
                    pcsc_status,
                    (unsigned)data_len,
                    (unsigned)device_type);
    rdp_buffer_free(&payload);
    return status;
}
#else
void rdp_session_smartcard_reset(librdp_session* session)
{
    (void)session;
}
#endif

librdp_status rdp_session_handle_smartcard_io_request(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_smartcard_redirection_request_message message;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                                "client.rdpdr.smartcard.create.response");
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                                "client.rdpdr.smartcard.close.response");
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            break;
        default:
            return rdp_session_send_smartcard_simple_completion(session,
                                                                &request,
                                                                RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                                "client.rdpdr.smartcard.not_supported.response");
    }

    memset(&message, 0, sizeof(message));
    status = rdp_smartcard_redirection_parse_device_control_request_message(request.payload,
                                                                           request.payload_len,
                                                                           &message);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_send_smartcard_simple_completion(session,
                                                            &request,
                                                            RDP_SESSION_DEVICE_INVALID_PARAMETER,
                                                            "client.rdpdr.smartcard.invalid.response");
#ifdef RDP_HAVE_PCSC
    switch (message.kind)
    {
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_ESTABLISH_CONTEXT:
            return rdp_session_smartcard_handle_establish(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT:
            return rdp_session_smartcard_handle_context(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READER_GROUPS:
            return rdp_session_smartcard_handle_list_reader_groups(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READERS:
            return rdp_session_smartcard_handle_list_readers(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_GET_STATUS_CHANGE:
            return rdp_session_smartcard_handle_get_status_change(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_STRING:
            return rdp_session_smartcard_handle_context_string(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_TWO_STRINGS:
            return rdp_session_smartcard_handle_context_two_strings(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS:
            return rdp_session_smartcard_handle_locate_cards(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE:
            return rdp_session_smartcard_handle_handle_only(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONNECT:
            return rdp_session_smartcard_handle_connect(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE_DISPOSITION:
            return rdp_session_smartcard_handle_disposition(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_RECONNECT:
            return rdp_session_smartcard_handle_reconnect(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_STATE:
            return rdp_session_smartcard_handle_state(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_STATUS:
            return rdp_session_smartcard_handle_status(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_TRANSMIT:
            return rdp_session_smartcard_handle_transmit(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTROL:
            return rdp_session_smartcard_handle_control(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_ATTRIB:
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_SET_ATTRIB:
            return rdp_session_smartcard_handle_attrib(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_ACCESS_STARTED_EVENT:
            return rdp_session_smartcard_handle_access_started_event(session, &request);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS_BY_ATR:
            return rdp_session_smartcard_handle_locate_cards_by_atr(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE:
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_WRITE_CACHE:
            return rdp_session_smartcard_handle_cache(session, &request, &message);
        case RDP_SMARTCARD_REDIRECTION_MESSAGE_READER_NAME:
            return rdp_session_smartcard_handle_reader_name(session, &request, &message);
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.smartcard.not_supported_ioctl",
                            "device_id=%u completion_id=%u ioctl=%u",
                            request.device_id,
                            request.completion_id,
                            message.request.io_control_code);
            return rdp_session_send_smartcard_long_result(session,
                                                          &request,
                                                          RDP_SESSION_SCARD_E_UNSUPPORTED_FEATURE,
                                                          "client.rdpdr.smartcard.not_supported_ioctl.response");
    }
#else
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.smartcard.no_backend",
                    "device_id=%u completion_id=%u ioctl=%u",
                    request.device_id,
                    request.completion_id,
                    message.request.io_control_code);
    return rdp_session_send_smartcard_long_result(session,
                                                  &request,
                                                  RDP_SESSION_SCARD_E_NO_SERVICE,
                                                  "client.rdpdr.smartcard.no_backend.response");
#endif
}

uint32_t rdp_session_read_u32_le_unaligned(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8u) | ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}
