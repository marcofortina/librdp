/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client protocol I/O session domain.
 * Invariants: wire reads and writes update metrics only after complete transport operations and validated protocol framing.
 * Ownership: temporary packet buffers are owned by the caller or stack frame; decoded fast-path fragments remain session-owned until reset.
 * Threading: callers must run on the session owner thread except where transport wait/read is already serialized by the lifecycle.
 * Trust boundary: TPKT, X.224, MCS, slow-path, fast-path, bulk-compressed, and CredSSP records are untrusted wire data.
 */

#include "client/session_internal.h"
#include "protocol/fastpath.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"

#include <poll.h>
#include <stdint.h>
#include <string.h>

static rdp_trace_sensitivity rdp_session_trace_sensitivity_for_event(const char* event);

librdp_status rdp_session_write_mcs_pdu(librdp_session* session,
                                               const rdp_buffer* pdu,
                                               const char* event,
                                               int allow_hexdump)
{
    rdp_buffer x224_data;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !pdu || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    status = rdp_x224_wrap_data(&x224_data, pdu->data, pdu->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&packet, x224_data.data, x224_data.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (allow_hexdump)
            rdp_trace_hexdump(event,
                              rdp_session_trace_sensitivity_for_event(event),
                              packet.data,
                              packet.length);
        status = rdp_transport_write_all(&session->transport, packet.data, packet.length);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_session_metric_add(&session->metrics.transport_bytes_written, packet.length);
            rdp_session_metric_add(&session->metrics.pdu_out, 1);
        }
    }

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
    return status;
}

static rdp_trace_sensitivity rdp_session_trace_sensitivity_for_event(const char* event)
{
    if (!event)
        return RDP_TRACE_SENSITIVITY_HEADER;
    if (strstr(event, "security") || strstr(event, "client_info") || strstr(event, "credssp") ||
        strstr(event, "nla") || strstr(event, "licensing"))
        return RDP_TRACE_SENSITIVITY_AUTH;
    if (strstr(event, "input") || strstr(event, "keyboard") || strstr(event, "mouse"))
        return RDP_TRACE_SENSITIVITY_INPUT;
    if (strstr(event, "clipboard") || strstr(event, "cliprdr"))
        return RDP_TRACE_SENSITIVITY_CLIPBOARD;
    if (strstr(event, "smartcard") || strstr(event, "apdu"))
        return RDP_TRACE_SENSITIVITY_APDU;
    if (strstr(event, "usb"))
        return RDP_TRACE_SENSITIVITY_USB;
    if (strstr(event, "audio") || strstr(event, "rdpsnd") || strstr(event, "audin"))
        return RDP_TRACE_SENSITIVITY_AUDIO;
    if (strstr(event, "graphics") || strstr(event, "fastpath") || strstr(event, "video") ||
        strstr(event, "slowpath"))
        return RDP_TRACE_SENSITIVITY_VIDEO;
    if (strstr(event, "rdpdr") || strstr(event, "drive") || strstr(event, "file") || strstr(event, "printer"))
        return RDP_TRACE_SENSITIVITY_FILE;
    return RDP_TRACE_SENSITIVITY_HEADER;
}

librdp_status rdp_session_write_slowpath_pdu(librdp_session* session,
                                                    const rdp_buffer* slowpath,
                                                    const char* event)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !slowpath || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (session->standard_security_active)
        status = rdp_security_write_encrypted_pdu(&security_payload,
                                                  &session->standard_security,
                                                  0,
                                                  slowpath->data,
                                                  slowpath->length);
    else
        status = rdp_buffer_append(&security_payload, slowpath->data, slowpath->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return status;
}

librdp_status rdp_session_write_license_pdu(librdp_session* session,
                                                   const rdp_buffer* license,
                                                   const char* event)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !license || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (session->standard_security_active)
        status = rdp_security_write_encrypted_pdu(&security_payload,
                                                  &session->standard_security,
                                                  (uint16_t)(RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC),
                                                  license->data,
                                                  license->length);
    else
        status = rdp_buffer_append(&security_payload, license->data, license->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return status;
}

librdp_status rdp_session_write_channel_pdu(librdp_session* session,
                                                   uint16_t channel_id,
                                                   const rdp_buffer* payload,
                                                   const char* event)
{
    rdp_buffer channel_packet;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    status = rdp_virtual_channel_write_packet(&channel_packet, payload->data, payload->length, 3);
    if (status == LIBRDP_STATUS_OK)
    {
        if (session->standard_security_active)
            status = rdp_security_write_encrypted_pdu(&security_payload,
                                                      &session->standard_security,
                                                      0,
                                                      channel_packet.data,
                                                      channel_packet.length);
        else
            status = rdp_buffer_append(&security_payload, channel_packet.data, channel_packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      channel_id,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_metric_add(&session->metrics.channel_out, 1);
        rdp_session_metric_add(&session->metrics.channel_bytes_out, payload->length);
    }
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&channel_packet);
    return status;
}


static size_t rdp_session_dynamic_channel_header_size(uint8_t channel_id_bytes)
{
    return 1u + channel_id_bytes;
}

static uint8_t rdp_session_dynamic_length_bytes(size_t length)
{
    if (length <= 0xffu)
        return 1;
    if (length <= 0xffffu)
        return 2;
    return 4;
}


librdp_status rdp_session_send_dynamic_channel_data_priority(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint8_t channel_id_bytes,
                                                                    uint8_t priority,
                                                                    const void* data,
                                                                    size_t data_len,
                                                                    const char* event);

librdp_status rdp_session_send_dynamic_channel_data(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const void* data,
                                                           size_t data_len,
                                                           const char* event)
{
    return rdp_session_send_dynamic_channel_data_priority(session,
                                                          channel_id,
                                                          channel_id_bytes,
                                                          0,
                                                          data,
                                                          data_len,
                                                          event);
}

librdp_status rdp_session_send_dynamic_channel_data_priority(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint8_t channel_id_bytes,
                                                                    uint8_t priority,
                                                                    const void* data,
                                                                    size_t data_len,
                                                                    const char* event)
{
    rdp_buffer response;
    size_t offset = 0;
    size_t header_size = 0;
    size_t chunk_max = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event || session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&response);
    header_size = rdp_session_dynamic_channel_header_size(channel_id_bytes);
    if (header_size >= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    else if (status == LIBRDP_STATUS_OK && data_len <= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size)
    {
        status = rdp_dynamic_channel_write_data_ex(&response,
                                                   channel_id,
                                                   channel_id_bytes,
                                                   priority,
                                                   data,
                                                   data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
    }
    else if (status == LIBRDP_STATUS_OK)
    {
        uint8_t length_bytes = rdp_session_dynamic_length_bytes(data_len);

        chunk_max = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size - length_bytes;
        if (chunk_max == 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
        {
            size_t chunk = data_len < chunk_max ? data_len : chunk_max;

            status = rdp_dynamic_channel_write_data_first_ex(&response,
                                                             channel_id,
                                                             channel_id_bytes,
                                                             priority,
                                                             (uint32_t)data_len,
                                                             data,
                                                             chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset = chunk;
        }
        while (status == LIBRDP_STATUS_OK && offset < data_len)
        {
            size_t remaining = data_len - offset;
            size_t chunk = remaining < RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size ?
                               remaining :
                               RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size;

            response.length = 0;
            status = rdp_dynamic_channel_write_data_ex(&response,
                                                       channel_id,
                                                       channel_id_bytes,
                                                       priority,
                                                       ((const uint8_t*)data) + offset,
                                                       chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset += chunk;
        }
    }
    rdp_buffer_free(&response);
    return status;
}

librdp_status rdp_session_send_clipboard_packet(librdp_session* session,
                                                       const rdp_buffer* payload,
                                                       const char* event)
{
    if (!session || !payload || !event || session->clipboard_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->clipboard_channel_id, payload, event);
}


librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event)
{
    rdp_tpkt parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !pdu || !pdu_len || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_transport_read_tpkt(&session->transport, packet);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (packet->length > session->limits.pdu_buffer_bytes)
        return rdp_session_limit_rejected(session);
    rdp_session_metric_add(&session->metrics.transport_bytes_read, packet->length);
    rdp_session_metric_add(&session->metrics.pdu_in, 1);
    rdp_trace_hexdump(event,
                      rdp_session_trace_sensitivity_for_event(event),
                      packet->data,
                      packet->length);
    status = rdp_tpkt_parse(packet->data, packet->length, &parsed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_x224_parse_data(parsed.payload, parsed.payload_len, pdu, pdu_len);
}


librdp_status rdp_session_read_fastpath_packet(librdp_session* session, rdp_buffer* packet)
{
    uint8_t header[3];
    uint16_t total = 0;
    size_t header_len = 2;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((header[1] & 0x80u) != 0)
    {
        status = rdp_transport_read_exact(&session->transport, header + 2, 1);
        if (status != LIBRDP_STATUS_OK)
            return status;
        total = (uint16_t)(((uint16_t)(header[1] & 0x7fu) << 8) | header[2]);
        header_len = 3;
    }
    else
    {
        total = header[1];
    }
    if (total < header_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (total > session->limits.frame_bytes)
        return rdp_session_limit_rejected(session);

    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    status = rdp_transport_read_exact(&session->transport, packet->data + header_len, (size_t)total - header_len);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_metric_add(&session->metrics.transport_bytes_read, packet->length);
        rdp_session_metric_add(&session->metrics.pdu_in, 1);
        rdp_trace_hexdump("rdp.fastpath.pdu", RDP_TRACE_SENSITIVITY_VIDEO, packet->data, packet->length);
    }
    return status;
}

static librdp_status rdp_session_unwrap_fastpath_packet(librdp_session* session,
                                                        const rdp_buffer* packet,
                                                        rdp_buffer* decoded,
                                                        int* used_decoded)
{
    if (!session || !packet || !decoded || !used_decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_fastpath_unwrap_security(&session->standard_security,
                                        session->standard_security_active,
                                        packet->data,
                                        packet->length,
                                        decoded,
                                        used_decoded);
}

librdp_status rdp_session_read_credssp_ts_request(librdp_session* session, rdp_buffer* packet, int timeout_ms)
{
    uint8_t header[6];
    uint8_t first_len = 0;
    size_t header_len = 0;
    size_t content_len = 0;
    size_t i = 0;
    short revents = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((revents & POLLIN) == 0)
        return LIBRDP_STATUS_TIMEOUT;

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header[0] != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    first_len = header[1];
    header_len = 2;
    if ((first_len & 0x80u) == 0)
    {
        content_len = first_len;
    }
    else
    {
        uint8_t count = (uint8_t)(first_len & 0x7fu);
        if (count == 0 || count > 4)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_transport_read_exact(&session->transport, header + 2, count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        header_len += count;
        for (i = 0; i < count; i++)
            content_len = (content_len << 8) | header[2u + i];
    }
    if (content_len == 0 || content_len > 1024u * 1024u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, header_len + content_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = header_len + content_len;
    return rdp_transport_read_exact(&session->transport, packet->data + header_len, content_len);
}

librdp_status rdp_session_apply_bitmap_update(librdp_session* session, const rdp_bitmap_update* update)
{
    uint16_t i = 0;

    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < update->count; i++)
    {
        const rdp_bitmap_rect* rect = &update->rects[i];
        size_t stride = 0;
        rdp_buffer pixels;
        librdp_status status = LIBRDP_STATUS_OK;

        rdp_buffer_init(&pixels);
        status = rdp_bitmap_decode_rect_bgra32_with_palette(rect,
                                                            session->palette_valid ? &session->palette : NULL,
                                                            &pixels,
                                                            &stride);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_surface_blit_bgra32(session->surface,
                                                rect->dest_left,
                                                rect->dest_top,
                                                rect->width,
                                                rect->height,
                                                pixels.data,
                                                stride);
        rdp_buffer_free(&pixels);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_session_emit_surface_invalidated(session, rect->dest_left, rect->dest_top, rect->width, rect->height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.framebuffer.blit",
                        "x=%u y=%u width=%u height=%u",
                        rect->dest_left,
                        rect->dest_top,
                        rect->width,
                        rect->height);
    }
    return LIBRDP_STATUS_OK;
}

void rdp_session_fastpath_fragment_reset(librdp_session* session)
{
    if (!session)
        return;
    session->fastpath_fragmenting = 0;
    session->fastpath_fragment_update_code = 0;
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
    session->fastpath_decompressed.length = 0;
}

librdp_status rdp_session_decompress_bulk_payload(librdp_session* session,
                                                  uint8_t flags,
                                                  const uint8_t* data,
                                                  size_t data_len,
                                                  rdp_buffer* decoded)
{
    uint8_t type = (uint8_t)(flags & RDP_BULK_TYPE_MASK);

    if (!session || (!data && data_len > 0) || !decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    decoded->length = 0;
    if ((flags & RDP_BULK_FLAGS_MASK) == 0)
        return rdp_buffer_append(decoded, data, data_len);
    if (type == RDP_BULK_TYPE_RDP8)
        return rdp_graphics_decode_segmented_data(&session->bulk_rdp8_decompressor, data, data_len, decoded);
    return rdp_bulk_decompress(&session->bulk_decompressor, flags, data, data_len, decoded);
}

/*
 * Process the plaintext fast-path payload after security and fragmentation
 * handling. Update parsing, batching, and event emission remain ordered with
 * the packet stream.
 */
static librdp_status rdp_session_fastpath_payload(librdp_session* session,
                                                  const rdp_fastpath_update* update,
                                                  const uint8_t** data,
                                                  size_t* data_len,
                                                  int* complete,
                                                  int* from_fragment)
{
    const uint8_t* payload_data = NULL;
    size_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !update || !data || !data_len || !complete || !from_fragment)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    *data_len = 0;
    *complete = 0;
    *from_fragment = 0;
    if (update->compression != 0)
    {
        status = rdp_session_decompress_bulk_payload(session,
                                                     update->compression_flags,
                                                     update->data,
                                                     update->data_len,
                                                     &session->fastpath_decompressed);
        if (status != LIBRDP_STATUS_OK)
            return status;
        payload_data = session->fastpath_decompressed.data;
        payload_len = session->fastpath_decompressed.length;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.fastpath.decompress",
                              "code=%u flags=%u compressed_len=%u decoded_len=%u",
                              update->update_code,
                              update->compression_flags,
                              (unsigned)update->data_len,
                              (unsigned)payload_len);
    }
    else
    {
        payload_data = update->data;
        payload_len = update->data_len;
    }
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE)
    {
        if (session->fastpath_fragmenting)
            rdp_session_fastpath_fragment_reset(session);
        *data = payload_data;
        *data_len = payload_len;
        *complete = 1;
        return LIBRDP_STATUS_OK;
    }
    if (payload_len > session->limits.frame_bytes ||
        session->fastpath_fragment.length > session->limits.frame_bytes - payload_len)
        return rdp_session_limit_rejected(session);
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_FIRST)
    {
        rdp_session_fastpath_fragment_reset(session);
        status = rdp_buffer_append(&session->fastpath_fragment, payload_data, payload_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->fastpath_fragmenting = 1;
        session->fastpath_fragment_update_code = update->update_code;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.fastpath.fragment.start",
                              "code=%u received=%u",
                              update->update_code,
                              (unsigned)session->fastpath_fragment.length);
        return LIBRDP_STATUS_OK;
    }
    if (update->fragmentation != RDP_FASTPATH_FRAGMENT_NEXT &&
        update->fragmentation != RDP_FASTPATH_FRAGMENT_LAST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!session->fastpath_fragmenting || session->fastpath_fragment_update_code != update->update_code)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(&session->fastpath_fragment, payload_data, payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.fastpath.fragment.data",
                          "code=%u fragmentation=%u received=%u",
                          update->update_code,
                          update->fragmentation,
                          (unsigned)session->fastpath_fragment.length);
    if (update->fragmentation == RDP_FASTPATH_FRAGMENT_NEXT)
        return LIBRDP_STATUS_OK;
    *data = session->fastpath_fragment.data;
    *data_len = session->fastpath_fragment.length;
    *complete = 1;
    *from_fragment = 1;
    return LIBRDP_STATUS_OK;
}

/*
 * Fast-path packets may be encrypted, compressed, fragmented, and batched.
 * Unwrap once, then process each update in wire order; fragmented bitmap,
 * surface, orders, and pointer updates share the same fragment accumulator.
 */
librdp_status rdp_session_process_fastpath_packet(librdp_session* session, const rdp_buffer* packet)
{
    rdp_buffer decoded;
    const rdp_buffer* parse_packet = packet;
    rdp_fastpath_update_list updates;
    uint16_t i = 0;
    int used_decoded = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_session_unwrap_fastpath_packet(session, packet, &decoded, &used_decoded);
    if (status == LIBRDP_STATUS_OK && used_decoded)
        parse_packet = &decoded;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_parse_updates(parse_packet->data, parse_packet->length, &updates);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    for (i = 0; i < updates.count; i++)
    {
        const rdp_fastpath_update* update = &updates.updates[i];

        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.fastpath.update",
                              "code=%u fragmentation=%u compression=%u payload_len=%u",
                              update->update_code,
                              update->fragmentation,
                              update->compression,
                              (unsigned)update->data_len);
        if (update->update_code == RDP_FASTPATH_UPDATE_BITMAP)
        {
            rdp_bitmap_update bitmap;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.update.rejected",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_bitmap_parse_fastpath_update(update_data, update_len, &bitmap);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_bitmap_update(session, &bitmap);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.fastpath.bitmap_update", "rectangles=%u", bitmap.count);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_PALETTE)
        {
            rdp_palette_update palette;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.palette.rejected",
                                "fragmentation=%u compression=%u payload_len=%u",
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_bitmap_parse_fastpath_palette_update(update_data, update_len, &palette);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_palette_update(session, &palette);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.fastpath.palette_update", "colors=%u", palette.count);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_ORDERS)
        {
            rdp_gdi_orders_update orders;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.orders.rejected",
                                "fragmentation=%u compression=%u payload_len=%u",
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_gdi_parse_fast_orders_update_payload(update_data, update_len, &orders);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_gdi_orders_update(session, &orders);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status == LIBRDP_STATUS_UNSUPPORTED)
                {
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.fastpath.orders.rejected",
                                    "orders=%u payload_len=%u",
                                    orders.number_orders,
                                    (unsigned)orders.order_data_len);
                }
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.fastpath.orders", "orders=%u", orders.number_orders);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_SURFACE_COMMANDS)
        {
            rdp_surface_command_list commands;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.surface.rejected",
                                "fragmentation=%u compression=%u payload_len=%u",
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_surface_commands_parse(update_data, update_len, &commands);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_surface_commands(session, &commands);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.surface",
                                "commands=%u payload_len=%u",
                                commands.count,
                                (unsigned)update_len);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_SYNCHRONIZE)
        {
            rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "rdp.fastpath.synchronize",
                                  "fragmentation=%u compression=%u payload_len=%u",
                                  update->fragmentation,
                                  update->compression,
                                  (unsigned)update->data_len);
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_POINTER_NULL ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_DEFAULT ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_POSITION ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_COLOR ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_CACHED ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_NEW ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_LARGE)
        {
            rdp_pointer_update pointer;
            const uint8_t* update_data = NULL;
            size_t update_len = 0;
            int complete = 0;
            int from_fragment = 0;

            status = rdp_session_fastpath_payload(session, update, &update_data, &update_len, &complete, &from_fragment);
            if (status == LIBRDP_STATUS_UNSUPPORTED)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer.rejected",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else if (status != LIBRDP_STATUS_OK)
            {
                goto out;
            }
            else if (complete)
            {
                status = rdp_pointer_parse_fastpath(update->update_code, update_data, update_len, &pointer);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_pointer_apply_update(session, &pointer);
                if (from_fragment)
                    rdp_session_fastpath_fragment_reset(session);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer",
                                "code=%u kind=%u cache_index=%u width=%u height=%u",
                                update->update_code,
                                pointer.kind,
                                pointer.cache_index,
                                pointer.width,
                                pointer.height);
            }
        }
    }

out:
    rdp_buffer_free(&decoded);
    return status;
}
