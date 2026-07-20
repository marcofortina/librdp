/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session selection and routing-token helper support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/session_selection.h"

#include "common/stream.h"
#include "protocol/slowpath.h"

#include <limits.h>
#include <string.h>

librdp_status rdp_session_selection_parse_pdu(const void* data,
                                              size_t length,
                                              rdp_session_selection_pdu* pdu)
{
    rdp_session_selection_pdu parsed;
    rdp_stream stream;
    uint32_t expected = 0;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SESSION_SELECTION_V1_LENGTH || length > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.cb_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.cb_size != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.cb_size == RDP_SESSION_SELECTION_V1_LENGTH)
    {
        if (parsed.version != RDP_SESSION_SELECTION_VERSION1 || rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *pdu = parsed;
        return LIBRDP_STATUS_OK;
    }

    if (parsed.cb_size < RDP_SESSION_SELECTION_V2_HEADER_LENGTH ||
        parsed.version != RDP_SESSION_SELECTION_VERSION2 ||
        rdp_stream_read_u16_le(&stream, &parsed.text_chars) != LIBRDP_STATUS_OK ||
        parsed.text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    expected = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + ((uint32_t)parsed.text_chars * 2u);
    if (parsed.cb_size != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.text_utf16le, (size_t)parsed.text_chars * 2u) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_selection_write_v1(rdp_buffer* buffer, uint32_t id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_V1_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, id);
}

librdp_status rdp_session_selection_write_v2(rdp_buffer* buffer,
                                             uint32_t id,
                                             const void* text_utf16le,
                                             uint16_t text_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t byte_len = (uint32_t)text_chars * 2u;
    uint32_t cb_size = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + byte_len;

    if (!buffer || (!text_utf16le && text_chars > 0) ||
        text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u32_le(buffer, cb_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, text_chars);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, text_utf16le, byte_len);
}

static int rdp_server_redirection_blob_enabled(
    uint32_t flags,
    uint32_t flag,
    const rdp_server_redirection_blob* blob)
{
    int enabled = (flags & flag) != 0u;

    if (!blob)
        return 0;
    if (enabled)
        return blob->data != NULL && blob->length > 0u;
    return blob->data == NULL && blob->length == 0u;
}

static int rdp_server_redirection_utf16_valid(
    const rdp_server_redirection_blob* blob)
{
    if (!blob || !blob->data || blob->length < 2u ||
        (blob->length & 1u) != 0u)
        return 0;
    return blob->data[blob->length - 2u] == 0u &&
           blob->data[blob->length - 1u] == 0u;
}

static librdp_status rdp_server_redirection_read_blob(
    rdp_stream* stream,
    rdp_server_redirection_blob* blob)
{
    uint32_t length = 0u;

    if (!stream || !blob)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &length) != LIBRDP_STATUS_OK ||
        length == 0u || length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &blob->data, length) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    blob->length = length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_redirection_append_blob(
    rdp_buffer* buffer,
    const rdp_server_redirection_blob* blob)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !blob || !blob->data || blob->length == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, blob->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, blob->data, blob->length);
    return status;
}

/*
 * Validate presence flags and field semantics before serialization or commit.
 * Unicode fields include an aligned UTF-16LE terminator, while routing,
 * address-list, and TSV payloads remain bounded opaque data.
 */
static int rdp_server_redirection_packet_valid(
    const rdp_server_redirection_packet* packet)
{
    uint32_t flags = 0u;

    if (!packet)
        return 0;
    flags = packet->redirection_flags;
    if ((flags & ~RDP_SERVER_REDIRECTION_KNOWN_FLAGS) != 0u)
        return 0;
    if (!rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS,
            &packet->target_net_address) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO,
            &packet->load_balance_info) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_USERNAME,
            &packet->username) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_DOMAIN,
            &packet->domain) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_PASSWORD,
            &packet->password) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_TARGET_FQDN,
            &packet->target_fqdn) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME,
            &packet->target_netbios_name) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_CLIENT_TSV_URL,
            &packet->tsv_url) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_REDIRECTION_GUID,
            &packet->redirection_guid) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_TARGET_CERTIFICATE,
            &packet->target_certificate) ||
        !rdp_server_redirection_blob_enabled(
            flags,
            RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES,
            &packet->target_net_addresses))
        return 0;

    if ((flags & RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->target_net_address))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_USERNAME) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->username))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_DOMAIN) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->domain))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_PASSWORD) != 0u &&
        (flags & RDP_SERVER_REDIRECTION_LB_PASSWORD_IS_PK_ENCRYPTED) == 0u &&
        !rdp_server_redirection_utf16_valid(&packet->password))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_TARGET_FQDN) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->target_fqdn))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->target_netbios_name))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_REDIRECTION_GUID) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->redirection_guid))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_TARGET_CERTIFICATE) != 0u &&
        !rdp_server_redirection_utf16_valid(&packet->target_certificate))
        return 0;
    if ((flags & RDP_SERVER_REDIRECTION_LB_PASSWORD_IS_PK_ENCRYPTED) != 0u &&
        (flags & RDP_SERVER_REDIRECTION_LB_PASSWORD) == 0u)
        return 0;
    return 1;
}

static librdp_status rdp_server_redirection_packet_size(
    const rdp_server_redirection_packet* packet,
    int append_pad,
    uint16_t* packet_length)
{
    const rdp_server_redirection_blob* blobs[] = {
        &packet->target_net_address,
        &packet->load_balance_info,
        &packet->username,
        &packet->domain,
        &packet->password,
        &packet->target_fqdn,
        &packet->target_netbios_name,
        &packet->tsv_url,
        &packet->redirection_guid,
        &packet->target_certificate,
        &packet->target_net_addresses
    };
    size_t total = RDP_SERVER_REDIRECTION_PACKET_BASE_LENGTH;
    size_t i = 0u;

    if (!packet_length || !rdp_server_redirection_packet_valid(packet))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0u; i < sizeof(blobs) / sizeof(blobs[0]); i++)
    {
        if (blobs[i]->length == 0u)
            continue;
        if (blobs[i]->length > UINT16_MAX ||
            total > UINT16_MAX - 4u - blobs[i]->length)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        total += 4u + blobs[i]->length;
    }
    if (append_pad)
    {
        if (total > UINT16_MAX - RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        total += RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH;
    }
    *packet_length = (uint16_t)total;
    return LIBRDP_STATUS_OK;
}

/*
 * Decode the complete server redirection structure without committing partial
 * borrowed views. Presence flags determine field order, and only the specified
 * optional eight-byte packet padding may remain after the final field.
 */
librdp_status rdp_server_redirection_parse_packet(
    const void* data,
    size_t length,
    rdp_server_redirection_packet* packet)
{
    rdp_server_redirection_packet parsed;
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SERVER_REDIRECTION_PACKET_BASE_LENGTH ||
        length > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed.flags) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.length) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.session_id) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.redirection_flags) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.flags != RDP_SERVER_REDIRECTION_PACKET_FLAGS ||
        parsed.length != length ||
        (parsed.redirection_flags &
         ~RDP_SERVER_REDIRECTION_KNOWN_FLAGS) != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

#define RDP_READ_REDIRECTION_BLOB(flag_, field_)                           \
    do                                                                     \
    {                                                                      \
        if ((parsed.redirection_flags & (flag_)) != 0u)                    \
            status = rdp_server_redirection_read_blob(&stream,             \
                                                       &parsed.field_);     \
    } while (0)

    RDP_READ_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS,
        target_net_address);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO,
            load_balance_info);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_USERNAME,
            username);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_DOMAIN,
            domain);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_PASSWORD,
            password);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_TARGET_FQDN,
            target_fqdn);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME,
            target_netbios_name);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_CLIENT_TSV_URL,
            tsv_url);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_REDIRECTION_GUID,
            redirection_guid);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_TARGET_CERTIFICATE,
            target_certificate);
    if (status == LIBRDP_STATUS_OK)
        RDP_READ_REDIRECTION_BLOB(
            RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES,
            target_net_addresses);
#undef RDP_READ_REDIRECTION_BLOB

    if (status != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) ==
        RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH)
    {
        parsed.has_pad = 1u;
        if (rdp_stream_skip(
                &stream,
                RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (rdp_stream_remaining(&stream) != 0u ||
        !rdp_server_redirection_packet_valid(&parsed))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *packet = parsed;
    return LIBRDP_STATUS_OK;
}

/*
 * Serialize into temporary storage so allocation or validation failures leave
 * the destination unchanged. Sensitive fields remain opaque and are never
 * emitted through diagnostics.
 */
librdp_status rdp_server_redirection_write_packet(
    rdp_buffer* buffer,
    const rdp_server_redirection_packet* packet,
    int append_pad)
{
    rdp_buffer output;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t packet_length = 0u;
    static const uint8_t padding[
        RDP_SERVER_REDIRECTION_PACKET_PAD_LENGTH] = {0};

    if (!buffer || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_redirection_packet_size(
        packet,
        append_pad,
        &packet_length);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_buffer_init(&output);
    status = rdp_buffer_append_u16_le(
        &output,
        RDP_SERVER_REDIRECTION_PACKET_FLAGS);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&output, packet_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&output, packet->session_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(
            &output,
            packet->redirection_flags);

#define RDP_APPEND_REDIRECTION_BLOB(flag_, field_)                         \
    do                                                                     \
    {                                                                      \
        if (status == LIBRDP_STATUS_OK &&                                  \
            (packet->redirection_flags & (flag_)) != 0u)                   \
            status = rdp_server_redirection_append_blob(                   \
                &output,                                                   \
                &packet->field_);                                          \
    } while (0)

    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESS,
        target_net_address);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO,
        load_balance_info);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_USERNAME,
        username);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_DOMAIN,
        domain);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_PASSWORD,
        password);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_FQDN,
        target_fqdn);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_NETBIOS_NAME,
        target_netbios_name);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_CLIENT_TSV_URL,
        tsv_url);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_REDIRECTION_GUID,
        redirection_guid);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_CERTIFICATE,
        target_certificate);
    RDP_APPEND_REDIRECTION_BLOB(
        RDP_SERVER_REDIRECTION_LB_TARGET_NET_ADDRESSES,
        target_net_addresses);
#undef RDP_APPEND_REDIRECTION_BLOB

    if (status == LIBRDP_STATUS_OK && append_pad)
        status = rdp_buffer_append(
            &output,
            padding,
            sizeof(padding));
    if (status == LIBRDP_STATUS_OK && output.length != packet_length)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, output.data, output.length);
    rdp_buffer_free(&output);
    return status;
}

librdp_status rdp_server_redirection_parse_enhanced(
    const void* data,
    size_t length,
    rdp_server_redirection_packet* packet)
{
    rdp_slowpath_share_control_header header;
    const uint8_t* bytes = (const uint8_t*)data;
    uint16_t packet_length = 0u;
    size_t expected = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_parse_share_control_header(
        data,
        length,
        &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.pdu_type != RDP_SLOWPATH_PDU_TYPE_SERVER_REDIRECTION ||
        length < 8u + RDP_SERVER_REDIRECTION_PACKET_BASE_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    packet_length =
        (uint16_t)((uint16_t)bytes[10] | ((uint16_t)bytes[11] << 8u));
    expected = 8u + packet_length;
    if (packet_length < RDP_SERVER_REDIRECTION_PACKET_BASE_LENGTH ||
        (length != expected && length != expected + 1u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_server_redirection_parse_packet(
        bytes + 8u,
        packet_length,
        packet);
}

librdp_status rdp_server_redirection_write_enhanced(
    rdp_buffer* buffer,
    uint16_t channel_id,
    const rdp_server_redirection_packet* packet,
    int append_packet_pad,
    int append_outer_pad)
{
    rdp_buffer packet_data;
    rdp_buffer output;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total_length = 0u;

    if (!buffer || !packet || channel_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet_data);
    rdp_buffer_init(&output);
    status = rdp_server_redirection_write_packet(
        &packet_data,
        packet,
        append_packet_pad);
    total_length =
        8u + packet_data.length + (append_outer_pad ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK && total_length > UINT16_MAX)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_share_control_header(
            &output,
            (uint16_t)total_length,
            RDP_SLOWPATH_PDU_TYPE_SERVER_REDIRECTION,
            channel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&output, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(
            &output,
            packet_data.data,
            packet_data.length);
    if (status == LIBRDP_STATUS_OK && append_outer_pad)
        status = rdp_buffer_append_u8(&output, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, output.data, output.length);
    rdp_buffer_free(&output);
    rdp_buffer_free(&packet_data);
    return status;
}
