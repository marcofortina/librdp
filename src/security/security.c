#include "security/security.h"

#include "common/stream.h"
#include "protocol/mcs.h"
#include "protocol/x224.h"

#include <string.h>

#define RDP_INFO_MOUSE 0x00000001u
#define RDP_INFO_DISABLE_CTRL_ALT_DEL 0x00000002u
#define RDP_INFO_UNICODE 0x00000010u
#define RDP_INFO_MAXIMIZE_SHELL 0x00000020u
#define RDP_INFO_ENABLE_WINDOWS_KEY 0x00000100u
#define RDP_INFO_FORCE_ENCRYPTED_CS_PDU 0x00004000u
#define RDP_INFO_LOGON_ERRORS 0x00010000u
#define RDP_INFO_MOUSE_HAS_WHEEL 0x00020000u

uint32_t rdp_security_protocol_mask(librdp_security_mode mode)
{
    switch (mode)
    {
        case LIBRDP_SECURITY_STANDARD:
            return RDP_X224_PROTOCOL_STANDARD;
        case LIBRDP_SECURITY_TLS:
            return RDP_X224_PROTOCOL_TLS;
        case LIBRDP_SECURITY_NLA:
            return RDP_X224_PROTOCOL_NLA;
        case LIBRDP_SECURITY_AUTO:
        default:
            return RDP_X224_PROTOCOL_TLS | RDP_X224_PROTOCOL_NLA;
    }
}

bool rdp_security_protocol_supported(uint32_t selected_protocol)
{
    return selected_protocol == RDP_X224_PROTOCOL_STANDARD;
}

static size_t rdp_ascii_len(const char* text)
{
    return text ? strlen(text) : 0;
}

static librdp_status rdp_write_utf16le_text(rdp_buffer* buffer, const char* text)
{
    size_t i = 0;
    size_t length = rdp_ascii_len(text);

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < length; i++)
    {
        librdp_status status = rdp_buffer_append_u16_le(buffer, (uint16_t)(uint8_t)text[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return rdp_buffer_append_u16_le(buffer, 0);
}

static librdp_status rdp_security_write_per_length(rdp_buffer* buffer, size_t length)
{
    if (!buffer || length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0x7fu)
        return rdp_buffer_append_u16_be(buffer, (uint16_t)(length | 0x8000u));
    return rdp_buffer_append_u8(buffer, (uint8_t)length);
}

static librdp_status rdp_security_write_per_integer16(rdp_buffer* buffer, uint16_t value, uint16_t min)
{
    if (!buffer || value < min)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_be(buffer, (uint16_t)(value - min));
}

librdp_status rdp_security_write_header(rdp_buffer* buffer, uint16_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, 0);
}

librdp_status rdp_security_write_exchange_pdu(rdp_buffer* buffer,
                                              const uint8_t* encrypted_client_random,
                                              size_t encrypted_client_random_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t pad[8];

    if (!buffer || (!encrypted_client_random && encrypted_client_random_len > 0) ||
        encrypted_client_random_len > 0xffffu - sizeof(pad))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pad, 0, sizeof(pad));
    status = rdp_security_write_header(buffer, (uint16_t)RDP_SEC_EXCHANGE_PKT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(encrypted_client_random_len + sizeof(pad)));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, encrypted_client_random, encrypted_client_random_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, pad, sizeof(pad));
    return status;
}

librdp_status rdp_security_write_client_info_pdu(rdp_buffer* buffer, const rdp_client_info* info)
{
    const size_t domain_len = info ? rdp_ascii_len(info->domain) : 0;
    const size_t username_len = info ? rdp_ascii_len(info->username) : 0;
    const size_t password_len = info ? rdp_ascii_len(info->password) : 0;
    const size_t shell_len = info ? rdp_ascii_len(info->alternate_shell) : 0;
    const size_t work_len = info ? rdp_ascii_len(info->working_dir) : 0;
    const uint32_t flags = RDP_INFO_MOUSE | RDP_INFO_UNICODE | RDP_INFO_LOGON_ERRORS | RDP_INFO_MAXIMIZE_SHELL |
                           RDP_INFO_ENABLE_WINDOWS_KEY | RDP_INFO_DISABLE_CTRL_ALT_DEL | RDP_INFO_MOUSE_HAS_WHEEL |
                           RDP_INFO_FORCE_ENCRYPTED_CS_PDU;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || domain_len > 0x7fffu || username_len > 0x7fffu || password_len > 0x7fffu ||
        shell_len > 0x7fffu || work_len > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_security_write_header(buffer, (uint16_t)RDP_SEC_INFO_PKT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(domain_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(username_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(password_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(shell_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(work_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->domain : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->username : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->password : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->alternate_shell : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->working_dir : NULL);
    return status;
}

librdp_status rdp_security_parse_client_info_pdu(const void* data, size_t length, rdp_client_info_summary* summary)
{
    rdp_stream stream;
    uint16_t flags = 0;
    uint16_t flags_hi = 0;
    size_t need = 0;

    if (!data || !summary)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(summary, 0, sizeof(*summary));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &flags_hi) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & RDP_SEC_INFO_PKT) == 0 || flags_hi != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &summary->code_page) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &summary->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->domain_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->username_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->password_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->alternate_shell_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->working_dir_bytes) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    need = (size_t)summary->domain_bytes + summary->username_bytes + summary->password_bytes +
           summary->alternate_shell_bytes + summary->working_dir_bytes + 10u;
    if (rdp_stream_remaining(&stream) < need)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_write_send_data_request(rdp_buffer* buffer,
                                                   uint16_t user_id,
                                                   uint16_t channel_id,
                                                   const void* payload,
                                                   size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || user_id < RDP_MCS_BASE_CHANNEL_ID || (!payload && payload_len > 0) || payload_len > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)(25u << 2));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_integer16(buffer, user_id, (uint16_t)RDP_MCS_BASE_CHANNEL_ID);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_integer16(buffer, channel_id, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0x70);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_length(buffer, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}
