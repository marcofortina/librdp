/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client audio session domain for RDPSND and AUDIN.
 * Invariants: negotiated formats are copied into session state before callbacks, and audio payload trace stays metadata-only.
 * Ownership: packet buffers are temporary, selected format arrays are session-owned, and callback data is borrowed for callback duration.
 * Threading: called on the session owner thread; public AUDIN send APIs enforce the owner-thread contract.
 * Trust boundary: server audio PDUs, UDP datagrams, and format lists are length-checked before state changes or playback callbacks.
 */

#include "client/session_internal.h"

#include "platform/socket.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int rdp_session_audio_format_is_supported(const rdp_audio_format* format)
{
    uint32_t bytes_per_sample = 0;

    if (!format)
        return 0;
    if (format->channels == 0 || format->channels > 2)
        return 0;
    if (format->samples_per_sec == 0 || format->block_align == 0 || format->avg_bytes_per_sec == 0)
        return 0;
    if (format->format_tag == RDP_AUDIO_FORMAT_ALAW || format->format_tag == RDP_AUDIO_FORMAT_MULAW)
        return format->bits_per_sample == 8u && format->block_align == format->channels;
    if (format->format_tag != RDP_AUDIO_FORMAT_PCM)
        return 0;
    if (format->bits_per_sample != 8u && format->bits_per_sample != 16u && format->bits_per_sample != 24u &&
        format->bits_per_sample != 32u)
        return 0;
    bytes_per_sample = format->bits_per_sample / 8u;
    return bytes_per_sample > 0 && format->block_align == format->channels * bytes_per_sample;
}

static void rdp_session_audio_format_to_public(const rdp_audio_format* in, librdp_audio_format* out)
{
    if (!in || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->format_tag = in->format_tag;
    out->channels = in->channels;
    out->samples_per_sec = in->samples_per_sec;
    out->avg_bytes_per_sec = in->avg_bytes_per_sec;
    out->block_align = in->block_align;
    out->bits_per_sample = in->bits_per_sample;
    out->extra_data = in->extra_data;
    out->extra_data_len = in->extra_data_len;
}

static void rdp_session_emit_audio_output_formats(librdp_session* session, uint16_t version)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS;
    event.data.audio_output_formats.formats = session->audio_output_selected_formats;
    event.data.audio_output_formats.count = session->audio_output_selected_format_count;
    event.data.audio_output_formats.version = version;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_output_data(librdp_session* session,
                                               uint16_t timestamp,
                                               uint16_t format_no,
                                               uint8_t block_no,
                                               uint32_t audio_timestamp,
                                               const uint8_t* data,
                                               size_t data_len)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_DATA;
    event.data.audio_output_data.timestamp = timestamp;
    event.data.audio_output_data.format_no = format_no;
    event.data.audio_output_data.block_no = block_no;
    event.data.audio_output_data.audio_timestamp = audio_timestamp;
    event.data.audio_output_data.data = data;
    event.data.audio_output_data.data_len = data_len;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_output_close(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_input_formats(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_INPUT_FORMATS;
    event.data.audio_input_formats.formats = session->audio_input_selected_formats;
    event.data.audio_input_formats.count = session->audio_input_selected_format_count;
    event.data.audio_input_formats.version = session->audio_input_version;
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_audio_input_open(librdp_session* session, const rdp_audio_input_open* open)
{
    librdp_event event;

    if (!session || !open)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_AUDIO_INPUT_OPEN;
    event.data.audio_input_open.frames_per_packet = open->frames_per_packet;
    event.data.audio_input_open.initial_format = open->initial_format;
    rdp_session_audio_format_to_public(&open->format, &event.data.audio_input_open.format);
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_send_audio_output_wave_confirm(librdp_session* session,
                                                                uint16_t timestamp,
                                                                uint8_t block_no);

static librdp_status rdp_session_send_audio_output_packet(librdp_session* session,
                                                          const rdp_buffer* payload,
                                                          const char* event)
{
    if (!session || !payload || !event || session->audio_output_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->audio_output_channel_id, payload, event);
}

void rdp_session_audio_output_udp_close(librdp_session* session)
{
    if (!session)
        return;
    if (session->audio_output_udp_fd >= 0)
        (void)rdp_socket_close(session->audio_output_udp_fd);
    session->audio_output_udp_fd = -1;
    session->audio_output_udp_port = 0;
    session->audio_output_udp_peer_valid = 0;
    session->audio_output_udp_peer_len = 0;
    memset(&session->audio_output_udp_peer, 0, sizeof(session->audio_output_udp_peer));
}

static librdp_status rdp_session_audio_output_udp_open(librdp_session* session)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = 0;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->audio_output_udp_fd >= 0)
        return LIBRDP_STATUS_OK;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return LIBRDP_STATUS_IO_ERROR;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        (void)rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (rdp_socket_set_nonblocking(fd, 1) != 0)
    {
        (void)rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    addr_len = (socklen_t)sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0)
    {
        (void)rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    session->audio_output_udp_fd = fd;
    session->audio_output_udp_port = ntohs(addr.sin_port);
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "transport.udp.bind.done",
                    "component=rdpsnd port=%u",
                    session->audio_output_udp_port);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_audio_output_udp_payload(librdp_session* session,
                                                               const void* data,
                                                               size_t data_len,
                                                               const char* event)
{
    ssize_t sent = 0;

    if (!session || (!data && data_len > 0) || !event || session->audio_output_udp_fd < 0 ||
        !session->audio_output_udp_peer_valid || session->audio_output_udp_peer_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > (size_t)SSIZE_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    do
    {
        sent = sendto(session->audio_output_udp_fd,
                      data,
                      data_len,
                      0,
                      (const struct sockaddr*)&session->audio_output_udp_peer,
                      session->audio_output_udp_peer_len);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0 || (size_t)sent != data_len)
        return LIBRDP_STATUS_IO_ERROR;

    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.udp.write.done",
                          "component=rdpsnd event=%s bytes=%u",
                          event,
                          (unsigned)data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_audio_output_wave_confirm_udp(librdp_session* session,
                                                                    uint16_t timestamp,
                                                                    uint8_t block_no)
{
    rdp_buffer confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&confirm);
    status = rdp_audio_output_write_wave_confirm(&confirm, timestamp, block_no);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_output_udp_payload(session,
                                                           confirm.data,
                                                           confirm.length,
                                                           "client.rdpsnd.wave_confirm");
    rdp_buffer_free(&confirm);
    return status;
}

static librdp_status rdp_session_send_audio_output_wave_confirm_route(librdp_session* session,
                                                                      uint16_t timestamp,
                                                                      uint8_t block_no,
                                                                      int use_udp)
{
    if (use_udp)
        return rdp_session_send_audio_output_wave_confirm_udp(session, timestamp, block_no);
    return rdp_session_send_audio_output_wave_confirm(session, timestamp, block_no);
}

static CRYPTO_ONCE rdp_session_audio_output_provider_once = CRYPTO_ONCE_STATIC_INIT;
static OSSL_PROVIDER* rdp_session_audio_output_default_provider;
static OSSL_PROVIDER* rdp_session_audio_output_legacy_provider;
static int rdp_session_audio_output_legacy_ready;

static void rdp_session_audio_output_provider_init(void)
{
    rdp_session_audio_output_default_provider = OSSL_PROVIDER_load(NULL, "default");
    rdp_session_audio_output_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    rdp_session_audio_output_legacy_ready = rdp_session_audio_output_legacy_provider != NULL;
}

static librdp_status rdp_session_audio_output_legacy_ensure(void)
{
    if (CRYPTO_THREAD_run_once(&rdp_session_audio_output_provider_once,
                               rdp_session_audio_output_provider_init) != 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_session_audio_output_legacy_ready ? LIBRDP_STATUS_OK : LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_session_audio_output_sha1(const uint8_t* first,
                                                   size_t first_len,
                                                   const uint8_t* second,
                                                   size_t second_len,
                                                   uint8_t output[20])
{
    EVP_MD_CTX* context = NULL;
    unsigned int got = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((!first && first_len > 0) || (!second && second_len > 0) || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context = EVP_MD_CTX_new();
    if (!context)
        return LIBRDP_STATUS_NO_MEMORY;
    if (EVP_DigestInit_ex(context, EVP_sha1(), NULL) != 1)
        goto out;
    if (first_len > 0 && EVP_DigestUpdate(context, first, first_len) != 1)
        goto out;
    if (second_len > 0 && EVP_DigestUpdate(context, second, second_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, output, &got) != 1 || got != 20u)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MD_CTX_free(context);
    return status;
}

static librdp_status rdp_session_audio_output_rc4(uint8_t key[20], uint8_t* data, size_t data_len)
{
    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* context = NULL;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!key || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_audio_output_legacy_ensure();
    if (status != LIBRDP_STATUS_OK)
        return status;
    cipher = EVP_CIPHER_fetch(NULL, "RC4", "provider=legacy");
    if (!cipher)
        return LIBRDP_STATUS_UNSUPPORTED;
    context = EVP_CIPHER_CTX_new();
    if (!context)
    {
        EVP_CIPHER_free(cipher);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    if (EVP_DecryptInit_ex(context, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_set_key_length(context, 20) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, NULL) != 1)
        goto out;
    while (data_len > 0)
    {
        int out_len = 0;
        int chunk = data_len > (size_t)INT_MAX ? INT_MAX : (int)data_len;

        if (EVP_DecryptUpdate(context, data, &out_len, data, chunk) != 1 || out_len != chunk)
            goto out;
        data += chunk;
        data_len -= (size_t)chunk;
    }
    status = LIBRDP_STATUS_OK;

out:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    return status;
}

static librdp_status rdp_session_audio_output_decrypt_wave(librdp_session* session,
                                                           const rdp_audio_output_wave_encrypt* wave,
                                                           rdp_buffer* decrypted)
{
    uint8_t nonce[36];
    uint8_t key[20];
    uint8_t signature[20];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !wave || !decrypted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(nonce, 0, sizeof(nonce));
    if (session->audio_output_crypt_seed_valid)
        memcpy(nonce, session->audio_output_crypt_seed, sizeof(session->audio_output_crypt_seed));
    nonce[32] = wave->block_no;

    status = rdp_session_audio_output_sha1(nonce, sizeof(nonce), NULL, 0, key);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (wave->signature_len == 8u)
    {
        status = rdp_session_audio_output_sha1(nonce, sizeof(nonce), wave->data, wave->data_len, signature);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (memcmp(wave->signature, signature, 8u) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_buffer_append(decrypted, wave->data, wave->data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    return rdp_session_audio_output_rc4(key, decrypted->data, decrypted->length);
}

static librdp_status rdp_session_send_audio_input_packet(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event)
{
    if (!session || !payload || !event || session->audio_input_channel_id == 0 ||
        session->audio_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->audio_input_channel_id,
                                                 session->audio_input_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_audio_input_incoming(librdp_session* session)
{
    rdp_buffer incoming;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&incoming);
    status = rdp_audio_input_write_incoming_data(&incoming);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &incoming, "client.audin.data_incoming");
    rdp_buffer_free(&incoming);
    return status;
}

static librdp_status rdp_session_send_audio_input_formats(librdp_session* session,
                                                          const rdp_audio_input_formats* server_formats)
{
    rdp_audio_format selected[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer formats_pdu;
    uint32_t selected_count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !server_formats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(selected, 0, sizeof(selected));
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    session->audio_input_selected_format_count = 0;
    for (i = 0; i < server_formats->format_count && selected_count < RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT; i++)
    {
        rdp_audio_format format;

        status = rdp_audio_format_get_from_list(server_formats->formats,
                                                server_formats->formats_len,
                                                server_formats->format_count,
                                                i,
                                                &format);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (rdp_session_audio_format_is_supported(&format))
        {
            selected[selected_count] = format;
            rdp_session_audio_format_to_public(&format,
                                               &session->audio_input_selected_formats[selected_count]);
            selected_count++;
        }
    }

    rdp_buffer_init(&formats_pdu);
    status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_formats(&formats_pdu, selected, selected_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &formats_pdu, "client.audin.formats");
    rdp_buffer_free(&formats_pdu);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_input_ready = selected_count > 0 ? 1u : 0u;
        session->audio_input_selected_format_count = selected_count;
        rdp_session_emit_audio_input_formats(session);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.formats",
                        "dvc_channel_id=%u server_formats=%u selected_formats=%u",
                        session->audio_input_channel_id,
                        server_formats->format_count,
                        selected_count);
    }
    return status;
}

/*
 * Handle audio-input control messages. Version, format negotiation, open/close
 * state, and captured sample flow are validated before callbacks or backend
 * capture state are touched.
 */
librdp_status rdp_session_handle_audio_input_message(librdp_session* session,
                                                            uint32_t channel_id,
                                                            const uint8_t* data,
                                                            size_t data_len)
{
    rdp_audio_input_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_audio_input_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.audin.pdu",
                          "dvc_channel_id=%u message_id=%u payload_len=%u",
                          channel_id,
                          header.message_id,
                          (unsigned)data_len);
    if (header.message_id == RDP_AUDIO_INPUT_VERSION)
    {
        rdp_buffer response;
        uint32_t server_version = 0;
        uint32_t client_version = 0;

        rdp_buffer_init(&response);
        status = rdp_audio_input_parse_version(data, data_len, &server_version);
        if (status == LIBRDP_STATUS_OK)
        {
            client_version = server_version > RDP_AUDIO_INPUT_VERSION_2 ? RDP_AUDIO_INPUT_VERSION_2 : server_version;
            if (client_version == 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_input_write_version(&response, client_version);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_packet(session, &response, "client.audin.version");
        rdp_buffer_free(&response);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_input_version = client_version;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.version",
                            "dvc_channel_id=%u server_version=%u client_version=%u",
                            channel_id,
                            server_version,
                            client_version);
        }
    }
    else if (header.message_id == RDP_AUDIO_INPUT_FORMATS)
    {
        rdp_audio_input_formats formats;

        status = rdp_audio_input_parse_formats(data, data_len, &formats);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_formats(session, &formats);
    }
    else if (header.message_id == RDP_AUDIO_INPUT_OPEN)
    {
        rdp_audio_input_open open;

        status = rdp_audio_input_parse_open(data, data_len, &open);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_input_open_reply_sent = 0;
            rdp_session_emit_audio_input_open(session, &open);
            if (!session->audio_input_open_reply_sent)
                status = librdp_session_audio_input_open_reply(session, RDP_AUDIO_INPUT_RESULT_FAIL);
        }
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.open",
                            "dvc_channel_id=%u frames_per_packet=%u initial_format=%u result=%u",
                            channel_id,
                            open.frames_per_packet,
                            open.initial_format,
                            session->audio_input_open ? RDP_AUDIO_INPUT_RESULT_OK : RDP_AUDIO_INPUT_RESULT_FAIL);
    }
    else if (header.message_id == RDP_AUDIO_INPUT_FORMAT_CHANGE)
    {
        rdp_buffer response;
        uint32_t new_format = 0;

        rdp_buffer_init(&response);
        status = rdp_audio_input_parse_format_change(data, data_len, &new_format);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_input_write_format_change(&response, new_format);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_input_packet(session, &response, "client.audin.format_change");
        rdp_buffer_free(&response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.format_change",
                            "dvc_channel_id=%u new_format=%u",
                            channel_id,
                            new_format);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.audin.pdu",
                              "dvc_channel_id=%u message_id=%u payload_len=%u",
                              channel_id,
                              header.message_id,
                              (unsigned)data_len);
    }
    return status;
}

/*
 * Handle server audio-output format negotiation. Advertised formats are
 * filtered against local capabilities and the selected format is copied into
 * session state before playback starts.
 */
static librdp_status rdp_session_handle_audio_output_formats(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_audio_output_formats server_formats;
    rdp_audio_format selected[RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT];
    rdp_buffer response;
    rdp_buffer quality;
    uint16_t selected_count = 0;
    uint16_t i = 0;
    uint16_t client_version = 6;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(selected, 0, sizeof(selected));
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    session->audio_output_selected_format_count = 0;
    rdp_buffer_init(&response);
    rdp_buffer_init(&quality);

    status = rdp_audio_output_parse_formats(data, data_len, &server_formats);
    if (status == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < server_formats.format_count && selected_count < RDP_SESSION_AUDIO_OUTPUT_FORMAT_LIMIT; i++)
        {
            rdp_audio_format format;

            status = rdp_audio_format_get_from_list(server_formats.formats,
                                                    server_formats.formats_len,
                                                    server_formats.format_count,
                                                    i,
                                                    &format);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (rdp_session_audio_format_is_supported(&format))
            {
                selected[selected_count] = format;
                rdp_session_audio_format_to_public(&format,
                                                   &session->audio_output_selected_formats[selected_count]);
                selected_count++;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        uint32_t flags = selected_count > 0 ? RDP_AUDIO_OUTPUT_CAP_ALIVE : 0;
        uint16_t datagram_port = 0;

        session->audio_output_server_version = server_formats.version;
        session->audio_output_client_version = client_version;
        if (selected_count > 0)
        {
            librdp_status udp_status = rdp_session_audio_output_udp_open(session);

            if (udp_status == LIBRDP_STATUS_OK)
                datagram_port = session->audio_output_udp_port;
            else
                rdp_trace_event(RDP_TRACE_TRANSPORT,
                                "transport.udp.bind.failed",
                                "component=rdpsnd status=%s",
                                librdp_status_string(udp_status));
        }
        status = rdp_audio_output_write_client_formats(&response,
                                                       flags,
                                                       0xffffffffu,
                                                       0x00010000u,
                                                       datagram_port,
                                                       server_formats.last_block_confirmed,
                                                       client_version,
                                                       selected,
                                                       selected_count);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_output_packet(session, &response, "client.rdpsnd.formats");
    if (status == LIBRDP_STATUS_OK && server_formats.version >= 6u && client_version >= 6u)
    {
        status = rdp_audio_output_write_quality_mode(&quality, RDP_AUDIO_OUTPUT_QUALITY_HIGH);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_packet(session, &quality, "client.rdpsnd.quality_mode");
    }
    rdp_buffer_free(&quality);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_output_ready = selected_count > 0 ? 1u : 0u;
        session->audio_output_selected_format_count = selected_count;
        rdp_session_emit_audio_output_formats(session, client_version);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.formats",
                        "channel_id=%u server_version=%u client_version=%u server_formats=%u selected_formats=%u",
                        session->audio_output_channel_id,
                        server_formats.version,
                        client_version,
                        server_formats.format_count,
                        selected_count);
    }
    return status;
}

static librdp_status rdp_session_send_audio_output_wave_confirm(librdp_session* session,
                                                                uint16_t timestamp,
                                                                uint8_t block_no)
{
    rdp_buffer confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&confirm);
    status = rdp_audio_output_write_wave_confirm(&confirm, timestamp, block_no);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_output_packet(session, &confirm, "client.rdpsnd.wave_confirm");
    rdp_buffer_free(&confirm);
    return status;
}

static int rdp_session_audio_output_format_valid(const librdp_session* session, uint16_t format_no)
{
    return session && format_no < session->audio_output_selected_format_count;
}

static void rdp_session_audio_output_pending_reset(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
    session->audio_output_pending_wave = 0u;
    session->audio_output_pending_format_no = 0u;
    session->audio_output_pending_timestamp = 0u;
    session->audio_output_pending_expected_len = 0u;
    session->audio_output_pending_block_no = 0u;
}

static void rdp_session_audio_output_udp_reset(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    session->audio_output_udp_active = 0;
    session->audio_output_udp_block_no = 0;
    session->audio_output_udp_next_fragment_no = 0;
}

static librdp_status rdp_session_handle_audio_output_udp_wave(librdp_session* session,
                                                              const uint8_t* data,
                                                              size_t data_len)
{
    rdp_audio_output_udp_wave wave;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->audio_output_ready)
        return LIBRDP_STATUS_STATE;
    status = rdp_audio_output_parse_udp_wave(data, data_len, &wave);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_audio_output_udp_reset(session);
        return status;
    }
    if (wave.fragment_no == 0)
    {
        rdp_session_audio_output_udp_reset(session);
        session->audio_output_udp_active = 1;
        session->audio_output_udp_block_no = wave.block_no;
        session->audio_output_udp_next_fragment_no = 1;
    }
    else if (!session->audio_output_udp_active ||
             session->audio_output_udp_block_no != wave.block_no ||
             session->audio_output_udp_next_fragment_no != wave.fragment_no)
    {
        rdp_session_audio_output_udp_reset(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
    {
        session->audio_output_udp_next_fragment_no++;
    }
    status = rdp_buffer_append(&session->audio_output_udp_data, wave.data, wave.data_len);
    if (status != LIBRDP_STATUS_OK)
        rdp_session_audio_output_udp_reset(session);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpsnd.udp_wave",
                              "channel_id=%u block_no=%u fragment_no=%u received=%u data_len=%u",
                              session->audio_output_channel_id,
                              wave.block_no,
                              wave.fragment_no,
                              (unsigned)session->audio_output_udp_data.length,
                              (unsigned)wave.data_len);
    return status;
}

static librdp_status rdp_session_handle_audio_output_udp_wave_last(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len,
                                                                   int use_udp)
{
    rdp_audio_output_udp_wave_last wave;
    const uint8_t* audio_data = NULL;
    size_t audio_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->audio_output_ready)
        return LIBRDP_STATUS_STATE;
    status = rdp_audio_output_parse_udp_wave_last(data, data_len, &wave);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_audio_output_udp_reset(session);
        return status;
    }
    if (!rdp_session_audio_output_format_valid(session, wave.format_no))
    {
        rdp_session_audio_output_udp_reset(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (session->audio_output_udp_active)
    {
        if (session->audio_output_udp_block_no != wave.block_no)
        {
            rdp_session_audio_output_udp_reset(session);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        status = rdp_buffer_append(&session->audio_output_udp_data, wave.data, wave.data_len);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_audio_output_udp_reset(session);
            return status;
        }
        audio_data = session->audio_output_udp_data.data;
        audio_len = session->audio_output_udp_data.length;
    }
    else
    {
        audio_data = wave.data;
        audio_len = wave.data_len;
    }
    if (wave.total_size != 0 && audio_len > wave.total_size)
    {
        rdp_session_audio_output_udp_reset(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_session_emit_audio_output_data(session,
                                       wave.timestamp,
                                       wave.format_no,
                                       wave.block_no,
                                       0,
                                       audio_data,
                                       audio_len);
    status = rdp_session_send_audio_output_wave_confirm_route(session,
                                                              wave.timestamp,
                                                              wave.block_no,
                                                              use_udp);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.udp_wave_last",
                        "channel_id=%u format_no=%u block_no=%u total_size=%u data_len=%u",
                        session->audio_output_channel_id,
                        wave.format_no,
                        wave.block_no,
                        wave.total_size,
                        (unsigned)audio_len);
    rdp_session_audio_output_udp_reset(session);
    return status;
}

static librdp_status rdp_session_handle_audio_output_wave_encrypt(librdp_session* session,
                                                                  const uint8_t* data,
                                                                  size_t data_len,
                                                                  int use_udp)
{
    rdp_audio_output_wave_encrypt wave;
    rdp_buffer decrypted;
    int expect_signature = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->audio_output_ready)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&decrypted);
    expect_signature = session->audio_output_server_version >= 5u && session->audio_output_client_version >= 5u;
    status = rdp_audio_output_parse_wave_encrypt(data, data_len, expect_signature, &wave);
    if (status != LIBRDP_STATUS_OK)
        status = rdp_audio_output_parse_wave_encrypt(data, data_len, expect_signature ? 0 : 1, &wave);
    if (status == LIBRDP_STATUS_OK && !rdp_session_audio_output_format_valid(session, wave.format_no))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_audio_output_decrypt_wave(session, &wave, &decrypted);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.wave_encrypt.failed",
                        "channel_id=%u status=%s use_udp=%u",
                        session->audio_output_channel_id,
                        librdp_status_string(status),
                        use_udp ? 1u : 0u);
        rdp_buffer_free(&decrypted);
        return LIBRDP_STATUS_OK;
    }

    rdp_session_emit_audio_output_data(session,
                                       wave.timestamp,
                                       wave.format_no,
                                       wave.block_no,
                                       0,
                                       decrypted.data,
                                       decrypted.length);
    status = rdp_session_send_audio_output_wave_confirm_route(session,
                                                              wave.timestamp,
                                                              wave.block_no,
                                                              use_udp);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.wave_encrypt",
                        "channel_id=%u format_no=%u block_no=%u signature_len=%u encrypted_len=%u delivered=1 use_udp=%u",
                        session->audio_output_channel_id,
                        wave.format_no,
                        wave.block_no,
                        (unsigned)wave.signature_len,
                        (unsigned)wave.data_len,
                        use_udp ? 1u : 0u);
    rdp_buffer_free(&decrypted);
    return status;
}

/*
 * Audio output has three framing layers: virtual-channel fragmentation,
 * rdpsnd message framing, and sometimes a split wave-info/wave-data pair.
 * This dispatcher owns the pending wave state so acknowledgements are emitted
 * only after the matching payload has been delivered to the application.
 */
librdp_status rdp_session_handle_audio_output_message(librdp_session* session,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_audio_output_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->audio_output_pending_wave)
    {
        rdp_audio_output_wave_data wave_data;

        if (!session->audio_output_ready)
        {
            rdp_session_audio_output_pending_reset(session);
            return LIBRDP_STATUS_STATE;
        }
        status = rdp_audio_output_parse_wave_data(data, data_len, &wave_data);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_audio_output_pending_reset(session);
            return status;
        }
        if (wave_data.data_len != session->audio_output_pending_expected_len)
        {
            rdp_session_audio_output_pending_reset(session);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (!rdp_session_audio_output_format_valid(session, session->audio_output_pending_format_no))
        {
            rdp_session_audio_output_pending_reset(session);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (rdp_buffer_append(&session->audio_output_pending_data, wave_data.data, wave_data.data_len) !=
            LIBRDP_STATUS_OK)
        {
            rdp_session_audio_output_pending_reset(session);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        rdp_session_emit_audio_output_data(session,
                                           session->audio_output_pending_timestamp,
                                           session->audio_output_pending_format_no,
                                           session->audio_output_pending_block_no,
                                           0,
                                           session->audio_output_pending_data.data,
                                           session->audio_output_pending_data.length);
        status = rdp_session_send_audio_output_wave_confirm(session,
                                                            session->audio_output_pending_timestamp,
                                                            session->audio_output_pending_block_no);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave",
                            "channel_id=%u format_no=%u block_no=%u data_len=%u",
                            session->audio_output_channel_id,
                            session->audio_output_pending_format_no,
                            session->audio_output_pending_block_no,
                            (unsigned)session->audio_output_pending_data.length);
        rdp_session_audio_output_pending_reset(session);
        return status;
    }

    if (data_len > 0 && data[0] == RDP_AUDIO_OUTPUT_UDPWAVE)
        return rdp_session_handle_audio_output_udp_wave(session, data, data_len);
    if (data_len > 0 && data[0] == RDP_AUDIO_OUTPUT_UDPWAVELAST)
        return rdp_session_handle_audio_output_udp_wave_last(session, data, data_len, 0);

    status = rdp_audio_output_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.rdpsnd.pdu",
                          "channel_id=%u type=%u body_size=%u payload_len=%u",
                          session->audio_output_channel_id,
                          header.msg_type,
                          header.body_size,
                          (unsigned)data_len);
    if (header.msg_type == RDP_AUDIO_OUTPUT_FORMATS)
    {
        status = rdp_session_handle_audio_output_formats(session, data, data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_TRAINING)
    {
        rdp_audio_output_training training;
        rdp_buffer confirm;

        rdp_buffer_init(&confirm);
        status = rdp_audio_output_parse_training(data, data_len, &training);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_audio_output_write_training_confirm(&confirm, training.timestamp, training.packet_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_packet(session, &confirm, "client.rdpsnd.training_confirm");
        rdp_buffer_free(&confirm);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.training",
                            "channel_id=%u timestamp=%u packet_size=%u data_len=%u",
                            session->audio_output_channel_id,
                            training.timestamp,
                            training.packet_size,
                            (unsigned)training.data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVE)
    {
        rdp_audio_output_wave_info wave;

        status = session->audio_output_ready ?
            rdp_audio_output_parse_wave_info(data, data_len, &wave) :
            LIBRDP_STATUS_STATE;
        if (status == LIBRDP_STATUS_OK && !rdp_session_audio_output_format_valid(session, wave.format_no))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&session->audio_output_pending_data);
            rdp_buffer_init(&session->audio_output_pending_data);
            status = rdp_buffer_append(&session->audio_output_pending_data, wave.first_data, wave.first_data_len);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_output_pending_wave = 1;
            session->audio_output_pending_timestamp = wave.timestamp;
            session->audio_output_pending_format_no = wave.format_no;
            session->audio_output_pending_block_no = wave.block_no;
            session->audio_output_pending_expected_len = wave.expected_data_len;
        }
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave_info",
                            "channel_id=%u format_no=%u block_no=%u expected_tail=%u",
                            session->audio_output_channel_id,
                            wave.format_no,
                            wave.block_no,
                            wave.expected_data_len);
        }
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVE2)
    {
        rdp_audio_output_wave2 wave;

        status = session->audio_output_ready ?
            rdp_audio_output_parse_wave2(data, data_len, &wave) :
            LIBRDP_STATUS_STATE;
        if (status == LIBRDP_STATUS_OK && !rdp_session_audio_output_format_valid(session, wave.format_no))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            rdp_session_emit_audio_output_data(session,
                                               wave.timestamp,
                                               wave.format_no,
                                               wave.block_no,
                                               wave.audio_timestamp,
                                               wave.data,
                                               wave.data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_audio_output_wave_confirm(session, wave.timestamp, wave.block_no);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.wave2",
                            "channel_id=%u format_no=%u block_no=%u audio_timestamp=%u data_len=%u",
                            session->audio_output_channel_id,
                            wave.format_no,
                            wave.block_no,
                            wave.audio_timestamp,
                            (unsigned)wave.data_len);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_CLOSE)
    {
        status = rdp_audio_output_parse_close(data, data_len);
        if (status == LIBRDP_STATUS_OK)
        {
            session->audio_output_ready = 0;
            session->audio_output_selected_format_count = 0u;
            rdp_session_audio_output_pending_reset(session);
            rdp_session_audio_output_udp_reset(session);
            rdp_session_emit_audio_output_close(session);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.close",
                            "channel_id=%u",
                            session->audio_output_channel_id);
        }
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_SETVOLUME || header.msg_type == RDP_AUDIO_OUTPUT_SETPITCH)
    {
        rdp_audio_output_setting setting;

        status = rdp_audio_output_parse_setting(data, data_len, header.msg_type, &setting);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            header.msg_type == RDP_AUDIO_OUTPUT_SETVOLUME ? "client.rdpsnd.volume" :
                                                                             "client.rdpsnd.pitch",
                            "channel_id=%u value=%u",
                            session->audio_output_channel_id,
                            setting.value);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_QUALITYMODE)
    {
        uint16_t quality_mode = 0;

        status = rdp_audio_output_parse_quality_mode(data, data_len, &quality_mode);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.quality_mode",
                            "channel_id=%u quality_mode=%u",
                            session->audio_output_channel_id,
                            quality_mode);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVECONFIRM)
    {
        uint16_t timestamp = 0;
        uint8_t block_no = 0;

        status = rdp_audio_output_parse_wave_confirm(data, data_len, &timestamp, &block_no);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.rdpsnd.wave_confirm",
                                  "channel_id=%u timestamp=%u block_no=%u",
                                  session->audio_output_channel_id,
                                  timestamp,
                                  block_no);
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_CRYPTKEY)
    {
        rdp_audio_output_crypt_key crypt_key;

        status = rdp_audio_output_parse_crypt_key(data, data_len, &crypt_key);
        if (status == LIBRDP_STATUS_OK)
        {
            if (crypt_key.seed_len == sizeof(session->audio_output_crypt_seed))
            {
                memcpy(session->audio_output_crypt_seed, crypt_key.seed, sizeof(session->audio_output_crypt_seed));
                session->audio_output_crypt_seed_valid = 1;
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpsnd.crypt_key",
                            "channel_id=%u seed_len=%u stored=%u",
                            session->audio_output_channel_id,
                            (unsigned)crypt_key.seed_len,
                            session->audio_output_crypt_seed_valid ? 1u : 0u);
        }
    }
    else if (header.msg_type == RDP_AUDIO_OUTPUT_WAVEENCRYPT)
    {
        status = rdp_session_handle_audio_output_wave_encrypt(session, data, data_len, 0);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpsnd.pdu",
                              "channel_id=%u type=%u body_size=%u",
                              session->audio_output_channel_id,
                              header.msg_type,
                              header.body_size);
    }
    return status;
}

/*
 * Handle audio-output UDP datagrams associated with the current playback
 * stream. Sequence and payload checks prevent stale datagrams from being mixed
 * into the active audio buffer.
 */
librdp_status rdp_session_handle_audio_output_udp_datagram(librdp_session* session)
{
    uint8_t packet[65536];
    struct sockaddr_storage peer;
    socklen_t peer_len = 0;
    ssize_t got = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->audio_output_udp_fd < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&peer, 0, sizeof(peer));
    peer_len = (socklen_t)sizeof(peer);
    do
    {
        got = recvfrom(session->audio_output_udp_fd,
                       packet,
                       sizeof(packet),
                       0,
                       (struct sockaddr*)&peer,
                       &peer_len);
    } while (got < 0 && errno == EINTR);
    if (got < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
    if (got == 0)
        return LIBRDP_STATUS_OK;

    session->audio_output_udp_peer = peer;
    session->audio_output_udp_peer_len = peer_len;
    session->audio_output_udp_peer_valid = 1;
    rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "transport.udp.read.done",
                          "component=rdpsnd bytes=%u",
                          (unsigned)got);

    if (packet[0] == RDP_AUDIO_OUTPUT_UDPWAVE)
    {
        status = rdp_session_handle_audio_output_udp_wave(session, packet, (size_t)got);
    }
    else if (packet[0] == RDP_AUDIO_OUTPUT_UDPWAVELAST)
    {
        status = rdp_session_handle_audio_output_udp_wave_last(session, packet, (size_t)got, 1);
    }
    else
    {
        rdp_audio_output_header header;

        status = rdp_audio_output_parse_header(packet, (size_t)got, &header);
        if (status == LIBRDP_STATUS_OK && header.msg_type == RDP_AUDIO_OUTPUT_TRAINING)
        {
            rdp_audio_output_training training;
            rdp_buffer confirm;

            rdp_buffer_init(&confirm);
            status = rdp_audio_output_parse_training(packet, (size_t)got, &training);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_audio_output_write_training_confirm(&confirm,
                                                                 training.timestamp,
                                                                 training.packet_size);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_audio_output_udp_payload(session,
                                                                   confirm.data,
                                                                   confirm.length,
                                                                   "client.rdpsnd.training_confirm");
            rdp_buffer_free(&confirm);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rdpsnd.training",
                                "channel_id=%u timestamp=%u packet_size=%u data_len=%u use_udp=1",
                                session->audio_output_channel_id,
                                training.timestamp,
                                training.packet_size,
                                (unsigned)training.data_len);
        }
        else if (status == LIBRDP_STATUS_OK && header.msg_type == RDP_AUDIO_OUTPUT_WAVEENCRYPT)
        {
            status = rdp_session_handle_audio_output_wave_encrypt(session, packet, (size_t)got, 1);
        }
        else
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.rdpsnd.udp_pdu",
                                  "status=%s bytes=%u",
                                  librdp_status_string(status),
                                  (unsigned)got);
            status = LIBRDP_STATUS_OK;
        }
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpsnd.udp_pdu.failed",
                        "status=%s bytes=%u",
                        librdp_status_string(status),
                        (unsigned)got);
        status = LIBRDP_STATUS_OK;
    }
    return status;
}


static librdp_status rdp_session_require_audio_input_channel(const librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->audio_input_channel_id == 0 || session->audio_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_audio_input_open_reply(librdp_session* session, uint32_t result)
{
    rdp_buffer reply;
    librdp_status status = rdp_session_require_owner(session, "client.audio_input.open_reply.owner");

    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_require_audio_input_channel(session);
    rdp_buffer_init(&reply);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_open_reply(&reply, result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &reply, "client.audin.open_reply");
    rdp_buffer_free(&reply);
    if (status == LIBRDP_STATUS_OK)
    {
        session->audio_input_open_reply_sent = 1;
        session->audio_input_open = result == RDP_AUDIO_INPUT_RESULT_OK ? 1u : 0u;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.open_reply",
                        "dvc_channel_id=%u result=%u",
                        session->audio_input_channel_id,
                        result);
    }
    return status;
}

librdp_status librdp_session_audio_input_send_data(librdp_session* session, const void* data, size_t data_len)
{
    rdp_buffer pdu;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.audio_input.data.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session && data_len > session->limits.dynamic_channel_message_bytes)
        return rdp_session_limit_rejected(session);
    status = rdp_session_require_audio_input_channel(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->audio_input_ready || !session->audio_input_open)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&pdu);
    status = rdp_session_send_audio_input_incoming(session);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_input_write_data(&pdu, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &pdu, "client.audin.data");
    rdp_buffer_free(&pdu);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.data",
                        "dvc_channel_id=%u data_len=%u",
                        session->audio_input_channel_id,
                        (unsigned)data_len);
    return status;
}

librdp_status librdp_session_audio_input_send_format_change(librdp_session* session, uint32_t new_format)
{
    rdp_buffer pdu;
    librdp_status status = rdp_session_require_owner(session, "client.audio_input.format.owner");

    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_require_audio_input_channel(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->audio_input_ready)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&pdu);
    status = rdp_audio_input_write_format_change(&pdu, new_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_audio_input_packet(session, &pdu, "client.audin.format_change");
    rdp_buffer_free(&pdu);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.audin.format_change_send",
                        "dvc_channel_id=%u new_format=%u",
                        session->audio_input_channel_id,
                        new_format);
    return status;
}
