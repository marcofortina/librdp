/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client session orchestration across transport, security,
 * capabilities, graphics, input, and channels.
 * Invariants: session state transitions happen in protocol order and callbacks
 * never receive invalid surfaces or channels.
 * Ownership: session-owned caches, channels, surfaces, and credentials change
 * only through the session thread.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include <librdp/session.h>
#include <librdp/video.h>

#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/pnp_redirection.h"
#include "channels/port_redirection.h"
#include "channels/printer_redirection.h"
#include "channels/remote_programs.h"
#include "channels/smartcard_redirection.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/virtual_channel.h"
#include "channels/webauthn_channel.h"
#include "client/error_internal.h"
#include "client/printer_backend.h"
#include "client/settings_internal.h"
#include "client/session_internal.h"
#include "client/usb_backend.h"
#include "client/webauthn_backend.h"
#include "clipboard/clipboard.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "graphics/avc.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/gdi_orders.h"
#include "graphics/gdi_render.h"
#include "graphics/nscodec.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "graphics/rfx_stream.h"
#include "graphics/surface_commands.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "platform/socket.h"
#include "protocol/bulk.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/transport.h"
#include "input/input.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
#include <sys/xattr.h>
#endif
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef RDP_HAVE_WINPR_SMARTCARD
#include <winpr/smartcard.h>
#elif defined(RDP_HAVE_PCSC)
#include <winscard.h>
#endif
#include "client/smartcard_backend.h"
#ifdef RDP_HAVE_LIBUSB
#include <libusb-1.0/libusb.h>
#endif

static void rdp_session_composited_reset(librdp_session* session)
{
    if (!session)
        return;
    session->composited_channel_id = 0;
    session->composited_channel_id_bytes = 0;
    session->composited_ready = 0;
    session->composited_connection_open = 0;
    session->composited_connection_id = 0;
    session->composited_open_channel_id = 0;
    rdp_composited_render_tree_reset(&session->composited_tree);
}

static void rdp_session_video_redirection_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_redirection_channel_id = 0;
    session->video_redirection_channel_id_bytes = 0;
    session->video_redirection_ready = 0;
    session->video_redirection_capabilities_sent = 0;
    session->video_redirection_rim_sent = 0;
    memset(session->video_streams, 0, sizeof(session->video_streams));
}

static void rdp_session_video_optimized_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_optimized_control_channel_id = 0;
    session->video_optimized_control_channel_id_bytes = 0;
    session->video_optimized_control_ready = 0;
    session->video_optimized_data_channel_id = 0;
    session->video_optimized_data_channel_id_bytes = 0;
    memset(session->video_optimized_presentations, 0, sizeof(session->video_optimized_presentations));
}

static rdp_session_video_optimized_presentation* rdp_session_video_optimized_find(librdp_session* session,
                                                                                  uint8_t presentation_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (session->video_optimized_presentations[i].active &&
            session->video_optimized_presentations[i].presentation_id == presentation_id)
            return &session->video_optimized_presentations[i];
    }
    return NULL;
}

static rdp_session_video_optimized_presentation* rdp_session_video_optimized_upsert(librdp_session* session,
                                                                                    uint8_t presentation_id)
{
    size_t i = 0;
    rdp_session_video_optimized_presentation* entry = rdp_session_video_optimized_find(session, presentation_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (!session->video_optimized_presentations[i].active)
        {
            memset(&session->video_optimized_presentations[i], 0, sizeof(session->video_optimized_presentations[i]));
            session->video_optimized_presentations[i].active = 1;
            session->video_optimized_presentations[i].presentation_id = presentation_id;
            return &session->video_optimized_presentations[i];
        }
    }
    return NULL;
}

static int rdp_session_video_optimized_sample_sequence_valid(
    const rdp_session_video_optimized_presentation* presentation,
    const rdp_video_optimized_video_data* video)
{
    if (!presentation || !video)
        return 0;
    if (presentation->last_sample_number == 0)
        return video->current_packet_index == 1u;
    if (video->sample_number < presentation->last_sample_number)
        return 0;
    if (video->sample_number == presentation->last_sample_number)
    {
        return video->packets_in_sample == presentation->last_packets_in_sample &&
               video->current_packet_index > presentation->last_packet_index;
    }
    return video->current_packet_index == 1u;
}

static void rdp_session_video_optimized_remove(librdp_session* session, uint8_t presentation_id)
{
    rdp_session_video_optimized_presentation* entry = rdp_session_video_optimized_find(session, presentation_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static void rdp_session_video_capture_reset(librdp_session* session)
{
    if (!session)
        return;
    session->video_capture_control_channel_id = 0;
    session->video_capture_control_channel_id_bytes = 0;
    session->video_capture_channel_id = 0;
    session->video_capture_channel_id_bytes = 0;
    session->video_capture_version = 0;
    session->video_capture_active = 0;
    session->video_capture_streaming = 0;
    session->video_capture_selected_stream = 0;
    session->video_capture_sample_reply_pending = 0;
    memset(&session->video_capture_media, 0, sizeof(session->video_capture_media));
    session->video_capture_brightness_mode = RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL;
    session->video_capture_brightness = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
}

static void rdp_session_auth_redirection_channel_reset(librdp_session* session)
{
    if (!session)
        return;
    session->auth_redirection_channel_id = 0;
    session->auth_redirection_channel_id_bytes = 0;
    session->auth_redirection_ready = 0;
}

static void rdp_session_webauthn_channel_reset(librdp_session* session)
{
    if (!session)
        return;
    session->webauthn_channel_id = 0;
    session->webauthn_channel_id_bytes = 0;
    session->webauthn_ready = 0;
}

static void rdp_session_credssp_security_reset(librdp_session* session)
{
    if (!session)
        return;
    OPENSSL_cleanse(&session->credssp_security, sizeof(session->credssp_security));
    session->credssp_security_ready = 0;
}

static rdp_session_video_stream* rdp_session_video_stream_find(librdp_session* session,
                                                               const uint8_t presentation_id[16],
                                                               uint32_t stream_id)
{
    uint32_t i = 0;

    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active &&
            session->video_streams[i].stream_id == stream_id &&
            memcmp(session->video_streams[i].presentation_id, presentation_id, 16u) == 0)
            return &session->video_streams[i];
    }
    return NULL;
}

static rdp_session_video_stream* rdp_session_video_stream_upsert(librdp_session* session,
                                                                 const uint8_t presentation_id[16],
                                                                 uint32_t stream_id)
{
    uint32_t i = 0;
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        return entry;
    if (!session || !presentation_id)
        return NULL;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (!session->video_streams[i].active)
        {
            memset(&session->video_streams[i], 0, sizeof(session->video_streams[i]));
            session->video_streams[i].active = 1;
            session->video_streams[i].stream_id = stream_id;
            memcpy(session->video_streams[i].presentation_id, presentation_id, 16u);
            return &session->video_streams[i];
        }
    }
    return NULL;
}

static void rdp_session_video_stream_remove(librdp_session* session,
                                            const uint8_t presentation_id[16],
                                            uint32_t stream_id)
{
    rdp_session_video_stream* entry = rdp_session_video_stream_find(session, presentation_id, stream_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

static uint32_t rdp_session_video_presentation_update(librdp_session* session,
                                                      const uint8_t presentation_id[16],
                                                      uint8_t set_paused,
                                                      uint8_t paused,
                                                      uint8_t increment_preroll,
                                                      uint32_t rate_bits)
{
    uint32_t i = 0;
    uint32_t matched = 0;

    if (!session || !presentation_id)
        return 0;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        rdp_session_video_stream* entry = &session->video_streams[i];

        if (!entry->active || memcmp(entry->presentation_id, presentation_id, 16u) != 0)
            continue;
        if (set_paused)
            entry->paused = paused;
        if (increment_preroll)
            entry->preroll_count++;
        if (rate_bits != UINT32_MAX)
            entry->playback_rate_bits = rate_bits;
        matched++;
    }
    return matched;
}

static uint32_t rdp_session_video_presentation_remove(librdp_session* session,
                                                      const uint8_t presentation_id[16])
{
    uint32_t i = 0;
    uint32_t removed = 0;

    if (!session || !presentation_id)
        return 0;
    for (i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active &&
            memcmp(session->video_streams[i].presentation_id, presentation_id, 16u) == 0)
        {
            memset(&session->video_streams[i], 0, sizeof(session->video_streams[i]));
            removed++;
        }
    }
    return removed;
}

static rdp_trace_sensitivity rdp_session_trace_sensitivity_for_event(const char* event);

static librdp_status rdp_session_write_mcs_pdu(librdp_session* session,
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

static librdp_status rdp_session_write_license_pdu(librdp_session* session,
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

static uint32_t rdp_session_pixels_to_mm(uint16_t pixels)
{
    uint32_t mm = ((uint32_t)pixels * 254u + 480u) / 960u;

    if (mm < 10u)
        return 10u;
    if (mm > 10000u)
        return 10000u;
    return mm;
}

/*
 * GCC channel advertisement is stricter than a requested feature bit. A client
 * must only ask the server for channels whose host-side backend is already
 * configured and whose implementation is not parser-only.
 */
uint8_t rdp_session_feature_ready_for_negotiation(const librdp_session* session, librdp_feature feature)
{
    librdp_feature_status status;

    if (!session || !session->settings)
        return 0;
    memset(&status, 0, sizeof(status));
    if (librdp_settings_get_feature_status(session->settings, feature, &status) != LIBRDP_STATUS_OK)
        return 0;
    return (status.requested && status.backend_ready &&
            status.reason != LIBRDP_FEATURE_REASON_PARSER_ONLY) ?
               1u :
               0u;
}

static uint8_t rdp_session_device_redirection_ready_for_negotiation(const librdp_session* session)
{
    if (!session || !session->settings)
        return 0;
    if (librdp_settings_drive_count(session->settings) > 0 ||
        librdp_settings_serial_port_count(session->settings) > 0 ||
        librdp_settings_parallel_port_count(session->settings) > 0 ||
        librdp_settings_printer_count(session->settings) > 0)
    {
        return 1;
    }
    if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_SMARTCARD) ||
        rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_USB))
    {
        return 1;
    }
    return 0;
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

static rdp_session_graphics_surface* rdp_session_graphics_surface_find(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < session->limits.surface_count; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
    }
    return NULL;
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find_slot(librdp_session* session,
                                                                            uint16_t surface_id)
{
    size_t i = 0;
    rdp_session_graphics_surface* free_slot = NULL;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
        if (!session->graphics_surfaces[i].active && !free_slot)
            free_slot = &session->graphics_surfaces[i];
    }
    return free_slot;
}

static void rdp_session_progressive_tiles_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        free(session->progressive_tiles[i].state);
        free(session->progressive_tiles[i].pixels);
        session->progressive_tiles[i].state = NULL;
        session->progressive_tiles[i].pixels = NULL;
    }
    memset(session->progressive_tiles, 0, sizeof(session->progressive_tiles));
    session->progressive_tile_clock = 0;
}

static void rdp_session_progressive_tiles_clear_surface(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id)
        {
            free(entry->state);
            free(entry->pixels);
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_find(librdp_session* session,
                                                                             uint16_t surface_id,
                                                                             uint16_t x_idx,
                                                                             uint16_t y_idx)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id &&
            entry->x_idx == x_idx && entry->y_idx == y_idx)
            return entry;
    }
    return NULL;
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_get(librdp_session* session,
                                                                            uint16_t surface_id,
                                                                            uint16_t x_idx,
                                                                            uint16_t y_idx,
                                                                            int create)
{
    size_t i = 0;
    rdp_session_progressive_tile_cache* entry = NULL;
    rdp_session_progressive_tile_cache* victim = NULL;
    size_t victim_slot = 0;
    int evicting = 0;
    uint16_t old_surface_id = 0;
    uint16_t old_x_idx = 0;
    uint16_t old_y_idx = 0;
    uint32_t old_valid = 0;
    uint32_t old_pass = 0;

    if (!session)
        return NULL;
    entry = rdp_session_progressive_tile_find(session, surface_id, x_idx, y_idx);
    if (entry)
    {
        entry->last_used = ++session->progressive_tile_clock;
        return entry;
    }
    if (!create)
        return NULL;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* candidate = &session->progressive_tiles[i];

        if (!candidate->active)
        {
            victim = candidate;
            break;
        }
        if (!victim || candidate->last_used < victim->last_used)
            victim = candidate;
    }
    if (!victim)
        return NULL;
    victim_slot = (size_t)(victim - session->progressive_tiles);
    evicting = victim->active != 0;
    if (evicting)
    {
        old_surface_id = victim->surface_id;
        old_x_idx = victim->x_idx;
        old_y_idx = victim->y_idx;
        old_valid = victim->state ? victim->state->valid : 0u;
        old_pass = victim->state ? victim->state->pass : 0u;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.tile_state.evict",
                              "slot=%u old_surface_id=%u old_x_idx=%u old_y_idx=%u old_valid=%u old_pass=%u old_frame_id=%u new_surface_id=%u new_x_idx=%u new_y_idx=%u",
                              (unsigned)victim_slot,
                              old_surface_id,
                              old_x_idx,
                              old_y_idx,
                              old_valid,
                              old_pass,
                              victim->updated_frame_id,
                              surface_id,
                              x_idx,
                              y_idx);
    }
    if (!victim->state)
    {
        victim->state = (rdp_rfx_progressive_tile_state*)calloc(1, sizeof(*victim->state));
        if (!victim->state)
            return NULL;
    }
    if (!victim->pixels)
    {
        victim->pixels = (rdp_rfx_tile_pixels*)calloc(1, sizeof(*victim->pixels));
        if (!victim->pixels)
            return NULL;
    }
    else
    {
        memset(victim->pixels, 0, sizeof(*victim->pixels));
    }
    if (victim->state)
    {
        memset(victim->state, 0, sizeof(*victim->state));
    }
    victim->active = 1;
    victim->surface_id = surface_id;
    victim->x_idx = x_idx;
    victim->y_idx = y_idx;
    victim->has_pixels = 0;
    victim->updated_frame_id = 0;
    victim->last_used = ++session->progressive_tile_clock;
    victim->state->x_idx = x_idx;
    victim->state->y_idx = y_idx;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile_state.alloc",
                          "slot=%u surface_id=%u x_idx=%u y_idx=%u evicted=%u",
                          (unsigned)victim_slot,
                          surface_id,
                          x_idx,
                          y_idx,
                          (unsigned)evicting);
    return victim;
}

static void rdp_session_graphics_surfaces_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    rdp_session_progressive_tiles_clear(session);
    rdp_avc_decoder_reset(session->avc);
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
        rdp_buffer_free(&session->graphics_surfaces[i].pixels);
    memset(session->graphics_surfaces, 0, sizeof(session->graphics_surfaces));
}

static librdp_status rdp_session_graphics_surface_create(librdp_session* session,
                                                         const rdp_graphics_create_surface* create)
{
    rdp_session_graphics_surface* surface = NULL;
    size_t stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !create)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (create->width == 0 || create->height == 0 ||
        create->width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        create->height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (create->width > session->limits.surface_max_dimension ||
        create->height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);

    stride = (size_t)create->width * 4u;
    if ((size_t)create->height > ((size_t)-1) / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = stride * (size_t)create->height;

    surface = rdp_session_graphics_surface_find_slot(session, create->surface_id);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;

    if (surface->active)
        rdp_session_progressive_tiles_clear_surface(session, create->surface_id);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
    status = rdp_buffer_reserve(&surface->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(surface->pixels.data, 0, size);
    surface->pixels.length = size;
    surface->active = 1;
    surface->surface_id = create->surface_id;
    surface->width = create->width;
    surface->height = create->height;
    surface->target_width = create->width;
    surface->target_height = create->height;
    surface->pixel_format = create->pixel_format;
    {
        librdp_rect rect;

        rect.x = 0;
        rect.y = 0;
        rect.width = create->width;
        rect.height = create->height;
        rdp_session_emit_graphics_update(session,
                                         LIBRDP_GRAPHICS_UPDATE_SURFACE_CREATE,
                                         create->surface_id,
                                         session->graphics_current_frame_id,
                                         &rect,
                                         LIBRDP_PIXEL_FORMAT_BGRA32,
                                         NULL,
                                         0);
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_surface_delete(librdp_session* session, uint16_t surface_id)
{
    rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, surface_id);
    librdp_rect rect;

    if (!surface)
        return;
    rect.x = 0;
    rect.y = 0;
    rect.width = surface->width;
    rect.height = surface->height;
    rdp_session_emit_graphics_update(session,
                                     LIBRDP_GRAPHICS_UPDATE_SURFACE_DESTROY,
                                     surface_id,
                                     session->graphics_current_frame_id,
                                     &rect,
                                     LIBRDP_PIXEL_FORMAT_BGRA32,
                                     NULL,
                                     0);
    rdp_session_progressive_tiles_clear_surface(session, surface_id);
    rdp_avc_decoder_reset(session->avc);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride);
static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height);

/*
 * Flush a graphics surface into the primary framebuffer with scaling. Source
 * and destination rectangles are clipped together so partial monitor layouts
 * cannot read outside cached surfaces.
 */
static librdp_status rdp_session_graphics_surface_flush_scaled(librdp_session* session,
                                                               rdp_session_graphics_surface* surface,
                                                               uint16_t left,
                                                               uint16_t top,
                                                               uint16_t right,
                                                               uint16_t bottom,
                                                               const char* source)
{
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    uint64_t rel_left = 0;
    uint64_t rel_top = 0;
    uint64_t rel_right = 0;
    uint64_t rel_bottom = 0;
    uint64_t abs_left = 0;
    uint64_t abs_top = 0;
    uint64_t abs_right = 0;
    uint64_t abs_bottom = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    size_t scaled_stride = 0;
    size_t scaled_len = 0;
    uint32_t y = 0;
    rdp_buffer scaled;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface->target_width == 0 || surface->target_height == 0 ||
        surface->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        surface->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface->target_width > session->limits.surface_max_dimension ||
        surface->target_height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    rel_left = ((uint64_t)left * surface->target_width) / surface->width;
    rel_top = ((uint64_t)top * surface->target_height) / surface->height;
    rel_right = (((uint64_t)right * surface->target_width) + surface->width - 1u) / surface->width;
    rel_bottom = (((uint64_t)bottom * surface->target_height) + surface->height - 1u) / surface->height;
    if (rel_right <= rel_left || rel_bottom <= rel_top)
        return LIBRDP_STATUS_OK;

    abs_left = (uint64_t)surface->output_origin_x + rel_left;
    abs_top = (uint64_t)surface->output_origin_y + rel_top;
    abs_right = (uint64_t)surface->output_origin_x + rel_right;
    abs_bottom = (uint64_t)surface->output_origin_y + rel_bottom;
    if (abs_left >= output_width || abs_top >= output_height || abs_right <= abs_left || abs_bottom <= abs_top)
        return LIBRDP_STATUS_OK;
    if (abs_right > output_width)
        abs_right = output_width;
    if (abs_bottom > output_height)
        abs_bottom = output_height;
    dst_x = (uint32_t)abs_left;
    dst_y = (uint32_t)abs_top;
    width = (uint32_t)(abs_right - abs_left);
    height = (uint32_t)(abs_bottom - abs_top);
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    scaled_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / scaled_stride)
        return LIBRDP_STATUS_NO_MEMORY;
    scaled_len = scaled_stride * height;
    rdp_buffer_init(&scaled);
    status = rdp_buffer_reserve(&scaled, scaled_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    scaled.length = scaled_len;

    stride = (size_t)surface->width * 4u;
    for (y = 0; y < height; y++)
    {
        uint64_t rel_y = ((uint64_t)dst_y + y) - surface->output_origin_y;
        uint32_t src_y = (uint32_t)((rel_y * surface->height) / surface->target_height);
        uint8_t* dst = scaled.data + ((size_t)y * scaled_stride);
        uint32_t x = 0;

        if (src_y >= surface->height)
            src_y = surface->height - 1u;
        for (x = 0; x < width; x++)
        {
            uint64_t rel_x = ((uint64_t)dst_x + x) - surface->output_origin_x;
            uint32_t src_x = (uint32_t)((rel_x * surface->width) / surface->target_width);
            const uint8_t* src = NULL;

            if (src_x >= surface->width)
                src_x = surface->width - 1u;
            src = surface->pixels.data + ((size_t)src_y * stride) + ((size_t)src_x * 4u);
            memcpy(dst + ((size_t)x * 4u), src, 4u);
        }
    }

    status = librdp_surface_blit_bgra32(session->surface,
                                        dst_x,
                                        dst_y,
                                        width,
                                        height,
                                        scaled.data,
                                        scaled_stride);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush_scaled",
                              "source=%s surface_id=%u src_x=%u src_y=%u src_width=%u src_height=%u dst_x=%u dst_y=%u dst_width=%u dst_height=%u surface_width=%u surface_height=%u target_width=%u target_height=%u frame_id=%u scaled_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              (uint32_t)(right - left),
                              (uint32_t)(bottom - top),
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              surface->target_width,
                              surface->target_height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(scaled.data,
                                                                               width,
                                                                               height,
                                                                               scaled_stride));
    }
    rdp_buffer_free(&scaled);
    return status;
}

/*
 * Flush a graphics surface into the primary framebuffer without scaling. Dirty
 * tracking is updated only after clipped blits have reached the session
 * surface.
 */
static librdp_status rdp_session_graphics_surface_flush(librdp_session* session,
                                                        rdp_session_graphics_surface* surface,
                                                        uint16_t left,
                                                        uint16_t top,
                                                        uint16_t right,
                                                        uint16_t bottom,
                                                        const char* source)
{
    uint64_t dst_x64 = 0;
    uint64_t dst_y64 = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    size_t stride = 0;
    size_t output_stride = 0;
    const uint8_t* pixels = NULL;
    const uint8_t* output_pixels = NULL;
    uint64_t source_hash = 0;
    uint64_t output_hash = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!surface->mapped || left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (right > surface->width || bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface->scaled)
        return rdp_session_graphics_surface_flush_scaled(session,
                                                         surface,
                                                         left,
                                                         top,
                                                         right,
                                                         bottom,
                                                         source);

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    dst_x64 = (uint64_t)surface->output_origin_x + left;
    dst_y64 = (uint64_t)surface->output_origin_y + top;
    if (dst_x64 >= output_width || dst_y64 >= output_height)
        return LIBRDP_STATUS_OK;
    dst_x = (uint32_t)dst_x64;
    dst_y = (uint32_t)dst_y64;
    width = (uint32_t)(right - left);
    height = (uint32_t)(bottom - top);
    if (width > output_width - dst_x)
        width = output_width - dst_x;
    if (height > output_height - dst_y)
        height = output_height - dst_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)top * stride) + ((size_t)left * 4u);
    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    status = librdp_surface_blit_bgra32(session->surface, dst_x, dst_y, width, height, pixels, stride);
    if (status == LIBRDP_STATUS_OK)
    {
        output_stride = librdp_surface_stride(session->surface);
        output_pixels = librdp_surface_pixels(session->surface);
        if (output_pixels)
        {
            output_hash = rdp_session_trace_hash_bgra(output_pixels + ((size_t)dst_y * output_stride) +
                                                          ((size_t)dst_x * 4u),
                                                      width,
                                                      height,
                                                      output_stride);
        }
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.flush",
                              "source=%s surface_id=%u src_x=%u src_y=%u dst_x=%u dst_y=%u width=%u height=%u surface_width=%u surface_height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u source_hash=%016llx output_hash=%016llx",
                              source ? source : "unknown",
                              surface->surface_id,
                              left,
                              top,
                              dst_x,
                              dst_y,
                              width,
                              height,
                              surface->width,
                              surface->height,
                              output_width,
                              output_height,
                              session->graphics_current_frame_id,
                              session->graphics_frame_active ? 1u : 0u,
                              (unsigned long long)source_hash,
                              (unsigned long long)output_hash);
    }
    return status;
}

static librdp_status rdp_session_graphics_surface_map(librdp_session* session,
                                                      const rdp_graphics_map_surface_to_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = surface->width;
    surface->target_height = surface->height;
    surface->scaled = 0;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_map_scaled(
    librdp_session* session,
    const rdp_graphics_map_surface_to_scaled_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (map->target_width == 0 || map->target_height == 0 ||
        map->target_width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        map->target_height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (map->target_width > session->limits.surface_max_dimension ||
        map->target_height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    surface->target_width = map->target_width;
    surface->target_height = map->target_height;
    surface->scaled = map->target_width != surface->width || map->target_height != surface->height;
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              0,
                                              0,
                                              surface->width,
                                              surface->height,
                                              surface->scaled ? "map_scaled_output" : "map_output");
}

static librdp_status rdp_session_graphics_surface_fill(librdp_session* session,
                                                       rdp_session_graphics_surface* surface,
                                                       const rdp_graphics_rect16* rect,
                                                       uint32_t fill_pixel)
{
    uint8_t b = (uint8_t)(fill_pixel & 0xffu);
    uint8_t g = (uint8_t)((fill_pixel >> 8) & 0xffu);
    uint8_t r = (uint8_t)((fill_pixel >> 16) & 0xffu);
    uint8_t a = 0xffu;
    size_t stride = 0;
    uint16_t y = 0;

    if (!session || !surface || !rect || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > surface->width || rect->bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_OK;
    if (surface->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888)
        a = (uint8_t)((fill_pixel >> 24) & 0xffu);

    stride = (size_t)surface->width * 4u;
    for (y = rect->top; y < rect->bottom; y++)
    {
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)rect->left * 4u);
        uint16_t x = 0;

        for (x = rect->left; x < rect->right; x++)
        {
            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = a;
            pixel += 4;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.fill.rect",
                          "source=solid_fill surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u fill_pixel=%08x frame_id=%u dest_hash=%016llx",
                          surface->surface_id,
                          rect->left,
                          rect->top,
                          (unsigned)(rect->right - rect->left),
                          (unsigned)(rect->bottom - rect->top),
                          surface->width,
                          surface->height,
                          fill_pixel,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              rect->left,
                                                                              rect->top,
                                                                              (uint32_t)(rect->right - rect->left),
                                                                              (uint32_t)(rect->bottom - rect->top)));
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              rect->left,
                                              rect->top,
                                              rect->right,
                                              rect->bottom,
                                              "solid_fill");
}

static librdp_status rdp_session_graphics_surface_write_bgra(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             uint16_t x,
                                                             uint16_t y,
                                                             uint16_t width,
                                                             uint16_t height,
                                                             const uint8_t* pixels,
                                                             size_t stride,
                                                             int force_opaque,
                                                             const char* source)
{
    uint16_t row = 0;
    size_t dest_stride = 0;
    uint64_t source_hash = 0;
    uint64_t dest_hash = 0;

    if (!session || !surface || !surface->active || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (x > surface->width || y > surface->height ||
        width > surface->width - x || height > surface->height - y ||
        stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    dest_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        uint8_t* dest = surface->pixels.data + ((size_t)(y + row) * dest_stride) + ((size_t)x * 4u);
        const uint8_t* source = pixels + ((size_t)row * stride);

        memcpy(dest, source, (size_t)width * 4u);
        if (force_opaque)
        {
            uint16_t column = 0;

            for (column = 0; column < width; column++)
                dest[((size_t)column * 4u) + 3u] = 0xffu;
        }
    }
    dest_hash = rdp_session_trace_surface_hash(surface, x, y, width, height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.surface.write",
                          "source=%s surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u stride=%u dest_stride=%u force_opaque=%u frame_id=%u source_hash=%016llx dest_hash=%016llx",
                          source ? source : "unknown",
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          surface->width,
                          surface->height,
                          (unsigned)stride,
                          (unsigned)dest_stride,
                          force_opaque ? 1u : 0u,
                          session->graphics_current_frame_id,
                          (unsigned long long)source_hash,
                          (unsigned long long)dest_hash);
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              x,
                                              y,
                                              (uint16_t)(x + width),
                                              (uint16_t)(y + height),
                                              source);
}

static librdp_status rdp_session_graphics_surface_write_avc_regions(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_avc420_metablock* meta,
    const rdp_avc_frame* frame,
    int force_opaque,
    const char* source)
{
    uint32_t i = 0;

    if (!session || !surface || !meta || !frame || !frame->pixels.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (frame->stride < (size_t)frame->width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < meta->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint16_t width = 0;
        uint16_t height = 0;
        const uint8_t* pixels = NULL;
        librdp_status status = LIBRDP_STATUS_OK;

        if (meta->rects_len < ((size_t)i + 1u) * 8u ||
            rdp_graphics_parse_rect16(meta->rects + ((size_t)i * 8u), 8u, &rect) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rect.left >= rect.right || rect.top >= rect.bottom ||
            rect.right > surface->width || rect.bottom > surface->height ||
            rect.right > frame->width || rect.bottom > frame->height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        width = (uint16_t)(rect.right - rect.left);
        height = (uint16_t)(rect.bottom - rect.top);
        pixels = frame->pixels.data + ((size_t)rect.top * frame->stride) + ((size_t)rect.left * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         rect.left,
                                                         rect.top,
                                                         width,
                                                         height,
                                                         pixels,
                                                         frame->stride,
                                                         force_opaque,
                                                         source);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_write_wire(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t width = 0;
    uint16_t height = 0;
    size_t expected = 0;

    if (!session || !surface || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.right < wire->dest_rect.left || wire->dest_rect.bottom < wire->dest_rect.top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    expected = (size_t)width * (size_t)height * 4u;
    if (wire->bitmap_data_length != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_session_graphics_surface_write_bgra(session,
                                                   surface,
                                                   wire->dest_rect.left,
                                                   wire->dest_rect.top,
                                                   width,
                                                   height,
                                                   wire->bitmap_data,
                                                   (size_t)width * 4u,
                                                   wire->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                   "uncompressed");
}

static librdp_status rdp_session_graphics_surface_alpha_run(rdp_session_graphics_surface* surface,
                                                            uint16_t left,
                                                            uint16_t top,
                                                            uint16_t width,
                                                            uint32_t* position,
                                                            uint32_t total,
                                                            uint32_t count,
                                                            uint8_t alpha)
{
    uint32_t i = 0;
    size_t stride = 0;

    if (!surface || !position || count == 0 || count > total - *position)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stride = (size_t)surface->width * 4u;
    for (i = 0; i < count; i++)
    {
        uint32_t index = *position + i;
        uint32_t x = (uint32_t)left + (index % width);
        uint32_t y = (uint32_t)top + (index / width);
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);

        pixel[3] = alpha;
    }
    *position += count;
    return LIBRDP_STATUS_OK;
}

/*
 * Apply alpha composition for a graphics surface update. The routine keeps
 * source pixels, destination clips, and blend mode validation together before
 * mutating the visible framebuffer.
 */
static librdp_status rdp_session_graphics_surface_apply_alpha(librdp_session* session,
                                                              rdp_session_graphics_surface* surface,
                                                              const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t left = 0;
    uint16_t top = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t signature = 0;
    uint16_t compressed = 0;
    uint32_t total = 0;
    uint32_t position = 0;
    size_t offset = 4u;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !wire || !wire->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.left >= wire->dest_rect.right ||
        wire->dest_rect.top >= wire->dest_rect.bottom ||
        wire->dest_rect.right > surface->width ||
        wire->dest_rect.bottom > surface->height ||
        wire->bitmap_data_length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    left = wire->dest_rect.left;
    top = wire->dest_rect.top;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    if ((uint32_t)width > UINT32_MAX / (uint32_t)height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = (uint32_t)width * (uint32_t)height;
    signature = (uint16_t)(wire->bitmap_data[0] | ((uint16_t)wire->bitmap_data[1] << 8u));
    compressed = (uint16_t)(wire->bitmap_data[2] | ((uint16_t)wire->bitmap_data[3] << 8u));
    if (signature != 0x414cu)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (compressed == 0)
    {
        if (wire->bitmap_data_length - offset != total)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < total; i++)
        {
            status = rdp_session_graphics_surface_alpha_run(surface,
                                                            left,
                                                            top,
                                                            width,
                                                            &position,
                                                            total,
                                                            1,
                                                            wire->bitmap_data[offset + i]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    else
    {
        while (position < total)
        {
            uint8_t alpha = 0;
            uint32_t count = 0;

            if (wire->bitmap_data_length - offset < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            alpha = wire->bitmap_data[offset++];
            count = wire->bitmap_data[offset++];
            if (count >= 0xffu)
            {
                if (wire->bitmap_data_length - offset < 2u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                count = (uint32_t)wire->bitmap_data[offset] |
                        ((uint32_t)wire->bitmap_data[offset + 1u] << 8u);
                offset += 2u;
                if (count >= 0xffffu)
                {
                    if (wire->bitmap_data_length - offset < 4u)
                        return LIBRDP_STATUS_PROTOCOL_ERROR;
                    count = (uint32_t)wire->bitmap_data[offset] |
                            ((uint32_t)wire->bitmap_data[offset + 1u] << 8u) |
                            ((uint32_t)wire->bitmap_data[offset + 2u] << 16u) |
                            ((uint32_t)wire->bitmap_data[offset + 3u] << 24u);
                    offset += 4u;
                }
            }
            status = rdp_session_graphics_surface_alpha_run(surface,
                                                            left,
                                                            top,
                                                            width,
                                                            &position,
                                                            total,
                                                            count,
                                                            alpha);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        if (offset != wire->bitmap_data_length)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    status = rdp_session_graphics_surface_flush(session,
                                                surface,
                                                left,
                                                top,
                                                wire->dest_rect.right,
                                                wire->dest_rect.bottom,
                                                "alpha");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.alpha",
                        "surface_id=%u x=%u y=%u width=%u height=%u compressed=%u pixels=%u",
                        surface->surface_id,
                        left,
                        top,
                        width,
                        height,
                        compressed ? 1u : 0u,
                        total);
    return status;
}

typedef struct rdp_session_graphics_rfx_context
{
    librdp_session* session;
    rdp_session_graphics_surface* surface;
    int force_opaque;
    uint16_t tiles;
} rdp_session_graphics_rfx_context;

static librdp_status rdp_session_graphics_rfx_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_graphics_rfx_context* context = (rdp_session_graphics_rfx_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!tile || !context || !context->session || !context->surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->surface->width || tile->y >= context->surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->surface->width - tile->x)
        width = context->surface->width - tile->x;
    if (height > context->surface->height - tile->y)
        height = context->surface->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    return rdp_session_graphics_surface_write_bgra(context->session,
                                                   context->surface,
                                                   (uint16_t)tile->x,
                                                   (uint16_t)tile->y,
                                                   (uint16_t)width,
                                                   (uint16_t)height,
                                                   tile->pixels.bgra,
                                                   tile->pixels.stride,
                                                   context->force_opaque,
                                                   "cavideo");
}

static librdp_status rdp_session_graphics_surface_write_rfx(librdp_session* session,
                                                            rdp_session_graphics_surface* surface,
                                                            const uint8_t* data,
                                                            size_t data_len,
                                                            uint8_t pixel_format)
{
    rdp_session_graphics_rfx_context context;
    rdp_rfx_stream_summary summary;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.session = session;
    context.surface = surface;
    context.force_opaque = pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888;
    status = rdp_rfx_stream_decode(data, data_len, rdp_session_graphics_rfx_tile, &context, &summary);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.cavideo",
                        "surface_id=%u frame_id=%u width=%u height=%u tiles=%u rects=%u blitted=%u",
                        surface->surface_id,
                        summary.frame_id,
                        summary.width,
                        summary.height,
                        summary.tile_count,
                        summary.rect_count,
                        context.tiles);
    return status;
}

static uint32_t rdp_session_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

static uint64_t rdp_session_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
        !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = rdp_session_trace_hash_seed(hash, width);
    hash = rdp_session_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return rdp_session_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = rdp_session_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    size_t stride = 0;
    const uint8_t* pixels = NULL;

    if (!surface || !surface->active || !surface->pixels.data)
        return 0;
    if (width == 0 || height == 0 || x > surface->width || y > surface->height ||
        width > (uint32_t)surface->width - x || height > (uint32_t)surface->height - y)
        return 0;
    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);
    return rdp_session_trace_hash_bgra(pixels, width, height, stride);
}

static librdp_status rdp_session_graphics_progressive_base_quant(const rdp_graphics_progressive_region* region,
                                                                 uint8_t quant_idx,
                                                                 rdp_rfx_component_quant* quant)
{
    if (!region || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (quant_idx >= region->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_rfx_parse_component_quant(region->quant_values + ((size_t)quant_idx * 5u), 5u, quant);
}

static librdp_status rdp_session_graphics_progressive_delta_quant(const rdp_graphics_progressive_region* region,
                                                                  uint8_t progressive_idx,
                                                                  uint8_t component_idx,
                                                                  rdp_rfx_component_quant* delta)
{
    rdp_rfx_progressive_quant progressive;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!region || !delta)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(delta, 0, sizeof(*delta));
    if (progressive_idx == 0xffu)
        return LIBRDP_STATUS_OK;
    if (progressive_idx >= region->progressive_quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_parse_progressive_quant(region->progressive_quant_values + ((size_t)progressive_idx * 16u),
                                             16u,
                                             &progressive);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (component_idx == 0)
        *delta = progressive.y;
    else if (component_idx == 1)
        *delta = progressive.cb;
    else if (component_idx == 2)
        *delta = progressive.cr;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

/*
 * Write one progressive-codec tile into a region buffer. Tile coordinates,
 * quantization state, and destination stride are validated before the partial
 * region becomes renderable.
 */
static librdp_status rdp_session_graphics_progressive_write_region_tile(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    uint32_t x,
    uint32_t y,
    uint32_t width,
    uint32_t height,
    const rdp_rfx_tile_pixels* pixels,
    int* wrote)
{
    uint16_t i = 0;
    uint32_t tile_right = 0;
    uint32_t tile_bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !pixels || !wrote)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pixels->stride < RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE * 4u)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.write_region.failed",
                        "stage=stride surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u stride=%u",
                        surface ? surface->surface_id : 0u,
                        x,
                        y,
                        width,
                        height,
                        (unsigned)pixels->stride);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    *wrote = 0;
    tile_right = x + width;
    tile_bottom = y + height;
    for (i = 0; i < region->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint32_t left = 0;
        uint32_t top = 0;
        uint32_t right = 0;
        uint32_t bottom = 0;
        const uint8_t* src = NULL;

        status = rdp_graphics_progressive_parse_region_rect(region->rects + ((size_t)i * 8u),
                                                            region->rects_len - ((size_t)i * 8u),
                                                            &rect);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=rect_parse surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u status=%d",
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            i,
                            (int)status);
            return status;
        }
        if (rect.right <= rect.left || rect.bottom <= rect.top)
            continue;

        left = rdp_session_max_u32(x, rect.left);
        top = rdp_session_max_u32(y, rect.top);
        right = rdp_session_min_u32(tile_right, rect.right);
        bottom = rdp_session_min_u32(tile_bottom, rect.bottom);
        if (right <= left || bottom <= top)
            continue;

        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.progressive.region.write",
                              "surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u frame_id=%u",
                              surface->surface_id,
                              x,
                              y,
                              width,
                              height,
                              i,
                              rect.left,
                              rect.top,
                              rect.right,
                              rect.bottom,
                              left,
                              top,
                              right - left,
                              bottom - top,
                              session->graphics_current_frame_id);
        src = pixels->bgra + (((size_t)top - y) * pixels->stride) + (((size_t)left - x) * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         (uint16_t)left,
                                                         (uint16_t)top,
                                                         (uint16_t)(right - left),
                                                         (uint16_t)(bottom - top),
                                                         src,
                                                         pixels->stride,
                                                         0,
                                                         "progressive");
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=surface_write surface_id=%u surface_width=%u surface_height=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u stride=%u status=%d",
                            surface->surface_id,
                            surface->width,
                            surface->height,
                            x,
                            y,
                            width,
                            height,
                            rect.left,
                            rect.top,
                            rect.right,
                            rect.bottom,
                            left,
                            top,
                            right - left,
                            bottom - top,
                            (unsigned)pixels->stride,
                            (int)status);
            return status;
        }
        *wrote = 1;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Progressive tiles update a cached surface through region clipping, optional
 * quantization upgrades, and dirty tracking. Render through this single path so
 * partial progressive state is promoted to the visible surface only after the
 * tile payload and destination rectangle have both been validated.
 */
static librdp_status rdp_session_graphics_progressive_render_tile(librdp_session* session,
                                                                  uint32_t channel_id,
                                                                  uint32_t codec_context_id,
                                                                  rdp_session_graphics_surface* surface,
                                                                  const rdp_graphics_progressive_region* region,
                                                                  uint16_t block_type,
                                                                  uint8_t quant_idx_y,
                                                                  uint8_t quant_idx_cb,
                                                                  uint8_t quant_idx_cr,
                                                                  uint16_t x_idx,
                                                                  uint16_t y_idx,
                                                                  uint8_t tile_flags,
                                                                  uint8_t progressive_idx,
                                                                  const uint8_t* y_data,
                                                                  size_t y_len,
                                                                  const uint8_t* cb_data,
                                                                  size_t cb_len,
                                                                  const uint8_t* cr_data,
                                                                  size_t cr_len,
                                                                  uint32_t* rendered_tiles,
                                                                  uint32_t* failed_tiles,
                                                                  uint32_t* missing_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = (uint32_t)x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t y = (uint32_t)y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = "base_quant.y";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!y_data || !cb_data || !cr_data)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 2, &cr_delta);
    }
    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "state";
        tile_cache = rdp_session_progressive_tile_get(session,
                                                      surface->surface_id,
                                                      x_idx,
                                                      y_idx,
                                                      1);
        if (!tile_cache || !tile_cache->state || !tile_cache->pixels)
            status = LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK &&
        (tile_flags & 0x01u) != 0 &&
        (!tile_cache->state->valid ||
         !tile_cache->state->y.valid ||
         !tile_cache->state->cb.valid ||
         !tile_cache->state->cr.valid))
    {
        (*missing_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx);
        return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_tile_state(y_data,
                                                       y_len,
                                                       cb_data,
                                                       cb_len,
                                                       cr_data,
                                                       cr_len,
                                                       &y_quant,
                                                       &y_delta,
                                                       &cb_quant,
                                                       &cb_delta,
                                                       &cr_quant,
                                                       &cr_delta,
                                                       extrapolate,
                                                       (tile_flags & 0x01u) != 0,
                                                       tile_cache->state,
                                                       &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        tile_cache->state->x_idx = x_idx;
        tile_cache->state->y_idx = y_idx;
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u stage=%s status=%d y_len=%u cb_len=%u cr_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx,
                        stage,
                        (int)status,
                        (unsigned)y_len,
                        (unsigned)cb_len,
                        (unsigned)cr_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u flags=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          block_type,
                          tile_flags,
                          progressive_idx,
                          tile_cache && tile_cache->state ? tile_cache->state->pass : 0u,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

/*
 * Render a progressive-codec upgrade pass. The function merges cached tile
 * state with new coefficient data while preserving the previous visible
 * surface until the upgrade is complete.
 */
static librdp_status rdp_session_graphics_progressive_render_upgrade(
    librdp_session* session,
    uint32_t channel_id,
    uint32_t codec_context_id,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    const rdp_graphics_progressive_tile_upgrade* tile,
    uint32_t* rendered_tiles,
    uint32_t* failed_tiles,
    uint32_t* missing_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    const char* stage = "state";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !tile || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = (uint32_t)tile->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    y = (uint32_t)tile->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    tile_cache = rdp_session_progressive_tile_get(session,
                                                  surface->surface_id,
                                                  tile->x_idx,
                                                  tile->y_idx,
                                                  0);
    if (!tile_cache || !tile_cache->state || !tile_cache->pixels || !tile_cache->state->valid)
    {
        (*missing_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        tile->progressive_quality);
        return LIBRDP_STATUS_OK;
    }

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 2, &cr_delta);
    }

    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_upgrade_tile(tile->y_srl_data,
                                                         tile->y_srl_len,
                                                         tile->y_raw_data,
                                                         tile->y_raw_len,
                                                         tile->cb_srl_data,
                                                         tile->cb_srl_len,
                                                         tile->cb_raw_data,
                                                         tile->cb_raw_len,
                                                         tile->cr_srl_data,
                                                         tile->cr_srl_len,
                                                         tile->cr_raw_data,
                                                         tile->cr_raw_len,
                                                         &y_quant,
                                                         &y_delta,
                                                         &cb_quant,
                                                         &cb_delta,
                                                         &cr_quant,
                                                         &cr_delta,
                                                         extrapolate,
                                                         tile_cache->state,
                                                         &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(tile_cache->pixels, &pixels, sizeof(*tile_cache->pixels));
        tile_cache->has_pixels = 1;
        tile_cache->updated_frame_id = session->graphics_current_frame_id;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u stage=%s status=%d y_srl_len=%u y_raw_len=%u cb_srl_len=%u cb_raw_len=%u cr_srl_len=%u cr_raw_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        stage,
                        (int)status,
                        tile->y_srl_len,
                        tile->y_raw_len,
                        tile->cb_srl_len,
                        tile->cb_raw_len,
                        tile->cr_srl_len,
                        tile->cr_raw_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.tile",
                          "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u progressive_idx=%u pass=%u extrapolate=%u frame_id=%u queued=1",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          x,
                          y,
                          width,
                          height,
                          tile->block_type,
                          tile->progressive_quality,
                          tile_cache->state->pass,
                          (unsigned)extrapolate,
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

/*
 * Flush a completed progressive region to the target surface. Region damage is
 * emitted only after every clipped tile in the region has been applied.
 */
static librdp_status rdp_session_graphics_progressive_flush_region(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   uint32_t codec_context_id,
                                                                   rdp_session_graphics_surface* surface,
                                                                   const rdp_graphics_progressive_region* region,
                                                                   uint32_t* flushed_tiles,
                                                                   uint32_t* failed_tiles)
{
    size_t i = 0;
    uint32_t considered_tiles = 0;
    uint32_t clipped_tiles = 0;

    if (!session || !surface || !region || !flushed_tiles || !failed_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* tile_cache = &session->progressive_tiles[i];
        uint32_t x = 0;
        uint32_t y = 0;
        uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        int wrote = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (!tile_cache->active || tile_cache->surface_id != surface->surface_id ||
            tile_cache->updated_frame_id != session->graphics_current_frame_id ||
            !tile_cache->has_pixels || !tile_cache->pixels)
            continue;

        x = (uint32_t)tile_cache->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        y = (uint32_t)tile_cache->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
        if (x >= surface->width || y >= surface->height)
        {
            clipped_tiles++;
            continue;
        }
        if (width > (uint32_t)surface->width - x)
            width = (uint32_t)surface->width - x;
        if (height > (uint32_t)surface->height - y)
            height = (uint32_t)surface->height - y;
        considered_tiles++;
        status = rdp_session_graphics_progressive_write_region_tile(session,
                                                                    surface,
                                                                    region,
                                                                    x,
                                                                    y,
                                                                    width,
                                                                    height,
                                                                    tile_cache->pixels,
                                                                    &wrote);
        if (status != LIBRDP_STATUS_OK)
        {
            (*failed_tiles)++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.tile.flush.failed",
                            "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u frame_id=%u status=%d",
                            channel_id,
                            codec_context_id,
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            session->graphics_current_frame_id,
                            (int)status);
            continue;
        }
        if (wrote)
            (*flushed_tiles)++;
        else
            clipped_tiles++;
    }

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.progressive.region.flush",
                          "dvc_channel_id=%u context_id=%u surface_id=%u frame_id=%u considered_tiles=%u flushed_tiles=%u clipped_tiles=%u failed_tiles=%u",
                          channel_id,
                          codec_context_id,
                          surface->surface_id,
                          session->graphics_current_frame_id,
                          considered_tiles,
                          *flushed_tiles,
                          clipped_tiles,
                          *failed_tiles);
    return LIBRDP_STATUS_OK;
}

/*
 * Render all tiles for a progressive region. Codec state, tile cache lookup,
 * and destination clipping stay ordered so incomplete regions do not leak into
 * the framebuffer.
 */
static librdp_status rdp_session_graphics_progressive_render_region(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint32_t codec_context_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_progressive_region* region,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* missing_tiles)
{
    size_t offset = 0;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    while (offset < region->tiles_len)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(region->tiles + offset,
                                                                    region->tiles_len - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE)
        {
            rdp_graphics_progressive_tile_simple tile;

            status = rdp_graphics_progressive_parse_tile_simple(region->tiles + offset,
                                                                region->tiles_len - offset,
                                                                &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  0xffu,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST)
        {
            rdp_graphics_progressive_tile_first tile;

            status = rdp_graphics_progressive_parse_tile_first(region->tiles + offset,
                                                               region->tiles_len - offset,
                                                               &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  tile.progressive_quality,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE)
        {
            rdp_graphics_progressive_tile_upgrade tile;

            status = rdp_graphics_progressive_parse_tile_upgrade(region->tiles + offset,
                                                                 region->tiles_len - offset,
                                                                 &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_upgrade(session,
                                                                     channel_id,
                                                                     codec_context_id,
                                                                     surface,
                                                                     region,
                                                                     &tile,
                                                                     rendered_tiles,
                                                                     failed_tiles,
                                                                     missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_stream(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_wire_to_surface_2* wire,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* missing_tiles)
{
    size_t offset = 0;
    uint32_t region_index = 0;

    if (!session || !surface || !wire || !rendered_tiles || !failed_tiles || !missing_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *rendered_tiles = 0;
    *failed_tiles = 0;
    *missing_tiles = 0;
    while (offset < wire->bitmap_data_length)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(wire->bitmap_data + offset,
                                                                    wire->bitmap_data_length - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION)
        {
            rdp_graphics_progressive_region region;
            uint32_t flushed_tiles = 0;

            status = rdp_graphics_progressive_parse_region(wire->bitmap_data + offset,
                                                           wire->bitmap_data_length - offset,
                                                           &region);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.region",
                            "dvc_channel_id=%u context_id=%u surface_id=%u region_index=%u rect_count=%u quant_count=%u progressive_quant_count=%u tile_count=%u tile_data_size=%u flags=%u tile_size=%u frame_id=%u",
                            channel_id,
                            wire->codec_context_id,
                            surface->surface_id,
                            region_index,
                            region.rect_count,
                            region.quant_count,
                            region.progressive_quant_count,
                            region.tile_count,
                            region.tile_data_size,
                            region.flags,
                            region.tile_size,
                            session->graphics_current_frame_id);
            status = rdp_session_graphics_progressive_render_region(session,
                                                                    channel_id,
                                                                    wire->codec_context_id,
                                                                    surface,
                                                                    &region,
                                                                    rendered_tiles,
                                                                    failed_tiles,
                                                                    missing_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_flush_region(session,
                                                                   channel_id,
                                                                   wire->codec_context_id,
                                                                   surface,
                                                                   &region,
                                                                   &flushed_tiles,
                                                                   failed_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            region_index++;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_cache_evict(librdp_session* session, uint16_t cache_slot)
{
    rdp_session_graphics_cache_entry* entry = NULL;

    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return;
    entry = &session->graphics_cache[cache_slot];
    if (entry->active)
    {
        if (session->graphics_cache_bytes >= entry->pixels.length)
            session->graphics_cache_bytes -= entry->pixels.length;
        else
            session->graphics_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_graphics_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GRAPHICS_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->graphics_cache[i].pixels);
    memset(session->graphics_cache, 0, sizeof(session->graphics_cache));
    session->graphics_cache_bytes = 0;
}

static size_t rdp_session_gdi_bitmap_cache_entry_size(const rdp_session_gdi_bitmap_cache_entry* entry);

static void rdp_session_gdi_bitmap_cache_evict(librdp_session* session, size_t index)
{
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;

    if (!session || index >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        return;
    entry = &session->gdi_bitmap_cache[index];
    if (entry->active)
    {
        size_t size = rdp_session_gdi_bitmap_cache_entry_size(entry);

        if (session->gdi_bitmap_cache_bytes >= size)
            session->gdi_bitmap_cache_bytes -= size;
        else
            session->gdi_bitmap_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    rdp_buffer_free(&entry->raw);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_gdi_bitmap_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_buffer_free(&session->gdi_bitmap_cache[i].pixels);
        rdp_buffer_free(&session->gdi_bitmap_cache[i].raw);
    }
    memset(session->gdi_bitmap_cache, 0, sizeof(session->gdi_bitmap_cache));
    session->gdi_bitmap_cache_bytes = 0;
    session->gdi_bitmap_cache_clock = 0;
}

static void rdp_session_gdi_color_table_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_color_table_cache, 0, sizeof(session->gdi_color_table_cache));
}

static void rdp_session_gdi_brush_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_brush_cache, 0, sizeof(session->gdi_brush_cache));
}

static void rdp_session_gdi_ninegrid_cache_clear(librdp_session* session)
{
    if (!session)
        return;
    memset(session->gdi_ninegrid_cache, 0, sizeof(session->gdi_ninegrid_cache));
}

static void rdp_session_gdi_glyph_cache_clear(librdp_session* session)
{
    size_t id = 0;
    size_t index = 0;

    if (!session)
        return;
    for (id = 0; id < RDP_SESSION_GDI_GLYPH_CACHE_IDS; id++)
    {
        for (index = 0; index < RDP_SESSION_GDI_GLYPH_CACHE_SLOTS; index++)
            rdp_buffer_free(&session->gdi_glyph_cache[id][index].bitmap);
    }
    memset(session->gdi_glyph_cache, 0, sizeof(session->gdi_glyph_cache));
    session->gdi_glyph_cache_bytes = 0;
}

static void rdp_session_gdi_glyph_fragment_cache_clear(librdp_session* session)
{
    size_t index = 0;

    if (!session)
        return;
    for (index = 0; index < RDP_SESSION_GDI_GLYPH_FRAGMENT_SLOTS; index++)
        rdp_buffer_free(&session->gdi_glyph_fragments[index].data);
    memset(session->gdi_glyph_fragments, 0, sizeof(session->gdi_glyph_fragments));
}

static rdp_session_gdi_glyph_cache_entry* rdp_session_gdi_glyph_cache_find(librdp_session* session,
                                                                           uint32_t cache_id,
                                                                           uint32_t cache_index)
{
    if (!session || cache_id >= RDP_SESSION_GDI_GLYPH_CACHE_IDS ||
        cache_index >= RDP_SESSION_GDI_GLYPH_CACHE_SLOTS)
        return NULL;
    if (!session->gdi_glyph_cache[cache_id][cache_index].active)
        return NULL;
    return &session->gdi_glyph_cache[cache_id][cache_index];
}

static librdp_status rdp_session_gdi_glyph_cache_store(librdp_session* session,
                                                       uint32_t cache_id,
                                                       const rdp_gdi_glyph_bitmap* glyph)
{
    rdp_session_gdi_glyph_cache_entry* entry = NULL;
    size_t old_size = 0;

    if (!session || !glyph || !glyph->bitmap || glyph->bitmap_len == 0 ||
        cache_id >= RDP_SESSION_GDI_GLYPH_CACHE_IDS ||
        glyph->cache_index >= RDP_SESSION_GDI_GLYPH_CACHE_SLOTS ||
        glyph->bitmap_len > RDP_SESSION_GDI_GLYPH_MAX_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry = &session->gdi_glyph_cache[cache_id][glyph->cache_index];
    old_size = entry->bitmap.length;
    if (session->gdi_glyph_cache_bytes >= old_size)
        session->gdi_glyph_cache_bytes -= old_size;
    else
        session->gdi_glyph_cache_bytes = 0;
    if (session->gdi_glyph_cache_bytes > RDP_SESSION_GDI_GLYPH_MAX_BYTES - glyph->bitmap_len)
    {
        rdp_session_gdi_glyph_cache_clear(session);
        entry = &session->gdi_glyph_cache[cache_id][glyph->cache_index];
    }
    if (rdp_buffer_reserve(&entry->bitmap, glyph->bitmap_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    memcpy(entry->bitmap.data, glyph->bitmap, glyph->bitmap_len);
    entry->bitmap.length = glyph->bitmap_len;
    entry->active = 1;
    entry->cache_id = cache_id;
    entry->cache_index = glyph->cache_index;
    entry->x = glyph->x;
    entry->y = glyph->y;
    entry->width = glyph->width;
    entry->height = glyph->height;
    session->gdi_glyph_cache_bytes += glyph->bitmap_len;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.glyph_cache.store",
                          "cache_id=%u cache_index=%u x=%d y=%d width=%u height=%u bytes=%u total_bytes=%u",
                          cache_id,
                          glyph->cache_index,
                          glyph->x,
                          glyph->y,
                          glyph->width,
                          glyph->height,
                          glyph->bitmap_len,
                          (unsigned)session->gdi_glyph_cache_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_glyph_fragment_store(librdp_session* session,
                                                          uint8_t fragment_id,
                                                          const uint8_t* data,
                                                          uint32_t length)
{
    rdp_session_gdi_glyph_fragment* fragment = NULL;

    if (!session || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fragment = &session->gdi_glyph_fragments[fragment_id];
    if (rdp_buffer_reserve(&fragment->data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    if (length > 0)
        memcpy(fragment->data.data, data, length);
    fragment->data.length = length;
    fragment->active = 1;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.glyph_fragment.store",
                          "fragment_id=%u bytes=%u",
                          fragment_id,
                          length);
    return LIBRDP_STATUS_OK;
}

static size_t rdp_session_gdi_bitmap_cache_entry_size(const rdp_session_gdi_bitmap_cache_entry* entry)
{
    if (!entry || !entry->active)
        return 0;
    return entry->pixels.length + entry->raw.length;
}

static rdp_session_gdi_ninegrid_cache_entry* rdp_session_gdi_ninegrid_cache_find(librdp_session* session,
                                                                                 uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_ninegrid_cache_entry* entry = &session->gdi_ninegrid_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_ninegrid_cache_entry* rdp_session_gdi_ninegrid_cache_slot(librdp_session* session,
                                                                                 uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_ninegrid_cache_entry* entry =
        rdp_session_gdi_ninegrid_cache_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS; i++)
    {
        if (!session->gdi_ninegrid_cache[i].active)
            return &session->gdi_ninegrid_cache[i];
    }
    return &session->gdi_ninegrid_cache[bitmap_id % RDP_SESSION_GDI_NINEGRID_CACHE_SLOTS];
}

static const rdp_palette_update* rdp_session_gdi_color_table_find(const librdp_session* session,
                                                                  uint32_t cache_index)
{
    if (!session || cache_index >= RDP_SESSION_GDI_COLOR_TABLE_SLOTS ||
        !session->gdi_color_table_cache[cache_index].active)
        return NULL;
    return &session->gdi_color_table_cache[cache_index].palette;
}

static librdp_status rdp_session_gdi_color_table_store(librdp_session* session,
                                                       const rdp_gdi_cache_color_table_order* order)
{
    rdp_session_gdi_color_table_cache_entry* entry = NULL;

    if (!session || !order || order->palette.count != RDP_BITMAP_PALETTE_MAX_ENTRIES ||
        order->cache_index >= RDP_SESSION_GDI_COLOR_TABLE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry = &session->gdi_color_table_cache[order->cache_index];
    entry->active = 1;
    entry->palette = order->palette;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.color_table.store",
                          "cache_index=%u colors=%u",
                          order->cache_index,
                          order->palette.count);
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_session_gdi_scale_5_to_8(uint16_t value)
{
    return (uint8_t)((value << 3u) | (value >> 2u));
}

static uint8_t rdp_session_gdi_scale_6_to_8(uint16_t value)
{
    return (uint8_t)((value << 2u) | (value >> 4u));
}

static uint32_t rdp_session_gdi_brush_bpp(uint32_t format)
{
    if (format == RDP_GDI_BMF_1BPP)
        return 1;
    if (format == RDP_GDI_BMF_8BPP)
        return 8;
    if (format == RDP_GDI_BMF_16BPP)
        return 16;
    if (format == RDP_GDI_BMF_24BPP)
        return 24;
    if (format == RDP_GDI_BMF_32BPP)
        return 32;
    return 0;
}

static void rdp_session_gdi_brush_index_to_bgra(const librdp_session* session,
                                                uint8_t index,
                                                uint8_t* dst)
{
    const rdp_palette_update* palette = session && session->palette_valid ? &session->palette : NULL;

    if (palette && index < palette->count)
    {
        dst[0] = palette->entries[index].blue;
        dst[1] = palette->entries[index].green;
        dst[2] = palette->entries[index].red;
    }
    else
    {
        dst[0] = index;
        dst[1] = index;
        dst[2] = index;
    }
    dst[3] = 0xffu;
}

static librdp_status rdp_session_gdi_brush_read_color(const librdp_session* session,
                                                      uint32_t format,
                                                      const uint8_t* data,
                                                      size_t length,
                                                      uint8_t* dst,
                                                      size_t* consumed)
{
    uint32_t pixel = 0;

    if (!data || !dst || !consumed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (format == RDP_GDI_BMF_8BPP)
    {
        if (length < 1u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_session_gdi_brush_index_to_bgra(session, data[0], dst);
        *consumed = 1;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_16BPP)
    {
        if (length < 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        pixel = (uint32_t)data[0] | ((uint32_t)data[1] << 8u);
        dst[0] = rdp_session_gdi_scale_5_to_8((uint16_t)(pixel & 0x001fu));
        dst[1] = rdp_session_gdi_scale_6_to_8((uint16_t)((pixel >> 5u) & 0x003fu));
        dst[2] = rdp_session_gdi_scale_5_to_8((uint16_t)((pixel >> 11u) & 0x001fu));
        dst[3] = 0xffu;
        *consumed = 2;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_24BPP)
    {
        if (length < 3u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        dst[0] = data[0];
        dst[1] = data[1];
        dst[2] = data[2];
        dst[3] = 0xffu;
        *consumed = 3;
        return LIBRDP_STATUS_OK;
    }
    if (format == RDP_GDI_BMF_32BPP)
    {
        if (length < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        dst[0] = data[0];
        dst[1] = data[1];
        dst[2] = data[2];
        dst[3] = 0xffu;
        *consumed = 4;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static int rdp_session_gdi_brush_compressed(uint32_t format, uint32_t length)
{
    return (format == RDP_GDI_BMF_8BPP && length == 20u) ||
           (format == RDP_GDI_BMF_16BPP && length == 24u) ||
           (format == RDP_GDI_BMF_24BPP && length == 28u) ||
           (format == RDP_GDI_BMF_32BPP && length == 32u);
}

/*
 * Store a decoded GDI brush in the session cache. Cache index validation and
 * brush ownership transfer happen together so later orders never reference
 * transient order memory.
 */
static librdp_status rdp_session_gdi_store_cache_brush(librdp_session* session,
                                                       const rdp_gdi_cache_brush_order* order)
{
    rdp_session_gdi_brush_cache_entry* entry = NULL;
    uint32_t bits_per_pixel = 0;
    uint32_t bytes_per_pixel = 0;
    uint32_t i = 0;

    if (!session || !order || !order->brush_data ||
        order->cache_entry >= RDP_SESSION_GDI_BRUSH_CACHE_SLOTS ||
        order->width != 8u ||
        order->height != 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    bits_per_pixel = rdp_session_gdi_brush_bpp(order->bitmap_format);
    if (bits_per_pixel == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    entry = &session->gdi_brush_cache[order->cache_entry];
    memset(entry, 0, sizeof(*entry));
    entry->cache_entry = order->cache_entry;
    entry->bitmap_format = order->bitmap_format;
    if (bits_per_pixel == 1u)
    {
        if (order->brush_data_len != sizeof(entry->mono_rows))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        entry->mono = 1;
        for (i = 0; i < 8u; i++)
            entry->mono_rows[i] = order->brush_data[7u - i];
    }
    else if (rdp_session_gdi_brush_compressed(order->bitmap_format, order->brush_data_len))
    {
        uint8_t table[4u * 4u];
        size_t offset = 16u;
        uint32_t table_entry = 0;

        for (table_entry = 0; table_entry < 4u; table_entry++)
        {
            size_t consumed = 0;
            librdp_status status = rdp_session_gdi_brush_read_color(session,
                                                                    order->bitmap_format,
                                                                    order->brush_data + offset,
                                                                    order->brush_data_len - offset,
                                                                    table + table_entry * 4u,
                                                                    &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += consumed;
        }
        if (offset != order->brush_data_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < 64u; i++)
        {
            uint8_t packed = order->brush_data[i / 4u];
            uint32_t table_index = (uint32_t)((packed >> ((3u - (i & 3u)) * 2u)) & 0x03u);

            memcpy(entry->bgra + ((size_t)i * 4u), table + table_index * 4u, 4u);
        }
    }
    else
    {
        size_t offset = 0;

        bytes_per_pixel = (bits_per_pixel + 7u) / 8u;
        if (order->brush_data_len != 64u * bytes_per_pixel)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < 64u; i++)
        {
            size_t consumed = 0;
            librdp_status status = rdp_session_gdi_brush_read_color(session,
                                                                    order->bitmap_format,
                                                                    order->brush_data + offset,
                                                                    order->brush_data_len - offset,
                                                                    entry->bgra + ((size_t)i * 4u),
                                                                    &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += consumed;
        }
    }
    entry->active = 1;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.brush_cache.store",
                          "cache_entry=%u bitmap_format=%u mono=%u bytes=%u",
                          order->cache_entry,
                          order->bitmap_format,
                          entry->mono,
                          order->brush_data_len);
    return LIBRDP_STATUS_OK;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_bitmap_cache_find(librdp_session* session,
                                                                             uint32_t cache_id,
                                                                             uint32_t cache_index)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_bitmap_cache_entry* entry = &session->gdi_bitmap_cache[i];

        if (entry->active && entry->cache_id == cache_id && entry->cache_index == cache_index)
        {
            entry->last_used = ++session->gdi_bitmap_cache_clock;
            return entry;
        }
    }
    return NULL;
}

static size_t rdp_session_gdi_bitmap_cache_lru(librdp_session* session,
                                               const rdp_session_gdi_bitmap_cache_entry* skip)
{
    size_t i = 0;
    size_t candidate = RDP_SESSION_GDI_BITMAP_CACHE_SLOTS;
    uint64_t oldest = UINT64_MAX;

    if (!session)
        return candidate;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_bitmap_cache_entry* entry = &session->gdi_bitmap_cache[i];

        if (!entry->active || entry == skip)
            continue;
        if (entry->last_used < oldest)
        {
            oldest = entry->last_used;
            candidate = i;
        }
    }
    return candidate;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_bitmap_cache_slot(librdp_session* session,
                                                                             uint32_t cache_id,
                                                                             uint32_t cache_index)
{
    size_t i = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = rdp_session_gdi_bitmap_cache_find(session, cache_id, cache_index);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        if (!session->gdi_bitmap_cache[i].active)
            return &session->gdi_bitmap_cache[i];
    }
    i = rdp_session_gdi_bitmap_cache_lru(session, NULL);
    if (i >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        return NULL;
    rdp_session_gdi_bitmap_cache_evict(session, i);
    return &session->gdi_bitmap_cache[i];
}

static void rdp_session_gdi_saved_bitmap_evict(librdp_session* session, size_t index)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;

    if (!session || index >= RDP_SESSION_GDI_SAVE_BITMAP_SLOTS)
        return;
    entry = &session->gdi_saved_bitmaps[index];
    if (entry->active)
    {
        if (session->gdi_saved_bitmap_bytes >= entry->pixels.length)
            session->gdi_saved_bitmap_bytes -= entry->pixels.length;
        else
            session->gdi_saved_bitmap_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_gdi_saved_bitmaps_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
        rdp_buffer_free(&session->gdi_saved_bitmaps[i].pixels);
    memset(session->gdi_saved_bitmaps, 0, sizeof(session->gdi_saved_bitmaps));
    session->gdi_saved_bitmap_bytes = 0;
}

static rdp_session_gdi_saved_bitmap* rdp_session_gdi_saved_bitmap_find(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
    {
        rdp_session_gdi_saved_bitmap* entry = &session->gdi_saved_bitmaps[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static rdp_session_gdi_saved_bitmap* rdp_session_gdi_saved_bitmap_slot(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_saved_bitmap* entry = rdp_session_gdi_saved_bitmap_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_SAVE_BITMAP_SLOTS; i++)
    {
        if (!session->gdi_saved_bitmaps[i].active)
            return &session->gdi_saved_bitmaps[i];
    }
    i = (size_t)(bitmap_id % RDP_SESSION_GDI_SAVE_BITMAP_SLOTS);
    rdp_session_gdi_saved_bitmap_evict(session, i);
    return &session->gdi_saved_bitmaps[i];
}

static rdp_session_gdi_offscreen_bitmap* rdp_session_gdi_offscreen_find(librdp_session* session,
                                                                        uint32_t bitmap_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
    {
        rdp_session_gdi_offscreen_bitmap* entry = &session->gdi_offscreen_cache[i];

        if (entry->active && entry->bitmap_id == bitmap_id)
            return entry;
    }
    return NULL;
}

static void rdp_session_gdi_offscreen_delete(librdp_session* session, uint32_t bitmap_id)
{
    rdp_session_gdi_offscreen_bitmap* entry = rdp_session_gdi_offscreen_find(session, bitmap_id);

    if (!session || !entry)
        return;
    librdp_surface_free(entry->surface);
    memset(entry, 0, sizeof(*entry));
    if (session->gdi_current_surface_id == bitmap_id)
        session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.offscreen.delete",
                          "surface_id=%u",
                          bitmap_id);
}

static void rdp_session_gdi_offscreen_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
        librdp_surface_free(session->gdi_offscreen_cache[i].surface);
    memset(session->gdi_offscreen_cache, 0, sizeof(session->gdi_offscreen_cache));
    session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    session->gdi_drawing_to_offscreen = 0;
}

static rdp_session_gdi_offscreen_bitmap* rdp_session_gdi_offscreen_slot(librdp_session* session,
                                                                       uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_offscreen_bitmap* entry = rdp_session_gdi_offscreen_find(session, bitmap_id);

    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS; i++)
    {
        if (!session->gdi_offscreen_cache[i].active)
            return &session->gdi_offscreen_cache[i];
    }
    i = (size_t)(bitmap_id % RDP_SESSION_GDI_OFFSCREEN_CACHE_SLOTS);
    librdp_surface_free(session->gdi_offscreen_cache[i].surface);
    memset(&session->gdi_offscreen_cache[i], 0, sizeof(session->gdi_offscreen_cache[i]));
    return &session->gdi_offscreen_cache[i];
}

static librdp_status rdp_session_gdi_create_offscreen_bitmap(
    librdp_session* session,
    const rdp_gdi_create_offscreen_bitmap_order* order)
{
    rdp_session_gdi_offscreen_bitmap* entry = NULL;
    librdp_surface* surface = NULL;
    uint32_t i = 0;

    if (!session || !order || order->bitmap_id > 0x7fffu ||
        order->width == 0 || order->height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < order->delete_count; i++)
        rdp_session_gdi_offscreen_delete(session, order->delete_indices[i]);
    entry = rdp_session_gdi_offscreen_slot(session, order->bitmap_id);
    if (!entry)
        return LIBRDP_STATUS_NO_MEMORY;
    surface = librdp_surface_new(order->width, order->height, LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;
    librdp_surface_free(entry->surface);
    memset(entry, 0, sizeof(*entry));
    entry->active = 1;
    entry->bitmap_id = order->bitmap_id;
    entry->surface = surface;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.offscreen.create",
                          "surface_id=%u width=%u height=%u delete_count=%u",
                          order->bitmap_id,
                          order->width,
                          order->height,
                          order->delete_count);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_switch_surface(librdp_session* session, uint32_t bitmap_id)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (bitmap_id == RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE)
    {
        session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.surface.switch",
                              "surface_id=%u primary=1",
                              bitmap_id);
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_session_gdi_offscreen_find(session, bitmap_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    session->gdi_current_surface_id = bitmap_id;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.surface.switch",
                          "surface_id=%u primary=0",
                          bitmap_id);
    return LIBRDP_STATUS_OK;
}

static librdp_surface* rdp_session_gdi_target_surface(librdp_session* session)
{
    rdp_session_gdi_offscreen_bitmap* entry = NULL;

    if (!session)
        return NULL;
    if (session->gdi_current_surface_id == RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE)
        return session->surface;
    entry = rdp_session_gdi_offscreen_find(session, session->gdi_current_surface_id);
    return entry ? entry->surface : NULL;
}

static void rdp_session_gdi_stream_bitmap_reset(librdp_session* session)
{
    if (!session)
        return;
    rdp_buffer_free(&session->gdi_stream_bitmap.bitmap_data);
    memset(&session->gdi_stream_bitmap, 0, sizeof(session->gdi_stream_bitmap));
}

static librdp_status rdp_session_gdi_stream_bitmap_blit(librdp_session* session)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    librdp_surface* target = NULL;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t to_offscreen = 0;

    if (!session || !session->gdi_stream_bitmap.bitmap_data.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->gdi_stream_bitmap.bitmap_data.length != session->gdi_stream_bitmap.bitmap_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    target = rdp_session_gdi_target_surface(session);
    if (!target ||
        session->gdi_stream_bitmap.width > librdp_surface_width(target) ||
        session->gdi_stream_bitmap.height > librdp_surface_height(target))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = 0;
    rect.dest_top = 0;
    rect.dest_right = (uint16_t)(session->gdi_stream_bitmap.width - 1u);
    rect.dest_bottom = (uint16_t)(session->gdi_stream_bitmap.height - 1u);
    rect.width = (uint16_t)session->gdi_stream_bitmap.width;
    rect.height = (uint16_t)session->gdi_stream_bitmap.height;
    rect.bits_per_pixel = (uint16_t)session->gdi_stream_bitmap.bits_per_pixel;
    rect.flags = (session->gdi_stream_bitmap.flags & RDP_GDI_STREAM_BITMAP_COMPRESSED) != 0 ?
                 RDP_SESSION_BITMAP_FLAG_COMPRESSED : 0;
    rect.data = session->gdi_stream_bitmap.bitmap_data.data;
    rect.data_len = (uint32_t)session->gdi_stream_bitmap.bitmap_data.length;

    rdp_buffer_init(&pixels);
    status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                        session->palette_valid ? &session->palette : NULL,
                                                        &pixels,
                                                        &stride);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_surface_blit_bgra32(target,
                                            0,
                                            0,
                                            session->gdi_stream_bitmap.width,
                                            session->gdi_stream_bitmap.height,
                                            pixels.data,
                                            stride);
    if (status == LIBRDP_STATUS_OK)
    {
        to_offscreen = target != session->surface;
        if (to_offscreen)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_TRACE,
                                  "client.gdi.stream_bitmap.offscreen_blit",
                                  "surface_id=%u width=%u height=%u bpp=%u compressed=%u",
                                  session->gdi_current_surface_id,
                                  session->gdi_stream_bitmap.width,
                                  session->gdi_stream_bitmap.height,
                                  session->gdi_stream_bitmap.bits_per_pixel,
                                  (session->gdi_stream_bitmap.flags & RDP_GDI_STREAM_BITMAP_COMPRESSED) != 0 ? 1u : 0u);
        }
        else
        {
            rdp_session_emit_surface_invalidated(session,
                                                 0,
                                                 0,
                                                 session->gdi_stream_bitmap.width,
                                                 session->gdi_stream_bitmap.height);
        }
    }
    rdp_buffer_free(&pixels);
    return status;
}

static librdp_status rdp_session_gdi_stream_bitmap_finish_if_needed(librdp_session* session, uint32_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((flags & RDP_GDI_STREAM_BITMAP_END) == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_session_gdi_stream_bitmap_blit(session);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          status == LIBRDP_STATUS_OK ? RDP_TRACE_LEVEL_DEBUG : RDP_TRACE_LEVEL_INFO,
                          status == LIBRDP_STATUS_OK ? "client.gdi.stream_bitmap.done" :
                                                        "client.gdi.stream_bitmap.failed",
                          "status=%d surface_id=%u width=%u height=%u bpp=%u received=%u expected=%u flags=%u type=%u",
                          (int)status,
                          session->gdi_current_surface_id,
                          session->gdi_stream_bitmap.width,
                          session->gdi_stream_bitmap.height,
                          session->gdi_stream_bitmap.bits_per_pixel,
                          (unsigned)session->gdi_stream_bitmap.bitmap_data.length,
                          session->gdi_stream_bitmap.bitmap_size,
                          session->gdi_stream_bitmap.flags,
                          session->gdi_stream_bitmap.bitmap_type);
    rdp_session_gdi_stream_bitmap_reset(session);
    return status;
}

static librdp_status rdp_session_gdi_stream_bitmap_first(
    librdp_session* session,
    const rdp_gdi_stream_bitmap_first_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || !order->bitmap_block)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->width == 0 || order->height == 0 ||
        order->width > UINT16_MAX || order->height > UINT16_MAX ||
        order->bits_per_pixel == 0 || order->bits_per_pixel > UINT16_MAX ||
        order->bitmap_size == 0 || order->bitmap_block_len > order->bitmap_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_session_gdi_stream_bitmap_reset(session);
    session->gdi_stream_bitmap.active = 1;
    session->gdi_stream_bitmap.flags = order->flags;
    session->gdi_stream_bitmap.bits_per_pixel = order->bits_per_pixel;
    session->gdi_stream_bitmap.bitmap_type = order->bitmap_type;
    session->gdi_stream_bitmap.width = order->width;
    session->gdi_stream_bitmap.height = order->height;
    session->gdi_stream_bitmap.bitmap_size = order->bitmap_size;
    status = rdp_buffer_reserve(&session->gdi_stream_bitmap.bitmap_data, order->bitmap_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&session->gdi_stream_bitmap.bitmap_data,
                                   order->bitmap_block,
                                   order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.stream_bitmap.first",
                          "surface_id=%u width=%u height=%u bpp=%u received=%u expected=%u flags=%u type=%u",
                          session->gdi_current_surface_id,
                          order->width,
                          order->height,
                          order->bits_per_pixel,
                          order->bitmap_block_len,
                          order->bitmap_size,
                          order->flags,
                          order->bitmap_type);
    return rdp_session_gdi_stream_bitmap_finish_if_needed(session, order->flags);
}

static librdp_status rdp_session_gdi_stream_bitmap_next(
    librdp_session* session,
    const rdp_gdi_stream_bitmap_next_order* order)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || (!order->bitmap_block && order->bitmap_block_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->gdi_stream_bitmap.active ||
        order->bitmap_type != session->gdi_stream_bitmap.bitmap_type ||
        order->bitmap_block_len > session->gdi_stream_bitmap.bitmap_size ||
        session->gdi_stream_bitmap.bitmap_data.length >
            session->gdi_stream_bitmap.bitmap_size - order->bitmap_block_len)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_buffer_append(&session->gdi_stream_bitmap.bitmap_data,
                               order->bitmap_block,
                               order->bitmap_block_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_gdi_stream_bitmap_reset(session);
        return status;
    }
    session->gdi_stream_bitmap.flags = order->flags;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.gdi.stream_bitmap.next",
                          "surface_id=%u received=%u expected=%u block_len=%u flags=%u type=%u",
                          session->gdi_current_surface_id,
                          (unsigned)session->gdi_stream_bitmap.bitmap_data.length,
                          session->gdi_stream_bitmap.bitmap_size,
                          order->bitmap_block_len,
                          order->flags,
                          order->bitmap_type);
    return rdp_session_gdi_stream_bitmap_finish_if_needed(session, order->flags);
}

static rdp_session_graphics_cache_entry* rdp_session_graphics_cache_find(librdp_session* session, uint16_t cache_slot)
{
    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS || !session->graphics_cache[cache_slot].active)
        return NULL;
    return &session->graphics_cache[cache_slot];
}

/*
 * Store graphics-pipeline cache entries supplied by the server. Keys, payload
 * lengths, and replacement ownership are validated before the session cache is
 * updated.
 */
static librdp_status rdp_session_graphics_cache_store(librdp_session* session,
                                                      const rdp_graphics_surface_to_cache* surface_to_cache)
{
    rdp_session_graphics_surface* surface = NULL;
    rdp_session_graphics_cache_entry* entry = NULL;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface_to_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface_to_cache->cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    surface = rdp_session_graphics_surface_find(session, surface_to_cache->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface_to_cache->rect_src.right > surface->width ||
        surface_to_cache->rect_src.bottom > surface->height ||
        surface_to_cache->rect_src.left >= surface_to_cache->rect_src.right ||
        surface_to_cache->rect_src.top >= surface_to_cache->rect_src.bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    width = (uint16_t)(surface_to_cache->rect_src.right - surface_to_cache->rect_src.left);
    height = (uint16_t)(surface_to_cache->rect_src.bottom - surface_to_cache->rect_src.top);
    size = (size_t)width * (size_t)height * 4u;
    entry = &session->graphics_cache[surface_to_cache->cache_slot];
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->graphics_cache_bytes >= old_size ? session->graphics_cache_bytes - old_size : 0;
    if (size > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES ||
        current_without_old > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;

    source_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        memcpy(entry->pixels.data + ((size_t)row * (size_t)width * 4u),
               surface->pixels.data + ((size_t)(surface_to_cache->rect_src.top + row) * source_stride) +
                   ((size_t)surface_to_cache->rect_src.left * 4u),
               (size_t)width * 4u);
    }
    entry->pixels.length = size;
    entry->active = 1;
    entry->cache_slot = surface_to_cache->cache_slot;
    entry->width = width;
    entry->height = height;
    entry->cache_key = surface_to_cache->cache_key;
    session->graphics_cache_bytes = current_without_old + size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.store",
                          "surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u cache_key=%llu cache_bytes=%llu source_hash=%016llx cache_hash=%016llx frame_id=%u",
                          surface_to_cache->surface_id,
                          surface_to_cache->cache_slot,
                          width,
                          height,
                          surface_to_cache->rect_src.left,
                          surface_to_cache->rect_src.top,
                          surface_to_cache->rect_src.right,
                          surface_to_cache->rect_src.bottom,
                          (unsigned long long)surface_to_cache->cache_key,
                          (unsigned long long)session->graphics_cache_bytes,
                          (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                              surface_to_cache->rect_src.left,
                                                                              surface_to_cache->rect_src.top,
                                                                              width,
                                                                              height),
                          (unsigned long long)rdp_session_trace_hash_bgra(entry->pixels.data,
                                                                          width,
                                                                          height,
                                                                          (size_t)width * 4u),
                          session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_copy(librdp_session* session,
                                                       rdp_session_graphics_surface* source,
                                                       rdp_session_graphics_surface* dest,
                                                       const rdp_graphics_rect16* rect,
                                                       const rdp_graphics_point16* point)
{
    rdp_buffer copy;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t row_stride = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !source || !dest || !rect || !point || !source->active || !dest->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > source->width || rect->bottom > source->height ||
        rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(rect->right - rect->left);
    height = (uint16_t)(rect->bottom - rect->top);
    if (point->x > dest->width || point->y > dest->height ||
        width > dest->width - point->x || height > dest->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&copy);
    row_stride = (size_t)width * 4u;
    status = rdp_buffer_reserve(&copy, row_stride * (size_t)height);
    if (status == LIBRDP_STATUS_OK)
    {
        source_stride = (size_t)source->width * 4u;
        for (row = 0; row < height; row++)
        {
            memcpy(copy.data + ((size_t)row * row_stride),
                   source->pixels.data + ((size_t)(rect->top + row) * source_stride) + ((size_t)rect->left * 4u),
                   row_stride);
        }
        copy.length = row_stride * (size_t)height;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "client.graphics.surface.copy",
                              "source_id=%u dest_id=%u src_left=%u src_top=%u src_right=%u src_bottom=%u dst_x=%u dst_y=%u width=%u height=%u frame_id=%u copy_hash=%016llx",
                              source->surface_id,
                              dest->surface_id,
                              rect->left,
                              rect->top,
                              rect->right,
                              rect->bottom,
                              point->x,
                              point->y,
                              width,
                              height,
                              session->graphics_current_frame_id,
                              (unsigned long long)rdp_session_trace_hash_bgra(copy.data, width, height, row_stride));
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         dest,
                                                         point->x,
                                                         point->y,
                                                         width,
                                                         height,
                                                         copy.data,
                                                         row_stride,
                                                         0,
                                                         "surface_to_surface");
    }
    rdp_buffer_free(&copy);
    return status;
}

static librdp_status rdp_session_graphics_cache_copy_to_surface(librdp_session* session,
                                                                rdp_session_graphics_cache_entry* cache,
                                                                rdp_session_graphics_surface* surface,
                                                                const rdp_graphics_point16* point)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !cache || !surface || !point || !cache->active || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (point->x > surface->width || point->y > surface->height ||
        cache->width > surface->width - point->x || cache->height > surface->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
                          "client.graphics.cache.copy",
                          "cache_slot=%u surface_id=%u dst_x=%u dst_y=%u width=%u height=%u cache_key=%llu frame_id=%u cache_hash=%016llx",
                          cache->cache_slot,
                          surface->surface_id,
                          point->x,
                          point->y,
                          cache->width,
                          cache->height,
                          (unsigned long long)cache->cache_key,
                          session->graphics_current_frame_id,
                          (unsigned long long)rdp_session_trace_hash_bgra(cache->pixels.data,
                                                                          cache->width,
                                                                          cache->height,
                                                                          (size_t)cache->width * 4u));
    status = rdp_session_graphics_surface_write_bgra(session,
                                                     surface,
                                                     point->x,
                                                     point->y,
                                                     cache->width,
                                                     cache->height,
                                                     cache->pixels.data,
                                                     (size_t)cache->width * 4u,
                                                     0,
                                                     "cache_to_surface");
    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event);

static librdp_status rdp_session_display_layout_bounds(const rdp_display_control_monitor* monitors,
                                                       uint32_t monitor_count,
                                                       uint32_t* width,
                                                       uint32_t* height)
{
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    uint32_t i = 0;

    if (!monitors || monitor_count == 0 || !width || !height)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    left = monitors[0].left;
    top = monitors[0].top;
    right = (int64_t)monitors[0].left + (int64_t)monitors[0].width;
    bottom = (int64_t)monitors[0].top + (int64_t)monitors[0].height;
    for (i = 1u; i < monitor_count; i++)
    {
        int64_t monitor_right = (int64_t)monitors[i].left + (int64_t)monitors[i].width;
        int64_t monitor_bottom = (int64_t)monitors[i].top + (int64_t)monitors[i].height;

        if ((int64_t)monitors[i].left < left)
            left = monitors[i].left;
        if ((int64_t)monitors[i].top < top)
            top = monitors[i].top;
        if (monitor_right > right)
            right = monitor_right;
        if (monitor_bottom > bottom)
            bottom = monitor_bottom;
    }
    if (right <= left || bottom <= top ||
        right - left > UINT32_MAX ||
        bottom - top > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *width = (uint32_t)(right - left);
    *height = (uint32_t)(bottom - top);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_copy_display_monitors(rdp_display_control_monitor* dst,
                                                       const librdp_display_monitor* src,
                                                       uint32_t monitor_count)
{
    uint32_t i = 0;

    if (!dst || !src || monitor_count == 0 || monitor_count > LIBRDP_DISPLAY_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < monitor_count; i++)
    {
        dst[i].flags = src[i].flags;
        dst[i].left = src[i].left;
        dst[i].top = src[i].top;
        dst[i].width = src[i].width;
        dst[i].height = src[i].height;
        dst[i].physical_width = src[i].physical_width;
        dst[i].physical_height = src[i].physical_height;
        dst[i].orientation = src[i].orientation;
        dst[i].desktop_scale_factor = src[i].desktop_scale_factor;
        dst[i].device_scale_factor = src[i].device_scale_factor;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_display_control_monitors(librdp_session* session,
                                                               const rdp_display_control_monitor* monitors,
                                                               uint32_t monitor_count)
{
    rdp_buffer layout;
    uint32_t width = 0;
    uint32_t height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !monitors || monitor_count == 0 || monitor_count > LIBRDP_DISPLAY_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->display_control_ready || session->display_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&layout);
    status = rdp_display_control_write_monitor_layout_with_caps(&layout,
                                                                monitors,
                                                                monitor_count,
                                                                &session->display_control_caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_display_layout_bounds(monitors, monitor_count, &width, &height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->display_control_channel_id,
                                                       session->display_control_channel_id_bytes,
                                                       layout.data,
                                                       layout.length,
                                                       "client.display_control.layout_sent");
    rdp_buffer_free(&layout);
    if (status == LIBRDP_STATUS_OK)
    {
        session->sent_desktop_width = width;
        session->sent_desktop_height = height;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout_sent",
                        "dvc_channel_id=%u monitors=%u width=%u height=%u",
                        session->display_control_channel_id,
                        monitor_count,
                        width,
                        height);
    }
    return status;
}

static librdp_status rdp_session_send_display_control_layout(librdp_session* session,
                                                             uint32_t width,
                                                             uint32_t height)
{
    rdp_display_control_monitor monitor;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->display_control_ready || session->display_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    if (session->sent_desktop_width == width && session->sent_desktop_height == height)
        return LIBRDP_STATUS_OK;

    status = rdp_display_control_make_single_monitor(&monitor, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_display_control_monitors(session, &monitor, 1u);
    return status;
}

static librdp_status rdp_session_request_display_control_layout(librdp_session* session,
                                                                uint32_t width,
                                                                uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || width > 8192u || height > 8192u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width > session->limits.surface_max_dimension ||
        height > session->limits.surface_max_dimension)
        return rdp_session_limit_rejected(session);
    status = librdp_settings_enable_feature(session->settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;

    session->requested_desktop_width = width;
    session->requested_desktop_height = height;
    session->requested_monitor_layout_valid = 0;
    session->requested_monitor_count = 0;
    memset(session->requested_monitors, 0, sizeof(session->requested_monitors));
    status = rdp_session_send_display_control_layout(session, width, height);
    if (status == LIBRDP_STATUS_STATE)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout.local",
                        "width=%u height=%u wire=not_sent",
                        width,
                        height);
        return LIBRDP_STATUS_OK;
    }
    return status;
}

static int rdp_session_display_control_local_rejection(librdp_status status)
{
    return status == LIBRDP_STATUS_INVALID_ARGUMENT ||
           status == LIBRDP_STATUS_LIMIT_EXCEEDED ||
           status == LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_session_send_core_input_init(librdp_session* session)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->core_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&request);
    status = rdp_core_input_write_init_request(&request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->core_input_channel_id,
                                                       session->core_input_channel_id_bytes,
                                                       request.data,
                                                       request.length,
                                                       "client.core_input.init");
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.init",
                        "dvc_channel_id=%u version=%u",
                        session->core_input_channel_id,
                        RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    return status;
}

static librdp_status rdp_session_send_input_channel_ready(librdp_session* session,
                                                          const rdp_input_channel_sc_ready* ready)
{
    rdp_buffer response;
    rdp_input_channel_negotiation negotiation;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !ready || session->input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_input_channel_negotiate_client_ready(ready, 10, 0, &negotiation);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_buffer_init(&response);
    status = rdp_input_channel_write_cs_ready(&response,
                                              negotiation.flags,
                                              negotiation.protocol_version,
                                              negotiation.max_touch_contacts);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       response.data,
                                                       response.length,
                                                       "client.input_channel.ready");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->input_channel_protocol_version = negotiation.protocol_version;
        session->input_channel_max_touch_contacts = negotiation.max_touch_contacts;
        session->input_channel_supports_pen = negotiation.supports_pen;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.ready",
                        "dvc_channel_id=%u protocol_version=%u flags=%u max_contacts=%u touch=%u pen=%u timestamp_disabled=%u",
                        session->input_channel_id,
                        negotiation.protocol_version,
                        negotiation.flags,
                        negotiation.max_touch_contacts,
                        negotiation.supports_touch,
                        negotiation.supports_pen,
                        negotiation.disables_timestamp_injection);
    }
    return status;
}

static librdp_status rdp_session_send_mouse_cursor_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->mouse_cursor_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_mouse_cursor_write_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->mouse_cursor_channel_id,
                                                       session->mouse_cursor_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.mouse_cursor.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_advertise",
                        "dvc_channel_id=%u version=%u",
                        session->mouse_cursor_channel_id,
                        RDP_MOUSE_CURSOR_CAPSET_VERSION1);
    return status;
}

static librdp_status rdp_session_send_graphics_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_graphics_write_default_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.graphics.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.caps_advertise",
                        "dvc_channel_id=%u",
                        session->graphics_channel_id);
    return status;
}

static librdp_status rdp_session_send_graphics_frame_ack(librdp_session* session, uint32_t frame_id)
{
    rdp_buffer ack;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&ack);
    status = rdp_graphics_write_frame_ack(&ack,
                                          RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                          frame_id,
                                          session->graphics_frames_decoded);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       ack.data,
                                                       ack.length,
                                                       "client.graphics.frame_ack");
    rdp_buffer_free(&ack);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.frame_ack",
                        "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                        session->graphics_channel_id,
                        frame_id,
                        session->graphics_frames_decoded);
    return status;
}

/*
 * Graphics pipeline traffic is segmented, optionally bulk-compressed, and can
 * carry frame markers, cache operations, surface commands, and codec payloads
 * in one byte stream. Decode and apply in-order here so frame acknowledgements
 * reflect only work that has reached the local surface/cache state.
 */
static librdp_status rdp_session_handle_graphics_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_buffer decoded;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_graphics_decode_segmented_data(&session->graphics_decompressor, data, data_len, &decoded);
    if (status == LIBRDP_STATUS_UNSUPPORTED)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.rejected",
                        "dvc_channel_id=%u reason=bulk_compression payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    while (offset < decoded.length)
    {
        rdp_graphics_header header;
        const uint8_t* pdu = decoded.data + offset;
        size_t remaining = decoded.length - offset;

        status = rdp_graphics_parse_header(pdu, remaining, &header);
        if (status != LIBRDP_STATUS_OK)
            break;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.graphics.pdu",
                              "dvc_channel_id=%u cmd_id=%u pdu_len=%u",
                              channel_id,
                              header.cmd_id,
                              header.pdu_length);
        rdp_trace_hexdump("rdp.graphics.pdu", RDP_TRACE_SENSITIVITY_VIDEO, pdu, header.pdu_length);
        if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM)
        {
            rdp_graphics_caps_confirm confirm;

            status = rdp_graphics_parse_caps_confirm(pdu, header.pdu_length, &confirm);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (!rdp_graphics_capset_is_default_supported(&confirm.selected))
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.caps_confirm.invalid",
                                "dvc_channel_id=%u version=%u flags=%u",
                                channel_id,
                                confirm.selected.version,
                                confirm.selected.flags);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            session->graphics_selected_version = confirm.selected.version;
            session->graphics_selected_flags = confirm.selected.flags;
            session->graphics_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.caps_confirm",
                            "dvc_channel_id=%u version=%u flags=%u",
                            channel_id,
                            confirm.selected.version,
                            confirm.selected.flags);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1)
        {
            rdp_graphics_wire_to_surface_1 wire;

            status = rdp_graphics_parse_wire_to_surface_1(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED ||
                wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR ||
                wire.codec_id == RDP_GRAPHICS_CODECID_ALPHA ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ||
                wire.codec_id == RDP_GRAPHICS_CODECID_AVC444V2)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                int rendered = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED)
                {
                    status = rdp_session_graphics_surface_write_wire(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else if (wire.codec_id == RDP_GRAPHICS_CODECID_ALPHA)
                {
                    status = rdp_session_graphics_surface_apply_alpha(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ||
                         wire.codec_id == RDP_GRAPHICS_CODECID_PLANAR)
                {
                    rdp_buffer decoded_bitmap;
                    size_t decoded_stride = 0;
                    uint16_t width = (uint16_t)(wire.dest_rect.right - wire.dest_rect.left);
                    uint16_t height = (uint16_t)(wire.dest_rect.bottom - wire.dest_rect.top);

                    rdp_buffer_init(&decoded_bitmap);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC)
                    {
                        status = rdp_clearcodec_decode_bitmap(&session->clearcodec,
                                                              wire.bitmap_data,
                                                              wire.bitmap_data_length,
                                                              width,
                                                              height,
                                                              &decoded_bitmap,
                                                              &decoded_stride);
                    }
                    else
                    {
                        status = rdp_planar_decode_argb(wire.bitmap_data,
                                                        wire.bitmap_data_length,
                                                        width,
                                                        height,
                                                        &decoded_bitmap,
                                                        &decoded_stride);
                    }
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_graphics_surface_write_bgra(session,
                                                                         surface,
                                                                         wire.dest_rect.left,
                                                                         wire.dest_rect.top,
                                                                         width,
                                                                         height,
                                                                         decoded_bitmap.data,
                                                                         decoded_stride,
                                                                         wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                                         wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC ? "clearcodec" : "planar");
                    rdp_buffer_free(&decoded_bitmap);
                    if (status == LIBRDP_STATUS_UNSUPPORTED)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.rejected",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    }
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    if (decoded_stride != 0)
                        rendered = 1;
                }
                else
                {
                    rdp_avc_frame avc_frame;
                    int avc_rendered = 0;
                    const char* source = wire.codec_id == RDP_GRAPHICS_CODECID_AVC420 ? "avc420" :
                                         wire.codec_id == RDP_GRAPHICS_CODECID_AVC444 ? "avc444" :
                                                                                        "avc444v2";

                    rdp_avc_frame_init(&avc_frame);
                    if (wire.codec_id == RDP_GRAPHICS_CODECID_AVC420)
                    {
                        rdp_graphics_avc420_stream avc420;

                        status = rdp_graphics_parse_avc420_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc420);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_420(session->avc,
                                                        &avc420,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc420.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    else
                    {
                        rdp_graphics_avc444_stream avc444;

                        status = rdp_graphics_parse_avc444_stream(wire.bitmap_data,
                                                                  wire.bitmap_data_length,
                                                                  &avc444);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_avc_decode_444(session->avc,
                                                        wire.codec_id,
                                                        &avc444,
                                                        surface->width,
                                                        surface->height,
                                                        &avc_frame);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc444.stream1.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK && avc444.lc == RDP_GRAPHICS_AVC444_LC_BOTH)
                            status = rdp_session_graphics_surface_write_avc_regions(
                                session,
                                surface,
                                &avc444.stream2.meta,
                                &avc_frame,
                                wire.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                source);
                        if (status == LIBRDP_STATUS_OK)
                            avc_rendered = 1;
                    }
                    if (status == LIBRDP_STATUS_UNSUPPORTED)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.codec.rejected",
                                        "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.codec_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    }
                    if (status == LIBRDP_STATUS_OK && avc_rendered)
                        rendered = 1;
                    rdp_avc_frame_free(&avc_frame);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                }
                if (rendered)
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.wire_to_surface",
                                          "dvc_channel_id=%u surface_id=%u codec_id=%u x=%u y=%u width=%u height=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_id,
                                          wire.dest_rect.left,
                                          wire.dest_rect.top,
                                          (unsigned)(wire.dest_rect.right - wire.dest_rect.left),
                                          (unsigned)(wire.dest_rect.bottom - wire.dest_rect.top));
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.rejected",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.bitmap_data_length);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2)
        {
            rdp_graphics_wire_to_surface_2 wire;

            status = rdp_graphics_parse_wire_to_surface_2(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                rdp_graphics_progressive_stream progressive;
                uint32_t rendered_tiles = 0;
                uint32_t failed_tiles = 0;
                uint32_t missing_tiles = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_graphics_progressive_parse_stream(wire.bitmap_data,
                                                               wire.bitmap_data_length,
                                                               &progressive);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_progressive_render_stream(session,
                                                                           channel_id,
                                                                           surface,
                                                                           &wire,
                                                                           &rendered_tiles,
                                                                           &failed_tiles,
                                                                           &missing_tiles);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.graphics.progressive",
                                          "dvc_channel_id=%u surface_id=%u context_id=%u blocks=%u regions=%u tiles=%u simple_tiles=%u first_tiles=%u upgrade_tiles=%u rendered_tiles=%u failed_tiles=%u missing_tiles=%u",
                                          channel_id,
                                          wire.surface_id,
                                          wire.codec_context_id,
                                          progressive.block_count,
                                          progressive.region_count,
                                          progressive.tile_count,
                                          progressive.simple_tile_count,
                                          progressive.first_tile_count,
                                          progressive.upgrade_tile_count,
                                          rendered_tiles,
                                          failed_tiles,
                                          missing_tiles);
                }
                else
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.progressive.rejected",
                                    "dvc_channel_id=%u surface_id=%u context_id=%u payload_len=%u parser_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
            }
            else if (wire.codec_id == RDP_GRAPHICS_CODECID_CAVIDEO)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_session_graphics_surface_write_rfx(session,
                                                                surface,
                                                                wire.bitmap_data,
                                                                wire.bitmap_data_length,
                                                                wire.pixel_format);
                if (status == LIBRDP_STATUS_UNSUPPORTED)
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.codec.rejected",
                                    "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u decoder_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.rejected",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.codec_context_id,
                                wire.bitmap_data_length);
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT)
        {
            rdp_graphics_delete_encoding_context context;

            status = rdp_graphics_parse_delete_encoding_context(pdu, header.pdu_length, &context);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.encoding_context.delete",
                            "dvc_channel_id=%u surface_id=%u context_id=%u",
                            channel_id,
                            context.surface_id,
                            context.codec_context_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE)
        {
            rdp_graphics_surface_to_surface surface_to_surface;
            rdp_session_graphics_surface* source = NULL;
            rdp_session_graphics_surface* dest = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_surface_to_surface(pdu, header.pdu_length, &surface_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            source = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_src);
            dest = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_dest);
            if (!source || !dest)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < surface_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(surface_to_surface.dest_points + ((size_t)i * 4u),
                                                    surface_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_surface_copy(session,
                                                               source,
                                                               dest,
                                                               &surface_to_surface.rect_src,
                                                               &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_surface",
                                  "dvc_channel_id=%u source_id=%u dest_id=%u points=%u src_left=%u src_top=%u src_right=%u src_bottom=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  surface_to_surface.surface_id_src,
                                  surface_to_surface.surface_id_dest,
                                  surface_to_surface.dest_points_count,
                                  surface_to_surface.rect_src.left,
                                  surface_to_surface.rect_src.top,
                                  surface_to_surface.rect_src.right,
                                  surface_to_surface.rect_src.bottom,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE)
        {
            rdp_graphics_surface_to_cache surface_to_cache;

            status = rdp_graphics_parse_surface_to_cache(pdu, header.pdu_length, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_cache_store(session, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.surface_to_cache",
                                  "dvc_channel_id=%u surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u",
                                  channel_id,
                                  surface_to_cache.surface_id,
                                  surface_to_cache.cache_slot,
                                  (unsigned)(surface_to_cache.rect_src.right - surface_to_cache.rect_src.left),
                                  (unsigned)(surface_to_cache.rect_src.bottom - surface_to_cache.rect_src.top),
                                  surface_to_cache.rect_src.left,
                                  surface_to_cache.rect_src.top,
                                  surface_to_cache.rect_src.right,
                                  surface_to_cache.rect_src.bottom);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE)
        {
            rdp_graphics_cache_to_surface cache_to_surface;
            rdp_session_graphics_cache_entry* cache = NULL;
            rdp_session_graphics_surface* surface = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_cache_to_surface(pdu, header.pdu_length, &cache_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            cache = rdp_session_graphics_cache_find(session, cache_to_surface.cache_slot);
            surface = rdp_session_graphics_surface_find(session, cache_to_surface.surface_id);
            if (!cache || !surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < cache_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(cache_to_surface.dest_points + ((size_t)i * 4u),
                                                    cache_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_cache_copy_to_surface(session, cache, surface, &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.cache_to_surface",
                                  "dvc_channel_id=%u cache_slot=%u surface_id=%u points=%u cache_width=%u cache_height=%u last_dst_x=%u last_dst_y=%u",
                                  channel_id,
                                  cache_to_surface.cache_slot,
                                  cache_to_surface.surface_id,
                                  cache_to_surface.dest_points_count,
                                  cache->width,
                                  cache->height,
                                  last_point.x,
                                  last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY)
        {
            rdp_graphics_evict_cache_entry evict;

            status = rdp_graphics_parse_evict_cache_entry(pdu, header.pdu_length, &evict);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_cache_evict(session, evict.cache_slot);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.cache.evict",
                            "dvc_channel_id=%u cache_slot=%u",
                            channel_id,
                            evict.cache_slot);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_RESET_GRAPHICS)
        {
            rdp_graphics_reset reset;

            status = rdp_graphics_parse_reset(pdu, header.pdu_length, &reset);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_dirty_reset(session);
            rdp_session_graphics_surfaces_clear(session);
            if (reset.width != librdp_surface_width(session->surface) ||
                reset.height != librdp_surface_height(session->surface))
            {
                status = librdp_surface_resize(session->surface, reset.width, reset.height);
                if (status != LIBRDP_STATUS_OK)
                    break;
                {
                    librdp_rect rect;

                    rect.x = 0;
                    rect.y = 0;
                    rect.width = reset.width;
                    rect.height = reset.height;
                    rdp_session_emit_graphics_update(session,
                                                     LIBRDP_GRAPHICS_UPDATE_DESKTOP_RESIZE,
                                                     0,
                                                     session->graphics_current_frame_id,
                                                     &rect,
                                                     LIBRDP_PIXEL_FORMAT_BGRA32,
                                                     NULL,
                                                     0);
                }
                rdp_session_emit_surface_invalidated(session, 0, 0, reset.width, reset.height);
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.reset",
                            "dvc_channel_id=%u width=%u height=%u monitors=%u",
                            channel_id,
                            reset.width,
                            reset.height,
                            reset.monitor_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CREATE_SURFACE)
        {
            rdp_graphics_create_surface create_surface;

            status = rdp_graphics_parse_create_surface(pdu, header.pdu_length, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_create(session, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.create",
                            "dvc_channel_id=%u surface_id=%u width=%u height=%u pixel_format=%u",
                            channel_id,
                            create_surface.surface_id,
                            create_surface.width,
                            create_surface.height,
                            create_surface.pixel_format);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_SURFACE)
        {
            rdp_graphics_delete_surface delete_surface;

            status = rdp_graphics_parse_delete_surface(pdu, header.pdu_length, &delete_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_surface_delete(session, delete_surface.surface_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.delete",
                            "dvc_channel_id=%u surface_id=%u",
                            channel_id,
                            delete_surface.surface_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT)
        {
            rdp_graphics_map_surface_to_output map;

            status = rdp_graphics_parse_map_surface_to_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT)
        {
            rdp_graphics_map_surface_to_scaled_output map;

            status = rdp_graphics_parse_map_surface_to_scaled_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map_scaled(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_scaled_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u target_width=%u target_height=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y,
                            map.target_width,
                            map.target_height);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SOLIDFILL)
        {
            rdp_graphics_solid_fill solid_fill;
            rdp_session_graphics_surface* surface = NULL;
            uint16_t i = 0;

            status = rdp_graphics_parse_solid_fill(pdu, header.pdu_length, &solid_fill);
            if (status != LIBRDP_STATUS_OK)
                break;
            surface = rdp_session_graphics_surface_find(session, solid_fill.surface_id);
            if (!surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < solid_fill.rect_count; i++)
            {
                rdp_graphics_rect16 rect;

                status = rdp_graphics_parse_rect16(solid_fill.rects + ((size_t)i * 8u),
                                                   solid_fill.rects_len - ((size_t)i * 8u),
                                                   &rect);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_graphics_surface_fill(session, surface, &rect, solid_fill.fill_pixel);
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.solid_fill",
                            "dvc_channel_id=%u surface_id=%u rects=%u",
                            channel_id,
                            solid_fill.surface_id,
                            solid_fill.rect_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_START_FRAME)
        {
            rdp_graphics_start_frame start_frame;

            status = rdp_graphics_parse_start_frame(pdu, header.pdu_length, &start_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_current_frame_id = start_frame.frame_id;
            session->graphics_dirty_pending = 0;
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                            start_frame.frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.start",
                                  "dvc_channel_id=%u frame_id=%u timestamp=%u",
                                  channel_id,
                                  start_frame.frame_id,
                                  start_frame.timestamp);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_END_FRAME)
        {
            rdp_graphics_end_frame end_frame;

            status = rdp_graphics_parse_end_frame(pdu, header.pdu_length, &end_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_session_metric_add(&session->metrics.frames, 1);
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                            end_frame.frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.graphics.frame.end",
                                  "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                                  channel_id,
                                  end_frame.frame_id,
                                  session->graphics_frames_decoded);
            status = rdp_session_send_graphics_frame_ack(session, end_frame.frame_id);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        offset += header.pdu_length;
    }

    rdp_buffer_free(&decoded);
    return status;
}

static librdp_status rdp_session_join_mcs_channel(librdp_session* session,
                                                  uint16_t channel_id,
                                                  const char* name,
                                                  rdp_buffer* request,
                                                  rdp_buffer* reply)
{
    const uint8_t* pdu = NULL;
    size_t pdu_len = 0;
    rdp_mcs_channel_join_confirm confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(request);
    rdp_buffer_init(request);
    status = rdp_mcs_write_channel_join_request(request, session->mcs_user_id, channel_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.request",
                    "channel_id=%u name=%s",
                    channel_id,
                    name ? name : "");
    status = rdp_session_write_mcs_pdu(session, request, "mcs.channel_join.request", 1);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_buffer_free(reply);
    rdp_buffer_init(reply);
    status = rdp_session_read_mcs_pdu(session, reply, &pdu, &pdu_len, "mcs.channel_join.confirm");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_mcs_parse_channel_join_confirm(pdu, pdu_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (confirm.result != 0 || confirm.initiator != session->mcs_user_id || confirm.channel_id != channel_id)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.channel_join.failed",
                        "result=%u initiator=%u channel_id=%u",
                        confirm.result,
                        confirm.initiator,
                        confirm.channel_id);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.confirm",
                    "channel_id=%u name=%s",
                    confirm.channel_id,
                    name ? name : "");
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_activation_finalization(librdp_session* session, uint32_t share_id)
{
    rdp_buffer sync;
    rdp_buffer cooperate;
    rdp_buffer request;
    rdp_buffer persistent_keys;
    rdp_buffer font_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&sync);
    rdp_buffer_init(&cooperate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&persistent_keys);
    rdp_buffer_init(&font_list);

    status = rdp_slowpath_write_client_synchronize(&sync, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &sync, "rdp.activation.client_synchronize");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_synchronize", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&cooperate, share_id, session->mcs_user_id, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &cooperate, "rdp.activation.client_control_cooperate");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_cooperate", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&request, share_id, session->mcs_user_id, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &request, "rdp.activation.client_control_request");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_request", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_persistent_key_list(&persistent_keys, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &persistent_keys, "rdp.activation.client_persistent_key_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_persistent_key_list", "share_id=%u entries=0", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_font_list(&font_list, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &font_list, "rdp.activation.client_font_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_font_list", "share_id=%u", share_id);

    rdp_buffer_free(&font_list);
    rdp_buffer_free(&persistent_keys);
    rdp_buffer_free(&request);
    rdp_buffer_free(&cooperate);
    rdp_buffer_free(&sync);
    return status;
}

static librdp_status rdp_session_send_active_output_request(librdp_session* session)
{
    rdp_buffer suppress;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!session || !session->surface || session->share_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    if (width == 0 || height == 0 || width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&suppress);
    status = rdp_slowpath_write_client_suppress_output(&suppress,
                                                       session->share_id,
                                                       session->mcs_user_id,
                                                       1,
                                                       0,
                                                       0,
                                                       (uint16_t)width,
                                                       (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &suppress, "rdp.activation.client_suppress_output");
    rdp_buffer_free(&suppress);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.client_suppress_output",
                    "share_id=%u width=%u height=%u",
                    session->share_id,
                    width,
                    height);
    return librdp_session_refresh(session, 0, 0, width, height);
}

static librdp_status rdp_session_trace_slowpath_data_pdu(librdp_session* session, const rdp_slowpath_data_pdu* data_pdu)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
    {
        rdp_slowpath_font_map font_map;

        status = rdp_slowpath_parse_font_map(data_pdu->payload, data_pdu->payload_len, &font_map);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.activation.font_map",
                            "entries=%u total_entries=%u flags=%u entry_size=%u",
                            font_map.number_entries,
                            font_map.total_entries,
                            font_map.map_flags,
                            font_map.entry_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_active_output_request(session);
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
    {
        uint32_t error_info = 0;

        status = rdp_slowpath_parse_set_error_info(data_pdu->payload, data_pdu->payload_len, &error_info);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.set_error_info", "error_info=%u", error_info);
            if (error_info != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
    {
        rdp_slowpath_save_session_info info;

        status = rdp_slowpath_parse_save_session_info(data_pdu->payload, data_pdu->payload_len, &info);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.save_session_info",
                            "info_type=%u data_len=%u",
                            info.info_type,
                            (unsigned)info.data_len);
    }

    return status;
}

/*
 * Handle mouse-cursor channel messages. Shape, cached-pointer, and visibility
 * updates are applied in protocol order and emitted to the viewer only after
 * cache state is valid.
 */
static librdp_status rdp_session_handle_mouse_cursor_message(librdp_session* session,
                                                             uint32_t channel_id,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_mouse_cursor_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_mouse_cursor_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM)
    {
        rdp_mouse_cursor_capset capset;

        status = rdp_mouse_cursor_parse_caps_confirm(data, data_len, &capset);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->mouse_cursor_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_confirm",
                        "dvc_channel_id=%u version=%u size=%u",
                        channel_id,
                        capset.version,
                        capset.size);
        return LIBRDP_STATUS_OK;
    }

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE)
    {
        rdp_pointer_update update;

        status = rdp_mouse_cursor_parse_update(data, data_len, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.update.rejected",
                            "dvc_channel_id=%u update_type=%u payload_len=%u",
                            channel_id,
                            header.update_type,
                            (unsigned)data_len);
            return LIBRDP_STATUS_OK;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.update",
                        "dvc_channel_id=%u update_type=%u kind=%u cache_index=%u width=%u height=%u",
                        channel_id,
                        header.update_type,
                        update.kind,
                        update.cache_index,
                        update.width,
                        update.height);
        status = rdp_session_pointer_apply_update(session, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.shape.rejected",
                            "dvc_channel_id=%u update_type=%u xor_bpp=%u width=%u height=%u",
                            channel_id,
                            header.update_type,
                            update.xor_bpp,
                            update.width,
                            update.height);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        return status;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.mouse_cursor.pdu.ignored",
                    "dvc_channel_id=%u pdu_type=%u update_type=%u payload_len=%u",
                    channel_id,
                    header.pdu_type,
                    header.update_type,
                    (unsigned)data_len);
    return LIBRDP_STATUS_OK;
}

/*
 * Clipboard requests and responses share one channel and several asynchronous
 * transactions. This dispatcher keeps pending format/file requests correlated
 * with their stream IDs and copies only the data that must outlive the PDU.
 */
static librdp_status rdp_session_handle_clipboard_message(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_clipboard_packet packet;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_clipboard_parse_packet(data, data_len, &packet);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.clipboard.pdu",
                          "channel_id=%u type=%u flags=%u payload_len=%u",
                          session->clipboard_channel_id,
                          packet.type,
                          packet.flags,
                          (unsigned)packet.payload_len);

    rdp_buffer_init(&response);
    if (packet.type == RDP_CLIPBOARD_CB_CLIP_CAPS)
    {
        rdp_clipboard_capabilities caps;

        status = rdp_clipboard_parse_capabilities(&packet, &caps);
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_general_flags = caps.has_general ? caps.general.general_flags : 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.capabilities.server",
                            "channel_id=%u has_general=%u flags=%u",
                            session->clipboard_channel_id,
                            caps.has_general ? 1u : 0u,
                            session->clipboard_general_flags);
            status = rdp_session_send_clipboard_handshake(session);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_MONITOR_READY)
    {
        status = rdp_session_send_clipboard_handshake(session);
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_LIST)
    {
        rdp_clipboard_format_list list;
        librdp_clipboard_format formats[RDP_SESSION_CLIPBOARD_MAX_FORMATS];
        librdp_event event;
        uint32_t count = 0;
        uint32_t stored = 0;
        uint32_t i = 0;
        int long_names = (packet.flags & RDP_CLIPBOARD_CB_ASCII_NAMES) == 0;

        memset(formats, 0, sizeof(formats));
        status = rdp_clipboard_parse_format_list(&packet, &list);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_clipboard_format_list_entry_count(&list, long_names, &count);
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_remote_format_count = 0;
            for (i = 0; i < count && i < RDP_SESSION_CLIPBOARD_MAX_FORMATS; i++)
            {
                rdp_clipboard_format_entry item;

                status = rdp_clipboard_format_list_get_entry(&list, long_names, i, &item);
                if (status != LIBRDP_STATUS_OK)
                    break;
                formats[i].format_id = item.format_id;
                formats[i].name = item.name;
                formats[i].name_len = item.name_len;
                session->clipboard_remote_formats[i] = item.format_id;
                stored++;
            }
        }
        if (status == LIBRDP_STATUS_OK)
        {
            session->clipboard_remote_format_count = stored;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_list",
                            "channel_id=%u count=%u stored=%u long_names=%u",
                            session->clipboard_channel_id,
                            count,
                            stored,
                            long_names ? 1u : 0u);
            status = rdp_clipboard_write_format_list_response(&response, 1);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.format_list_response");
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_FORMATS;
            event.data.clipboard_formats.formats = formats;
            event.data.clipboard_formats.count = stored;
            event.data.clipboard_formats.total_count = count;
            rdp_session_emit(session, &event);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST)
    {
        rdp_clipboard_format_data_request request;
        librdp_event event;
        uint8_t available = 0;
        size_t response_len = 0;

        status = rdp_clipboard_parse_format_data_request(&packet, &request);
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_REQUEST;
            event.data.clipboard_request.format_id = request.format_id;
            rdp_session_emit(session, &event);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_data_request",
                            "channel_id=%u format_id=%u available=%u data_len=%u",
                            session->clipboard_channel_id,
                            request.format_id,
                            0u,
                            0u);
            status = rdp_session_clipboard_write_local_data_response(session,
                                                                     request.format_id,
                                                                     &response,
                                                                     &available,
                                                                     &response_len);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.clipboard.format_data_response.local",
                                "channel_id=%u format_id=%u available=%u data_len=%u",
                                session->clipboard_channel_id,
                                request.format_id,
                                available,
                                (unsigned)response_len);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.format_data_response");
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE)
    {
        rdp_clipboard_format_data_response data_response;
        librdp_event event;

        status = rdp_clipboard_parse_format_data_response(&packet, &data_response);
        if (status == LIBRDP_STATUS_OK)
        {
            if (session->clipboard_pending_request_format_id == 0)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.clipboard.format_data_response.late",
                                "channel_id=%u ok=%u data_len=%u",
                                session->clipboard_channel_id,
                                data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                                (unsigned)data_response.data_len);
                rdp_buffer_free(&response);
                return LIBRDP_STATUS_OK;
            }
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_DATA;
            event.data.clipboard_data.format_id = session->clipboard_pending_request_format_id;
            event.data.clipboard_data.data = data_response.data;
            event.data.clipboard_data.data_len = data_response.data_len;
            event.data.clipboard_data.ok =
                data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1 : 0;
            rdp_session_emit(session, &event);
            session->clipboard_pending_request_format_id = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.format_data_response",
                            "channel_id=%u ok=%u format_id=%u data_len=%u",
                            session->clipboard_channel_id,
                            data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                            event.data.clipboard_data.format_id,
                            (unsigned)data_response.data_len);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FILECONTENTS_REQUEST)
    {
        rdp_clipboard_file_contents_request request;
        uint8_t ok = 0;
        size_t file_data_len = 0;

        status = rdp_clipboard_parse_file_contents_request(&packet, &request);
        if (status == LIBRDP_STATUS_OK)
        {
            status = rdp_session_clipboard_write_file_contents(session,
                                                               &request,
                                                               &response,
                                                               &ok,
                                                               &file_data_len);
        }
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.filecontents_request",
                            "channel_id=%u stream_id=%u index=%d flags=%u requested=%u ok=%u data_len=%u",
                            session->clipboard_channel_id,
                            request.stream_id,
                            request.lindex,
                            request.flags,
                            request.requested,
                            ok,
                            (unsigned)file_data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_clipboard_packet(session, &response, "client.clipboard.filecontents_response");
    }
    else if (packet.type == RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE)
    {
        rdp_clipboard_file_contents_response file_response;
        rdp_session_clipboard_file_request pending;
        rdp_session_clipboard_file_request* request = NULL;
        librdp_event event;

        status = rdp_clipboard_parse_file_contents_response(&packet, &file_response);
        if (status == LIBRDP_STATUS_OK)
        {
            memset(&pending, 0, sizeof(pending));
            request = rdp_session_clipboard_file_request_find(session, file_response.stream_id);
            if (request)
            {
                pending = *request;
                memset(request, 0, sizeof(*request));
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.clipboard.filecontents_response.late",
                                "channel_id=%u ok=%u stream_id=%u data_len=%u",
                                session->clipboard_channel_id,
                                file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                                file_response.stream_id,
                                (unsigned)file_response.data_len);
                rdp_buffer_free(&response);
                return LIBRDP_STATUS_OK;
            }
            memset(&event, 0, sizeof(event));
            event.type = LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS;
            event.data.clipboard_file_contents.stream_id = file_response.stream_id;
            event.data.clipboard_file_contents.file_index = pending.file_index;
            event.data.clipboard_file_contents.flags = pending.flags;
            event.data.clipboard_file_contents.position = pending.position;
            event.data.clipboard_file_contents.requested = pending.requested;
            event.data.clipboard_file_contents.data = file_response.data;
            event.data.clipboard_file_contents.data_len = file_response.data_len;
            event.data.clipboard_file_contents.ok =
                file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1 : 0;
            rdp_session_emit(session, &event);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.filecontents_response",
                            "channel_id=%u ok=%u stream_id=%u index=%d flags=%u data_len=%u pending=%u",
                            session->clipboard_channel_id,
                            file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK ? 1u : 0u,
                            file_response.stream_id,
                            pending.file_index,
                            pending.flags,
                            (unsigned)file_response.data_len,
                            1u);
        }
    }
    else if (packet.type == RDP_CLIPBOARD_CB_LOCK_CLIPDATA)
    {
        rdp_clipboard_lock lock;

        status = rdp_clipboard_parse_lock(&packet, &lock);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.lock",
                            "channel_id=%u clip_data_id=%u",
                            session->clipboard_channel_id,
                            lock.clip_data_id);
    }
    else if (packet.type == RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA)
    {
        rdp_clipboard_lock lock;

        status = rdp_clipboard_parse_unlock(&packet, &lock);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.clipboard.unlock",
                            "channel_id=%u clip_data_id=%u",
                            session->clipboard_channel_id,
                            lock.clip_data_id);
    }
    else
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.clipboard.pdu.ignored",
                        "channel_id=%u type=%u payload_len=%u",
                        session->clipboard_channel_id,
                        packet.type,
                        (unsigned)packet.payload_len);
    }

    rdp_buffer_free(&response);
    return status;
}

static int rdp_session_webauthn_feature_enabled(const librdp_session* session)
{
    return rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_WEBAUTHN) != 0;
}

static const char* rdp_session_webauthn_provider(const librdp_session* session)
{
    if (!session || !session->settings)
        return NULL;
    return librdp_settings_webauthn_provider(session->settings);
}

static int rdp_session_webauthn_mock_enabled(const librdp_session* session)
{
    const char* provider = NULL;

    if (!rdp_session_webauthn_feature_enabled(session))
        return 0;
    provider = rdp_session_webauthn_provider(session);
    return !provider || strcmp(provider, "mock") == 0 || strncmp(provider, "mock=", 5u) == 0;
}

static int rdp_session_webauthn_fido2_enabled(const librdp_session* session)
{
    const char* provider = NULL;

    if (!rdp_session_webauthn_feature_enabled(session))
        return 0;
    provider = rdp_session_webauthn_provider(session);
    return provider && (strcmp(provider, "fido2") == 0 || strncmp(provider, "fido2=", 6u) == 0);
}

static const char* rdp_session_webauthn_mock_path(const librdp_session* session)
{
    const char* provider = NULL;

    provider = rdp_session_webauthn_provider(session);
    if (!provider || strncmp(provider, "mock=", 5u) != 0)
        return NULL;
    return provider + 5u;
}

static const char* rdp_session_webauthn_fido2_requested_path(const librdp_session* session)
{
    const char* provider = rdp_session_webauthn_provider(session);

    if (!provider || strncmp(provider, "fido2=", 6u) != 0 || provider[6] == '\0')
        return NULL;
    return provider + 6u;
}

static int rdp_session_webauthn_rp_id_allowed(const librdp_session* session,
                                              const rdp_webauthn_request* request)
{
    uint32_t count = 0;

    if (!session || !session->settings || !request)
        return 0;
    count = librdp_settings_webauthn_rp_id_count(session->settings);
    if (count == 0)
        return 1;
    if (!request->rp_id || request->rp_id_len == 0)
        return 0;
    for (uint32_t i = 0; i < count; i++)
    {
        const char* allowed = librdp_settings_webauthn_rp_id(session->settings, i);
        size_t allowed_len = allowed ? strlen(allowed) : 0;

        if (allowed_len == request->rp_id_len &&
            memcmp(allowed, request->rp_id, request->rp_id_len) == 0)
            return 1;
    }
    return 0;
}

static void rdp_session_webauthn_init_mock_info(rdp_webauthn_device_info* info)
{
    static const uint8_t guid[RDP_WEBAUTHN_GUID_LENGTH] = {
        0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x77,
        0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x31
    };

    if (!info)
        return;
    memset(info, 0, sizeof(*info));
    info->provider_type = "mock";
    info->provider_name = "local mock";
    info->device_path = "mock://local";
    info->manufacturer = "librdp";
    info->product = "librdp mock authenticator";
    info->aaguid = guid;
    info->aaguid_len = sizeof(guid);
    info->max_msg_size = RDP_WEBAUTHN_MAX_MESSAGE;
    info->transports = 1u;
}

static librdp_status rdp_session_webauthn_load_mock_response(const char* path, rdp_buffer* response)
{
    FILE* file = NULL;
    uint8_t chunk[4096];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!path || !path[0] || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    file = fopen(path, "rb");
    if (!file)
        return LIBRDP_STATUS_STATE;
    while (!feof(file))
    {
        size_t count = fread(chunk, 1u, sizeof(chunk), file);

        if (count > 0)
        {
            if (response->length > RDP_WEBAUTHN_MAX_MESSAGE - count)
            {
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
                break;
            }
            status = rdp_buffer_append(response, chunk, count);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        if (ferror(file))
        {
            status = LIBRDP_STATUS_STATE;
            break;
        }
    }
    if (fclose(file) != 0 && status == LIBRDP_STATUS_OK)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK && response->length == 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    return status;
}

/*
 * WebAuthn requests cross a trust boundary: malformed CBOR/RPC data must turn
 * into a protocol failure response, while provider failures must not leak host
 * authenticator details beyond the HRESULT-style status and response payload.
 */
static librdp_status rdp_session_handle_webauthn_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         uint8_t channel_id_bytes,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_webauthn_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t hresult = RDP_SESSION_HRESULT_OK;
    int mock_enabled = 0;
    int fido2_enabled = 0;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    rdp_buffer_init(&response);
    mock_enabled = rdp_session_webauthn_mock_enabled(session);
    fido2_enabled = rdp_session_webauthn_fido2_enabled(session);
    status = rdp_webauthn_parse_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_FAIL, NULL, 0);
        hresult = RDP_SESSION_HRESULT_FAIL;
    }
    else if (!rdp_session_webauthn_feature_enabled(session))
    {
        if (request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN)
        {
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                               NULL,
                                                               0);
            hresult = RDP_SESSION_HRESULT_OK;
        }
        else
        {
            status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_FAIL, NULL, 0);
            hresult = RDP_SESSION_HRESULT_FAIL;
        }
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_API_VERSION)
    {
        status = rdp_webauthn_write_u32_response(&response, RDP_SESSION_HRESULT_OK, 4u);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_IUVPAA)
    {
        status = rdp_webauthn_write_u32_response(&response,
                                                 RDP_SESSION_HRESULT_OK,
                                                 (mock_enabled || fido2_enabled) ? 1u : 0u);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_CANCEL)
    {
        status = rdp_webauthn_write_response(&response, RDP_SESSION_HRESULT_OK, NULL, 0);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN &&
             !rdp_session_webauthn_rp_id_allowed(session, &request))
    {
        status = rdp_webauthn_write_authenticator_response(&response,
                                                           RDP_SESSION_HRESULT_OK,
                                                           RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                           NULL,
                                                           0);
        hresult = RDP_SESSION_HRESULT_OK;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.rp_id.denied",
                        "rp_id_len=%u allowlist_count=%u",
                        (unsigned)request.rp_id_len,
                        librdp_settings_webauthn_rp_id_count(session->settings));
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_GET_CREDENTIALS)
    {
        status = rdp_webauthn_write_empty_array_response(&response, RDP_SESSION_HRESULT_OK);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_GET_AUTHENTICATOR_LIST)
    {
        rdp_webauthn_backend_fido2_device fido2_device;
        rdp_webauthn_device_info mock_info;
        const rdp_webauthn_device_info* devices = NULL;
        const char* requested_path = rdp_session_webauthn_fido2_requested_path(session);
        uint32_t device_count = 0;

        memset(&fido2_device, 0, sizeof(fido2_device));
        memset(&mock_info, 0, sizeof(mock_info));
        if (mock_enabled)
        {
            rdp_session_webauthn_init_mock_info(&mock_info);
            devices = &mock_info;
            device_count = 1u;
        }
        else if (fido2_enabled &&
                 rdp_webauthn_backend_select_fido2_device(requested_path, &fido2_device) ==
                     LIBRDP_STATUS_OK)
        {
            devices = &fido2_device.info;
            device_count = 1u;
        }
        status = rdp_webauthn_write_authenticator_list_response(&response,
                                                                RDP_SESSION_HRESULT_OK,
                                                                devices,
                                                                device_count);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.authenticator_list",
                        "count=%u mock=%u fido2=%u",
                        device_count,
                        mock_enabled ? 1u : 0u,
                        fido2_enabled ? 1u : 0u);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN && mock_enabled)
    {
        const char* mock_path = rdp_session_webauthn_mock_path(session);
        rdp_buffer mock_response;

        rdp_buffer_init(&mock_response);
        if (mock_path)
            status = rdp_session_webauthn_load_mock_response(mock_path, &mock_response);
        if (status == LIBRDP_STATUS_OK && mock_response.length > 0)
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               mock_response.data[0],
                                                               mock_response.data + 1u,
                                                               mock_response.length - 1u);
        else if (status == LIBRDP_STATUS_OK)
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                               NULL,
                                                               0);
        else
        {
            status = rdp_webauthn_write_authenticator_response(&response,
                                                               RDP_SESSION_HRESULT_OK,
                                                               RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                               NULL,
                                                               0);
        }
        hresult = RDP_SESSION_HRESULT_OK;
        rdp_buffer_free(&mock_response);
    }
    else if (request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN && fido2_enabled)
    {
        rdp_webauthn_backend_fido2_device device;
        rdp_buffer ctap_response;
        librdp_status fido2_status = LIBRDP_STATUS_OK;
        const char* requested_path = rdp_session_webauthn_fido2_requested_path(session);

        rdp_buffer_init(&ctap_response);
        fido2_status =
            rdp_webauthn_backend_fido2_exchange(requested_path, &request, &device, &ctap_response);
        if (fido2_status == LIBRDP_STATUS_OK && ctap_response.length > 0)
            status = rdp_webauthn_write_authenticator_response_ex(&response,
                                                                  RDP_SESSION_HRESULT_OK,
                                                                  &device.info,
                                                                  ctap_response.data[0],
                                                                  ctap_response.data + 1u,
                                                                  ctap_response.length - 1u);
        else
            status = rdp_webauthn_write_authenticator_response_ex(&response,
                                                                  RDP_SESSION_HRESULT_OK,
                                                                  &device.info,
                                                                  RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                                  NULL,
                                                                  0);
        hresult = RDP_SESSION_HRESULT_OK;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.fido2.response",
                        "exchange_status=%s ctap_len=%u response_status=%s",
                        librdp_status_string(fido2_status),
                        (unsigned)ctap_response.length,
                        librdp_status_string(status));
        rdp_buffer_free(&ctap_response);
    }
    else
    {
        status = rdp_webauthn_write_authenticator_response(&response,
                                                           RDP_SESSION_HRESULT_OK,
                                                           RDP_SESSION_CTAP2_ERR_OPERATION_DENIED,
                                                           NULL,
                                                           0);
        hresult = RDP_SESSION_HRESULT_OK;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       channel_id,
                                                       channel_id_bytes,
                                                       response.data,
                                                       response.length,
                                                       "client.webauthn.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.webauthn.pdu",
                    "dvc_channel_id=%u command=%u request_len=%u response_len=%u hresult=%u mock=%u fido2=%u status=%s",
                    channel_id,
                    status == LIBRDP_STATUS_OK ? request.command : 0u,
                    (unsigned)data_len,
                    (unsigned)response.length,
                    hresult,
                    mock_enabled ? 1u : 0u,
                    fido2_enabled ? 1u : 0u,
                    librdp_status_string(status));
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_auth_redirection_send_payload(librdp_session* session,
                                                               uint32_t channel_id,
                                                               uint8_t channel_id_bytes,
                                                               uint32_t package,
                                                               const void* payload,
                                                               size_t payload_len)
{
    rdp_buffer encoded;
    rdp_buffer encrypted;
    rdp_buffer outer;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!payload && payload_len > 0) || !session->credssp_security_ready)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&encoded);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&outer);
    status = rdp_auth_redirection_write_encoded_payload(&encoded, package, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_wrap(&session->credssp_security,
                                       encoded.data,
                                       encoded.length,
                                       &encrypted);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_write_outer_packet(&outer, encrypted.data, encrypted.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       channel_id,
                                                       channel_id_bytes,
                                                       outer.data,
                                                       outer.length,
                                                       "client.auth_redirection.response");
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.auth_redirection.response",
                    "dvc_channel_id=%u package=%u payload_len=%u encrypted_len=%u outer_len=%u status=%s",
                    channel_id,
                    package,
                    (unsigned)payload_len,
                    (unsigned)encrypted.length,
                    (unsigned)outer.length,
                    librdp_status_string(status));
    rdp_buffer_free(&outer);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&encoded);
    return status;
}

static uint32_t rdp_session_auth_redirection_response_status(
    const rdp_auth_redirection_call_message* call)
{
    if (!call)
        return RDP_SESSION_HRESULT_FAIL;
    if (call->kind == RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION ||
        call->call.call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS)
        return RDP_SESSION_HRESULT_OK;
    return RDP_SESSION_HRESULT_FAIL;
}

/*
 * Handle authentication-redirection channel messages. Request IDs, credential
 * blobs, and completion status remain correlated while sensitive fields are
 * kept out of trace output.
 */
static librdp_status rdp_session_handle_auth_redirection_message(librdp_session* session,
                                                                 uint32_t channel_id,
                                                                 uint8_t channel_id_bytes,
                                                                 const uint8_t* data,
                                                                 size_t data_len)
{
    rdp_auth_redirection_outer_packet outer;
    rdp_auth_redirection_encoded_payload encoded;
    rdp_auth_redirection_call_message call;
    rdp_buffer plain;
    rdp_buffer response_payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t response_status = RDP_SESSION_HRESULT_FAIL;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->credssp_security_ready)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.auth_redirection.no_security",
                        "dvc_channel_id=%u payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
        return LIBRDP_STATUS_OK;
    }

    memset(&outer, 0, sizeof(outer));
    memset(&encoded, 0, sizeof(encoded));
    memset(&call, 0, sizeof(call));
    rdp_buffer_init(&plain);
    rdp_buffer_init(&response_payload);

    status = rdp_auth_redirection_parse_outer_packet(data, data_len, &outer);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_unwrap(&session->credssp_security,
                                         outer.payload,
                                         outer.payload_len,
                                         &plain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_auth_redirection_parse_encoded_payload(plain.data, plain.length, &encoded);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.auth_redirection.pdu",
                        "dvc_channel_id=%u package=%u encrypted_len=%u decoded_len=%u payload_len=%u",
                        channel_id,
                        encoded.package,
                        (unsigned)outer.payload_len,
                        (unsigned)plain.length,
                        (unsigned)encoded.payload_len);
        status = rdp_auth_redirection_parse_call_message(encoded.payload, encoded.payload_len, &call);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        response_status = rdp_session_auth_redirection_response_status(&call);
        status = rdp_auth_redirection_write_default_response(&response_payload,
                                                             &call,
                                                             response_status);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_auth_redirection_send_payload(session,
                                                               channel_id,
                                                               channel_id_bytes,
                                                               encoded.package,
                                                               response_payload.data,
                                                               response_payload.length);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.auth_redirection.call",
                        "dvc_channel_id=%u package=%u call_id=%u kind=%u response_status=%u status=%s",
                        channel_id,
                        encoded.package,
                        call.call.call_id,
                        call.kind,
                        response_status,
                        librdp_status_string(status));
    }
    else
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.auth_redirection.rejected",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        status = LIBRDP_STATUS_OK;
    }
    rdp_buffer_free(&response_payload);
    rdp_buffer_free(&plain);
    return status;
}

static librdp_status rdp_session_send_composited_packet(librdp_session* session,
                                                        const rdp_buffer* payload,
                                                        const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->composited_channel_id == 0 || session->composited_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->composited_channel_id,
                                                 session->composited_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static uint32_t rdp_session_composited_payload_code(const rdp_composited_control* control)
{
    const uint8_t* data = NULL;

    if (!control || control->payload_len < 4u)
        return 0;
    data = control->payload;
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static librdp_status rdp_session_send_composited_batch_reply(
    librdp_session* session,
    uint32_t channel,
    const rdp_composited_channel_message* message)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t value = 0;
    const char* event = NULL;

    if (!session || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    switch (message->control_code)
    {
        case RDP_COMPOSITED_CMD_SYNC_FLUSH:
            if (message->payload_len != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_composited_write_sync_flush_reply(&response,
                                                           channel,
                                                           RDP_SESSION_HRESULT_OK);
            event = "client.cr2.sync_flush.reply";
            break;
        case RDP_COMPOSITED_CMD_ROUNDTRIP_REQUEST:
            if (message->payload_len != 4u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            value = rdp_session_read_u32_le_unaligned(message->payload);
            status = rdp_composited_write_roundtrip_reply(&response, channel, value);
            event = "client.cr2.roundtrip.reply";
            break;
        case RDP_COMPOSITED_CMD_ASYNC_FLUSH:
            if (message->payload_len != 8u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            value = rdp_session_read_u32_le_unaligned(message->payload);
            status = rdp_composited_write_async_flush_reply(&response,
                                                            channel,
                                                            value,
                                                            RDP_SESSION_HRESULT_OK);
            event = "client.cr2.async_flush.reply";
            break;
        case RDP_COMPOSITED_CMD_REQUEST_TIER:
            if (message->payload_len != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_composited_write_hardware_tier(&response, channel, 1u, 0u);
            event = "client.cr2.hardware_tier";
            break;
        default:
            rdp_buffer_free(&response);
            return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_composited_packet(session, &response, event);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "channel=%u command=%u value=%u",
                        channel,
                        message->control_code,
                        value);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_send_composited_batch_replies(librdp_session* session,
                                                               uint32_t channel,
                                                               const void* data,
                                                               size_t data_len)
{
    rdp_composited_batch_reader reader;
    rdp_composited_channel_message message;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_batch_init(&reader, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    while ((status = rdp_composited_batch_next(&reader, &message)) == LIBRDP_STATUS_OK)
    {
        status = rdp_session_send_composited_batch_reply(session, channel, &message);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return status == LIBRDP_STATUS_AGAIN ? LIBRDP_STATUS_OK : status;
}

static uint32_t rdp_session_composited_clamp_coord(int32_t value, uint32_t limit)
{
    if (value <= 0)
        return 0;
    if ((uint32_t)value > limit)
        return limit;
    return (uint32_t)value;
}

static void rdp_session_emit_composited_invalidations(librdp_session* session,
                                                      uint32_t before_invalidation_count)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t i = 0;

    if (!session || !session->surface)
        return;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (surface_width == 0 || surface_height == 0)
        return;

    for (i = 0; i < RDP_COMPOSITED_RENDER_INVALIDATION_LIMIT; i++)
    {
        const rdp_composited_render_invalidation* invalidation =
            &session->composited_tree.invalidations[i];
        uint32_t left = 0;
        uint32_t top = 0;
        uint32_t right = surface_width;
        uint32_t bottom = surface_height;
        uint8_t fallback_full = 0;

        if (!invalidation->active || invalidation->generation <= before_invalidation_count)
            continue;

        left = rdp_session_composited_clamp_coord(invalidation->rect.left, surface_width);
        top = rdp_session_composited_clamp_coord(invalidation->rect.top, surface_height);
        right = rdp_session_composited_clamp_coord(invalidation->rect.right, surface_width);
        bottom = rdp_session_composited_clamp_coord(invalidation->rect.bottom, surface_height);
        if (right <= left || bottom <= top)
        {
            left = 0;
            top = 0;
            right = surface_width;
            bottom = surface_height;
            fallback_full = 1u;
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.cr2.surface.invalidated",
                        "resource=%u generation=%u x=%u y=%u width=%u height=%u fallback_full=%u",
                        invalidation->resource,
                        invalidation->generation,
                        left,
                        top,
                        right - left,
                        bottom - top,
                        fallback_full);
        rdp_session_emit_surface_invalidated(session, left, top, right - left, bottom - top);
    }
}

/*
 * Handle composited-remoting channel messages at the session boundary. Tree
 * mutations and rendered surface damage are applied only after the channel
 * decoder accepts the complete message.
 */
static librdp_status rdp_session_handle_composited_message(librdp_session* session,
                                                           uint32_t channel_id,
                                                           const uint8_t* data,
                                                           size_t data_len)
{
    rdp_composited_control control;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_composited_parse_control(data, data_len, &control);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.cr2.pdu.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.cr2.control",
                          "dvc_channel_id=%u control=%u word0=%u word1=%u payload_len=%u enabled=%u",
                          channel_id,
                          control.control_code,
                          control.word0,
                          control.word1,
                          (unsigned)control.payload_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CR2));
    switch (control.control_code)
    {
        case RDP_COMPOSITED_CONTROL_VERSION_REQUEST:
        {
            uint32_t versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_composited_write_version_reply(&response, versions, 1);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_composited_packet(session, &response, "client.cr2.version_reply");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.version_reply",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            RDP_COMPOSITED_PROTOCOL_VERSION);
            break;
        }
        case RDP_COMPOSITED_CONTROL_VERSION_ANNOUNCEMENT:
        {
            rdp_composited_version_reply reply;

            status = rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply);
            if (status == LIBRDP_STATUS_OK)
            {
                session->composited_ready =
                    rdp_composited_version_reply_has(&reply, RDP_COMPOSITED_PROTOCOL_VERSION) ? 1u : 0u;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.cr2.version_announcement",
                                "dvc_channel_id=%u versions=%u supported=%u",
                                channel_id,
                                reply.version_count,
                                session->composited_ready ? 1u : 0u);
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.cr2.version_announcement.invalid",
                                "dvc_channel_id=%u payload_len=%u status=%s",
                                channel_id,
                                (unsigned)control.payload_len,
                                librdp_status_string(status));
                return status;
            }
            break;
        }
        case RDP_COMPOSITED_CONTROL_OPEN_CONNECTION:
            session->composited_connection_open = 1;
            session->composited_connection_id = control.word0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.connection.open",
                            "dvc_channel_id=%u connection_id=%u flags=%u",
                            channel_id,
                            control.word0,
                            control.word1);
            break;
        case RDP_COMPOSITED_CONTROL_CLOSE_CONNECTION:
            session->composited_connection_open = 0;
            session->composited_connection_id = 0;
            session->composited_open_channel_id = 0;
            rdp_composited_render_tree_reset(&session->composited_tree);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.connection.close",
                            "dvc_channel_id=%u",
                            channel_id);
            break;
        case RDP_COMPOSITED_CONTROL_OPEN_CHANNEL:
            session->composited_ready = 1;
            session->composited_open_channel_id = control.word0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel.open",
                            "dvc_channel_id=%u channel=%u flags=%u",
                            channel_id,
                            control.word0,
                            control.word1);
            break;
        case RDP_COMPOSITED_CONTROL_CLOSE_CHANNEL:
            if (session->composited_open_channel_id == control.word0)
                session->composited_open_channel_id = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel.close",
                            "dvc_channel_id=%u channel=%u",
                            channel_id,
                            control.word0);
            break;
        case RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL:
        {
            uint32_t before_commands = session->composited_tree.command_count;
            uint32_t before_resources = session->composited_tree.resource_count;
            uint32_t before_invalidations = session->composited_tree.invalidation_count;

            status = rdp_composited_render_tree_apply_batch(&session->composited_tree,
                                                            control.payload,
                                                            control.payload_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_composited_batch_replies(session,
                                                                   control.word0,
                                                                   control.payload,
                                                                   control.payload_len);
            if (status == LIBRDP_STATUS_OK &&
                session->composited_tree.invalidation_count > before_invalidations)
                rdp_session_emit_composited_invalidations(session, before_invalidations);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.render.batch",
                            "dvc_channel_id=%u channel=%u payload_len=%u status=%s commands=%u resources=%u resource_delta=%d invalidations=%u bitmap_pixels=%u bitmap_compressed=%u glyph_cache_add=%u glyph_cache_remove=%u glyph_realization_add=%u glyph_realization_remove=%u visual_group=%u extension_commands=%u skipped=%u",
                            channel_id,
                            control.word0,
                            (unsigned)control.payload_len,
                            librdp_status_string(status),
                            session->composited_tree.command_count - before_commands,
                            session->composited_tree.resource_count,
                            (int)session->composited_tree.resource_count - (int)before_resources,
                            session->composited_tree.invalidation_count,
                            session->composited_tree.bitmap_pixels_count,
                            session->composited_tree.bitmap_compressed_pixels_count,
                            session->composited_tree.glyph_cache_add_count,
                            session->composited_tree.glyph_cache_remove_count,
                            session->composited_tree.glyph_realization_add_count,
                            session->composited_tree.glyph_realization_remove_count,
                            session->composited_tree.visual_group_count,
                            session->composited_tree.extension_command_count,
                            session->composited_tree.skipped_known_count);
            return status;
        }
        case RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CHANNEL_NOTIFICATION:
        case RDP_COMPOSITED_CONTROL_CONNECTION_BROADCAST:
        case RDP_COMPOSITED_CONTROL_SURFACE_MANAGER_EVENT:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.cr2.notification",
                                  "dvc_channel_id=%u control=%u channel=%u code=%u payload_len=%u",
                                  channel_id,
                                  control.control_code,
                                  control.word0,
                                  rdp_session_composited_payload_code(&control),
                                  (unsigned)control.payload_len);
            break;
        default:
            break;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_write_u32_bytes(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

static librdp_status rdp_session_send_video_redirection_packet(librdp_session* session,
                                                               const rdp_buffer* payload,
                                                               const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->video_redirection_channel_id == 0 || session->video_redirection_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->video_redirection_channel_id,
                                                 session->video_redirection_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capabilities(librdp_session* session, uint32_t message_id)
{
    uint8_t protocol[4];
    uint8_t platform[4];
    uint8_t audio[4];
    rdp_video_redirection_capability caps[3];
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2, protocol);
    rdp_session_write_u32_bytes(RDP_VIDEO_REDIRECTION_PLATFORM_OTHER, platform);
    rdp_session_write_u32_bytes(
        rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_AUDIO_OUTPUT) ?
            RDP_VIDEO_REDIRECTION_AUDIO_SUPPORTED :
            RDP_VIDEO_REDIRECTION_AUDIO_NO_DEVICE,
        audio);
    memset(caps, 0, sizeof(caps));
    caps[0].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION;
    caps[0].length = sizeof(protocol);
    caps[0].data = protocol;
    caps[0].data_len = sizeof(protocol);
    caps[1].type = RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM;
    caps[1].length = sizeof(platform);
    caps[1].data = platform;
    caps[1].data_len = sizeof(platform);
    caps[2].type = RDP_VIDEO_REDIRECTION_CAPABILITY_AUDIO_SUPPORT;
    caps[2].length = sizeof(audio);
    caps[2].data = audio;
    caps[2].data_len = sizeof(audio);
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_exchange_capabilities_response(&response,
                                                                        message_id,
                                                                        caps,
                                                                        3u,
                                                                        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.capabilities.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_capabilities_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.response",
                        "dvc_channel_id=%u message_id=%u audio=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        audio[0]);
    }
    return status;
}

static librdp_status rdp_session_send_video_rim(librdp_session* session, uint32_t message_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_rim_capability_response(
        &response,
        message_id,
        RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01,
        RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.rim.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_redirection_rim_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.rim.response",
                        "dvc_channel_id=%u message_id=%u",
                        session->video_redirection_channel_id,
                        message_id);
    }
    return status;
}

static librdp_status rdp_session_send_video_format_support(librdp_session* session,
                                                           uint32_t message_id,
                                                           uint32_t platform_cookie,
                                                           uint32_t supported)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || supported > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_check_format_support_response(&response,
                                                                       message_id,
                                                                       supported,
                                                                       platform_cookie,
                                                                       RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.format.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.format.response",
                        "dvc_channel_id=%u message_id=%u platform=%u supported=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        platform_cookie,
                        supported);
    return status;
}

static librdp_status rdp_session_send_video_topology(librdp_session* session,
                                                     uint32_t message_id,
                                                     uint32_t ready)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || ready > 1u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_set_topology_response(&response,
                                                               message_id,
                                                               ready,
                                                               RDP_SESSION_HRESULT_OK);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session,
                                                           &response,
                                                           "client.tsmf.topology.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.topology.response",
                        "dvc_channel_id=%u message_id=%u ready=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        ready);
    return status;
}

static librdp_status rdp_session_send_video_event(librdp_session* session,
                                                  uint32_t message_id,
                                                  uint32_t stream_id,
                                                  uint32_t event_id,
                                                  const char* event_name)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event_name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_client_event(&response, message_id, stream_id, event_id, NULL, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, event_name);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event_name,
                        "dvc_channel_id=%u message_id=%u stream_id=%u event_id=%u",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        event_id);
    return status;
}

static librdp_status rdp_session_send_video_sample_ack(librdp_session* session,
                                                       uint32_t message_id,
                                                       uint32_t stream_id,
                                                       uint64_t duration,
                                                       uint64_t data_len)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_redirection_write_playback_ack(&response,
                                                      message_id,
                                                      stream_id,
                                                      duration,
                                                      data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_redirection_packet(session, &response, "client.tsmf.sample.ack");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.sample.ack",
                        "dvc_channel_id=%u message_id=%u stream_id=%u duration=%llu data_len=%llu",
                        session->video_redirection_channel_id,
                        message_id,
                        stream_id,
                        (unsigned long long)duration,
                        (unsigned long long)data_len);
    return status;
}

static librdp_status rdp_session_send_video_optimized_control(librdp_session* session,
                                                              const rdp_buffer* payload,
                                                              const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->video_optimized_control_channel_id == 0 ||
        session->video_optimized_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->video_optimized_control_channel_id,
                                                 session->video_optimized_control_channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_optimized_presentation_response(librdp_session* session,
                                                                           uint8_t presentation_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_optimized_write_presentation_response(&response, presentation_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_optimized_control(session,
                                                          &response,
                                                          "client.video_optimized.presentation.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.presentation.response",
                        "dvc_channel_id=%u presentation_id=%u",
                        session->video_optimized_control_channel_id,
                        presentation_id);
    return status;
}

/*
 * Handle video-optimized remoting control traffic. Presentation identifiers,
 * format negotiation, and stream state are validated before media payload
 * callbacks are enabled.
 */
static librdp_status rdp_session_handle_video_optimized_control_message(librdp_session* session,
                                                                        uint32_t channel_id,
                                                                        const uint8_t* data,
                                                                        size_t data_len)
{
    rdp_video_optimized_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.control.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.control",
                          "dvc_channel_id=%u packet_type=%u payload_len=%u enabled=%u",
                          channel_id,
                          header.packet_type,
                          (unsigned)header.payload_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));

    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST)
    {
        rdp_video_optimized_presentation_request request;

        status = rdp_video_optimized_parse_presentation_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (request.command == RDP_VIDEO_OPTIMIZED_COMMAND_START)
        {
            rdp_session_video_optimized_presentation* entry =
                rdp_session_video_optimized_upsert(session, request.presentation_id);

            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            entry->frame_rate = request.frame_rate;
            entry->average_bitrate_kbps = request.average_bitrate_kbps;
            entry->source_width = request.source_width;
            entry->source_height = request.source_height;
            entry->scaled_width = request.scaled_width;
            entry->scaled_height = request.scaled_height;
            entry->timestamp_offset = request.timestamp_offset;
            entry->geometry_mapping_id = request.geometry_mapping_id;
            status = rdp_session_send_video_optimized_presentation_response(session, request.presentation_id);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.video_optimized.presentation.start",
                                "dvc_channel_id=%u presentation_id=%u source_width=%u source_height=%u scaled_width=%u scaled_height=%u frame_rate=%u bitrate_kbps=%u extra_len=%u",
                                channel_id,
                                request.presentation_id,
                                request.source_width,
                                request.source_height,
                                request.scaled_width,
                                request.scaled_height,
                                request.frame_rate,
                                request.average_bitrate_kbps,
                                request.extra_len);
            return status;
        }
        rdp_session_video_optimized_remove(session, request.presentation_id);
        status = rdp_session_send_video_optimized_presentation_response(session, request.presentation_id);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.presentation.stop",
                            "dvc_channel_id=%u presentation_id=%u",
                            channel_id,
                            request.presentation_id);
        return status;
    }
    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_CLIENT_NOTIFICATION)
    {
        rdp_video_optimized_client_notification notification;

        status = rdp_video_optimized_parse_client_notification(data, data_len, &notification);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE)
        {
            rdp_video_optimized_framerate_override framerate;

            status = rdp_video_optimized_parse_framerate_override(notification.data,
                                                                 notification.data_len,
                                                                 &framerate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.framerate",
                            "dvc_channel_id=%u presentation_id=%u flags=%u desired_frame_rate=%u",
                            channel_id,
                            notification.presentation_id,
                            framerate.flags,
                            framerate.desired_frame_rate);
        }
        else
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.network_error",
                            "dvc_channel_id=%u presentation_id=%u",
                            channel_id,
                            notification.presentation_id);
        }
        return LIBRDP_STATUS_OK;
    }
    if (header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_RESPONSE)
    {
        rdp_video_optimized_presentation_response response;

        status = rdp_video_optimized_parse_presentation_response(data, data_len, &response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.presentation.response.recv",
                        "dvc_channel_id=%u presentation_id=%u",
                        channel_id,
                        response.presentation_id);
        return LIBRDP_STATUS_OK;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.control.skipped",
                          "dvc_channel_id=%u packet_type=%u payload_len=%u",
                          channel_id,
                          header.packet_type,
                          (unsigned)header.payload_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_handle_video_optimized_data_message(librdp_session* session,
                                                                     rdp_session_dynamic_channel* entry,
                                                                     uint32_t channel_id,
                                                                     const uint8_t* data,
                                                                     size_t data_len)
{
    rdp_video_optimized_video_data video;
    rdp_session_video_optimized_presentation* presentation = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !entry || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_optimized_parse_video_data(data, data_len, &video);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.data.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }

    presentation = rdp_session_video_optimized_find(session, video.presentation_id);
    if (!presentation)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.rejected",
                        "dvc_channel_id=%u presentation_id=%u reason=unknown_presentation sample_number=%u",
                        channel_id,
                        video.presentation_id,
                        video.sample_number);
        return LIBRDP_STATUS_STATE;
    }
    if (!rdp_session_video_optimized_sample_sequence_valid(presentation, &video))
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.video_optimized.sample.rejected",
                        "dvc_channel_id=%u presentation_id=%u reason=sequence sample_number=%u packet=%u last_sample_number=%u last_packet=%u",
                        channel_id,
                        video.presentation_id,
                        video.sample_number,
                        video.current_packet_index,
                        presentation->last_sample_number,
                        presentation->last_packet_index);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    presentation->sample_count++;
    presentation->sample_bytes += video.sample_len;
    presentation->last_timestamp = video.timestamp;
    presentation->last_duration = video.duration;
    presentation->last_sample_number = video.sample_number;
    presentation->last_packet_index = video.current_packet_index;
    presentation->last_packets_in_sample = video.packets_in_sample;
    presentation->last_flags = video.flags;
    if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO) && video.sample_len > 0)
        rdp_session_emit_channel_data(session, entry, video.sample, video.sample_len);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.video_optimized.sample",
                          "dvc_channel_id=%u presentation_id=%u sample_number=%u packet=%u packets=%u flags=%u sample_len=%u samples=%llu bytes=%llu emitted=%u",
                          channel_id,
                          video.presentation_id,
                          video.sample_number,
                          video.current_packet_index,
                          video.packets_in_sample,
                          video.flags,
                          video.sample_len,
                          (unsigned long long)presentation->sample_count,
                          (unsigned long long)presentation->sample_bytes,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
    return LIBRDP_STATUS_OK;
}

/*
 * TSMF control and data messages can use either the full channel header or a
 * compact channel-specific header. Parse both forms here and keep presentation
 * bookkeeping synchronized with application data events.
 */
static librdp_status rdp_session_handle_video_redirection_message(librdp_session* session,
                                                                  rdp_session_dynamic_channel* channel,
                                                                  uint32_t channel_id,
                                                                  const uint8_t* data,
                                                                  size_t data_len)
{
    rdp_video_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_redirection_parse_header(data, data_len, 1, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        status = rdp_video_redirection_parse_header(data, data_len, 0, &header);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.pdu.invalid",
                            "dvc_channel_id=%u payload_len=%u status=%s",
                            channel_id,
                            (unsigned)data_len,
                            librdp_status_string(status));
            return status;
        }
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.tsmf.pdu",
                          "dvc_channel_id=%u interface_id=%u stream_mask=%u message_id=%u function_id=%u payload_len=%u enabled=%u",
                          channel_id,
                          header.interface_id,
                          header.stream_id_mask,
                          header.message_id,
                          header.has_function_id ? header.function_id : 0u,
                          (unsigned)header.payload_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_RIM_CAPABILITIES &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_RIM_EXCHANGE_CAPABILITY_REQUEST)
    {
        rdp_video_redirection_rim_capability request;

        status = rdp_video_redirection_parse_rim_capability_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_send_video_rim(session, request.header.message_id);
    }
    if (header.has_function_id &&
        header.interface_id == RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT &&
        header.function_id == RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ)
    {
        rdp_video_redirection_capability_message request;

        status = rdp_video_redirection_parse_exchange_capabilities_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->video_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.tsmf.capabilities.request",
                        "dvc_channel_id=%u message_id=%u count=%u",
                        channel_id,
                        request.header.message_id,
                        request.capabilities.count);
        return rdp_session_send_video_capabilities(session, request.header.message_id);
    }
    if (!header.has_function_id || header.interface_id != RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT)
        return LIBRDP_STATUS_OK;

    switch (header.function_id)
    {
        case RDP_VIDEO_REDIRECTION_FUNC_CHECK_FORMAT_SUPPORT_REQ:
        {
            rdp_video_redirection_format_support_request request;
            uint32_t supported =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO);

            status = rdp_video_redirection_parse_check_format_support_request(data, data_len, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.format.request",
                            "dvc_channel_id=%u message_id=%u platform=%u media_types=%u media_len=%u supported=%u",
                            channel_id,
                            request.header.message_id,
                            request.platform_cookie,
                            request.media_type_count,
                            (unsigned)request.media_types_len,
                            supported);
            return rdp_session_send_video_format_support(session,
                                                         request.header.message_id,
                                                         request.platform_cookie,
                                                         supported);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_CHANNEL_PARAMS:
        {
            rdp_video_redirection_stream params;

            status = rdp_video_redirection_parse_set_channel_params(data, data_len, &params);
            if (status != LIBRDP_STATUS_OK)
                return status;
            (void)rdp_session_video_stream_upsert(session, params.presentation_id, params.stream_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.channel_params",
                            "dvc_channel_id=%u message_id=%u stream_id=%u",
                            channel_id,
                            params.header.message_id,
                            params.stream_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_NEW_PRESENTATION:
        {
            rdp_video_redirection_presentation presentation;

            status = rdp_video_redirection_parse_new_presentation(data, data_len, &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.presentation",
                            "dvc_channel_id=%u message_id=%u platform=%u",
                            channel_id,
                            presentation.header.message_id,
                            presentation.platform_cookie);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t ready =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO);

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.topology.request",
                            "dvc_channel_id=%u message_id=%u ready=%u",
                            channel_id,
                            presentation.header.message_id,
                            ready);
            return rdp_session_send_video_topology(session, presentation.header.message_id, ready);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SHUTDOWN_PRESENTATION_REQ:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t removed = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            removed = rdp_session_video_presentation_remove(session, presentation.presentation_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.presentation.shutdown",
                            "dvc_channel_id=%u message_id=%u streams_removed=%u",
                            channel_id,
                            presentation.header.message_id,
                            removed);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ADD_STREAM:
        {
            rdp_video_redirection_stream stream;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_add_stream(data, data_len, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_upsert(session, stream.presentation_id, stream.stream_id);
            if (!entry)
                return LIBRDP_STATUS_NO_MEMORY;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.add",
                            "dvc_channel_id=%u message_id=%u stream_id=%u media_len=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id,
                            stream.data_len);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_SAMPLE:
        {
            rdp_video_redirection_stream stream;
            rdp_video_redirection_data_sample sample;
            rdp_session_video_stream* entry = NULL;
            uint64_t duration = 0;

            status = rdp_video_redirection_parse_sample_message(data, data_len, &stream);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_video_redirection_parse_data_sample(stream.data, stream.data_len, &sample);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, stream.presentation_id, stream.stream_id);
            if (!entry)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.tsmf.sample.rejected",
                                "dvc_channel_id=%u message_id=%u stream_id=%u reason=unknown_stream",
                                channel_id,
                                stream.header.message_id,
                                stream.stream_id);
                return LIBRDP_STATUS_STATE;
            }
            if (entry->sample_count > 0 && sample.sample_start_time <= entry->last_sample_start)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.tsmf.sample.rejected",
                                "dvc_channel_id=%u message_id=%u stream_id=%u reason=sequence sample_start=%llu last_sample_start=%llu",
                                channel_id,
                                stream.header.message_id,
                                stream.stream_id,
                                (unsigned long long)sample.sample_start_time,
                                (unsigned long long)entry->last_sample_start);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            duration = sample.sample_end_time - sample.sample_start_time;
            entry->sample_count++;
            entry->sample_bytes += sample.data_len;
            entry->last_sample_start = sample.sample_start_time;
            entry->last_sample_end = sample.sample_end_time;
            if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO) &&
                sample.data_len > 0)
                rdp_session_emit_channel_data(session, channel, sample.data, sample.data_len);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.sample",
                                  "dvc_channel_id=%u message_id=%u stream_id=%u sample_len=%u samples=%llu bytes=%llu flags=%u emitted=%u",
                                  channel_id,
                                  stream.header.message_id,
                                  stream.stream_id,
                                  sample.data_len,
                                  (unsigned long long)entry->sample_count,
                                  (unsigned long long)entry->sample_bytes,
                                  sample.sample_flags,
                                  rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
            return rdp_session_send_video_sample_ack(session,
                                                     stream.header.message_id,
                                                     stream.stream_id,
                                                     duration,
                                                     sample.data_len);
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STARTED:
        {
            rdp_video_redirection_playback_started started;

            status = rdp_video_redirection_parse_playback_started(data, data_len, &started);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.started",
                            "dvc_channel_id=%u message_id=%u offset=%llu seek=%u",
                            channel_id,
                            started.header.message_id,
                            (unsigned long long)started.playback_start_offset,
                            started.is_seek);
            return rdp_session_send_video_event(session,
                                                started.header.message_id,
                                                0,
                                                RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                "client.tsmf.playback.start_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_PAUSED:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RESTARTED:
        {
            rdp_video_redirection_presentation presentation;
            uint8_t paused =
                header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_PAUSED ? 1u : 0u;
            uint32_t matched = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            matched = rdp_session_video_presentation_update(session,
                                                            presentation.presentation_id,
                                                            1,
                                                            paused,
                                                            0,
                                                            UINT32_MAX);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            paused ? "client.tsmf.playback.paused" :
                                     "client.tsmf.playback.restarted",
                            "dvc_channel_id=%u message_id=%u streams=%u",
                            channel_id,
                            presentation.header.message_id,
                            matched);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH:
        {
            rdp_video_redirection_stream stream;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, stream.presentation_id, stream.stream_id);
            if (entry)
                entry->flush_count++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.flush",
                            "dvc_channel_id=%u message_id=%u stream_id=%u flushes=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id,
                            entry ? entry->flush_count : 0u);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_STOPPED:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM:
        {
            rdp_video_redirection_stream stream;
            uint32_t event_id = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_END_OF_STREAM ?
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM :
                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_STOP_COMPLETED;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_session_video_stream_remove(session, stream.presentation_id, stream.stream_id);
            return rdp_session_send_video_event(session,
                                                stream.header.message_id,
                                                stream.stream_id,
                                                event_id,
                                                event_id == RDP_VIDEO_REDIRECTION_CLIENT_EVENT_ENDOFSTREAM ?
                                                    "client.tsmf.playback.end_of_stream" :
                                                    "client.tsmf.playback.stop_completed");
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_VIDEO_WINDOW:
        {
            rdp_video_redirection_window window;
            rdp_session_video_stream* entry = NULL;

            status = rdp_video_redirection_parse_set_video_window(data, data_len, &window);
            if (status != LIBRDP_STATUS_OK)
                return status;
            entry = rdp_session_video_stream_find(session, window.presentation_id, 0);
            if (entry)
                entry->video_window_id = window.video_window_id;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.window",
                            "dvc_channel_id=%u message_id=%u video_window_id=%llu parent_window_id=%llu",
                            channel_id,
                            window.header.message_id,
                            (unsigned long long)window.video_window_id,
                            (unsigned long long)window.parent_window_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_REMOVE_STREAM:
        {
            rdp_video_redirection_stream stream;

            status = rdp_video_redirection_parse_stream_only(data, data_len, header.function_id, &stream);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_session_video_stream_remove(session, stream.presentation_id, stream.stream_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.stream.remove",
                            "dvc_channel_id=%u message_id=%u stream_id=%u",
                            channel_id,
                            stream.header.message_id,
                            stream.stream_id);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_SOURCE_VIDEO_RECT:
        {
            rdp_video_redirection_source_video_rect rect;

            status = rdp_video_redirection_parse_source_video_rect(data, data_len, &rect);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.source_rect",
                            "dvc_channel_id=%u message_id=%u left=%u top=%u right=%u bottom=%u",
                            channel_id,
                            rect.header.message_id,
                            rect.left_bits,
                            rect.top_bits,
                            rect.right_bits,
                            rect.bottom_bits);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_SET_ALLOCATOR:
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.allocator",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)header.payload_len);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_NOTIFY_PREROLL:
        {
            rdp_video_redirection_presentation presentation;
            uint32_t matched = 0;

            status = rdp_video_redirection_parse_presentation_only(data,
                                                                   data_len,
                                                                   header.function_id,
                                                                   &presentation);
            if (status != LIBRDP_STATUS_OK)
                return status;
            matched = rdp_session_video_presentation_update(session,
                                                            presentation.presentation_id,
                                                            1,
                                                            1,
                                                            1,
                                                            UINT32_MAX);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.preroll",
                            "dvc_channel_id=%u message_id=%u streams=%u",
                            channel_id,
                            presentation.header.message_id,
                            matched);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_UPDATE_GEOMETRY_INFO:
        {
            rdp_video_redirection_geometry_update update;
            rdp_video_redirection_geometry_info info;

            status = rdp_video_redirection_parse_geometry_update(data, data_len, &update);
            if (status != LIBRDP_STATUS_OK)
                return status;
            memset(&info, 0, sizeof(info));
            if (update.geometry_len > 0)
            {
                status = rdp_video_redirection_parse_geometry_info(update.geometry, update.geometry_len, &info);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.geometry",
                            "dvc_channel_id=%u message_id=%u geometry_len=%u visible_len=%u window_state=%u width=%u height=%u",
                            channel_id,
                            update.header.message_id,
                            update.geometry_len,
                            update.visible_rect_len,
                            info.window_state,
                            info.width,
                            info.height);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_PLAYBACK_RATE_CHANGED:
        {
            rdp_video_redirection_playback_rate rate;

            status = rdp_video_redirection_parse_playback_rate(data, data_len, &rate);
            if (status != LIBRDP_STATUS_OK)
                return status;
            (void)rdp_session_video_presentation_update(session,
                                                        rate.presentation_id,
                                                        0,
                                                        0,
                                                        0,
                                                        rate.rate_bits);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.playback.rate",
                            "dvc_channel_id=%u message_id=%u rate_bits=%u",
                            channel_id,
                            rate.header.message_id,
                            rate.rate_bits);
            break;
        }
        case RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME:
        case RDP_VIDEO_REDIRECTION_FUNC_ON_CHANNEL_VOLUME:
        {
            rdp_video_redirection_volume volume;

            status = header.function_id == RDP_VIDEO_REDIRECTION_FUNC_ON_STREAM_VOLUME ?
                         rdp_video_redirection_parse_stream_volume(data, data_len, &volume) :
                         rdp_video_redirection_parse_channel_volume(data, data_len, &volume);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.volume",
                            "dvc_channel_id=%u message_id=%u function_id=%u value=%u second=%u",
                            channel_id,
                            volume.header.message_id,
                            header.function_id,
                            volume.value,
                            volume.second_value);
            break;
        }
        default:
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.tsmf.pdu.skipped",
                                  "dvc_channel_id=%u message_id=%u function_id=%u payload_len=%u",
                                  channel_id,
                                  header.message_id,
                                  header.function_id,
                                  (unsigned)header.payload_len);
            break;
    }
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_session_video_capture_version(const librdp_session* session)
{
    if (!session || session->video_capture_version == 0)
        return RDP_VIDEO_CAPTURE_VERSION_2;
    return session->video_capture_version;
}

static const char* rdp_session_video_capture_source(const librdp_session* session)
{
    if (!session || !rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA) ||
        librdp_settings_camera_count(session->settings) == 0)
        return NULL;
    return librdp_settings_camera_source(session->settings, 0);
}

static const char* rdp_session_video_capture_source_value(const char* source)
{
    if (!source)
        return NULL;
    if (strncmp(source, "device=", 7u) == 0 && source[7] != '\0')
        return source + 7u;
    if (strncmp(source, "file=", 5u) == 0 && source[5] != '\0')
        return source + 5u;
    return source;
}

static const char* rdp_session_video_capture_source_kind(const char* source)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);

    if (!source || source[0] == '\0' || !value || value[0] == '\0')
        return "none";
    if (strncmp(source, "file=", 5u) == 0)
        return "file";
    if (strncmp(source, "device=", 7u) == 0)
        return "device";
    memset(&st, 0, sizeof(st));
    if (stat(value, &st) == 0 && S_ISREG(st.st_mode))
        return "file";
    return "device";
}

static int rdp_session_video_capture_source_is_file(const char* source)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);

    if (!source || source[0] == '\0' || !value || value[0] == '\0')
        return 0;
    if (strncmp(source, "file=", 5u) == 0)
        return 1;
    memset(&st, 0, sizeof(st));
    return stat(value, &st) == 0 && S_ISREG(st.st_mode);
}

static void rdp_session_video_capture_media_from_source(const char* source,
                                                        rdp_video_capture_media_type* media)
{
    const char* value = rdp_session_video_capture_source_value(source);
    const char* ext = value ? strrchr(value, '.') : NULL;

    memset(media, 0, sizeof(*media));
    media->format = RDP_VIDEO_CAPTURE_MEDIA_NV12;
    media->width = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_WIDTH;
    media->height = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_HEIGHT;
    media->frame_rate_numerator = RDP_SESSION_VIDEO_CAPTURE_DEFAULT_FPS;
    media->frame_rate_denominator = 1;
    media->pixel_aspect_ratio_numerator = 1;
    media->pixel_aspect_ratio_denominator = 1;
    media->flags = 0;
    if ((source && strncmp(source, "device=", 7u) == 0) ||
        (value && strncmp(value, "/dev/video", 10u) == 0))
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    if (!value || !ext)
        return;
    if (strcasecmp(ext, ".h264") == 0 || strcasecmp(ext, ".avc") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_H264;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0 ||
             strcasecmp(ext, ".mjpg") == 0 || strcasecmp(ext, ".mjpeg") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_MJPG;
        media->flags = RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED;
    }
    else if (strcasecmp(ext, ".yuy2") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_YUY2;
    }
    else if (strcasecmp(ext, ".i420") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_I420;
    }
    else if (strcasecmp(ext, ".rgb24") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB24;
    }
    else if (strcasecmp(ext, ".rgb32") == 0 || strcasecmp(ext, ".bgra") == 0)
    {
        media->format = RDP_VIDEO_CAPTURE_MEDIA_RGB32;
    }
}

static void rdp_session_video_capture_update_media(librdp_session* session, const char* source)
{
    if (!session)
        return;
    rdp_session_video_capture_media_from_source(source, &session->video_capture_media);
}

static void rdp_session_video_capture_media_to_public(const rdp_video_capture_media_type* in,
                                                      librdp_video_capture_media* out)
{
    if (!in || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->format = in->format;
    out->width = in->width;
    out->height = in->height;
    out->frame_rate_numerator = in->frame_rate_numerator;
    out->frame_rate_denominator = in->frame_rate_denominator;
    out->pixel_aspect_ratio_numerator = in->pixel_aspect_ratio_numerator;
    out->pixel_aspect_ratio_denominator = in->pixel_aspect_ratio_denominator;
    out->flags = in->flags;
}

static void rdp_session_emit_video_capture_open(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_OPEN;
    event.data.video_capture_open.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_open.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_sample_request(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST;
    event.data.video_capture_sample_request.stream_index = stream_index;
    rdp_session_video_capture_media_to_public(&session->video_capture_media,
                                              &event.data.video_capture_sample_request.media);
    rdp_session_emit(session, &event);
}

static void rdp_session_emit_video_capture_close(librdp_session* session, uint8_t stream_index)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE;
    event.data.video_capture_close.stream_index = stream_index;
    rdp_session_emit(session, &event);
}

/*
 * Reads one synthetic camera sample from a viewer-provided file source. The
 * source string is untrusted configuration, so the function opens the final
 * path directly, refuses symlink traversal when the platform exposes
 * O_NOFOLLOW, validates the resulting descriptor with fstat, and caps the
 * accumulated sample before it can be queued on the video-capture channel.
 * Failures are converted to the protocol error code consumed by the caller.
 */
static librdp_status rdp_session_video_capture_read_sample(const char* source,
                                                           rdp_buffer* sample,
                                                           uint32_t* error_code)
{
    struct stat st;
    const char* value = rdp_session_video_capture_source_value(source);
    int fd = -1;
    int flags = O_RDONLY;
    uint8_t chunk[8192];
    librdp_status status = LIBRDP_STATUS_OK;

    if (error_code)
        *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
    if (!source || !sample || !error_code)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&st, 0, sizeof(st));
    if (!value || value[0] == '\0')
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(value, flags);
    if (fd < 0)
    {
        *error_code = errno == EACCES ? RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                        RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (fstat(fd, &st) != 0)
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
        close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (!S_ISREG(st.st_mode))
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED;
        close(fd);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
    {
        *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
        close(fd);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (;;)
    {
        ssize_t count = read(fd, chunk, sizeof(chunk));

        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            status = LIBRDP_STATUS_IO_ERROR;
            break;
        }
        if (count == 0)
            break;
        if ((uint64_t)sample->length + (uint64_t)count > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        {
            *error_code = RDP_VIDEO_CAPTURE_ERROR_INVALID_MEDIA_TYPE;
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
        }
        status = rdp_buffer_append(sample, chunk, (size_t)count);
        if (status != LIBRDP_STATUS_OK)
        {
            *error_code = status == LIBRDP_STATUS_NO_MEMORY ?
                              RDP_VIDEO_CAPTURE_ERROR_OUT_OF_MEMORY :
                              RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;
            break;
        }
    }
    close(fd);
    return status;
}

static librdp_status rdp_session_send_video_capture_packet(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const rdp_buffer* payload,
                                                           const char* event)
{
    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id == 0 || channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_dynamic_channel_data(session,
                                                 channel_id,
                                                 channel_id_bytes,
                                                 payload->data,
                                                 payload->length,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_control(librdp_session* session,
                                                            const rdp_buffer* payload,
                                                            const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_control_channel_id : 0,
                                                 session ? session->video_capture_control_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_data(librdp_session* session,
                                                         const rdp_buffer* payload,
                                                         const char* event)
{
    return rdp_session_send_video_capture_packet(session,
                                                 session ? session->video_capture_channel_id : 0,
                                                 session ? session->video_capture_channel_id_bytes : 0,
                                                 payload,
                                                 event);
}

static librdp_status rdp_session_send_video_capture_error(librdp_session* session,
                                                          int control_channel,
                                                          uint32_t error_code,
                                                          const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_error(&response, version, error_code);
    if (status == LIBRDP_STATUS_OK)
    {
        status = control_channel ?
                     rdp_session_send_video_capture_control(session, &response, event) :
                     rdp_session_send_video_capture_data(session, &response, event);
    }
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "channel=%s error=%u",
                        control_channel ? "control" : "data",
                        error_code);
    return status;
}

static librdp_status rdp_session_send_video_capture_success(librdp_session* session, const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_empty(&response,
                                           version,
                                           RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u version=%u",
                        session->video_capture_channel_id,
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_device_added(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer device_name;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t version = rdp_session_video_capture_version(session);

    if (!session || !source)
        return LIBRDP_STATUS_OK;
    rdp_buffer_init(&device_name);
    rdp_buffer_init(&response);
    status = rdp_session_utf8_to_utf16le("Camera", &device_name, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_video_capture_write_device_added(&response,
                                                      version,
                                                      device_name.data,
                                                      device_name.length,
                                                      RDP_VIDEO_CAPTURE_CHANNEL_NAME);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_control(session,
                                                        &response,
                                                        "client.rdpecam.device.added");
    rdp_buffer_free(&response);
    rdp_buffer_free(&device_name);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.device.added",
                        "control_channel_id=%u capture_channel=%s source_kind=%s version=%u",
                        session->video_capture_control_channel_id,
                        RDP_VIDEO_CAPTURE_CHANNEL_NAME,
                        rdp_session_video_capture_source_kind(source),
                        version);
    return status;
}

static librdp_status rdp_session_send_video_capture_stream_list(librdp_session* session)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_stream_description stream;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.stream_list.error");
    memset(&stream, 0, sizeof(stream));
    stream.frame_source_types = RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR;
    stream.stream_category = RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE;
    stream.selected = 1;
    stream.can_be_shared = 1;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_stream_list(&response,
                                                 rdp_session_video_capture_version(session),
                                                 &stream,
                                                 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.stream_list.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.stream_list.response",
                        "dvc_channel_id=%u count=1 source_kind=%s",
                        session->video_capture_channel_id,
                        rdp_session_video_capture_source_kind(source));
    return status;
}

static librdp_status rdp_session_send_video_capture_media_list(librdp_session* session,
                                                               uint8_t message_id,
                                                               const char* event)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_video_capture_media_type media;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!source)
        return rdp_session_send_video_capture_error(session,
                                                    0,
                                                    RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                    "client.rdpecam.media.error");
    rdp_session_video_capture_update_media(session, source);
    media = session->video_capture_media;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_media_list(&response,
                                                rdp_session_video_capture_version(session),
                                                message_id,
                                                &media,
                                                1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u format=%u width=%u height=%u fps_num=%u fps_den=%u flags=%u",
                        session->video_capture_channel_id,
                        media.format,
                        media.width,
                        media.height,
                        media.frame_rate_numerator,
                        media.frame_rate_denominator,
                        media.flags);
    return status;
}

static int rdp_session_video_capture_property_is_brightness(
    const rdp_video_capture_property_request* request)
{
    return request &&
           request->property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP &&
           request->property_id == RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS;
}

static rdp_video_capture_property_description rdp_session_video_capture_brightness_property(void)
{
    rdp_video_capture_property_description property;

    memset(&property, 0, sizeof(property));
    property.property_set = RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP;
    property.property_id = RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS;
    property.capabilities = RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_MANUAL |
                            RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_AUTO;
    property.min_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MIN;
    property.max_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MAX;
    property.step = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_STEP;
    property.default_value = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
    return property;
}

static librdp_status rdp_session_send_video_capture_property_list(librdp_session* session)
{
    rdp_video_capture_property_description property;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    property = rdp_session_video_capture_brightness_property();
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_property_list(&response,
                                                   rdp_session_video_capture_version(session),
                                                   &property,
                                                   1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.property_list.response");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.property_list.response",
                        "dvc_channel_id=%u count=1 property_set=%u property_id=%u",
                        session->video_capture_channel_id,
                        property.property_set,
                        property.property_id);
    return status;
}

static librdp_status rdp_session_send_video_capture_property_value(librdp_session* session,
                                                                   const char* event)
{
    rdp_video_capture_property_value value;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&value, 0, sizeof(value));
    value.mode = session->video_capture_brightness_mode;
    value.value = session->video_capture_brightness;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_property_value(&response,
                                                    rdp_session_video_capture_version(session),
                                                    &value);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u property_set=%u property_id=%u mode=%u value=%d",
                        session->video_capture_channel_id,
                        RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP,
                        RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS,
                        value.mode,
                        value.value);
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_error(librdp_session* session,
                                                                 uint8_t stream_index,
                                                                 uint32_t error_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample_error(&response,
                                                  rdp_session_video_capture_version(session),
                                                  stream_index,
                                                  error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session,
                                                     &response,
                                                     "client.rdpecam.sample.error");
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.sample.error",
                        "dvc_channel_id=%u stream=%u error=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        error_code);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample_payload(librdp_session* session,
                                                                   uint8_t stream_index,
                                                                   const void* data,
                                                                   size_t data_len,
                                                                   const char* event)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event ||
        data_len > RDP_VIDEO_CAPTURE_MAX_SAMPLE_BYTES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_video_capture_write_sample(&response,
                                            rdp_session_video_capture_version(session),
                                            stream_index,
                                            data,
                                            data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_data(session, &response, event);
    rdp_buffer_free(&response);
    if (status == LIBRDP_STATUS_OK)
    {
        session->video_capture_sample_reply_pending = 0;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        event,
                        "dvc_channel_id=%u stream=%u data_len=%u",
                        session->video_capture_channel_id,
                        stream_index,
                        (unsigned)data_len);
    }
    return status;
}

static librdp_status rdp_session_send_video_capture_sample(librdp_session* session, uint8_t stream_index)
{
    const char* source = rdp_session_video_capture_source(session);
    rdp_buffer sample;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t error_code = RDP_VIDEO_CAPTURE_ERROR_UNEXPECTED;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!source)
        return rdp_session_send_video_capture_sample_error(session,
                                                          stream_index,
                                                          RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND);
    rdp_buffer_init(&sample);
    status = rdp_session_video_capture_read_sample(source, &sample, &error_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_video_capture_sample_payload(session,
                                                               stream_index,
                                                               sample.data,
                                                               sample.length,
                                                               "client.rdpecam.sample.response");
    rdp_buffer_free(&sample);
    if (status == LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_OK;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

/*
 * Handle redirected camera control messages. Open, sample request, close, and
 * error paths keep backend state and protocol request IDs synchronized.
 */
static librdp_status rdp_session_handle_video_capture_control_message(librdp_session* session,
                                                                      uint32_t channel_id,
                                                                      const uint8_t* data,
                                                                      size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.control.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version == RDP_VIDEO_CAPTURE_VERSION_1 ?
                                         RDP_VIDEO_CAPTURE_VERSION_1 :
                                         RDP_VIDEO_CAPTURE_VERSION_2;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.control.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u enabled=%u cameras=%u",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA),
                          librdp_settings_camera_count(session->settings));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST:
        {
            rdp_buffer response;
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_buffer_init(&response);
            status = rdp_video_capture_write_empty(&response,
                                                   session->video_capture_version,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_RESPONSE);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_video_capture_control(session,
                                                                &response,
                                                                "client.rdpecam.version.response");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.version.response",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            session->video_capture_version);
            return rdp_session_send_video_capture_device_added(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEVICE_REMOVED:
        {
            rdp_video_capture_device_notification removed;

            status = rdp_video_capture_parse_device_removed(data, data_len, &removed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.device.removed",
                            "dvc_channel_id=%u channel_name_len=%u",
                            channel_id,
                            (unsigned)removed.channel_name_len);
            break;
        }
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.invalid_message",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)data_len);
            return rdp_session_send_video_capture_error(session,
                                                        1,
                                                        RDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE,
                                                        "client.rdpecam.control.error");
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Camera data-channel messages drive a request/reply protocol: open selects a
 * source, sample requests arm exactly one pending reply, and close/error clear
 * the streaming state. Keeping that state here prevents duplicate replies.
 */
static librdp_status rdp_session_handle_video_capture_data_message(librdp_session* session,
                                                                   uint32_t channel_id,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_video_capture_header header;
    librdp_status status = LIBRDP_STATUS_OK;
    const char* source = NULL;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_video_capture_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpecam.data.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    session->video_capture_version = header.version;
    source = rdp_session_video_capture_source(session);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.rdpecam.data.pdu",
                          "dvc_channel_id=%u version=%u message_id=%u payload_len=%u active=%u streaming=%u source_kind=%s",
                          channel_id,
                          header.version,
                          header.message_id,
                          (unsigned)data_len,
                          session->video_capture_active,
                          session->video_capture_streaming,
                          rdp_session_video_capture_source_kind(source));
    switch (header.message_id)
    {
        case RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_ACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.activate.error");
            session->video_capture_active = 1;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.activate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_DEACTIVATE_DEVICE_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (session->video_capture_streaming)
                rdp_session_emit_video_capture_close(session, session->video_capture_selected_stream);
            session->video_capture_active = 0;
            session->video_capture_streaming = 0;
            return rdp_session_send_video_capture_success(session, "client.rdpecam.deactivate.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_STREAM_LIST_REQUEST,
                                                   &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_stream_list(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_REQUEST:
        {
            rdp_video_capture_stream_index request;
            uint8_t response_id = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_REQUEST ?
                                      RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE :
                                      RDP_VIDEO_CAPTURE_MESSAGE_CURRENT_MEDIA_TYPE_RESPONSE;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.media.error");
            return rdp_session_send_video_capture_media_list(
                session,
                response_id,
                response_id == RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE ?
                    "client.rdpecam.media_list.response" :
                    "client.rdpecam.current_media.response");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST:
        case RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data, data_len, header.message_id, &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != 0)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER,
                                                            "client.rdpecam.stream.error");
            if (!source)
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_ITEM_NOT_FOUND,
                                                            "client.rdpecam.stream.error");
            rdp_session_video_capture_update_media(session, source);
            session->video_capture_selected_stream = request.stream_index;
            session->video_capture_active = header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                                                1u :
                                                session->video_capture_active;
            session->video_capture_streaming =
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ? 1u : 0u;
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST &&
                !rdp_session_video_capture_source_is_file(source))
                rdp_session_emit_video_capture_open(session, request.stream_index);
            if (header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_STOP_STREAMS_REQUEST)
                rdp_session_emit_video_capture_close(session, request.stream_index);
            return rdp_session_send_video_capture_success(
                session,
                header.message_id == RDP_VIDEO_CAPTURE_MESSAGE_START_STREAMS_REQUEST ?
                    "client.rdpecam.stream.start.success" :
                    "client.rdpecam.stream.stop.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST:
        {
            rdp_video_capture_stream_index request;

            status = rdp_video_capture_parse_stream_index(data,
                                                          data_len,
                                                          RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                                          &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (request.stream_index != session->video_capture_selected_stream)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER);
            if (!session->video_capture_active || !session->video_capture_streaming)
                return rdp_session_send_video_capture_sample_error(
                    session,
                    request.stream_index,
                    RDP_VIDEO_CAPTURE_ERROR_NOT_INITIALIZED);
            if (!rdp_session_video_capture_source_is_file(source))
            {
                session->video_capture_sample_reply_pending = 1;
                rdp_session_emit_video_capture_sample_request(session, request.stream_index);
                if (session->video_capture_sample_reply_pending)
                {
                    session->video_capture_sample_reply_pending = 0;
                    return rdp_session_send_video_capture_sample_error(
                        session,
                        request.stream_index,
                        RDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED);
                }
                return LIBRDP_STATUS_OK;
            }
            return rdp_session_send_video_capture_sample(session, request.stream_index);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST:
        {
            rdp_video_capture_header request;

            status = rdp_video_capture_parse_empty(data,
                                                    data_len,
                                                    RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST,
                                                    &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            return rdp_session_send_video_capture_property_list(session);
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST:
        {
            rdp_video_capture_property_request request;

            status = rdp_video_capture_parse_property_request(
                data,
                data_len,
                RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST,
                &request);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!rdp_session_video_capture_property_is_brightness(&request))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND,
                                                            "client.rdpecam.property.error");
            return rdp_session_send_video_capture_property_value(
                session,
                "client.rdpecam.property_value.response");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST:
        {
            rdp_video_capture_property_request request;
            rdp_video_capture_property_value value;

            status = rdp_video_capture_parse_set_property_request(data, data_len, &request, &value);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!rdp_session_video_capture_property_is_brightness(&request))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_SET_NOT_FOUND,
                                                            "client.rdpecam.property.error");
            if (value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL &&
                (value.value < RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MIN ||
                 value.value > RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_MAX))
                return rdp_session_send_video_capture_error(session,
                                                            0,
                                                            RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST,
                                                            "client.rdpecam.property.error");
            session->video_capture_brightness_mode = value.mode;
            if (value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL)
                session->video_capture_brightness = value.value;
            else
                session->video_capture_brightness = RDP_SESSION_VIDEO_CAPTURE_BRIGHTNESS_DEFAULT;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.property.set",
                            "dvc_channel_id=%u property_set=%u property_id=%u mode=%u value=%d",
                            session->video_capture_channel_id,
                            request.property_set,
                            request.property_id,
                            session->video_capture_brightness_mode,
                            session->video_capture_brightness);
            return rdp_session_send_video_capture_success(session,
                                                          "client.rdpecam.property.set.success");
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE:
        {
            rdp_video_capture_header response;

            status = rdp_video_capture_parse_empty(data,
                                                   data_len,
                                                   RDP_VIDEO_CAPTURE_MESSAGE_SUCCESS_RESPONSE,
                                                   &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.success",
                            "dvc_channel_id=%u version=%u",
                            channel_id,
                            response.version);
            break;
        }
        case RDP_VIDEO_CAPTURE_MESSAGE_ERROR_RESPONSE:
        {
            rdp_video_capture_error error;

            status = rdp_video_capture_parse_error(data, data_len, &error);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.error",
                            "dvc_channel_id=%u error=%u",
                            channel_id,
                            error.error_code);
            break;
        }
        default:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.invalid_message",
                            "dvc_channel_id=%u message_id=%u payload_len=%u",
                            channel_id,
                            header.message_id,
                            (unsigned)data_len);
            return rdp_session_send_video_capture_error(session,
                                                        0,
                                                        RDP_VIDEO_CAPTURE_ERROR_INVALID_MESSAGE,
                                                        "client.rdpecam.data.error");
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Dynamic virtual channels are the extension demultiplexer for display,
 * graphics, input, devices, media, and application-owned channels. Route known
 * channel names internally first; only unknown active user channels are exposed
 * to the public callback surface after state and payload validation.
 */
static librdp_status rdp_session_handle_dynamic_channel_message(librdp_session* session,
                                                                rdp_session_dynamic_channel* entry,
                                                                uint32_t channel_id,
                                                                uint8_t channel_id_bytes,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !entry || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    (void)channel_id_bytes;

    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.drdynvc.data",
                          "dvc_channel_id=%u name=%s payload_len=%u",
                          channel_id,
                          entry->name,
                          (unsigned)data_len);
    if (strcmp(entry->name, RDP_SESSION_DISPLAY_CONTROL_NAME) == 0)
    {
        rdp_display_control_caps caps;

        status = rdp_display_control_parse_caps(data, data_len, &caps);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->display_control_caps = caps;
        session->display_control_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.caps",
                        "dvc_channel_id=%u max_monitors=%u area_a=%u area_b=%u",
                        channel_id,
                        caps.max_num_monitors,
                        caps.max_monitor_area_factor_a,
                        caps.max_monitor_area_factor_b);
        if (session->requested_monitor_layout_valid)
            status = rdp_session_send_display_control_monitors(session,
                                                               session->requested_monitors,
                                                               session->requested_monitor_count);
        else
            status = rdp_session_request_display_control_layout(
                session,
                session->requested_desktop_width != 0 ? session->requested_desktop_width :
                                                        librdp_surface_width(session->surface),
                session->requested_desktop_height != 0 ? session->requested_desktop_height :
                                                         librdp_surface_height(session->surface));
        if (rdp_session_display_control_local_rejection(status))
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.display_control.layout.rejected",
                            "dvc_channel_id=%u status=%u reason=server_caps",
                            channel_id,
                            (unsigned)status);
            status = LIBRDP_STATUS_OK;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (strcmp(entry->name, RDP_SESSION_CORE_INPUT_NAME) == 0)
    {
        rdp_core_input_init_response response;
        rdp_core_input_negotiation negotiation;

        status = rdp_core_input_parse_init_response(data, data_len, &response);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_core_input_negotiate(&response, &negotiation);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->core_input_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.ready",
                        "dvc_channel_id=%u selected_version=%u max_version=%u relmouse=%u qoe=%u",
                        channel_id,
                        negotiation.selected_protocol_version,
                        negotiation.protocol_version_max,
                        negotiation.supports_relative_mouse,
                        negotiation.supports_qoe_timestamp);
    }
    else if (strcmp(entry->name, RDP_SESSION_INPUT_CHANNEL_NAME) == 0)
    {
        rdp_input_channel_header header;

        status = rdp_input_channel_parse_header(data, data_len, &header);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "rdp.input_channel.pdu",
                              "dvc_channel_id=%u event_id=%u pdu_len=%u",
                              channel_id,
                              header.event_id,
                              header.pdu_length);
        if (header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY)
        {
            rdp_input_channel_sc_ready ready;

            status = rdp_input_channel_parse_sc_ready(data, data_len, &ready);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_protocol_version = ready.protocol_version;
            session->input_channel_supported_features = ready.supported_features;
            session->input_channel_suspended = 0;
            status = rdp_session_send_input_channel_ready(session, &ready);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.sc_ready",
                            "dvc_channel_id=%u protocol_version=%u features=%u",
                            channel_id,
                            ready.protocol_version,
                            ready.supported_features);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT)
        {
            status = rdp_input_channel_parse_empty(data, data_len, RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_suspended = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.suspend",
                            "dvc_channel_id=%u",
                            channel_id);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT)
        {
            status = rdp_input_channel_parse_empty(data, data_len, RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT);
            if (status != LIBRDP_STATUS_OK)
                return status;
            session->input_channel_suspended = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.resume",
                            "dvc_channel_id=%u",
                            channel_id);
        }
        else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_DISMISS_HOVERING_TOUCH_CONTACT)
        {
            uint8_t contact_id = 0;

            status = rdp_input_channel_parse_dismiss_hovering(data, data_len, &contact_id);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.dismiss_hovering",
                            "dvc_channel_id=%u contact_id=%u",
                            channel_id,
                            contact_id);
        }
        else
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.input_channel.server_event",
                                  "dvc_channel_id=%u event_id=%u payload_len=%u",
                                  channel_id,
                                  header.event_id,
                                  (unsigned)data_len);
        }
    }
    else if (strcmp(entry->name, RDP_SESSION_MOUSE_CURSOR_NAME) == 0)
    {
        status = rdp_session_handle_mouse_cursor_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_GRAPHICS_PIPELINE_NAME) == 0)
    {
        status = rdp_session_handle_graphics_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_AUDIO_INPUT_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_audio_input_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_webauthn_message(session, channel_id, channel_id_bytes, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_AUTH_REDIRECTION_NAME) == 0)
    {
        status = rdp_session_handle_auth_redirection_message(session, channel_id, channel_id_bytes, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_usb_redirection_message(session, data, data_len);
    }
    else if (strcmp(entry->name, RDP_COMPOSITED_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_composited_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_redirection_message(session, entry, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) == 0)
    {
        status = rdp_session_handle_video_optimized_control_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL) == 0)
    {
        status = rdp_session_handle_video_optimized_data_message(session, entry, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_capture_control_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_VIDEO_CAPTURE_CHANNEL_NAME) == 0)
    {
        status = rdp_session_handle_video_capture_data_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_ECHO_CHANNEL_NAME) == 0 &&
             librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_ECHO))
    {
        rdp_echo_channel_pdu request;
        rdp_buffer response;
        uint64_t now_ns = 0;
        uint64_t rtt_us = 0;
        int matches_pending = 0;
        int expired = 0;

        rdp_buffer_init(&response);
        status = rdp_echo_channel_parse_request(data, data_len, &request);
        if (status != LIBRDP_STATUS_OK)
            rdp_session_metric_add(&session->echo_stats.malformed_packets, 1);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_session_metric_add(&session->echo_stats.bytes_received, request.payload_len);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.echo.request",
                            "dvc_channel_id=%u payload_len=%u",
                            channel_id,
                            (unsigned)request.payload_len);
            matches_pending = session->echo_pending &&
                              request.payload_len == session->echo_pending_payload.length &&
                              (request.payload_len == 0 ||
                               memcmp(request.payload,
                                      session->echo_pending_payload.data,
                                      request.payload_len) == 0);
            if (matches_pending)
            {
                now_ns = rdp_session_monotonic_ns();
                expired = rdp_session_echo_pending_expired(session, now_ns, &rtt_us);
                if (expired)
                {
                    rdp_session_metric_add(&session->echo_stats.late_responses, 1);
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.echo.response.late",
                                    "dvc_channel_id=%u sequence=%llu payload_len=%u rtt_us=%llu timeout_ms=%u",
                                    channel_id,
                                    (unsigned long long)session->echo_pending_sequence,
                                    (unsigned)request.payload_len,
                                    (unsigned long long)rtt_us,
                                    session->echo_pending_timeout_ms);
                    rdp_session_echo_emit_result(session,
                                                 session->echo_pending_sequence,
                                                 session->echo_pending_payload.data,
                                                 session->echo_pending_payload.length,
                                                 0,
                                                 0,
                                                 1);
                    rdp_session_echo_clear_pending(session);
                }
                else
                {
                    rdp_session_metric_add(&session->echo_stats.ping_responses, 1);
                    rdp_session_echo_record_rtt(session, rtt_us);
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.echo.response.matched",
                                    "dvc_channel_id=%u sequence=%llu payload_len=%u rtt_us=%llu",
                                    channel_id,
                                    (unsigned long long)session->echo_pending_sequence,
                                    (unsigned)request.payload_len,
                                    (unsigned long long)rtt_us);
                    rdp_session_echo_emit_result(session,
                                                 session->echo_pending_sequence,
                                                 session->echo_pending_payload.data,
                                                 session->echo_pending_payload.length,
                                                 rtt_us,
                                                 1,
                                                 0);
                    rdp_session_echo_clear_pending(session);
                }
            }
        }
        if (status == LIBRDP_STATUS_OK && !matches_pending)
        {
            rdp_session_metric_add(&session->echo_stats.requests_received, 1);
            status = rdp_echo_channel_write_response(&response, request.payload, request.payload_len);
        }
        if (status == LIBRDP_STATUS_OK && !matches_pending)
        {
            status = rdp_session_send_dynamic_channel_data(session,
                                                           entry->channel_id,
                                                           entry->channel_id_bytes,
                                                           response.data,
                                                           response.length,
                                                           "client.echo.response");
        }
        if (status == LIBRDP_STATUS_OK && !matches_pending)
        {
            rdp_session_metric_add(&session->echo_stats.responses_sent, 1);
            rdp_session_metric_add(&session->echo_stats.bytes_sent, response.length);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.echo.response",
                            "dvc_channel_id=%u payload_len=%u",
                            channel_id,
                            (unsigned)response.length);
        }
        rdp_buffer_free(&response);
    }
    else
    {
        rdp_session_emit_channel_data(session, entry, data, data_len);
    }
    return status;
}

/*
 * The dynamic-channel control stream manages channel creation, close, and data
 * framing before payload dispatch. This function owns the channel table update
 * order so public channel events cannot refer to entries that are not active.
 */
static librdp_status rdp_session_handle_dynamic_channel(librdp_session* session,
                                                        const rdp_virtual_channel_packet* channel_packet)
{
    rdp_dynamic_channel_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !channel_packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_dynamic_channel_parse_header(channel_packet->payload, channel_packet->payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES)
    {
        rdp_dynamic_channel_capabilities capabilities;
        rdp_buffer response;
        uint16_t client_version = 0;

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_capabilities(channel_packet->payload,
                                                        channel_packet->payload_len,
                                                        &capabilities);
        if (status == LIBRDP_STATUS_OK)
        {
            client_version = rdp_dynamic_channel_select_version(capabilities.version);
            if (client_version == 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_capabilities_response(&response, client_version);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.capabilities");
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.capabilities",
                        "server_version=%u client_version=%u",
                        capabilities.version,
                        client_version);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CREATE)
    {
        rdp_dynamic_channel_create_response create_response;
        rdp_session_dynamic_channel* pending = NULL;
        rdp_dynamic_channel_create_request request;
        rdp_buffer response;
        size_t trace_name_len = 0;
        int name_len = 0;
        rdp_session_dynamic_channel* entry = NULL;
        uint32_t create_status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;

        if (rdp_dynamic_channel_parse_create_response(channel_packet->payload,
                                                      channel_packet->payload_len,
                                                      &create_response) == LIBRDP_STATUS_OK)
        {
            pending = rdp_session_dynamic_channel_find_opening(session, create_response.channel_id);
            if (pending)
            {
                if (pending->channel_id_bytes != create_response.channel_id_bytes)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                if (create_response.status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
                {
                    pending->opening = 0;
                    pending->active = 1;
                    rdp_session_emit_channel_open(session, pending);
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.drdynvc.open.done",
                                    "dvc_channel_id=%u name=%s status=0",
                                    pending->channel_id,
                                    pending->name);
                }
                else
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.drdynvc.open.failed",
                                    "dvc_channel_id=%u name=%s status=%u",
                                    pending->channel_id,
                                    pending->name,
                                    create_response.status_code);
                    rdp_session_dynamic_channel_clear_entry(pending);
                }
                return LIBRDP_STATUS_OK;
            }
        }

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_create_request(channel_packet->payload,
                                                          channel_packet->payload_len,
                                                          &request);
        if (status == LIBRDP_STATUS_OK)
            create_status_code = rdp_session_dynamic_channel_create_status(session, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_create_response(&response,
                                                               request.channel_id,
                                                               request.channel_id_bytes,
                                                               create_status_code);
        if (status == LIBRDP_STATUS_OK && create_status_code == RDP_DYNAMIC_CHANNEL_STATUS_OK)
            status = rdp_session_dynamic_channel_add(session, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.create");
        if (status == LIBRDP_STATUS_OK)
            entry = rdp_session_dynamic_channel_find(session, request.channel_id);
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        trace_name_len = request.name_len > 120u ? 120u : request.name_len;
        name_len = (int)trace_name_len;
        if (create_status_code != RDP_DYNAMIC_CHANNEL_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.create.rejected",
                            "channel_id=%u name=%.*s status=%u",
                            request.channel_id,
                            name_len,
                            request.name,
                            create_status_code);
            return LIBRDP_STATUS_OK;
        }
        if (request.name_len == sizeof(RDP_SESSION_DISPLAY_CONTROL_NAME) - 1u &&
            memcmp(request.name, RDP_SESSION_DISPLAY_CONTROL_NAME, request.name_len) == 0)
        {
            session->display_control_channel_id = request.channel_id;
            session->display_control_channel_id_bytes = request.channel_id_bytes;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.display_control.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_SESSION_CORE_INPUT_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_CORE_INPUT_NAME, request.name_len) == 0)
        {
            session->core_input_channel_id = request.channel_id;
            session->core_input_channel_id_bytes = request.channel_id_bytes;
            session->core_input_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.core_input.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_core_input_init(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_INPUT_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_INPUT_CHANNEL_NAME, request.name_len) == 0)
        {
            session->input_channel_id = request.channel_id;
            session->input_channel_id_bytes = request.channel_id_bytes;
            session->input_channel_ready = 0;
            session->input_channel_suspended = 0;
            session->input_channel_protocol_version = 0;
            session->input_channel_supported_features = 0;
            session->input_channel_max_touch_contacts = 0;
            session->input_channel_supports_pen = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.input_channel.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_AUDIO_INPUT_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_AUDIO_INPUT_CHANNEL_NAME, request.name_len) == 0)
        {
            session->audio_input_channel_id = request.channel_id;
            session->audio_input_channel_id_bytes = request.channel_id_bytes;
            session->audio_input_ready = 0;
            session->audio_input_open = 0;
            session->audio_input_open_reply_sent = 0;
            session->audio_input_version = 0;
            session->audio_input_selected_format_count = 0;
            memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.audin.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_SESSION_WEBAUTHN_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_WEBAUTHN_CHANNEL_NAME, request.name_len) == 0)
        {
            session->webauthn_channel_id = request.channel_id;
            session->webauthn_channel_id_bytes = request.channel_id_bytes;
            session->webauthn_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.webauthn.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_WEBAUTHN));
        }
        else if (request.name_len == sizeof(RDP_SESSION_AUTH_REDIRECTION_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_AUTH_REDIRECTION_NAME, request.name_len) == 0)
        {
            session->auth_redirection_channel_id = request.channel_id;
            session->auth_redirection_channel_id_bytes = request.channel_id_bytes;
            session->auth_redirection_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.auth_redirection.channel",
                            "dvc_channel_id=%u nla_ready=%u",
                            request.channel_id,
                            session->credssp_security_ready ? 1u : 0u);
        }
        else if (request.name_len == sizeof(RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_USB_REDIRECTION_CHANNEL_NAME, request.name_len) == 0)
        {
            session->usb_redirection_channel_id = request.channel_id;
            session->usb_redirection_channel_id_bytes = request.channel_id_bytes;
            session->usb_redirection_ready = 0;
            session->usb_request_completion_ready = 0;
            session->usb_message_id = 0;
            session->usb_request_completion_interface_id = 0;
            session->usb_device_count_sent = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.channel",
                            "dvc_channel_id=%u enabled=%u configured_devices=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_USB),
                            librdp_settings_usb_device_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_COMPOSITED_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_COMPOSITED_CHANNEL_NAME, request.name_len) == 0)
        {
            session->composited_channel_id = request.channel_id;
            session->composited_channel_id_bytes = request.channel_id_bytes;
            session->composited_ready = 0;
            session->composited_connection_open = 0;
            session->composited_connection_id = 0;
            session->composited_open_channel_id = 0;
            rdp_composited_render_tree_reset(&session->composited_tree);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.cr2.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CR2));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_REDIRECTION_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_REDIRECTION_CHANNEL_NAME, request.name_len) == 0)
        {
            session->video_redirection_channel_id = request.channel_id;
            session->video_redirection_channel_id_bytes = request.channel_id_bytes;
            session->video_redirection_ready = 0;
            session->video_redirection_capabilities_sent = 0;
            session->video_redirection_rim_sent = 0;
            memset(session->video_streams, 0, sizeof(session->video_streams));
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.tsmf.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) - 1u &&
                 memcmp(request.name, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL, request.name_len) == 0)
        {
            session->video_optimized_control_channel_id = request.channel_id;
            session->video_optimized_control_channel_id_bytes = request.channel_id_bytes;
            session->video_optimized_control_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.control.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_OPTIMIZED_DATA_CHANNEL) - 1u &&
                 memcmp(request.name, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL, request.name_len) == 0)
        {
            session->video_optimized_data_channel_id = request.channel_id;
            session->video_optimized_data_channel_id_bytes = request.channel_id_bytes;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.video_optimized.data.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME, request.name_len) == 0)
        {
            rdp_session_video_capture_reset(session);
            session->video_capture_control_channel_id = request.channel_id;
            session->video_capture_control_channel_id_bytes = request.channel_id_bytes;
            session->video_capture_version = RDP_VIDEO_CAPTURE_VERSION_2;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.control.channel",
                            "dvc_channel_id=%u enabled=%u cameras=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA),
                            librdp_settings_camera_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_VIDEO_CAPTURE_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_VIDEO_CAPTURE_CHANNEL_NAME, request.name_len) == 0)
        {
            session->video_capture_channel_id = request.channel_id;
            session->video_capture_channel_id_bytes = request.channel_id_bytes;
            session->video_capture_active = 0;
            session->video_capture_streaming = 0;
            session->video_capture_selected_stream = 0;
            if (session->video_capture_version == 0)
                session->video_capture_version = RDP_VIDEO_CAPTURE_VERSION_2;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpecam.data.channel",
                            "dvc_channel_id=%u enabled=%u cameras=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_CAMERA),
                            librdp_settings_camera_count(session->settings));
        }
        else if (request.name_len == sizeof(RDP_SESSION_MOUSE_CURSOR_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_MOUSE_CURSOR_NAME, request.name_len) == 0)
        {
            session->mouse_cursor_channel_id = request.channel_id;
            session->mouse_cursor_channel_id_bytes = request.channel_id_bytes;
            session->mouse_cursor_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_mouse_cursor_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_GRAPHICS_PIPELINE_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_GRAPHICS_PIPELINE_NAME, request.name_len) == 0)
        {
            session->graphics_channel_id = request.channel_id;
            session->graphics_channel_id_bytes = request.channel_id_bytes;
            session->graphics_ready = 0;
            session->graphics_selected_version = 0;
            session->graphics_selected_flags = 0;
            session->graphics_frames_decoded = 0;
            rdp_graphics_decompressor_reset(&session->graphics_decompressor);
            rdp_clearcodec_context_reset(&session->clearcodec);
            rdp_session_graphics_surfaces_clear(session);
            rdp_session_graphics_cache_clear(session);
            rdp_session_gdi_color_table_cache_clear(session);
            rdp_session_gdi_ninegrid_cache_clear(session);
            rdp_session_gdi_glyph_cache_clear(session);
            rdp_session_gdi_glyph_fragment_cache_clear(session);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_graphics_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (entry)
        {
            if (strcmp(entry->name, RDP_SESSION_ECHO_CHANNEL_NAME) == 0)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.echo.channel",
                                "dvc_channel_id=%u enabled=%u",
                                request.channel_id,
                                librdp_settings_feature_enabled(session->settings, LIBRDP_FEATURE_ECHO) ? 1u : 0u);
            }
            else
            {
                rdp_session_emit_channel_open(session, entry);
            }
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.create",
                        "channel_id=%u name=%.*s status=0",
                        request.channel_id,
                        name_len,
                        request.name);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
    {
        rdp_dynamic_channel_data_first_pdu first_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data_first(channel_packet->payload,
                                                      channel_packet->payload_len,
                                                      &first_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (first_pdu.total_length == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (first_pdu.total_length > session->limits.dynamic_channel_message_bytes)
            return rdp_session_limit_rejected(session);
        entry = rdp_session_dynamic_channel_find(session, first_pdu.channel_id);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.fragment.start",
                              "dvc_channel_id=%u name=%s total_len=%u payload_len=%u",
                              first_pdu.channel_id,
                              entry ? entry->name : "",
                              first_pdu.total_length,
                              (unsigned)first_pdu.data_len);
        if (!entry)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (entry->fragmenting)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
        status = rdp_buffer_reserve(&entry->fragment, first_pdu.total_length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&entry->fragment, first_pdu.data, first_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry->fragment_expected = first_pdu.total_length;
        entry->fragmenting = entry->fragment.length < entry->fragment_expected;
        if (!entry->fragmenting)
        {
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                first_pdu.channel_id,
                                                                first_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
        }
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA)
    {
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data(channel_packet->payload, channel_packet->payload_len, &data_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;

        entry = rdp_session_dynamic_channel_find(session, data_pdu.channel_id);
        if (!entry)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "dvc_channel_id=%u name= payload_len=%u",
                                  data_pdu.channel_id,
                                  (unsigned)data_pdu.data_len);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (entry->fragmenting)
        {
            if (data_pdu.data_len == 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (data_pdu.data_len > (size_t)entry->fragment_expected - entry->fragment.length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_buffer_append(&entry->fragment, data_pdu.data, data_pdu.data_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.fragment.data",
                                  "dvc_channel_id=%u name=%s total_len=%u received=%u payload_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  entry->fragment_expected,
                                  (unsigned)entry->fragment.length,
                                  (unsigned)data_pdu.data_len);
            if (entry->fragment.length < entry->fragment_expected)
                return LIBRDP_STATUS_OK;
            entry->fragmenting = 0;
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                data_pdu.channel_id,
                                                                data_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
            return status;
        }
        status = rdp_session_handle_dynamic_channel_message(session,
                                                            entry,
                                                            data_pdu.channel_id,
                                                            data_pdu.channel_id_bytes,
                                                            data_pdu.data,
                                                            data_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED)
    {
        rdp_dynamic_channel_compressed_data_first_pdu first_pdu;
        rdp_session_dynamic_channel* entry = NULL;
        rdp_buffer decoded;

        rdp_buffer_init(&decoded);
        status = rdp_dynamic_channel_parse_compressed_data_first(channel_packet->payload,
                                                                 channel_packet->payload_len,
                                                                 &first_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (first_pdu.total_length == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (first_pdu.total_length > session->limits.dynamic_channel_message_bytes)
            return rdp_session_limit_rejected(session);
        entry = rdp_session_dynamic_channel_find(session, first_pdu.channel_id);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.compressed.fragment.start",
                              "dvc_channel_id=%u name=%s total_len=%u compressed_len=%u",
                              first_pdu.channel_id,
                              entry ? entry->name : "",
                              first_pdu.total_length,
                              (unsigned)first_pdu.data_len);
        if (!entry)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (entry->fragmenting)
        {
            rdp_buffer_free(&decoded);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        status = rdp_graphics_decode_segmented_data(&entry->decompressor,
                                                    first_pdu.data,
                                                    first_pdu.data_len,
                                                    &decoded);
        if (status == LIBRDP_STATUS_OK && decoded.length == 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK && decoded.length > first_pdu.total_length)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&entry->fragment);
            rdp_buffer_init(&entry->fragment);
            status = rdp_buffer_reserve(&entry->fragment, first_pdu.total_length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&entry->fragment, decoded.data, decoded.length);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.drdynvc.compressed.fragment.data",
                              "dvc_channel_id=%u name=%s total_len=%u received=%u compressed_len=%u decoded_len=%u",
                              first_pdu.channel_id,
                              entry->name,
                              first_pdu.total_length,
                              (unsigned)entry->fragment.length,
                              (unsigned)first_pdu.data_len,
                              (unsigned)decoded.length);
        if (status == LIBRDP_STATUS_OK)
        {
            entry->fragment_expected = first_pdu.total_length;
            entry->fragmenting = entry->fragment.length < entry->fragment_expected;
            if (!entry->fragmenting)
            {
                status = rdp_session_handle_dynamic_channel_message(session,
                                                                    entry,
                                                                    first_pdu.channel_id,
                                                                    first_pdu.channel_id_bytes,
                                                                    entry->fragment.data,
                                                                    entry->fragment.length);
                rdp_buffer_free(&entry->fragment);
                entry->fragment_expected = 0;
            }
        }
        rdp_buffer_free(&decoded);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_COMPRESSED)
    {
        rdp_dynamic_channel_compressed_data_pdu data_pdu;
        rdp_session_dynamic_channel* entry = NULL;
        rdp_buffer decoded;

        rdp_buffer_init(&decoded);
        status = rdp_dynamic_channel_parse_compressed_data(channel_packet->payload,
                                                           channel_packet->payload_len,
                                                           &data_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_dynamic_channel_find(session, data_pdu.channel_id);
        if (!entry)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.data",
                                  "dvc_channel_id=%u name= compressed_len=%u",
                                  data_pdu.channel_id,
                                  (unsigned)data_pdu.data_len);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        status = rdp_graphics_decode_segmented_data(&entry->decompressor,
                                                    data_pdu.data,
                                                    data_pdu.data_len,
                                                    &decoded);
        if (status == LIBRDP_STATUS_OK && entry->fragmenting)
        {
            if (decoded.length == 0 ||
                entry->fragment.length > entry->fragment_expected ||
                decoded.length > (size_t)entry->fragment_expected - entry->fragment.length)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            else
            {
                status = rdp_buffer_append(&entry->fragment, decoded.data, decoded.length);
            }
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.fragment.data",
                                  "dvc_channel_id=%u name=%s total_len=%u received=%u compressed_len=%u decoded_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  entry->fragment_expected,
                                  (unsigned)entry->fragment.length,
                                  (unsigned)data_pdu.data_len,
                                  (unsigned)decoded.length);
            if (status == LIBRDP_STATUS_OK && entry->fragment.length >= entry->fragment_expected)
            {
                entry->fragmenting = 0;
                status = rdp_session_handle_dynamic_channel_message(session,
                                                                    entry,
                                                                    data_pdu.channel_id,
                                                                    data_pdu.channel_id_bytes,
                                                                    entry->fragment.data,
                                                                    entry->fragment.length);
                rdp_buffer_free(&entry->fragment);
                entry->fragment_expected = 0;
            }
        }
        else if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.compressed.data",
                                  "dvc_channel_id=%u name=%s compressed_len=%u decoded_len=%u",
                                  data_pdu.channel_id,
                                  entry->name,
                                  (unsigned)data_pdu.data_len,
                                  (unsigned)decoded.length);
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                data_pdu.channel_id,
                                                                data_pdu.channel_id_bytes,
                                                                decoded.data,
                                                                decoded.length);
        }
        rdp_buffer_free(&decoded);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
    {
        rdp_dynamic_channel_close_pdu close_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_close(channel_packet->payload, channel_packet->payload_len, &close_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_dynamic_channel_find(session, close_pdu.channel_id);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.close",
                        "dvc_channel_id=%u name=%s",
                        close_pdu.channel_id,
                        entry ? entry->name : "");
        if (entry)
        {
            if (!rdp_session_dynamic_channel_is_internal(entry))
                rdp_session_emit_channel_close(session, entry);
            if (entry->channel_id == session->display_control_channel_id)
            {
                session->display_control_channel_id = 0;
                session->display_control_channel_id_bytes = 0;
                session->display_control_ready = 0;
                session->sent_desktop_width = 0;
                session->sent_desktop_height = 0;
                memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
            }
            if (entry->channel_id == session->core_input_channel_id)
            {
                session->core_input_channel_id = 0;
                session->core_input_channel_id_bytes = 0;
                session->core_input_ready = 0;
            }
            if (entry->channel_id == session->input_channel_id)
            {
                session->input_channel_id = 0;
                session->input_channel_id_bytes = 0;
                session->input_channel_ready = 0;
                session->input_channel_suspended = 0;
                session->input_channel_protocol_version = 0;
                session->input_channel_supported_features = 0;
                session->input_channel_max_touch_contacts = 0;
                session->input_channel_supports_pen = 0;
            }
            if (entry->channel_id == session->audio_input_channel_id)
            {
                session->audio_input_channel_id = 0;
                session->audio_input_channel_id_bytes = 0;
                session->audio_input_ready = 0;
                session->audio_input_open = 0;
                session->audio_input_open_reply_sent = 0;
                session->audio_input_version = 0;
                session->audio_input_selected_format_count = 0;
                memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
            }
            if (entry->channel_id == session->auth_redirection_channel_id)
                rdp_session_auth_redirection_channel_reset(session);
            if (entry->channel_id == session->webauthn_channel_id)
                rdp_session_webauthn_channel_reset(session);
            if (entry->channel_id == session->mouse_cursor_channel_id)
            {
                session->mouse_cursor_channel_id = 0;
                session->mouse_cursor_channel_id_bytes = 0;
                session->mouse_cursor_ready = 0;
                rdp_session_pointer_emit_default(session);
            }
            if (entry->channel_id == session->graphics_channel_id)
            {
                session->graphics_channel_id = 0;
                session->graphics_channel_id_bytes = 0;
                session->graphics_ready = 0;
                session->graphics_selected_version = 0;
                session->graphics_selected_flags = 0;
                session->graphics_frames_decoded = 0;
                rdp_graphics_decompressor_reset(&session->graphics_decompressor);
                rdp_clearcodec_context_reset(&session->clearcodec);
                rdp_session_graphics_surfaces_clear(session);
                rdp_session_graphics_cache_clear(session);
                rdp_session_gdi_color_table_cache_clear(session);
                rdp_session_gdi_ninegrid_cache_clear(session);
                rdp_session_gdi_glyph_cache_clear(session);
                rdp_session_gdi_glyph_fragment_cache_clear(session);
            }
            if (entry->channel_id == session->usb_redirection_channel_id)
                rdp_session_usb_redirection_reset(session);
            if (entry->channel_id == session->composited_channel_id)
                rdp_session_composited_reset(session);
            if (entry->channel_id == session->video_redirection_channel_id)
                rdp_session_video_redirection_reset(session);
            if (entry->channel_id == session->video_optimized_control_channel_id ||
                entry->channel_id == session->video_optimized_data_channel_id)
                rdp_session_video_optimized_reset(session);
            if (entry->channel_id == session->video_capture_control_channel_id ||
                entry->channel_id == session->video_capture_channel_id)
                rdp_session_video_capture_reset(session);
            rdp_session_dynamic_channel_clear_entry(entry);
        }
    }
    else
    {
        if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST)
        {
            rdp_dynamic_channel_soft_sync_request request;
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_dynamic_channel_parse_soft_sync_request(channel_packet->payload,
                                                                 channel_packet->payload_len,
                                                                 &request);
            if (status == LIBRDP_STATUS_OK &&
                request.tunnel_count > 0 &&
                (!rdp_session_multitransport_runtime_supported() ||
                 !session->multitransport_negotiated ||
                 session->multitransport_flags == 0))
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.drdynvc.soft_sync.ignored",
                                "tunnel_count=%u reason=multitransport_unavailable",
                                request.tunnel_count);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_dynamic_channel_write_soft_sync_response(&response, NULL, 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session,
                                                       session->dynamic_channel_id,
                                                       &response,
                                                       "client.drdynvc.soft_sync");
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.soft_sync",
                            "flags=%u tunnel_count=%u",
                            request.flags,
                            request.tunnel_count);
        }
        else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE)
        {
            rdp_dynamic_channel_soft_sync_response response;

            status = rdp_dynamic_channel_parse_soft_sync_response(channel_packet->payload,
                                                                  channel_packet->payload_len,
                                                                  &response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.soft_sync_response",
                            "tunnel_count=%u",
                            response.tunnel_count);
        }
        else
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "command=%u payload_len=%u",
                                  header.command,
                                  (unsigned)channel_packet->payload_len);
        }
    }

    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
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

static librdp_status rdp_session_read_fastpath_packet(librdp_session* session, rdp_buffer* packet)
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

static librdp_status rdp_session_read_credssp_ts_request(librdp_session* session, rdp_buffer* packet, int timeout_ms)
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

static librdp_status rdp_session_apply_bitmap_update(librdp_session* session, const rdp_bitmap_update* update)
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

static librdp_status rdp_session_blit_bgra32_flipped(librdp_session* session,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     const uint8_t* pixels,
                                                     size_t stride)
{
    rdp_buffer flipped;
    size_t output_stride = 0;
    size_t output_size = 0;
    uint32_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / output_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_size = (size_t)height * output_stride;
    rdp_buffer_init(&flipped);
    status = rdp_buffer_reserve(&flipped, output_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    flipped.length = output_size;
    for (row = 0; row < height; row++)
    {
        const uint8_t* src = pixels + ((size_t)(height - 1u - row) * stride);
        uint8_t* dst = flipped.data + ((size_t)row * output_stride);

        memcpy(dst, src, output_stride);
    }
    status = librdp_surface_blit_bgra32(session->surface,
                                        x,
                                        y,
                                        width,
                                        height,
                                        flipped.data,
                                        output_stride);
    rdp_buffer_free(&flipped);
    return status;
}

static librdp_status rdp_session_apply_surface_bits_raw(librdp_session* session,
                                                        const rdp_surface_bits* bits)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = bits->dest_left;
    rect.dest_top = bits->dest_top;
    rect.dest_right = bits->dest_right;
    rect.dest_bottom = bits->dest_bottom;
    rect.width = bits->width;
    rect.height = bits->height;
    rect.bits_per_pixel = bits->bpp;
    rect.flags = 0;
    rect.data = bits->bitmap_data;
    rect.data_len = bits->bitmap_data_length;
    rdp_buffer_init(&pixels);
    status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                        session->palette_valid ? &session->palette : NULL,
                                                        &pixels,
                                                        &stride);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_surface_blit_bgra32(session->surface,
                                            bits->dest_left,
                                            bits->dest_top,
                                            bits->width,
                                            bits->height,
                                            pixels.data,
                                            stride);
    rdp_buffer_free(&pixels);
    return status;
}

static librdp_status rdp_session_apply_surface_bits_nscodec(librdp_session* session,
                                                            const rdp_surface_bits* bits)
{
    rdp_buffer pixels;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&pixels);
    status = rdp_nscodec_decode_bgra32(&session->surface_nscodec,
                                       bits->bitmap_data,
                                       bits->bitmap_data_length,
                                       bits->width,
                                       bits->height,
                                       &pixels,
                                       &stride);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_blit_bgra32_flipped(session,
                                                 bits->dest_left,
                                                 bits->dest_top,
                                                 bits->width,
                                                 bits->height,
                                                 pixels.data,
                                                 stride);
    rdp_buffer_free(&pixels);
    return status;
}

typedef struct rdp_session_rfx_surface_context
{
    librdp_session* session;
    const rdp_surface_bits* bits;
    uint16_t tiles;
} rdp_session_rfx_surface_context;

static librdp_status rdp_session_rfx_surface_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_rfx_surface_context* context = (rdp_session_rfx_surface_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t dest_x = 0;
    uint32_t dest_y = 0;

    if (!tile || !context || !context->session || !context->bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->bits->width || tile->y >= context->bits->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->bits->width - tile->x)
        width = context->bits->width - tile->x;
    if (height > context->bits->height - tile->y)
        height = context->bits->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    dest_x = (uint32_t)context->bits->dest_left + tile->x;
    dest_y = (uint32_t)context->bits->dest_top + tile->y;
    if (dest_x > librdp_surface_width(context->session->surface) ||
        dest_y > librdp_surface_height(context->session->surface) ||
        width > librdp_surface_width(context->session->surface) - dest_x ||
        height > librdp_surface_height(context->session->surface) - dest_y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.surface.rfx.tile",
                          "x=%u y=%u width=%u height=%u tile_x=%u tile_y=%u",
                          dest_x,
                          dest_y,
                          width,
                          height,
                          tile->x_idx,
                          tile->y_idx);
    return librdp_surface_blit_bgra32(context->session->surface,
                                      dest_x,
                                      dest_y,
                                      width,
                                      height,
                                      tile->pixels.bgra,
                                      tile->pixels.stride);
}

static librdp_status rdp_session_apply_surface_bits_rfx(librdp_session* session,
                                                        const rdp_surface_bits* bits)
{
    rdp_session_rfx_surface_context context;
    rdp_rfx_stream_summary summary;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.session = session;
    context.bits = bits;
    status = rdp_rfx_stream_decode(bits->bitmap_data,
                                   bits->bitmap_data_length,
                                   rdp_session_rfx_surface_tile,
                                   &context,
                                   &summary);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.surface.rfx.blit",
                        "frame_id=%u width=%u height=%u tiles=%u rects=%u blitted=%u",
                        summary.frame_id,
                        summary.width,
                        summary.height,
                        summary.tile_count,
                        summary.rect_count,
                        context.tiles);
    return status;
}

static librdp_status rdp_session_apply_surface_bits(librdp_session* session,
                                                    const rdp_surface_bits* bits)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t dest_width = 0;
    uint32_t dest_height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (bits->dest_right > surface_width || bits->dest_bottom > surface_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    dest_width = (uint32_t)(bits->dest_right - bits->dest_left);
    dest_height = (uint32_t)(bits->dest_bottom - bits->dest_top);
    if (dest_width == 0 || dest_height == 0 || bits->width != dest_width || bits->height != dest_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (bits->codec_id == RDP_SURFACE_CODEC_NONE)
        status = rdp_session_apply_surface_bits_raw(session, bits);
    else if (bits->codec_id == RDP_SURFACE_CODEC_NSCODEC)
        status = rdp_session_apply_surface_bits_nscodec(session, bits);
    else if (bits->codec_id == RDP_SURFACE_CODEC_REMOTEFX ||
             bits->codec_id == RDP_SURFACE_CODEC_IMAGE_REMOTEFX)
        status = rdp_session_apply_surface_bits_rfx(session, bits);
    else
        status = LIBRDP_STATUS_UNSUPPORTED;

    if (status == LIBRDP_STATUS_OK)
    {
        rdp_session_emit_surface_invalidated(session,
                                             bits->dest_left,
                                             bits->dest_top,
                                             bits->width,
                                             bits->height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.surface.bits.blit",
                        "codec_id=%u x=%u y=%u width=%u height=%u bpp=%u command_type=%u",
                        bits->codec_id,
                        bits->dest_left,
                        bits->dest_top,
                        bits->width,
                        bits->height,
                        bits->bpp,
                        bits->command_type);
    }
    return status;
}

static librdp_status rdp_session_apply_surface_commands(librdp_session* session,
                                                        const rdp_surface_command_list* list)
{
    uint16_t i = 0;

    if (!session || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < list->count; i++)
    {
        const rdp_surface_command* command = &list->commands[i];
        librdp_status status = LIBRDP_STATUS_OK;

        if (command->kind == RDP_SURFACE_COMMAND_KIND_FRAME_MARKER)
        {
            if (command->frame_marker.action == 0u)
                rdp_session_emit_graphics_frame(session,
                                                LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                                command->frame_marker.has_frame_id ?
                                                    command->frame_marker.frame_id :
                                                    session->graphics_current_frame_id);
            else if (command->frame_marker.action == 1u)
                rdp_session_emit_graphics_frame(session,
                                                LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                                command->frame_marker.has_frame_id ?
                                                    command->frame_marker.frame_id :
                                                    session->graphics_current_frame_id);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.surface.frame_marker",
                                  "action=%u frame_id=%u has_frame_id=%u",
                                  command->frame_marker.action,
                                  command->frame_marker.frame_id,
                                  command->frame_marker.has_frame_id);
            continue;
        }
        if (command->kind != RDP_SURFACE_COMMAND_KIND_BITS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_session_apply_surface_bits(session, &command->bits);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.surface.bits.rejected",
                            "codec_id=%u command_type=%u width=%u height=%u payload_len=%u",
                            command->bits.codec_id,
                            command->bits.command_type,
                            command->bits.width,
                            command->bits.height,
                            command->bits.bitmap_data_length);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_palette_reset(librdp_session* session)
{
    if (!session)
        return;
    session->palette_valid = 0;
    memset(&session->palette, 0, sizeof(session->palette));
}

static librdp_status rdp_session_apply_palette_update(librdp_session* session, const rdp_palette_update* palette)
{
    if (!session || !palette || palette->count > RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    session->palette = *palette;
    session->palette_valid = 1;
    rdp_trace_event(RDP_TRACE_CLIENT, "client.graphics.palette.update", "colors=%u", palette->count);
    return LIBRDP_STATUS_OK;
}

typedef struct rdp_session_gdi_region
{
    uint32_t dst_x;
    uint32_t dst_y;
    uint32_t src_x;
    uint32_t src_y;
    uint32_t width;
    uint32_t height;
} rdp_session_gdi_region;

static uint8_t rdp_session_gdi_rop3(uint8_t rop, uint8_t source, uint8_t pattern, uint8_t dest)
{
    uint8_t result = 0;
    uint8_t bit = 0;

    for (bit = 0; bit < 8u; bit++)
    {
        uint8_t index = (uint8_t)((((pattern >> bit) & 1u) << 2u) |
                                  (((source >> bit) & 1u) << 1u) |
                                  ((dest >> bit) & 1u));

        if ((rop >> index) & 1u)
            result |= (uint8_t)(1u << bit);
    }
    return result;
}

static int rdp_session_gdi_clip_dest(const rdp_gdi_render_op* op,
                                     uint32_t surface_width,
                                     uint32_t surface_height,
                                     rdp_session_gdi_region* region)
{
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    int64_t clip_left = 0;
    int64_t clip_top = 0;
    int64_t clip_right = surface_width;
    int64_t clip_bottom = surface_height;

    if (!op || !region || op->rect.width <= 0 || op->rect.height <= 0 || surface_width == 0 || surface_height == 0)
        return 0;
    left = op->rect.x;
    top = op->rect.y;
    right = (int64_t)op->rect.x + op->rect.width;
    bottom = (int64_t)op->rect.y + op->rect.height;
    if (op->bounds.present)
    {
        clip_left = op->bounds.left;
        clip_top = op->bounds.top;
        clip_right = (int64_t)op->bounds.right + 1;
        clip_bottom = (int64_t)op->bounds.bottom + 1;
    }
    if (clip_left < 0)
        clip_left = 0;
    if (clip_top < 0)
        clip_top = 0;
    if (clip_right > (int64_t)surface_width)
        clip_right = surface_width;
    if (clip_bottom > (int64_t)surface_height)
        clip_bottom = surface_height;
    if (left < clip_left)
        left = clip_left;
    if (top < clip_top)
        top = clip_top;
    if (right > clip_right)
        right = clip_right;
    if (bottom > clip_bottom)
        bottom = clip_bottom;
    if (left >= right || top >= bottom)
        return 0;
    region->dst_x = (uint32_t)left;
    region->dst_y = (uint32_t)top;
    region->width = (uint32_t)(right - left);
    region->height = (uint32_t)(bottom - top);
    region->src_x = 0;
    region->src_y = 0;
    return 1;
}

static int rdp_session_gdi_clip_copy(const rdp_gdi_render_op* op,
                                     uint32_t surface_width,
                                     uint32_t surface_height,
                                     rdp_session_gdi_region* region)
{
    int64_t src_x = 0;
    int64_t src_y = 0;
    int64_t shift = 0;

    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, region))
        return 0;
    src_x = (int64_t)op->src_x + ((int64_t)region->dst_x - op->rect.x);
    src_y = (int64_t)op->src_y + ((int64_t)region->dst_y - op->rect.y);
    if (src_x < 0)
    {
        shift = -src_x;
        if (shift >= (int64_t)region->width)
            return 0;
        region->dst_x += (uint32_t)shift;
        region->width -= (uint32_t)shift;
        src_x = 0;
    }
    if (src_y < 0)
    {
        shift = -src_y;
        if (shift >= (int64_t)region->height)
            return 0;
        region->dst_y += (uint32_t)shift;
        region->height -= (uint32_t)shift;
        src_y = 0;
    }
    if (src_x >= (int64_t)surface_width || src_y >= (int64_t)surface_height)
        return 0;
    if (region->width > surface_width - (uint32_t)src_x)
        region->width = surface_width - (uint32_t)src_x;
    if (region->height > surface_height - (uint32_t)src_y)
        region->height = surface_height - (uint32_t)src_y;
    if (region->width == 0 || region->height == 0)
        return 0;
    region->src_x = (uint32_t)src_x;
    region->src_y = (uint32_t)src_y;
    return 1;
}

static int rdp_session_gdi_clip_bitmap_copy(const rdp_gdi_render_op* op,
                                            uint32_t surface_width,
                                            uint32_t surface_height,
                                            uint32_t source_width,
                                            uint32_t source_height,
                                            rdp_session_gdi_region* region)
{
    int64_t src_x = 0;
    int64_t src_y = 0;
    int64_t shift = 0;

    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, region) ||
        source_width == 0 || source_height == 0)
        return 0;
    src_x = (int64_t)op->src_x + ((int64_t)region->dst_x - op->rect.x);
    src_y = (int64_t)op->src_y + ((int64_t)region->dst_y - op->rect.y);
    if (src_x < 0)
    {
        shift = -src_x;
        if (shift >= (int64_t)region->width)
            return 0;
        region->dst_x += (uint32_t)shift;
        region->width -= (uint32_t)shift;
        src_x = 0;
    }
    if (src_y < 0)
    {
        shift = -src_y;
        if (shift >= (int64_t)region->height)
            return 0;
        region->dst_y += (uint32_t)shift;
        region->height -= (uint32_t)shift;
        src_y = 0;
    }
    if (src_x >= (int64_t)source_width || src_y >= (int64_t)source_height)
        return 0;
    if (region->width > source_width - (uint32_t)src_x)
        region->width = source_width - (uint32_t)src_x;
    if (region->height > source_height - (uint32_t)src_y)
        region->height = source_height - (uint32_t)src_y;
    if (region->width == 0 || region->height == 0)
        return 0;
    region->src_x = (uint32_t)src_x;
    region->src_y = (uint32_t)src_y;
    return 1;
}

static librdp_status rdp_session_gdi_save_bitmap(librdp_session* session,
                                                 const rdp_gdi_render_op* op,
                                                 const rdp_session_gdi_region* region)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t row_bytes = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint32_t y = 0;
    uint32_t origin_x = 0;
    uint32_t origin_y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (region->width == 0 || region->height == 0)
        return LIBRDP_STATUS_OK;
    row_bytes = (size_t)region->width * 4u;
    if ((size_t)region->height > ((size_t)-1) / row_bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = row_bytes * (size_t)region->height;

    entry = rdp_session_gdi_saved_bitmap_slot(session, op->bitmap_id);
    if (!entry)
        return LIBRDP_STATUS_NO_MEMORY;
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->gdi_saved_bitmap_bytes >= old_size ?
                          session->gdi_saved_bitmap_bytes - old_size :
                          0;
    if (size > RDP_SESSION_GDI_SAVE_BITMAP_MAX_BYTES ||
        current_without_old > RDP_SESSION_GDI_SAVE_BITMAP_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = pixels + ((size_t)(region->dst_y + y) * stride) +
                             ((size_t)region->dst_x * 4u);
        uint8_t* dst = entry->pixels.data + ((size_t)y * row_bytes);

        memcpy(dst, src, row_bytes);
    }
    origin_x = (uint32_t)((int64_t)region->dst_x - op->rect.x);
    origin_y = (uint32_t)((int64_t)region->dst_y - op->rect.y);
    entry->pixels.length = size;
    entry->active = 1;
    entry->bitmap_id = op->bitmap_id;
    entry->width = region->width;
    entry->height = region->height;
    entry->origin_x = origin_x;
    entry->origin_y = origin_y;
    session->gdi_saved_bitmap_bytes = current_without_old + size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.save_bitmap.store",
                          "id=%u x=%u y=%u width=%u height=%u bytes=%u total_bytes=%u",
                          op->bitmap_id,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          (unsigned)size,
                          (unsigned)session->gdi_saved_bitmap_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_restore_bitmap(librdp_session* session,
                                                    const rdp_gdi_render_op* op,
                                                    const rdp_session_gdi_region* region)
{
    rdp_session_gdi_saved_bitmap* entry = NULL;
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t row_bytes = 0;
    uint32_t src_x = 0;
    uint32_t src_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t y = 0;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    entry = rdp_session_gdi_saved_bitmap_find(session, op->bitmap_id);
    if (!entry || !entry->active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.save_bitmap.miss",
                              "id=%u x=%u y=%u width=%u height=%u",
                              op->bitmap_id,
                              region->dst_x,
                              region->dst_y,
                              region->width,
                              region->height);
        return LIBRDP_STATUS_OK;
    }
    if ((int64_t)region->dst_x - op->rect.x < (int64_t)entry->origin_x ||
        (int64_t)region->dst_y - op->rect.y < (int64_t)entry->origin_y)
        return LIBRDP_STATUS_OK;
    src_x = (uint32_t)((int64_t)region->dst_x - op->rect.x - entry->origin_x);
    src_y = (uint32_t)((int64_t)region->dst_y - op->rect.y - entry->origin_y);
    if (src_x >= entry->width || src_y >= entry->height)
        return LIBRDP_STATUS_OK;
    width = region->width;
    height = region->height;
    if (width > entry->width - src_x)
        width = entry->width - src_x;
    if (height > entry->height - src_y)
        height = entry->height - src_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_bytes = (size_t)width * 4u;
    for (y = 0; y < height; y++)
    {
        const uint8_t* src = entry->pixels.data + (((size_t)(src_y + y) * entry->width) + src_x) * 4u;
        uint8_t* dst = pixels + ((size_t)(region->dst_y + y) * stride) +
                       ((size_t)region->dst_x * 4u);

        memcpy(dst, src, row_bytes);
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, width, height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.save_bitmap.restore",
                          "id=%u x=%u y=%u width=%u height=%u",
                          op->bitmap_id,
                          region->dst_x,
                          region->dst_y,
                          width,
                          height);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_fill_rect(librdp_session* session,
                                               const rdp_gdi_render_op* op,
                                               const rdp_session_gdi_region* region,
                                               uint8_t rop,
                                               uint32_t color,
                                               int use_rop)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t y = 0;
    uint8_t b = (uint8_t)(color & 0xffu);
    uint8_t g = (uint8_t)((color >> 8u) & 0xffu);
    uint8_t r = (uint8_t)((color >> 16u) & 0xffu);

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (y = 0; y < region->height; y++)
    {
        uint8_t* pixel = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            if (use_rop)
            {
                pixel[0] = rdp_session_gdi_rop3(rop, 0, b, pixel[0]);
                pixel[1] = rdp_session_gdi_rop3(rop, 0, g, pixel[1]);
                pixel[2] = rdp_session_gdi_rop3(rop, 0, r, pixel[2]);
            }
            else
            {
                pixel[0] = b;
                pixel[1] = g;
                pixel[2] = r;
            }
            pixel[3] = 0xffu;
            pixel += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u rop=%u color=%06x",
                          op->order_type,
                          op->kind,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          rop,
                          color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_hatch_bit(uint8_t hatch, uint32_t x, uint32_t y)
{
    uint32_t px = x & 7u;
    uint32_t py = y & 7u;

    switch (hatch)
    {
        case 0u:
            return py == 0u;
        case 1u:
            return px == 0u;
        case 2u:
            return ((px + py) & 7u) == 0u;
        case 3u:
            return ((px + (7u - py)) & 7u) == 0u;
        case 4u:
            return px == 0u || py == 0u;
        case 5u:
            return ((px + py) & 7u) == 0u || ((px + (7u - py)) & 7u) == 0u;
        default:
            return 0;
    }
}

static int rdp_session_gdi_pattern_bit(const rdp_gdi_render_op* op, uint32_t x, uint32_t y)
{
    uint8_t pattern[8];
    uint32_t px = 0;
    uint32_t py = 0;

    if (!op)
        return 0;
    pattern[0] = op->brush_hatch;
    memcpy(pattern + 1u, op->brush_extra, sizeof(op->brush_extra));
    px = (uint32_t)((int64_t)x - op->brush_x) & 7u;
    py = (uint32_t)((int64_t)y - op->brush_y) & 7u;
    return ((pattern[py] >> (7u - px)) & 1u) != 0;
}

static int rdp_session_gdi_brush_style_is_pattern(uint8_t style)
{
    switch (style & (uint8_t)~RDP_GDI_CACHED_BRUSH)
    {
        case RDP_SESSION_GDI_BRUSH_PATTERN:
        case RDP_SESSION_GDI_BRUSH_INDEXED:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERN:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERNPT:
        case RDP_SESSION_GDI_BRUSH_PATTERN8X8:
        case RDP_SESSION_GDI_BRUSH_DIBPATTERN8X8:
            return 1;
        default:
            return 0;
    }
}

static const rdp_session_gdi_brush_cache_entry*
rdp_session_gdi_cached_brush_find(const librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t cache_entry = 0;
    uint32_t format = 0;
    const rdp_session_gdi_brush_cache_entry* entry = NULL;

    if (!session || !op || (op->brush_style & RDP_GDI_CACHED_BRUSH) == 0)
        return NULL;
    cache_entry = op->brush_hatch;
    format = op->brush_style & 0x0fu;
    if (cache_entry >= RDP_SESSION_GDI_BRUSH_CACHE_SLOTS)
        return NULL;
    entry = &session->gdi_brush_cache[cache_entry];
    if (!entry->active || entry->cache_entry != cache_entry || entry->bitmap_format != format)
        return NULL;
    return entry;
}

static int rdp_session_gdi_cached_brush_bgr(const rdp_session_gdi_brush_cache_entry* entry,
                                            const rdp_gdi_render_op* op,
                                            uint32_t x,
                                            uint32_t y,
                                            uint8_t* b,
                                            uint8_t* g,
                                            uint8_t* r)
{
    uint32_t px = 0;
    uint32_t py = 0;
    const uint8_t* color = NULL;

    if (!entry || !op)
        return 0;
    px = (uint32_t)((int64_t)x - op->brush_x) & 7u;
    py = (uint32_t)((int64_t)y - op->brush_y) & 7u;
    if (entry->mono)
    {
        uint32_t source = ((entry->mono_rows[py] >> (7u - px)) & 1u) ? op->color : op->back_color;

        if (b)
            *b = (uint8_t)(source & 0xffu);
        if (g)
            *g = (uint8_t)((source >> 8u) & 0xffu);
        if (r)
            *r = (uint8_t)((source >> 16u) & 0xffu);
        return 1;
    }
    color = entry->bgra + (((size_t)py * 8u + px) * 4u);
    if (b)
        *b = color[0];
    if (g)
        *g = color[1];
    if (r)
        *r = color[2];
    return 1;
}

static void rdp_session_gdi_brush_bgr(const librdp_session* session,
                                      const rdp_gdi_render_op* op,
                                      uint32_t x,
                                      uint32_t y,
                                      uint8_t* b,
                                      uint8_t* g,
                                      uint8_t* r)
{
    const rdp_session_gdi_brush_cache_entry* cached = rdp_session_gdi_cached_brush_find(session, op);
    uint32_t color = op ? op->color : 0;
    int foreground = 1;

    if (cached && rdp_session_gdi_cached_brush_bgr(cached, op, x, y, b, g, r))
        return;
    if (op && op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
        foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, x, y);
    else if (op && rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        foreground = rdp_session_gdi_pattern_bit(op, x, y);
    if (!foreground && op)
        color = op->back_color;
    if (b)
        *b = (uint8_t)(color & 0xffu);
    if (g)
        *g = (uint8_t)((color >> 8u) & 0xffu);
    if (r)
        *r = (uint8_t)((color >> 16u) & 0xffu);
}

/*
 * Copy a cached GDI bitmap into the target surface. Cache lookup, source
 * clipping, raster operation, and destination bounds are validated before
 * pixels are written.
 */
static librdp_status rdp_session_gdi_copy_cached_bitmap(librdp_session* session,
                                                        const rdp_gdi_render_op* op,
                                                        const rdp_session_gdi_bitmap_cache_entry* entry,
                                                        const rdp_session_gdi_region* region)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    const uint8_t* source_pixels = NULL;
    size_t source_stride = 0;
    rdp_buffer decoded;
    uint32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !entry || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&decoded);
    if (op->kind == RDP_GDI_RENDER_OP_MEM3BLT &&
        (op->brush_style & RDP_GDI_CACHED_BRUSH) != 0 &&
        !rdp_session_gdi_cached_brush_find(session, op))
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.brush_cache.miss",
                              "kind=%u cache_entry=%u brush_style=%u",
                              op->kind,
                              op->brush_hatch,
                              op->brush_style);
        return LIBRDP_STATUS_OK;
    }
    if (entry->pixels.data)
    {
        if (entry->stride < (size_t)entry->width * 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        source_pixels = entry->pixels.data;
        source_stride = entry->stride;
    }
    else if (entry->bits_per_pixel == 8u && entry->raw.data)
    {
        rdp_bitmap_rect rect;
        const rdp_palette_update* palette = rdp_session_gdi_color_table_find(session, op->color_index);

        if (!palette && session->palette_valid)
            palette = &session->palette;
        if (!palette)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.gdi.color_table.miss",
                                  "cache_id=%u cache_index=%u color_index=%u",
                                  op->cache_id,
                                  op->cache_index,
                                  op->color_index);
            return LIBRDP_STATUS_OK;
        }
        if (entry->raw.length > UINT32_MAX)
        {
            rdp_buffer_free(&decoded);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        memset(&rect, 0, sizeof(rect));
        rect.dest_right = (uint16_t)(entry->width - 1u);
        rect.dest_bottom = (uint16_t)(entry->height - 1u);
        rect.width = (uint16_t)entry->width;
        rect.height = (uint16_t)entry->height;
        rect.bits_per_pixel = (uint16_t)entry->bits_per_pixel;
        rect.flags = entry->bitmap_flags;
        rect.data = entry->raw.data;
        rect.data_len = (uint32_t)entry->raw.length;
        status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect, palette, &decoded, &source_stride);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&decoded);
            return status;
        }
        source_pixels = decoded.data;
    }
    else
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
    {
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = source_pixels + ((size_t)(region->src_y + y) * source_stride) +
                             ((size_t)region->src_x * 4u);
        uint8_t* dst = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            uint8_t pb = 0;
            uint8_t pg = 0;
            uint8_t pr = 0;

            if (op->kind == RDP_GDI_RENDER_OP_MEM3BLT)
                rdp_session_gdi_brush_bgr(session, op, region->dst_x + x, region->dst_y + y, &pb, &pg, &pr);
            dst[0] = rdp_session_gdi_rop3(op->rop, src[0], pb, dst[0]);
            dst[1] = rdp_session_gdi_rop3(op->rop, src[1], pg, dst[1]);
            dst[2] = rdp_session_gdi_rop3(op->rop, src[2], pr, dst[2]);
            dst[3] = 0xffu;
            src += 4u;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.blit",
                          "kind=%u cache_id=%u cache_index=%u src_x=%u src_y=%u x=%u y=%u width=%u height=%u rop=%u",
                          op->kind,
                          op->cache_id,
                          op->cache_index,
                          region->src_x,
                          region->src_y,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop);
    rdp_buffer_free(&decoded);
    return LIBRDP_STATUS_OK;
}

/*
 * Render a GDI PatBlt order into the session surface. Brush resolution, raster
 * operation selection, and clipping are kept in one path to avoid inconsistent
 * cache use.
 */
static librdp_status rdp_session_gdi_patblt(librdp_session* session,
                                            const rdp_gdi_render_op* op,
                                            const rdp_session_gdi_region* region)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t y = 0;
    uint8_t fore_b = 0;
    uint8_t fore_g = 0;
    uint8_t fore_r = 0;
    uint8_t back_b = 0;
    uint8_t back_g = 0;
    uint8_t back_r = 0;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_NULL)
        return LIBRDP_STATUS_OK;
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0 &&
        !rdp_session_gdi_cached_brush_find(session, op))
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.brush_cache.miss",
                              "kind=%u cache_entry=%u brush_style=%u",
                              op->kind,
                              op->brush_hatch,
                              op->brush_style);
        return LIBRDP_STATUS_OK;
    }
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) == 0 &&
        op->brush_style != RDP_SESSION_GDI_BRUSH_SOLID &&
        op->brush_style != RDP_SESSION_GDI_BRUSH_HATCHED &&
        !rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        return LIBRDP_STATUS_UNSUPPORTED;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fore_b = (uint8_t)(op->color & 0xffu);
    fore_g = (uint8_t)((op->color >> 8u) & 0xffu);
    fore_r = (uint8_t)((op->color >> 16u) & 0xffu);
    back_b = (uint8_t)(op->back_color & 0xffu);
    back_g = (uint8_t)((op->back_color >> 8u) & 0xffu);
    back_r = (uint8_t)((op->back_color >> 16u) & 0xffu);
    for (y = 0; y < region->height; y++)
    {
        uint8_t* pixel = pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            uint32_t absolute_x = region->dst_x + x;
            uint32_t absolute_y = region->dst_y + y;
            int foreground = 1;
            uint8_t b = fore_b;
            uint8_t g = fore_g;
            uint8_t r = fore_r;

            if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0)
            {
                rdp_session_gdi_brush_bgr(session, op, absolute_x, absolute_y, &b, &g, &r);
                foreground = 1;
            }
            else if (op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
                foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, absolute_x, absolute_y);
            else if (rdp_session_gdi_brush_style_is_pattern(op->brush_style))
                foreground = rdp_session_gdi_pattern_bit(op, absolute_x, absolute_y);
            if (!foreground)
            {
                b = back_b;
                g = back_g;
                r = back_r;
            }
            pixel[0] = rdp_session_gdi_rop3(op->rop, 0, b, pixel[0]);
            pixel[1] = rdp_session_gdi_rop3(op->rop, 0, g, pixel[1]);
            pixel[2] = rdp_session_gdi_rop3(op->rop, 0, r, pixel[2]);
            pixel[3] = 0xffu;
            pixel += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u rop=%u brush_style=%u brush_hatch=%u fore=%06x back=%06x",
                          op->order_type,
                          op->kind,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop,
                          op->brush_style,
                          op->brush_hatch,
                          op->color & 0x00ffffffu,
                          op->back_color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_copy_rect(librdp_session* session,
                                               const rdp_gdi_render_op* op,
                                               const rdp_session_gdi_region* region)
{
    rdp_buffer temp;
    const uint8_t* pixels = NULL;
    uint8_t* mutable_pixels = NULL;
    size_t stride = 0;
    size_t row_stride = 0;
    uint32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op || !region)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pixels = librdp_surface_pixels(session->surface);
    mutable_pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || !mutable_pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_stride = (size_t)region->width * 4u;
    rdp_buffer_init(&temp);
    status = rdp_buffer_reserve(&temp, row_stride * (size_t)region->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (y = 0; y < region->height; y++)
    {
        memcpy(temp.data + ((size_t)y * row_stride),
               pixels + ((size_t)(region->src_y + y) * stride) + ((size_t)region->src_x * 4u),
               row_stride);
    }
    temp.length = row_stride * (size_t)region->height;
    for (y = 0; y < region->height; y++)
    {
        const uint8_t* src = temp.data + ((size_t)y * row_stride);
        uint8_t* dst = mutable_pixels + ((size_t)(region->dst_y + y) * stride) + ((size_t)region->dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region->width; x++)
        {
            dst[0] = rdp_session_gdi_rop3(op->rop, src[0], 0, dst[0]);
            dst[1] = rdp_session_gdi_rop3(op->rop, src[1], 0, dst[1]);
            dst[2] = rdp_session_gdi_rop3(op->rop, src[2], 0, dst[2]);
            dst[3] = 0xffu;
            src += 4u;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region->dst_x, region->dst_y, region->width, region->height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u src_x=%u src_y=%u x=%u y=%u width=%u height=%u rop=%u",
                          op->order_type,
                          op->kind,
                          region->src_x,
                          region->src_y,
                          region->dst_x,
                          region->dst_y,
                          region->width,
                          region->height,
                          op->rop);
    rdp_buffer_free(&temp);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_glyph_bit(const rdp_session_gdi_glyph_cache_entry* glyph,
                                     uint32_t x,
                                     uint32_t y)
{
    size_t row_stride = 0;
    size_t offset = 0;
    uint8_t mask = 0;

    if (!glyph || !glyph->active || !glyph->bitmap.data ||
        x >= glyph->width || y >= glyph->height)
        return 0;
    row_stride = (size_t)(glyph->width + 7u) / 8u;
    offset = (size_t)y * row_stride + (x / 8u);
    if (offset >= glyph->bitmap.length)
        return 0;
    mask = (uint8_t)(0x80u >> (x & 7u));
    return (glyph->bitmap.data[offset] & mask) != 0;
}

static void rdp_session_gdi_glyph_advance(const uint8_t* data,
                                          uint32_t length,
                                          uint32_t* index,
                                          int32_t* x,
                                          int32_t* y,
                                          uint32_t char_inc,
                                          uint32_t flags)
{
    uint32_t offset = 0;

    if (!data || !index || !x || !y)
        return;
    if (char_inc != 0u)
        return;
    if ((flags & RDP_GDI_GLYPH_SO_CHAR_INC_EQUAL_BM_BASE) != 0)
        return;
    if (*index >= length)
        return;
    offset = data[(*index)++];
    if ((offset & 0x80u) != 0)
    {
        if (*index + 2u > length)
            return;
        offset = data[(*index)++];
        offset |= (uint32_t)data[(*index)++] << 8u;
    }
    if ((flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
        *y += (int32_t)offset;
    if ((flags & RDP_GDI_GLYPH_SO_HORIZONTAL) != 0 ||
        (flags & RDP_GDI_GLYPH_SO_VERTICAL) == 0)
        *x += (int32_t)offset;
}

static void rdp_session_gdi_glyph_post_advance(const rdp_session_gdi_glyph_cache_entry* glyph,
                                               int32_t* x,
                                               int32_t* y,
                                               uint32_t char_inc,
                                               uint32_t flags)
{
    int32_t amount = 0;

    if (!glyph || !x || !y)
        return;
    if ((flags & RDP_GDI_GLYPH_SO_CHAR_INC_EQUAL_BM_BASE) != 0)
        amount = (int32_t)glyph->width;
    else if (char_inc != 0u)
        amount = (int32_t)char_inc;
    else
        return;
    if ((flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
        *y += amount;
    else
        *x += amount;
}

/*
 * Render one cached glyph from a GDI text order. Glyph cache lookup and
 * foreground/background composition are bounded by the current clipping
 * region.
 */
static librdp_status rdp_session_gdi_draw_cached_glyph(librdp_session* session,
                                                       const rdp_gdi_render_op* op,
                                                       const rdp_session_gdi_glyph_cache_entry* glyph,
                                                       int32_t* pen_x,
                                                       int32_t* pen_y)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    int64_t left = 0;
    int64_t top = 0;
    int64_t right = 0;
    int64_t bottom = 0;
    int64_t clip_left = 0;
    int64_t clip_top = 0;
    int64_t clip_right = 0;
    int64_t clip_bottom = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t y = 0;
    uint8_t b = 0;
    uint8_t g = 0;
    uint8_t r = 0;

    if (!session || !op || !glyph || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!glyph->active || glyph->width == 0 || glyph->height == 0)
        return LIBRDP_STATUS_OK;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    left = (int64_t)*pen_x + glyph->x;
    top = (int64_t)*pen_y + glyph->y;
    right = left + glyph->width;
    bottom = top + glyph->height;
    clip_right = surface_width;
    clip_bottom = surface_height;
    if (op->glyph_back_rect.width > 0 && op->glyph_back_rect.height > 0)
    {
        clip_left = op->glyph_back_rect.x;
        clip_top = op->glyph_back_rect.y;
        clip_right = (int64_t)op->glyph_back_rect.x + op->glyph_back_rect.width;
        clip_bottom = (int64_t)op->glyph_back_rect.y + op->glyph_back_rect.height;
    }
    if (clip_left < 0)
        clip_left = 0;
    if (clip_top < 0)
        clip_top = 0;
    if (clip_right > (int64_t)surface_width)
        clip_right = surface_width;
    if (clip_bottom > (int64_t)surface_height)
        clip_bottom = surface_height;
    if (left < clip_left)
        left = clip_left;
    if (top < clip_top)
        top = clip_top;
    if (right > clip_right)
        right = clip_right;
    if (bottom > clip_bottom)
        bottom = clip_bottom;
    if (right <= left || bottom <= top)
    {
        rdp_session_gdi_glyph_post_advance(glyph, pen_x, pen_y, op->glyph_char_inc, op->glyph_flags);
        return LIBRDP_STATUS_OK;
    }
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    if (!pixels || stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    b = (uint8_t)(op->color & 0xffu);
    g = (uint8_t)((op->color >> 8u) & 0xffu);
    r = (uint8_t)((op->color >> 16u) & 0xffu);
    for (y = (uint32_t)top; y < (uint32_t)bottom; y++)
    {
        uint32_t x = 0;
        uint8_t* dst = pixels + ((size_t)y * stride) + ((size_t)left * 4u);

        for (x = (uint32_t)left; x < (uint32_t)right; x++)
        {
            uint32_t gx = (uint32_t)((int64_t)x - ((int64_t)*pen_x + glyph->x));
            uint32_t gy = (uint32_t)((int64_t)y - ((int64_t)*pen_y + glyph->y));

            if (rdp_session_gdi_glyph_bit(glyph, gx, gy))
            {
                dst[0] = b;
                dst[1] = g;
                dst[2] = r;
                dst[3] = 0xffu;
            }
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session,
                                         (uint32_t)left,
                                         (uint32_t)top,
                                         (uint32_t)(right - left),
                                         (uint32_t)(bottom - top));
    rdp_session_gdi_glyph_post_advance(glyph, pen_x, pen_y, op->glyph_char_inc, op->glyph_flags);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_process_glyph_bytes(librdp_session* session,
                                                         const rdp_gdi_render_op* op,
                                                         const uint8_t* data,
                                                         uint32_t length,
                                                         int32_t* pen_x,
                                                         int32_t* pen_y);

static librdp_status rdp_session_gdi_process_glyph_fragment(librdp_session* session,
                                                            const rdp_gdi_render_op* op,
                                                            uint8_t fragment_id,
                                                            int32_t* pen_x,
                                                            int32_t* pen_y)
{
    rdp_session_gdi_glyph_fragment* fragment = NULL;

    if (!session || !op || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fragment = &session->gdi_glyph_fragments[fragment_id];
    if (!fragment->active)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph_fragment.miss",
                              "fragment_id=%u",
                              fragment_id);
        return LIBRDP_STATUS_OK;
    }
    return rdp_session_gdi_process_glyph_bytes(session,
                                               op,
                                               fragment->data.data,
                                               (uint32_t)fragment->data.length,
                                               pen_x,
                                               pen_y);
}

static librdp_status rdp_session_gdi_process_glyph_bytes(librdp_session* session,
                                                         const rdp_gdi_render_op* op,
                                                         const uint8_t* data,
                                                         uint32_t length,
                                                         int32_t* pen_x,
                                                         int32_t* pen_y)
{
    uint32_t index = 0;

    if (!session || !op || (!data && length > 0) || !pen_x || !pen_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (index < length)
    {
        uint8_t token = data[index++];
        librdp_status status = LIBRDP_STATUS_OK;

        if (token == RDP_GDI_GLYPH_FRAGMENT_USE)
        {
            if (index >= length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_session_gdi_process_glyph_fragment(session, op, data[index++], pen_x, pen_y);
            if (status != LIBRDP_STATUS_OK)
                return status;
            continue;
        }
        if (token == RDP_GDI_GLYPH_FRAGMENT_ADD)
        {
            uint8_t fragment_id = 0;
            uint8_t fragment_len = 0;

            if (index + 2u > length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            fragment_id = data[index++];
            fragment_len = data[index++];
            if (index + fragment_len > length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_session_gdi_glyph_fragment_store(session, fragment_id, data + index, fragment_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            index += fragment_len;
            continue;
        }
        rdp_session_gdi_glyph_advance(data,
                                      length,
                                      &index,
                                      pen_x,
                                      pen_y,
                                      op->glyph_char_inc,
                                      op->glyph_flags);
        {
            const rdp_session_gdi_glyph_cache_entry* glyph =
                rdp_session_gdi_glyph_cache_find(session, op->cache_id, token);

            if (!glyph)
            {
                if (op->glyph_char_inc != 0u)
                {
                    if ((op->glyph_flags & RDP_GDI_GLYPH_SO_VERTICAL) != 0)
                        *pen_y += (int32_t)op->glyph_char_inc;
                    else
                        *pen_x += (int32_t)op->glyph_char_inc;
                }
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.gdi.glyph_cache.miss",
                                      "cache_id=%u cache_index=%u",
                                      op->cache_id,
                                      token);
                continue;
            }
            status = rdp_session_gdi_draw_cached_glyph(session, op, glyph, pen_x, pen_y);
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_draw_glyphs(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_region region;
    rdp_gdi_render_op fill_op;
    int32_t pen_x = 0;
    int32_t pen_y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->inline_glyph_present)
    {
        rdp_gdi_glyph_bitmap glyph;

        memset(&glyph, 0, sizeof(glyph));
        glyph.cache_index = op->inline_glyph_cache_index;
        glyph.x = op->inline_glyph_x;
        glyph.y = op->inline_glyph_y;
        glyph.width = op->inline_glyph_width;
        glyph.height = op->inline_glyph_height;
        glyph.bitmap = op->inline_glyph_bitmap;
        glyph.bitmap_len = op->inline_glyph_bitmap_len;
        status = rdp_session_gdi_glyph_cache_store(session, op->cache_id, &glyph);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!op->glyph_opaque && op->rect.width > 0 && op->rect.height > 0)
    {
        memset(&region, 0, sizeof(region));
        fill_op = *op;
        fill_op.kind = RDP_GDI_RENDER_OP_OPAQUE_RECT;
        if (rdp_session_gdi_clip_dest(&fill_op,
                                      librdp_surface_width(session->surface),
                                      librdp_surface_height(session->surface),
                                      &region))
        {
            status = rdp_session_gdi_fill_rect(session, &fill_op, &region, 0, op->back_color, 0);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    pen_x = op->glyph_x;
    pen_y = op->glyph_y;
    status = rdp_session_gdi_process_glyph_bytes(session,
                                                 op,
                                                 op->glyph_data,
                                                 op->glyph_data_len,
                                                 &pen_x,
                                                 &pen_y);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph.draw",
                              "cache_id=%u x=%d y=%d bytes=%u fore=%06x back=%06x",
                              op->cache_id,
                              op->glyph_x,
                              op->glyph_y,
                              op->glyph_data_len,
                              op->color & 0x00ffffffu,
                              op->back_color & 0x00ffffffu);
    }
    return status;
}

static rdp_session_gdi_bitmap_cache_entry* rdp_session_gdi_ninegrid_bitmap_find(librdp_session* session,
                                                                                uint32_t bitmap_id)
{
    size_t i = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;

    entry = rdp_session_gdi_bitmap_cache_find(session, 0, bitmap_id);
    if (entry)
        return entry;
    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_GDI_BITMAP_CACHE_SLOTS; i++)
    {
        entry = &session->gdi_bitmap_cache[i];
        if (entry->active && entry->cache_index == bitmap_id)
        {
            entry->last_used = ++session->gdi_bitmap_cache_clock;
            return entry;
        }
    }
    return NULL;
}

static uint32_t rdp_session_gdi_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_gdi_ninegrid_axis(uint32_t pos,
                                              uint32_t dst_len,
                                              uint32_t src_start,
                                              uint32_t src_len,
                                              uint32_t src_leading,
                                              uint32_t src_trailing,
                                              uint32_t dst_leading,
                                              uint32_t dst_trailing)
{
    uint32_t src_center = 0;
    uint32_t dst_center = 0;

    if (src_len == 0 || dst_len == 0)
        return src_start;
    if (pos < dst_leading)
        return src_start + rdp_session_gdi_min_u32(pos, src_len - 1u);
    if (pos >= dst_len - dst_trailing)
    {
        uint32_t tail = dst_len - 1u - pos;

        return src_start + src_len - 1u - rdp_session_gdi_min_u32(tail, src_len - 1u);
    }
    src_center = src_len - src_leading - src_trailing;
    dst_center = dst_len - dst_leading - dst_trailing;
    if (src_center == 0 || dst_center == 0)
        return src_start + rdp_session_gdi_min_u32(src_leading, src_len - 1u);
    return src_start + src_leading + (uint32_t)(((uint64_t)(pos - dst_leading) * src_center) / dst_center);
}

/*
 * Render a nine-grid order by splitting stretchable and fixed regions. Source
 * bitmap bounds and destination slices are checked before each blit.
 */
static librdp_status rdp_session_gdi_draw_ninegrid(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_ninegrid_cache_entry* grid = NULL;
    rdp_session_gdi_bitmap_cache_entry* bitmap = NULL;
    rdp_session_gdi_region region;
    uint8_t* dst_pixels = NULL;
    const uint8_t* src_pixels = NULL;
    size_t dst_stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t src_left = 0;
    uint32_t src_top = 0;
    uint32_t src_right = 0;
    uint32_t src_bottom = 0;
    uint32_t src_width = 0;
    uint32_t src_height = 0;
    uint32_t src_left_band = 0;
    uint32_t src_right_band = 0;
    uint32_t src_top_band = 0;
    uint32_t src_bottom_band = 0;
    uint32_t dst_left_band = 0;
    uint32_t dst_right_band = 0;
    uint32_t dst_top_band = 0;
    uint32_t dst_bottom_band = 0;
    uint32_t y = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    grid = rdp_session_gdi_ninegrid_cache_find(session, op->bitmap_id);
    bitmap = rdp_session_gdi_ninegrid_bitmap_find(session, op->bitmap_id);
    if (!grid || !bitmap || !bitmap->active || bitmap->pixels.length == 0 || bitmap->stride == 0)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.ninegrid.miss",
                              "bitmap_id=%u has_grid=%u has_bitmap=%u x=%d y=%d width=%d height=%d",
                              op->bitmap_id,
                              grid ? 1u : 0u,
                              bitmap ? 1u : 0u,
                              op->rect.x,
                              op->rect.y,
                              op->rect.width,
                              op->rect.height);
        return LIBRDP_STATUS_OK;
    }
    if (op->src_left < 0 || op->src_top < 0 || op->src_right < op->src_left || op->src_bottom < op->src_top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    src_left = (uint32_t)op->src_left;
    src_top = (uint32_t)op->src_top;
    src_right = (uint32_t)op->src_right;
    src_bottom = (uint32_t)op->src_bottom;
    if (src_left >= bitmap->width || src_top >= bitmap->height)
        return LIBRDP_STATUS_OK;
    if (src_right >= bitmap->width)
        src_right = bitmap->width - 1u;
    if (src_bottom >= bitmap->height)
        src_bottom = bitmap->height - 1u;
    if (src_right < src_left || src_bottom < src_top)
        return LIBRDP_STATUS_OK;
    src_width = src_right - src_left + 1u;
    src_height = src_bottom - src_top + 1u;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
        return LIBRDP_STATUS_OK;
    dst_pixels = librdp_surface_pixels_mut(session->surface);
    src_pixels = bitmap->pixels.data;
    dst_stride = librdp_surface_stride(session->surface);
    if (!dst_pixels || !src_pixels || dst_stride == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    src_left_band = rdp_session_gdi_min_u32(grid->info.left_width, src_width);
    src_right_band = rdp_session_gdi_min_u32(grid->info.right_width, src_width - src_left_band);
    src_top_band = rdp_session_gdi_min_u32(grid->info.top_height, src_height);
    src_bottom_band = rdp_session_gdi_min_u32(grid->info.bottom_height, src_height - src_top_band);
    dst_left_band = rdp_session_gdi_min_u32(grid->info.left_width, (uint32_t)op->rect.width);
    dst_right_band = rdp_session_gdi_min_u32(grid->info.right_width, (uint32_t)op->rect.width - dst_left_band);
    dst_top_band = rdp_session_gdi_min_u32(grid->info.top_height, (uint32_t)op->rect.height);
    dst_bottom_band = rdp_session_gdi_min_u32(grid->info.bottom_height, (uint32_t)op->rect.height - dst_top_band);
    for (y = 0; y < region.height; y++)
    {
        uint32_t dst_abs_y = region.dst_y + y;
        uint32_t dst_rel_y = (uint32_t)((int32_t)dst_abs_y - op->rect.y);
        uint32_t sy = rdp_session_gdi_ninegrid_axis(dst_rel_y,
                                                    (uint32_t)op->rect.height,
                                                    src_top,
                                                    src_height,
                                                    src_top_band,
                                                    src_bottom_band,
                                                    dst_top_band,
                                                    dst_bottom_band);
        uint8_t* dst = dst_pixels + ((size_t)dst_abs_y * dst_stride) + ((size_t)region.dst_x * 4u);
        uint32_t x = 0;

        for (x = 0; x < region.width; x++)
        {
            uint32_t dst_abs_x = region.dst_x + x;
            uint32_t dst_rel_x = (uint32_t)((int32_t)dst_abs_x - op->rect.x);
            uint32_t sx = rdp_session_gdi_ninegrid_axis(dst_rel_x,
                                                        (uint32_t)op->rect.width,
                                                        src_left,
                                                        src_width,
                                                        src_left_band,
                                                        src_right_band,
                                                        dst_left_band,
                                                        dst_right_band);
            const uint8_t* src = src_pixels + ((size_t)sy * bitmap->stride) + ((size_t)sx * 4u);

            if ((grid->info.flags & 0x01u) != 0 &&
                (((uint32_t)src[0] | ((uint32_t)src[1] << 8u) | ((uint32_t)src[2] << 16u)) ==
                 (grid->info.transparent_color & 0x00ffffffu)))
            {
                dst += 4u;
                continue;
            }
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = 0xffu;
            dst += 4u;
        }
    }
    rdp_session_emit_surface_invalidated(session, region.dst_x, region.dst_y, region.width, region.height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.ninegrid.blit",
                          "bitmap_id=%u src=%u,%u,%u,%u x=%u y=%u width=%u height=%u",
                          op->bitmap_id,
                          src_left,
                          src_top,
                          src_right,
                          src_bottom,
                          region.dst_x,
                          region.dst_y,
                          region.width,
                          region.height);
    return LIBRDP_STATUS_OK;
}

static int32_t rdp_session_gdi_abs_i32(int32_t value)
{
    return value < 0 ? -value : value;
}

static uint8_t rdp_session_gdi_rop2(uint8_t rop, uint8_t pen, uint8_t dest)
{
    switch (rop)
    {
        case 1u:
            return 0;
        case 2u:
            return (uint8_t)~(dest | pen);
        case 3u:
            return (uint8_t)(dest & (uint8_t)~pen);
        case 4u:
            return (uint8_t)~pen;
        case 5u:
            return (uint8_t)(pen & (uint8_t)~dest);
        case 6u:
            return (uint8_t)~dest;
        case 7u:
            return (uint8_t)(dest ^ pen);
        case 8u:
            return (uint8_t)~(dest & pen);
        case 9u:
            return (uint8_t)(dest & pen);
        case 10u:
            return (uint8_t)~(dest ^ pen);
        case 11u:
            return dest;
        case 12u:
            return (uint8_t)(dest | (uint8_t)~pen);
        case 13u:
            return pen;
        case 14u:
            return (uint8_t)(pen | (uint8_t)~dest);
        case 15u:
            return (uint8_t)(dest | pen);
        case 16u:
            return 0xffu;
        default:
            return pen;
    }
}

static int rdp_session_gdi_line_point_visible(const rdp_gdi_render_op* op,
                                              int32_t x,
                                              int32_t y,
                                              uint32_t width,
                                              uint32_t height)
{
    if (x < 0 || y < 0 || x >= (int32_t)width || y >= (int32_t)height)
        return 0;
    if (op->bounds.present &&
        (x < op->bounds.left || y < op->bounds.top || x > op->bounds.right || y > op->bounds.bottom))
        return 0;
    return 1;
}

static int rdp_session_gdi_pen_style_visible(uint32_t style, uint32_t step)
{
    uint32_t phase = 0;

    switch (style)
    {
        case RDP_SESSION_GDI_PEN_SOLID:
        case RDP_SESSION_GDI_PEN_INSIDEFRAME:
            return 1;
        case RDP_SESSION_GDI_PEN_DASH:
            phase = step % 24u;
            return phase < 18u;
        case RDP_SESSION_GDI_PEN_DOT:
            phase = step % 6u;
            return phase < 2u;
        case RDP_SESSION_GDI_PEN_DASHDOT:
            phase = step % 22u;
            return phase < 12u || (phase >= 16u && phase < 18u);
        case RDP_SESSION_GDI_PEN_DASHDOTDOT:
            phase = step % 28u;
            return phase < 12u || (phase >= 16u && phase < 18u) || (phase >= 22u && phase < 24u);
        case RDP_SESSION_GDI_PEN_NULL:
        default:
            return 0;
    }
}

static void rdp_session_gdi_line_plot(librdp_session* session,
                                      const rdp_gdi_render_op* op,
                                      int32_t x,
                                      int32_t y,
                                      uint32_t step,
                                      uint32_t surface_width,
                                      uint32_t surface_height,
                                      uint32_t* dirty_left,
                                      uint32_t* dirty_top,
                                      uint32_t* dirty_right,
                                      uint32_t* dirty_bottom)
{
    uint8_t* pixels = librdp_surface_pixels_mut(session->surface);
    size_t stride = librdp_surface_stride(session->surface);
    uint32_t pen_width = op->pen_width == 0 ? 1u : op->pen_width;
    int32_t start = -(int32_t)(pen_width / 2u);
    int32_t end = start + (int32_t)pen_width;
    int32_t dy = 0;
    uint8_t b = (uint8_t)(op->color & 0xffu);
    uint8_t g = (uint8_t)((op->color >> 8u) & 0xffu);
    uint8_t r = (uint8_t)((op->color >> 16u) & 0xffu);

    if (!pixels || stride == 0)
        return;
    if (!rdp_session_gdi_pen_style_visible(op->pen_style, step))
        return;
    for (dy = start; dy < end; dy++)
    {
        int32_t dx = 0;

        for (dx = start; dx < end; dx++)
        {
            int32_t px = x + dx;
            int32_t py = y + dy;
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_line_point_visible(op, px, py, surface_width, surface_height))
                continue;
            pixel = pixels + ((size_t)(uint32_t)py * stride) + ((size_t)(uint32_t)px * 4u);
            pixel[0] = rdp_session_gdi_rop2(op->rop, b, pixel[0]);
            pixel[1] = rdp_session_gdi_rop2(op->rop, g, pixel[1]);
            pixel[2] = rdp_session_gdi_rop2(op->rop, r, pixel[2]);
            pixel[3] = 0xffu;
            if ((uint32_t)px < *dirty_left)
                *dirty_left = (uint32_t)px;
            if ((uint32_t)py < *dirty_top)
                *dirty_top = (uint32_t)py;
            if ((uint32_t)px + 1u > *dirty_right)
                *dirty_right = (uint32_t)px + 1u;
            if ((uint32_t)py + 1u > *dirty_bottom)
                *dirty_bottom = (uint32_t)py + 1u;
        }
    }
}

static int rdp_session_gdi_shape_color(const librdp_session* session,
                                       const rdp_gdi_render_op* op,
                                       uint32_t x,
                                       uint32_t y,
                                       uint32_t* color)
{
    int foreground = 1;

    if (!op || !color)
        return 0;
    if (op->kind != RDP_GDI_RENDER_OP_POLYGON_CB &&
        op->kind != RDP_GDI_RENDER_OP_ELLIPSE_CB)
    {
        *color = op->color;
        return 1;
    }
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_NULL)
        return 0;
    if ((op->brush_style & RDP_GDI_CACHED_BRUSH) != 0)
    {
        uint8_t b = 0;
        uint8_t g = 0;
        uint8_t r = 0;

        if (!rdp_session_gdi_cached_brush_find(session, op))
            return 0;
        rdp_session_gdi_brush_bgr(session, op, x, y, &b, &g, &r);
        *color = (uint32_t)b | ((uint32_t)g << 8u) | ((uint32_t)r << 16u);
        return 1;
    }
    if (op->brush_style == RDP_SESSION_GDI_BRUSH_HATCHED)
        foreground = rdp_session_gdi_hatch_bit(op->brush_hatch, x, y);
    else if (rdp_session_gdi_brush_style_is_pattern(op->brush_style))
        foreground = rdp_session_gdi_pattern_bit(op, x, y);
    else if (op->brush_style != RDP_SESSION_GDI_BRUSH_SOLID)
        return 0;
    if (!foreground && op->transparent_background)
        return 0;
    *color = foreground ? op->color : op->back_color;
    return 1;
}

static void rdp_session_gdi_plot_rop2_pixel(librdp_session* session,
                                            uint8_t* pixel,
                                            const rdp_gdi_render_op* op,
                                            uint32_t x,
                                            uint32_t y)
{
    uint32_t color = 0;
    uint8_t b = 0;
    uint8_t g = 0;
    uint8_t r = 0;

    if (!rdp_session_gdi_shape_color(session, op, x, y, &color))
        return;
    b = (uint8_t)(color & 0xffu);
    g = (uint8_t)((color >> 8u) & 0xffu);
    r = (uint8_t)((color >> 16u) & 0xffu);
    pixel[0] = rdp_session_gdi_rop2(op->rop, b, pixel[0]);
    pixel[1] = rdp_session_gdi_rop2(op->rop, g, pixel[1]);
    pixel[2] = rdp_session_gdi_rop2(op->rop, r, pixel[2]);
    pixel[3] = 0xffu;
}

/*
 * Render a GDI line order with clipping and raster-operation handling.
 * Endpoint normalization stays local so degenerate or out-of-bounds lines
 * remain safe.
 */
static librdp_status rdp_session_gdi_draw_line(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    int32_t x0 = 0;
    int32_t y0 = 0;
    int32_t x1 = 0;
    int32_t y1 = 0;
    int32_t dx = 0;
    int32_t dy = 0;
    int32_t sx = 0;
    int32_t sy = 0;
    int32_t err = 0;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;
    uint32_t step = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->pen_style > RDP_SESSION_GDI_PEN_INSIDEFRAME)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    x0 = op->rect.x;
    y0 = op->rect.y;
    x1 = op->end_x;
    y1 = op->end_y;
    dx = rdp_session_gdi_abs_i32(x1 - x0);
    dy = -rdp_session_gdi_abs_i32(y1 - y0);
    sx = x0 < x1 ? 1 : -1;
    sy = y0 < y1 ? 1 : -1;
    err = dx + dy;
    for (;;)
    {
        int32_t e2 = 0;

        rdp_session_gdi_line_plot(session,
                                  op,
                                  x0,
                                  y0,
                                  step,
                                  surface_width,
                                  surface_height,
                                  &dirty_left,
                                  &dirty_top,
                                  &dirty_right,
                                  &dirty_bottom);
        if (x0 == x1 && y0 == y1)
            break;
        step++;
        e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
    if (dirty_left < dirty_right && dirty_top < dirty_bottom)
    {
        rdp_session_emit_surface_invalidated(session,
                                             dirty_left,
                                             dirty_top,
                                             dirty_right - dirty_left,
                                             dirty_bottom - dirty_top);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.order.apply",
                              "type=%u kind=%u x0=%d y0=%d x1=%d y1=%d width=%u style=%u rop2=%u dirty_x=%u dirty_y=%u dirty_width=%u dirty_height=%u",
                              op->order_type,
                              op->kind,
                              op->rect.x,
                              op->rect.y,
                              op->end_x,
                              op->end_y,
                              op->pen_width,
                              op->pen_style,
                              op->rop,
                              dirty_left,
                              dirty_top,
                              dirty_right - dirty_left,
                              dirty_bottom - dirty_top);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_draw_polyline(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    x = op->rect.x;
    y = op->rect.y;
    for (i = 0; i < op->point_count; i++)
    {
        rdp_gdi_render_op segment = *op;

        segment.kind = RDP_GDI_RENDER_OP_LINE;
        segment.rect.x = x;
        segment.rect.y = y;
        x += op->points[i].x;
        y += op->points[i].y;
        segment.end_x = x;
        segment.end_y = y;
        segment.pen_width = 1;
        status = rdp_session_gdi_draw_line(session, &segment);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%d y=%d points=%u rop2=%u color=%06x",
                          op->order_type,
                          op->kind,
                          op->rect.x,
                          op->rect.y,
                          op->point_count,
                          op->rop,
                          op->color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static int rdp_session_gdi_shape_point_visible(const rdp_gdi_render_op* op,
                                               int32_t x,
                                               int32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    return rdp_session_gdi_line_point_visible(op, x, y, width, height);
}

static int rdp_session_gdi_polygon_inside(const rdp_gdi_render_point* points,
                                          uint32_t count,
                                          int32_t x,
                                          int32_t y,
                                          uint32_t fill_mode)
{
    uint32_t i = 0;
    uint32_t j = 0;
    int alternate = 0;
    int winding = 0;
    int64_t px2 = ((int64_t)x * 2) + 1;
    int64_t py2 = ((int64_t)y * 2) + 1;

    if (!points || count < 3)
        return 0;
    j = count - 1u;
    for (i = 0; i < count; i++)
    {
        int64_t xi2 = (int64_t)points[i].x * 2;
        int64_t yi2 = (int64_t)points[i].y * 2;
        int64_t xj2 = (int64_t)points[j].x * 2;
        int64_t yj2 = (int64_t)points[j].y * 2;

        if ((yi2 > py2) != (yj2 > py2))
        {
            int64_t lhs = (px2 - xi2) * (yj2 - yi2);
            int64_t rhs = (xj2 - xi2) * (py2 - yi2);
            int crosses = yj2 > yi2 ? lhs < rhs : lhs > rhs;

            if (crosses)
            {
                alternate = !alternate;
                winding += yj2 > yi2 ? 1 : -1;
            }
        }
        j = i;
    }
    if (fill_mode == 2u)
        return winding != 0;
    return alternate;
}

/*
 * Render a GDI polygon fill order. Point arrays, fill mode, brush selection,
 * and clip state are validated before scan conversion touches the surface.
 */
static librdp_status rdp_session_gdi_fill_polygon(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_gdi_render_point points[RDP_GDI_RENDER_MAX_POINTS + 1u];
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    int32_t min_x = INT32_MAX;
    int32_t min_y = INT32_MAX;
    int32_t max_x = INT32_MIN;
    int32_t max_y = INT32_MIN;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (op->point_count == 0 || op->point_count > RDP_GDI_RENDER_MAX_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!pixels || stride == 0 || surface_width == 0 || surface_height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = op->rect.x;
    y = op->rect.y;
    points[0].x = x;
    points[0].y = y;
    count = op->point_count + 1u;
    for (i = 0; i < op->point_count; i++)
    {
        x += op->points[i].x;
        y += op->points[i].y;
        points[i + 1u].x = x;
        points[i + 1u].y = y;
    }
    for (i = 0; i < count; i++)
    {
        if (points[i].x < min_x)
            min_x = points[i].x;
        if (points[i].x > max_x)
            max_x = points[i].x;
        if (points[i].y < min_y)
            min_y = points[i].y;
        if (points[i].y > max_y)
            max_y = points[i].y;
    }
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= (int32_t)surface_width)
        max_x = (int32_t)surface_width - 1;
    if (max_y >= (int32_t)surface_height)
        max_y = (int32_t)surface_height - 1;
    if (min_x > max_x || min_y > max_y)
        return LIBRDP_STATUS_OK;
    for (y = min_y; y <= max_y; y++)
    {
        for (x = min_x; x <= max_x; x++)
        {
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_shape_point_visible(op, x, y, surface_width, surface_height) ||
                !rdp_session_gdi_polygon_inside(points, count, x, y, op->fill_mode))
                continue;
            pixel = pixels + ((size_t)(uint32_t)y * stride) + ((size_t)(uint32_t)x * 4u);
            rdp_session_gdi_plot_rop2_pixel(session, pixel, op, (uint32_t)x, (uint32_t)y);
            if ((uint32_t)x < dirty_left)
                dirty_left = (uint32_t)x;
            if ((uint32_t)y < dirty_top)
                dirty_top = (uint32_t)y;
            if ((uint32_t)x + 1u > dirty_right)
                dirty_right = (uint32_t)x + 1u;
            if ((uint32_t)y + 1u > dirty_bottom)
                dirty_bottom = (uint32_t)y + 1u;
        }
    }
    if (dirty_left < dirty_right && dirty_top < dirty_bottom)
        rdp_session_emit_surface_invalidated(session,
                                             dirty_left,
                                             dirty_top,
                                             dirty_right - dirty_left,
                                             dirty_bottom - dirty_top);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%d y=%d points=%u fill_mode=%u rop2=%u color=%06x dirty=%u",
                          op->order_type,
                          op->kind,
                          op->rect.x,
                          op->rect.y,
                          op->point_count,
                          op->fill_mode,
                          op->rop,
                          op->color & 0x00ffffffu,
                          dirty_left < dirty_right);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_fill_ellipse(librdp_session* session, const rdp_gdi_render_op* op)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    rdp_session_gdi_region region;
    uint32_t x = 0;
    uint32_t y = 0;
    double width = 0.0;
    double height = 0.0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_session_gdi_clip_dest(op,
                                   librdp_surface_width(session->surface),
                                   librdp_surface_height(session->surface),
                                   &region))
        return LIBRDP_STATUS_OK;
    pixels = librdp_surface_pixels_mut(session->surface);
    stride = librdp_surface_stride(session->surface);
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    if (!pixels || stride == 0 || surface_width == 0 || surface_height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = (double)op->rect.width;
    height = (double)op->rect.height;
    for (y = 0; y < region.height; y++)
    {
        for (x = 0; x < region.width; x++)
        {
            uint32_t absolute_x = region.dst_x + x;
            uint32_t absolute_y = region.dst_y + y;
            double dx = (((double)(int32_t)absolute_x - (double)op->rect.x) + 0.5) * 2.0 - width;
            double dy = (((double)(int32_t)absolute_y - (double)op->rect.y) + 0.5) * 2.0 - height;
            uint8_t* pixel = NULL;

            if (!rdp_session_gdi_shape_point_visible(op,
                                                     (int32_t)absolute_x,
                                                     (int32_t)absolute_y,
                                                     surface_width,
                                                     surface_height) ||
                ((dx * dx) / (width * width) + (dy * dy) / (height * height)) > 0.25)
                continue;
            pixel = pixels + ((size_t)absolute_y * stride) + ((size_t)absolute_x * 4u);
            rdp_session_gdi_plot_rop2_pixel(session, pixel, op, absolute_x, absolute_y);
        }
    }
    rdp_session_emit_surface_invalidated(session, region.dst_x, region.dst_y, region.width, region.height);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.order.apply",
                          "type=%u kind=%u x=%u y=%u width=%u height=%u fill_mode=%u rop2=%u color=%06x",
                          op->order_type,
                          op->kind,
                          region.dst_x,
                          region.dst_y,
                          region.width,
                          region.height,
                          op->fill_mode,
                          op->rop,
                          op->color & 0x00ffffffu);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_apply_gdi_render_op(librdp_session* session, const rdp_gdi_render_op* op);

/*
 * Apply the core GDI raster operation between source, pattern, and destination
 * pixels. Keeping the operation table centralized avoids divergent rendering
 * behavior across order types.
 */
static librdp_status rdp_session_apply_gdi_render_op_core(librdp_session* session, const rdp_gdi_render_op* op)
{
    rdp_session_gdi_region region;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(session->surface);
    surface_height = librdp_surface_height(session->surface);
    memset(&region, 0, sizeof(region));
    if (op->kind == RDP_GDI_RENDER_OP_OPAQUE_RECT)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_fill_rect(session, op, &region, 0, op->color, 0);
    }
    if (op->kind == RDP_GDI_RENDER_OP_DSTBLT)
    {
        if (op->rop == 0xaau)
            return LIBRDP_STATUS_OK;
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_fill_rect(session, op, &region, op->rop, 0, 1);
    }
    if (op->kind == RDP_GDI_RENDER_OP_PATBLT)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_patblt(session, op, &region);
    }
    if (op->kind == RDP_GDI_RENDER_OP_SCRBLT)
    {
        if (!rdp_session_gdi_clip_copy(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        return rdp_session_gdi_copy_rect(session, op, &region);
    }
    if (op->kind == RDP_GDI_RENDER_OP_MEMBLT || op->kind == RDP_GDI_RENDER_OP_MEM3BLT)
    {
        rdp_session_gdi_bitmap_cache_entry* entry =
            rdp_session_gdi_bitmap_cache_find(session, op->cache_id, op->cache_index);

        if (entry &&
            rdp_session_gdi_clip_bitmap_copy(op,
                                             surface_width,
                                             surface_height,
                                             entry->width,
                                             entry->height,
                                             &region))
            return rdp_session_gdi_copy_cached_bitmap(session, op, entry, &region);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.bitmap_cache.miss",
                              "kind=%u cache_id=%u color_index=%u cache_index=%u x=%d y=%d width=%d height=%d src_x=%d src_y=%d rop=%u",
                              op->kind,
                              op->cache_id,
                              op->color_index,
                              op->cache_index,
                              op->rect.x,
                              op->rect.y,
                              op->rect.width,
                              op->rect.height,
                              op->src_x,
                              op->src_y,
                              op->rop);
        return LIBRDP_STATUS_OK;
    }
    if (op->kind == RDP_GDI_RENDER_OP_DRAW_NINEGRID)
        return rdp_session_gdi_draw_ninegrid(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_GLYPH)
        return rdp_session_gdi_draw_glyphs(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_LINE)
        return rdp_session_gdi_draw_line(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_POLYLINE)
        return rdp_session_gdi_draw_polyline(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_POLYGON_SC || op->kind == RDP_GDI_RENDER_OP_POLYGON_CB)
        return rdp_session_gdi_fill_polygon(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_ELLIPSE_SC || op->kind == RDP_GDI_RENDER_OP_ELLIPSE_CB)
        return rdp_session_gdi_fill_ellipse(session, op);
    if (op->kind == RDP_GDI_RENDER_OP_SAVE_BITMAP)
    {
        if (!rdp_session_gdi_clip_dest(op, surface_width, surface_height, &region))
            return LIBRDP_STATUS_OK;
        if (op->operation == 0u)
            return rdp_session_gdi_save_bitmap(session, op, &region);
        if (op->operation == 1u)
            return rdp_session_gdi_restore_bitmap(session, op, &region);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (op->kind == RDP_GDI_RENDER_OP_MULTIDSTBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTIPATBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTISCRBLT ||
        op->kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT ||
        op->kind == RDP_GDI_RENDER_OP_MULTI_DRAW_NINEGRID)
    {
        uint32_t i = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (op->rect_count > RDP_GDI_RENDER_MAX_RECTS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < op->rect_count; i++)
        {
            rdp_gdi_render_op single = *op;

            single.rect = op->rects[i];
            single.rect_count = 0;
            if (op->kind == RDP_GDI_RENDER_OP_MULTIDSTBLT)
                single.kind = RDP_GDI_RENDER_OP_DSTBLT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTIPATBLT)
                single.kind = RDP_GDI_RENDER_OP_PATBLT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTIOPAQUE_RECT)
                single.kind = RDP_GDI_RENDER_OP_OPAQUE_RECT;
            else if (op->kind == RDP_GDI_RENDER_OP_MULTISCRBLT)
            {
                single.kind = RDP_GDI_RENDER_OP_SCRBLT;
                single.src_x = op->src_x + (op->rects[i].x - op->rect.x);
                single.src_y = op->src_y + (op->rects[i].y - op->rect.y);
            }
            else
                single.kind = RDP_GDI_RENDER_OP_DRAW_NINEGRID;
            status = rdp_session_apply_gdi_render_op(session, &single);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.order.apply",
                              "type=%u kind=%u rects=%u rop=%u color=%06x",
                              op->order_type,
                              op->kind,
                              op->rect_count,
                              op->rop,
                              op->color & 0x00ffffffu);
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_session_apply_gdi_render_op(librdp_session* session, const rdp_gdi_render_op* op)
{
    librdp_surface* primary = NULL;
    librdp_surface* target = NULL;
    uint8_t previous_offscreen = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !op)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    primary = session->surface;
    target = rdp_session_gdi_target_surface(session);
    if (!primary || !target)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    previous_offscreen = session->gdi_drawing_to_offscreen;
    if (target != primary)
    {
        session->surface = target;
        session->gdi_drawing_to_offscreen = 1;
    }
    status = rdp_session_apply_gdi_render_op_core(session, op);
    session->surface = primary;
    session->gdi_drawing_to_offscreen = previous_offscreen;
    return status;
}

typedef struct rdp_session_gdi_rfx_cache_context
{
    rdp_buffer* pixels;
    uint32_t width;
    uint32_t height;
    size_t stride;
    uint16_t tiles;
} rdp_session_gdi_rfx_cache_context;

static librdp_status rdp_session_gdi_rfx_cache_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    rdp_session_gdi_rfx_cache_context* context = (rdp_session_gdi_rfx_cache_context*)user;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t y = 0;

    if (!tile || !context || !context->pixels || !context->pixels->data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (tile->x >= context->width || tile->y >= context->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = tile->width;
    height = tile->height;
    if (width > context->width - tile->x)
        width = context->width - tile->x;
    if (height > context->height - tile->y)
        height = context->height - tile->y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (y = 0; y < height; y++)
    {
        memcpy(context->pixels->data + (((size_t)(tile->y + y) * context->stride) + ((size_t)tile->x * 4u)),
               tile->pixels.bgra + ((size_t)y * tile->pixels.stride),
               (size_t)width * 4u);
    }
    if (context->tiles < UINT16_MAX)
        context->tiles++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_gdi_decode_rfx_cache_bitmap(const rdp_gdi_cache_bitmap_order* order,
                                                             rdp_buffer* pixels,
                                                             size_t* stride)
{
    rdp_session_gdi_rfx_cache_context context;
    rdp_rfx_stream_summary summary;
    size_t length = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!order || !pixels || !stride || !order->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->width == 0 || order->height == 0 || order->width > UINT16_MAX ||
        order->height > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *stride = (size_t)order->width * 4u;
    length = *stride * (size_t)order->height;
    status = rdp_buffer_reserve(pixels, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(pixels->data, 0, length);
    pixels->length = length;
    memset(&context, 0, sizeof(context));
    memset(&summary, 0, sizeof(summary));
    context.pixels = pixels;
    context.width = order->width;
    context.height = order->height;
    context.stride = *stride;
    status = rdp_rfx_stream_decode(order->bitmap_data,
                                   order->bitmap_data_len,
                                   rdp_session_gdi_rfx_cache_tile,
                                   &context,
                                   &summary);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (context.tiles == 0 || summary.tile_count == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.rfx_decode",
                          "cache_id=%u cache_index=%u width=%u height=%u frame_id=%u tiles=%u decoded_tiles=%u",
                          order->cache_id,
                          order->cache_index,
                          order->width,
                          order->height,
                          summary.frame_id,
                          summary.tile_count,
                          context.tiles);
    return LIBRDP_STATUS_OK;
}

/*
 * Store a decoded GDI bitmap into the session bitmap cache. Cell selection,
 * dimensions, and pixel ownership are finalized before later drawing orders
 * can reference the cache entry.
 */
static librdp_status rdp_session_gdi_store_cache_bitmap(librdp_session* session,
                                                        const rdp_gdi_cache_bitmap_order* order)
{
    rdp_bitmap_rect rect;
    rdp_buffer pixels;
    rdp_buffer raw;
    size_t stride = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    size_t new_size = 0;
    rdp_session_gdi_bitmap_cache_entry* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !order || !order->bitmap_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (order->do_not_cache && !order->rev3)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.bitmap_cache.skip",
                              "cache_id=%u cache_index=%u width=%u height=%u bpp=%u",
                              order->cache_id,
                              order->cache_index,
                              order->width,
                              order->height,
                              order->bits_per_pixel);
        return LIBRDP_STATUS_OK;
    }
    if (order->width == 0 || order->height == 0 ||
        order->width > UINT16_MAX || order->height > UINT16_MAX ||
        order->bits_per_pixel > UINT16_MAX || order->bitmap_data_len > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&rect, 0, sizeof(rect));
    rect.dest_left = 0;
    rect.dest_top = 0;
    rect.dest_right = (uint16_t)(order->width - 1u);
    rect.dest_bottom = (uint16_t)(order->height - 1u);
    rect.width = (uint16_t)order->width;
    rect.height = (uint16_t)order->height;
    rect.bits_per_pixel = (uint16_t)order->bits_per_pixel;
    rect.flags = order->compressed ? RDP_SESSION_BITMAP_FLAG_COMPRESSED : 0;
    if (order->compressed && !order->bitmap_data_includes_compression_header)
        rect.flags |= RDP_GDI_NO_BITMAP_COMPRESSION_HEADER;
    rect.data = order->bitmap_data;
    rect.data_len = order->bitmap_data_len;

    rdp_buffer_init(&pixels);
    rdp_buffer_init(&raw);
    if (order->rev3 && order->codec_id == RDP_SURFACE_CODEC_NSCODEC)
    {
        status = rdp_nscodec_decode_bgra32(&session->surface_nscodec,
                                           order->bitmap_data,
                                           order->bitmap_data_len,
                                           order->width,
                                           order->height,
                                           &pixels,
                                           &stride);
    }
    else if (order->rev3 &&
             (order->codec_id == RDP_SURFACE_CODEC_REMOTEFX ||
              order->codec_id == RDP_SURFACE_CODEC_IMAGE_REMOTEFX))
    {
        status = rdp_session_gdi_decode_rfx_cache_bitmap(order, &pixels, &stride);
    }
    else if (order->bits_per_pixel == 8u)
    {
        status = rdp_buffer_append(&raw, order->bitmap_data, order->bitmap_data_len);
    }
    else
    {
        status = rdp_bitmap_decode_rect_bgra32_with_palette(&rect,
                                                            session->palette_valid ? &session->palette : NULL,
                                                            &pixels,
                                                            &stride);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return status;
    }
    new_size = pixels.length + raw.length;
    if (new_size < pixels.length || new_size > RDP_SESSION_GDI_BITMAP_CACHE_MAX_BYTES)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    entry = rdp_session_gdi_bitmap_cache_slot(session, order->cache_id, order->cache_index);
    if (!entry)
    {
        rdp_buffer_free(&pixels);
        rdp_buffer_free(&raw);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    old_size = rdp_session_gdi_bitmap_cache_entry_size(entry);
    current_without_old = session->gdi_bitmap_cache_bytes >= old_size ?
                          session->gdi_bitmap_cache_bytes - old_size :
                          0;
    while (current_without_old > RDP_SESSION_GDI_BITMAP_CACHE_MAX_BYTES - new_size)
    {
        size_t index = rdp_session_gdi_bitmap_cache_lru(session, entry);

        if (index >= RDP_SESSION_GDI_BITMAP_CACHE_SLOTS)
        {
            rdp_buffer_free(&pixels);
            rdp_buffer_free(&raw);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        rdp_session_gdi_bitmap_cache_evict(session, index);
        current_without_old = session->gdi_bitmap_cache_bytes >= old_size ?
                              session->gdi_bitmap_cache_bytes - old_size :
                              session->gdi_bitmap_cache_bytes;
    }
    rdp_buffer_free(&entry->pixels);
    rdp_buffer_free(&entry->raw);
    entry->pixels = pixels;
    entry->raw = raw;
    entry->active = 1;
    entry->cache_id = order->cache_id;
    entry->cache_index = order->cache_index;
    entry->width = order->width;
    entry->height = order->height;
    entry->bits_per_pixel = order->bits_per_pixel;
    entry->bitmap_flags = rect.flags;
    entry->stride = stride;
    entry->last_used = ++session->gdi_bitmap_cache_clock;
    session->gdi_bitmap_cache_bytes = current_without_old + new_size;
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.gdi.bitmap_cache.store",
                          "cache_id=%u cache_index=%u width=%u height=%u bpp=%u compressed=%u decoded_bytes=%u raw_bytes=%u total_bytes=%u",
                          order->cache_id,
                          order->cache_index,
                          order->width,
                          order->height,
                          order->bits_per_pixel,
                          order->compressed,
                          (unsigned)entry->pixels.length,
                          (unsigned)entry->raw.length,
                          (unsigned)session->gdi_bitmap_cache_bytes);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_apply_gdi_secondary_order(librdp_session* session,
                                                           const rdp_gdi_secondary_order_header* header)
{
    rdp_gdi_cache_bitmap_order bitmap;
    rdp_gdi_cache_color_table_order color_table;
    rdp_gdi_cache_brush_order brush;
    rdp_gdi_cache_glyph_order glyphs;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!session || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_UNCOMPRESSED_REV2 ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV2 ||
        header->order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED_REV3)
    {
        status = rdp_gdi_parse_cache_bitmap_order(header, &bitmap);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_store_cache_bitmap(session, &bitmap);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_COLOR_TABLE)
    {
        status = rdp_gdi_parse_cache_color_table_order(header, &color_table);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_color_table_store(session, &color_table);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_BRUSH)
    {
        status = rdp_gdi_parse_cache_brush_order(header, &brush);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_gdi_store_cache_brush(session, &brush);
        return status;
    }
    if (header->order_type == RDP_GDI_SECONDARY_CACHE_GLYPH)
    {
        status = rdp_gdi_parse_cache_glyph_order(header, &glyphs);
        if (status != LIBRDP_STATUS_OK)
            return status;
        for (i = 0; i < glyphs.glyph_count; i++)
        {
            status = rdp_session_gdi_glyph_cache_store(session, glyphs.cache_id, &glyphs.glyphs[i]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.glyph_cache.order",
                              "cache_id=%u version=%u glyphs=%u flags=%u",
                              glyphs.cache_id,
                              glyphs.version,
                              glyphs.glyph_count,
                              glyphs.flags);
        return LIBRDP_STATUS_OK;
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.gdi.secondary.rejected",
                          "order_type=%u payload_len=%u",
                          header->order_type,
                          (unsigned)header->payload_len);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

/*
 * Apply alternate secondary GDI orders such as cache and glyph updates. The
 * dispatcher validates order type and payload length before mutating any GDI
 * cache.
 */
static librdp_status rdp_session_apply_gdi_altsec_order(librdp_session* session,
                                                        const rdp_gdi_altsec_order_header* header)
{
    rdp_gdi_create_ninegrid_bitmap_order order;
    rdp_gdi_create_offscreen_bitmap_order offscreen;
    rdp_gdi_switch_surface_order switch_surface;
    rdp_gdi_frame_marker_order frame_marker;
    rdp_gdi_stream_bitmap_first_order stream_first;
    rdp_gdi_stream_bitmap_next_order stream_next;
    rdp_session_gdi_ninegrid_cache_entry* entry = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->order_type == RDP_GDI_ALTSEC_CREATE_OFFSCREEN_BITMAP)
    {
        status = rdp_gdi_parse_create_offscreen_bitmap_order(header, &offscreen);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_create_offscreen_bitmap(session, &offscreen);
    }
    if (header->order_type == RDP_GDI_ALTSEC_SWITCH_SURFACE)
    {
        status = rdp_gdi_parse_switch_surface_order(header, &switch_surface);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_switch_surface(session, switch_surface.bitmap_id);
    }
    if (header->order_type == RDP_GDI_ALTSEC_CREATE_NINEGRID_BITMAP)
    {
        status = rdp_gdi_parse_create_ninegrid_bitmap_order(header, &order);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_gdi_ninegrid_cache_slot(session, order.bitmap_id);
        if (!entry)
            return LIBRDP_STATUS_NO_MEMORY;
        memset(entry, 0, sizeof(*entry));
        entry->active = 1;
        entry->bitmap_id = order.bitmap_id;
        entry->bits_per_pixel = order.bits_per_pixel;
        entry->info = order.info;
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.ninegrid.store",
                              "bitmap_id=%u bpp=%u left=%u right=%u top=%u bottom=%u flags=%u",
                              entry->bitmap_id,
                              entry->bits_per_pixel,
                              entry->info.left_width,
                              entry->info.right_width,
                              entry->info.top_height,
                              entry->info.bottom_height,
                              entry->info.flags);
        return LIBRDP_STATUS_OK;
    }
    if (header->order_type == RDP_GDI_ALTSEC_FRAME_MARKER)
    {
        status = rdp_gdi_parse_frame_marker_order(header, &frame_marker);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (frame_marker.action == 0u)
        {
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_dirty_pending = 0;
            session->graphics_current_frame_id++;
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN,
                                            session->graphics_current_frame_id);
        }
        else if (frame_marker.action == 1u)
        {
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_session_metric_add(&session->metrics.frames, 1);
            rdp_session_emit_graphics_frame(session,
                                            LIBRDP_GRAPHICS_UPDATE_FRAME_END,
                                            session->graphics_current_frame_id);
        }
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.gdi.frame_marker",
                              "action=%u frame_id=%u active=%u",
                              frame_marker.action,
                              session->graphics_current_frame_id,
                              session->graphics_frame_active ? 1u : 0u);
        return LIBRDP_STATUS_OK;
    }
    if (header->order_type == RDP_GDI_ALTSEC_STREAM_BITMAP_FIRST)
    {
        status = rdp_gdi_parse_stream_bitmap_first_order(header, &stream_first);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_stream_bitmap_first(session, &stream_first);
    }
    if (header->order_type == RDP_GDI_ALTSEC_STREAM_BITMAP_NEXT)
    {
        status = rdp_gdi_parse_stream_bitmap_next_order(header, &stream_next);
        if (status != LIBRDP_STATUS_OK)
            return status;
        return rdp_session_gdi_stream_bitmap_next(session, &stream_next);
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "rdp.gdi.altsec.rejected",
                          "order_type=%u payload_len=%u",
                          header->order_type,
                          (unsigned)header->payload_len);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_session_apply_gdi_orders_update(librdp_session* session, const rdp_gdi_orders_update* update)
{
    size_t offset = 0;
    uint16_t i = 0;

    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < update->number_orders; i++)
    {
        rdp_gdi_render_op op;
        rdp_gdi_secondary_order_header secondary;
        rdp_gdi_altsec_order_header altsec;
        size_t consumed = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (offset >= update->order_data_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((update->order_data[offset] & (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY)) ==
            (RDP_GDI_TS_STANDARD | RDP_GDI_TS_SECONDARY))
        {
            status = rdp_gdi_parse_secondary_order(update->order_data + offset,
                                                   update->order_data_len - offset,
                                                   &secondary);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_apply_gdi_secondary_order(session, &secondary);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += secondary.actual_length;
            continue;
        }
        if ((update->order_data[offset] & 0x03u) == RDP_GDI_TS_SECONDARY)
        {
            status = rdp_gdi_parse_altsec_order(update->order_data + offset,
                                                update->order_data_len - offset,
                                                &altsec);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_apply_gdi_altsec_order(session, &altsec);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += altsec.actual_length;
            continue;
        }
        status = rdp_gdi_decode_primary_render_order(&session->gdi_render,
                                                     update->order_data + offset,
                                                     update->order_data_len - offset,
                                                     &op,
                                                     &consumed);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.gdi.order.rejected",
                            "index=%u remaining=%u",
                            i,
                            (unsigned)(update->order_data_len - offset));
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status != LIBRDP_STATUS_OK || consumed == 0 || consumed > update->order_data_len - offset)
            return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_PROTOCOL_ERROR : status;
        status = rdp_session_apply_gdi_render_op(session, &op);
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += consumed;
    }
    if (offset != update->order_data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.gdi.orders",
                    "count=%u payload_len=%u",
                    update->number_orders,
                    (unsigned)update->order_data_len);
    return LIBRDP_STATUS_OK;
}

static void rdp_session_fastpath_fragment_reset(librdp_session* session)
{
    if (!session)
        return;
    session->fastpath_fragmenting = 0;
    session->fastpath_fragment_update_code = 0;
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
    session->fastpath_decompressed.length = 0;
}

static librdp_status rdp_session_decompress_bulk_payload(librdp_session* session,
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
static librdp_status rdp_session_process_fastpath_packet(librdp_session* session, const rdp_buffer* packet)
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

librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;
    const librdp_limits* limits = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->wakeup_pipe[0] = -1;
    session->wakeup_pipe[1] = -1;
    atomic_init(&session->cancel_requested, 0u);

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }
    limits = rdp_settings_limits_internal(session->settings);
    if (!limits || librdp_metrics_init(&session->metrics) != LIBRDP_STATUS_OK ||
        librdp_echo_stats_init(&session->echo_stats) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    session->limits = *limits;
    if (rdp_session_wakeup_init(session) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    if (librdp_settings_width(session->settings) > session->limits.surface_max_dimension ||
        librdp_settings_height(session->settings) > session->limits.surface_max_dimension)
    {
        rdp_session_wakeup_close(session);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        rdp_session_wakeup_close(session);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    session->lifecycle = LIBRDP_LIFECYCLE_NEW;
    rdp_license_client_state_init(&session->license_state);
    if (pthread_mutex_init(&session->owner_mutex, NULL) != 0)
    {
        rdp_session_wakeup_close(session);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    session->gdi_current_surface_id = RDP_SESSION_GDI_SCREEN_BITMAP_SURFACE;
    session->requested_desktop_width = librdp_settings_width(session->settings);
    session->requested_desktop_height = librdp_settings_height(session->settings);
    rdp_transport_init(&session->transport);
    session->audio_output_udp_fd = -1;
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    rdp_buffer_init(&session->device_redirection_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_buffer_init(&session->echo_pending_payload);
    rdp_buffer_init(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_decompressed);
    rdp_buffer_init(&session->slowpath_decompressed);
    rdp_buffer_init(&session->gdi_stream_bitmap.bitmap_data);
    rdp_gdi_render_state_init(&session->gdi_render);
    rdp_graphics_decompressor_init(&session->graphics_decompressor);
    rdp_graphics_decompressor_init(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_init(&session->bulk_decompressor);
    rdp_clearcodec_context_init(&session->clearcodec);
    rdp_nscodec_context_init(&session->surface_nscodec);
    rdp_composited_render_tree_init(&session->composited_tree);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    session->next_dynamic_channel_id = 1;
#ifdef RDP_HAVE_PCSC
    rdp_smartcard_backend_init_pcsc(&session->smartcard_backend);
#endif
    session->avc = rdp_avc_decoder_new();
    if (!session->avc)
    {
        rdp_nscodec_context_free(&session->surface_nscodec);
        rdp_clearcodec_context_free(&session->clearcodec);
        rdp_bulk_decompressor_free(&session->bulk_decompressor);
        rdp_graphics_decompressor_free(&session->bulk_rdp8_decompressor);
        rdp_graphics_decompressor_free(&session->graphics_decompressor);
        rdp_transport_close(&session->transport);
        rdp_session_wakeup_close(session);
        pthread_mutex_destroy(&session->owner_mutex);
        librdp_surface_free(session->surface);
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }
    rdp_trace_event(RDP_TRACE_CLIENT, "client.session.new", "width=%u height=%u",
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));
    return session;
}

void librdp_session_free(librdp_session* session)
{
    if (!session)
        return;
    (void)librdp_session_disconnect(session);
    rdp_session_smartcard_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_auth_redirection_channel_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_session_credssp_security_reset(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_clipboard_clear(session);
    rdp_session_clipboard_local_clear(session);
    rdp_session_audio_output_udp_close(session);
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_free(&session->echo_pending_payload);
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_free(&session->fastpath_decompressed);
    rdp_buffer_free(&session->slowpath_decompressed);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_avc_decoder_free(session->avc);
    rdp_nscodec_context_free(&session->surface_nscodec);
    rdp_clearcodec_context_free(&session->clearcodec);
    rdp_bulk_decompressor_free(&session->bulk_decompressor);
    rdp_graphics_decompressor_free(&session->bulk_rdp8_decompressor);
    rdp_graphics_decompressor_free(&session->graphics_decompressor);
    rdp_security_standard_clear(&session->standard_security);
    rdp_license_crypto_context_clear(&session->license_crypto);
    rdp_transport_close(&session->transport);
    rdp_session_wakeup_close(session);
    rdp_session_trace_policy_clear(session);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    pthread_mutex_destroy(&session->owner_mutex);
    free(session);
}

/*
 * Drive the full client connection sequence from transport setup through
 * activation. Each phase commits session state only after the previous
 * handshake stage, security mode, and capability exchange succeed.
 */
librdp_status librdp_session_connect(librdp_session* session)
{
    rdp_buffer x224;
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs;
    rdp_buffer security_payload;
    rdp_buffer security_data;
    rdp_buffer server_random;
    rdp_buffer server_certificate;
    rdp_buffer request;
    rdp_buffer reply;
    rdp_tpkt packet;
    rdp_x224_connection_confirm confirm;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_credssp_state credssp_state = RDP_CREDSSP_DISABLED;
    const uint8_t* mcs_pdu = NULL;
    size_t mcs_pdu_len = 0;
    uint32_t protocols = 0;
    uint32_t selected_protocol = 0;
    uint32_t server_encryption_method = 0;
    uint32_t server_encryption_level = 0;
    int standard_security_ready = 0;
    rdp_trace_session_scope trace_scope;
    librdp_credentials provider_credentials;
    rdp_gcc_channel_definition static_channel_defs[LIBRDP_SETTINGS_MAX_STATIC_CHANNELS];
    uint32_t static_channel_count = 0;
    librdp_credentials_provider credentials_provider = NULL;
    void* credentials_provider_user_data = NULL;
    const char* credential_username = NULL;
    const char* credential_password = NULL;
    const char* credential_domain = NULL;
    int provider_credentials_initialized = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_bind_owner(session, "client.connect.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_IDLE && session->state != LIBRDP_SESSION_CLOSED &&
        session->state != LIBRDP_SESSION_FAILED && session->state != LIBRDP_SESSION_CANCELLED)
    {
        rdp_session_set_last_error(session,
                                   LIBRDP_STATUS_STATE,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_CLIENT,
                                   "client.connect.validate",
                                   "session state does not allow connect");
        return LIBRDP_STATUS_STATE;
    }
    if (!librdp_settings_target(session->settings))
    {
        rdp_session_set_last_error(session,
                                   LIBRDP_STATUS_INVALID_ARGUMENT,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_CLIENT,
                                   "client.connect.validate",
                                   "target is missing");
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    rdp_error_clear(&session->last_error);
    atomic_store_explicit(&session->cancel_requested, 0u, memory_order_release);
    rdp_session_wakeup_drain(session);
    rdp_session_trace_scope_begin(session, &trace_scope);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.start", "target=%s port=%u width=%u height=%u",
                    librdp_settings_target(session->settings),
                    (unsigned)librdp_settings_port(session->settings),
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));

    rdp_buffer_init(&x224);
    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&security_data);
    rdp_buffer_init(&server_random);
    rdp_buffer_init(&server_certificate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&reply);
    memset(static_channel_defs, 0, sizeof(static_channel_defs));
    static_channel_count = librdp_settings_static_channel_count(session->settings);
    for (uint32_t i = 0; i < static_channel_count; i++)
    {
        const char* name = rdp_settings_static_channel_name_internal(session->settings, i);

        if (!name)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto fail;
        }
        memcpy(static_channel_defs[i].name, name, strlen(name) + 1u);
        static_channel_defs[i].flags = rdp_settings_static_channel_flags_internal(session->settings, i);
    }

    status = librdp_credentials_init(&provider_credentials);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    provider_credentials_initialized = 1;
    credential_username = librdp_settings_username(session->settings);
    credential_password = rdp_settings_password_internal(session->settings);
    credential_domain = librdp_settings_domain(session->settings);
    credentials_provider =
        rdp_settings_credentials_provider_internal(session->settings, &credentials_provider_user_data);
    if (credentials_provider)
    {
        status = credentials_provider(&provider_credentials, credentials_provider_user_data);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_set_last_error(session,
                                       status,
                                       0,
                                       LIBRDP_ERROR_COMPONENT_CLIENT,
                                       "client.credentials",
                                       "credentials provider failed");
            goto fail;
        }
        if (provider_credentials.version != LIBRDP_CREDENTIALS_VERSION ||
            provider_credentials.size < sizeof(provider_credentials))
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            rdp_session_set_last_error(session,
                                       status,
                                       0,
                                       LIBRDP_ERROR_COMPONENT_CLIENT,
                                       "client.credentials",
                                       "credentials provider returned invalid object");
            goto fail;
        }
        credential_username = provider_credentials.username;
        credential_password = provider_credentials.password;
        credential_domain = provider_credentials.domain;
    }

    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_CONNECTING);
    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTING);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    rdp_license_client_state_init(&session->license_state);
    rdp_license_crypto_context_clear(&session->license_crypto);
    rdp_session_credssp_security_reset(session);
    rdp_session_auth_redirection_channel_reset(session);
    rdp_session_webauthn_channel_reset(session);
    session->share_id = 0;
    session->dynamic_channel_id = 0;
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    rdp_session_audio_output_udp_close(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_udp_active = 0;
    session->audio_output_udp_block_no = 0;
    session->audio_output_udp_peer_valid = 0;
    session->audio_output_crypt_seed_valid = 0;
    session->audio_output_udp_fd = -1;
    session->audio_output_udp_port = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_udp_next_fragment_no = 0;
    session->audio_output_udp_peer_len = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    memset(&session->audio_output_udp_peer, 0, sizeof(session->audio_output_udp_peer));
    memset(session->audio_output_crypt_seed, 0, sizeof(session->audio_output_crypt_seed));
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    session->device_redirection_channel_id = 0;
    session->device_redirection_ready = 0;
    session->device_redirection_fragmenting = 0;
    session->device_redirection_version_minor = 0;
    session->device_redirection_client_id = 0;
    session->device_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_init(&session->device_redirection_fragment);
    session->pnp_redirection_channel_id = 0;
    session->pnp_redirection_ready = 0;
    session->pnp_redirection_fragmenting = 0;
    session->pnp_redirection_io_version = 0;
    session->pnp_redirection_devices_sent = 0;
    session->pnp_redirection_open_device_active = 0;
    session->pnp_redirection_open_device_id = 0;
    session->pnp_redirection_storage_active = 0;
    session->pnp_redirection_storage_device_id = 0;
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_init(&session->pnp_redirection_storage);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_session_echo_clear_pending(session);
    session->fastpath_fragmenting = 0;
    session->fastpath_fragment_update_code = 0;
    rdp_buffer_free(&session->fastpath_fragment);
    rdp_buffer_init(&session->fastpath_fragment);
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->input_channel_id = 0;
    session->input_channel_id_bytes = 0;
    session->input_channel_ready = 0;
    session->input_channel_suspended = 0;
    session->input_channel_protocol_version = 0;
    session->input_channel_supported_features = 0;
    session->input_channel_max_touch_contacts = 0;
    session->input_channel_supports_pen = 0;
    session->display_control_channel_id = 0;
    session->display_control_channel_id_bytes = 0;
    session->display_control_ready = 0;
    session->sent_desktop_width = 0;
    session->sent_desktop_height = 0;
    memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
    session->graphics_channel_id = 0;
    session->graphics_channel_id_bytes = 0;
    session->graphics_ready = 0;
    session->graphics_selected_version = 0;
    session->graphics_selected_flags = 0;
    session->graphics_frames_decoded = 0;
    session->mouse_cursor_channel_id = 0;
    session->mouse_cursor_channel_id_bytes = 0;
    session->mouse_cursor_ready = 0;
    session->audio_input_channel_id = 0;
    session->audio_input_channel_id_bytes = 0;
    session->audio_input_ready = 0;
    session->audio_input_open = 0;
    session->audio_input_open_reply_sent = 0;
    session->audio_input_version = 0;
    session->audio_input_selected_format_count = 0;
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    session->multitransport_negotiated = 0;
    session->multitransport_flags = 0;
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_graphics_decompressor_reset(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_reset(&session->bulk_decompressor);
    session->slowpath_decompressed.length = 0;
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_nscodec_context_reset(&session->surface_nscodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_gdi_render_state_init(&session->gdi_render);
    rdp_session_palette_reset(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);

    status = rdp_transport_connect(&session->transport,
                                   librdp_settings_target(session->settings),
                                   librdp_settings_port(session->settings),
                                   5000);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_set_last_error(session,
                                   status,
                                   errno,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   "transport.tcp.connect",
                                   "tcp connect failed");
        goto fail;
    }

    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_NEGOTIATING);
    protocols = rdp_security_protocol_mask(librdp_settings_security_mode(session->settings));
    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.start", "protocols=%u", protocols);
    status = rdp_x224_build_connection_request(&x224, credential_username, protocols);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_tpkt_write(&request, x224.data, x224.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.request",
                      RDP_TRACE_SENSITIVITY_HEADER,
                      request.data,
                      request.length);
    status = rdp_transport_write_all(&session->transport, request.data, request.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_transport_read_tpkt(&session->transport, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.response",
                      RDP_TRACE_SENSITIVITY_HEADER,
                      reply.data,
                      reply.length);
    status = rdp_tpkt_parse(reply.data, reply.length, &packet);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_x224_parse_connection_confirm(packet.payload, packet.payload_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (confirm.negotiation.present && confirm.negotiation.failure)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.failed", "code=%u", confirm.negotiation.failure_code);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    selected_protocol = confirm.negotiation.present ? confirm.negotiation.selected_protocol : RDP_X224_PROTOCOL_STANDARD;
    if (confirm.negotiation.present && !rdp_security_protocol_supported(selected_protocol))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.rejected", "selected_protocol=%u",
                        selected_protocol);
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto fail;
    }
    if (!rdp_security_protocol_allowed(librdp_settings_security_mode(session->settings),
                                       confirm.negotiation.present,
                                       selected_protocol))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "x224.negotiation.downgrade",
                        "mode=%u negotiation_present=%u selected_protocol=%u",
                        (unsigned)librdp_settings_security_mode(session->settings),
                        confirm.negotiation.present ? 1u : 0u,
                        selected_protocol);
        status = LIBRDP_STATUS_SECURITY_DOWNGRADE;
        goto fail;
    }

    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.done", "selected_protocol=%u",
                    confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0);
    if (selected_protocol == RDP_X224_PROTOCOL_TLS || selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        librdp_tls_policy tls_policy;
        rdp_transport_tls_config tls_config;

        memset(&tls_policy, 0, sizeof(tls_policy));
        memset(&tls_config, 0, sizeof(tls_config));
        status = librdp_settings_get_tls_policy(session->settings, &tls_policy);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        tls_config.host = librdp_settings_target(session->settings);
        tls_config.use_system_store = tls_policy.use_system_store;
        tls_config.policy_mode = tls_policy.mode;
        tls_config.pinned_sha256 = tls_policy.pinned_sha256;
        tls_config.certificate_callback = tls_policy.certificate_callback;
        tls_config.certificate_callback_user_data = tls_policy.certificate_callback_user_data;
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_TLS_HANDSHAKE);
        status = rdp_transport_start_tls_with_config(&session->transport, &tls_config);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_set_last_error(session,
                                       status,
                                       errno,
                                       LIBRDP_ERROR_COMPONENT_TLS,
                                       "transport.tls.handshake",
                                       "tls handshake failed");
            goto fail;
        }
        rdp_session_set_lifecycle(session,
                                  selected_protocol == RDP_X224_PROTOCOL_NLA ?
                                      LIBRDP_LIFECYCLE_AUTHENTICATING :
                                      LIBRDP_LIFECYCLE_NEGOTIATING);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "transport.tls.ready", "selected_protocol=%u", selected_protocol);
    }
    if (selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        rdp_buffer credssp_request;
        rdp_buffer credssp_reply;
        rdp_buffer ntlm_negotiate;
        rdp_buffer spnego_negotiate;
        rdp_buffer ntlm_authenticate;
        rdp_buffer spnego_authenticate;
        rdp_buffer tls_public_key;
        rdp_buffer pub_key_auth;
        rdp_buffer auth_info;
        rdp_credssp_ts_request ts_response;
        rdp_credssp_ts_request auth_response;
        rdp_credssp_ts_request pub_key_response;
        rdp_ntlm_authenticate_result ntlm_auth_result;
        rdp_ntlm_security_context ntlm_security;
        uint8_t client_nonce[32];

        rdp_buffer_init(&credssp_request);
        rdp_buffer_init(&credssp_reply);
        rdp_buffer_init(&ntlm_negotiate);
        rdp_buffer_init(&spnego_negotiate);
        rdp_buffer_init(&ntlm_authenticate);
        rdp_buffer_init(&spnego_authenticate);
        rdp_buffer_init(&tls_public_key);
        rdp_buffer_init(&pub_key_auth);
        rdp_buffer_init(&auth_info);
        memset(&ntlm_auth_result, 0, sizeof(ntlm_auth_result));
        memset(&ntlm_security, 0, sizeof(ntlm_security));
        memset(client_nonce, 0, sizeof(client_nonce));
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_AUTHENTICATING);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.start", "state=begin");
        status = rdp_credssp_begin(true, &credssp_state);
        if (status == LIBRDP_STATUS_OK)
            status = RAND_bytes(client_nonce, (int)sizeof(client_nonce)) == 1 ? LIBRDP_STATUS_OK
                                                                              : LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_transport_get_tls_public_key(&session->transport, &tls_public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate,
                                                      "librdp",
                                                      credential_domain);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                             ntlm_negotiate.data,
                                                             ntlm_negotiate.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ts_request(&credssp_request,
                                                  6,
                                                  spnego_negotiate.data,
                                                  spnego_negotiate.length,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  0,
                                                  client_nonce,
                                                  sizeof(client_nonce));
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.negotiate",
                            "token_len=%u client_nonce_len=%u public_key_len=%u",
                            (unsigned)credssp_request.length,
                            (unsigned)sizeof(client_nonce),
                            (unsigned)tls_public_key.length);
            status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &ts_response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.challenge",
                            "version=%u token_len=%u error=%u",
                            ts_response.version,
                            (unsigned)ts_response.nego_token_len,
                            ts_response.has_error_code ? ts_response.error_code : 0);
        if (status == LIBRDP_STATUS_OK && ts_response.nego_token_len > 0)
        {
            const uint8_t* ntlm_token = NULL;
            size_t ntlm_token_len = 0;
            rdp_ntlm_challenge ntlm_challenge;

            status = rdp_credssp_extract_ntlm_challenge(ts_response.nego_token,
                                                        ts_response.nego_token_len,
                                                        &ntlm_token,
                                                        &ntlm_token_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ntlm_challenge(ntlm_token, ntlm_token_len, &ntlm_challenge);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.ntlm.challenge",
                                "flags=%u target_name_len=%u target_info_len=%u",
                                ntlm_challenge.flags,
                                (unsigned)ntlm_challenge.target_name_len,
                                (unsigned)ntlm_challenge.target_info_len);
            if (status == LIBRDP_STATUS_OK && (!credential_username || !credential_password))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                                             &ntlm_challenge,
                                                             credential_username,
                                                             credential_password,
                                                             credential_domain,
                                                             "librdp",
                                                             0,
                                                             NULL,
                                                             NULL,
                                                             &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                                    ntlm_authenticate.data,
                                                                    ntlm_authenticate.length);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      ts_response.version ? ts_response.version : 6,
                                                      spnego_authenticate.data,
                                                      spnego_authenticate.length,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate",
                                "token_len=%u flags=%u",
                                (unsigned)credssp_request.length,
                                ntlm_auth_result.flags);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &auth_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                auth_response.version,
                                (unsigned)auth_response.nego_token_len,
                                (unsigned)auth_response.auth_info_len,
                                (unsigned)auth_response.pub_key_auth_len,
                                auth_response.has_error_code ? auth_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                                             client_nonce,
                                                             sizeof(client_nonce),
                                                             tls_public_key.data,
                                                             tls_public_key.length,
                                                             &pub_key_auth);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      auth_response.version ? auth_response.version : 6,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      pub_key_auth.data,
                                                      pub_key_auth.length,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey",
                                "token_len=%u pub_key_auth_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)pub_key_auth.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &pub_key_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                pub_key_response.version,
                                (unsigned)pub_key_response.nego_token_len,
                                (unsigned)pub_key_response.auth_info_len,
                                (unsigned)pub_key_response.pub_key_auth_len,
                                pub_key_response.has_error_code ? pub_key_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_verify_public_key_hash(&ntlm_security,
                                                            client_nonce,
                                                            sizeof(client_nonce),
                                                            tls_public_key.data,
                                                            tls_public_key.length,
                                                            pub_key_response.pub_key_auth,
                                                            pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.pubkey.verified", "pub_key_auth_len=%u",
                                (unsigned)pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                                  credential_domain,
                                                                  credential_username,
                                                                  credential_password,
                                                                  &auth_info);
            if (status == LIBRDP_STATUS_OK)
            {
                session->credssp_security = ntlm_security;
                session->credssp_security_ready = 1;
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      pub_key_response.version ? pub_key_response.version : 6,
                                                      NULL,
                                                      0,
                                                      auth_info.data,
                                                      auth_info.length,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.credentials",
                                "token_len=%u auth_info_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)auth_info.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
        }
        rdp_buffer_free(&auth_info);
        rdp_buffer_free(&pub_key_auth);
        rdp_buffer_free(&tls_public_key);
        rdp_buffer_free(&spnego_authenticate);
        rdp_buffer_free(&ntlm_authenticate);
        rdp_buffer_free(&spnego_negotiate);
        rdp_buffer_free(&ntlm_negotiate);
        rdp_buffer_free(&credssp_reply);
        rdp_buffer_free(&credssp_request);
        OPENSSL_cleanse(&ntlm_security, sizeof(ntlm_security));
        OPENSSL_cleanse(client_nonce, sizeof(client_nonce));
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_session_set_last_error(session,
                                       status,
                                       0,
                                       LIBRDP_ERROR_COMPONENT_CREDSSP,
                                       "credssp.nla",
                                       "nla authentication failed");
            rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.failed", "status=%d", (int)status);
            goto fail;
        }
        credssp_state = RDP_CREDSSP_COMPLETE;
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_NEGOTIATING);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.done", "state=%u", (unsigned)credssp_state);
    }

    {
        rdp_gcc_client_config config;
        memset(&config, 0, sizeof(config));
        config.desktop_width = (uint16_t)librdp_settings_width(session->settings);
        config.desktop_height = (uint16_t)librdp_settings_height(session->settings);
        config.requested_protocols = selected_protocol;
        config.client_version = RDP_GCC_CLIENT_VERSION_10_12;
        config.early_capability_flags = RDP_GCC_EARLY_SUPPORT_ERRINFO | RDP_GCC_EARLY_WANT_32BPP |
                                        RDP_GCC_EARLY_SUPPORT_STATUSINFO |
                                        RDP_GCC_EARLY_SUPPORT_MONITOR_LAYOUT |
                                        RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT |
                                        RDP_GCC_EARLY_SUPPORT_DYNVC_GFX;
        config.supported_color_depths = RDP_GCC_SUPPORTED_COLOR_DEPTHS_32BPP;
        config.connection_type = RDP_GCC_CONNECTION_TYPE_LAN;
        config.desktop_physical_width = rdp_session_pixels_to_mm(config.desktop_width);
        config.desktop_physical_height = rdp_session_pixels_to_mm(config.desktop_height);
        config.desktop_scale_factor = 100;
        config.device_scale_factor = 100;
        config.client_name = "librdp";
        config.enable_dynamic_channels = 1;
        config.enable_clipboard = 1;
        config.enable_audio_output =
            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_AUDIO_OUTPUT);
        config.enable_device_redirection = rdp_session_device_redirection_ready_for_negotiation(session);
        config.enable_pnp_redirection =
            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_PNP);
        config.enable_remote_programs =
            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_RAIL);
        config.enable_multitransport =
            (rdp_session_multitransport_runtime_supported() &&
             rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_MULTITRANSPORT)) ?
                1u :
                0u;
        config.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                      RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                      RDP_GCC_MULTITRANSPORT_UDP_PREFERRED;
        config.extra_channels = static_channel_count > 0 ? static_channel_defs : NULL;
        config.extra_channel_count = (uint16_t)static_channel_count;

        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.connect.initial",
                        "width=%u height=%u selected_protocol=%u dynamic_channels=%u audio_output=%u device_redirection=%u pnp=%u remote_programs=%u multitransport=%u static_channels=%u multitransport_flags=%u early_capability_flags=%u",
                        (unsigned)config.desktop_width,
                        (unsigned)config.desktop_height,
                        config.requested_protocols,
                        (unsigned)config.enable_dynamic_channels,
                        (unsigned)config.enable_audio_output,
                        (unsigned)config.enable_device_redirection,
                        (unsigned)config.enable_pnp_redirection,
                        (unsigned)config.enable_remote_programs,
                        (unsigned)config.enable_multitransport,
                        (unsigned)config.extra_channel_count,
                        config.multitransport_flags,
                        (unsigned)config.early_capability_flags);
        status = rdp_gcc_write_client_data_blocks(&gcc_blocks, &config);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_mcs_write_connect_initial(&mcs, gcc_request.data, gcc_request.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.connect.initial", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.connect.response");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_connect_response(mcs_pdu, mcs_pdu_len, &mcs_response);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (!mcs_response.has_result || mcs_response.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response.failed", "result=%u", mcs_response.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response", "result=%u", mcs_response.result);
    if (mcs_response.user_data_len > 0)
    {
        status = rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                          mcs_response.user_data_len,
                                                          &gcc_response);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        if (gcc_response.result != 0)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "gcc.conference.response.failed", "result=%u", gcc_response.result);
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto fail;
        }
        status = rdp_gcc_parse_server_data_blocks(gcc_response.user_data, gcc_response.user_data_len, &server_data);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        server_encryption_method = server_data.encryption_method;
        server_encryption_level = server_data.encryption_level;
        if (server_data.server_random_len > 0)
        {
            status = rdp_buffer_append(&server_random, server_data.server_random, server_data.server_random_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        if (server_data.server_certificate_len > 0)
        {
            status = rdp_buffer_append(&server_certificate,
                                       server_data.server_certificate,
                                       server_data.server_certificate_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.conference.response",
                        "node_id=%u tag=%u user_data_len=%u",
                        gcc_response.node_id,
                        gcc_response.tag,
                        (unsigned)gcc_response.user_data_len);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.core",
                        "version=%u requested_protocols=%u early_capability_flags=%u",
                        server_data.version,
                        server_data.requested_protocols,
                        server_data.early_capability_flags);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.security",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_data.encryption_method,
                        server_data.encryption_level,
                        server_data.server_random_len,
                        server_data.server_certificate_len);
        if (server_data.has_multitransport && rdp_session_multitransport_runtime_supported())
        {
            session->multitransport_negotiated = 1;
            session->multitransport_flags = server_data.multitransport_flags;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.multitransport",
                            "flags=%u udp_fecr=%u udp_fecl=%u udp_preferred=%u softsync=%u",
                            server_data.multitransport_flags,
                            (server_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_UDP_FECR) ? 1u : 0u,
                            (server_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_UDP_FECL) ? 1u : 0u,
                            (server_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_UDP_PREFERRED) ? 1u : 0u,
                            (server_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP) ? 1u : 0u);
        }
        else if (server_data.has_multitransport)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.multitransport.ignored",
                            "flags=%u reason=runtime_unavailable",
                            server_data.multitransport_flags);
        }
        if (server_data.has_network)
        {
            uint16_t channel_index = 0;
            uint8_t audio_output_enabled =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_AUDIO_OUTPUT);
            uint8_t device_redirection_enabled = rdp_session_device_redirection_ready_for_negotiation(session);
            uint8_t pnp_redirection_enabled =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_PNP);
            uint8_t remote_programs_enabled =
                rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_RAIL);

            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.network",
                            "mcs_channel_id=%u channel_count=%u",
                            server_data.mcs_channel_id,
                            server_data.channel_count);
            if (server_data.channel_count > channel_index)
            {
                session->dynamic_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.drdynvc.channel",
                                "channel_id=%u",
                                session->dynamic_channel_id);
            }
            if (server_data.channel_count > channel_index)
            {
                session->clipboard_channel_id = server_data.channel_ids[channel_index++];
                rdp_session_clipboard_clear(session);
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.clipboard.channel",
                                "channel_id=%u",
                                session->clipboard_channel_id);
            }
            if (audio_output_enabled && server_data.channel_count > channel_index)
            {
                session->audio_output_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rdpsnd.channel",
                                "channel_id=%u",
                                session->audio_output_channel_id);
            }
            if (device_redirection_enabled && server_data.channel_count > channel_index)
            {
                session->device_redirection_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rdpdr.channel",
                                "channel_id=%u",
                                session->device_redirection_channel_id);
            }
            if (pnp_redirection_enabled && server_data.channel_count > channel_index)
            {
                session->pnp_redirection_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pnp.channel",
                                "channel_id=%u",
                                session->pnp_redirection_channel_id);
            }
            if (remote_programs_enabled && server_data.channel_count > channel_index)
            {
                session->remote_programs_channel_id = server_data.channel_ids[channel_index++];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.rail.channel",
                                "channel_id=%u apps=%u",
                                session->remote_programs_channel_id,
                                librdp_settings_rail_app_count(session->settings));
            }
            if ((uint32_t)(server_data.channel_count - channel_index) < static_channel_count)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                goto fail;
            }
            for (uint32_t i = 0; i < static_channel_count; i++)
            {
                const char* name = rdp_settings_static_channel_name_internal(session->settings, i);
                uint32_t flags = rdp_settings_static_channel_flags_internal(session->settings, i);
                uint16_t channel_id = server_data.channel_ids[channel_index++];

                status = rdp_session_static_channel_configure(session, i, name, flags, channel_id);
                if (status != LIBRDP_STATUS_OK)
                    goto fail;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.channel.static",
                                "name=%s channel_id=%u flags=%u",
                                name,
                                channel_id,
                                flags);
            }
        }
    }

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_erect_domain_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.erect_domain.request", "sub_height=0 sub_interval=0");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.erect_domain.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_attach_user_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.request", "message=sent");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.attach_user.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.attach_user.confirm");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_attach_user_confirm(mcs_pdu, mcs_pdu_len, &attach_confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (attach_confirm.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.failed", "result=%u", attach_confirm.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    session->mcs_user_id = attach_confirm.user_id;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.confirm", "result=0 user_id=%u", session->mcs_user_id);

    status = rdp_session_join_mcs_channel(session, session->mcs_user_id, "user", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_session_join_mcs_channel(session, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, "global", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    if (session->dynamic_channel_id != 0 && session->dynamic_channel_id != session->mcs_user_id &&
        session->dynamic_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->dynamic_channel_id, "drdynvc", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->clipboard_channel_id != 0 && session->clipboard_channel_id != session->mcs_user_id &&
        session->clipboard_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->clipboard_channel_id, "cliprdr", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->audio_output_channel_id != 0 && session->audio_output_channel_id != session->mcs_user_id &&
        session->audio_output_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->audio_output_channel_id, "rdpsnd", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->device_redirection_channel_id != 0 &&
        session->device_redirection_channel_id != session->mcs_user_id &&
        session->device_redirection_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->device_redirection_channel_id,
                                              "rdpdr",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->pnp_redirection_channel_id != 0 &&
        session->pnp_redirection_channel_id != session->mcs_user_id &&
        session->pnp_redirection_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->pnp_redirection_channel_id,
                                              "PNPDR",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->remote_programs_channel_id != 0 &&
        session->remote_programs_channel_id != session->mcs_user_id &&
        session->remote_programs_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session,
                                              session->remote_programs_channel_id,
                                              "rail",
                                              &mcs,
                                              &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    for (uint32_t i = 0; i < session->static_channel_count; i++)
    {
        rdp_session_static_channel* channel = &session->static_channels[i];

        if (!channel->active || channel->channel_id == session->mcs_user_id ||
            channel->channel_id == RDP_MCS_GLOBAL_CHANNEL_ID)
            continue;
        status = rdp_session_join_mcs_channel(session, channel->channel_id, channel->name, &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_session_emit_channel_open_data(session, channel->channel_id, channel->name);
    }

    if (selected_protocol == RDP_X224_PROTOCOL_STANDARD &&
        (server_encryption_method != 0 || server_encryption_level != 0))
    {
        uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
        rdp_security_public_key public_key;
        rdp_buffer encrypted_client_random;

        memset(&public_key, 0, sizeof(public_key));
        rdp_buffer_init(&encrypted_client_random);
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_AUTHENTICATING);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.security_exchange.start",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_encryption_method,
                        server_encryption_level,
                        (unsigned)server_random.length,
                        (unsigned)server_certificate.length);
        if (server_random.length != RDP_SECURITY_CLIENT_RANDOM_LEN || server_certificate.length == 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_security_parse_server_certificate(server_certificate.data, server_certificate.length, &public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_generate_client_random(client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_encrypt_client_random(&public_key, client_random, &encrypted_client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_standard_client_init(&session->standard_security,
                                                       server_encryption_method,
                                                       client_random,
                                                       server_random.data);
        memset(client_random, 0, sizeof(client_random));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_exchange_pdu(&security_payload,
                                                     encrypted_client_random.data,
                                                     encrypted_client_random.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_send_data_request(&security_data,
                                                          session->mcs_user_id,
                                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                          security_payload.data,
                                                          security_payload.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.security_exchange.pdu", 0);
        if (status == LIBRDP_STATUS_OK)
        {
            standard_security_ready = 1;
            session->standard_security_active = 1;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.security_exchange.done",
                            "encrypted_random_len=%u",
                            (unsigned)encrypted_client_random.length);
        }
        rdp_security_public_key_clear(&public_key);
        rdp_buffer_free(&encrypted_client_random);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_buffer_free(&security_payload);
        rdp_buffer_free(&security_data);
        rdp_buffer_init(&security_payload);
        rdp_buffer_init(&security_data);
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_NEGOTIATING);
    }

    {
        rdp_client_info info;
        memset(&info, 0, sizeof(info));
        info.domain = credential_domain;
        info.username = credential_username;
        info.password = credential_password;
        info.alternate_shell = NULL;
        info.working_dir = NULL;
        if (standard_security_ready)
            status = rdp_security_write_encrypted_client_info_pdu(&security_payload,
                                                                  &session->standard_security,
                                                                  &info);
        else
            status = rdp_security_write_client_info_pdu(&security_payload, &info);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_AUTHENTICATING);
    status = rdp_security_write_send_data_request(&security_data,
                                                  session->mcs_user_id,
                                                  (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                  security_payload.data,
                                                  security_payload.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.client_info.start",
                    "domain_present=%u username_present=%u password=masked encrypted=%u",
                    credential_domain ? 1u : 0u,
                    credential_username ? 1u : 0u,
                    standard_security_ready ? 1u : 0u);
    status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.client_info.pdu", 0);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.client_info.done", "status=sent");
    if (session->remote_programs_channel_id != 0)
    {
        status = rdp_session_send_remote_programs_startup(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    if (session->pnp_redirection_channel_id != 0)
    {
        status = rdp_session_pnp_send_version(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_session_pnp_send_authenticated(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_session_pnp_send_devices(session);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_ACTIVATING);
    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);

    rdp_session_emit_surface_invalidated(session,
                                         0,
                                         0,
                                         librdp_surface_width(session->surface),
                                         librdp_surface_height(session->surface));
    rdp_session_pointer_emit_default(session);

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.done", "transport=tcp");
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    if (provider_credentials_initialized)
        librdp_credentials_clear(&provider_credentials);
    rdp_session_trace_scope_end(session);
    return LIBRDP_STATUS_OK;

fail:
    rdp_transport_close(&session->transport);
    rdp_session_audio_output_udp_close(session);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    rdp_license_client_state_init(&session->license_state);
    rdp_license_crypto_context_clear(&session->license_crypto);
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_udp_active = 0;
    session->audio_output_udp_block_no = 0;
    session->audio_output_udp_peer_valid = 0;
    session->audio_output_crypt_seed_valid = 0;
    session->audio_output_udp_fd = -1;
    session->audio_output_udp_port = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_udp_next_fragment_no = 0;
    session->audio_output_udp_peer_len = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    memset(&session->audio_output_udp_peer, 0, sizeof(session->audio_output_udp_peer));
    memset(session->audio_output_crypt_seed, 0, sizeof(session->audio_output_crypt_seed));
    session->audio_input_channel_id = 0;
    session->audio_input_channel_id_bytes = 0;
    session->audio_input_ready = 0;
    session->audio_input_open = 0;
    session->audio_input_open_reply_sent = 0;
    session->audio_input_version = 0;
    session->audio_input_selected_format_count = 0;
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    session->multitransport_negotiated = 0;
    session->multitransport_flags = 0;
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    session->device_redirection_channel_id = 0;
    session->device_redirection_ready = 0;
    session->device_redirection_fragmenting = 0;
    session->device_redirection_version_minor = 0;
    session->device_redirection_client_id = 0;
    session->device_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_init(&session->device_redirection_fragment);
    session->pnp_redirection_channel_id = 0;
    session->pnp_redirection_ready = 0;
    session->pnp_redirection_fragmenting = 0;
    session->pnp_redirection_io_version = 0;
    session->pnp_redirection_devices_sent = 0;
    session->pnp_redirection_open_device_active = 0;
    session->pnp_redirection_open_device_id = 0;
    session->pnp_redirection_storage_active = 0;
    session->pnp_redirection_storage_device_id = 0;
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_init(&session->pnp_redirection_storage);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.failed", "status=%d", (int)status);
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    if (provider_credentials_initialized)
        librdp_credentials_clear(&provider_credentials);
    rdp_session_trace_scope_end(session);
    return rdp_session_fail(session, status);
}

static int rdp_session_reconnect_policy_valid(const librdp_reconnect_policy* policy)
{
    return policy && policy->version == LIBRDP_RECONNECT_POLICY_VERSION &&
           policy->size >= offsetof(librdp_reconnect_policy, max_delay_ms) + sizeof(policy->max_delay_ms) &&
           policy->max_attempts > 0 && policy->max_attempts <= RDP_SESSION_RECONNECT_MAX_ATTEMPTS;
}

static uint32_t rdp_session_reconnect_next_delay(uint32_t delay_ms, uint32_t max_delay_ms)
{
    uint32_t next = 0;

    if (delay_ms == 0)
        return 0;
    next = delay_ms > UINT32_MAX / 2u ? UINT32_MAX : delay_ms * 2u;
    if (max_delay_ms != 0 && next > max_delay_ms)
        return max_delay_ms;
    return next;
}

static librdp_status rdp_session_reconnect_wait(librdp_session* session, uint32_t delay_ms)
{
    uint64_t remaining = delay_ms;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
        return rdp_session_finish_cancel(session);
    while (remaining > 0)
    {
        struct pollfd wakeup;
        int timeout = remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
        int rc = 0;

        memset(&wakeup, 0, sizeof(wakeup));
        wakeup.fd = session->wakeup_pipe[0];
        wakeup.events = POLLIN;
        rc = poll(wakeup.fd >= 0 ? &wakeup : NULL, wakeup.fd >= 0 ? 1u : 0u, timeout);
        if (rc < 0)
        {
            if (errno == EINTR)
                continue;
            return LIBRDP_STATUS_IO_ERROR;
        }
        if (rc > 0)
        {
            rdp_session_wakeup_drain(session);
            if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
                return rdp_session_finish_cancel(session);
        }
        if (remaining <= (uint64_t)timeout)
            break;
        remaining -= (uint64_t)timeout;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Reconnect owns the transient transport teardown/recreate boundary while
 * preserving user settings and requested feature state.  Handles exported by a
 * previous connection are invalidated by the disconnect path before a new
 * activation is attempted, and any failed attempt leaves the session in FAILED
 * rather than reporting partially active state.
 */
librdp_status librdp_session_reconnect(librdp_session* session, const librdp_reconnect_policy* policy)
{
    librdp_reconnect_policy effective;
    rdp_trace_session_scope trace_scope;
    uint32_t attempt = 0;
    uint32_t delay_ms = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_bind_owner(session, "client.reconnect.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!policy)
    {
        status = librdp_reconnect_policy_init(&effective);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else
    {
        effective = *policy;
    }
    if (!rdp_session_reconnect_policy_valid(&effective))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_IDLE || session->state == LIBRDP_SESSION_CONNECTING ||
        session->state == LIBRDP_SESSION_CLOSING)
        return LIBRDP_STATUS_STATE;

    rdp_session_trace_scope_begin(session, &trace_scope);
    rdp_session_metric_add(&session->metrics.reconnects, 1);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.reconnect.start",
                    "state=%d max_attempts=%u initial_delay_ms=%u max_delay_ms=%u",
                    (int)session->state,
                    effective.max_attempts,
                    effective.initial_delay_ms,
                    effective.max_delay_ms);

    if (session->state == LIBRDP_SESSION_CONNECTED || session->state == LIBRDP_SESSION_ACTIVE ||
        session->state == LIBRDP_SESSION_FAILED)
    {
        status = rdp_session_disconnect_inner(session);
        if (status != LIBRDP_STATUS_OK)
            goto done;
    }

    delay_ms = effective.initial_delay_ms;
    for (attempt = 1; attempt <= effective.max_attempts; attempt++)
    {
        rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_RECONNECTING);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.reconnect.attempt",
                        "attempt=%u max_attempts=%u",
                        attempt,
                        effective.max_attempts);
        status = librdp_session_connect(session);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT, "client.reconnect.done", "attempt=%u", attempt);
            goto done;
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.reconnect.attempt.failed",
                        "attempt=%u status=%s",
                        attempt,
                        librdp_status_string(status));
        if (attempt == effective.max_attempts)
            break;
        status = rdp_session_reconnect_wait(session, delay_ms);
        if (status != LIBRDP_STATUS_OK)
            goto done;
        delay_ms = rdp_session_reconnect_next_delay(delay_ms, effective.max_delay_ms);
    }
    rdp_trace_event(RDP_TRACE_CLIENT, "client.reconnect.failed", "status=%s", librdp_status_string(status));

done:
    rdp_session_trace_scope_end(session);
    return status;
}

static librdp_status rdp_session_require_pollable(const librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->transport.fd < 0 || session->wakeup_pipe[0] < 0)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

static size_t rdp_session_pollfd_count(const librdp_session* session)
{
    return session && session->audio_output_udp_fd >= 0 ? 3u : 2u;
}

static void rdp_session_fill_pollfds(const librdp_session* session, struct pollfd* fds)
{
    memset(fds, 0, sizeof(*fds) * rdp_session_pollfd_count(session));
    fds[0].fd = session->transport.fd;
    fds[0].events = POLLIN;
    fds[1].fd = session->wakeup_pipe[0];
    fds[1].events = POLLIN;
    if (session->audio_output_udp_fd >= 0)
    {
        fds[2].fd = session->audio_output_udp_fd;
        fds[2].events = POLLIN;
    }
}

/*
 * Checks whether transport input is already queued before local timers consume
 * pending protocol state. This preserves ordering for late replies that arrived
 * while the application was outside the dispatch loop.
 */
static int rdp_session_transport_input_ready_now(const librdp_session* session)
{
    struct pollfd pfd;
    int rc = 0;

    if (!session || session->transport.fd < 0)
        return 0;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = session->transport.fd;
    pfd.events = POLLIN;
    do
    {
        rc = poll(&pfd, 1u, 0);
    } while (rc < 0 && errno == EINTR);
    return rc > 0 && (pfd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0;
}

/*
 * Run one iteration of the active session loop. Transport readiness, PDU
 * decoding, channel dispatch, framebuffer events, and disconnect conditions
 * are processed without re-entering callbacks concurrently.
 */
static librdp_status rdp_session_run_once_inner(librdp_session* session, int timeout_ms)
{
    short revents = 0;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
        return rdp_session_finish_cancel(session);
    if (!rdp_session_transport_input_ready_now(session))
        rdp_session_echo_check_timeout(session);
    {
        int echo_timeout_ms = rdp_session_echo_next_timeout_ms(session);

        if (echo_timeout_ms >= 0 && echo_timeout_ms < timeout_ms)
            timeout_ms = echo_timeout_ms;
    }

    rdp_buffer_init(&packet);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.active.loop.start",
                          "timeout_ms=%d",
                          timeout_ms);
    if (session->pending_poll)
    {
        short wakeup_revents = session->pending_wakeup_revents;
        short udp_revents = session->pending_udp_revents;

        revents = session->pending_tcp_revents;
        session->pending_tcp_revents = 0;
        session->pending_wakeup_revents = 0;
        session->pending_udp_revents = 0;
        session->pending_poll = 0;
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.wait.done",
                              "source=notify tcp_revents=%d wakeup_revents=%d udp_revents=%d",
                              (int)revents,
                              (int)wakeup_revents,
                              (int)udp_revents);
        if ((wakeup_revents & POLLIN) != 0)
        {
            rdp_session_wakeup_drain(session);
            if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
            {
                rdp_buffer_free(&packet);
                return rdp_session_finish_cancel(session);
            }
        }
        if ((wakeup_revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            status = LIBRDP_STATUS_IO_ERROR;
        if ((udp_revents & POLLIN) != 0)
            status = rdp_session_handle_audio_output_udp_datagram(session);
        if ((udp_revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            rdp_trace_event(RDP_TRACE_TRANSPORT,
                            "transport.udp.closed",
                            "component=rdpsnd revents=%d",
                            (int)udp_revents);
            rdp_session_audio_output_udp_close(session);
        }
        if (status == LIBRDP_STATUS_OK && (revents & POLLIN) == 0)
            goto done;
    }
    else
    {
        struct pollfd pfds[3];
        size_t pfd_count = rdp_session_pollfd_count(session);
        int rc = 0;
        short wakeup_revents = 0;
        short udp_revents = 0;

        rdp_session_fill_pollfds(session, pfds);
        rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "transport.wait.start",
                              "timeout_ms=%d fds=%u",
                              timeout_ms,
                              (unsigned)pfd_count);
        do
        {
            rc = poll(pfds, (nfds_t)pfd_count, timeout_ms);
        } while (rc < 0 && errno == EINTR);
        if (rc == 0)
            status = LIBRDP_STATUS_TIMEOUT;
        else if (rc < 0)
            status = LIBRDP_STATUS_IO_ERROR;
        else
        {
            status = LIBRDP_STATUS_OK;
            revents = pfds[0].revents;
            wakeup_revents = pfds[1].revents;
            if (pfd_count > 2u)
                udp_revents = pfds[2].revents;
            rdp_trace_event_level(RDP_TRACE_TRANSPORT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "transport.wait.done",
                                  "tcp_revents=%d wakeup_revents=%d udp_revents=%d",
                                  (int)pfds[0].revents,
                                  (int)wakeup_revents,
                                  (int)udp_revents);
            if ((wakeup_revents & POLLIN) != 0)
            {
                rdp_session_wakeup_drain(session);
                if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
                {
                    rdp_buffer_free(&packet);
                    return rdp_session_finish_cancel(session);
                }
            }
            if ((wakeup_revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
                status = LIBRDP_STATUS_IO_ERROR;
            if (status == LIBRDP_STATUS_OK && (udp_revents & POLLIN) != 0)
                status = rdp_session_handle_audio_output_udp_datagram(session);
            if ((udp_revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            {
                rdp_trace_event(RDP_TRACE_TRANSPORT,
                                "transport.udp.closed",
                                "component=rdpsnd revents=%d",
                                (int)udp_revents);
                rdp_session_audio_output_udp_close(session);
            }
            if (status == LIBRDP_STATUS_OK && (revents & POLLIN) == 0)
                goto done;
        }
    }
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        rdp_session_echo_check_timeout(session);
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.active.loop.done",
                              "status=timeout");
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&packet);
        return status;
    }
    if ((revents & POLLIN) != 0)
    {
        uint8_t first_byte = 0;
        size_t peeked = 0;

        status = rdp_transport_peek(&session->transport, &first_byte, 1, &peeked);
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK || peeked != 1)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_IO_ERROR : status);
        }
        if (first_byte != 3)
        {
            status = rdp_session_read_fastpath_packet(session, &packet);
            if (status == LIBRDP_STATUS_CLOSED)
            {
                rdp_buffer_free(&packet);
                return librdp_session_disconnect(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_process_fastpath_packet(session, &packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            goto done;
        }
        const uint8_t* pdu = NULL;
        size_t pdu_len = 0;
        rdp_mcs_send_data_indication indication;
        rdp_slowpath_share_control_header slow_header;
        rdp_buffer security_payload;
        const uint8_t* indication_payload = NULL;
        size_t indication_payload_len = 0;
        uint16_t security_flags = 0;
        int have_slow_header = 0;

        rdp_buffer_init(&security_payload);
        status = rdp_session_read_mcs_pdu(session, &packet, &pdu, &pdu_len, "rdp.slowpath.pdu");
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        status = rdp_mcs_parse_send_data_indication(pdu, pdu_len, &indication);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        indication_payload = indication.payload;
        indication_payload_len = indication.payload_len;
        if (session->standard_security_active)
        {
            status = rdp_security_unwrap_pdu(&session->standard_security,
                                             indication.payload,
                                             indication.payload_len,
                                             &security_payload,
                                             &security_flags);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            indication_payload = security_payload.data;
            indication_payload_len = security_payload.length;
        }
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "mcs.send_data.indication",
                              "initiator=%u channel_id=%u payload_len=%u security_flags=%u",
                              indication.initiator,
                              indication.channel_id,
                              (unsigned)indication_payload_len,
                              security_flags);
        if (session->dynamic_channel_id != 0 && indication.channel_id == session->dynamic_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_session_metric_add(&session->metrics.channel_in, 1);
            rdp_session_metric_add(&session->metrics.channel_bytes_in, channel_packet.payload_len);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.drdynvc.data",
                                  "channel_id=%u flags=%u payload_len=%u",
                                  indication.channel_id,
                                  channel_packet.flags,
                                  (unsigned)channel_packet.payload_len);
            status = rdp_session_handle_dynamic_channel(session, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_dynamic_channel_header failed_header;
                uint8_t failed_command = 0;
                uint8_t failed_raw = channel_packet.payload_len > 0 ? channel_packet.payload[0] : 0;

                if (rdp_dynamic_channel_parse_header(channel_packet.payload,
                                                     channel_packet.payload_len,
                                                     &failed_header) == LIBRDP_STATUS_OK)
                    failed_command = failed_header.command;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.drdynvc.dispatch.failed",
                                "status=%s static_channel_id=%u flags=%u virtual_len=%u payload_len=%u raw=%u command=%u",
                                librdp_status_string(status),
                                indication.channel_id,
                                channel_packet.flags,
                                channel_packet.length,
                                (unsigned)channel_packet.payload_len,
                                failed_raw,
                                failed_command);
                rdp_trace_hexdump("client.drdynvc.dispatch.failed",
                                  RDP_TRACE_SENSITIVITY_HEADER,
                                  channel_packet.payload,
                                  channel_packet.payload_len);
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        {
            rdp_session_static_channel* static_channel =
                rdp_session_static_channel_find_by_id(session, indication.channel_id);

            if (static_channel)
            {
                rdp_virtual_channel_packet channel_packet;

                status = rdp_virtual_channel_parse_packet(indication_payload,
                                                          indication_payload_len,
                                                          &channel_packet);
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
                rdp_session_metric_add(&session->metrics.channel_in, 1);
                rdp_session_metric_add(&session->metrics.channel_bytes_in, channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.channel.static.data",
                                      "name=%s channel_id=%u flags=%u payload_len=%u",
                                      static_channel->name,
                                      indication.channel_id,
                                      channel_packet.flags,
                                      (unsigned)channel_packet.payload_len);
                status = rdp_session_handle_static_channel(session, static_channel, &channel_packet);
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
                rdp_buffer_free(&security_payload);
                goto done;
            }
        }
        if (session->clipboard_channel_id != 0 && indication.channel_id == session->clipboard_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_session_metric_add(&session->metrics.channel_in, 1);
            rdp_session_metric_add(&session->metrics.channel_bytes_in, channel_packet.payload_len);
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_clipboard_message(session,
                                                              channel_packet.payload,
                                                              channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->clipboard_fragment);
                rdp_buffer_init(&session->clipboard_fragment);
                if (channel_packet.length == 0)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else if (channel_packet.length > session->limits.channel_buffer_bytes)
                    status = rdp_session_limit_rejected(session);
                else
                    status = rdp_buffer_reserve(&session->clipboard_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->clipboard_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->clipboard_fragmenting = 1;
                    session->clipboard_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.clipboard.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->clipboard_fragmenting)
            {
                if (session->clipboard_fragment.length > session->clipboard_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->clipboard_fragment_expected - session->clipboard_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->clipboard_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.clipboard.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->clipboard_fragment_expected,
                                      (unsigned)session->clipboard_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->clipboard_fragment.length != session->clipboard_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_clipboard_message(session,
                                                                      session->clipboard_fragment.data,
                                                                      session->clipboard_fragment.length);
                    rdp_buffer_free(&session->clipboard_fragment);
                    session->clipboard_fragmenting = 0;
                    session->clipboard_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->audio_output_channel_id != 0 && indication.channel_id == session->audio_output_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_audio_output_message(session,
                                                                 channel_packet.payload,
                                                                 channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->audio_output_fragment);
                rdp_buffer_init(&session->audio_output_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->audio_output_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->audio_output_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->audio_output_fragmenting = 1;
                    session->audio_output_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rdpsnd.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->audio_output_fragmenting)
            {
                if (session->audio_output_fragment.length > session->audio_output_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->audio_output_fragment_expected - session->audio_output_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->audio_output_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rdpsnd.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->audio_output_fragment_expected,
                                      (unsigned)session->audio_output_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->audio_output_fragment.length != session->audio_output_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_audio_output_message(session,
                                                                         session->audio_output_fragment.data,
                                                                         session->audio_output_fragment.length);
                    rdp_buffer_free(&session->audio_output_fragment);
                    session->audio_output_fragmenting = 0;
                    session->audio_output_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->device_redirection_channel_id != 0 &&
            indication.channel_id == session->device_redirection_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_device_redirection_message(session,
                                                                       channel_packet.payload,
                                                                       channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->device_redirection_fragment);
                rdp_buffer_init(&session->device_redirection_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->device_redirection_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->device_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->device_redirection_fragmenting = 1;
                    session->device_redirection_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rdpdr.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->device_redirection_fragmenting)
            {
                if (session->device_redirection_fragment.length > session->device_redirection_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->device_redirection_fragment_expected -
                    session->device_redirection_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->device_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rdpdr.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->device_redirection_fragment_expected,
                                      (unsigned)session->device_redirection_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->device_redirection_fragment.length !=
                        session->device_redirection_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_device_redirection_message(
                            session,
                            session->device_redirection_fragment.data,
                            session->device_redirection_fragment.length);
                    rdp_buffer_free(&session->device_redirection_fragment);
                    session->device_redirection_fragmenting = 0;
                    session->device_redirection_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->pnp_redirection_channel_id != 0 &&
            indication.channel_id == session->pnp_redirection_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_pnp_redirection_message(session,
                                                                    channel_packet.payload,
                                                                    channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->pnp_redirection_fragment);
                rdp_buffer_init(&session->pnp_redirection_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->pnp_redirection_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->pnp_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->pnp_redirection_fragmenting = 1;
                    session->pnp_redirection_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.pnp.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->pnp_redirection_fragmenting)
            {
                if (session->pnp_redirection_fragment.length > session->pnp_redirection_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->pnp_redirection_fragment_expected -
                    session->pnp_redirection_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->pnp_redirection_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.pnp.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->pnp_redirection_fragment_expected,
                                      (unsigned)session->pnp_redirection_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->pnp_redirection_fragment.length != session->pnp_redirection_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_pnp_redirection_message(
                            session,
                            session->pnp_redirection_fragment.data,
                            session->pnp_redirection_fragment.length);
                    rdp_buffer_free(&session->pnp_redirection_fragment);
                    session->pnp_redirection_fragmenting = 0;
                    session->pnp_redirection_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        if (session->remote_programs_channel_id != 0 &&
            indication.channel_id == session->remote_programs_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;
            uint32_t fragment_flags = 0;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            fragment_flags = channel_packet.flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
            if (fragment_flags == (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
            {
                status = rdp_session_handle_remote_programs_message(session,
                                                                    channel_packet.payload,
                                                                    channel_packet.payload_len);
            }
            else if (fragment_flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST)
            {
                rdp_buffer_free(&session->remote_programs_fragment);
                rdp_buffer_init(&session->remote_programs_fragment);
                if (channel_packet.length == 0 || channel_packet.length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                    status = rdp_buffer_reserve(&session->remote_programs_fragment, channel_packet.length);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->remote_programs_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->remote_programs_fragmenting = 1;
                    session->remote_programs_fragment_expected = channel_packet.length;
                    rdp_trace_event_level(RDP_TRACE_CLIENT,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "client.rail.fragment.start",
                                          "channel_id=%u total_len=%u payload_len=%u",
                                          indication.channel_id,
                                          channel_packet.length,
                                          (unsigned)channel_packet.payload_len);
                }
            }
            else if (session->remote_programs_fragmenting)
            {
                if (session->remote_programs_fragment.length > session->remote_programs_fragment_expected ||
                    channel_packet.payload_len >
                    (size_t)session->remote_programs_fragment_expected -
                    session->remote_programs_fragment.length)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_buffer_append(&session->remote_programs_fragment,
                                               channel_packet.payload,
                                               channel_packet.payload_len);
                rdp_trace_event_level(RDP_TRACE_CLIENT,
                                      RDP_TRACE_LEVEL_DEBUG,
                                      "client.rail.fragment.data",
                                      "channel_id=%u total_len=%u received=%u payload_len=%u flags=%u",
                                      indication.channel_id,
                                      session->remote_programs_fragment_expected,
                                      (unsigned)session->remote_programs_fragment.length,
                                      (unsigned)channel_packet.payload_len,
                                      channel_packet.flags);
                if (status == LIBRDP_STATUS_OK && (channel_packet.flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) != 0)
                {
                    if (session->remote_programs_fragment.length !=
                        session->remote_programs_fragment_expected)
                        status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_handle_remote_programs_message(
                            session,
                            session->remote_programs_fragment.data,
                            session->remote_programs_fragment.length);
                    rdp_buffer_free(&session->remote_programs_fragment);
                    session->remote_programs_fragmenting = 0;
                    session->remote_programs_fragment_expected = 0;
                }
            }
            else
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        status = rdp_slowpath_parse_share_control_header(indication_payload, indication_payload_len, &slow_header);
        if (status == LIBRDP_STATUS_OK)
            have_slow_header = 1;
        if (status != LIBRDP_STATUS_OK)
        {
            uint8_t license_message_type = 0;
            librdp_status license_status = rdp_license_classify_message(indication_payload,
                                                                        indication_payload_len,
                                                                        &license_message_type);
            if (license_status == LIBRDP_STATUS_OK)
            {
                if (license_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT)
                {
                    rdp_license_error_alert alert;

                    license_status = rdp_license_parse_error_alert(indication_payload,
                                                                   indication_payload_len,
                                                                   &alert);
                    if (license_status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step_error_alert(&session->license_state,
                                                                                   &alert);
                    if (license_status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.error_alert",
                                        "type=%u flags=%u error=%u state=%u blob_type=%u blob_len=%u client_state=%u",
                                        alert.message_type,
                                        alert.flags,
                                        alert.error_code,
                                        alert.state_transition,
                                        alert.blob_type,
                                        alert.blob_length,
                                        (unsigned)session->license_state.state);
                        status = rdp_license_error_alert_is_terminal_success(&alert) ?
                                     LIBRDP_STATUS_OK :
                                     LIBRDP_STATUS_PROTOCOL_ERROR;
                    }
                }
                else if (license_message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE ||
                         license_message_type == RDP_LICENSE_MESSAGE_UPGRADE_LICENSE)
                {
                    rdp_license_new_or_upgrade license;

                    license_status = rdp_license_parse_new_or_upgrade(indication_payload,
                                                                      indication_payload_len,
                                                                      &license);
                    if (license_status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step(&session->license_state,
                                                                       RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                                                       license_message_type);
                    if (license_status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.new_or_upgrade",
                                        "type=%u blob_type=%u blob_len=%u client_state=%u",
                                        license.preamble.message_type,
                                        license.encrypted_license_info.type,
                                        license.encrypted_license_info.length,
                                        (unsigned)session->license_state.state);
                        status = LIBRDP_STATUS_OK;
                    }
                }
                else if (license_message_type == RDP_LICENSE_MESSAGE_REQUEST)
                {
                    rdp_license_server_request request;
                    rdp_buffer response;

                    rdp_buffer_init(&response);
                    license_status = rdp_license_parse_server_request(indication_payload,
                                                                      indication_payload_len,
                                                                      &request);
                    if (license_status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step(&session->license_state,
                                                                       RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                                                       license_message_type);
                    if (license_status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.request",
                                        "scope_count=%u key_exchange_blob_len=%u cert_len=%u client_state=%u",
                                        request.scope_list.count,
                                        request.key_exchange_list.length,
                                        request.server_certificate.length,
                                        (unsigned)session->license_state.state);
                        status = rdp_license_build_new_license_request(&session->license_crypto,
                                                                       &request,
                                                                       librdp_settings_username(session->settings),
                                                                       "librdp",
                                                                       &response);
                    }
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                        status = rdp_session_write_license_pdu(session,
                                                               &response,
                                                               "rdp.licensing.new_license_request");
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step(&session->license_state,
                                                                       RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                                                                       RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST);
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.new_license_request",
                                        "payload_len=%u client_state=%u",
                                        (unsigned)response.length,
                                        (unsigned)session->license_state.state);
                    }
                    rdp_buffer_free(&response);
                }
                else if (license_message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE)
                {
                    rdp_license_platform_challenge challenge;
                    rdp_buffer response;

                    rdp_buffer_init(&response);
                    license_status = rdp_license_parse_platform_challenge(indication_payload,
                                                                          indication_payload_len,
                                                                          &challenge);
                    if (license_status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step(&session->license_state,
                                                                       RDP_LICENSE_DIRECTION_SERVER_TO_CLIENT,
                                                                       license_message_type);
                    if (license_status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.platform_challenge",
                                        "connect_flags=%u challenge_len=%u client_state=%u",
                                        challenge.connect_flags,
                                        challenge.encrypted_challenge.length,
                                        (unsigned)session->license_state.state);
                        status = rdp_license_build_platform_challenge_response(&session->license_crypto,
                                                                               &challenge,
                                                                               &response);
                    }
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                        status = rdp_session_write_license_pdu(session,
                                                               &response,
                                                               "rdp.licensing.platform_challenge_response");
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                        license_status = rdp_license_client_state_step(
                            &session->license_state,
                            RDP_LICENSE_DIRECTION_CLIENT_TO_SERVER,
                            RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE);
                    if (license_status == LIBRDP_STATUS_OK && status == LIBRDP_STATUS_OK)
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.licensing.platform_challenge_response",
                                        "payload_len=%u client_state=%u",
                                        (unsigned)response.length,
                                        (unsigned)session->license_state.state);
                    }
                    rdp_buffer_free(&response);
                }
            }
            if (license_status == LIBRDP_STATUS_OK)
            {
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
                goto done;
            }
        }
        if (have_slow_header && status == LIBRDP_STATUS_OK &&
            (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        {
            rdp_slowpath_demand_active demand;
            rdp_buffer confirm;

            rdp_buffer_init(&confirm);
            status = rdp_slowpath_parse_demand_active(indication_payload, indication_payload_len, &demand);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.activation.demand_active",
                                "share_id=%u capabilities=%u",
                                demand.share_id,
                                demand.capabilities.count);
            if (status == LIBRDP_STATUS_OK)
                session->share_id = demand.share_id;
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_session_pointer_cache_clear(session);
                rdp_session_pointer_emit_default(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_slowpath_write_confirm_active(&confirm,
                                                           demand.share_id,
                                                           session->mcs_user_id,
                                                           (uint16_t)librdp_surface_width(session->surface),
                                                           (uint16_t)librdp_surface_height(session->surface),
                                                           "librdp");
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_slowpath_pdu(session, &confirm, "rdp.activation.confirm_active");
            rdp_buffer_free(&confirm);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.confirm_active", "share_id=%u", demand.share_id);
            status = rdp_session_send_activation_finalization(session, demand.share_id);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            if (session->clipboard_channel_id != 0)
            {
                status = rdp_session_send_clipboard_handshake(session);
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
            }
            rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_ACTIVE);
            rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);
        }
        else if (have_slow_header && status == LIBRDP_STATUS_OK &&
                 (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
        {
            rdp_slowpath_data_pdu data_pdu;

            status = rdp_slowpath_parse_data_pdu(indication_payload, indication_payload_len, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "rdp.slowpath.data",
                                  "type=%u compressed_type=%u payload_len=%u",
                                  data_pdu.pdu_type2,
                                  data_pdu.compressed_type,
                                  (unsigned)data_pdu.payload_len);
            status = rdp_session_trace_slowpath_data_pdu(session, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE)
            {
                const uint8_t* slow_payload = data_pdu.payload;
                size_t slow_payload_len = data_pdu.payload_len;

                if (session->state != LIBRDP_SESSION_ACTIVE)
                {
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.slowpath.update.rejected",
                                    "reason=before_activation type=%u payload_len=%u",
                                    data_pdu.pdu_type2,
                                    (unsigned)data_pdu.payload_len);
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                }
                if (data_pdu.compressed_type != 0)
                {
                    size_t compressed_payload_len = 0;

                    if (data_pdu.compressed_length < 18u)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                    }
                    compressed_payload_len = (size_t)data_pdu.compressed_length - 18u;
                    if (compressed_payload_len > data_pdu.payload_len)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                    }
                    status = rdp_session_decompress_bulk_payload(session,
                                                                data_pdu.compressed_type,
                                                                data_pdu.payload,
                                                                compressed_payload_len,
                                                                &session->slowpath_decompressed);
                    if (status != LIBRDP_STATUS_OK)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, status);
                    }
                    slow_payload = session->slowpath_decompressed.data;
                    slow_payload_len = session->slowpath_decompressed.length;
                    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "rdp.slowpath.decompress",
                                          "compressed_type=%u compressed_len=%u decoded_len=%u",
                                          data_pdu.compressed_type,
                                          (unsigned)compressed_payload_len,
                                          (unsigned)slow_payload_len);
                }
                {
                    rdp_stream update_stream;
                    uint16_t update_type = 0;

                    rdp_stream_init(&update_stream, slow_payload, slow_payload_len);
                    if (rdp_stream_read_u16_le(&update_stream, &update_type) != LIBRDP_STATUS_OK)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                    }
                    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                                          RDP_TRACE_LEVEL_DEBUG,
                                          "rdp.slowpath.update",
                                          "update_type=%u payload_len=%u",
                                          update_type,
                                          (unsigned)slow_payload_len);
                    if (update_type == RDP_GDI_UPDATE_TYPE_ORDERS)
                    {
                        rdp_gdi_orders_update orders;

                        status = rdp_gdi_parse_slow_orders_update_payload(slow_payload,
                                                                          slow_payload_len,
                                                                          &orders);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_apply_gdi_orders_update(session, &orders);
                        if (status == LIBRDP_STATUS_UNSUPPORTED)
                        {
                            rdp_trace_event(RDP_TRACE_PROTOCOL,
                                            "rdp.slowpath.orders.rejected",
                                            "orders=%u payload_len=%u",
                                            orders.number_orders,
                                            (unsigned)orders.order_data_len);
                        }
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.orders", "orders=%u", orders.number_orders);
                    }
                    else if (update_type == RDP_UPDATE_TYPE_BITMAP)
                    {
                        rdp_bitmap_update update;

                        status = rdp_bitmap_parse_update(slow_payload, slow_payload_len, &update);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_apply_bitmap_update(session, &update);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.bitmap_update", "rectangles=%u", update.count);
                    }
                    else if (update_type == RDP_UPDATE_TYPE_PALETTE)
                    {
                        rdp_palette_update palette;

                        status = rdp_bitmap_parse_palette_update(slow_payload, slow_payload_len, &palette);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_apply_palette_update(session, &palette);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.palette_update", "colors=%u", palette.count);
                    }
                    else if (update_type == RDP_UPDATE_TYPE_POINTER)
                    {
                        rdp_pointer_update pointer;

                        status = rdp_pointer_parse_slowpath(slow_payload + 2u, slow_payload_len - 2u, &pointer);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_pointer_apply_update(session, &pointer);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.pointer",
                                        "kind=%u cache_index=%u width=%u height=%u",
                                        pointer.kind,
                                        pointer.cache_index,
                                        pointer.width,
                                        pointer.height);
                    }
                    else
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.update.ignored",
                                        "update_type=%u payload_len=%u",
                                        update_type,
                                        (unsigned)slow_payload_len);
                    }
                }
            }
        }
        rdp_buffer_free(&security_payload);
    }

done:
    rdp_buffer_free(&packet);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.active.loop.done",
                          "status=idle");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_run_once_inner(session, timeout_ms);
    status = rdp_session_bind_owner(session, "client.dispatch.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_run_once_inner(session, timeout_ms);
    rdp_session_trace_scope_end(session);
    return status;
}

librdp_status librdp_session_cancel(librdp_session* session)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_store_explicit(&session->cancel_requested, 1u, memory_order_release);
    status = rdp_session_wakeup_signal(session);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT, "client.cancel.requested", "state=%d", (int)session->state);
    return status;
}

librdp_status librdp_session_get_pollfds(librdp_session* session,
                                         struct pollfd* fds,
                                         size_t capacity,
                                         size_t* count)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t required = 0;

    if (!count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.pollfds.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;

    required = rdp_session_pollfd_count(session);
    *count = required;
    if (!fds)
        return capacity == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capacity < required)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_session_fill_pollfds(session, fds);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_notify_poll(librdp_session* session, const struct pollfd* fds, size_t count)
{
    size_t i = 0;
    int matched = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!fds || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.notify_poll.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (i = 0; i < count; i++)
    {
        if (fds[i].fd == session->transport.fd)
        {
            session->pending_tcp_revents = (short)(session->pending_tcp_revents | fds[i].revents);
            matched = 1;
        }
        else if (fds[i].fd == session->wakeup_pipe[0])
        {
            session->pending_wakeup_revents = (short)(session->pending_wakeup_revents | fds[i].revents);
            matched = 1;
        }
        else if (session->audio_output_udp_fd >= 0 && fds[i].fd == session->audio_output_udp_fd)
        {
            session->pending_udp_revents = (short)(session->pending_udp_revents | fds[i].revents);
            matched = 1;
        }
        else
        {
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
    }
    if (matched && (session->pending_tcp_revents != 0 || session->pending_wakeup_revents != 0 ||
                    session->pending_udp_revents != 0))
        session->pending_poll = 1;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_dispatch_pending(librdp_session* session)
{
    librdp_status status = rdp_session_bind_owner(session, "client.dispatch_pending.owner");

    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->pending_poll &&
        atomic_load_explicit(&session->cancel_requested, memory_order_acquire) == 0u)
    {
        if (rdp_session_echo_next_timeout_ms(session) == 0)
            rdp_session_echo_check_timeout(session);
        return LIBRDP_STATUS_OK;
    }
    return librdp_session_run_once(session, 0);
}

librdp_status librdp_session_get_next_timeout(const librdp_session* session, int* timeout_ms)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner_const(session, "client.next_timeout.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    *timeout_ms = (session->pending_poll ||
                   atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
                      ? 0
                      : -1;
    {
        int echo_timeout_ms = rdp_session_echo_next_timeout_ms(session);

        if (echo_timeout_ms >= 0 &&
            (*timeout_ms < 0 || echo_timeout_ms < *timeout_ms))
            *timeout_ms = echo_timeout_ms;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Tear down an active or partially connected session. Transport, channels,
 * backends, caches, surfaces, and sensitive buffers are released in an order
 * that prevents callbacks from observing freed state.
 */
librdp_status rdp_session_disconnect_inner(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE ||
        session->state == LIBRDP_SESSION_CANCELLED)
        return LIBRDP_STATUS_OK;

    atomic_store_explicit(&session->cancel_requested, 0u, memory_order_release);
    rdp_session_wakeup_drain(session);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_DISCONNECTING);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_session_graphics_dirty_reset(session);
    rdp_transport_close(&session->transport);
    rdp_session_audio_output_udp_close(session);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    rdp_license_crypto_context_clear(&session->license_crypto);
    session->clipboard_channel_id = 0;
    rdp_session_clipboard_clear(session);
    session->audio_output_channel_id = 0;
    session->audio_output_ready = 0;
    session->audio_output_fragmenting = 0;
    session->audio_output_pending_wave = 0;
    session->audio_output_udp_active = 0;
    session->audio_output_udp_block_no = 0;
    session->audio_output_udp_peer_valid = 0;
    session->audio_output_crypt_seed_valid = 0;
    session->audio_output_udp_fd = -1;
    session->audio_output_udp_port = 0;
    session->audio_output_fragment_expected = 0;
    session->audio_output_server_version = 0;
    session->audio_output_client_version = 0;
    session->audio_output_pending_format_no = 0;
    session->audio_output_pending_timestamp = 0;
    session->audio_output_pending_expected_len = 0;
    session->audio_output_pending_block_no = 0;
    session->audio_output_udp_next_fragment_no = 0;
    session->audio_output_udp_peer_len = 0;
    session->audio_output_selected_format_count = 0;
    memset(session->audio_output_selected_formats, 0, sizeof(session->audio_output_selected_formats));
    memset(&session->audio_output_udp_peer, 0, sizeof(session->audio_output_udp_peer));
    memset(session->audio_output_crypt_seed, 0, sizeof(session->audio_output_crypt_seed));
    rdp_buffer_free(&session->audio_output_fragment);
    rdp_buffer_init(&session->audio_output_fragment);
    rdp_buffer_free(&session->audio_output_pending_data);
    rdp_buffer_init(&session->audio_output_pending_data);
    rdp_buffer_free(&session->audio_output_udp_data);
    rdp_buffer_init(&session->audio_output_udp_data);
    session->device_redirection_channel_id = 0;
    session->device_redirection_ready = 0;
    session->device_redirection_fragmenting = 0;
    session->device_redirection_version_minor = 0;
    session->device_redirection_client_id = 0;
    session->device_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->device_redirection_fragment);
    rdp_buffer_init(&session->device_redirection_fragment);
    session->pnp_redirection_channel_id = 0;
    session->pnp_redirection_ready = 0;
    session->pnp_redirection_fragmenting = 0;
    session->pnp_redirection_io_version = 0;
    session->pnp_redirection_devices_sent = 0;
    session->pnp_redirection_open_device_active = 0;
    session->pnp_redirection_open_device_id = 0;
    session->pnp_redirection_storage_active = 0;
    session->pnp_redirection_storage_device_id = 0;
    session->pnp_redirection_fragment_expected = 0;
    rdp_buffer_free(&session->pnp_redirection_fragment);
    rdp_buffer_init(&session->pnp_redirection_fragment);
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_init(&session->pnp_redirection_storage);
    session->remote_programs_channel_id = 0;
    session->remote_programs_ready = 0;
    session->remote_programs_fragmenting = 0;
    session->remote_programs_exec_sent = 0;
    session->remote_programs_fragment_expected = 0;
    rdp_buffer_free(&session->remote_programs_fragment);
    rdp_buffer_init(&session->remote_programs_fragment);
    rdp_session_echo_clear_pending(session);
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->input_channel_id = 0;
    session->input_channel_id_bytes = 0;
    session->input_channel_ready = 0;
    session->input_channel_suspended = 0;
    session->input_channel_protocol_version = 0;
    session->input_channel_supported_features = 0;
    session->input_channel_max_touch_contacts = 0;
    session->input_channel_supports_pen = 0;
    session->display_control_channel_id = 0;
    session->display_control_channel_id_bytes = 0;
    session->display_control_ready = 0;
    session->sent_desktop_width = 0;
    session->sent_desktop_height = 0;
    memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
    session->graphics_channel_id = 0;
    session->graphics_channel_id_bytes = 0;
    session->graphics_ready = 0;
    session->graphics_selected_version = 0;
    session->graphics_selected_flags = 0;
    session->graphics_frames_decoded = 0;
    session->mouse_cursor_channel_id = 0;
    session->mouse_cursor_channel_id_bytes = 0;
    session->mouse_cursor_ready = 0;
    session->audio_input_channel_id = 0;
    session->audio_input_channel_id_bytes = 0;
    session->audio_input_ready = 0;
    session->audio_input_open = 0;
    session->audio_input_open_reply_sent = 0;
    session->audio_input_version = 0;
    session->audio_input_selected_format_count = 0;
    memset(session->audio_input_selected_formats, 0, sizeof(session->audio_input_selected_formats));
    session->multitransport_negotiated = 0;
    session->multitransport_flags = 0;
    rdp_session_composited_reset(session);
    rdp_session_video_redirection_reset(session);
    rdp_session_video_optimized_reset(session);
    rdp_session_video_capture_reset(session);
    rdp_session_webauthn_channel_reset(session);
    rdp_session_usb_redirection_reset(session);
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_graphics_decompressor_reset(&session->bulk_rdp8_decompressor);
    rdp_bulk_decompressor_reset(&session->bulk_decompressor);
    session->slowpath_decompressed.length = 0;
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_nscodec_context_reset(&session->surface_nscodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_gdi_color_table_cache_clear(session);
    rdp_session_gdi_brush_cache_clear(session);
    rdp_session_gdi_ninegrid_cache_clear(session);
    rdp_session_gdi_glyph_cache_clear(session);
    rdp_session_gdi_glyph_fragment_cache_clear(session);
    rdp_session_gdi_bitmap_cache_clear(session);
    rdp_session_gdi_saved_bitmaps_clear(session);
    rdp_session_gdi_offscreen_cache_clear(session);
    rdp_session_gdi_stream_bitmap_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_palette_reset(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);
    rdp_session_smartcard_reset(session);
    rdp_session_set_lifecycle(session, LIBRDP_LIFECYCLE_DISCONNECTED);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_disconnect_inner(session);
    status = rdp_session_require_owner(session, "client.disconnect.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_disconnect_inner(session);
    rdp_session_trace_scope_end(session);
    return status;
}

librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.resize.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;

    status = rdp_session_request_display_control_layout(session, width, height);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_OK : status;
}

librdp_status librdp_session_set_display_layout(librdp_session* session,
                                                const librdp_display_monitor* monitors,
                                                uint32_t monitor_count)
{
    rdp_display_control_monitor internal[LIBRDP_DISPLAY_MAX_MONITORS];
    rdp_buffer validation;
    uint32_t width = 0;
    uint32_t height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !monitors || monitor_count == 0 || monitor_count > LIBRDP_DISPLAY_MAX_MONITORS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.display_layout.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(internal, 0, sizeof(internal));
    status = rdp_session_copy_display_monitors(internal, monitors, monitor_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_display_layout_bounds(internal, monitor_count, &width, &height);
    if (status == LIBRDP_STATUS_OK &&
        (width > session->limits.surface_max_dimension ||
         height > session->limits.surface_max_dimension))
        status = rdp_session_limit_rejected(session);
    rdp_buffer_init(&validation);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_display_control_write_monitor_layout(&validation, internal, monitor_count);
    rdp_buffer_free(&validation);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_settings_enable_feature(session->settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;

    memcpy(session->requested_monitors, internal, sizeof(internal[0]) * monitor_count);
    if (monitor_count < LIBRDP_DISPLAY_MAX_MONITORS)
        memset(session->requested_monitors + monitor_count,
               0,
               sizeof(internal[0]) * (LIBRDP_DISPLAY_MAX_MONITORS - monitor_count));
    session->requested_monitor_count = monitor_count;
    session->requested_monitor_layout_valid = 1;
    session->requested_desktop_width = width;
    session->requested_desktop_height = height;

    status = rdp_session_send_display_control_monitors(session, internal, monitor_count);
    if (status == LIBRDP_STATUS_STATE)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout.local",
                        "monitors=%u width=%u height=%u wire=not_sent",
                        monitor_count,
                        width,
                        height);
        return LIBRDP_STATUS_OK;
    }
    return status;
}

librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    rdp_buffer refresh;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || x > 0xffffu || y > 0xffffu ||
        width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.refresh.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (x + width - 1u > 0xffffu || y + height - 1u > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&refresh);
    status = rdp_slowpath_write_client_refresh_rect(&refresh,
                                                    session->share_id,
                                                    session->mcs_user_id,
                                                    (uint16_t)x,
                                                    (uint16_t)y,
                                                    (uint16_t)width,
                                                    (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &refresh, "rdp.refresh_rect");
    rdp_buffer_free(&refresh);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.refresh_rect",
                        "x=%u y=%u width=%u height=%u",
                        x,
                        y,
                        width,
                        height);
    return status;
}

librdp_status librdp_session_video_capture_send_sample(librdp_session* session,
                                                       uint8_t stream_index,
                                                       const void* data,
                                                       size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_owner(session, "client.video_capture.sample.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (data_len > session->limits.frame_bytes)
        return rdp_session_limit_rejected(session);
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    status = rdp_session_send_video_capture_sample_payload(session,
                                                           stream_index,
                                                           data,
                                                           data_len,
                                                           "client.rdpecam.sample.response");
    return status;
}

librdp_status librdp_session_video_capture_send_error(librdp_session* session,
                                                      uint8_t stream_index,
                                                      uint32_t error_code)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    {
        librdp_status status = rdp_session_require_owner(session, "client.video_capture.error.owner");
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->video_capture_channel_id == 0 || session->video_capture_channel_id_bytes == 0 ||
        !session->video_capture_active || !session->video_capture_streaming ||
        !session->video_capture_sample_reply_pending ||
        stream_index != session->video_capture_selected_stream)
        return LIBRDP_STATUS_STATE;
    return rdp_session_send_video_capture_sample_error(session, stream_index, error_code);
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

librdp_session_lifecycle librdp_session_get_lifecycle(const librdp_session* session)
{
    return session ? session->lifecycle : LIBRDP_LIFECYCLE_FAILED;
}

static int rdp_session_video_runtime_active(const librdp_session* session)
{
    if (!session)
        return 0;
    for (uint32_t i = 0; i < RDP_SESSION_VIDEO_STREAMS; i++)
    {
        if (session->video_streams[i].active)
            return 1;
    }
    for (uint32_t i = 0; i < RDP_SESSION_VIDEO_OPTIMIZED_PRESENTATIONS; i++)
    {
        if (session->video_optimized_presentations[i].active)
            return 1;
    }
    return 0;
}

static void rdp_session_finish_feature_status(librdp_feature_status* status,
                                              int negotiated,
                                              int active,
                                              int parser_only)
{
    if (!status)
        return;

    status->negotiated = negotiated ? 1 : 0;
    status->active = active ? 1 : 0;
    if (parser_only)
        status->reason = LIBRDP_FEATURE_REASON_PARSER_ONLY;
    else if (!status->negotiated)
        status->reason = LIBRDP_FEATURE_REASON_NOT_NEGOTIATED;
    else if (!status->active)
        status->reason = LIBRDP_FEATURE_REASON_NOT_ACTIVE;
    else
        status->reason = LIBRDP_FEATURE_REASON_NONE;
}

/*
 * Runtime feature status must be derived from real negotiated channel state.
 * The enabled bit only expresses intent; it cannot make parser-only helpers or
 * unavailable OS backends appear active to public callers.
 */
librdp_status librdp_session_get_feature_status(const librdp_session* session,
                                                librdp_feature feature,
                                                librdp_feature_status* status)
{
    librdp_status rc = LIBRDP_STATUS_OK;

    if (!session || !status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rc = rdp_session_require_owner_const(session, "client.feature_status.owner");
    if (rc != LIBRDP_STATUS_OK)
        return rc;

    rc = librdp_settings_get_feature_status(session->settings, feature, status);
    if (rc != LIBRDP_STATUS_OK)
        return rc;
    if (!status->requested || !status->built || !status->backend_ready)
        return LIBRDP_STATUS_OK;

    switch (feature)
    {
        case LIBRDP_FEATURE_AUDIO_OUTPUT:
            rdp_session_finish_feature_status(status,
                                              session->audio_output_channel_id != 0,
                                              session->audio_output_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_AUDIO_INPUT:
            rdp_session_finish_feature_status(status,
                                              session->audio_input_channel_id != 0,
                                              session->audio_input_open != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_VIDEO:
            rdp_session_finish_feature_status(status,
                                              session->video_redirection_channel_id != 0 ||
                                                  session->video_optimized_control_channel_id != 0 ||
                                                  session->video_optimized_data_channel_id != 0,
                                              rdp_session_video_runtime_active(session),
                                              0);
            break;
        case LIBRDP_FEATURE_CAMERA:
            rdp_session_finish_feature_status(status,
                                              session->video_capture_control_channel_id != 0 ||
                                                  session->video_capture_channel_id != 0,
                                              session->video_capture_active != 0 ||
                                                  session->video_capture_streaming != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_SMARTCARD:
            rdp_session_finish_feature_status(status,
                                              session->device_redirection_channel_id != 0,
                                              session->device_redirection_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_USB:
            rdp_session_finish_feature_status(status,
                                              session->usb_redirection_channel_id != 0,
                                              session->usb_redirection_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_PNP:
            rdp_session_finish_feature_status(status,
                                              session->pnp_redirection_channel_id != 0,
                                              session->pnp_redirection_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_WEBAUTHN:
            rdp_session_finish_feature_status(status,
                                              session->webauthn_channel_id != 0,
                                              session->webauthn_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_RAIL:
            rdp_session_finish_feature_status(status,
                                              session->remote_programs_channel_id != 0,
                                              session->remote_programs_ready != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_CR2:
            rdp_session_finish_feature_status(status,
                                              session->composited_channel_id != 0,
                                              session->composited_connection_open != 0,
                                              0);
            break;
        case LIBRDP_FEATURE_ECHO:
            rdp_session_finish_feature_status(status,
                                              rdp_session_echo_channel_active(session),
                                              rdp_session_echo_channel_active(session),
                                              0);
            break;
        case LIBRDP_FEATURE_TELEMETRY:
            rdp_session_finish_feature_status(status, 0, 0, 1);
            break;
        case LIBRDP_FEATURE_MULTITRANSPORT:
            rdp_session_finish_feature_status(status,
                                              session->multitransport_negotiated != 0 &&
                                                  session->multitransport_flags != 0,
                                              0,
                                              !rdp_session_multitransport_runtime_supported());
            break;
        case LIBRDP_FEATURE_DESKTOP_COMPOSITION:
            rdp_session_finish_feature_status(status, 0, 0, 1);
            break;
        case LIBRDP_FEATURE_UDP_TRANSPORT:
        case LIBRDP_FEATURE_UDP2_TRANSPORT:
        case LIBRDP_FEATURE_GEOMETRY_TRACKING:
        case LIBRDP_FEATURE_MULTIPARTY:
            rdp_session_finish_feature_status(status, 0, 0, 1);
            break;
        case LIBRDP_FEATURE_DISPLAY_CONTROL:
            rdp_session_finish_feature_status(status,
                                              session->display_control_channel_id != 0,
                                              session->display_control_ready != 0,
                                              0);
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    return LIBRDP_STATUS_OK;
}

const librdp_surface* librdp_session_get_surface(const librdp_session* session)
{
    return session ? session->surface : NULL;
}
