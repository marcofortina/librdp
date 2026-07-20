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


#include <librdp/channel.h>
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
#include "gateway/gateway.h"
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
#include "transport/udp_transport.h"
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
#include <libusb.h>
#endif

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
 * must only ask the server for channels whose host-side backend and runtime
 * path are already configured.
 */
uint8_t rdp_session_feature_ready_for_negotiation(const librdp_session* session, librdp_feature feature)
{
    librdp_feature_status status;

    if (!session || !session->settings)
        return 0;
    memset(&status, 0, sizeof(status));
    if (librdp_settings_get_feature_status(session->settings, feature, &status) != LIBRDP_STATUS_OK)
        return 0;
    return (status.requested && status.backend_ready) ? 1u : 0u;
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

static int rdp_session_static_channel_def_exists(const rdp_gcc_channel_definition* defs,
                                                 uint32_t count,
                                                 const char* name)
{
    uint32_t i = 0;

    if (!defs || !name)
        return 0;
    for (i = 0; i < count; i++)
    {
        if (strncmp(defs[i].name, name, sizeof(defs[i].name)) == 0)
            return 1;
    }
    return 0;
}

static librdp_status rdp_session_add_static_channel_def(rdp_gcc_channel_definition* defs,
                                                        uint32_t* count,
                                                        const char* name,
                                                        uint32_t flags)
{
    size_t name_len = 0;

    if (!defs || !count || !name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_session_static_channel_def_exists(defs, *count, name))
        return LIBRDP_STATUS_OK;
    name_len = strlen(name);
    if (name_len == 0 || name_len >= sizeof(defs[0].name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (*count >= LIBRDP_SETTINGS_MAX_STATIC_CHANNELS)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    memset(&defs[*count], 0, sizeof(defs[*count]));
    memcpy(defs[*count].name, name, name_len + 1u);
    defs[*count].flags = flags != 0 ? flags : LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS;
    (*count)++;
    return LIBRDP_STATUS_OK;
}

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

    if (!session ||
        width < LIBRDP_DESKTOP_MIN_DIMENSION ||
        height < LIBRDP_DESKTOP_MIN_DIMENSION ||
        width > LIBRDP_DESKTOP_MAX_DIMENSION ||
        height > LIBRDP_DESKTOP_MAX_DIMENSION)
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
    status = rdp_session_read_mcs_pdu_timeout(session,
                                              reply,
                                              &pdu,
                                              &pdu_len,
                                              "mcs.channel_join.confirm",
                                              RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
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
        uint32_t right = 0;
        uint32_t bottom = 0;
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
    else if (strcmp(entry->name, RDP_TELEMETRY_DVC_CHANNEL_NAME) == 0)
    {
        rdp_telemetry_pdu pdu;

        status = rdp_telemetry_parse_pdu(data, data_len, &pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->telemetry_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.telemetry.pdu",
                        "dvc_channel_id=%u prompt_ms=%u first_graphics_ms=%u",
                        channel_id,
                        pdu.prompt_for_credentials_ms,
                        pdu.first_graphics_received_ms);
        rdp_session_emit_channel_data(session, entry, data, data_len);
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
        else if (request.name_len == sizeof(RDP_TELEMETRY_DVC_CHANNEL_NAME) - 1u &&
                 memcmp(request.name, RDP_TELEMETRY_DVC_CHANNEL_NAME, request.name_len) == 0)
        {
            session->telemetry_channel_id = request.channel_id;
            session->telemetry_channel_id_bytes = request.channel_id_bytes;
            session->telemetry_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.telemetry.channel",
                            "dvc_channel_id=%u enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_TELEMETRY));
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
                            "dvc_channel_id=%u video_enabled=%u geometry_enabled=%u",
                            request.channel_id,
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_VIDEO),
                            rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_GEOMETRY_TRACKING));
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
            rdp_session_gdi_gdiplus_reset(session);
            rdp_session_gdi_window_state_reset(session);
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
                rdp_session_gdi_gdiplus_reset(session);
                rdp_session_gdi_window_state_reset(session);
            }
            if (entry->channel_id == session->usb_redirection_channel_id)
                rdp_session_usb_redirection_reset(session);
            if (entry->channel_id == session->telemetry_channel_id)
            {
                session->telemetry_channel_id = 0;
                session->telemetry_channel_id_bytes = 0;
                session->telemetry_ready = 0;
            }
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
            uint32_t tunnels[2];
            uint32_t tunnel_count = 0;

            rdp_buffer_init(&response);
            memset(tunnels, 0, sizeof(tunnels));
            status = rdp_dynamic_channel_parse_soft_sync_request(channel_packet->payload,
                                                                 channel_packet->payload_len,
                                                                 &request);
            if (status == LIBRDP_STATUS_OK && request.tunnel_count > 0)
            {
                for (uint16_t i = 0; i < request.tunnel_count && tunnel_count < 2u; i++)
                {
                    rdp_dynamic_channel_soft_sync_channel_list list;

                    status = rdp_dynamic_channel_soft_sync_request_get_list(&request, i, &list);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    if (list.tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
                        rdp_session_multitransport_runtime_supported() &&
                        session->multitransport_negotiated &&
                        session->multitransport_flags != 0 &&
                        rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_UDP_TRANSPORT))
                    {
                        tunnels[tunnel_count++] = list.tunnel_type;
                    }
                    else if (list.tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY &&
                             rdp_session_multitransport_runtime_supported() &&
                             session->multitransport_negotiated &&
                             session->multitransport_flags != 0 &&
                             rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_UDP_TRANSPORT))
                    {
                        tunnels[tunnel_count++] = list.tunnel_type;
                    }
                }
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_dynamic_channel_write_soft_sync_response(&response,
                                                                      tunnel_count > 0 ? tunnels : NULL,
                                                                      tunnel_count);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session,
                                                       session->dynamic_channel_id,
                                                       &response,
                                                       "client.drdynvc.soft_sync");
            if (status == LIBRDP_STATUS_OK && tunnel_count > 0)
            {
                session->multitransport_udp_active = 1;
                session->multitransport_soft_sync_count++;
            }
            rdp_buffer_free(&response);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.soft_sync",
                            "flags=%u requested_tunnel_count=%u selected_tunnel_count=%u",
                            request.flags,
                            request.tunnel_count,
                            tunnel_count);
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

/*
 * Refresh values derived when the session was constructed. The client facade
 * exposes the session-owned settings before connect, so limits and the primary
 * surface must follow any valid changes made through that public accessor.
 */
static librdp_status rdp_session_refresh_preconnect_configuration(librdp_session* session)
{
    const librdp_limits* limits = NULL;
    uint32_t width = 0;
    uint32_t height = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !session->settings || !session->surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    limits = rdp_settings_limits_internal(session->settings);
    if (!limits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = librdp_settings_width(session->settings);
    height = librdp_settings_height(session->settings);
    if (width > limits->surface_max_dimension || height > limits->surface_max_dimension)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (librdp_surface_width(session->surface) != width ||
        librdp_surface_height(session->surface) != height)
    {
        status = librdp_surface_resize(session->surface, width, height);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    session->limits = *limits;
    session->requested_desktop_width = width;
    session->requested_desktop_height = height;
    return LIBRDP_STATUS_OK;
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
    status = rdp_session_refresh_preconnect_configuration(session);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_set_last_error(session,
                                   status,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_CLIENT,
                                   "client.connect.settings",
                                   "pre-connect settings are not usable");
        return status;
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
    if (rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_MULTIPARTY))
    {
        status = rdp_session_add_static_channel_def(static_channel_defs,
                                                    &static_channel_count,
                                                    RDP_MULTIPARTY_CHANNEL_NAME,
                                                    LIBRDP_STATIC_CHANNEL_DEFAULT_FLAGS);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
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
    rdp_session_gdi_gdiplus_reset(session);
    rdp_session_gdi_window_state_reset(session);
    rdp_session_pointer_cache_clear(session);
    rdp_gdi_render_state_init(&session->gdi_render);
    rdp_session_palette_reset(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_static_channels_clear(session);
    rdp_session_redirected_files_clear(session);
    rdp_session_drive_roots_clear(session);

    if (rdp_settings_gateway_mode_internal(session->settings) != LIBRDP_GATEWAY_DISABLED)
    {
        rdp_gateway_connect_config gateway_config;
        const char* gateway_username = rdp_settings_gateway_username_internal(session->settings);
        const char* gateway_password = rdp_settings_gateway_password_internal(session->settings);
        const char* gateway_domain = rdp_settings_gateway_domain_internal(session->settings);
        const librdp_limits* limits = rdp_settings_limits_internal(session->settings);

        memset(&gateway_config, 0, sizeof(gateway_config));
        if (!gateway_username && rdp_settings_gateway_use_session_credentials_internal(session->settings))
        {
            gateway_username = credential_username;
            gateway_password = credential_password;
            gateway_domain = credential_domain;
        }
        gateway_config.gateway_url = rdp_settings_gateway_url_internal(session->settings);
        gateway_config.target_host = librdp_settings_target(session->settings);
        gateway_config.target_port = librdp_settings_port(session->settings);
        gateway_config.username = gateway_username;
        gateway_config.password = gateway_password;
        gateway_config.domain = gateway_domain;
        gateway_config.timeout_ms = rdp_settings_gateway_timeout_ms_internal(session->settings);
        gateway_config.queue_bytes = limits->pdu_buffer_bytes;
        gateway_config.queue_nodes = limits->pending_requests;
        gateway_config.mode = rdp_settings_gateway_mode_internal(session->settings);
        status = rdp_gateway_connect_transport(&session->transport, &gateway_config);
    }
    else
        status = rdp_transport_connect(&session->transport,
                                       librdp_settings_target(session->settings),
                                       librdp_settings_port(session->settings),
                                       RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
    if (status == LIBRDP_STATUS_OK)
        rdp_session_transport_cancel_arm(session);
    if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
    {
        status = LIBRDP_STATUS_CANCELLED;
        goto fail;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        const int via_gateway =
            rdp_settings_gateway_mode_internal(session->settings) != LIBRDP_GATEWAY_DISABLED;

        rdp_session_set_last_error(session,
                                   status,
                                   errno,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   via_gateway ? "transport.gateway.connect" : "transport.tcp.connect",
                                   via_gateway ? "gateway connect failed" : "tcp connect failed");
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
                      RDP_TRACE_SENSITIVITY_AUTH,
                      request.data,
                      request.length);
    status = rdp_transport_write_all(&session->transport, request.data, request.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_transport_read_tpkt_timeout(&session->transport,
                                             &reply,
                                             RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_session_set_last_error(session,
                                   status,
                                   status == LIBRDP_STATUS_IO_ERROR ? errno : 0,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   "x224.negotiation.read",
                                   "x224 negotiation response failed");
        goto fail;
    }
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
        rdp_session_set_last_error(session,
                                   status,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_PROTOCOL,
                                   "x224.negotiation.policy",
                                   "server selected a protocol below the configured security policy");
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
        tls_config.timeout_ms = RDP_SESSION_HANDSHAKE_TIMEOUT_MS;
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
                                       status == LIBRDP_STATUS_IO_ERROR ? errno : 0,
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
        rdp_credssp_ts_request pub_key_response;
        rdp_ntlm_authenticate_result ntlm_auth_result;
        rdp_ntlm_security_context ntlm_security;
        uint8_t client_nonce[32];
        const char* credssp_failure_phase = "credssp.nla";

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
        {
            credssp_failure_phase = "credssp.nla.challenge.read";
            status = rdp_session_read_credssp_ts_request(session,
                                                         &credssp_reply,
                                                         RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            credssp_failure_phase = "credssp.nla.challenge";
            status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &ts_response);
        }
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.challenge",
                            "version=%u token_len=%u error=%u",
                            ts_response.version,
                            (unsigned)ts_response.nego_token_len,
                            ts_response.has_error_code ? ts_response.error_code : 0);
        if (status == LIBRDP_STATUS_OK && ts_response.has_error_code)
        {
            credssp_failure_phase = "credssp.nla.challenge";
            status = rdp_credssp_status_from_error_code(ts_response.error_code);
        }
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
                status = rdp_credssp_ntlm_security_init(&ntlm_security,
                                                        &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_public_key_hash(
                    &ntlm_security,
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
                                                      ts_response.version ? ts_response.version : 6,
                                                      spnego_authenticate.data,
                                                      spnego_authenticate.length,
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
                                "credssp.nla.authenticate",
                                "token_len=%u flags=%u pub_key_auth_len=%u",
                                (unsigned)credssp_request.length,
                                ntlm_auth_result.flags,
                                (unsigned)pub_key_auth.length);
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey",
                                "token_len=%u pub_key_auth_len=%u combined=1",
                                (unsigned)credssp_request.length,
                                (unsigned)pub_key_auth.length);
                status = rdp_transport_write_all(&session->transport,
                                                 credssp_request.data,
                                                 credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
            {
                credssp_failure_phase = "credssp.nla.pubkey.read";
                status = rdp_session_read_credssp_ts_request(session,
                                                             &credssp_reply,
                                                             RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
            }
            if (status == LIBRDP_STATUS_OK)
            {
                credssp_failure_phase = "credssp.nla.pubkey";
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &pub_key_response);
            }
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                pub_key_response.version,
                                (unsigned)pub_key_response.nego_token_len,
                                (unsigned)pub_key_response.auth_info_len,
                                (unsigned)pub_key_response.pub_key_auth_len,
                                pub_key_response.has_error_code ? pub_key_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK && pub_key_response.has_error_code)
            {
                credssp_failure_phase = "credssp.nla.authenticate";
                status = rdp_credssp_status_from_error_code(pub_key_response.error_code);
            }
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
                                       credssp_failure_phase,
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
    status = rdp_session_read_mcs_pdu_timeout(session,
                                              &reply,
                                              &mcs_pdu,
                                              &mcs_pdu_len,
                                              "mcs.connect.response",
                                              RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
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
                const char* name = static_channel_defs[i].name;
                uint32_t flags = static_channel_defs[i].flags;
                uint16_t channel_id = server_data.channel_ids[channel_index++];

                status = rdp_session_static_channel_configure(session, i, name, flags, channel_id);
                if (status != LIBRDP_STATUS_OK)
                    goto fail;
                if (strcmp(name, RDP_MULTIPARTY_CHANNEL_NAME) == 0)
                    session->multiparty_channel_id = channel_id;
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
    status = rdp_session_read_mcs_pdu_timeout(session,
                                              &reply,
                                              &mcs_pdu,
                                              &mcs_pdu_len,
                                              "mcs.attach_user.confirm",
                                              RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
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
        channel->joined = 1;
        if (strcmp(channel->name, RDP_MULTIPARTY_CHANNEL_NAME) == 0)
            session->multiparty_joined = 1;
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
    status = rdp_session_activation_deadline_start(session);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
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
    if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
        status = LIBRDP_STATUS_CANCELLED;
    rdp_session_transport_close(session);
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
    if (status == LIBRDP_STATUS_CANCELLED)
        return rdp_session_finish_cancel(session);
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
    int attempts_exhausted = 0;
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
        status = rdp_session_disconnect_inner(session);

    if (status == LIBRDP_STATUS_OK)
    {
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
                break;
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.reconnect.attempt.failed",
                            "attempt=%u status=%s",
                            attempt,
                            librdp_status_string(status));
            if (attempt == effective.max_attempts)
            {
                attempts_exhausted = 1;
                break;
            }
            status = rdp_session_reconnect_wait(session, delay_ms);
            if (status != LIBRDP_STATUS_OK)
                break;
            delay_ms = rdp_session_reconnect_next_delay(delay_ms, effective.max_delay_ms);
        }
    }
    if (attempts_exhausted)
        rdp_trace_event(RDP_TRACE_CLIENT, "client.reconnect.failed", "status=%s", librdp_status_string(status));
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

static librdp_status rdp_session_run_once_idle(rdp_buffer* packet)
{
    rdp_buffer_free(packet);
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.active.loop.done",
                          "status=idle");
    return LIBRDP_STATUS_OK;
}

/*
 * Fail a session that connected its transport but never received Demand
 * Active. Teardown precedes the terminal error event so no partially activated
 * channel or transport remains usable after the deadline.
 */
static librdp_status rdp_session_fail_activation_timeout(
    librdp_session* session)
{
    rdp_session_set_last_error(session,
                               LIBRDP_STATUS_TIMEOUT,
                               0,
                               LIBRDP_ERROR_COMPONENT_PROTOCOL,
                               "rdp.activation.timeout",
                               "server activation deadline expired");
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.timeout",
                    "timeout_ms=%u",
                    (unsigned int)RDP_SESSION_HANDSHAKE_TIMEOUT_MS);
    (void)rdp_session_disconnect_inner(session);
    return rdp_session_fail(session, LIBRDP_STATUS_TIMEOUT);
}

/*
 * Reject an encrypted packet before any decoded content reaches a domain
 * dispatcher. Closing the transport first prevents an integrity failure from
 * leaving a failed session attached to an attacker-controlled peer.
 */
static librdp_status rdp_session_fail_security_integrity(
    librdp_session* session,
    const char* phase)
{
    rdp_session_set_last_error(session,
                               LIBRDP_STATUS_PROTOCOL_ERROR,
                               0,
                               LIBRDP_ERROR_COMPONENT_PROTOCOL,
                               phase,
                               "encrypted packet integrity verification failed");
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.security.integrity.failed",
                    "phase=%s",
                    phase);
    (void)rdp_session_disconnect_inner(session);
    return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
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
    int activation_expired = 0;
    int activation_timeout_ms = -1;

    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_require_pollable(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (atomic_load_explicit(&session->cancel_requested, memory_order_acquire) != 0u)
        return rdp_session_finish_cancel(session);
    activation_timeout_ms =
        rdp_session_activation_timeout_ms(session, &activation_expired);
    if (activation_expired)
        return rdp_session_fail_activation_timeout(session);
    if (activation_timeout_ms >= 0 && timeout_ms > activation_timeout_ms)
        timeout_ms = activation_timeout_ms;
    status = rdp_session_usb_dispatch_completions(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_printer_dispatch_completions(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
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
            status = rdp_session_usb_dispatch_completions(session);
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
            return rdp_session_run_once_idle(&packet);
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
                status = rdp_session_usb_dispatch_completions(session);
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
                return rdp_session_run_once_idle(&packet);
        }
    }
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        rdp_session_echo_check_timeout(session);
        (void)rdp_session_activation_timeout_ms(session,
                                                &activation_expired);
        if (activation_expired)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail_activation_timeout(session);
        }
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
        if (status == LIBRDP_STATUS_AGAIN)
            return rdp_session_run_once_idle(&packet);
        if (status != LIBRDP_STATUS_OK || peeked != 1)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_IO_ERROR : status);
        }
        if (first_byte != 3)
        {
            int encrypted_fastpath = 0;

            status = rdp_session_read_fastpath_packet(session, &packet);
            if (status == LIBRDP_STATUS_CLOSED)
            {
                rdp_buffer_free(&packet);
                return librdp_session_disconnect(session);
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_fastpath_header fastpath_header;

                if (rdp_fastpath_parse_header(packet.data,
                                              packet.length,
                                              &fastpath_header) ==
                        LIBRDP_STATUS_OK &&
                    (fastpath_header.security_flags &
                     RDP_FASTPATH_OUTPUT_ENCRYPTED) != 0u)
                    encrypted_fastpath = 1;
                status = rdp_session_process_fastpath_packet(session, &packet);
            }
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                if (status == LIBRDP_STATUS_PROTOCOL_ERROR &&
                    encrypted_fastpath)
                    return rdp_session_fail_security_integrity(
                        session,
                        "rdp.fastpath.security");
                return rdp_session_fail(session, status);
            }
            return rdp_session_run_once_idle(&packet);
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
                if (status == LIBRDP_STATUS_PROTOCOL_ERROR)
                    return rdp_session_fail_security_integrity(
                        session,
                        "rdp.slowpath.security");
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
            return rdp_session_run_once_idle(&packet);
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
                return rdp_session_run_once_idle(&packet);
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
            return rdp_session_run_once_idle(&packet);
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
            return rdp_session_run_once_idle(&packet);
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
            return rdp_session_run_once_idle(&packet);
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
            return rdp_session_run_once_idle(&packet);
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
            return rdp_session_run_once_idle(&packet);
        }
        status = rdp_slowpath_parse_share_control_header(indication_payload, indication_payload_len, &slow_header);
        if (status == LIBRDP_STATUS_OK)
            have_slow_header = 1;
        if (status != LIBRDP_STATUS_OK)
        {
            uint8_t license_message_type = 0;
            int have_license_message = 0;
            librdp_status license_status = rdp_license_classify_message(indication_payload,
                                                                        indication_payload_len,
                                                                        &license_message_type);
            if (license_status == LIBRDP_STATUS_OK)
            {
                have_license_message = 1;
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
            if (have_license_message)
            {
                if (license_status != LIBRDP_STATUS_OK)
                    status = license_status;
                if (status != LIBRDP_STATUS_OK)
                {
                    const char* phase =
                        license_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT ?
                            "rdp.licensing.error_alert" :
                            "rdp.licensing.process";
                    const char* message =
                        license_message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT ?
                            "server rejected licensing exchange" :
                            "licensing message processing failed";

                    rdp_session_set_last_error(session,
                                               status,
                                               0,
                                               LIBRDP_ERROR_COMPONENT_PROTOCOL,
                                               phase,
                                               message);
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.licensing.failed",
                                    "type=%u status=%s client_state=%u",
                                    license_message_type,
                                    librdp_status_string(status),
                                    (unsigned)session->license_state.state);
                    rdp_buffer_free(&security_payload);
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
                rdp_buffer_free(&security_payload);
                return rdp_session_run_once_idle(&packet);
            }
        }
        if (have_slow_header && status == LIBRDP_STATUS_OK &&
            (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        {
            status = rdp_session_handle_demand_active(session, indication_payload, indication_payload_len);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
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

    return rdp_session_run_once_idle(&packet);
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

/*
 * Processes one caller-supplied UDP2 datagram after multitransport negotiation.
 * The function is deliberately session-owned and side-effect limited: malformed
 * packets fail before activation state changes, DATA packets produce bounded
 * ACK bytes in the caller buffer, and no payload bytes are exposed through trace.
 */
librdp_status librdp_session_process_udp2_datagram(librdp_session* session,
                                                   const void* datagram,
                                                   size_t datagram_len,
                                                   void* response,
                                                   size_t response_capacity,
                                                   size_t* response_len)
{
    rdp_buffer packet_bytes;
    rdp_buffer ack_packet;
    rdp_buffer ack_wire;
    rdp_udp2_prefix prefix;
    rdp_udp2_packet packet;
    rdp_udp2_packet_kind kind = RDP_UDP2_PACKET_KIND_CONTROL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    status = rdp_session_require_owner(session, "client.udp2.datagram.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_UDP2_TRANSPORT) ||
        !session->multitransport_negotiated)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_buffer_init(&packet_bytes);
    rdp_buffer_init(&ack_packet);
    rdp_buffer_init(&ack_wire);
    memset(&prefix, 0, sizeof(prefix));
    memset(&packet, 0, sizeof(packet));

    status = rdp_udp2_unwrap_packet(&packet_bytes, datagram, datagram_len, &prefix);
    if (status == LIBRDP_STATUS_OK && prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_parse_packet(packet_bytes.data, packet_bytes.length, &packet);
    if (status == LIBRDP_STATUS_OK && prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_classify_packet(&packet, &kind);
    if (status == LIBRDP_STATUS_OK &&
        (kind == RDP_UDP2_PACKET_KIND_DATA || kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK))
    {
        status = rdp_udp2_write_ack_packet(&ack_packet,
                                           packet.header.log_window_size,
                                           packet.data_sequence_number,
                                           0,
                                           0,
                                           NULL,
                                           0,
                                           0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp2_wrap_packet(&ack_wire,
                                          ack_packet.data,
                                          ack_packet.length,
                                          RDP_UDP2_PACKET_TYPE_DATA);
    }
    if (status == LIBRDP_STATUS_OK && ack_wire.length > response_capacity)
    {
        *response_len = ack_wire.length;
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (ack_wire.length > 0)
            memcpy(response, ack_wire.data, ack_wire.length);
        *response_len = ack_wire.length;
        session->multitransport_udp2_active = 1;
        rdp_session_metric_add(&session->metrics.pdu_in, 1u);
        if (ack_wire.length > 0)
            rdp_session_metric_add(&session->metrics.pdu_out, 1u);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.udp2.datagram",
                        "wire_len=%u ack_len=%u kind=%u",
                        (unsigned)datagram_len,
                        (unsigned)ack_wire.length,
                        (unsigned)kind);
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_session_set_last_error(session,
                                   status,
                                   0,
                                   LIBRDP_ERROR_COMPONENT_TRANSPORT,
                                   "client.udp2.datagram",
                                   "UDP2 datagram processing failed");

    rdp_buffer_free(&ack_wire);
    rdp_buffer_free(&ack_packet);
    rdp_buffer_free(&packet_bytes);
    return status;
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
    {
        int activation_expired = 0;
        int activation_timeout_ms =
            rdp_session_activation_timeout_ms(session, &activation_expired);

        if (activation_expired)
            activation_timeout_ms = 0;
        if (activation_timeout_ms >= 0 &&
            (*timeout_ms < 0 || activation_timeout_ms < *timeout_ms))
            *timeout_ms = activation_timeout_ms;
    }
    return LIBRDP_STATUS_OK;
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

static void rdp_session_finish_feature_status(librdp_feature_status* status,
                                              int negotiated,
                                              int active)
{
    if (!status)
        return;

    status->negotiated = negotiated ? 1 : 0;
    status->active = active ? 1 : 0;
    if (!status->negotiated)
        status->reason = LIBRDP_FEATURE_REASON_NOT_NEGOTIATED;
    else if (!status->active)
        status->reason = LIBRDP_FEATURE_REASON_NOT_ACTIVE;
    else
        status->reason = LIBRDP_FEATURE_REASON_NONE;
}

/*
 * Runtime feature status must be derived from real negotiated channel state.
 * The enabled bit only expresses intent; it cannot make packet helpers or
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
                                              session->audio_output_ready != 0);
            break;
        case LIBRDP_FEATURE_AUDIO_INPUT:
            rdp_session_finish_feature_status(status,
                                              session->audio_input_channel_id != 0,
                                              session->audio_input_open != 0);
            break;
        case LIBRDP_FEATURE_VIDEO:
            rdp_session_finish_feature_status(status,
                                              session->video_redirection_channel_id != 0 ||
                                                  session->video_optimized_control_channel_id != 0 ||
                                                  session->video_optimized_data_channel_id != 0,
                                              rdp_session_video_runtime_active(session));
            break;
        case LIBRDP_FEATURE_CAMERA:
            rdp_session_finish_feature_status(status,
                                              session->video_capture_control_channel_id != 0 ||
                                                  session->video_capture_channel_id != 0,
                                              session->video_capture_active != 0 ||
                                                  session->video_capture_streaming != 0);
            break;
        case LIBRDP_FEATURE_SMARTCARD:
            rdp_session_finish_feature_status(status,
                                              session->device_redirection_channel_id != 0,
                                              session->device_redirection_ready != 0);
            break;
        case LIBRDP_FEATURE_USB:
            rdp_session_finish_feature_status(status,
                                              session->usb_redirection_channel_id != 0,
                                              session->usb_redirection_ready != 0);
            break;
        case LIBRDP_FEATURE_PNP:
            rdp_session_finish_feature_status(status,
                                              session->pnp_redirection_channel_id != 0,
                                              session->pnp_redirection_ready != 0);
            break;
        case LIBRDP_FEATURE_WEBAUTHN:
            rdp_session_finish_feature_status(status,
                                              session->webauthn_channel_id != 0,
                                              session->webauthn_ready != 0);
            break;
        case LIBRDP_FEATURE_RAIL:
            rdp_session_finish_feature_status(status,
                                              session->remote_programs_channel_id != 0,
                                              session->remote_programs_ready != 0);
            break;
        case LIBRDP_FEATURE_CR2:
            rdp_session_finish_feature_status(status,
                                              session->composited_channel_id != 0,
                                              session->composited_connection_open != 0);
            break;
        case LIBRDP_FEATURE_ECHO:
            rdp_session_finish_feature_status(status,
                                              rdp_session_echo_channel_active(session),
                                              rdp_session_echo_channel_active(session));
            break;
        case LIBRDP_FEATURE_TELEMETRY:
            rdp_session_finish_feature_status(status,
                                              session->telemetry_channel_id != 0,
                                              session->telemetry_ready != 0);
            break;
        case LIBRDP_FEATURE_MULTITRANSPORT:
            rdp_session_finish_feature_status(status,
                                              session->multitransport_negotiated != 0 &&
                                                  session->multitransport_flags != 0,
                                              session->multitransport_udp_active != 0 ||
                                                  session->multitransport_udp2_active != 0);
            break;
        case LIBRDP_FEATURE_DESKTOP_COMPOSITION:
            rdp_session_finish_feature_status(status,
                                              session->state == LIBRDP_SESSION_ACTIVE ||
                                                  session->desktop_composition_active != 0,
                                              session->desktop_composition_active != 0);
            break;
        case LIBRDP_FEATURE_UDP_TRANSPORT:
            rdp_session_finish_feature_status(status,
                                              session->multitransport_negotiated != 0 &&
                                                  session->multitransport_flags != 0,
                                              session->multitransport_udp_active != 0);
            break;
        case LIBRDP_FEATURE_UDP2_TRANSPORT:
            rdp_session_finish_feature_status(status,
                                              session->multitransport_negotiated != 0 &&
                                                  session->multitransport_flags != 0,
                                              session->multitransport_udp2_active != 0);
            break;
        case LIBRDP_FEATURE_GEOMETRY_TRACKING:
            rdp_session_finish_feature_status(status,
                                              session->video_redirection_channel_id != 0,
                                              session->video_geometry_update_count != 0);
            break;
        case LIBRDP_FEATURE_MULTIPARTY:
            rdp_session_finish_feature_status(status,
                                              session->multiparty_channel_id != 0,
                                              session->multiparty_joined != 0);
            break;
        case LIBRDP_FEATURE_DISPLAY_CONTROL:
            rdp_session_finish_feature_status(status,
                                              session->display_control_channel_id != 0,
                                              session->display_control_ready != 0);
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
