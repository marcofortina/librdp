/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: protocol channel conformance vectors.
 * Coverage: static and dynamic channel parser/serializer fixtures for audio, device, file, printer, smartcard, WebAuthn, RAIL, telemetry, XPS, and related virtual channels.
 * Bug classes: malformed channel PDUs, string and payload bounds, request correlation, and device I/O edge cases.
 * Determinism: fixtures are synthetic and do not use external services.
 */

#include "channels/virtual_channel.h"
#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/desktop_composition.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/port_redirection.h"
#include "channels/pnp_redirection.h"
#include "channels/printer_redirection.h"
#include "channels/remote_programs.h"
#include "channels/smartcard_redirection.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "channels/xps_print.h"
#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "common/stream.h"
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
#include "protocol/bulk.h"
#include "protocol/capabilities.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/session_selection.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/multitransport.h"
#include "transport/udp_transport.h"

#include <librdp/session.h>

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static uint16_t test_read_u16_le(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t test_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t test_read_u64_le(const uint8_t* data)
{
    return (uint64_t)test_read_u32_le(data) | ((uint64_t)test_read_u32_le(data + 4u) << 32u);
}

static int test_contains_bytes(const uint8_t* data, size_t data_len, const char* needle, size_t needle_len)
{
    size_t i = 0;

    if (!data || !needle || needle_len == 0 || needle_len > data_len)
        return 0;
    for (i = 0; i + needle_len <= data_len; i++)
    {
        if (memcmp(data + i, needle, needle_len) == 0)
            return 1;
    }
    return 0;
}

static int test_session_selection_and_echo(void)
{
    const uint8_t text_utf16[] = {'T', 0, 'e', 0, 's', 0, 't', 0, 0, 0};
    const uint8_t echo_payload[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    static uint8_t oversized_echo_payload[RDP_ECHO_CHANNEL_MAX_PAYLOAD + 1u];
    uint8_t invalid_v1[] = {
        0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    rdp_buffer buffer;
    rdp_session_selection_pdu selection;
    rdp_echo_channel_pdu echo;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_session_selection_write_v1(&buffer, 0xeec699ebu) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == RDP_SESSION_SELECTION_V1_LENGTH);
    PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) == LIBRDP_STATUS_OK);
    PCHECK(selection.version == RDP_SESSION_SELECTION_VERSION1 && selection.id == 0xeec699ebu);
    PCHECK(selection.text_chars == 0 && selection.text_utf16le == NULL);
    {
        rdp_session_selection_pdu valid_selection = selection;

        buffer.data[0] = 0x0fu;
        PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&selection, &valid_selection, sizeof(selection)) == 0);
        PCHECK(rdp_session_selection_parse_pdu(invalid_v1, sizeof(invalid_v1), &selection) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&selection, &valid_selection, sizeof(selection)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_session_selection_write_v2(&buffer, 0, text_utf16, 5) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == RDP_SESSION_SELECTION_V2_HEADER_LENGTH + sizeof(text_utf16));
    PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) == LIBRDP_STATUS_OK);
    PCHECK(selection.version == RDP_SESSION_SELECTION_VERSION2 && selection.text_chars == 5);
    PCHECK(memcmp(selection.text_utf16le, text_utf16, sizeof(text_utf16)) == 0);
    {
        rdp_session_selection_pdu valid_selection = selection;

        buffer.data[16] = 6;
        PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&selection, &valid_selection, sizeof(selection)) == 0);
        buffer.data[16] = 5;
        PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length - 1u, &selection) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&selection, &valid_selection, sizeof(selection)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_echo_channel_parse_request(echo_payload, sizeof(echo_payload), &echo) == LIBRDP_STATUS_OK);
    PCHECK(echo.payload_len == sizeof(echo_payload) && memcmp(echo.payload, echo_payload, sizeof(echo_payload)) == 0);
    PCHECK(rdp_echo_channel_write_response(&buffer, echo.payload, echo.payload_len) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == sizeof(echo_payload) && memcmp(buffer.data, echo_payload, sizeof(echo_payload)) == 0);
    PCHECK(rdp_echo_channel_parse_response(buffer.data, buffer.length, &echo) == LIBRDP_STATUS_OK);
    PCHECK(echo.payload_len == sizeof(echo_payload));
    PCHECK(rdp_echo_channel_write_request(&buffer, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_echo_channel_parse_response(oversized_echo_payload,
                                           sizeof(oversized_echo_payload),
                                           &echo) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_echo_channel_write_request(&buffer,
                                          oversized_echo_payload,
                                          sizeof(oversized_echo_payload)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates serial and parallel redirection parsers, IOCTL
 * filtering, and request serialization against malformed port payloads.
 */
static int test_port_redirection_channel(void)
{
    const uint8_t input[] = {0x80, 0x25, 0x00, 0x00};
    char com1[8] = {'C', 'O', 'M', '1', ':', 0, 0, 0};
    char lpt1[8] = {'L', 'P', 'T', '1', ':', 0, 0, 0};
    rdp_device_redirection_device_announce devices[2];
    rdp_device_redirection_device_list list;
    rdp_filesystem_redirection_control_request control;
    rdp_device_redirection_io_completion completion;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);
    memset(devices, 0, sizeof(devices));

    PCHECK(rdp_port_redirection_device_type_valid(RDP_DEVICE_REDIRECTION_TYPE_SERIAL));
    PCHECK(rdp_port_redirection_device_type_valid(RDP_DEVICE_REDIRECTION_TYPE_PARALLEL));
    PCHECK(!rdp_port_redirection_device_type_valid(RDP_DEVICE_REDIRECTION_TYPE_PRINTER));
    PCHECK(rdp_port_redirection_ioctl_serial(RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE));
    PCHECK(rdp_port_redirection_ioctl_parallel(RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID));
    PCHECK(!rdp_port_redirection_ioctl_known(0xffffffffu));
    PCHECK(rdp_port_redirection_serial_wait_result(RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR |
                                                       RDP_PORT_REDIRECTION_SERIAL_EV_CTS,
                                                   RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR |
                                                       RDP_PORT_REDIRECTION_SERIAL_EV_TXEMPTY) ==
           RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR);
    PCHECK(rdp_port_redirection_serial_wait_result(0, RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR) == 0);

    PCHECK(rdp_port_redirection_make_announce(&devices[0],
                                              RDP_PORT_REDIRECTION_SERIAL,
                                              0x100u,
                                              com1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_port_redirection_make_announce(&devices[1],
                                              RDP_PORT_REDIRECTION_PARALLEL,
                                              0x101u,
                                              lpt1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_port_redirection_write_device_list_announce(&buffer, devices, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_port_redirection_parse_device_list_announce(buffer.data, buffer.length, &list) ==
           LIBRDP_STATUS_OK);
    PCHECK(list.count == 2u &&
           list.devices[0].device_type == RDP_DEVICE_REDIRECTION_TYPE_SERIAL &&
           list.devices[1].device_type == RDP_DEVICE_REDIRECTION_TYPE_PARALLEL);
    devices[0].device_type = RDP_DEVICE_REDIRECTION_TYPE_PRINTER;
    PCHECK(rdp_port_redirection_write_device_list_announce(&buffer, devices, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_port_redirection_write_control_request(&buffer,
                                                      0x100u,
                                                      2u,
                                                      3u,
                                                      4u,
                                                      RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE,
                                                      input,
                                                      sizeof(input)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_port_redirection_parse_control_request(buffer.data, buffer.length, &control) ==
           LIBRDP_STATUS_OK);
    PCHECK(control.io.device_id == 0x100u &&
           control.io_control_code == RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE &&
           control.input_buffer_length == sizeof(input));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_port_redirection_write_control_request(&buffer,
                                                      0x100u,
                                                      2u,
                                                      3u,
                                                      4u,
                                                      0xffffffffu,
                                                      input,
                                                      sizeof(input)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_port_redirection_parse_control_request(buffer.data, buffer.length, &control) ==
           LIBRDP_STATUS_OK);
    PCHECK(control.io_control_code == 0xffffffffu && control.input_buffer_length == sizeof(input));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_port_redirection_write_control_response(&buffer,
                                                       0x100u,
                                                       3u,
                                                       RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                       input,
                                                       sizeof(input)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_completion(buffer.data, buffer.length, &completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(completion.device_id == 0x100u &&
           completion.completion_id == 3u &&
           completion.payload_len == sizeof(input) + 4u);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates camera capability, open, sample request, sample
 * response, and error paths for bounds and stream-state regressions.
 */
static int test_video_capture_channel(void)
{
    const uint8_t device_name[] = {'C', 0, 'a', 0, 'm', 0};
    const uint8_t sample_data[] = {0x00, 0x00, 0x01, 0x65};
    const uint8_t opaque_data[] = {0xaa, 0xbb, 0xcc};
    rdp_video_capture_header header;
    rdp_video_capture_device_notification notification;
    rdp_video_capture_error error;
    rdp_video_capture_stream_description stream = {
        RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR,
        RDP_VIDEO_CAPTURE_STREAM_CATEGORY_CAPTURE,
        1,
        1
    };
    rdp_video_capture_stream_list stream_list;
    rdp_video_capture_media_type media = {
        RDP_VIDEO_CAPTURE_MEDIA_NV12,
        1280,
        720,
        30,
        1,
        1,
        1,
        RDP_VIDEO_CAPTURE_MEDIA_FLAG_DECODING_REQUIRED
    };
    rdp_video_capture_media_type parsed_media;
    rdp_video_capture_media_list media_list;
    rdp_video_capture_stream_index index;
    rdp_video_capture_sample sample;
    rdp_video_capture_opaque opaque;
    rdp_video_capture_property_description property = {
        RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP,
        RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS,
        RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_MANUAL | RDP_VIDEO_CAPTURE_PROPERTY_CAPABILITY_AUTO,
        0,
        100,
        1,
        50
    };
    rdp_video_capture_property_list property_list;
    rdp_video_capture_property_request property_request;
    rdp_video_capture_property_value property_value = {
        RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL,
        42
    };
    rdp_video_capture_property_value parsed_property_value;
    uint8_t sample_error_index = 0;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(strcmp(RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME, "RDCamera_Device_Enumerator") == 0);
    PCHECK(strcmp(RDP_VIDEO_CAPTURE_CHANNEL_NAME, "rdpecam") == 0);
    PCHECK(rdp_video_capture_version_valid(RDP_VIDEO_CAPTURE_VERSION_1));
    PCHECK(rdp_video_capture_version_valid(RDP_VIDEO_CAPTURE_VERSION_2));
    PCHECK(!rdp_video_capture_version_valid(0));
    PCHECK(rdp_video_capture_message_valid(RDP_VIDEO_CAPTURE_VERSION_2,
                                           RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST));
    PCHECK(!rdp_video_capture_message_valid(RDP_VIDEO_CAPTURE_VERSION_1,
                                            RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST));

    PCHECK(rdp_video_capture_write_empty(&buffer,
                                         RDP_VIDEO_CAPTURE_VERSION_2,
                                         RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_empty(buffer.data,
                                         buffer.length,
                                         RDP_VIDEO_CAPTURE_MESSAGE_SELECT_VERSION_REQUEST,
                                         &header) == LIBRDP_STATUS_OK);
    PCHECK(header.version == RDP_VIDEO_CAPTURE_VERSION_2);
    buffer.data[1] = RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_LIST_REQUEST;
    PCHECK(rdp_video_capture_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    buffer.data[0] = RDP_VIDEO_CAPTURE_VERSION_1;
    PCHECK(rdp_video_capture_parse_header(buffer.data, buffer.length, &header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_device_added(&buffer,
                                                RDP_VIDEO_CAPTURE_VERSION_2,
                                                device_name,
                                                sizeof(device_name),
                                                "cam0") == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_device_added(buffer.data, buffer.length, &notification) ==
           LIBRDP_STATUS_OK);
    PCHECK(notification.device_name_len == sizeof(device_name) &&
           notification.channel_name_len == 4u &&
           memcmp(notification.channel_name, "cam0", 4u) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_device_removed(&buffer,
                                                  RDP_VIDEO_CAPTURE_VERSION_2,
                                                  "cam0") == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_device_removed(buffer.data, buffer.length, &notification) ==
           LIBRDP_STATUS_OK);
    PCHECK(notification.channel_name_len == 4u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_error(&buffer,
                                         RDP_VIDEO_CAPTURE_VERSION_2,
                                         RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_error(buffer.data, buffer.length, &error) == LIBRDP_STATUS_OK);
    PCHECK(error.error_code == RDP_VIDEO_CAPTURE_ERROR_INVALID_REQUEST);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_stream_list(&buffer, RDP_VIDEO_CAPTURE_VERSION_2, &stream, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_stream_list(buffer.data, buffer.length, &stream_list) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream_list.count == 1u &&
           stream_list.streams[0].frame_source_types == RDP_VIDEO_CAPTURE_STREAM_SOURCE_COLOR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_media_type(&buffer, &media) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == RDP_VIDEO_CAPTURE_MEDIA_TYPE_LENGTH);
    PCHECK(rdp_video_capture_parse_media_type(buffer.data, buffer.length, &parsed_media) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_media.width == 1280u && parsed_media.height == 720u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_media_list(&buffer,
                                              RDP_VIDEO_CAPTURE_VERSION_2,
                                              RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE,
                                              &media,
                                              1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_media_list(buffer.data,
                                              buffer.length,
                                              RDP_VIDEO_CAPTURE_MESSAGE_MEDIA_TYPE_LIST_RESPONSE,
                                              &media_list) == LIBRDP_STATUS_OK);
    PCHECK(media_list.count == 1u && media_list.media[0].format == RDP_VIDEO_CAPTURE_MEDIA_NV12);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_stream_index(&buffer,
                                                RDP_VIDEO_CAPTURE_VERSION_2,
                                                RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                                7) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_stream_index(buffer.data,
                                                buffer.length,
                                                RDP_VIDEO_CAPTURE_MESSAGE_SAMPLE_REQUEST,
                                                &index) == LIBRDP_STATUS_OK);
    PCHECK(index.stream_index == 7u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_sample(&buffer,
                                          RDP_VIDEO_CAPTURE_VERSION_2,
                                          1,
                                          sample_data,
                                          sizeof(sample_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_sample(buffer.data, buffer.length, &sample) == LIBRDP_STATUS_OK);
    PCHECK(sample.stream_index == 1u && sample.sample_len == sizeof(sample_data));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_sample_error(&buffer,
                                                RDP_VIDEO_CAPTURE_VERSION_2,
                                                1,
                                                RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_sample_error(buffer.data,
                                                buffer.length,
                                                &error,
                                                &sample_error_index) == LIBRDP_STATUS_OK);
    PCHECK(sample_error_index == 1u &&
           error.error_code == RDP_VIDEO_CAPTURE_ERROR_INVALID_STREAM_NUMBER);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_opaque(&buffer,
                                          RDP_VIDEO_CAPTURE_VERSION_2,
                                          RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE,
                                          opaque_data,
                                          sizeof(opaque_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_opaque(buffer.data,
                                          buffer.length,
                                          RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE,
                                          &opaque) == LIBRDP_STATUS_OK);
    PCHECK(opaque.payload_len == sizeof(opaque_data));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_property_list(&buffer,
                                                 RDP_VIDEO_CAPTURE_VERSION_2,
                                                 &property,
                                                 1u) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 2u + RDP_VIDEO_CAPTURE_PROPERTY_DESCRIPTION_LENGTH);
    PCHECK(rdp_video_capture_parse_property_list(buffer.data,
                                                 buffer.length,
                                                 &property_list) == LIBRDP_STATUS_OK);
    PCHECK(property_list.count == 1u &&
           property_list.properties[0].property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP &&
           property_list.properties[0].property_id == RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS &&
           property_list.properties[0].default_value == 50);
    buffer.data[4] = 0x80u;
    PCHECK(rdp_video_capture_parse_property_list(buffer.data,
                                                 buffer.length,
                                                 &property_list) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[4] = property.capabilities;
    PCHECK(rdp_video_capture_parse_property_list(buffer.data,
                                                 buffer.length - 1u,
                                                 &property_list) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_header(&buffer,
                                          RDP_VIDEO_CAPTURE_VERSION_2,
                                          RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_property_request(
               buffer.data,
               buffer.length,
               RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST,
               &property_request) == LIBRDP_STATUS_OK);
    PCHECK(property_request.property_set == RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP &&
           property_request.property_id == RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS);
    buffer.data[2] = 0xffu;
    PCHECK(rdp_video_capture_parse_property_request(
               buffer.data,
               buffer.length,
               RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_REQUEST,
               &property_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_property_value(&buffer,
                                                  RDP_VIDEO_CAPTURE_VERSION_2,
                                                  &property_value) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_opaque(buffer.data,
                                          buffer.length,
                                          RDP_VIDEO_CAPTURE_MESSAGE_PROPERTY_VALUE_RESPONSE,
                                          &opaque) == LIBRDP_STATUS_OK);
    PCHECK(opaque.payload_len == 5u);
    PCHECK(rdp_video_capture_parse_property_value(buffer.data + 2u,
                                                  buffer.length - 2u,
                                                  &parsed_property_value) == LIBRDP_STATUS_OK);
    PCHECK(parsed_property_value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_MANUAL &&
           parsed_property_value.value == 42);
    buffer.data[2] = 0xffu;
    PCHECK(rdp_video_capture_parse_property_value(buffer.data + 2u,
                                                  buffer.length - 2u,
                                                  &parsed_property_value) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_capture_write_header(&buffer,
                                          RDP_VIDEO_CAPTURE_VERSION_2,
                                          RDP_VIDEO_CAPTURE_MESSAGE_SET_PROPERTY_VALUE_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, RDP_VIDEO_CAPTURE_PROPERTY_SET_VIDEO_PROC_AMP) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, RDP_VIDEO_CAPTURE_PROPERTY_MODE_AUTO) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 50u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_capture_parse_set_property_request(buffer.data,
                                                        buffer.length,
                                                        &property_request,
                                                        &parsed_property_value) ==
           LIBRDP_STATUS_OK);
    PCHECK(property_request.property_id == RDP_VIDEO_CAPTURE_PROPERTY_ID_VIDEO_BRIGHTNESS &&
           parsed_property_value.mode == RDP_VIDEO_CAPTURE_PROPERTY_MODE_AUTO);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates WebAuthn CBOR/RPC request and response vectors,
 * including malformed length fields and provider boundary handling.
 */
static int test_webauthn_channel(void)
{
    const uint8_t command_payload[] = {RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL, 0xa0};
    const uint8_t response_payload[] = {0x01, 0x00, 0x00, 0x00};
    const uint8_t request_with_u64_cbor[] = {
        0xa2,
        0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
        0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, RDP_WEBAUTHN_COMMAND_API_VERSION,
        0x67, 'i', 'g', 'n', 'o', 'r', 'e', 'd',
        0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t request_with_indefinite_cbor[] = {
        0xbfu,
        0x67u, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
        RDP_WEBAUTHN_COMMAND_API_VERSION,
        0x67u, 'i', 'g', 'n', 'o', 'r', 'e', 'd',
        0x9fu,
        0x01u,
        0x5fu, 0x42u, 'a', 'b', 0x40u, 0xffu,
        0xffu,
        0xffu
    };
    const uint8_t request_with_tagged_cbor[] = {
        0xa2u,
        0x67u, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
        RDP_WEBAUTHN_COMMAND_API_VERSION,
        0x67u, 'i', 'g', 'n', 'o', 'r', 'e', 'd',
        0xc1u, 0x63u, 'a', 'b', 'c'
    };
    const uint8_t request_with_float_cbor[] = {
        0xa2u,
        0x67u, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
        RDP_WEBAUTHN_COMMAND_API_VERSION,
        0x67u, 'i', 'g', 'n', 'o', 'r', 'e', 'd',
        0xf9u, 0x3c, 0x00
    };
    const uint8_t unterminated_indefinite_cbor[] = {
        0xbfu,
        0x67u, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
        RDP_WEBAUTHN_COMMAND_API_VERSION
    };
    const uint8_t truncated_cbor[] = {0xa1, 0x63, 'k', 'e', 'y'};
    const uint8_t trailing_cbor[] = {0x01, 0x02};
    const uint8_t reserved_cbor[] = {0xfcu};
    uint8_t guid[RDP_WEBAUTHN_GUID_LENGTH] = {
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    const rdp_webauthn_device_info device_info = {
        "Hid",
        "Authenticator",
        "/dev/hidraw0",
        "Vendor",
        "Token",
        guid,
        sizeof(guid),
        4096,
        256,
        2,
        3,
        1,
        0,
        1,
        1
    };
    rdp_webauthn_request request;
    rdp_webauthn_response response;
    rdp_buffer buffer;
    uint32_t value = 0;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_command_valid(RDP_WEBAUTHN_COMMAND_WEB_AUTHN));
    PCHECK(!rdp_webauthn_command_valid(0xffffffffu));
    PCHECK(rdp_webauthn_flags_valid(RDP_WEBAUTHN_FLAG_UV_PREFERRED |
                                    RDP_WEBAUTHN_FLAG_HMAC_SECRET_EXTENSION));
    PCHECK(!rdp_webauthn_flags_valid(0x00000001u));

    PCHECK(rdp_webauthn_write_request(&buffer,
                                      RDP_WEBAUTHN_COMMAND_WEB_AUTHN,
                                      RDP_WEBAUTHN_FLAG_UV_PREFERRED,
                                      command_payload,
                                      sizeof(command_payload),
                                      "example.test",
                                      guid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_request(buffer.data, buffer.length, &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_WEBAUTHN_COMMAND_WEB_AUTHN &&
           request.has_flags == 1u &&
           request.flags == RDP_WEBAUTHN_FLAG_UV_PREFERRED &&
           request.request_len == sizeof(command_payload) &&
           request.request[0] == RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL &&
           request.rp_id_len == strlen("example.test") &&
           request.transaction_id_len == RDP_WEBAUTHN_GUID_LENGTH);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_request(&buffer,
                                      RDP_WEBAUTHN_COMMAND_CANCEL,
                                      0,
                                      guid,
                                      sizeof(guid),
                                      NULL,
                                      NULL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_request(buffer.data, buffer.length, &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_WEBAUTHN_COMMAND_CANCEL &&
           request.request_len == RDP_WEBAUTHN_GUID_LENGTH);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_parse_request(request_with_u64_cbor,
                                      sizeof(request_with_u64_cbor),
                                      &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_WEBAUTHN_COMMAND_API_VERSION);
    PCHECK(rdp_webauthn_validate_cbor(request_with_u64_cbor, sizeof(request_with_u64_cbor)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_request(request_with_indefinite_cbor,
                                      sizeof(request_with_indefinite_cbor),
                                      &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_WEBAUTHN_COMMAND_API_VERSION);
    PCHECK(rdp_webauthn_validate_cbor(request_with_indefinite_cbor,
                                      sizeof(request_with_indefinite_cbor)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_request(request_with_tagged_cbor,
                                      sizeof(request_with_tagged_cbor),
                                      &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_WEBAUTHN_COMMAND_API_VERSION);
    PCHECK(rdp_webauthn_validate_cbor(request_with_float_cbor,
                                      sizeof(request_with_float_cbor)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_request(unterminated_indefinite_cbor,
                                      sizeof(unterminated_indefinite_cbor),
                                      &request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_webauthn_validate_cbor(truncated_cbor, sizeof(truncated_cbor)) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_webauthn_validate_cbor(trailing_cbor, sizeof(trailing_cbor)) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_webauthn_validate_cbor(reserved_cbor, sizeof(reserved_cbor)) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_webauthn_write_response(&buffer, 0, response_payload, sizeof(response_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(response.hresult == 0 && response.payload_len == sizeof(response_payload));
    PCHECK(rdp_webauthn_parse_u32_response(&response, &value) == LIBRDP_STATUS_OK);
    PCHECK(value == 1u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_u32_response(&buffer, 0, 0x11223344u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_u32_response(&response, &value) == LIBRDP_STATUS_OK);
    PCHECK(value == 0x11223344u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_authenticator_response(&buffer,
                                                     0x80004005u,
                                                     0x01u,
                                                     response_payload,
                                                     sizeof(response_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(response.hresult == 0x80004005u && response.payload_len > sizeof(response_payload) &&
           response.payload[0] == 0xa3u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_authenticator_response_ex(&buffer,
                                                        0,
                                                        &device_info,
                                                        0,
                                                        response_payload,
                                                        sizeof(response_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(response.hresult == 0 &&
           response.payload_len > sizeof(response_payload) &&
           response.payload[0] == 0xa3u &&
           test_contains_bytes(response.payload, response.payload_len, "Hid", 3) &&
           test_contains_bytes(response.payload, response.payload_len, "/dev/hidraw0", 12) &&
           test_contains_bytes(response.payload, response.payload_len, "Token", 5));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_empty_array_response(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(response.hresult == 0 && response.payload_len == 1u && response.payload[0] == 0x80u);
    PCHECK(rdp_webauthn_validate_cbor(response.payload, response.payload_len) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_authenticator_list_response(&buffer,
                                                          0,
                                                          &device_info,
                                                          1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_webauthn_parse_response(buffer.data, buffer.length, &response) == LIBRDP_STATUS_OK);
    PCHECK(response.hresult == 0 &&
           response.payload_len > RDP_WEBAUTHN_GUID_LENGTH &&
           response.payload[0] == 0x81u &&
           response.payload[1] == 0xa5u &&
           test_contains_bytes(response.payload, response.payload_len, "/dev/hidraw0", 12) == 0 &&
           test_contains_bytes(response.payload, response.payload_len, "Token", 5));
    PCHECK(rdp_webauthn_validate_cbor(response.payload, response.payload_len) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_webauthn_write_request(&buffer,
                                      RDP_WEBAUTHN_COMMAND_WEB_AUTHN,
                                      0x00000001u,
                                      command_payload,
                                      sizeof(command_payload),
                                      NULL,
                                      NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates remote-application order parsing and writing, including
 * startup, window lifecycle, and shell command payload boundaries.
 */
static int test_remote_programs_channel(void)
{
    const uint8_t exe[] = {'n', 0, 'o', 0, 't', 0, 'e', 0, 'p', 0, 'a', 0, 'd', 0};
    const uint8_t args[] = {'/', 0, 'A', 0};
    const uint8_t opaque_payload[] = {0x11, 0x22, 0x33};
    rdp_remote_programs_header header;
    rdp_remote_programs_u32_order u32_order;
    rdp_remote_programs_handshake_ex handshake_ex;
    rdp_remote_programs_exec exec;
    rdp_remote_programs_exec_result exec_result;
    rdp_remote_programs_activate activate;
    rdp_remote_programs_sysmenu sysmenu;
    rdp_remote_programs_syscommand syscommand;
    rdp_remote_programs_notify_event notify_event;
    rdp_remote_programs_minmaxinfo minmaxinfo;
    rdp_remote_programs_localmovesize localmovesize;
    rdp_remote_programs_windowmove windowmove;
    rdp_remote_programs_opaque opaque;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_order_valid(RDP_REMOTE_PROGRAMS_ORDER_EXEC));
    PCHECK(!rdp_remote_programs_order_valid(0x7777u));
    PCHECK(rdp_remote_programs_exec_flags_valid(RDP_REMOTE_PROGRAMS_EXEC_FLAG_FILE |
                                                RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES));
    PCHECK(!rdp_remote_programs_exec_flags_valid(RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES));
    PCHECK(rdp_remote_programs_exec_result_valid(RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK));
    PCHECK(!rdp_remote_programs_exec_result_valid(0xffffu));
    PCHECK(rdp_remote_programs_write_header(&buffer,
                                            RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE,
                                            4u) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 4u);
    buffer.length = 0;
    PCHECK(rdp_remote_programs_write_header(&buffer,
                                            0xffffu,
                                            4u) == LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_remote_programs_write_u32_order(&buffer,
                                               RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE,
                                               22621u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.order_type == RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE && header.order_length == 8u);
    PCHECK(rdp_remote_programs_parse_u32_order(buffer.data,
                                               buffer.length,
                                               RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE,
                                               &u32_order) == LIBRDP_STATUS_OK);
    PCHECK(u32_order.value == 22621u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_u32_order(&buffer,
                                               RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS,
                                               RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ZORDER_SYNC |
                                                   RDP_REMOTE_PROGRAMS_CLIENTSTATUS_HIGH_DPI_ICONS) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_u32_order(buffer.data,
                                               buffer.length,
                                               RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS,
                                               &u32_order) == LIBRDP_STATUS_OK);
    PCHECK((u32_order.value & RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ZORDER_SYNC) != 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_handshake_ex(&buffer,
                                                  22621u,
                                                  RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF |
                                                      RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_TEXT_SCALE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_handshake_ex(buffer.data,
                                                  buffer.length,
                                                  &handshake_ex) == LIBRDP_STATUS_OK);
    PCHECK(handshake_ex.build_number == 22621u &&
           (handshake_ex.flags & RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF) != 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_exec(&buffer,
                                          RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS,
                                          exe,
                                          sizeof(exe),
                                          NULL,
                                          0,
                                          args,
                                          sizeof(args)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_exec(buffer.data, buffer.length, &exec) == LIBRDP_STATUS_OK);
    PCHECK(exec.exe_or_file_len == sizeof(exe) &&
           exec.arguments_len == sizeof(args) &&
           memcmp(exec.exe_or_file, exe, sizeof(exe)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_exec_result(&buffer,
                                                 RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS,
                                                 RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK,
                                                 0,
                                                 exe,
                                                 sizeof(exe)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_exec_result(buffer.data,
                                                 buffer.length,
                                                 &exec_result) == LIBRDP_STATUS_OK);
    PCHECK(exec_result.exec_result == RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK &&
           exec_result.exe_or_file_len == sizeof(exe));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_activate(&buffer, 0x11223344u, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_activate(buffer.data, buffer.length, &activate) ==
           LIBRDP_STATUS_OK);
    PCHECK(activate.window_id == 0x11223344u && activate.enabled == 1u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_sysmenu(&buffer, 0x01020304u, -10, 20) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_sysmenu(buffer.data, buffer.length, &sysmenu) ==
           LIBRDP_STATUS_OK);
    PCHECK(sysmenu.window_id == 0x01020304u && sysmenu.left == -10 && sysmenu.top == 20);
    PCHECK(rdp_remote_programs_parse_sysmenu(buffer.data, buffer.length - 1u, &sysmenu) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_syscommand(&buffer, 0x01020304u, 0xf060u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_syscommand(buffer.data, buffer.length, &syscommand) ==
           LIBRDP_STATUS_OK);
    PCHECK(syscommand.window_id == 0x01020304u && syscommand.command == 0xf060u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_notify_event(&buffer, 0x01020304u, 0xaabbccddu, 0x00000201u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_notify_event(buffer.data, buffer.length, &notify_event) ==
           LIBRDP_STATUS_OK);
    PCHECK(notify_event.window_id == 0x01020304u &&
           notify_event.notify_icon_id == 0xaabbccddu &&
           notify_event.message == 0x00000201u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&minmaxinfo, 0, sizeof(minmaxinfo));
    minmaxinfo.window_id = 0x01020304u;
    minmaxinfo.max_width = 1920;
    minmaxinfo.max_height = 1080;
    minmaxinfo.max_pos_x = -8;
    minmaxinfo.max_pos_y = -8;
    minmaxinfo.min_track_width = 120;
    minmaxinfo.min_track_height = 80;
    minmaxinfo.max_track_width = 3200;
    minmaxinfo.max_track_height = 2000;
    PCHECK(rdp_remote_programs_write_minmaxinfo(&buffer, &minmaxinfo) == LIBRDP_STATUS_OK);
    memset(&minmaxinfo, 0, sizeof(minmaxinfo));
    PCHECK(rdp_remote_programs_parse_minmaxinfo(buffer.data, buffer.length, &minmaxinfo) ==
           LIBRDP_STATUS_OK);
    PCHECK(minmaxinfo.window_id == 0x01020304u &&
           minmaxinfo.max_width == 1920 &&
           minmaxinfo.max_pos_x == -8 &&
           minmaxinfo.max_track_height == 2000);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&localmovesize, 0, sizeof(localmovesize));
    localmovesize.window_id = 0x01020304u;
    localmovesize.is_move_size_start = 1;
    localmovesize.move_size_type = 9;
    localmovesize.pos_x = -5;
    localmovesize.pos_y = 6;
    PCHECK(rdp_remote_programs_write_localmovesize(&buffer, &localmovesize) ==
           LIBRDP_STATUS_OK);
    memset(&localmovesize, 0, sizeof(localmovesize));
    PCHECK(rdp_remote_programs_parse_localmovesize(buffer.data, buffer.length, &localmovesize) ==
           LIBRDP_STATUS_OK);
    PCHECK(localmovesize.window_id == 0x01020304u &&
           localmovesize.is_move_size_start == 1 &&
           localmovesize.move_size_type == 9 &&
           localmovesize.pos_x == -5 &&
           localmovesize.pos_y == 6);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_windowmove(&buffer, 0x01020304u, -10, -20, 640, 480) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_windowmove(buffer.data, buffer.length, &windowmove) ==
           LIBRDP_STATUS_OK);
    PCHECK(windowmove.window_id == 0x01020304u &&
           windowmove.left == -10 &&
           windowmove.top == -20 &&
           windowmove.right == 640 &&
           windowmove.bottom == 480);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_write_opaque(&buffer,
                                            RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM,
                                            opaque_payload,
                                            sizeof(opaque_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_remote_programs_parse_opaque(buffer.data, buffer.length, &opaque) == LIBRDP_STATUS_OK);
    PCHECK(opaque.header.order_type == RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM &&
           opaque.payload_len == sizeof(opaque_payload));
    buffer.data[2] = 0xffu;
    PCHECK(rdp_remote_programs_parse_opaque(buffer.data, buffer.length, &opaque) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    return 0;
}

static librdp_status test_append_zeroes(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeroes[32] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    while (count > 0)
    {
        size_t chunk = count > sizeof(zeroes) ? sizeof(zeroes) : count;
        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status test_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)((value >> 32) & 0xffffffffu));
}

static librdp_status test_append_device_io_request(rdp_buffer* buffer,
                                                   uint32_t device_id,
                                                   uint32_t file_id,
                                                   uint32_t completion_id,
                                                   uint32_t major,
                                                   uint32_t minor)
{
    return rdp_device_redirection_write_io_request(buffer,
                                                   device_id,
                                                   file_id,
                                                   completion_id,
                                                   major,
                                                   minor,
                                                   NULL,
                                                   0);
}

/*
 * Coverage: validates TPKT and X.224 framing, negotiation, and malformed
 * header handling at the transport/protocol boundary.
 */
static int test_audio_channels(void)
{
    static const uint8_t pcm_format[] = {
        0x01, 0x00, 0x02, 0x00, 0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00,
        0x04, 0x00, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t bad_extensible[] = {
        0xfe, 0xff, 0x02, 0x00, 0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00,
        0x04, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00
    };
    static const uint8_t server_formats[] = {
        0x07, 0x2b, 0x26, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x28,
        0x06, 0x00,
        0x00,
        0x01, 0x00, 0x02, 0x00, 0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00,
        0x04, 0x00, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t training_pdu[] = {
        0x06, 0x23, 0x06, 0x00, 0x34, 0x12, 0x02, 0x00, 0xaa, 0xbb
    };
    static const uint8_t wave_info_pdu[] = {
        0x02, 0x7e, 0x14, 0x00, 0xd7, 0xad, 0x0f, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x20, 0x48, 0x17, 0xd6
    };
    static const uint8_t wave_data_pdu[] = {0x00, 0x00, 0x00, 0x00, 0x84, 0x02, 0x80};
    static const uint8_t wave2_pdu[] = {
        0x0d, 0x00, 0x0f, 0x00, 0x16, 0xa1, 0x03, 0x00, 0x02, 0x00,
        0x00, 0x00, 0xc2, 0xb8, 0xac, 0x0d, 0x27, 0x0c, 0x45
    };
    static const uint8_t crypt_key_pdu[] = {
        0x08, 0x11, 0x24, 0x00, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t wave_encrypt_pdu[] = {
        0x09, 0xe0, 0x13, 0x00, 0xb4, 0xd0, 0x2d, 0x00,
        0x24, 0x00, 0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3,
        0xa4, 0xa5, 0xa6, 0xa7, 0x55, 0x66, 0x77
    };
    static const uint8_t wave_encrypt_no_sig_pdu[] = {
        0x09, 0xe0, 0x0b, 0x00, 0xb4, 0xd0, 0x2d, 0x00,
        0x24, 0x00, 0x00, 0x00, 0x55, 0x66, 0x77
    };
    static const uint8_t udp_wave_pdu[] = {0x0a, 0x24, 0x81, 0x23, 0xde, 0xad};
    static const uint8_t udp_wave_last_pdu[] = {
        0x0b, 0x08, 0x20, 0xb9, 0x1a, 0x04, 0x00, 0x24,
        0x00, 0x00, 0x00, 0xbe, 0xef
    };
    static const uint8_t frag_data[] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xbe, 0xef
    };
    static const uint8_t input_extra[] = {0xde, 0xad, 0xfa, 0xce};
    rdp_audio_format pcm;
    rdp_audio_format alaw;
    rdp_audio_format mulaw;
    rdp_audio_format parsed_pcm;
    rdp_audio_format parsed_codec;
    rdp_audio_output_formats output_formats;
    rdp_audio_output_training training;
    rdp_audio_output_wave_info wave_info;
    rdp_audio_output_wave_data wave_data;
    rdp_audio_output_wave2 wave2;
    rdp_audio_output_crypt_key crypt_key;
    rdp_audio_output_wave_encrypt wave_encrypt;
    rdp_audio_output_udp_wave udp_wave;
    rdp_audio_output_udp_wave_last udp_wave_last;
    rdp_audio_output_frag_data parsed_frag;
    rdp_audio_output_setting setting;
    rdp_audio_input_formats input_formats;
    rdp_audio_input_open input_open;
    rdp_audio_input_data input_data;
    rdp_buffer out;
    uint16_t quality_mode = 0;
    uint16_t confirm_timestamp = 0;
    uint8_t confirm_block = 0;
    uint32_t version = 0;
    uint32_t result = 0;
    uint32_t new_format = 0;
    size_t consumed = 0;
    uint8_t invalid_audio_format[sizeof(pcm_format)];

    memset(&pcm, 0, sizeof(pcm));
    rdp_buffer_init(&out);

    PCHECK(rdp_audio_format_parse(pcm_format, sizeof(pcm_format), &pcm, &consumed) == LIBRDP_STATUS_OK);
    PCHECK(consumed == sizeof(pcm_format));
    PCHECK(rdp_audio_format_encoded_size(&pcm) == sizeof(pcm_format));
    PCHECK(rdp_audio_format_encoded_size(NULL) == 0);
    PCHECK(pcm.format_tag == RDP_AUDIO_FORMAT_PCM);
    PCHECK(pcm.channels == 2 && pcm.samples_per_sec == 44100 && pcm.avg_bytes_per_sec == 176400);
    PCHECK(pcm.block_align == 4 && pcm.bits_per_sample == 16 && pcm.extra_data_len == 0);
    PCHECK(rdp_audio_format_write(&out, &pcm) == LIBRDP_STATUS_OK);
    PCHECK(out.length == sizeof(pcm_format) && memcmp(out.data, pcm_format, sizeof(pcm_format)) == 0);
    memcpy(invalid_audio_format, pcm_format, sizeof(invalid_audio_format));
    invalid_audio_format[2] = 0;
    invalid_audio_format[3] = 0;
    PCHECK(rdp_audio_format_parse(invalid_audio_format,
                                  sizeof(invalid_audio_format),
                                  &parsed_pcm,
                                  &consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memcpy(invalid_audio_format, pcm_format, sizeof(invalid_audio_format));
    invalid_audio_format[12] = 0;
    invalid_audio_format[13] = 0;
    PCHECK(rdp_audio_format_parse(invalid_audio_format,
                                  sizeof(invalid_audio_format),
                                  &parsed_pcm,
                                  &consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
    parsed_pcm = pcm;
    parsed_pcm.channels = 0;
    PCHECK(rdp_audio_format_write(&out, &parsed_pcm) == LIBRDP_STATUS_INVALID_ARGUMENT);
    parsed_pcm = pcm;
    parsed_pcm.extra_data_len = 0x10000u;
    PCHECK(rdp_audio_format_encoded_size(&parsed_pcm) == 0);
    PCHECK(rdp_audio_format_parse(bad_extensible, sizeof(bad_extensible), &parsed_pcm, &consumed) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    memset(&alaw, 0, sizeof(alaw));
    alaw.format_tag = RDP_AUDIO_FORMAT_ALAW;
    alaw.channels = 1;
    alaw.samples_per_sec = 8000;
    alaw.avg_bytes_per_sec = 8000;
    alaw.block_align = 1;
    alaw.bits_per_sample = 8;
    memset(&mulaw, 0, sizeof(mulaw));
    mulaw.format_tag = RDP_AUDIO_FORMAT_MULAW;
    mulaw.channels = 2;
    mulaw.samples_per_sec = 16000;
    mulaw.avg_bytes_per_sec = 32000;
    mulaw.block_align = 2;
    mulaw.bits_per_sample = 8;
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_client_formats(&out,
                                                 RDP_AUDIO_OUTPUT_CAP_ALIVE,
                                                 0xffffffffu,
                                                 0x00010000u,
                                                 0x1234,
                                                 0,
                                                 6,
                                                 (rdp_audio_format[]){pcm, alaw, mulaw},
                                                 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_formats(out.data, out.length, &output_formats) == LIBRDP_STATUS_OK);
    PCHECK(output_formats.format_count == 3);
    PCHECK(output_formats.datagram_port == 0x1234);
    PCHECK(rdp_audio_format_get_from_list(output_formats.formats,
                                          output_formats.formats_len,
                                          output_formats.format_count,
                                          1,
                                          &parsed_codec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_format_wire_equal(&alaw, &parsed_codec));
    PCHECK(rdp_audio_format_get_from_list(output_formats.formats,
                                          output_formats.formats_len,
                                          output_formats.format_count,
                                          2,
                                          &parsed_codec) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_format_wire_equal(&mulaw, &parsed_codec));

    PCHECK(rdp_audio_output_parse_formats(server_formats, sizeof(server_formats), &output_formats) ==
           LIBRDP_STATUS_OK);
    PCHECK(output_formats.flags == 1 && output_formats.format_count == 1 && output_formats.version == 6);
    PCHECK(rdp_audio_format_get_from_list(output_formats.formats,
                                          output_formats.formats_len,
                                          output_formats.format_count,
                                          0,
                                          &parsed_pcm) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_format_wire_equal(&pcm, &parsed_pcm));
    PCHECK(rdp_audio_output_parse_formats(server_formats, sizeof(server_formats) - 1u, &output_formats) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_client_formats(&out,
                                                 RDP_AUDIO_OUTPUT_CAP_ALIVE | RDP_AUDIO_OUTPUT_CAP_VOLUME,
                                                 0xffffffffu,
                                                 0x00010000u,
                                                 0,
                                                 0x28,
                                                 6,
                                                 &pcm,
                                                 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_formats(out.data, out.length, &output_formats) == LIBRDP_STATUS_OK);
    PCHECK(output_formats.flags == (RDP_AUDIO_OUTPUT_CAP_ALIVE | RDP_AUDIO_OUTPUT_CAP_VOLUME));
    PCHECK(output_formats.format_count == 1 && output_formats.last_block_confirmed == 0x28);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_quality_mode(&out, RDP_AUDIO_OUTPUT_QUALITY_HIGH) == LIBRDP_STATUS_OK);
    PCHECK(out.length == 8 && out.data[0] == RDP_AUDIO_OUTPUT_QUALITYMODE && test_read_u16_le(out.data + 4) == 2);
    PCHECK(rdp_audio_output_parse_quality_mode(out.data, out.length, &quality_mode) == LIBRDP_STATUS_OK);
    PCHECK(quality_mode == RDP_AUDIO_OUTPUT_QUALITY_HIGH);
    out.data[4] = 3;
    out.data[5] = 0;
    PCHECK(rdp_audio_output_parse_quality_mode(out.data, out.length, &quality_mode) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_audio_output_write_quality_mode(&out, 3) == LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_audio_output_parse_training(training_pdu, sizeof(training_pdu), &training) == LIBRDP_STATUS_OK);
    PCHECK(training.timestamp == 0x1234 && training.packet_size == 2);
    PCHECK(training.data_len == 2 && training.data[0] == 0xaa && training.data[1] == 0xbb);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_training(&out,
                                           training.timestamp,
                                           training.data,
                                           (uint16_t)training.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_training(out.data, out.length, &training) == LIBRDP_STATUS_OK);
    PCHECK(training.timestamp == 0x1234 && training.packet_size == 2 && training.data[1] == 0xbb);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_training_confirm(&out, training.timestamp, training.packet_size) ==
           LIBRDP_STATUS_OK);
    PCHECK(out.length == 8 && out.data[0] == RDP_AUDIO_OUTPUT_TRAINING && test_read_u16_le(out.data + 4) == 0x1234);

    PCHECK(rdp_audio_output_parse_wave_info(wave_info_pdu, sizeof(wave_info_pdu), &wave_info) == LIBRDP_STATUS_OK);
    PCHECK(wave_info.timestamp == 0xadd7 && wave_info.format_no == 15 && wave_info.block_no == 8);
    PCHECK(wave_info.expected_data_len == 8 && wave_info.first_data_len == 4 && wave_info.first_data[0] == 0x20);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_info(&out,
                                            wave_info.timestamp,
                                            wave_info.format_no,
                                            wave_info.block_no,
                                            wave_info.first_data,
                                            wave_info.expected_data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_wave_info(out.data, out.length, &wave_info) == LIBRDP_STATUS_OK);
    PCHECK(wave_info.expected_data_len == 8 && wave_info.first_data[3] == 0xd6);
    PCHECK(rdp_audio_output_parse_wave_data(wave_data_pdu, sizeof(wave_data_pdu), &wave_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(wave_data.data_len == 3 && wave_data.data[0] == 0x84);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_data(&out, wave_data.data, wave_data.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_wave_data(out.data, out.length, &wave_data) == LIBRDP_STATUS_OK);
    PCHECK(wave_data.data_len == 3 && wave_data.data[2] == 0x80);
    PCHECK(rdp_audio_output_parse_wave2(wave2_pdu, sizeof(wave2_pdu), &wave2) == LIBRDP_STATUS_OK);
    PCHECK(wave2.timestamp == 0xa116 && wave2.format_no == 3 && wave2.block_no == 2);
    PCHECK(wave2.audio_timestamp == 0x0dacb8c2u && wave2.data_len == 3 && wave2.data[2] == 0x45);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave2(&out,
                                        wave2.timestamp,
                                        wave2.format_no,
                                        wave2.block_no,
                                        wave2.audio_timestamp,
                                        wave2.data,
                                        (uint16_t)wave2.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_wave2(out.data, out.length, &wave2) == LIBRDP_STATUS_OK);
    PCHECK(wave2.audio_timestamp == 0x0dacb8c2u && wave2.data_len == 3 && wave2.data[0] == 0x27);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_confirm(&out, 0x5ab7, 8) == LIBRDP_STATUS_OK);
    PCHECK(out.length == 8 && out.data[0] == RDP_AUDIO_OUTPUT_WAVECONFIRM &&
           test_read_u16_le(out.data + 4) == 0x5ab7 && out.data[6] == 8);
    PCHECK(rdp_audio_output_parse_wave_confirm(out.data, out.length, &confirm_timestamp, &confirm_block) ==
           LIBRDP_STATUS_OK);
    PCHECK(confirm_timestamp == 0x5ab7 && confirm_block == 8);

    PCHECK(rdp_audio_output_parse_crypt_key(crypt_key_pdu, sizeof(crypt_key_pdu), &crypt_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(crypt_key.reserved == 0x12345678u && crypt_key.seed_len == 32 && crypt_key.seed[31] == 0x1f);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_crypt_key(&out, crypt_key.reserved, crypt_key.seed) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_crypt_key(out.data, out.length, &crypt_key) == LIBRDP_STATUS_OK);
    PCHECK(crypt_key.seed_len == 32 && crypt_key.seed[0] == 0x00 && crypt_key.seed[31] == 0x1f);
    PCHECK(rdp_audio_output_parse_wave_encrypt(wave_encrypt_pdu,
                                               sizeof(wave_encrypt_pdu),
                                               1,
                                               &wave_encrypt) == LIBRDP_STATUS_OK);
    PCHECK(wave_encrypt.timestamp == 0xd0b4 && wave_encrypt.format_no == 0x2d &&
           wave_encrypt.block_no == 0x24 && wave_encrypt.signature_len == 8 &&
           wave_encrypt.signature[7] == 0xa7 && wave_encrypt.data_len == 3 && wave_encrypt.data[2] == 0x77);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_encrypt(&out,
                                               wave_encrypt.timestamp,
                                               wave_encrypt.format_no,
                                               wave_encrypt.block_no,
                                               wave_encrypt.signature,
                                               wave_encrypt.data,
                                               (uint16_t)wave_encrypt.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_wave_encrypt(out.data, out.length, 1, &wave_encrypt) == LIBRDP_STATUS_OK);
    PCHECK(wave_encrypt.signature_len == 8 && wave_encrypt.signature[3] == 0xa3 &&
           wave_encrypt.data_len == 3 && wave_encrypt.data[0] == 0x55);
    PCHECK(rdp_audio_output_parse_wave_encrypt(wave_encrypt_no_sig_pdu,
                                               sizeof(wave_encrypt_no_sig_pdu),
                                               0,
                                               &wave_encrypt) == LIBRDP_STATUS_OK);
    PCHECK(wave_encrypt.signature_len == 0 && wave_encrypt.data_len == 3 && wave_encrypt.data[0] == 0x55);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_encrypt(&out,
                                               wave_encrypt.timestamp,
                                               wave_encrypt.format_no,
                                               wave_encrypt.block_no,
                                               NULL,
                                               wave_encrypt.data,
                                               (uint16_t)wave_encrypt.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_wave_encrypt(out.data, out.length, 0, &wave_encrypt) == LIBRDP_STATUS_OK);
    PCHECK(wave_encrypt.signature_len == 0 && wave_encrypt.data_len == 3 && wave_encrypt.data[2] == 0x77);
    PCHECK(rdp_audio_output_parse_wave_encrypt(wave_encrypt_no_sig_pdu,
                                               sizeof(wave_encrypt_no_sig_pdu),
                                               1,
                                               &wave_encrypt) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_audio_output_parse_udp_wave(udp_wave_pdu, sizeof(udp_wave_pdu), &udp_wave) ==
           LIBRDP_STATUS_OK);
    PCHECK(udp_wave.block_no == 0x24 && udp_wave.fragment_no == 0x0123 &&
           udp_wave.fragment_no_size == 2 && udp_wave.data_len == 2 && udp_wave.data[1] == 0xad);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_udp_wave(&out,
                                           udp_wave.block_no,
                                           udp_wave.fragment_no,
                                           udp_wave.data,
                                           udp_wave.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_udp_wave(out.data, out.length, &udp_wave) == LIBRDP_STATUS_OK);
    PCHECK(udp_wave.fragment_no == 0x0123 && udp_wave.fragment_no_size == 2 && udp_wave.data[0] == 0xde);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_udp_wave(&out, 0x11, 0x12, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_udp_wave(out.data, out.length, &udp_wave) == LIBRDP_STATUS_OK);
    PCHECK(udp_wave.block_no == 0x11 && udp_wave.fragment_no == 0x12 &&
           udp_wave.fragment_no_size == 1 && udp_wave.data_len == 0);
    PCHECK(rdp_audio_output_write_udp_wave(&out, 0, 0x8000, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    out.data[0] = 0xff;
    PCHECK(rdp_audio_output_parse_udp_wave(out.data, out.length, &udp_wave) == LIBRDP_STATUS_PROTOCOL_ERROR);
    out.data[0] = RDP_AUDIO_OUTPUT_UDPWAVE;
    PCHECK(rdp_audio_output_parse_udp_wave_last(udp_wave_last_pdu,
                                                sizeof(udp_wave_last_pdu),
                                                &udp_wave_last) == LIBRDP_STATUS_OK);
    PCHECK(udp_wave_last.total_size == 0x2008 && udp_wave_last.timestamp == 0x1ab9 &&
           udp_wave_last.format_no == 4 && udp_wave_last.block_no == 0x24 &&
           udp_wave_last.data_len == 2 && udp_wave_last.data[0] == 0xbe);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_udp_wave_last(&out,
                                                udp_wave_last.total_size,
                                                udp_wave_last.timestamp,
                                                udp_wave_last.format_no,
                                                udp_wave_last.block_no,
                                                udp_wave_last.data,
                                                udp_wave_last.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_udp_wave_last(out.data, out.length, &udp_wave_last) ==
           LIBRDP_STATUS_OK);
    PCHECK(udp_wave_last.total_size == 0x2008 && udp_wave_last.data_len == 2 && udp_wave_last.data[1] == 0xef);
    out.data[0] = 0xff;
    PCHECK(rdp_audio_output_parse_udp_wave_last(out.data, out.length, &udp_wave_last) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    out.data[0] = RDP_AUDIO_OUTPUT_UDPWAVELAST;
    PCHECK(rdp_audio_output_parse_frag_data(frag_data, sizeof(frag_data), &parsed_frag) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_frag.signature_len == 8 && parsed_frag.signature[0] == 0xa0 &&
           parsed_frag.data_len == 2 && parsed_frag.data[1] == 0xef);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_frag_data(&out,
                                            parsed_frag.signature,
                                            parsed_frag.data,
                                            parsed_frag.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_frag_data(out.data, out.length, &parsed_frag) == LIBRDP_STATUS_OK);
    PCHECK(parsed_frag.signature[7] == 0xa7 && parsed_frag.data_len == 2 && parsed_frag.data[0] == 0xbe);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_setting(&out, RDP_AUDIO_OUTPUT_SETVOLUME, 0x11223344u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_setting(out.data,
                                          out.length,
                                          RDP_AUDIO_OUTPUT_SETVOLUME,
                                          &setting) == LIBRDP_STATUS_OK);
    PCHECK(setting.value == 0x11223344u);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_close(&out) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_close(out.data, out.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_write_wave_info(&out, 0, 0, 0, NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_version(&out, RDP_AUDIO_INPUT_VERSION_2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_version(out.data, out.length, &version) == LIBRDP_STATUS_OK);
    PCHECK(version == RDP_AUDIO_INPUT_VERSION_2);
    PCHECK(rdp_audio_input_parse_version("\x01\x03\x00\x00\x00", 5, &version) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_formats(&out, &pcm, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_formats(out.data, out.length, &input_formats) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_client_formats(out.data, out.length, &input_formats) == LIBRDP_STATUS_OK);
    PCHECK(input_formats.format_count == 1 && input_formats.formats_len == sizeof(pcm_format));
    PCHECK(input_formats.formats_packet_size == out.length && input_formats.extra_data_len == 0);
    out.data[5] ^= 1u;
    PCHECK(rdp_audio_input_parse_formats(out.data, out.length, &input_formats) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_client_formats(out.data, out.length, &input_formats) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    out.data[5] ^= 1u;
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_formats_with_extra(&out,
                                                    &pcm,
                                                    1,
                                                    input_extra,
                                                    sizeof(input_extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_client_formats(out.data, out.length, &input_formats) == LIBRDP_STATUS_OK);
    PCHECK(input_formats.formats_packet_size == out.length - sizeof(input_extra) &&
           input_formats.extra_data_len == sizeof(input_extra) &&
           memcmp(input_formats.extra_data, input_extra, sizeof(input_extra)) == 0);

    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_buffer_append_u8(&out, RDP_AUDIO_INPUT_OPEN) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&out, 128) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&out, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_format_write(&out, &pcm) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_open(out.data, out.length, &input_open) == LIBRDP_STATUS_OK);
    PCHECK(input_open.frames_per_packet == 128 && input_open.initial_format == 0);
    PCHECK(rdp_audio_format_wire_equal(&pcm, &input_open.format));
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_open(&out, 256, 1, &pcm) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_open(out.data, out.length, &input_open) == LIBRDP_STATUS_OK);
    PCHECK(input_open.frames_per_packet == 256 && input_open.initial_format == 1);
    PCHECK(rdp_audio_format_wire_equal(&pcm, &input_open.format));

    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_open_reply(&out, RDP_AUDIO_INPUT_RESULT_FAIL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_open_reply(out.data, out.length, &result) == LIBRDP_STATUS_OK);
    PCHECK(result == RDP_AUDIO_INPUT_RESULT_FAIL);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_incoming_data(&out) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_empty(out.data, out.length, RDP_AUDIO_INPUT_DATA_INCOMING) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_data(&out, "abc", 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_data(out.data, out.length, &input_data) == LIBRDP_STATUS_OK);
    PCHECK(input_data.data_len == 3 && memcmp(input_data.data, "abc", 3) == 0);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_input_write_format_change(&out, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_input_parse_format_change(out.data, out.length, &new_format) == LIBRDP_STATUS_OK);
    PCHECK(new_format == 1);

    rdp_buffer_free(&out);
    return 0;
}

/*
 * Coverage: validates path helpers, security packet vectors, licensing state
 * transitions, and many channel parsers against malformed lengths and
 * unsupported values.
 */
static int test_device_redirection_channel(void)
{
    const uint8_t server_announce[] = {
        0x72, 0x44, 0x6e, 0x49, 0x01, 0x00, 0x0d, 0x00, 0x44, 0x33, 0x22, 0x11
    };
    const uint8_t io_request_data[] = {
        0x72, 0x44, 0x52, 0x49, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05,
        0x0d, 0x0c, 0x0b, 0x0a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xaa, 0xbb
    };
    const uint8_t machine_utf16[] = {'T', 0, 'E', 0, 'S', 0, 'T', 0, 0, 0};
    const uint8_t drive_name_utf16[] = {'C', 0, 'l', 0, 'i', 0, 'e', 0, 'n', 0, 't', 0, 0, 0};
    rdp_device_redirection_header header;
    rdp_device_redirection_announce announce;
    rdp_device_redirection_announce confirm;
    rdp_device_redirection_client_name client_name;
    rdp_device_redirection_capability_config cap_config;
    rdp_device_redirection_capability_list caps;
    rdp_device_redirection_general_capability general;
    rdp_device_redirection_device_announce device;
    rdp_device_redirection_device_list device_list;
    rdp_device_redirection_device_remove remove;
    rdp_device_redirection_device_reply reply;
    rdp_device_redirection_io_request request;
    rdp_device_redirection_io_completion completion;
    rdp_device_redirection_capability bad_cap;
    rdp_buffer buffer;
    rdp_buffer packet;
    uint32_t remove_ids[2] = {0x10203040u, 0x50607080u};

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_device_redirection_parse_header(server_announce, sizeof(server_announce), &header) ==
           LIBRDP_STATUS_OK);
    PCHECK(header.component == RDP_DEVICE_REDIRECTION_COMPONENT_CORE);
    PCHECK(header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_ANNOUNCE);
    PCHECK(rdp_device_redirection_write_header(&buffer,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_device_redirection_parse_server_announce(server_announce,
                                                        sizeof(server_announce),
                                                        &announce) == LIBRDP_STATUS_OK);
    PCHECK(announce.version_major == RDP_DEVICE_REDIRECTION_VERSION_MAJOR);
    PCHECK(announce.version_minor == RDP_DEVICE_REDIRECTION_VERSION_MINOR_13);
    PCHECK(announce.client_id == 0x11223344u);
    PCHECK(rdp_device_redirection_parse_server_announce(server_announce,
                                                        sizeof(server_announce) - 1u,
                                                        &announce) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_device_redirection_write_server_announce(&buffer,
                                                        RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
                                                        announce.client_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_server_announce(buffer.data, buffer.length, &announce) ==
           LIBRDP_STATUS_OK);
    PCHECK(announce.client_id == 0x11223344u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_client_announce(&buffer,
                                                        RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
                                                        announce.client_id) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == sizeof(server_announce));
    PCHECK(buffer.data[2] == 0x43 && buffer.data[3] == 0x43);
    PCHECK(rdp_device_redirection_parse_client_id_confirm(buffer.data, buffer.length, &confirm) ==
           LIBRDP_STATUS_OK);
    PCHECK(confirm.client_id == announce.client_id);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_client_name_utf16le(&buffer,
                                                            machine_utf16,
                                                            (uint32_t)sizeof(machine_utf16)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_client_name(buffer.data, buffer.length, &client_name) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_name.unicode == 1 && client_name.code_page == 0);
    PCHECK(client_name.name_len == sizeof(machine_utf16));
    PCHECK(memcmp(client_name.name, machine_utf16, sizeof(machine_utf16)) == 0);
    buffer.data[4] = 2u;
    PCHECK(rdp_device_redirection_parse_client_name(buffer.data, buffer.length, &client_name) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[4] = 1u;
    buffer.data[buffer.length - 2u] = 'X';
    PCHECK(rdp_device_redirection_parse_client_name(buffer.data, buffer.length, &client_name) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_device_redirection_write_client_name_utf16le(&buffer, machine_utf16, 9) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_user_loggedon(&buffer) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.component == RDP_DEVICE_REDIRECTION_COMPONENT_CORE &&
           header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_USER_LOGGEDON);
    PCHECK(rdp_device_redirection_parse_user_loggedon(buffer.data, buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_user_loggedon(buffer.data, buffer.length - 1u) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_make_default_capability_config(&cap_config) == LIBRDP_STATUS_OK);
    cap_config.include_drive = 1;
    cap_config.include_smartcard = 1;
    PCHECK(rdp_device_redirection_write_client_capability_response(&buffer, &cap_config) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_capability_list(buffer.data,
                                                        buffer.length,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
                                                        &caps) == LIBRDP_STATUS_OK);
    PCHECK(caps.count == 3);
    PCHECK(caps.capabilities[0].type == RDP_DEVICE_REDIRECTION_CAP_GENERAL);
    PCHECK(caps.capabilities[0].length == 44);
    PCHECK(rdp_device_redirection_parse_general_capability(&caps.capabilities[0], &general) ==
           LIBRDP_STATUS_OK);
    PCHECK(general.protocol_minor_version == RDP_DEVICE_REDIRECTION_VERSION_MINOR_13);
    PCHECK((general.io_code1 & RDP_DEVICE_REDIRECTION_IRP_MASK_READ) != 0);
    PCHECK((general.io_code1 & RDP_DEVICE_REDIRECTION_IRP_MASK_QUERY_SECURITY) != 0);
    PCHECK((general.io_code1 & RDP_DEVICE_REDIRECTION_IRP_MASK_SET_SECURITY) != 0);
    PCHECK((general.extended_pdu & RDP_DEVICE_REDIRECTION_EXT_USER_LOGGEDON) != 0);
    PCHECK(caps.capabilities[1].type == RDP_DEVICE_REDIRECTION_CAP_DRIVE);
    PCHECK(caps.capabilities[1].version == RDP_DEVICE_REDIRECTION_CAP_VERSION_2);
    PCHECK(caps.capabilities[2].type == RDP_DEVICE_REDIRECTION_CAP_SMARTCARD);
    PCHECK(rdp_device_redirection_write_server_capability_request(
               &packet,
               &cap_config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_capability_list(
               packet.data,
               packet.length,
               RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
               &caps) == LIBRDP_STATUS_OK);
    PCHECK(caps.count == 3 &&
           caps.capabilities[0].type ==
               RDP_DEVICE_REDIRECTION_CAP_GENERAL &&
           caps.capabilities[1].type ==
               RDP_DEVICE_REDIRECTION_CAP_DRIVE &&
           caps.capabilities[2].type ==
               RDP_DEVICE_REDIRECTION_CAP_SMARTCARD);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_device_redirection_parse_capability_list(
               buffer.data,
               buffer.length,
               RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
               &caps) == LIBRDP_STATUS_OK);
    bad_cap = caps.capabilities[0];
    bad_cap.length = 43;
    PCHECK(rdp_device_redirection_parse_general_capability(&bad_cap, &general) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_device_redirection_write_general_capability(&packet, &general) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 44);
    caps.capabilities[0].type = test_read_u16_le(packet.data);
    caps.capabilities[0].length = test_read_u16_le(packet.data + 2);
    caps.capabilities[0].version = test_read_u32_le(packet.data + 4);
    caps.capabilities[0].data = packet.data + 8;
    caps.capabilities[0].data_len = packet.length - 8u;
    PCHECK(rdp_device_redirection_parse_general_capability(&caps.capabilities[0], &general) ==
           LIBRDP_STATUS_OK);
    PCHECK(general.version == RDP_DEVICE_REDIRECTION_CAP_VERSION_2 &&
           general.protocol_minor_version == RDP_DEVICE_REDIRECTION_VERSION_MINOR_13);
    general.version = RDP_DEVICE_REDIRECTION_CAP_VERSION_1;
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_device_redirection_write_general_capability(&packet, &general) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 40);
    caps.capabilities[0].type = test_read_u16_le(packet.data);
    caps.capabilities[0].length = test_read_u16_le(packet.data + 2);
    caps.capabilities[0].version = test_read_u32_le(packet.data + 4);
    caps.capabilities[0].data = packet.data + 8;
    caps.capabilities[0].data_len = packet.length - 8u;
    PCHECK(rdp_device_redirection_parse_general_capability(&caps.capabilities[0], &general) ==
           LIBRDP_STATUS_OK);
    PCHECK(general.version == RDP_DEVICE_REDIRECTION_CAP_VERSION_1);
    general.protocol_minor_version = 0xffffu;
    PCHECK(rdp_device_redirection_write_general_capability(&packet, &general) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_device_redirection_parse_capability_list(buffer.data,
                                                        buffer.length,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
                                                        &caps) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_write_capability_list(&packet,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
                                                        caps.capabilities,
                                                        caps.count) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_capability_list(packet.data,
                                                        packet.length,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
                                                        &caps) == LIBRDP_STATUS_OK);
    PCHECK(caps.count == 3 && caps.capabilities[0].type == RDP_DEVICE_REDIRECTION_CAP_GENERAL);
    PCHECK(rdp_device_redirection_write_capability_list(&packet,
                                                        RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY,
                                                        caps.capabilities,
                                                        caps.count) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&device, 0, sizeof(device));
    device.device_type = RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
    device.device_id = 7;
    memcpy(device.preferred_dos_name, "C:", 3);
    device.data = drive_name_utf16;
    device.data_len = sizeof(drive_name_utf16);
    PCHECK(rdp_device_redirection_write_device_list_announce(&buffer, &device, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_device_list_announce(buffer.data, buffer.length, &device_list) ==
           LIBRDP_STATUS_OK);
    PCHECK(device_list.count == 1);
    PCHECK(device_list.devices[0].device_type == RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM);
    PCHECK(device_list.devices[0].device_id == 7);
    PCHECK(memcmp(device_list.devices[0].preferred_dos_name, "C:", 3) == 0);
    PCHECK(device_list.devices[0].data_len == sizeof(drive_name_utf16));
    PCHECK(memcmp(device_list.devices[0].data, drive_name_utf16, sizeof(drive_name_utf16)) == 0);
    buffer.data[8] = 0xffu;
    PCHECK(rdp_device_redirection_parse_device_list_announce(buffer.data, buffer.length, &device_list) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[8] = RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
    buffer.data[17] = '/';
    PCHECK(rdp_device_redirection_parse_device_list_announce(buffer.data, buffer.length, &device_list) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[17] = ':';
    device.preferred_dos_name[0] = 'B';
    device.preferred_dos_name[1] = '/';
    device.preferred_dos_name[2] = 0;
    PCHECK(rdp_device_redirection_write_device_list_announce(&buffer, &device, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_device_redirection_write_device_list_announce(&buffer, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_device_list_announce(buffer.data, buffer.length, &device_list) ==
           LIBRDP_STATUS_OK);
    PCHECK(device_list.count == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_device_remove(&buffer, remove_ids, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_device_remove(buffer.data, buffer.length, &remove) ==
           LIBRDP_STATUS_OK);
    PCHECK(remove.count == 2 && remove.device_ids[0] == remove_ids[0] && remove.device_ids[1] == remove_ids[1]);
    PCHECK(rdp_device_redirection_parse_device_remove(buffer.data, buffer.length - 1u, &remove) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_device_reply(&buffer,
                                                     7,
                                                     RDP_DEVICE_REDIRECTION_STATUS_SUCCESS) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_device_reply(buffer.data, buffer.length, &reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(reply.device_id == 7 && reply.result_code == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_parse_io_request(io_request_data, sizeof(io_request_data), &request) ==
           LIBRDP_STATUS_OK);
    PCHECK(request.device_id == 0x01020304u);
    PCHECK(request.file_id == 0x05060708u);
    PCHECK(request.completion_id == 0x0a0b0c0du);
    PCHECK(request.major_function == RDP_DEVICE_REDIRECTION_IRP_READ);
    PCHECK(request.payload_len == 2 && request.payload[0] == 0xaa && request.payload[1] == 0xbb);
    PCHECK(rdp_device_redirection_parse_io_request(io_request_data, 23, &request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   request.device_id,
                                                   request.file_id,
                                                   request.completion_id,
                                                   request.major_function,
                                                   request.minor_function,
                                                   request.payload,
                                                   request.payload_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    PCHECK(request.payload_len == 2 && request.payload[1] == 0xbb);
    buffer.data[16] = 0xffu;
    buffer.data[17] = 0xffu;
    buffer.data[18] = 0xffu;
    buffer.data[19] = 0xffu;
    PCHECK(rdp_device_redirection_parse_io_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   7,
                                                   8,
                                                   9,
                                                   RDP_DEVICE_REDIRECTION_IRP_CLEANUP,
                                                   0,
                                                   NULL,
                                                   0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    PCHECK(request.device_id == 7 &&
           request.file_id == 8 &&
           request.completion_id == 9 &&
           request.major_function == RDP_DEVICE_REDIRECTION_IRP_CLEANUP &&
           request.payload_len == 0);
    buffer.length = 0;
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   7,
                                                   8,
                                                   10,
                                                   RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS,
                                                   0,
                                                   NULL,
                                                   0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    PCHECK(request.major_function == RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS &&
           request.completion_id == 10);
    buffer.length = 0;
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   7,
                                                   0,
                                                   11,
                                                   RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN,
                                                   0,
                                                   NULL,
                                                   0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_request(buffer.data, buffer.length, &request) ==
           LIBRDP_STATUS_OK);
    PCHECK(request.major_function == RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN &&
           request.file_id == 0 &&
           request.completion_id == 11);
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   1,
                                                   2,
                                                   3,
                                                   0xffffffffu,
                                                   0,
                                                   NULL,
                                                   0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_device_redirection_write_io_request(&buffer,
                                                   1,
                                                   2,
                                                   3,
                                                   RDP_DEVICE_REDIRECTION_IRP_READ,
                                                   0,
                                                   NULL,
                                                   1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_device_redirection_write_io_completion(&buffer,
                                                      request.device_id,
                                                      request.completion_id,
                                                      RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                      io_request_data + 24u,
                                                      2u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_completion(buffer.data, buffer.length, &completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(completion.device_id == request.device_id);
    PCHECK(completion.completion_id == request.completion_id);
    PCHECK(completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    PCHECK(completion.payload_len == 2 && completion.payload[0] == 0xaa && completion.payload[1] == 0xbb);

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    return 0;
}

/*
 * Coverage: validates filesystem metadata, directory, lock, notify, and
 * security request vectors with host-independent malformed payload checks.
 */
static int test_filesystem_redirection_channel(void)
{
    const uint8_t path[] = {'f', 0, 'i', 0, 'l', 0, 'e', 0, 0, 0};
    const uint8_t data[] = {'a', 'b', 'c'};
    const rdp_filesystem_redirection_lock_info locks[2] = {{10u, 20u}, {30u, 40u}};
    rdp_filesystem_redirection_create_request create_request;
    rdp_device_redirection_io_request close_request;
    rdp_filesystem_redirection_read_request read_request;
    rdp_filesystem_redirection_write_request write_request;
    rdp_filesystem_redirection_control_request control_request;
    rdp_filesystem_redirection_information_request information_request;
    rdp_filesystem_redirection_query_directory_request directory_request;
    rdp_filesystem_redirection_notify_change_request notify_request;
    rdp_filesystem_redirection_lock_request lock_request;
    rdp_filesystem_redirection_security_request security_request;
    rdp_filesystem_redirection_create_response create_response;
    rdp_filesystem_redirection_length_response length_response;
    rdp_device_redirection_io_completion completion_response;
    rdp_device_redirection_io_completion security_descriptor_response;
    rdp_buffer request;
    rdp_buffer response;

    rdp_buffer_init(&request);
    rdp_buffer_init(&response);

    PCHECK(rdp_filesystem_redirection_write_create_request(&request,
                                                           0x11111111u,
                                                           0x22222222u,
                                                           0x33333333u,
                                                           0x0012019fu,
                                                           0x0102030405060708ull,
                                                           0x00000080u,
                                                           0x00000003u,
                                                           0x00000001u,
                                                           0x00000020u,
                                                           path,
                                                           sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_create_request(request.data,
                                                           request.length,
                                                           &create_request) == LIBRDP_STATUS_OK);
    PCHECK(create_request.io.completion_id == 0x33333333u &&
           create_request.path_len == sizeof(path));
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_create_request(&request,
                                                           1,
                                                           2,
                                                           3,
                                                           0,
                                                           0,
                                                           0,
                                                           0,
                                                           0,
                                                           0,
                                                           path,
                                                           sizeof(path) - 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_filesystem_redirection_write_close_request(&request, 1, 2, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_close_request(request.data,
                                                          request.length,
                                                          &close_request) == LIBRDP_STATUS_OK);
    PCHECK(close_request.file_id == 2 && close_request.completion_id == 3);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_read_request(&request,
                                                         1,
                                                         2,
                                                         3,
                                                         4096u,
                                                         0x1122334455667788ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_read_request(request.data,
                                                         request.length,
                                                         &read_request) == LIBRDP_STATUS_OK);
    PCHECK(read_request.length == 4096u && read_request.offset == 0x1122334455667788ull);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_write_request(&request,
                                                          1,
                                                          2,
                                                          3,
                                                          0xffffffffffffffffull,
                                                          data,
                                                          sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_write_request(request.data,
                                                          request.length,
                                                          &write_request) == LIBRDP_STATUS_OK);
    PCHECK(write_request.length == sizeof(data) && write_request.data[2] == 'c');
    PCHECK(rdp_filesystem_redirection_write_write_request(&response,
                                                          1,
                                                          2,
                                                          3,
                                                          0,
                                                          NULL,
                                                          1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_control_request(&request,
                                                            1,
                                                            2,
                                                            3,
                                                            16u,
                                                            0x000900c0u,
                                                            data,
                                                            sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_control_request(request.data,
                                                            request.length,
                                                            &control_request) == LIBRDP_STATUS_OK);
    PCHECK(control_request.output_buffer_length == 16u &&
           control_request.input_buffer_length == sizeof(data));
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_information_request(
               &request,
               1,
               2,
               3,
               RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
               5u,
               data,
               sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_information_request(request.data,
                                                                      request.length,
                                                                      &information_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(information_request.information_class == 5u &&
           information_request.length == sizeof(data));
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_information_request(
               &request,
               1,
               2,
               3,
               RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
               18u,
               NULL,
               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_information_request(request.data,
                                                                      request.length,
                                                                      &information_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(information_request.information_class == 18u &&
           information_request.length == 0);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_information_request(
               &request,
               1,
               2,
               3,
               RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION,
               39u,
               data,
               sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_set_information_request(request.data,
                                                                    request.length,
                                                                    &information_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(information_request.information_class == 39u &&
           information_request.length == sizeof(data) &&
           memcmp(information_request.buffer, data, sizeof(data)) == 0);
    PCHECK(rdp_filesystem_redirection_write_information_request(&response,
                                                               1,
                                                               2,
                                                               3,
                                                               RDP_DEVICE_REDIRECTION_IRP_READ,
                                                               0,
                                                               NULL,
                                                               0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_query_directory_request(&request,
                                                                    1,
                                                                    2,
                                                                    3,
                                                                    1u,
                                                                    1u,
                                                                    path,
                                                                    sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_directory_request(request.data,
                                                                    request.length,
                                                                    &directory_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(directory_request.path_len == sizeof(path));
    request.data[28] = 2u;
    PCHECK(rdp_filesystem_redirection_parse_query_directory_request(request.data,
                                                                    request.length,
                                                                    &directory_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_notify_change_request(&request,
                                                                  1,
                                                                  2,
                                                                  3,
                                                                  1u,
                                                                  RDP_FILESYSTEM_REDIRECTION_NOTIFY_FILE_NAME |
                                                                      RDP_FILESYSTEM_REDIRECTION_NOTIFY_LAST_WRITE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) == LIBRDP_STATUS_OK);
    PCHECK(notify_request.watch_tree == 1u);
    PCHECK(notify_request.completion_filter ==
           (RDP_FILESYSTEM_REDIRECTION_NOTIFY_FILE_NAME |
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_LAST_WRITE));
    request.data[24] = 2u;
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[24] = 1u;
    request.data[25] = 0u;
    request.data[26] = 0u;
    request.data[27] = 0u;
    request.data[28] = 0u;
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_filesystem_redirection_write_notify_change_request(&response,
                                                                  1,
                                                                  2,
                                                                  3,
                                                                  1u,
                                                                  0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_filesystem_redirection_write_notify_change_request(&response,
                                                                  1,
                                                                  2,
                                                                  3,
                                                                  1u,
                                                                  0x10000000u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_lock_request(&request,
                                                         1,
                                                         2,
                                                         3,
                                                         RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK,
                                                         1u,
                                                         locks,
                                                         2u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_lock_request(request.data,
                                                         request.length,
                                                         &lock_request) == LIBRDP_STATUS_OK);
    PCHECK(lock_request.lock_count == 2u && lock_request.locks[1].offset == 40u);
    memset(request.data + 56u, 0, 8u);
    PCHECK(rdp_filesystem_redirection_parse_lock_request(request.data,
                                                         request.length,
                                                         &lock_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[56] = 10u;
    request.data[64] = 0xffu;
    request.data[65] = 0xffu;
    request.data[66] = 0xffu;
    request.data[67] = 0xffu;
    request.data[68] = 0xffu;
    request.data[69] = 0xffu;
    request.data[70] = 0xffu;
    request.data[71] = 0xffu;
    PCHECK(rdp_filesystem_redirection_parse_lock_request(request.data,
                                                         request.length,
                                                         &lock_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[64] = 20u;
    request.data[65] = 0u;
    request.data[66] = 0u;
    request.data[67] = 0u;
    request.data[68] = 0u;
    request.data[69] = 0u;
    request.data[70] = 0u;
    request.data[71] = 0u;
    {
        const rdp_filesystem_redirection_lock_info invalid_locks[2] = {
            {0u, 20u},
            {10u, UINT64_MAX}
        };

        PCHECK(rdp_filesystem_redirection_write_lock_request(&response,
                                                             1,
                                                             2,
                                                             3,
                                                             RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK,
                                                             0,
                                                             invalid_locks,
                                                             1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
        PCHECK(rdp_filesystem_redirection_write_lock_request(&response,
                                                             1,
                                                             2,
                                                             3,
                                                             RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK,
                                                             0,
                                                             invalid_locks + 1,
                                                             1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    PCHECK(rdp_filesystem_redirection_write_lock_request(&response,
                                                         1,
                                                         2,
                                                         3,
                                                         0xffu,
                                                         0,
                                                         NULL,
                                                         0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_security_request(&request,
                                                             1,
                                                             2,
                                                             3,
                                                             RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY,
                                                             0x07u,
                                                             NULL,
                                                             128u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_security_request(request.data,
                                                                   request.length,
                                                                   &security_request) == LIBRDP_STATUS_OK);
    PCHECK(security_request.io.major_function == RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY &&
           security_request.security_information == 0x07u &&
           security_request.length == 128u &&
           security_request.buffer == NULL);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_security_request(&request,
                                                             1,
                                                             2,
                                                             3,
                                                             RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY,
                                                             0x04u,
                                                             data,
                                                             sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_set_security_request(request.data,
                                                                 request.length,
                                                                 &security_request) == LIBRDP_STATUS_OK);
    PCHECK(security_request.io.major_function == RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY &&
           security_request.security_information == 0x04u &&
           security_request.length == sizeof(data) &&
           memcmp(security_request.buffer, data, sizeof(data)) == 0);
    PCHECK(rdp_filesystem_redirection_write_security_request(&response,
                                                             1,
                                                             2,
                                                             3,
                                                             RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
                                                             0,
                                                             NULL,
                                                             0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);

    PCHECK(rdp_filesystem_redirection_write_posix_security_descriptor(
               &response,
               RDP_FILESYSTEM_REDIRECTION_SUPPORTED_SECURITY_INFORMATION,
               1000u,
               100u,
               0640u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 136u);
    PCHECK(response.data[0] == 1u);
    PCHECK(test_read_u16_le(response.data + 2u) == 0x8014u);
    PCHECK(test_read_u32_le(response.data + 4u) == 20u);
    PCHECK(test_read_u32_le(response.data + 8u) == 36u);
    PCHECK(test_read_u32_le(response.data + 12u) == 128u);
    PCHECK(test_read_u32_le(response.data + 16u) == 52u);
    PCHECK(response.data[20] == 1u && response.data[21] == 2u);
    PCHECK(test_read_u32_le(response.data + 28u) == 1u);
    PCHECK(test_read_u32_le(response.data + 32u) == 1000u);
    PCHECK(response.data[36] == 1u && response.data[37] == 2u);
    PCHECK(test_read_u32_le(response.data + 44u) == 2u);
    PCHECK(test_read_u32_le(response.data + 48u) == 100u);
    PCHECK(response.data[52] == 2u);
    PCHECK(test_read_u16_le(response.data + 54u) == 76u);
    PCHECK(test_read_u16_le(response.data + 56u) == 3u);
    PCHECK(test_read_u32_le(response.data + 64u) == 0x0012019fu);
    PCHECK(test_read_u32_le(response.data + 88u) == 0x00120089u);
    PCHECK(test_read_u32_le(response.data + 112u) == 0u);
    PCHECK(response.data[116] == 1u && response.data[117] == 1u);
    PCHECK(test_read_u32_le(response.data + 124u) == 0u);
    PCHECK(response.data[128] == 2u);
    PCHECK(test_read_u16_le(response.data + 130u) == 8u);
    PCHECK(test_read_u16_le(response.data + 132u) == 0u);
    {
        rdp_filesystem_redirection_posix_security parsed_security;

        PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                   response.data,
                   response.length,
                   RDP_FILESYSTEM_REDIRECTION_SUPPORTED_SECURITY_INFORMATION,
                   &parsed_security) == LIBRDP_STATUS_OK);
        PCHECK(parsed_security.owner_present == 1u && parsed_security.owner_id == 1000u);
        PCHECK(parsed_security.group_present == 1u && parsed_security.group_id == 100u);
        PCHECK(parsed_security.mode_present == 1u && parsed_security.mode == 0640u);
        {
            uint8_t saved_group_sid[16];

            memcpy(saved_group_sid, response.data + 92u, sizeof(saved_group_sid));
            response.data[94] = 0u;
            response.data[95] = 0u;
            response.data[96] = 0u;
            response.data[97] = 0u;
            response.data[98] = 0u;
            response.data[99] = 5u;
            response.data[100] = 32u;
            response.data[101] = 0u;
            response.data[102] = 0u;
            response.data[103] = 0u;
            response.data[104] = 0x21u;
            response.data[105] = 0x02u;
            response.data[106] = 0u;
            response.data[107] = 0u;
            PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                       response.data,
                       response.length,
                       RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                       &parsed_security) == LIBRDP_STATUS_OK);
            PCHECK(parsed_security.mode_present == 1u && parsed_security.mode == 0640u);
            response.data[84] = 1u;
            PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                       response.data,
                       response.length,
                       RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                       &parsed_security) == LIBRDP_STATUS_OK);
            PCHECK(parsed_security.mode_present == 1u && parsed_security.mode == 0600u);
            response.data[84] = 0u;
            memcpy(response.data + 92u, saved_group_sid, sizeof(saved_group_sid));
        }
        response.data[4] = 0u;
        response.data[5] = 0u;
        response.data[6] = 0u;
        response.data[7] = 0u;
        PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                   response.data,
                   response.length,
                   RDP_FILESYSTEM_REDIRECTION_OWNER_SECURITY_INFORMATION,
                   &parsed_security) == LIBRDP_STATUS_OK);
        PCHECK(parsed_security.owner_present == 0u);
        response.data[4] = 20u;
        response.data[8] = 0u;
        response.data[9] = 0u;
        response.data[10] = 0u;
        response.data[11] = 0u;
        PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                   response.data,
                   response.length,
                   RDP_FILESYSTEM_REDIRECTION_GROUP_SECURITY_INFORMATION,
                   &parsed_security) == LIBRDP_STATUS_OK);
        PCHECK(parsed_security.group_present == 0u);
        response.data[8] = 36u;
        PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(response.data,
                                                                          19u,
                                                                          RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                                                                          &parsed_security) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        response.data[60] = 2u;
        response.data[84] = 2u;
        response.data[108] = 2u;
        PCHECK(rdp_filesystem_redirection_parse_posix_security_descriptor(
                   response.data,
                   response.length,
                   RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                   &parsed_security) == LIBRDP_STATUS_OK);
        PCHECK(parsed_security.mode_present == 0u);
        response.data[60] = 0u;
        response.data[84] = 0u;
        response.data[108] = 0u;
    }
    PCHECK(rdp_filesystem_redirection_write_buffer_response(&request,
                                                            1u,
                                                            3u,
                                                            RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                            response.data,
                                                            (uint32_t)response.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_completion(request.data,
                                                      request.length,
                                                      &security_descriptor_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(security_descriptor_response.payload_len == response.length + 4u);
    PCHECK(test_read_u32_le(security_descriptor_response.payload) == response.length);
    PCHECK(memcmp(security_descriptor_response.payload + 4u, response.data, response.length) == 0);
    rdp_buffer_free(&request);
    rdp_buffer_free(&response);
    rdp_buffer_init(&request);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_posix_security_descriptor(
               &response,
               0x00000008u,
               1000u,
               100u,
               0644u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 28u);
    PCHECK(test_read_u16_le(response.data + 2u) == 0x8010u);
    PCHECK(test_read_u32_le(response.data + 12u) == 20u);
    PCHECK(response.data[20] == 2u);
    PCHECK(test_read_u16_le(response.data + 22u) == 8u);
    PCHECK(test_read_u16_le(response.data + 24u) == 0u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);

    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_VOLUME_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0x0102030405060708ull,
                                                               0x11223344u,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               512u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 29u);
    PCHECK(test_read_u32_le(response.data) == 25u);
    PCHECK(test_read_u64_le(response.data + 4u) == 0x0102030405060708ull);
    PCHECK(test_read_u32_le(response.data + 12u) == 0x11223344u);
    PCHECK(test_read_u32_le(response.data + 16u) == 8u);
    PCHECK(response.data[20] == 0u && response.data[21] == 'V' && response.data[22] == 0u &&
           response.data[23] == 'O' && response.data[24] == 0u && response.data[25] == 'L');
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_LABEL_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               0,
                                                               0,
                                                               1u,
                                                               512u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 16u);
    PCHECK(test_read_u32_le(response.data) == 12u && test_read_u32_le(response.data + 4u) == 8u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_CONTROL_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               512u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 52u && test_read_u32_le(response.data) == 48u);
    PCHECK(test_read_u64_le(response.data + 4u) == 0u &&
           test_read_u32_le(response.data + 48u) == 0u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_OBJECT_ID_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0x11223344u,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               512u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 68u);
    PCHECK(test_read_u32_le(response.data) == 64u);
    PCHECK(test_read_u32_le(response.data + 4u) == 0x11223344u);
    PCHECK(test_read_u32_le(response.data + 8u) == 1000u);
    PCHECK(test_read_u32_le(response.data + 12u) == 400u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_VOLUME_FLAGS_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               512u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 8u && test_read_u32_le(response.data) == 4u &&
           test_read_u32_le(response.data + 4u) == 0u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_SECTOR_SIZE_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               4096u) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 32u);
    PCHECK(test_read_u32_le(response.data) == 28u &&
           test_read_u32_le(response.data + 4u) == 4096u &&
           test_read_u32_le(response.data + 16u) == 4096u &&
           test_read_u32_le(response.data + 20u) == 0u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               0xffu,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               1000u,
                                                               400u,
                                                               8u,
                                                               512u) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_filesystem_redirection_write_volume_information(&response,
                                                               RDP_FILESYSTEM_REDIRECTION_FS_SIZE_INFORMATION,
                                                               "VOL",
                                                               "POSIX",
                                                               0,
                                                               0,
                                                               1000u,
                                                               400u,
                                                               0,
                                                               512u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);

    PCHECK(test_append_device_io_request(&request,
                                         0x11111111u,
                                         0x22222222u,
                                         0x33333333u,
                                         RDP_DEVICE_REDIRECTION_IRP_CREATE,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x0012019fu) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 0x0102030405060708ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x00000080u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x00000003u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x00000001u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x00000020u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, (uint32_t)sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&request, path, sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_create_request(request.data,
                                                           request.length,
                                                           &create_request) == LIBRDP_STATUS_OK);
    PCHECK(create_request.io.device_id == 0x11111111u);
    PCHECK(create_request.io.file_id == 0x22222222u);
    PCHECK(create_request.desired_access == 0x0012019fu);
    PCHECK(create_request.allocation_size == 0x0102030405060708ull);
    PCHECK(create_request.path_len == sizeof(path));
    PCHECK(memcmp(create_request.path, path, sizeof(path)) == 0);
    PCHECK(rdp_filesystem_redirection_parse_create_request(request.data,
                                                           request.length - 1u,
                                                           &create_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_CLOSE,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 32u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_close_request(request.data,
                                                          request.length,
                                                          &close_request) == LIBRDP_STATUS_OK);
    PCHECK(close_request.file_id == 2 && close_request.completion_id == 3);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request, 1, 2, 3, RDP_DEVICE_REDIRECTION_IRP_READ, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 4096u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 0x1122334455667788ull) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 20u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_read_request(request.data,
                                                         request.length,
                                                         &read_request) == LIBRDP_STATUS_OK);
    PCHECK(read_request.length == 4096u && read_request.offset == 0x1122334455667788ull);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request, 1, 2, 3, RDP_DEVICE_REDIRECTION_IRP_WRITE, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, (uint32_t)sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 0xffffffffffffffffull) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 20u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&request, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_write_request(request.data,
                                                          request.length,
                                                          &write_request) == LIBRDP_STATUS_OK);
    PCHECK(write_request.length == sizeof(data) && write_request.offset == 0xffffffffffffffffull);
    PCHECK(memcmp(write_request.data, data, sizeof(data)) == 0);
    request.data[24] = 4;
    PCHECK(rdp_filesystem_redirection_parse_write_request(request.data,
                                                          request.length,
                                                          &write_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[24] = (uint8_t)sizeof(data);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, (uint32_t)sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x000900c0u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 20u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&request, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_control_request(request.data,
                                                            request.length,
                                                            &control_request) == LIBRDP_STATUS_OK);
    PCHECK(control_request.output_buffer_length == 16u);
    PCHECK(control_request.input_buffer_length == sizeof(data));
    PCHECK(control_request.io_control_code == 0x000900c0u);
    PCHECK(memcmp(control_request.input_buffer, data, sizeof(data)) == 0);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(rdp_filesystem_redirection_fsctl_supported(RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION));
    PCHECK(rdp_filesystem_redirection_fsctl_supported(RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_COMPRESSION));
    PCHECK(rdp_filesystem_redirection_fsctl_supported(RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE));
    PCHECK(rdp_filesystem_redirection_fsctl_supported(RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA));
    PCHECK(rdp_filesystem_redirection_fsctl_supported(
        RDP_FILESYSTEM_REDIRECTION_FSCTL_QUERY_ALLOCATED_RANGES));
    PCHECK(!rdp_filesystem_redirection_fsctl_supported(0xffffffffu));

    PCHECK(rdp_filesystem_redirection_write_control_request(
               &request,
               1,
               2,
               3,
               2u,
               RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION,
               NULL,
               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_control_request(request.data,
                                                            request.length,
                                                            &control_request) == LIBRDP_STATUS_OK);
    PCHECK(control_request.output_buffer_length == 2u &&
           control_request.input_buffer_length == 0u &&
           control_request.io_control_code == RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    {
        const uint8_t zero_range[16] = {
            0x10, 0, 0, 0, 0, 0, 0, 0,
            0x20, 0, 0, 0, 0, 0, 0, 0};

        PCHECK(rdp_filesystem_redirection_write_control_request(
                   &request,
                   1,
                   2,
                   3,
                   0,
                   RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA,
                   zero_range,
                   sizeof(zero_range)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_filesystem_redirection_parse_control_request(request.data,
                                                                request.length,
                                                                &control_request) == LIBRDP_STATUS_OK);
        PCHECK(control_request.input_buffer_length == sizeof(zero_range) &&
               control_request.io_control_code == RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA &&
               memcmp(control_request.input_buffer, zero_range, sizeof(zero_range)) == 0);
        rdp_buffer_free(&request);
        rdp_buffer_init(&request);
    }

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, (uint32_t)sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 24u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&request, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_information_request(request.data,
                                                                      request.length,
                                                                      &information_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(information_request.information_class == 5u);
    PCHECK(information_request.length == sizeof(data));
    PCHECK(memcmp(information_request.buffer, data, sizeof(data)) == 0);
    request.data[16] = RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION;
    PCHECK(rdp_filesystem_redirection_parse_set_information_request(request.data,
                                                                    request.length,
                                                                    &information_request) ==
           LIBRDP_STATUS_OK);
    request.data[16] = RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION;
    PCHECK(rdp_filesystem_redirection_parse_query_volume_request(request.data,
                                                                 request.length,
                                                                 &information_request) ==
           LIBRDP_STATUS_OK);
    request.data[16] = RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION;
    PCHECK(rdp_filesystem_redirection_parse_set_volume_request(request.data,
                                                               request.length,
                                                               &information_request) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                         RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&request, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, (uint32_t)sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 23u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&request, path, sizeof(path)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_directory_request(request.data,
                                                                    request.length,
                                                                    &directory_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(directory_request.information_class == 1u && directory_request.initial_query == 1u);
    PCHECK(directory_request.path_len == sizeof(path));
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_DIRECTORY_CONTROL,
                                         RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&request, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request,
                                    RDP_FILESYSTEM_REDIRECTION_NOTIFY_FILE_NAME |
                                        RDP_FILESYSTEM_REDIRECTION_NOTIFY_LAST_WRITE) ==
           LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 27u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) == LIBRDP_STATUS_OK);
    PCHECK(notify_request.watch_tree == 1u);
    PCHECK(notify_request.completion_filter ==
           (RDP_FILESYSTEM_REDIRECTION_NOTIFY_FILE_NAME |
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_LAST_WRITE));
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request, 1, 2, 3, RDP_DEVICE_REDIRECTION_IRP_LOCK_CONTROL, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 2u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 20u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 10u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 20u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 30u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&request, 40u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_lock_request(request.data,
                                                         request.length,
                                                         &lock_request) == LIBRDP_STATUS_OK);
    PCHECK(lock_request.operation == RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK);
    PCHECK(lock_request.flags == 1u && lock_request.lock_count == 2u);
    PCHECK(lock_request.locks[1].length == 30u && lock_request.locks[1].offset == 40u);
    request.data[24] = 0xff;
    PCHECK(rdp_filesystem_redirection_parse_lock_request(request.data,
                                                         request.length,
                                                         &lock_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(test_append_device_io_request(&request,
                                         1,
                                         2,
                                         3,
                                         RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 64u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&request, 0x07u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 24u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_query_security_request(request.data,
                                                                   request.length,
                                                                   &security_request) == LIBRDP_STATUS_OK);
    PCHECK(security_request.length == 64u && security_request.security_information == 0x07u);
    request.data[16] = 0x05u;
    PCHECK(rdp_filesystem_redirection_parse_query_security_request(request.data,
                                                                   request.length,
                                                                   &security_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    request.data[16] = (uint8_t)RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY;
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);

    PCHECK(rdp_filesystem_redirection_write_create_response(&response,
                                                            1,
                                                            3,
                                                            RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                            9,
                                                            RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_create_response(response.data,
                                                            response.length,
                                                            &create_response) == LIBRDP_STATUS_OK);
    PCHECK(create_response.io.device_id == 1u && create_response.io.completion_id == 3u);
    PCHECK(create_response.file_id == 9u);
    PCHECK(create_response.information == RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);

    PCHECK(rdp_filesystem_redirection_write_close_response(&response, 1, 3, 0) == LIBRDP_STATUS_OK);
    PCHECK(response.length == 21u);
    PCHECK(rdp_filesystem_redirection_parse_close_response(response.data,
                                                           response.length,
                                                           &completion_response) == LIBRDP_STATUS_OK);
    PCHECK(completion_response.device_id == 1u && completion_response.completion_id == 3u);
    PCHECK(rdp_filesystem_redirection_parse_close_response(response.data,
                                                           response.length - 1u,
                                                           &completion_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
    response.data[16] = 1;
    PCHECK(rdp_filesystem_redirection_parse_close_response(response.data,
                                                           response.length,
                                                           &completion_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_read_response(&response, 1, 3, 0, data, (uint32_t)sizeof(data)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_length_response(response.data,
                                                            response.length,
                                                            &length_response) == LIBRDP_STATUS_OK);
    PCHECK(length_response.length == sizeof(data));
    PCHECK(length_response.buffer_len == sizeof(data));
    PCHECK(memcmp(length_response.buffer, data, sizeof(data)) == 0);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_write_response(&response, 1, 3, 0, 99u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_length_response(response.data,
                                                            response.length,
                                                            &length_response) == LIBRDP_STATUS_OK);
    PCHECK(length_response.length == 99u && length_response.buffer_len == 0u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_buffer_response(&response, 1, 3, 0, data, (uint32_t)sizeof(data)) ==
           LIBRDP_STATUS_OK);
    PCHECK(response.length == 23u);
    rdp_buffer_free(&response);
    rdp_buffer_init(&response);
    PCHECK(rdp_filesystem_redirection_write_lock_response(&response, 1, 3, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_lock_response(response.data,
                                                          response.length,
                                                          &completion_response) == LIBRDP_STATUS_OK);
    PCHECK(completion_response.io_status == 0 && completion_response.payload_len == 5u);

    rdp_buffer_free(&response);
    rdp_buffer_free(&request);
    return 0;
}

/*
 * Coverage: validates printer redirection cache, document format detection,
 * job metadata, and spool payload length handling.
 */
static int test_printer_redirection_channel(void)
{
    const uint8_t driver[] = {'D', 0, 'r', 0, 'v', 0, 0, 0};
    const uint8_t printer[] = {'P', 0, 'r', 0, 'n', 0, 0, 0};
    const uint8_t pnp[] = {'P', 0, 'n', 0, 'P', 0, 0, 0};
    const uint8_t cache[] = {1, 2, 3, 4};
    const char port_name[8] = {'P', 'R', 'N', '1', 0, 0, 0, 0};
    rdp_printer_redirection_announce announce;
    rdp_printer_redirection_announce parsed_announce;
    rdp_printer_redirection_cache_event event;
    rdp_printer_redirection_xps_mode mode;
    rdp_device_redirection_io_completion printer_completion;
    const uint8_t* printer_payload = NULL;
    uint32_t printer_payload_len = 0;
    uint32_t printer_value = 0;
    rdp_buffer buffer;
    rdp_buffer packet;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);
    memset(&announce, 0, sizeof(announce));
    announce.flags = RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_DEFAULT |
                     RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_XPS;
    announce.pnp_name = pnp;
    announce.pnp_name_len = sizeof(pnp);
    announce.driver_name = driver;
    announce.driver_name_len = sizeof(driver);
    announce.printer_name = printer;
    announce.printer_name_len = sizeof(printer);
    announce.cached_fields = cache;
    announce.cached_fields_len = sizeof(cache);
    PCHECK(rdp_printer_redirection_write_announce_data(&buffer, &announce) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_announce_data(buffer.data,
                                                       buffer.length,
                                                       &parsed_announce) == LIBRDP_STATUS_OK);
    PCHECK(parsed_announce.flags == announce.flags);
    PCHECK(parsed_announce.driver_name_len == sizeof(driver));
    PCHECK(memcmp(parsed_announce.driver_name, driver, sizeof(driver)) == 0);
    PCHECK(parsed_announce.printer_name_len == sizeof(printer));
    PCHECK(memcmp(parsed_announce.printer_name, printer, sizeof(printer)) == 0);
    PCHECK(parsed_announce.cached_fields_len == sizeof(cache));
    PCHECK(memcmp(parsed_announce.cached_fields, cache, sizeof(cache)) == 0);
    buffer.data[0] = 0x80;
    PCHECK(rdp_printer_redirection_parse_announce_data(buffer.data,
                                                       buffer.length,
                                                       &parsed_announce) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = (uint8_t)announce.flags;
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    announce.driver_name_len = 0;
    PCHECK(rdp_printer_redirection_write_announce_data(&buffer, &announce) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    announce.driver_name_len = sizeof(driver);
    announce.printer_name_len = 0;
    PCHECK(rdp_printer_redirection_write_announce_data(&buffer, &announce) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    announce.printer_name_len = sizeof(printer);

    PCHECK(rdp_printer_redirection_write_cache_add(&packet,
                                                   port_name,
                                                   pnp,
                                                   sizeof(pnp),
                                                   driver,
                                                   sizeof(driver),
                                                   printer,
                                                   sizeof(printer),
                                                   cache,
                                                   sizeof(cache)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_ADD);
    PCHECK(memcmp(event.port_name, "PRN1", 5) == 0);
    PCHECK(event.printer_name_len == sizeof(printer));
    PCHECK(event.cached_fields_len == sizeof(cache));
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data,
                                                     packet.length - 1u,
                                                     &event) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_printer_redirection_write_cache_add(&buffer,
                                                   port_name,
                                                   pnp,
                                                   sizeof(pnp),
                                                   driver,
                                                   0,
                                                   printer,
                                                   sizeof(printer),
                                                   cache,
                                                   sizeof(cache)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_printer_redirection_write_cache_add(&buffer,
                                                   port_name,
                                                   pnp,
                                                   sizeof(pnp),
                                                   driver,
                                                   sizeof(driver),
                                                   printer,
                                                   0,
                                                   cache,
                                                   sizeof(cache)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_cache_update(&packet,
                                                      printer,
                                                      sizeof(printer),
                                                      cache,
                                                      sizeof(cache)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_UPDATE);
    PCHECK(rdp_printer_redirection_write_cache_update(&buffer,
                                                      printer,
                                                      0,
                                                      cache,
                                                      sizeof(cache)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_cache_delete(&packet,
                                                      printer,
                                                      sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_DELETE);
    PCHECK(event.printer_name_len == sizeof(printer));
    PCHECK(rdp_printer_redirection_write_cache_delete(&buffer,
                                                      printer,
                                                      0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_device_redirection_write_header(&buffer,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_PRINTER_REDIRECTION_CACHE_DELETE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(buffer.data, buffer.length, &event) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_cache_rename(&packet,
                                                      printer,
                                                      sizeof(printer),
                                                      driver,
                                                      sizeof(driver)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_RENAME);
    PCHECK(event.old_printer_name_len == sizeof(printer));
    PCHECK(event.new_printer_name_len == sizeof(driver));
    PCHECK(rdp_printer_redirection_write_cache_rename(&buffer,
                                                      printer,
                                                      0,
                                                      driver,
                                                      sizeof(driver)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_printer_redirection_write_cache_rename(&buffer,
                                                      printer,
                                                      sizeof(printer),
                                                      driver,
                                                      0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_xps_mode(&packet, 0x10203040u, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_xps_mode(packet.data, packet.length, &mode) ==
           LIBRDP_STATUS_OK);
    PCHECK(mode.printer_id == 0x10203040u && mode.flags == 1u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    {
        const char* format = NULL;
        const uint8_t pdf[] = {'%', 'P', 'D', 'F', '-'};
        const uint8_t ps[] = {'%', '!', 'P', 'S'};
        const uint8_t xps[] = {'P', 'K', 3, 4, '[', 'C', 'o', 'n', 't', 'e', 'n', 't',
                               '_', 'T', 'y', 'p', 'e', 's', ']', '.', 'x', 'm', 'l'};
        const uint8_t xps_zip[] = {
            0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x64,
            0xeb, 0x5c, 0x7d, 0x8f, 0xc3, 0x39, 0x4d, 0x00, 0x00, 0x00, 0x4d, 0x00,
            0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x5b, 0x43, 0x6f, 0x6e, 0x74, 0x65,
            0x6e, 0x74, 0x5f, 0x54, 0x79, 0x70, 0x65, 0x73, 0x5d, 0x2e, 0x78, 0x6d,
            0x6c, 0x3c, 0x54, 0x79, 0x70, 0x65, 0x73, 0x20, 0x78, 0x6d, 0x6c, 0x6e,
            0x73, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x63,
            0x68, 0x65, 0x6d, 0x61, 0x73, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x78, 0x6d,
            0x6c, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x73, 0x2e, 0x6f, 0x72, 0x67,
            0x2f, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x2f, 0x32, 0x30, 0x30,
            0x36, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79,
            0x70, 0x65, 0x73, 0x22, 0x2f, 0x3e, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x8b, 0x64, 0xeb, 0x5c, 0xd7, 0x97, 0x5f, 0xc0,
            0x18, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00,
            0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x31, 0x2f,
            0x46, 0x69, 0x78, 0x65, 0x64, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e,
            0x74, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x2e, 0x66, 0x64,
            0x73, 0x65, 0x71, 0x3c, 0x46, 0x69, 0x78, 0x65, 0x64, 0x44, 0x6f, 0x63,
            0x75, 0x6d, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63,
            0x65, 0x2f, 0x3e, 0x50, 0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x8b, 0x64, 0xeb, 0x5c, 0x7d, 0x8f, 0xc3, 0x39, 0x4d,
            0x00, 0x00, 0x00, 0x4d, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x5b, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x54, 0x79,
            0x70, 0x65, 0x73, 0x5d, 0x2e, 0x78, 0x6d, 0x6c, 0x50, 0x4b, 0x01, 0x02,
            0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x64, 0xeb, 0x5c,
            0xd7, 0x97, 0x5f, 0xc0, 0x18, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
            0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, 0x01, 0x7e, 0x00, 0x00, 0x00, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65,
            0x6e, 0x74, 0x73, 0x2f, 0x31, 0x2f, 0x46, 0x69, 0x78, 0x65, 0x64, 0x44,
            0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x71, 0x75, 0x65,
            0x6e, 0x63, 0x65, 0x2e, 0x66, 0x64, 0x73, 0x65, 0x71, 0x50, 0x4b, 0x05,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x96, 0x00, 0x00,
            0x00, 0xdb, 0x00, 0x00, 0x00, 0x00, 0x00};
        const uint8_t zip[] = {'P', 'K', 3, 4, 'd', 'a', 't', 'a'};
        const uint8_t png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        const uint8_t jpg[] = {0xff, 0xd8, 0xff, 0xe0};
        const uint8_t pcl[] = {0x1b, '%', '-', '1', '2', '3', '4', '5', 'X'};
        const uint8_t pdf_bom[] = {0xef, 0xbb, 0xbf, '\r', '\n', '%', 'P', 'D', 'F', '-'};
        const uint8_t pjl[] = {' ', '\t', '@', 'P', 'J', 'L', ' '};
        const uint8_t pclxl[] = {')', ' ', 'H', 'P', '-', 'P', 'C', 'L', ' ', 'X', 'L', ';'};

        PCHECK(rdp_printer_redirection_detect_document_format(pdf, sizeof(pdf), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PDF) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(pdf_bom, sizeof(pdf_bom), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PDF) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(ps, sizeof(ps), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_POSTSCRIPT) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(xps, sizeof(xps), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_XPS) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(xps_zip, sizeof(xps_zip), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_XPS) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(zip, sizeof(zip), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_RAW) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(png, sizeof(png), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PNG) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(jpg, sizeof(jpg), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_JPEG) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(pcl, sizeof(pcl), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PCL) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(pjl, sizeof(pjl), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PCL) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(pclxl, sizeof(pclxl), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_PCL) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(cache, sizeof(cache), &format) ==
               LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_RAW) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(NULL, 0, &format) == LIBRDP_STATUS_OK);
        PCHECK(strcmp(format, RDP_PRINTER_REDIRECTION_FORMAT_RAW) == 0);
        PCHECK(rdp_printer_redirection_detect_document_format(NULL, 0, NULL) ==
               LIBRDP_STATUS_INVALID_ARGUMENT);
    }

    PCHECK(rdp_printer_redirection_write_create_response(&packet, 1, 2, 0, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_create_response(packet.data,
                                                         packet.length,
                                                         &printer_completion,
                                                         &printer_value) == LIBRDP_STATUS_OK);
    PCHECK(printer_completion.device_id == 1u && printer_value == 3u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_close_response(&packet, 1, 2, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_close_response(packet.data,
                                                        packet.length,
                                                        &printer_completion) == LIBRDP_STATUS_OK);
    packet.data[16] = 1;
    PCHECK(rdp_printer_redirection_parse_close_response(packet.data,
                                                        packet.length,
                                                        &printer_completion) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_read_response(&packet, 1, 2, 0, cache, sizeof(cache)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_read_response(packet.data,
                                                       packet.length,
                                                       &printer_completion,
                                                       &printer_payload,
                                                       &printer_payload_len) == LIBRDP_STATUS_OK);
    PCHECK(printer_completion.device_id == 1u &&
           printer_payload_len == sizeof(cache) &&
           memcmp(printer_payload, cache, sizeof(cache)) == 0);
    packet.data[19] = 0xff;
    PCHECK(rdp_printer_redirection_parse_read_response(packet.data,
                                                       packet.length,
                                                       &printer_completion,
                                                       &printer_payload,
                                                       &printer_payload_len) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_write_response(&packet, 1, 2, 0, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_write_response(packet.data,
                                                        packet.length,
                                                        &printer_completion,
                                                        &printer_value) == LIBRDP_STATUS_OK);
    PCHECK(printer_value == 4u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_buffer_response(&packet, 1, 2, 0, cache, sizeof(cache)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_buffer_response(packet.data,
                                                         packet.length,
                                                         &printer_completion,
                                                         &printer_payload,
                                                         &printer_payload_len) == LIBRDP_STATUS_OK);
    PCHECK(printer_payload_len == sizeof(cache) &&
           memcmp(printer_payload, cache, sizeof(cache)) == 0);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_length_response(&packet, 1, 2, 0, 9) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_length_response(packet.data,
                                                         packet.length,
                                                         &printer_completion,
                                                         &printer_value) == LIBRDP_STATUS_OK);
    PCHECK(printer_value == 9u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_device_control_response(&packet, 1, 2, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_device_control_response(packet.data,
                                                                 packet.length,
                                                                 &printer_completion) == LIBRDP_STATUS_OK);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates telemetry and multiparty parser/writer vectors,
 * including unknown message rejection and bounded string handling.
 */
static int test_telemetry_multiparty_channels(void)
{
    const uint8_t name[] = {'A', 0};
    rdp_buffer buffer;
    rdp_telemetry_pdu telemetry;
    rdp_multiparty_filter_state filter;
    rdp_multiparty_app_created app;
    rdp_multiparty_id_message id_message;
    rdp_multiparty_window_created window;
    rdp_multiparty_region_update region;
    rdp_multiparty_participant_created participant;
    rdp_multiparty_participant_removed removed;
    rdp_multiparty_control_change change;
    rdp_multiparty_control_change_response response;
    rdp_multiparty_header header;
    rdp_multiparty_message message;

    rdp_buffer_init(&buffer);

    rdp_telemetry_pdu_init(&telemetry, 1, 2, 3, 4);
    PCHECK(telemetry.id == RDP_TELEMETRY_PDU_ID &&
           telemetry.length == RDP_TELEMETRY_PDU_LENGTH &&
           telemetry.prompt_for_credentials_done_ms == 2);
    PCHECK(rdp_telemetry_write_pdu(&buffer, &telemetry) == LIBRDP_STATUS_OK);
    PCHECK(rdp_telemetry_parse_pdu(buffer.data, buffer.length, &telemetry) == LIBRDP_STATUS_OK);
    PCHECK(telemetry.id == RDP_TELEMETRY_PDU_ID &&
           telemetry.length == RDP_TELEMETRY_PDU_LENGTH &&
           telemetry.first_graphics_received_ms == 4);
    buffer.data[0] = 2;
    PCHECK(rdp_telemetry_parse_pdu(buffer.data, buffer.length, &telemetry) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = RDP_TELEMETRY_PDU_ID;
    buffer.data[1] = RDP_TELEMETRY_PDU_LENGTH - 1u;
    PCHECK(rdp_telemetry_parse_pdu(buffer.data, buffer.length, &telemetry) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_telemetry_write_metrics(&buffer, 5, 6, 7, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_telemetry_parse_pdu(buffer.data, buffer.length, &telemetry) == LIBRDP_STATUS_OK);
    PCHECK(telemetry.prompt_for_credentials_ms == 5 &&
           telemetry.prompt_for_credentials_done_ms == 6 &&
           telemetry.graphics_channel_opened_ms == 7 &&
           telemetry.first_graphics_received_ms == 8);
    PCHECK(rdp_telemetry_write_metrics(NULL, 0, 0, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    telemetry.id = 0x7fu;
    telemetry.length = RDP_TELEMETRY_PDU_LENGTH;
    PCHECK(rdp_telemetry_write_pdu(&buffer, &telemetry) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    telemetry.id = RDP_TELEMETRY_PDU_ID;
    telemetry.length = 0x7fu;
    PCHECK(rdp_telemetry_write_pdu(&buffer, &telemetry) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_filter_state(&buffer, RDP_MULTIPARTY_FILTER_ENABLED) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_filter_state(buffer.data, buffer.length, &filter) == LIBRDP_STATUS_OK);
    PCHECK(filter.flags == RDP_MULTIPARTY_FILTER_ENABLED);
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.type == RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED &&
           message.body.filter_state.flags == RDP_MULTIPARTY_FILTER_ENABLED);
    {
        rdp_multiparty_filter_state valid_filter = filter;

        buffer.data[4] = 0x80;
        PCHECK(rdp_multiparty_parse_filter_state(buffer.data, buffer.length, &filter) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&filter, &valid_filter, sizeof(filter)) == 0);
    }
    memset(&message, 0x5a, sizeof(message));
    message.type = 0x7777u;
    {
        rdp_multiparty_message before = message;

        PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&message, &before, sizeof(message)) == 0);
    }
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_app_created(&buffer,
                                            RDP_MULTIPARTY_APPLICATION_SHARED,
                                            0x11223344u,
                                            name,
                                            1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_header(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.length == buffer.length && header.payload_len == buffer.length - 4u);
    {
        rdp_multiparty_header valid_header = header;

        PCHECK(rdp_multiparty_parse_header(buffer.data, buffer.length - 1u, &header) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&header, &valid_header, sizeof(header)) == 0);
    }
    PCHECK(rdp_multiparty_parse_app_created(buffer.data, buffer.length, &app) == LIBRDP_STATUS_OK);
    PCHECK(app.flags == RDP_MULTIPARTY_APPLICATION_SHARED &&
           app.app_id == 0x11223344u &&
           app.name.char_count == 1 &&
           app.name.utf16[0] == 'A');
    {
        rdp_multiparty_app_created valid_app = app;
        rdp_multiparty_string valid_name = app.name;
        size_t consumed = 0x77u;

        PCHECK(rdp_multiparty_parse_string(app.header.payload + 6u,
                                           app.header.payload_len - 7u,
                                           &app.name,
                                           &consumed) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&app.name, &valid_name, sizeof(app.name)) == 0);
        PCHECK(consumed == 0x77u);
        PCHECK(rdp_multiparty_parse_app_created(buffer.data,
                                                buffer.length - 1u,
                                                &app) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&app, &valid_app, sizeof(app)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_write_app_created(&buffer,
                                            RDP_MULTIPARTY_APPLICATION_SHARED,
                                            0x11223344u,
                                            NULL,
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_id_message(&buffer, RDP_MULTIPARTY_TYPE_WND_SHOW, 7u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_id_message(buffer.data,
                                           buffer.length,
                                           RDP_MULTIPARTY_TYPE_WND_SHOW,
                                           &id_message) == LIBRDP_STATUS_OK);
    PCHECK(id_message.id == 7u);
    {
        rdp_multiparty_id_message valid_id_message = id_message;

        PCHECK(rdp_multiparty_parse_id_message(buffer.data,
                                               buffer.length - 1u,
                                               RDP_MULTIPARTY_TYPE_WND_SHOW,
                                               &id_message) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&id_message, &valid_id_message, sizeof(id_message)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_window_created(&buffer,
                                               RDP_MULTIPARTY_WINDOW_SHARED,
                                               1u,
                                               2u,
                                               name,
                                               1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_window_created(buffer.data, buffer.length, &window) ==
           LIBRDP_STATUS_OK);
    PCHECK(window.app_id == 1u && window.window_id == 2u && window.name.utf16_len == 2u);
    {
        rdp_multiparty_window_created valid_window = window;

        PCHECK(rdp_multiparty_parse_window_created(buffer.data,
                                                   buffer.length - 1u,
                                                   &window) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&window, &valid_window, sizeof(window)) == 0);
    }
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.type == RDP_MULTIPARTY_TYPE_WND_CREATED &&
           message.body.window_created.window_id == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_write_window_created(&buffer,
                                               RDP_MULTIPARTY_WINDOW_SHARED,
                                               1u,
                                               2u,
                                               NULL,
                                               1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_region_update(&buffer, 1, 2, 10, 20) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_region_update(buffer.data, buffer.length, &region) == LIBRDP_STATUS_OK);
    PCHECK(region.left == 1 && region.bottom == 20);
    {
        rdp_multiparty_region_update valid_region = region;

        buffer.data[4] = 10u;
        buffer.data[5] = 0u;
        buffer.data[6] = 0u;
        buffer.data[7] = 0u;
        buffer.data[12] = 1u;
        buffer.data[13] = 0u;
        buffer.data[14] = 0u;
        buffer.data[15] = 0u;
        PCHECK(rdp_multiparty_parse_region_update(buffer.data, buffer.length, &region) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&region, &valid_region, sizeof(region)) == 0);
    }
    PCHECK(rdp_multiparty_write_region_update(&buffer, 10, 2, 1, 20) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_participant_created(&buffer,
                                                    3u,
                                                    4u,
                                                    RDP_MULTIPARTY_MAY_VIEW | RDP_MULTIPARTY_IS_PARTICIPANT,
                                                    name,
                                                    1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_participant_created(buffer.data, buffer.length, &participant) ==
           LIBRDP_STATUS_OK);
    PCHECK(participant.participant_id == 3u &&
           participant.group_id == 4u &&
           participant.friendly_name.char_count == 1);
    {
        rdp_multiparty_participant_created valid_participant = participant;

        PCHECK(rdp_multiparty_parse_participant_created(buffer.data,
                                                        buffer.length - 1u,
                                                        &participant) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&participant, &valid_participant, sizeof(participant)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_write_participant_created(&buffer,
                                                    3u,
                                                    4u,
                                                    RDP_MULTIPARTY_MAY_VIEW,
                                                    NULL,
                                                    1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_participant_removed(&buffer, 3u, 2u, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_participant_removed(buffer.data, buffer.length, &removed) ==
           LIBRDP_STATUS_OK);
    PCHECK(removed.participant_id == 3u && removed.disconnect_type == 2u);
    {
        rdp_multiparty_participant_removed valid_removed = removed;

        PCHECK(rdp_multiparty_parse_participant_removed(buffer.data,
                                                        buffer.length - 1u,
                                                        &removed) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&removed, &valid_removed, sizeof(removed)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_control_change(&buffer,
                                               RDP_MULTIPARTY_REQUEST_VIEW |
                                                   RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS,
                                               3u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_control_change(buffer.data, buffer.length, &change) ==
           LIBRDP_STATUS_OK);
    PCHECK(change.participant_id == 3u);
    {
        rdp_multiparty_control_change valid_change = change;

        buffer.data[5] = 0x80u;
        PCHECK(rdp_multiparty_parse_control_change(buffer.data, buffer.length, &change) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&change, &valid_change, sizeof(change)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_control_change_response(&buffer,
                                                        RDP_MULTIPARTY_REQUEST_INTERACT,
                                                        3u,
                                                        0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_control_change_response(buffer.data, buffer.length, &response) ==
           LIBRDP_STATUS_OK);
    PCHECK(response.flags == RDP_MULTIPARTY_REQUEST_INTERACT && response.reason_code == 0);
    {
        rdp_multiparty_control_change_response valid_response = response;

        buffer.data[5] = 0x80u;
        PCHECK(rdp_multiparty_parse_control_change_response(buffer.data, buffer.length, &response) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&response, &valid_response, sizeof(response)) == 0);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_empty(&buffer, RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_empty(buffer.data,
                                      buffer.length,
                                      RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.type == RDP_MULTIPARTY_TYPE_GRAPHICS_STREAM_PAUSED &&
           message.body.header.payload_len == 0);
    PCHECK(rdp_multiparty_parse_message(NULL, buffer.length, &message) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates XPS print package construction and malformed
 * archive/document metadata handling without invoking external spoolers.
 */
static int test_xps_print_channel(void)
{
    const uint8_t guid[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t xml[] = {'<', 'x', '/', '>'};
    const uint8_t cap_data[] = {1, 2, 3};
    const uint8_t prop_name[] = {'P', 0, 'r', 0};
    const uint8_t prop_value32[] = {0x78, 0x56, 0x34, 0x12};
    const uint32_t versions[] = {1, 2};
    uint32_t new_id = 0x10203040u;
    rdp_buffer buffer;
    rdp_xps_print_header header;
    rdp_xps_print_interface_query query;
    rdp_xps_print_interface_query_response query_response;
    rdp_xps_print_xml_document document;
    rdp_xps_print_device_capability capability;
    rdp_xps_print_printer_property property;
    rdp_xps_print_u32_request u32_request;
    rdp_xps_print_result result;
    rdp_xps_print_versions_response versions_response;
    rdp_xps_print_blob_result blob_result;
    rdp_xps_print_optional_blob_result optional_result;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_interface_query(&buffer, 0, 7, guid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_interface_query(buffer.data, buffer.length, &query) == LIBRDP_STATUS_OK);
    PCHECK(query.header.message_id == 7 && query.guid[15] == 15);
    PCHECK(rdp_xps_print_write_interface_query(&buffer, 0, 7, NULL) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_xps_print_parse_interface_query(buffer.data,
                                               buffer.length - 1u,
                                               &query) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_interface_query_response(&buffer, 0, 7, &new_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_interface_query_response(buffer.data,
                                                        buffer.length,
                                                        &query_response) == LIBRDP_STATUS_OK);
    PCHECK(query_response.has_new_interface_id && query_response.new_interface_id == new_id);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_release(&buffer, 0, 8) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_release(buffer.data, buffer.length, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.message_id == 8);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_xml_document(&buffer, xml, (uint32_t)sizeof(xml)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_xml_document(buffer.data, buffer.length, &document) == LIBRDP_STATUS_OK);
    PCHECK(document.size == sizeof(xml) && memcmp(document.data, xml, sizeof(xml)) == 0);
    buffer.data[0] = 0xff;
    PCHECK(rdp_xps_print_parse_xml_document(buffer.data, buffer.length, &document) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_device_capability(&buffer, 0xffffffffu, 0, cap_data, sizeof(cap_data)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_device_capability(buffer.data, buffer.length, &capability) ==
           LIBRDP_STATUS_OK);
    PCHECK(capability.return_value == 0xffffffffu &&
           capability.data_len == sizeof(cap_data) &&
           capability.data[2] == 3);
    buffer.data[buffer.length - 1u] = 0xff;
    PCHECK(rdp_xps_print_parse_device_capability(buffer.data,
                                                 buffer.length,
                                                 &capability) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_printer_property(&buffer,
                                                RDP_XPS_PRINT_PROPERTY_INT32,
                                                prop_name,
                                                sizeof(prop_name),
                                                prop_value32,
                                                sizeof(prop_value32)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_printer_property(buffer.data, buffer.length, &property) ==
           LIBRDP_STATUS_OK);
    PCHECK(property.property_type == RDP_XPS_PRINT_PROPERTY_INT32 &&
           property.name_len == sizeof(prop_name) &&
           property.value[0] == 0x78);
    PCHECK(rdp_xps_print_write_printer_property(&buffer,
                                                RDP_XPS_PRINT_PROPERTY_INT32,
                                                prop_name,
                                                3,
                                                prop_value32,
                                                sizeof(prop_value32)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_u32_request(&buffer,
                                           9,
                                           RDP_XPS_PRINT_DRIVER_INIT_PRINTER,
                                           0x11223344u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_u32_request(buffer.data,
                                           buffer.length,
                                           RDP_XPS_PRINT_DRIVER_INIT_PRINTER,
                                           &u32_request) == LIBRDP_STATUS_OK);
    PCHECK(u32_request.value == 0x11223344u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_result(&buffer, 0, 9, 0x80004005u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_result(buffer.data, buffer.length, &result) == LIBRDP_STATUS_OK);
    PCHECK(result.result == 0x80004005u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_versions_response(&buffer, 0, 10, versions, 2, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_versions_response(buffer.data,
                                                 buffer.length,
                                                 &versions_response) == LIBRDP_STATUS_OK);
    PCHECK(versions_response.version_count == 2 &&
           test_read_u32_le(versions_response.versions + 4) == 2);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_blob_result(&buffer, 0, 11, cap_data, sizeof(cap_data), 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_blob_result(buffer.data, buffer.length, &blob_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(blob_result.data_len == sizeof(cap_data) && blob_result.data[0] == 1);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_xps_print_write_optional_blob_result(&buffer,
                                                    0,
                                                    12,
                                                    xml,
                                                    sizeof(xml),
                                                    RDP_XPS_PRINT_NULL_PRESENT,
                                                    0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_optional_blob_result(buffer.data,
                                                    buffer.length,
                                                    &optional_result) == LIBRDP_STATUS_OK);
    PCHECK(optional_result.null_flag == RDP_XPS_PRINT_NULL_PRESENT &&
           optional_result.data_len == sizeof(xml));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_xps_print_write_optional_blob_result(&buffer,
                                                    0,
                                                    13,
                                                    NULL,
                                                    0,
                                                    RDP_XPS_PRINT_NULL_ABSENT,
                                                    0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_xps_print_parse_optional_blob_result(buffer.data,
                                                    buffer.length,
                                                    &optional_result) == LIBRDP_STATUS_OK);
    PCHECK(optional_result.null_flag == RDP_XPS_PRINT_NULL_ABSENT &&
           optional_result.data_len == 0);

    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates authentication redirection and smartcard PC/SC vectors,
 * including IOCTL dispatch, cache payloads, and handle-state boundaries.
 */
static int test_auth_smartcard_redirection_channels(void)
{
    const uint8_t call_payload[] = {0xaa, 0xbb, 0xcc};
    const uint8_t context_bytes[] = {0x00, 0x00, 0x01, 0xcd};
    const uint8_t nt_response_bytes[RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    const uint8_t session_key_bytes[RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    const uint8_t scard_extra[] = {0x01, 0x02, 0x03};
    const uint8_t scard_reader_name[] = {'R', 'e', 'a', 'd', 'e', 'r', ' ', 'A', 0};
    const uint8_t scard_atr_mask[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH] = {
        0xff, 0xff, 0xff
    };
    rdp_buffer buffer;
    rdp_buffer packet;
    rdp_auth_redirection_call auth_call;
    rdp_auth_redirection_response auth_response;
    rdp_auth_redirection_negotiate_version auth_version;
    rdp_auth_redirection_ecdh_key_agreement_call ecdh_call;
    rdp_auth_redirection_dh_key_agreement_call dh_call;
    rdp_auth_redirection_key_agreement_handle_call key_handle_call;
    rdp_auth_redirection_fixed_response fixed_response;
    rdp_auth_redirection_compare_credentials_result compare_result;
    rdp_auth_redirection_inner_buffer inner;
    rdp_auth_redirection_outer_packet outer;
    rdp_auth_redirection_encoded_payload encoded_payload;
    rdp_auth_redirection_octet_string auth_octet;
    rdp_auth_redirection_asn1_data auth_asn1;
    rdp_auth_redirection_finalize_key_agreement_call finalize_call;
    rdp_auth_redirection_call_message auth_call_message;
    rdp_auth_redirection_response_message auth_response_message;
    rdp_smartcard_redirection_establish_context_call establish_call;
    rdp_smartcard_redirection_device_control_request control_request;
    rdp_smartcard_redirection_device_control_response control_response;
    rdp_smartcard_redirection_request_message scard_message;
    rdp_smartcard_redirection_context context;
    rdp_smartcard_redirection_handle handle;
    rdp_smartcard_redirection_scard_io_request scard_io;
    rdp_smartcard_redirection_atr_mask atr_mask;
    rdp_smartcard_redirection_reader_state_common reader_state;
    rdp_smartcard_redirection_connect_common connect_common;
    rdp_smartcard_redirection_list_reader_groups_call list_groups_call;
    rdp_smartcard_redirection_list_readers_call list_readers_call;
    rdp_smartcard_redirection_reader_state_call status_readers[1];
    rdp_smartcard_redirection_get_status_change_call get_status_change_call;
    rdp_smartcard_redirection_get_status_change_return get_status_change_result;
    rdp_smartcard_redirection_reconnect_call reconnect_call;
    rdp_smartcard_redirection_handle_disposition_call disposition_call;
    rdp_smartcard_redirection_state_call state_call;
    rdp_smartcard_redirection_status_call status_call;
    rdp_smartcard_redirection_transmit_call transmit_call;
    rdp_smartcard_redirection_control_call control_call;
    rdp_smartcard_redirection_attrib_call attrib_call;
    rdp_smartcard_redirection_set_attrib_call set_attrib_call;
    rdp_smartcard_redirection_string scard_string;
    rdp_smartcard_redirection_context_string_call context_string_call;
    rdp_smartcard_redirection_context_two_strings_call context_two_strings_call;
    rdp_smartcard_redirection_locate_cards_call locate_cards_call;
    rdp_smartcard_redirection_locate_cards_by_atr_call locate_atr_call;
    rdp_smartcard_redirection_read_cache_call read_cache_call;
    rdp_smartcard_redirection_write_cache_call write_cache_call;
    rdp_smartcard_redirection_reader_name_call reader_name_call;
    rdp_smartcard_redirection_long_return long_result;
    rdp_smartcard_redirection_count_return count_result;
    rdp_smartcard_redirection_buffer_return buffer_result;
    rdp_smartcard_redirection_establish_context_return establish_result;
    rdp_smartcard_redirection_connect_return connect_result;
    rdp_smartcard_redirection_status_return status_result;
    rdp_smartcard_redirection_transmit_return transmit_result;
    rdp_device_redirection_io_request io_request;
    rdp_device_redirection_io_completion io_completion;
    uint8_t card_identifier[RDP_SMARTCARD_REDIRECTION_CARD_IDENTIFIER_LENGTH];

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);
    memset(card_identifier, 0x5a, sizeof(card_identifier));

    PCHECK(rdp_auth_redirection_kerb_call_id_valid(RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT));
    PCHECK(rdp_auth_redirection_ntlm_call_id_valid(
        RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT));
    PCHECK(rdp_auth_redirection_call_id_valid(RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION));
    PCHECK(rdp_auth_redirection_negotiate_call_id_valid(RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION));
    PCHECK(!rdp_auth_redirection_negotiate_call_id_valid(RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS));
    PCHECK(rdp_auth_redirection_asn1_pdu_valid(RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP));
    PCHECK(!rdp_auth_redirection_asn1_pdu_valid(0x7fu));
    PCHECK(!rdp_auth_redirection_kerb_call_id_valid(0x0000010cu));
    PCHECK(!rdp_auth_redirection_ntlm_call_id_valid(0x00000205u));
    PCHECK(!rdp_auth_redirection_ecdh_key_bits_valid(255));

    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                           call_payload,
                                           sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call(buffer.data, buffer.length, &auth_call) == LIBRDP_STATUS_OK);
    PCHECK(auth_call.call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS &&
           auth_call.payload_len == sizeof(call_payload) &&
           memcmp(auth_call.payload, call_payload, sizeof(call_payload)) == 0);
    PCHECK(rdp_auth_redirection_write_call(&packet, 0x0000010cu, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_auth_redirection_write_call(&packet, 0x00000205u, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_auth_redirection_write_call(&packet, 0x00000300u, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_auth_redirection_write_call(&packet, RDP_AUTH_REDIRECTION_CALL_INVALID, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_auth_redirection_write_response(&packet,
                                               RDP_AUTH_REDIRECTION_CALL_INVALID,
                                               0,
                                               NULL,
                                               0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    buffer.data[0] = 0x0c;
    buffer.data[1] = 0x01;
    PCHECK(rdp_auth_redirection_parse_call(buffer.data, buffer.length, &auth_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = 0x05;
    buffer.data[1] = 0x02;
    PCHECK(rdp_auth_redirection_parse_call(buffer.data, buffer.length, &auth_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[0] = 0x00;
    buffer.data[1] = 0x03;
    PCHECK(rdp_auth_redirection_parse_call(buffer.data, buffer.length, &auth_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_auth_redirection_write_negotiate_version_call(
               &buffer,
               RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_negotiate_version_call(buffer.data,
                                                             buffer.length,
                                                             &auth_version) == LIBRDP_STATUS_OK);
    PCHECK(auth_version.version == RDP_AUTH_REDIRECTION_VERSION);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_call_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION &&
           auth_call_message.body.negotiate_version.version == RDP_AUTH_REDIRECTION_VERSION);
    buffer.data[4] = 1;
    PCHECK(rdp_auth_redirection_parse_negotiate_version_call(buffer.data,
                                                             buffer.length,
                                                             &auth_version) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_negotiate_version_response(
               &buffer,
               RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_negotiate_version_response(buffer.data,
                                                                 buffer.length,
                                                                 &auth_response,
                                                                 &auth_version) == LIBRDP_STATUS_OK);
    PCHECK(auth_response.call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION &&
           auth_response.status == 0 &&
           auth_response.payload_len == 4u &&
           auth_version.version == RDP_AUTH_REDIRECTION_VERSION);
    PCHECK(rdp_auth_redirection_parse_response_message(buffer.data,
                                                       buffer.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION &&
           auth_response_message.body.negotiate_version.version == RDP_AUTH_REDIRECTION_VERSION);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_response(&buffer,
                                               RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                               0xc0000001u,
                                               call_payload,
                                               sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response(buffer.data,
                                               buffer.length,
                                               &auth_response) == LIBRDP_STATUS_OK);
    PCHECK(auth_response.status == 0xc0000001u &&
           auth_response.payload_len == sizeof(call_payload));
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_octet_string(&buffer,
                                                   call_payload,
                                                   sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_octet_string(buffer.data,
                                                   buffer.length,
                                                   &auth_octet) == LIBRDP_STATUS_OK);
    PCHECK(auth_octet.length == sizeof(call_payload) &&
           memcmp(auth_octet.value, call_payload, sizeof(call_payload)) == 0);
    buffer.data[0] = 0xff;
    PCHECK(rdp_auth_redirection_parse_octet_string(buffer.data,
                                                   buffer.length,
                                                   &auth_octet) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_asn1_data(&buffer,
                                                RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP,
                                                call_payload,
                                                sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_asn1_data(buffer.data,
                                                buffer.length,
                                                &auth_asn1) == LIBRDP_STATUS_OK);
    PCHECK(auth_asn1.pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_AS_REP &&
           auth_asn1.length == sizeof(call_payload) &&
           memcmp(auth_asn1.value, call_payload, sizeof(call_payload)) == 0);
    buffer.data[0] = 0x44;
    PCHECK(rdp_auth_redirection_parse_asn1_data(buffer.data,
                                                buffer.length,
                                                &auth_asn1) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_auth_redirection_write_asn1_data(&packet,
                                                0x44u,
                                                NULL,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_asn1_response(
               &buffer,
               RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY,
               0,
               RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP,
               call_payload,
               sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_asn1_response(
               buffer.data,
               buffer.length,
               RDP_AUTH_REDIRECTION_CALL_KERB_DECRYPT_AP_REPLY,
               &auth_response,
               &auth_asn1) == LIBRDP_STATUS_OK);
    PCHECK(auth_response.status == 0 &&
           auth_asn1.pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP &&
           auth_asn1.length == sizeof(call_payload));
    PCHECK(rdp_auth_redirection_parse_response_message(buffer.data,
                                                       buffer.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_ASN1_RESPONSE &&
           auth_response_message.body.asn1.pdu == RDP_AUTH_REDIRECTION_ASN1_PDU_TGS_REP);
    PCHECK(rdp_auth_redirection_parse_asn1_response(
               buffer.data,
               buffer.length,
               RDP_AUTH_REDIRECTION_CALL_KERB_VERIFY_SERVICE_TICKET,
               &auth_response,
               &auth_asn1) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_ecdh_key_agreement_call(
               &buffer,
               RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_ecdh_key_agreement_call(buffer.data,
                                                              buffer.length,
                                                              &ecdh_call) == LIBRDP_STATUS_OK);
    PCHECK(ecdh_call.key_bits == RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_call_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_ECDH_KEY_AGREEMENT &&
           auth_call_message.body.ecdh.key_bits == RDP_AUTH_REDIRECTION_ECDH_KEY_BITS_P384);
    PCHECK(rdp_auth_redirection_write_ecdh_key_agreement_call(&packet, 255) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_dh_key_agreement_call(&buffer, 0x7f) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_dh_key_agreement_call(buffer.data,
                                                            buffer.length,
                                                            &dh_call) == LIBRDP_STATUS_OK);
    PCHECK(dh_call.ignored == 0x7f);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_key_agreement_handle_call(
               &buffer,
               RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT,
               -1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_key_agreement_handle_call(
               buffer.data,
               buffer.length,
               RDP_AUTH_REDIRECTION_CALL_KERB_DESTROY_KEY_AGREEMENT,
               &key_handle_call) == LIBRDP_STATUS_OK);
    PCHECK(key_handle_call.handle == -1);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_call_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_KEY_AGREEMENT_HANDLE &&
           auth_call_message.body.key_handle.handle == -1);
    PCHECK(rdp_auth_redirection_write_key_agreement_handle_call(
               &packet,
               RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT,
               1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_finalize_key_agreement_call(&buffer,
                                                                  -2,
                                                                  18,
                                                                  call_payload,
                                                                  sizeof(call_payload),
                                                                  session_key_bytes,
                                                                  sizeof(session_key_bytes)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_finalize_key_agreement_call(buffer.data,
                                                                  buffer.length,
                                                                  &finalize_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(finalize_call.handle == -2 &&
           finalize_call.kerb_etype == 18 &&
           finalize_call.remote_nonce_len == sizeof(call_payload) &&
           finalize_call.x509_public_key_len == sizeof(session_key_bytes));
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_call_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_FINALIZE_KEY_AGREEMENT &&
           auth_call_message.body.finalize_key_agreement.kerb_etype == 18);
    buffer.data[16] = 0xff;
    PCHECK(rdp_auth_redirection_parse_finalize_key_agreement_call(buffer.data,
                                                                  buffer.length,
                                                                  &finalize_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_response(&buffer,
                                               RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE,
                                               0,
                                               nt_response_bytes,
                                               sizeof(nt_response_bytes)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_nt_response_response(buffer.data,
                                                           buffer.length,
                                                           &fixed_response) == LIBRDP_STATUS_OK);
    PCHECK(fixed_response.response.status == 0 &&
           fixed_response.data_len == sizeof(nt_response_bytes) &&
           fixed_response.data[23] == 0x17);
    PCHECK(rdp_auth_redirection_parse_response_message(buffer.data,
                                                       buffer.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE &&
           auth_response_message.body.fixed.data_len == sizeof(nt_response_bytes));
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_response(&buffer,
                                               RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT,
                                               0,
                                               session_key_bytes,
                                               sizeof(session_key_bytes)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_user_session_key_response(buffer.data,
                                                                buffer.length,
                                                                &fixed_response) == LIBRDP_STATUS_OK);
    PCHECK(fixed_response.data_len == sizeof(session_key_bytes) && fixed_response.data[15] == 0xff);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_octet_response(&buffer,
                                                     RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY,
                                                     0,
                                                     call_payload,
                                                     sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_octet_response(buffer.data,
                                                     buffer.length,
                                                     RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY,
                                                     &auth_response,
                                                     &auth_octet) == LIBRDP_STATUS_OK);
    PCHECK(auth_octet.length == sizeof(call_payload) &&
           memcmp(auth_octet.value, call_payload, sizeof(call_payload)) == 0);
    PCHECK(rdp_auth_redirection_parse_response_message(buffer.data,
                                                       buffer.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_OCTET_RESPONSE &&
           auth_response_message.body.octet.length == sizeof(call_payload));
    compare_result.nt_equal = 1;
    compare_result.lm_equal = 0;
    compare_result.sha_equal = 1;
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_compare_credentials_response(&buffer, 0, &compare_result) ==
           LIBRDP_STATUS_OK);
    memset(&compare_result, 0, sizeof(compare_result));
    PCHECK(rdp_auth_redirection_parse_compare_credentials_response(buffer.data,
                                                                   buffer.length,
                                                                   &auth_response,
                                                                   &compare_result) == LIBRDP_STATUS_OK);
    PCHECK(auth_response.call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS &&
           compare_result.nt_equal == 1 && compare_result.lm_equal == 0 &&
           compare_result.sha_equal == 1);
    buffer.data[8] = 2;
    PCHECK(rdp_auth_redirection_parse_compare_credentials_response(buffer.data,
                                                                   buffer.length,
                                                                   &auth_response,
                                                                   &compare_result) == LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_negotiate_version_call(
               &buffer,
               RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    packet.length = 0;
    PCHECK(rdp_auth_redirection_write_default_response(&packet,
                                                       &auth_call_message,
                                                       0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response_message(packet.data,
                                                       packet.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_NEGOTIATE_VERSION &&
           auth_response_message.response.status == 0);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                           call_payload,
                                           sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    packet.length = 0;
    PCHECK(rdp_auth_redirection_write_default_response(&packet,
                                                       &auth_call_message,
                                                       0x80004001u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response_message(packet.data,
                                                       packet.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_COMPARE_CREDENTIALS &&
           auth_response_message.response.status == 0x80004001u &&
           auth_response_message.body.compare_credentials.nt_equal == 0 &&
           auth_response_message.body.compare_credentials.lm_equal == 0 &&
           auth_response_message.body.compare_credentials.sha_equal == 0);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_NT_RESPONSE,
                                           call_payload,
                                           sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    packet.length = 0;
    PCHECK(rdp_auth_redirection_write_default_response(&packet,
                                                       &auth_call_message,
                                                       0x80004005u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response_message(packet.data,
                                                       packet.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE &&
           auth_response_message.response.status == 0x80004005u &&
           auth_response_message.body.fixed.data_len == RDP_AUTH_REDIRECTION_NT_RESPONSE_LENGTH);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT,
                                           call_payload,
                                           sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    packet.length = 0;
    PCHECK(rdp_auth_redirection_write_default_response(&packet,
                                                       &auth_call_message,
                                                       0x80004005u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response_message(packet.data,
                                                       packet.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_FIXED_RESPONSE &&
           auth_response_message.response.status == 0x80004005u &&
           auth_response_message.body.fixed.data_len == RDP_AUTH_REDIRECTION_USER_SESSION_KEY_LENGTH);
    buffer.length = 0;
    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_KERB_PACK_AP_REPLY,
                                           NULL,
                                           0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call_message(buffer.data,
                                                   buffer.length,
                                                   &auth_call_message) == LIBRDP_STATUS_OK);
    packet.length = 0;
    PCHECK(rdp_auth_redirection_write_default_response(&packet,
                                                       &auth_call_message,
                                                       0x80004001u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_response_message(packet.data,
                                                       packet.length,
                                                       &auth_response_message) == LIBRDP_STATUS_OK);
    PCHECK(auth_response_message.kind == RDP_AUTH_REDIRECTION_MESSAGE_OCTET_RESPONSE &&
           auth_response_message.response.status == 0x80004001u &&
           auth_response_message.body.octet.length == 0);
    PCHECK(rdp_auth_redirection_write_negotiate_version_call(&packet,
                                                             RDP_AUTH_REDIRECTION_CALL_INVALID) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_auth_redirection_write_inner_buffer(&buffer, call_payload, sizeof(call_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_inner_buffer(buffer.data, buffer.length, &inner) ==
           LIBRDP_STATUS_OK);
    PCHECK(inner.revision == RDP_AUTH_REDIRECTION_INNER_REVISION &&
           inner.payload_len == sizeof(call_payload));
    buffer.data[2] = 1;
    PCHECK(rdp_auth_redirection_parse_inner_buffer(buffer.data, buffer.length, &inner) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_auth_redirection_write_outer_packet(&buffer, call_payload, sizeof(call_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_outer_packet(buffer.data, buffer.length, &outer) ==
           LIBRDP_STATUS_OK);
    PCHECK(outer.protocol_magic == RDP_AUTH_REDIRECTION_MAGIC &&
           outer.length == sizeof(call_payload) &&
           outer.payload_len == sizeof(call_payload));
    buffer.data[8] = 1;
    PCHECK(rdp_auth_redirection_parse_outer_packet(buffer.data, buffer.length, &outer) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_auth_redirection_write_encoded_payload(&buffer,
                                                      RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS,
                                                      call_payload,
                                                      sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_encoded_payload(buffer.data,
                                                      buffer.length,
                                                      &encoded_payload) == LIBRDP_STATUS_OK);
    PCHECK(encoded_payload.package == RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS &&
           encoded_payload.package_name_len == 16u &&
           encoded_payload.payload_len == sizeof(call_payload) &&
           memcmp(encoded_payload.payload, call_payload, sizeof(call_payload)) == 0);
    buffer.data[0] = 0x31;
    PCHECK(rdp_auth_redirection_parse_encoded_payload(buffer.data,
                                                      buffer.length,
                                                      &encoded_payload) == LIBRDP_STATUS_PROTOCOL_ERROR);
    {
        const uint8_t bad_der_payload[] = {
            0x30u, 0x82u, 0x00u, 0x0cu,
            0x81u, 0x08u, 'N', 0, 'T', 0, 'L', 0, 'M', 0,
            0x82u, 0x00u
        };

        PCHECK(rdp_auth_redirection_parse_encoded_payload(bad_der_payload,
                                                          sizeof(bad_der_payload),
                                                          &encoded_payload) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_auth_redirection_write_encoded_payload(&buffer,
                                                      RDP_AUTH_REDIRECTION_PACKAGE_NTLM,
                                                      NULL,
                                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_encoded_payload(buffer.data,
                                                      buffer.length,
                                                      &encoded_payload) == LIBRDP_STATUS_OK);
    PCHECK(encoded_payload.package == RDP_AUTH_REDIRECTION_PACKAGE_NTLM &&
           encoded_payload.package_name_len == 8u &&
           encoded_payload.payload_len == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_auth_redirection_write_encoded_payload(&buffer,
                                                      RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN,
                                                      NULL,
                                                      0) == LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_smartcard_redirection_ioctl_valid(RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT));
    PCHECK(!rdp_smartcard_redirection_ioctl_valid(0x0009010cu));
    PCHECK(rdp_smartcard_redirection_share_mode_valid(RDP_SMARTCARD_REDIRECTION_SHARE_SHARED));
    PCHECK(!rdp_smartcard_redirection_share_mode_valid(0xffffffffu));
    PCHECK(rdp_smartcard_redirection_disposition_valid(RDP_SMARTCARD_REDIRECTION_LEAVE_CARD));
    PCHECK(!rdp_smartcard_redirection_disposition_valid(0xffffffffu));
    PCHECK(rdp_smartcard_redirection_initialization_valid(RDP_SMARTCARD_REDIRECTION_RESET_CARD));
    PCHECK(!rdp_smartcard_redirection_initialization_valid(0xffffffffu));
    PCHECK(rdp_smartcard_redirection_write_establish_context_call(
               &buffer,
               RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_establish_context_call(buffer.data,
                                                                  buffer.length,
                                                                  &establish_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(establish_call.scope == RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               64u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request(packet.data,
                                                                  packet.length,
                                                                  &control_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(control_request.output_buffer_len == 64u &&
           control_request.input_buffer_len == buffer.length &&
           control_request.io_control_code == RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_ESTABLISH_CONTEXT &&
           scard_message.body.establish_context.scope == RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM);
    packet.data[0] = 0x01u;
    packet.data[1] = 0x00u;
    packet.data[2] = 0x40u;
    packet.data[3] = 0x00u;
    PCHECK(rdp_smartcard_redirection_parse_device_control_request(packet.data,
                                                                  packet.length,
                                                                  &control_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    packet.data[0] = 64u;
    packet.data[1] = 0u;
    packet.data[2] = 0u;
    packet.data[3] = 0u;
    packet.data[8] = 0x0c;
    packet.data[9] = 0x01;
    PCHECK(rdp_smartcard_redirection_parse_device_control_request(packet.data,
                                                                  packet.length,
                                                                  &control_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH + 1u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(test_append_device_io_request(&packet,
                                         7u,
                                         8u,
                                         9u,
                                         RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL,
                                         0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               64u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_request(packet.data, packet.length, &io_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(io_request.device_id == 7u &&
           io_request.major_function == RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request(io_request.payload,
                                                                  io_request.payload_len,
                                                                  &control_request) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_smartcard_redirection_write_context(&buffer,
                                                   context_bytes,
                                                   sizeof(context_bytes)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_context(buffer.data, buffer.length, &context) ==
           LIBRDP_STATUS_OK);
    PCHECK(context.length == sizeof(context_bytes) &&
           memcmp(context.data, context_bytes, sizeof(context_bytes)) == 0);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT &&
           scard_message.body.context.length == sizeof(context_bytes));
    packet.length = 0;
    PCHECK(rdp_smartcard_redirection_write_context(&packet,
                                                   context_bytes,
                                                   RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_smartcard_redirection_write_handle(&buffer,
                                                  context_bytes,
                                                  sizeof(context_bytes),
                                                  call_payload,
                                                  sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_handle(buffer.data,
                                                  buffer.length,
                                                  &handle) == LIBRDP_STATUS_OK);
    PCHECK(handle.context.length == sizeof(context_bytes) &&
           handle.length == sizeof(call_payload) &&
           memcmp(handle.data, call_payload, sizeof(call_payload)) == 0);
    buffer.data[4 + sizeof(context_bytes)] = RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH + 1u;
    PCHECK(rdp_smartcard_redirection_parse_handle(buffer.data,
                                                  buffer.length,
                                                  &handle) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_write_atr_mask(&buffer,
                                                    scard_extra,
                                                    sizeof(scard_extra),
                                                    scard_atr_mask) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_atr_mask(buffer.data,
                                                    buffer.length,
                                                    &atr_mask) == LIBRDP_STATUS_OK);
    PCHECK(atr_mask.atr_len == sizeof(scard_extra) && atr_mask.atr[2] == 0x03);
    buffer.data[0] = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH + 1u;
    PCHECK(rdp_smartcard_redirection_parse_atr_mask(buffer.data,
                                                    buffer.length,
                                                    &atr_mask) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_write_reader_state_common(&buffer,
                                                               1u,
                                                               2u,
                                                               scard_extra,
                                                               sizeof(scard_extra)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_reader_state_common(buffer.data,
                                                               buffer.length,
                                                               &reader_state) == LIBRDP_STATUS_OK);
    PCHECK(reader_state.current_state == 1u &&
           reader_state.event_state == 2u &&
           reader_state.atr_len == sizeof(scard_extra));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_bool_valid(0));
    PCHECK(rdp_smartcard_redirection_bool_valid(1));
    PCHECK(!rdp_smartcard_redirection_bool_valid(2));
    PCHECK(rdp_smartcard_redirection_protocol_mask_valid(RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED));
    PCHECK(rdp_smartcard_redirection_protocol_mask_valid(RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 |
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1));
    PCHECK(rdp_smartcard_redirection_protocol_mask_valid(RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 |
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW |
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT));
    PCHECK(rdp_smartcard_redirection_protocol_mask_valid(RDP_SMARTCARD_REDIRECTION_PROTOCOL_T15 |
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT));
    PCHECK(!rdp_smartcard_redirection_protocol_mask_valid(0x00020000u));
    PCHECK(rdp_smartcard_redirection_write_scard_io_request(
               &buffer,
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
               scard_extra,
               sizeof(scard_extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_scard_io_request(buffer.data,
                                                            buffer.length,
                                                            &scard_io) == LIBRDP_STATUS_OK);
    PCHECK(scard_io.protocol == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 &&
           scard_io.extra_bytes_len == sizeof(scard_extra) &&
           memcmp(scard_io.extra_bytes, scard_extra, sizeof(scard_extra)) == 0);
    buffer.data[4] = 0xff;
    buffer.data[5] = 0x04;
    PCHECK(rdp_smartcard_redirection_parse_scard_io_request(buffer.data,
                                                            buffer.length,
                                                            &scard_io) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_smartcard_redirection_write_scard_io_request(
               &packet,
               0x00020000u,
               scard_extra,
               sizeof(scard_extra)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_scard_io_request(
               &packet,
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0,
               scard_extra,
               RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_smartcard_redirection_write_state_call(&buffer,
                                                      context_bytes,
                                                      sizeof(context_bytes),
                                                      call_payload,
                                                      sizeof(call_payload),
                                                      0,
                                                      RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_state_call(buffer.data,
                                                      buffer.length,
                                                      &state_call) == LIBRDP_STATUS_OK);
    PCHECK(state_call.atr_len == RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH);
    buffer.data[buffer.length - 4u] = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH + 1u;
    PCHECK(rdp_smartcard_redirection_parse_state_call(buffer.data,
                                                      buffer.length,
                                                      &state_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[buffer.length - 4u] = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    PCHECK(rdp_smartcard_redirection_write_state_call(&packet,
                                                      context_bytes,
                                                      sizeof(context_bytes),
                                                      call_payload,
                                                      sizeof(call_payload),
                                                      0,
                                                      RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_STATE,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_STATE);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_status_call(&buffer,
                                                       context_bytes,
                                                       sizeof(context_bytes),
                                                       call_payload,
                                                       sizeof(call_payload),
                                                       0,
                                                       32u,
                                                       36u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_status_call(buffer.data,
                                                       buffer.length,
                                                       &status_call) == LIBRDP_STATUS_OK);
    PCHECK(status_call.reader_len == 32u && status_call.atr_len == 36u);
    buffer.data[buffer.length - 4u] = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH + 1u;
    PCHECK(rdp_smartcard_redirection_parse_status_call(buffer.data,
                                                       buffer.length,
                                                       &status_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[buffer.length - 4u] = RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH;
    PCHECK(rdp_smartcard_redirection_write_status_call(&packet,
                                                       context_bytes,
                                                       sizeof(context_bytes),
                                                       call_payload,
                                                       sizeof(call_payload),
                                                       0,
                                                       32u,
                                                       RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSW,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_STATUS);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_transmit_call(&buffer,
                                                         context_bytes,
                                                         sizeof(context_bytes),
                                                         call_payload,
                                                         sizeof(call_payload),
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
                                                         scard_extra,
                                                         sizeof(scard_extra),
                                                         call_payload,
                                                         sizeof(call_payload),
                                                         1,
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0,
                                                         NULL,
                                                         0,
                                                         0,
                                                         64u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_transmit_call(buffer.data,
                                                         buffer.length,
                                                         &transmit_call) == LIBRDP_STATUS_OK);
    PCHECK(transmit_call.send_pci.protocol == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 &&
           transmit_call.send_len == sizeof(call_payload) &&
           transmit_call.recv_pci_present == 1u &&
           transmit_call.recv_len == 64u);
    buffer.data[buffer.length - 4u] = 0x01u;
    buffer.data[buffer.length - 3u] = 0x04u;
    buffer.data[buffer.length - 2u] = 0x01u;
    buffer.data[buffer.length - 1u] = 0x00u;
    PCHECK(rdp_smartcard_redirection_parse_transmit_call(buffer.data,
                                                         buffer.length,
                                                         &transmit_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[buffer.length - 4u] = 64u;
    buffer.data[buffer.length - 3u] = 0u;
    buffer.data[buffer.length - 2u] = 0u;
    buffer.data[buffer.length - 1u] = 0u;
    PCHECK(rdp_smartcard_redirection_write_transmit_call(
               &packet,
               context_bytes,
               sizeof(context_bytes),
               call_payload,
               sizeof(call_payload),
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
               scard_extra,
               sizeof(scard_extra),
               call_payload,
               sizeof(call_payload),
               1,
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0,
               NULL,
               0,
               0,
               RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_TRANSMIT);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_control_call(&buffer,
                                                        context_bytes,
                                                        sizeof(context_bytes),
                                                        call_payload,
                                                        sizeof(call_payload),
                                                        0x42000000u,
                                                        scard_extra,
                                                        sizeof(scard_extra),
                                                        0,
                                                        128u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_control_call(buffer.data,
                                                        buffer.length,
                                                        &control_call) == LIBRDP_STATUS_OK);
    PCHECK(control_call.control_code == 0x42000000u &&
           control_call.input_len == sizeof(scard_extra) &&
           control_call.output_len == 128u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_CONTROL,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTROL);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_attrib_call(&buffer,
                                                       context_bytes,
                                                       sizeof(context_bytes),
                                                       call_payload,
                                                       sizeof(call_payload),
                                                       0x00090303u,
                                                       0,
                                                       16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_attrib_call(buffer.data,
                                                       buffer.length,
                                                       &attrib_call) == LIBRDP_STATUS_OK);
    PCHECK(attrib_call.attr_id == 0x00090303u && attrib_call.attr_len == 16u);
    buffer.data[buffer.length - 4u] = 0x01u;
    buffer.data[buffer.length - 3u] = 0x00u;
    buffer.data[buffer.length - 2u] = 0x01u;
    buffer.data[buffer.length - 1u] = 0x00u;
    PCHECK(rdp_smartcard_redirection_parse_attrib_call(buffer.data,
                                                       buffer.length,
                                                       &attrib_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[buffer.length - 4u] = 16u;
    buffer.data[buffer.length - 3u] = 0u;
    buffer.data[buffer.length - 2u] = 0u;
    buffer.data[buffer.length - 1u] = 0u;
    PCHECK(rdp_smartcard_redirection_write_attrib_call(&packet,
                                                       context_bytes,
                                                       sizeof(context_bytes),
                                                       call_payload,
                                                       sizeof(call_payload),
                                                       0x00090303u,
                                                       0,
                                                       RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_ATTRIB);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_set_attrib_call(&buffer,
                                                           context_bytes,
                                                           sizeof(context_bytes),
                                                           call_payload,
                                                           sizeof(call_payload),
                                                           0x00090303u,
                                                           scard_extra,
                                                           sizeof(scard_extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_set_attrib_call(buffer.data,
                                                           buffer.length,
                                                           &set_attrib_call) == LIBRDP_STATUS_OK);
    PCHECK(set_attrib_call.attr_id == 0x00090303u &&
           set_attrib_call.attr_len == sizeof(scard_extra));
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_SETATTRIB,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_SET_ATTRIB);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_smartcard_redirection_write_connect_common(
               &buffer,
               context_bytes,
               sizeof(context_bytes),
               RDP_SMARTCARD_REDIRECTION_SHARE_SHARED,
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_connect_common(buffer.data,
                                                          buffer.length,
                                                          &connect_common) == LIBRDP_STATUS_OK);
    PCHECK(connect_common.share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_SHARED &&
           connect_common.preferred_protocols == RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONNECT &&
           scard_message.body.connect.share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_SHARED &&
           scard_message.body.connect.preferred_protocols == RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX);
    packet.length = 0;
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_context(&buffer,
                                                   context_bytes,
                                                   sizeof(context_bytes)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, (uint32_t)sizeof(scard_reader_name)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&buffer, scard_reader_name, sizeof(scard_reader_name)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_connect_common(buffer.data,
                                                          buffer.length,
                                                          &connect_common) == LIBRDP_STATUS_OK);
    PCHECK(connect_common.reader_name_is_null == 0 &&
           connect_common.reader_name_len == sizeof(scard_reader_name) &&
           memcmp(connect_common.reader_name, scard_reader_name, sizeof(scard_reader_name)) == 0 &&
           connect_common.share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONNECT &&
           scard_message.body.connect.reader_name_len == sizeof(scard_reader_name) &&
           memcmp(scard_message.body.connect.reader_name,
                  scard_reader_name,
                  sizeof(scard_reader_name)) == 0);
    packet.length = 0;
    buffer.data[4u + sizeof(context_bytes)] = 1u;
    PCHECK(rdp_smartcard_redirection_parse_connect_common(buffer.data,
                                                          buffer.length,
                                                          &connect_common) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[4u + sizeof(context_bytes)] = 0u;
    buffer.data[8 + sizeof(context_bytes)] = 0x10;
    PCHECK(rdp_smartcard_redirection_parse_connect_common(buffer.data,
                                                          buffer.length,
                                                          &connect_common) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_write_list_reader_groups_call(&buffer,
                                                                   context_bytes,
                                                                   sizeof(context_bytes),
                                                                   0,
                                                                   64u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_list_reader_groups_call(buffer.data,
                                                                   buffer.length,
                                                                   &list_groups_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(list_groups_call.context.length == sizeof(context_bytes) &&
           list_groups_call.groups_len == 64u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READER_GROUPS &&
           scard_message.body.list_reader_groups.groups_len == 64u);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_list_readers_call(&buffer,
                                                            context_bytes,
                                                            sizeof(context_bytes),
                                                            0,
                                                            "SCard$DefaultReaders\0\0",
                                                            22u,
                                                            0,
                                                            128u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_list_readers_call(buffer.data,
                                                            buffer.length,
                                                            &list_readers_call) == LIBRDP_STATUS_OK);
    PCHECK(list_readers_call.context.length == sizeof(context_bytes) &&
           list_readers_call.groups_len == 22u &&
           list_readers_call.readers_len == 128u &&
           list_readers_call.groups[0] == 'S');
    buffer.data[4u + sizeof(context_bytes)] = 1u;
    PCHECK(rdp_smartcard_redirection_parse_list_readers_call(buffer.data,
                                                            buffer.length,
                                                            &list_readers_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.data[4u + sizeof(context_bytes)] = 0u;
    PCHECK(rdp_smartcard_redirection_write_list_readers_call(&packet,
                                                            context_bytes,
                                                            sizeof(context_bytes),
                                                            1,
                                                            "S",
                                                            1u,
                                                            0,
                                                            128u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_LIST_READERS &&
           scard_message.body.list_readers.readers_len == 128u);
    packet.length = 0;
    buffer.data[4 + sizeof(context_bytes) + 4] = 0xff;
    buffer.data[5 + sizeof(context_bytes) + 4] = 0xff;
    buffer.data[6 + sizeof(context_bytes) + 4] = 0xff;
    buffer.data[7 + sizeof(context_bytes) + 4] = 0xff;
    PCHECK(rdp_smartcard_redirection_parse_list_readers_call(buffer.data,
                                                            buffer.length,
                                                            &list_readers_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_write_string(&buffer, 0, "Group A", 8u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_string(buffer.data, buffer.length, &scard_string) ==
           LIBRDP_STATUS_OK);
    PCHECK(!scard_string.is_null && scard_string.length == 8u && scard_string.data[0] == 'G');
    buffer.data[0] = 1u;
    PCHECK(rdp_smartcard_redirection_parse_string(buffer.data, buffer.length, &scard_string) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_string(&buffer, 1, "bad", 3u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_smartcard_redirection_write_context_string_call(&buffer,
                                                               context_bytes,
                                                               sizeof(context_bytes),
                                                               0,
                                                               "Group A",
                                                               8u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_context_string_call(buffer.data,
                                                               buffer.length,
                                                               &context_string_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(context_string_call.context.length == sizeof(context_bytes) &&
           context_string_call.value.length == 8u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_STRING &&
           scard_message.body.context_string.value.data[0] == 'G');
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_context_two_strings_call(&buffer,
                                                                    context_bytes,
                                                                    sizeof(context_bytes),
                                                                    0,
                                                                    "Reader A",
                                                                    9u,
                                                                    0,
                                                                    "Group A",
                                                                    8u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_context_two_strings_call(
               buffer.data,
               buffer.length,
               &context_two_strings_call) == LIBRDP_STATUS_OK);
    PCHECK(context_two_strings_call.first.length == 9u &&
           context_two_strings_call.second.length == 8u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT_TWO_STRINGS &&
           scard_message.body.context_two_strings.first.data[0] == 'R');
    buffer.length = 0;
    packet.length = 0;

    memset(status_readers, 0, sizeof(status_readers));
    status_readers[0].reader_name_is_null = 0;
    status_readers[0].reader_name = (const uint8_t*)"Reader A";
    status_readers[0].reader_name_len = 8u;
    status_readers[0].state.current_state = 0x10u;
    status_readers[0].state.event_state = 0x20u;
    status_readers[0].state.atr_len = sizeof(scard_extra);
    memcpy(status_readers[0].state.atr, scard_extra, sizeof(scard_extra));

    PCHECK(rdp_smartcard_redirection_write_locate_cards_call(&buffer,
                                                             context_bytes,
                                                             sizeof(context_bytes),
                                                             0,
                                                             "Card A\0\0",
                                                             8u,
                                                             status_readers,
                                                             1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_locate_cards_call(buffer.data,
                                                             buffer.length,
                                                             &locate_cards_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(locate_cards_call.reader_count == 1u &&
           locate_cards_call.card_names.length == 8u &&
           locate_cards_call.readers[0].state.atr_len == sizeof(scard_extra));
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS &&
           scard_message.body.locate_cards.reader_count == 1u);
    buffer.length = 0;
    packet.length = 0;

    atr_mask.atr_len = sizeof(scard_extra);
    memcpy(atr_mask.atr, scard_extra, sizeof(scard_extra));
    memcpy(atr_mask.mask, scard_atr_mask, sizeof(atr_mask.mask));
    PCHECK(rdp_smartcard_redirection_write_locate_cards_by_atr_call(&buffer,
                                                                    context_bytes,
                                                                    sizeof(context_bytes),
                                                                    &atr_mask,
                                                                    1u,
                                                                    status_readers,
                                                                    1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_locate_cards_by_atr_call(buffer.data,
                                                                    buffer.length,
                                                                    &locate_atr_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(locate_atr_call.atr_count == 1u &&
           locate_atr_call.reader_count == 1u &&
           locate_atr_call.atr_masks[0].atr_len == sizeof(scard_extra));
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_LOCATE_CARDS_BY_ATR &&
           scard_message.body.locate_cards_by_atr.atr_count == 1u);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_read_cache_call(&buffer,
                                                           context_bytes,
                                                           sizeof(context_bytes),
                                                           card_identifier,
                                                           7u,
                                                           0,
                                                           "cache-key",
                                                           10u,
                                                           0,
                                                           256u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_read_cache_call(buffer.data,
                                                           buffer.length,
                                                           &read_cache_call) == LIBRDP_STATUS_OK);
    PCHECK(read_cache_call.freshness_counter == 7u &&
           read_cache_call.lookup_name.length == 10u &&
           read_cache_call.data_len == 256u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READ_CACHE &&
           scard_message.body.read_cache.data_len == 256u);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_write_cache_call(&buffer,
                                                            context_bytes,
                                                            sizeof(context_bytes),
                                                            card_identifier,
                                                            8u,
                                                            0,
                                                            "cache-key",
                                                            10u,
                                                            scard_extra,
                                                            sizeof(scard_extra)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_write_cache_call(buffer.data,
                                                            buffer.length,
                                                            &write_cache_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(write_cache_call.freshness_counter == 8u &&
           write_cache_call.data_len == sizeof(scard_extra) &&
           write_cache_call.data[2] == 3u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_WRITE_CACHE &&
           scard_message.body.write_cache.data_len == sizeof(scard_extra));
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_reader_name_call(&buffer,
                                                            context_bytes,
                                                            sizeof(context_bytes),
                                                            0,
                                                            scard_reader_name,
                                                            sizeof(scard_reader_name),
                                                            0,
                                                            512u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_reader_name_call(buffer.data,
                                                            buffer.length,
                                                            &reader_name_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(reader_name_call.reader_name.length == sizeof(scard_reader_name) &&
           reader_name_call.output_len == 512u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READER_NAME &&
           scard_message.body.reader_name.output_len == 512u);
    buffer.length = 0;
    packet.length = 0;
    PCHECK(rdp_smartcard_redirection_write_reader_name_call(&buffer,
                                                            context_bytes,
                                                            sizeof(context_bytes),
                                                            0,
                                                            scard_reader_name,
                                                            sizeof(scard_reader_name),
                                                            0,
                                                            4u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_READER_NAME &&
           scard_message.body.reader_name.output_len == 4u);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_count_return(&buffer, 0, 0x20u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_count_return(buffer.data,
                                                        buffer.length,
                                                        &count_result) == LIBRDP_STATUS_OK);
    PCHECK(count_result.return_code == 0 && count_result.value == 0x20u);
    buffer.length = 0;
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_ACCESSSTARTEDEVENT,
               NULL,
               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_ACCESS_STARTED_EVENT);
    packet.length = 0;

    PCHECK(rdp_smartcard_redirection_write_get_status_change_call(&buffer,
                                                                  context_bytes,
                                                                  sizeof(context_bytes),
                                                                  250u,
                                                                  status_readers,
                                                                  1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_get_status_change_call(buffer.data,
                                                                  buffer.length,
                                                                  &get_status_change_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(get_status_change_call.timeout == 250u &&
           get_status_change_call.reader_count == 1u &&
           get_status_change_call.readers[0].state.current_state == 0x10u &&
           get_status_change_call.readers[0].reader_name_len == 8u);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEA,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_GET_STATUS_CHANGE &&
           scard_message.body.get_status_change.reader_count == 1u);
    buffer.length = 0;
    packet.length = 0;
    PCHECK(rdp_smartcard_redirection_write_get_status_change_return(&buffer,
                                                                    0,
                                                                    &status_readers[0].state,
                                                                    1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_get_status_change_return(buffer.data,
                                                                    buffer.length,
                                                                    &get_status_change_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(get_status_change_result.return_code == 0 &&
           get_status_change_result.reader_count == 1u &&
           get_status_change_result.readers[0].event_state == 0x20u);
    buffer.length = 0;

    PCHECK(rdp_smartcard_redirection_write_reconnect_call(
               &buffer,
               context_bytes,
               sizeof(context_bytes),
               call_payload,
               sizeof(call_payload),
               RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE,
               RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 | RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT,
               RDP_SMARTCARD_REDIRECTION_RESET_CARD) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_reconnect_call(buffer.data,
                                                          buffer.length,
                                                          &reconnect_call) == LIBRDP_STATUS_OK);
    PCHECK(reconnect_call.handle.length == sizeof(call_payload) &&
           reconnect_call.share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE &&
           reconnect_call.initialization == RDP_SMARTCARD_REDIRECTION_RESET_CARD);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_RECONNECT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_RECONNECT &&
           scard_message.body.reconnect.share_mode == RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE);
    packet.length = 0;
    buffer.data[buffer.length - 4u] = RDP_SMARTCARD_REDIRECTION_EJECT_CARD;
    PCHECK(rdp_smartcard_redirection_parse_reconnect_call(buffer.data,
                                                          buffer.length,
                                                          &reconnect_call) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_write_handle_disposition_call(
               &buffer,
               context_bytes,
               sizeof(context_bytes),
               call_payload,
               sizeof(call_payload),
               RDP_SMARTCARD_REDIRECTION_EJECT_CARD) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_handle_disposition_call(buffer.data,
                                                                   buffer.length,
                                                                   &disposition_call) ==
           LIBRDP_STATUS_OK);
    PCHECK(disposition_call.disposition == RDP_SMARTCARD_REDIRECTION_EJECT_CARD);
    PCHECK(rdp_smartcard_redirection_write_device_control_request(
               &packet,
               4u,
               RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT,
               buffer.data,
               (uint32_t)buffer.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_device_control_request_message(
               packet.data,
               packet.length,
               &scard_message) == LIBRDP_STATUS_OK);
    PCHECK(scard_message.kind == RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE_DISPOSITION &&
           scard_message.body.handle_disposition.disposition == RDP_SMARTCARD_REDIRECTION_EJECT_CARD);
    packet.length = 0;
    PCHECK(rdp_smartcard_redirection_write_handle_disposition_call(
               &packet,
               context_bytes,
               sizeof(context_bytes),
               call_payload,
               sizeof(call_payload),
               4u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_smartcard_redirection_write_long_return(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_long_return(buffer.data, buffer.length, &long_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(long_result.return_code == 0);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_count_return(&buffer, 0x80100069u, 42u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_count_return(buffer.data,
                                                        buffer.length,
                                                        &count_result) == LIBRDP_STATUS_OK);
    PCHECK(count_result.return_code == 0x80100069u && count_result.value == 42u);
    PCHECK(rdp_smartcard_redirection_parse_count_return(buffer.data,
                                                        buffer.length - 1u,
                                                        &count_result) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_buffer_return(&buffer,
                                                         0,
                                                         scard_extra,
                                                         sizeof(scard_extra)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_buffer_return(buffer.data,
                                                         buffer.length,
                                                         sizeof(scard_extra),
                                                         &buffer_result) == LIBRDP_STATUS_OK);
    PCHECK(buffer_result.return_code == 0 &&
           buffer_result.data_len == sizeof(scard_extra) &&
           memcmp(buffer_result.data, scard_extra, sizeof(scard_extra)) == 0);
    PCHECK(rdp_smartcard_redirection_parse_buffer_return(buffer.data,
                                                         buffer.length,
                                                         sizeof(scard_extra) - 1u,
                                                         &buffer_result) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_smartcard_redirection_write_buffer_return(&packet,
                                                         0,
                                                         scard_extra,
                                                         RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_establish_context_return(&buffer,
                                                                    0,
                                                                    context_bytes,
                                                                    sizeof(context_bytes)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_establish_context_return(buffer.data,
                                                                    buffer.length,
                                                                    &establish_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(establish_result.return_code == 0 &&
           establish_result.context.length == sizeof(context_bytes));
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_connect_return(&buffer,
                                                          0,
                                                          context_bytes,
                                                          sizeof(context_bytes),
                                                          call_payload,
                                                          sizeof(call_payload),
                                                          RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_connect_return(buffer.data,
                                                          buffer.length,
                                                          &connect_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(connect_result.return_code == 0 &&
           connect_result.handle.context.length == sizeof(context_bytes) &&
           connect_result.handle.length == sizeof(call_payload) &&
           connect_result.active_protocol == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_reconnect_return(&buffer,
                                                            0,
                                                            RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_count_return(buffer.data,
                                                        buffer.length,
                                                        &count_result) == LIBRDP_STATUS_OK);
    PCHECK(count_result.return_code == 0 &&
           count_result.value == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0);
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_status_return(&buffer,
                                                         0,
                                                         "reader\0",
                                                         7u,
                                                         0x22u,
                                                         RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
                                                         scard_extra,
                                                         sizeof(scard_extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_status_return(buffer.data,
                                                         buffer.length,
                                                         &status_result) == LIBRDP_STATUS_OK);
    PCHECK(status_result.return_code == 0 &&
           status_result.reader_names_len == 7u &&
           status_result.state == 0x22u &&
           status_result.protocol == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 &&
           status_result.atr_len == sizeof(scard_extra));
    buffer.length = 0;
    PCHECK(rdp_smartcard_redirection_write_transmit_return(&buffer,
                                                           0,
                                                           RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1,
                                                           NULL,
                                                           0,
                                                           call_payload,
                                                           sizeof(call_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_parse_transmit_return(buffer.data,
                                                           buffer.length,
                                                           &transmit_result) ==
           LIBRDP_STATUS_OK);
    PCHECK(transmit_result.return_code == 0 &&
           transmit_result.recv_protocol == RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 &&
           transmit_result.recv_data_len == sizeof(call_payload));
    PCHECK(rdp_smartcard_redirection_write_device_control_response(&packet,
                                                                   buffer.data,
                                                                   (uint32_t)buffer.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_write_device_control_response(
               &packet,
               call_payload,
               RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH + 1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_smartcard_redirection_parse_device_control_response(packet.data,
                                                                   packet.length,
                                                                   &control_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(control_response.output_buffer_len == buffer.length &&
           control_response.output_len == buffer.length);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_device_redirection_write_io_completion(&packet,
                                                      7u,
                                                      9u,
                                                      RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                      NULL,
                                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_smartcard_redirection_write_device_control_response(&packet,
                                                                   buffer.data,
                                                                   (uint32_t)buffer.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_completion(packet.data, packet.length, &io_completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(io_completion.device_id == 7u &&
           io_completion.completion_id == 9u &&
           io_completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    PCHECK(rdp_smartcard_redirection_parse_device_control_response(io_completion.payload,
                                                                   io_completion.payload_len,
                                                                   &control_response) ==
           LIBRDP_STATUS_OK);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates desktop composition parser/writer vectors and surface
 * metadata bounds independent of a compositor backend.
 */

int test_protocol_channel_vectors(void)
{
    if (test_session_selection_and_echo() != 0)
        return 1;
    if (test_port_redirection_channel() != 0)
        return 1;
    if (test_video_capture_channel() != 0)
        return 1;
    if (test_webauthn_channel() != 0)
        return 1;
    if (test_remote_programs_channel() != 0)
        return 1;
    if (test_audio_channels() != 0)
        return 1;
    if (test_device_redirection_channel() != 0)
        return 1;
    if (test_filesystem_redirection_channel() != 0)
        return 1;
    if (test_printer_redirection_channel() != 0)
        return 1;
    if (test_telemetry_multiparty_channels() != 0)
        return 1;
    if (test_xps_print_channel() != 0)
        return 1;
    if (test_auth_smartcard_redirection_channels() != 0)
        return 1;
    return 0;
}
