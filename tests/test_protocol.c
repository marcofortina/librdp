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
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/gdi_orders.h"
#include "graphics/nscodec.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
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

static int test_sha256_three(const uint8_t* a,
                             size_t a_len,
                             const uint8_t* b,
                             size_t b_len,
                             const uint8_t* c,
                             size_t c_len,
                             uint8_t out[32])
{
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    unsigned int got = 0;
    int ok = 0;

    if (!context)
        return 0;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto out;
    if (EVP_DigestUpdate(context, a, a_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, b, b_len) != 1)
        goto out;
    if (EVP_DigestUpdate(context, c, c_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, out, &got) != 1 || got != 32u)
        goto out;
    ok = 1;

out:
    EVP_MD_CTX_free(context);
    return ok;
}

static int test_contains_bytes(const uint8_t* data, size_t data_len, const char* needle, size_t needle_len)
{
    size_t i = 0;

    if (!data || !needle || needle_len == 0 || data_len < needle_len)
        return 0;
    for (i = 0; i <= data_len - needle_len; i++)
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
    buffer.data[0] = 0x0fu;
    PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_session_selection_parse_pdu(invalid_v1, sizeof(invalid_v1), &selection) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_session_selection_write_v2(&buffer, 0, text_utf16, 5) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == RDP_SESSION_SELECTION_V2_HEADER_LENGTH + sizeof(text_utf16));
    PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) == LIBRDP_STATUS_OK);
    PCHECK(selection.version == RDP_SESSION_SELECTION_VERSION2 && selection.text_chars == 5);
    PCHECK(memcmp(selection.text_utf16le, text_utf16, sizeof(text_utf16)) == 0);
    buffer.data[16] = 6;
    PCHECK(rdp_session_selection_parse_pdu(buffer.data, buffer.length, &selection) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_echo_channel_parse_request(echo_payload, sizeof(echo_payload), &echo) == LIBRDP_STATUS_OK);
    PCHECK(echo.payload_len == sizeof(echo_payload) && memcmp(echo.payload, echo_payload, sizeof(echo_payload)) == 0);
    PCHECK(rdp_echo_channel_write_response(&buffer, echo.payload, echo.payload_len) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == sizeof(echo_payload) && memcmp(buffer.data, echo_payload, sizeof(echo_payload)) == 0);
    PCHECK(rdp_echo_channel_parse_response(buffer.data, buffer.length, &echo) == LIBRDP_STATUS_OK);
    PCHECK(echo.payload_len == sizeof(echo_payload));
    PCHECK(rdp_echo_channel_write_request(&buffer, NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&buffer);
    return 0;
}

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
    uint8_t sample_error_index = 0;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(strcmp(RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME, "RDCamera_Device_Enumerator") == 0);
    PCHECK(strcmp(RDP_VIDEO_CAPTURE_CHANNEL_NAME, "rdpecam") == 0);

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
    return 0;
}

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
    const uint8_t truncated_cbor[] = {0xa1, 0x63, 'k', 'e', 'y'};
    const uint8_t trailing_cbor[] = {0x01, 0x02};
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
    PCHECK(rdp_webauthn_validate_cbor(truncated_cbor, sizeof(truncated_cbor)) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_webauthn_validate_cbor(trailing_cbor, sizeof(trailing_cbor)) ==
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
    rdp_remote_programs_opaque opaque;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_remote_programs_order_valid(RDP_REMOTE_PROGRAMS_ORDER_EXEC));
    PCHECK(!rdp_remote_programs_order_valid(0x7777u));
    PCHECK(rdp_remote_programs_exec_flags_valid(RDP_REMOTE_PROGRAMS_EXEC_FLAG_FILE |
                                                RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES));
    PCHECK(!rdp_remote_programs_exec_flags_valid(RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES));

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

static int test_tpkt_x224(void)
{
    rdp_buffer x224;
    rdp_buffer standard_x224;
    rdp_buffer x224_data;
    rdp_buffer packet;
    rdp_tpkt parsed;
    rdp_x224_connection_confirm confirm;
    const uint8_t* mcs_payload = NULL;
    size_t mcs_payload_len = 0;
    const uint8_t cc_payload[] = {
        0x0e, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00,
        0x02, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t bad_tpkt[] = {0x03, 0x00, 0x00, 0x03};

    rdp_buffer_init(&x224);
    rdp_buffer_init(&standard_x224);
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    PCHECK(rdp_x224_build_connection_request(&standard_x224, NULL, RDP_X224_PROTOCOL_STANDARD) ==
           LIBRDP_STATUS_OK);
    PCHECK(standard_x224.length == 7);
    PCHECK(standard_x224.data[0] == 6 && standard_x224.data[1] == 0xe0);

    PCHECK(rdp_x224_build_connection_request(&x224, "user", RDP_X224_PROTOCOL_TLS | RDP_X224_PROTOCOL_NLA) ==
           LIBRDP_STATUS_OK);
    PCHECK(x224.length > 8);
    PCHECK(x224.data[1] == 0xe0);
    PCHECK(rdp_tpkt_write(&packet, x224.data, x224.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_tpkt_parse(packet.data, packet.length, &parsed) == LIBRDP_STATUS_OK);
    PCHECK(parsed.payload_len == x224.length);
    PCHECK(memcmp(parsed.payload, x224.data, x224.length) == 0);
    PCHECK(rdp_tpkt_parse(bad_tpkt, sizeof(bad_tpkt), &parsed) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_x224_parse_connection_confirm(cc_payload, sizeof(cc_payload), &confirm) == LIBRDP_STATUS_OK);
    PCHECK(confirm.destination_ref == 0x1234);
    PCHECK(confirm.source_ref == 0x5678);
    PCHECK(confirm.negotiation.present);
    PCHECK(!confirm.negotiation.failure);
    PCHECK(confirm.negotiation.selected_protocol == 0);
    PCHECK(rdp_x224_parse_connection_confirm(cc_payload, 4, &confirm) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_x224_wrap_data(&x224_data, cc_payload, sizeof(cc_payload)) == LIBRDP_STATUS_OK);
    PCHECK(x224_data.length == sizeof(cc_payload) + 3u);
    PCHECK(x224_data.data[0] == 0x02 && x224_data.data[1] == 0xf0 && x224_data.data[2] == 0x80);
    PCHECK(rdp_x224_parse_data(x224_data.data, x224_data.length, &mcs_payload, &mcs_payload_len) == LIBRDP_STATUS_OK);
    PCHECK(mcs_payload_len == sizeof(cc_payload));
    PCHECK(memcmp(mcs_payload, cc_payload, sizeof(cc_payload)) == 0);
    PCHECK(rdp_x224_parse_data(cc_payload, sizeof(cc_payload), &mcs_payload, &mcs_payload_len) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
    rdp_buffer_free(&standard_x224);
    rdp_buffer_free(&x224);
    return 0;
}

static int test_mcs_gcc_capabilities(void)
{
    const uint8_t ber_short[] = {0x7f};
    const uint8_t ber_long[] = {0x82, 0x01, 0x23};
    const uint8_t ber_bad[] = {0x80};
    const uint8_t mcs_resp[] = {0x0a, 0x01, 0x00};
    const uint8_t mcs_wrapped_resp[] = {0x7f, 0x66, 0x03, 0x0a, 0x01, 0x00};
    const uint8_t mcs_resp_user_data[] = {0x7f, 0x66, 0x08, 0x0a, 0x01, 0x00, 0x04, 0x03, 7, 8, 9};
    const uint8_t gcc_block[] = {0xc1, 0x00, 0x08, 0x00, 1, 2, 3, 4};
    const uint8_t gcc_server_blocks[] = {
        0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x0c, 0x0a, 0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03
    };
    const uint8_t gcc_response[] = {
        0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x34, 0x14, 0x00, 0x03, 0x01, 0x2a, 0x00, 0x01,
        0xc0, 0x00, 'M',  'c',  'D',  'n',  0x26,
        0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x0c, 0x0a, 0x00, 0xeb, 0x03, 0x01, 0x00, 0xec, 0x03
    };
    const uint8_t caps[] = {
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        0x02, 0x00, 0x04, 0x00
    };
    rdp_stream stream;
    size_t length = 0;
    rdp_mcs_connect_response response;
    rdp_gcc_user_data_block block;
    rdp_capability_list list;
    rdp_buffer ber;
    rdp_buffer client_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs_initial;
    rdp_buffer mcs_domain;
    rdp_gcc_client_config config;
    rdp_gcc_client_data_summary summary;
    rdp_gcc_conference_response conference_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach;
    rdp_mcs_channel_join_confirm join;
    const uint8_t attach_confirm[] = {0x2e, 0x00, 0x00, 0x03};
    const uint8_t join_confirm[] = {0x3e, 0x00, 0x00, 0x03, 0x03, 0xec, 0x03, 0xec};

    rdp_buffer_init(&ber);
    rdp_buffer_init(&client_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs_initial);
    rdp_buffer_init(&mcs_domain);

    rdp_stream_init(&stream, ber_short, sizeof(ber_short));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_OK && length == 0x7f);
    rdp_stream_init(&stream, ber_long, sizeof(ber_long));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_OK && length == 0x123);
    rdp_stream_init(&stream, ber_bad, sizeof(ber_bad));
    PCHECK(rdp_mcs_read_ber_length(&stream, &length) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_mcs_parse_connect_response(mcs_resp, sizeof(mcs_resp), &response) == LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(rdp_mcs_parse_connect_response(mcs_wrapped_resp, sizeof(mcs_wrapped_resp), &response) == LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(rdp_mcs_parse_connect_response(mcs_resp_user_data, sizeof(mcs_resp_user_data), &response) ==
           LIBRDP_STATUS_OK);
    PCHECK(response.has_result && response.result == 0);
    PCHECK(response.user_data_len == 3 && response.user_data[0] == 7 && response.user_data[2] == 9);

    PCHECK(rdp_mcs_write_ber_length(&ber, 0x7f) == LIBRDP_STATUS_OK);
    PCHECK(rdp_mcs_write_ber_length(&ber, 0x123) == LIBRDP_STATUS_OK);
    PCHECK(ber.length == 4);
    PCHECK(ber.data[0] == 0x7f && ber.data[1] == 0x82 && ber.data[2] == 0x01 && ber.data[3] == 0x23);
    rdp_buffer_free(&ber);
    rdp_buffer_init(&ber);
    PCHECK(rdp_mcs_write_ber_integer(&ber, 0x80) == LIBRDP_STATUS_OK);
    PCHECK(ber.length == 4 && ber.data[0] == 0x02 && ber.data[1] == 0x02 && ber.data[2] == 0x00 &&
           ber.data[3] == 0x80);

    rdp_stream_init(&stream, gcc_block, sizeof(gcc_block));
    PCHECK(rdp_gcc_read_user_data_block(&stream, &block) == LIBRDP_STATUS_OK);
    PCHECK(block.type == 0x00c1);
    PCHECK(block.payload_len == 4 && block.payload[3] == 4);
    PCHECK(rdp_gcc_parse_server_data_blocks(gcc_server_blocks, sizeof(gcc_server_blocks), &server_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(server_data.has_core && server_data.has_security && server_data.has_network);
    PCHECK(server_data.version == 0x00080004u && server_data.requested_protocols == 2);
    PCHECK(server_data.early_capability_flags == 0x40);
    PCHECK(server_data.encryption_method == 0 && server_data.encryption_level == 0);
    PCHECK(server_data.mcs_channel_id == 1003 && server_data.channel_count == 1 && server_data.channel_ids[0] == 1004);
    PCHECK(rdp_gcc_parse_server_data_blocks(gcc_server_blocks, sizeof(gcc_server_blocks) - 1u, &server_data) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_gcc_parse_conference_create_response(gcc_response, sizeof(gcc_response), &conference_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(conference_response.node_id == 1004 && conference_response.tag == 42 && conference_response.result == 0);
    PCHECK(conference_response.user_data_len == sizeof(gcc_server_blocks));
    PCHECK(memcmp(conference_response.user_data, gcc_server_blocks, sizeof(gcc_server_blocks)) == 0);
    PCHECK(rdp_gcc_parse_server_data_blocks(conference_response.user_data,
                                            conference_response.user_data_len,
                                            &server_data) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_conference_create_response(gcc_response, sizeof(gcc_response) - 1u, &conference_response) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_capabilities_parse(caps, sizeof(caps), &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2);
    PCHECK(list.sets[0].type == 1 && list.sets[0].data_len == 4);
    PCHECK(list.sets[1].type == 2 && list.sets[1].data_len == 0);
    PCHECK(rdp_capabilities_parse(caps, 5, &list) == LIBRDP_STATUS_PROTOCOL_ERROR);

    memset(&config, 0, sizeof(config));
    config.desktop_width = 1024;
    config.desktop_height = 768;
    config.client_version = 0;
    config.requested_protocols = 0;
    config.early_capability_flags = 0;
    config.supported_color_depths = 0;
    config.connection_type = 0;
    config.desktop_physical_width = 0;
    config.desktop_physical_height = 0;
    config.desktop_orientation = 0;
    config.desktop_scale_factor = 0;
    config.device_scale_factor = 0;
    config.client_name = "librdp";
    config.enable_dynamic_channels = 0;
    config.enable_clipboard = 0;
    config.enable_audio_output = 0;
    config.enable_device_redirection = 0;
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.has_core && summary.has_security && summary.has_network);
    PCHECK(summary.desktop_width == 1024 && summary.desktop_height == 768);
    PCHECK(summary.version == RDP_GCC_CLIENT_VERSION_5);
    PCHECK(summary.early_capability_flags == RDP_GCC_EARLY_SUPPORT_ERRINFO);
    PCHECK(summary.supported_color_depths == RDP_GCC_SUPPORTED_COLOR_DEPTHS_LEGACY);
    PCHECK(summary.connection_type == RDP_GCC_CONNECTION_TYPE_LAN);
    PCHECK(summary.desktop_physical_width == 0 && summary.desktop_physical_height == 0);
    PCHECK(summary.channel_count == 0);
    rdp_buffer_free(&client_blocks);
    rdp_buffer_init(&client_blocks);
    config.client_version = RDP_GCC_CLIENT_VERSION_10_12;
    config.early_capability_flags = RDP_GCC_EARLY_SUPPORT_ERRINFO | RDP_GCC_EARLY_SUPPORT_STATUSINFO |
                                    RDP_GCC_EARLY_WANT_32BPP |
                                    RDP_GCC_EARLY_SUPPORT_MONITOR_LAYOUT |
                                    RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT |
                                    RDP_GCC_EARLY_SUPPORT_DYNVC_GFX;
    config.supported_color_depths = RDP_GCC_SUPPORTED_COLOR_DEPTHS_32BPP;
    config.connection_type = RDP_GCC_CONNECTION_TYPE_LAN;
    config.desktop_physical_width = 271;
    config.desktop_physical_height = 203;
    config.desktop_scale_factor = 100;
    config.device_scale_factor = 100;
    config.enable_dynamic_channels = 1;
    config.enable_clipboard = 1;
    config.enable_audio_output = 1;
    config.enable_device_redirection = 1;
    config.enable_pnp_redirection = 1;
    config.enable_remote_programs = 1;
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.channel_count == 6);
    PCHECK(summary.version == RDP_GCC_CLIENT_VERSION_10_12);
    PCHECK((summary.early_capability_flags & RDP_GCC_EARLY_SUPPORT_DYNVC_GFX) != 0);
    PCHECK((summary.early_capability_flags & RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT) != 0);
    PCHECK((summary.early_capability_flags & RDP_GCC_EARLY_WANT_32BPP) != 0);
    PCHECK(summary.supported_color_depths == RDP_GCC_SUPPORTED_COLOR_DEPTHS_32BPP);
    PCHECK(summary.desktop_physical_width == 271 && summary.desktop_physical_height == 203);
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "drdynvc", 7));
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "cliprdr", 7));
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "rdpsnd", 6));
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "rdpdr", 5));
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "PNPDR", 5));
    PCHECK(test_contains_bytes(client_blocks.data, client_blocks.length, "rail", 4));
    PCHECK(rdp_gcc_write_conference_create_request(&gcc_request, client_blocks.data, client_blocks.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(gcc_request.length > client_blocks.length);
    PCHECK(gcc_request.data[0] == 0 && gcc_request.data[1] == 5);
    PCHECK(rdp_mcs_write_connect_initial(&mcs_initial, gcc_request.data, gcc_request.length) == LIBRDP_STATUS_OK);
    PCHECK(mcs_initial.length > gcc_request.length);
    PCHECK(mcs_initial.data[0] == 0x7f && mcs_initial.data[1] == 0x65);

    PCHECK(rdp_mcs_write_erect_domain_request(&mcs_domain) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 5);
    PCHECK(mcs_domain.data[0] == 0x04 && mcs_domain.data[1] == 0x01 && mcs_domain.data[2] == 0x00 &&
           mcs_domain.data[3] == 0x01 && mcs_domain.data[4] == 0x00);
    rdp_buffer_free(&mcs_domain);
    rdp_buffer_init(&mcs_domain);
    PCHECK(rdp_mcs_write_attach_user_request(&mcs_domain) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 1 && mcs_domain.data[0] == 0x28);
    PCHECK(rdp_mcs_parse_attach_user_confirm(attach_confirm, sizeof(attach_confirm), &attach) == LIBRDP_STATUS_OK);
    PCHECK(attach.result == 0 && attach.user_id == 1004);
    PCHECK(rdp_mcs_parse_attach_user_confirm(join_confirm, sizeof(join_confirm), &attach) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&mcs_domain);
    rdp_buffer_init(&mcs_domain);
    PCHECK(rdp_mcs_write_channel_join_request(&mcs_domain, 1004, 1004) == LIBRDP_STATUS_OK);
    PCHECK(mcs_domain.length == 5);
    PCHECK(mcs_domain.data[0] == 0x38 && mcs_domain.data[1] == 0x00 && mcs_domain.data[2] == 0x03 &&
           mcs_domain.data[3] == 0x03 && mcs_domain.data[4] == 0xec);
    PCHECK(rdp_mcs_parse_channel_join_confirm(join_confirm, sizeof(join_confirm), &join) == LIBRDP_STATUS_OK);
    PCHECK(join.result == 0 && join.initiator == 1004 && join.requested_channel_id == 1004 &&
           join.channel_id == 1004);
    PCHECK(rdp_mcs_write_channel_join_request(&mcs_domain, 1000, 1004) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&mcs_domain);
    rdp_buffer_free(&mcs_initial);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&client_blocks);
    rdp_buffer_free(&ber);
    return 0;
}

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

    memset(&pcm, 0, sizeof(pcm));
    rdp_buffer_init(&out);

    PCHECK(rdp_audio_format_parse(pcm_format, sizeof(pcm_format), &pcm, &consumed) == LIBRDP_STATUS_OK);
    PCHECK(consumed == sizeof(pcm_format));
    PCHECK(pcm.format_tag == RDP_AUDIO_FORMAT_PCM);
    PCHECK(pcm.channels == 2 && pcm.samples_per_sec == 44100 && pcm.avg_bytes_per_sec == 176400);
    PCHECK(pcm.block_align == 4 && pcm.bits_per_sample == 16 && pcm.extra_data_len == 0);
    PCHECK(rdp_audio_format_write(&out, &pcm) == LIBRDP_STATUS_OK);
    PCHECK(out.length == sizeof(pcm_format) && memcmp(out.data, pcm_format, sizeof(pcm_format)) == 0);
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
                                                 0,
                                                 0,
                                                 6,
                                                 (rdp_audio_format[]){pcm, alaw, mulaw},
                                                 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_audio_output_parse_formats(out.data, out.length, &output_formats) == LIBRDP_STATUS_OK);
    PCHECK(output_formats.format_count == 3);
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

static int test_path_security_license_channels(void)
{
    const uint8_t fast_short[] = {0x00, 0x06, 1, 2, 3, 4};
    const uint8_t fast_long[] = {0x40, 0x80, 0x08, 1, 2, 3, 4, 5};
    const uint8_t fast_bad_update_compression[] = {0x00, 0x05, 0x40, 0x00, 0x00};
    const uint8_t slow[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03};
    const uint8_t demand_active[] = {
        0x1d, 0x00, 0x11, 0x00, 0xea, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x03, 0x00, 0x0c, 0x00, 's',  'r',  'v',  0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
    };
    const uint8_t capability_list_trailing[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0xff};
    const uint8_t bitmap_data_pdu[] = {
        0x3a, 0x00, 0x17, 0x00, 0xec, 0x03, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x01, 0x28, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t bitmap_24_data[] = {
        1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12
    };
    const uint8_t bitmap_15_data[] = {0x00, 0x7c, 0xe0, 0x03};
    const uint8_t bitmap_16_data[] = {0x00, 0xf8, 0xe0, 0x07};
    const uint8_t bitmap_24_rle_color_image[] = {
        0x84,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t bitmap_16_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0xf8
    };
    const uint8_t bitmap_15_rle_with_header[] = {
        0x00, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x64, 0x00, 0x7c
    };
    const uint8_t rfx_rlgr1_run_positive[] = {0xd8};
    const uint8_t rfx_rlgr1_run_negative[] = {0xf8};
    const uint8_t rfx_rlgr1_gr_mode[] = {0x83, 0x80};
    const uint8_t rfx_rlgr3_pair[] = {0x87, 0xd0};
    const uint8_t rfx_quant_values[] = {0x10, 0x32, 0x54, 0x76, 0x98};
    const uint8_t rfx_progressive_quant_values[] = {
        0x64,
        0x11, 0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x33
    };
    const uint8_t rfx_bad_progressive_quant_values[] = {
        0x64,
        0x99, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t planar_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA,
        0x10, 0x20,
        0x30, 0x40,
        0x50, 0x60
    };
    const uint8_t planar_alpha_padded[] = {
        0x00,
        0x7f, 0x80,
        0x11, 0x22,
        0x33, 0x44,
        0x55, 0x66,
        0x00
    };
    const uint8_t planar_ycocg_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | 0x01,
        100, 100,
        10, 0xf6,
        20, 0xec
    };
    const uint8_t planar_ycocg_alpha_padded[] = {
        0x01,
        0x7f,
        100,
        0,
        0,
        0
    };
    const uint8_t planar_ycocg_subsampled[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING | 0x01,
        100, 100, 100,
        100, 100, 100,
        100, 100, 100,
        0, 10, 20, 30,
        0, 0, 0, 0
    };
    const uint8_t planar_rle_argb[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x20, 0x10, 0x20,
        0x20, 0x30, 0x40,
        0x20, 0x50, 0x60
    };
    const uint8_t planar_rle_delta[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x20, 10, 20,
        0x20, 9, 10,
        0x20, 30, 40,
        0x20, 0, 0,
        0x20, 50, 60,
        0x20, 0, 0
    };
    const uint8_t planar_rle_bad_zero_control[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA | RDP_PLANAR_FORMAT_RLE,
        0x00
    };
    const uint8_t nscodec_capability_data[] = {1, 1, 7};
    const uint8_t nscodec_bad_capability_data[] = {1, 0, 0};
    const uint8_t nscodec_guid[RDP_NSCODEC_GUID_LENGTH] = RDP_NSCODEC_GUID_BYTES;
    const uint8_t nscodec_raw_argb[] = {
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        100, 10, 20, 0x7f
    };
    const uint8_t nscodec_subsampled_rle[] = {
        0x07, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00,
        100, 100, 18, 100, 100, 100, 100,
        0, 0, 2, 0, 0, 0, 0,
        0, 0, 2, 0, 0, 0, 0
    };
    const uint8_t nscodec_rle_plane[] = {0x63, 0x63, 0x01, 0x64, 0x65, 0x65, 0x65};
    const uint8_t nscodec_invalid_stream[] = {
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        1, 0, 0
    };
    const uint8_t planar_reserved[] = {0x80, 0, 0, 0};
    const uint8_t planar_subsample_without_loss[] = {RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING, 0, 0, 0};
    const uint8_t fast_bitmap_update[] = {
        0x00, 0x2b, 0x01, 0x26, 0x00,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1,    2,    3,    4,    5,    6,    7,    8,
        9,    10,   11,   12,   13,   14,   15,   16
    };
    const uint8_t pointer_shape_32[] = {
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t pointer_shape_16[] = {
        0x10, 0x00,
        0x08, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0xf8,
        0xe0, 0x07,
        0x00, 0x00
    };
    const uint8_t pointer_shape_15[] = {
        0x0f, 0x00,
        0x09, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x7c,
        0xe0, 0x03,
        0x00, 0x00
    };
    const uint8_t pointer_shape_1bpp_invert[] = {
        0x01, 0x00,
        0x06, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x80, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_shape_1bpp_transparent[] = {
        0x01, 0x00,
        0x07, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x00, 0x00,
        0x80, 0x00
    };
    const uint8_t pointer_slow_position[] = {
        0x03, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t pointer_slow_system_default[] = {
        0x01, 0x00,
        0x00, 0x7f, 0x00, 0x00
    };
    const uint8_t pointer_slow_large[] = {
        0x09, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_caps_confirm[] = {
        0x02, 0x00, 0x00, 0x00,
        0x43, 0x41, 0x50, 0x53,
        0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00
    };
    const uint8_t mouse_cursor_hidden[] = {0x03, 0x05, 0x00, 0x00};
    const uint8_t mouse_cursor_default[] = {0x03, 0x06, 0x00, 0x00};
    const uint8_t mouse_cursor_position[] = {
        0x03, 0x08, 0x00, 0x00,
        0x22, 0x00,
        0x33, 0x00
    };
    const uint8_t mouse_cursor_cached[] = {
        0x03, 0x0a, 0x00, 0x00,
        0x05, 0x00
    };
    const uint8_t mouse_cursor_shape_32[] = {
        0x03, 0x0b, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00,
        0x10, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t mouse_cursor_large_32[] = {
        0x03, 0x0c, 0x00, 0x00,
        0x20, 0x00,
        0x05, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        0x00, 0xff, 0x00, 0xff,
        0x40, 0x00,
        0x00, 0x00
    };
    const uint8_t license[] = {
        0xff, 0x03, 0x12, 0x00,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 2, 0,
        9, 8
    };
    const uint8_t license_company[] = {'C', 0, 0, 0};
    const uint8_t license_product[] = {'A', 0, '0', 0, '2', 0, 0, 0};
    const uint8_t license_scope[] = {'s', 'c', 'o', 'p', 'e', 0};
    const uint8_t license_cal[] = {'c', 'a', 'l'};
    const uint8_t license_requested_id[] = {'R', 'D', 'S', 0};
    const uint8_t license_adjusted_id[] = {'R', 'D', 'S', '-', 'A', 0};
    const uint8_t license_issuer_name[] = {'L', 0, 'S', 0, 0, 0};
    const uint8_t license_issuer_id[] = {'I', 0, 'D', 0, 0, 0};
    const uint8_t license_issuer_scope[] = {'D', 0, 0, 0};
    const uint8_t channel[] = {3, 0, 0, 0, 0x10, 0, 0, 0, 1, 2, 3};
    const uint8_t channel_fragment[] = {8, 0, 0, 0, RDP_VIRTUAL_CHANNEL_FLAG_FIRST, 0, 0, 0, 1, 2, 3};
    const uint8_t dyn_caps[] = {
        0x50, 0x00, 0x03, 0x00,
        0xa8, 0x03, 0xcc, 0x0c,
        0x92, 0x24, 0x55, 0x55
    };
    const uint8_t dyn_caps_zero[] = {0x50, 0x00, 0x00, 0x00};
    const uint8_t dyn_create[] = {0x18, 0x07, 'E', 'C', 'H', 'O', 0};
    const uint8_t dyn_data[] = {0x30, 0x07, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_data_first[] = {0x24, 0x07, 0x2c, 0x01, 0xaa, 0xbb, 0xcc};
    const uint8_t dyn_close[] = {0x40, 0x07};
    const uint8_t dyn_data_compressed[] = {0x70, 0x07, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_data_first_compressed[] = {0x64, 0x07, 0x2c, 0x01, 0xe0, 0x06, 0xaa};
    const uint8_t dyn_soft_sync_request[] = {
        0x80, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x03, 0x00,
        0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00
    };
    const uint8_t dyn_soft_sync_empty_request[] = {
        0x80, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x00
    };
    const uint8_t dyn_bad_header[] = {0x33};
    const uint8_t display_caps[] = {
        5, 0, 0, 0,
        20, 0, 0, 0,
        16, 0, 0, 0,
        0, 32, 0, 0,
        0, 32, 0, 0
    };
    const uint8_t core_response[] = {
        3, 2, 0, 0,
        0, 1, 0, 1,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    const uint8_t input_sc_ready_v300[] = {
        0x01, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    const uint8_t input_sc_ready_v200[] = {
        0x01, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00
    };
    const uint8_t graphics_confirm[] = {
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_bad_capset[] = {
        0x01, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_single[] = {
        0xe0, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_multipart[] = {
        0xe1, 0x02, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x04,
        0x13, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00, 0x04,
        0x04, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_segment_compressed_literal[] = {0xe0, 0x24, 0x24, 0x80, 0x07};
    const uint8_t graphics_segment_bad_compression_type[] = {0xe0, 0x20, 1, 2, 3};
    const uint8_t graphics_create_surface[] = {
        0x09, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x04,
        0x00, 0x03, 0x20
    };
    const uint8_t graphics_delete_surface[] = {
        0x0a, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x34, 0x12
    };
    const uint8_t graphics_map_output[] = {
        0x0f, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_scaled_map_output[] = {
        0x17, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00
    };
    const uint8_t graphics_solid_fill[] = {
        0x04, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x11, 0x22, 0x33, 0xff,
        0x01, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_bad_rect[] = {
        0x05, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_wire_to_surface_1[] = {
        0x01, 0x00, 0x00, 0x00,
        0x29, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x00, 0x00,
        0x20,
        0x01, 0x00, 0x02, 0x00,
        0x03, 0x00, 0x04, 0x00,
        0x10, 0x00, 0x00, 0x00,
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };
    const uint8_t graphics_wire_to_surface_2[] = {
        0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x09, 0x00,
        0x44, 0x33, 0x22, 0x11,
        0x21,
        0x03, 0x00, 0x00, 0x00,
        0xaa, 0xbb, 0xcc
    };
    const uint8_t graphics_avc420_stream[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_bad_rect[] = {
        0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc420_empty_bits[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64
    };
    const uint8_t graphics_avc444_both[] = {
        0x12, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_avc444_luma[] = {
        0x12, 0x00, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_chroma[] = {
        0x12, 0x00, 0x00, 0x80,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_invalid_lc[] = {
        0x12, 0x00, 0x00, 0xc0,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65
    };
    const uint8_t graphics_avc444_bad_split[] = {
        0x05, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x65,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x10, 0x00,
        0x45, 0x64,
        0x00, 0x00, 0x01, 0x66
    };
    const uint8_t graphics_progressive_stream[] = {
        0xc3, 0xcc, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x01,
        0xc1, 0xcc, 0x0c, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0xc4, 0xcc, 0x48, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x01,
        0x01,
        0x01, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0xc5, 0xcc, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0xaa, 0xbb, 0xcc,
        0xc2, 0xcc, 0x06, 0x00, 0x00, 0x00
    };
    const uint8_t graphics_progressive_tile_first[] = {
        0xc6, 0xcc, 0x1a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x01, 0x00,
        0x02, 0x00,
        0x01,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x00,
        0x11, 0x22, 0x33
    };
    const uint8_t graphics_progressive_tile_upgrade[] = {
        0xc7, 0xcc, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x03, 0x00,
        0x04, 0x00,
        0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66
    };
    const uint8_t graphics_progressive_bad_block[] = {0xc3, 0xcc, 0x05, 0x00, 0x00, 0x00};
    const uint8_t graphics_progressive_empty_region[] = {
        0xc4, 0xcc, 0x1f, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0d, 0x02, 0xd8, 0x02,
        0x40, 0x00, 0x20, 0x00,
        0x66, 0x76, 0x88, 0x99, 0xa9
    };
    const uint8_t graphics_progressive_bad_region[] = {
        0xc4, 0xcc, 0x17, 0x00, 0x00, 0x00,
        0x40,
        0x01, 0x00,
        0x01,
        0x00,
        0x00,
        0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55
    };
    const uint8_t graphics_progressive_region_rect[] = {
        0x80, 0x02, 0x20, 0x01,
        0x40, 0x00, 0x20, 0x00
    };
    const uint8_t graphics_progressive_region_rect_overflow[] = {
        0xff, 0xff, 0x00, 0x00,
        0x02, 0x00, 0x01, 0x00
    };
    const uint8_t graphics_surface_to_surface[] = {
        0x05, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x00, 0x00,
        0x10, 0x00,
        0x20, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_surface_to_cache[] = {
        0x06, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x08, 0x07, 0x06, 0x05,
        0x04, 0x03, 0x02, 0x01,
        0x42, 0x00,
        0x01, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x06, 0x00
    };
    const uint8_t graphics_cache_to_surface[] = {
        0x07, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00,
        0x42, 0x00,
        0x34, 0x12,
        0x02, 0x00,
        0x07, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x0a, 0x00
    };
    const uint8_t graphics_evict_cache[] = {
        0x08, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x42, 0x00
    };
    const uint8_t graphics_delete_context_pdu[] = {
        0x03, 0x00, 0x00, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x34, 0x12,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t clear_residual_bitmap[] = {
        0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_residual_zero_run_bitmap[] = {
        0x00, 0x06,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    const uint8_t clear_raw_subcodec_bitmap[] = {
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x00,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t clear_rlex_subcodec_bitmap[] = {
        0x00, 0x07,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0b, 0x00, 0x00, 0x00,
        0x02,
        0x02,
        1, 2, 3,
        4, 5, 6,
        0x03, 0x00,
        0x03, 0x00
    };
    const uint8_t clear_nsc_subcodec_bitmap[] = {
        0x00, 0x08,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x25, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01,
        0x00,
        0x00, 0x00,
        10, 0, 0, 0xff
    };
    const uint8_t clear_band_miss_bitmap[] = {
        0x04, 0x02,
        0x04, 0x00, 0x00, 0x00,
        0x13, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x02,
        1, 2, 3,
        4, 5, 6
    };
    const uint8_t clear_band_hit_bitmap[] = {
        0x00, 0x03,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x00, 0x80
    };
    const uint8_t clear_missing_band_bitmap[] = {
        0x00, 0x04,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x0a, 0x14, 0x1e,
        0x0a, 0x80
    };
    const uint8_t clear_glyph_store_bitmap[] = {
        0x01, 0x05,
        0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        9, 8, 7, 4
    };
    const uint8_t clear_glyph_hit[] = {
        0x03, 0x03,
        0x02, 0x00
    };
    const uint8_t clear_missing_glyph_hit[] = {
        0x03, 0x0a,
        0x03, 0x00
    };
    const uint8_t clear_empty_payload[] = {
        0x00, 0x0b
    };
    const uint8_t clear_unknown_subcodec_bitmap[] = {
        0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0xff,
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    const uint8_t graphics_start_frame[] = {
        0x0b, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t graphics_end_frame[] = {
        0x0c, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11
    };
    const uint8_t clip[] = {1, 0, 2, 0, 3, 0, 0, 0, 4, 5, 6};
    const uint8_t clip_caps[] = {
        0x07, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x0c, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x00, 0x00
    };
    const uint8_t clip_format_long[] = {
        0x02, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0x04, 0xc0, 0x00, 0x00,
        'N', 0x00, 'a', 0x00, 't', 0x00, 'i', 0x00, 'v', 0x00, 'e', 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x11, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    const uint8_t clip_format_short_ascii[] = {
        0x02, 0x00, 0x04, 0x00,
        0x24, 0x00, 0x00, 0x00,
        0xaa, 0xc0, 0x00, 0x00,
        'C', 'u', 's', 't', 'o', 'm', 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    const uint8_t clip_data_request[] = {
        0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_size_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_range_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00,
        0x33, 0x22, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x99, 0x00, 0x00, 0x00
    };
    const uint8_t clip_file_bad_request[] = {
        0x08, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00
    };
    const uint8_t indication_pdu[] = {0x68, 0x00, 0x03, 0x03, 0xeb, 0x70, 0x04, 1, 2, 3, 4};
    const uint8_t encrypted_random[] = {1, 2, 3, 4, 5};
    const uint8_t ntlm_challenge_token[] = {
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t wrapped_ntlm_challenge[] = {
        0xa1, 0x4c, 0x30, 0x4a, 0xa2, 0x48, 0x04, 0x46,
        'N',  'T',  'L',  'M',  'S',  'S',  'P',  0,
        2,    0,    0,    0,
        4,    0,    4,    0,    56,   0,    0,    0,
        1,    2,    3,    4,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0,    0,    0,    0,    0,    0,    0,    0,
        8,    0,    8,    0,    60,   0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,
        'S',  0,    'R',  0,
        1,    0,    4,    0,    'A',  0,    0,    0
    };
    const uint8_t ntlm_v2_target_name[] = {'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0};
    const uint8_t ntlm_v2_target_info[] = {
        0x02, 0x00, 0x0c, 0x00, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0,
        0x01, 0x00, 0x0c, 0x00, 'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0,
        0x04, 0x00, 0x14, 0x00, 'd', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0,
        '.', 0,    'c', 0,    'o', 0,    'm', 0,
        0x03, 0x00, 0x22, 0x00, 's', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0,
        '.', 0,    'd', 0,    'o', 0,    'm', 0, 'a', 0, 'i', 0, 'n', 0, '.', 0,
        'c', 0,    'o', 0,    'm', 0,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t ntlm_v2_server_challenge[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const uint8_t ntlm_v2_client_challenge[] = {0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44};
    const uint8_t ntlm_v2_session_key[] = {
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x99, 0x88
    };
    const uint8_t credssp_client_nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t credssp_public_key[] = {
        0x30, 0x13, 0x02, 0x0f, 0x00, 0xb8, 0x2d, 0xf1,
        0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6, 0x99, 0xf8,
        0x74, 0x2e, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    const uint8_t ntlm_v2_expected_lm[] = {
        0xd6, 0xe6, 0x15, 0x2e, 0xa2, 0x5d, 0x03, 0xb7,
        0xc6, 0xba, 0x66, 0x29, 0xc2, 0xd6, 0xaa, 0xf0,
        0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44
    };
    const uint8_t ntlm_v2_expected_proof[] = {
        0x29, 0x15, 0x7f, 0x79, 0xa3, 0x08, 0x93, 0x53,
        0x78, 0x3e, 0x24, 0x4f, 0xad, 0x52, 0x8a, 0x5c
    };
    const uint8_t server_certificate[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x9c, 0x00, 0x52, 0x53, 0x41, 0x31, 0x88, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xeb, 0x63, 0x25, 0x72, 0xe3, 0xeb, 0x4e, 0x15, 0x13, 0x3c, 0x7b, 0x9c,
        0x5c, 0x66, 0x61, 0x89, 0x0f, 0x7f, 0x79, 0x1a, 0x93, 0x75, 0x9c, 0xe2,
        0x98, 0xeb, 0xa5, 0xa6, 0x73, 0xd2, 0xc7, 0x14, 0x2c, 0x5a, 0x57, 0x10,
        0x48, 0x3b, 0x04, 0x69, 0xaf, 0x52, 0x86, 0x58, 0xe3, 0xf7, 0x05, 0xcf,
        0x22, 0x0f, 0x6e, 0x25, 0x41, 0xe0, 0x3a, 0x26, 0x62, 0x2f, 0x31, 0xcf,
        0xd5, 0x97, 0xd3, 0xa0, 0x93, 0x73, 0x4c, 0x9b, 0xc1, 0x9c, 0x2a, 0x30,
        0x66, 0x7f, 0x61, 0x25, 0x67, 0xab, 0xd3, 0xe7, 0xe2, 0x7f, 0x5e, 0x57,
        0x2a, 0x3a, 0x2b, 0x9c, 0x4f, 0x4e, 0x2c, 0xba, 0x8e, 0xf0, 0x93, 0x29,
        0x3f, 0xf7, 0xca, 0x9e, 0x46, 0xd4, 0x1e, 0x11, 0x96, 0x84, 0xef, 0x2d,
        0xa9, 0x57, 0x3d, 0x8b, 0x9b, 0x27, 0x90, 0x5b, 0x98, 0x9d, 0x5b, 0x80,
        0x64, 0x24, 0x76, 0xc0, 0xba, 0x8d, 0xe4, 0xb2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t x509_der[] = {
        0x30, 0x82, 0x02, 0x08, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x2b, 0x77, 0x94, 0x65, 0x7e, 0xcb, 0xa0, 0x19, 0xd9,
        0xec, 0x74, 0x9b, 0x9a, 0xd1, 0xd1, 0x83, 0x77, 0x7f, 0x9e, 0x5a, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0b, 0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x30, 0x37,
        0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x37, 0x30, 0x38, 0x31, 0x38, 0x30, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x6c,
        0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xb8, 0x2d, 0xf1, 0xa8, 0x88, 0x3d, 0xa8, 0xfb, 0xa6,
        0x99, 0xf8, 0x74, 0x2e, 0xc3, 0x89, 0xab, 0x17, 0x5c, 0xb6, 0xd2, 0x7f,
        0xbd, 0x88, 0x48, 0x3f, 0x16, 0x3f, 0x94, 0x9d, 0x6a, 0xd1, 0x38, 0x5b,
        0xe8, 0x53, 0xb4, 0x1c, 0x61, 0x80, 0xef, 0xa9, 0x8c, 0xf7, 0xeb, 0x01,
        0xad, 0x87, 0xc8, 0x70, 0x55, 0x98, 0x64, 0xce, 0x24, 0x07, 0x09, 0x59,
        0x4e, 0xdf, 0x44, 0x2c, 0x4c, 0xe4, 0x44, 0xb4, 0xb1, 0x10, 0x75, 0x0e,
        0x1e, 0x38, 0xda, 0x26, 0xf4, 0x9e, 0xef, 0xec, 0x15, 0xaa, 0x2f, 0x26,
        0x35, 0xb0, 0x17, 0x9d, 0x34, 0x7e, 0x58, 0xa0, 0xeb, 0x22, 0xb3, 0xf0,
        0xff, 0x1c, 0x87, 0x7f, 0xb0, 0xf4, 0xd4, 0x3c, 0x3d, 0x59, 0xe0, 0x10,
        0x77, 0x46, 0x94, 0xa5, 0x90, 0xcf, 0x1d, 0x2c, 0xf0, 0xd7, 0x44, 0x8f,
        0x9e, 0xaa, 0x60, 0x0b, 0x16, 0x6d, 0x79, 0x5c, 0xe4, 0xdd, 0xcd, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f,
        0xc0, 0x07, 0x93, 0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd,
        0x00, 0xc8, 0x15, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x7d, 0x2f, 0xcf, 0xa9, 0x1f, 0xc0, 0x07, 0x93,
        0x49, 0xc2, 0x4d, 0xfa, 0x0f, 0x8c, 0xe4, 0x25, 0xcd, 0x00, 0xc8, 0x15,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
        0x70, 0x99, 0xde, 0x9e, 0x51, 0xf6, 0x5a, 0x1d, 0x33, 0xab, 0xf4, 0x7b,
        0x4a, 0xa5, 0x9f, 0xf2, 0xda, 0x3a, 0xe3, 0x4d, 0x66, 0xb6, 0xfe, 0x68,
        0x44, 0x29, 0xb3, 0xe4, 0x8d, 0x8e, 0xef, 0xb4, 0x0e, 0xfc, 0xae, 0x74,
        0xb3, 0x2a, 0xf9, 0x90, 0x0c, 0x0c, 0xd6, 0xb1, 0x12, 0x6c, 0x7e, 0x6a,
        0x34, 0xb5, 0xe7, 0xc8, 0xb0, 0xee, 0x56, 0xb8, 0x02, 0xab, 0xf3, 0xe2,
        0x5e, 0xd6, 0xca, 0x4f, 0xa6, 0x3d, 0x10, 0xb1, 0x49, 0x32, 0x75, 0x07,
        0x00, 0x54, 0xa7, 0x9e, 0x65, 0xd0, 0xc4, 0x2b, 0xc4, 0xad, 0xc7, 0x3a,
        0xb9, 0xe5, 0x44, 0xdf, 0xed, 0xb8, 0x91, 0xea, 0xcc, 0x23, 0x16, 0xd3,
        0xa6, 0x23, 0x83, 0x62, 0x2d, 0x4e, 0xe4, 0x1c, 0xb8, 0x6c, 0x75, 0x61,
        0xde, 0xe6, 0x0e, 0xc8, 0xd5, 0x25, 0xc7, 0x69, 0x5a, 0xba, 0x06, 0xa3,
        0x30, 0xdb, 0xdf, 0xd2, 0xd8, 0xdc, 0xa0, 0x3f
    };
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint8_t fast_payload[130] = {0};
    rdp_fastpath_header fast;
    rdp_fastpath_update_list fast_updates;
    rdp_slowpath_share_control_header slow_header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    rdp_bitmap_update bitmap_update;
    rdp_bitmap_update_header bitmap_header;
    rdp_bitmap_rect bitmap_rect;
    rdp_pointer_update pointer_update;
    int32_t rfx_coefficients[8];
    int32_t rfx_component[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_y[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_cb[RDP_RFX_TILE_COEFFICIENTS];
    int32_t rfx_cr[RDP_RFX_TILE_COEFFICIENTS];
    uint8_t rfx_zero_rlgr[4];
    size_t rfx_written = 0;
    rdp_rfx_component_quant rfx_quant;
    rdp_rfx_component_quant rfx_decode_quant;
    rdp_rfx_progressive_quant rfx_progressive_quant;
    rdp_rfx_component_quant rfx_added_quant;
    rdp_rfx_component_quant rfx_zero_delta;
    rdp_rfx_tile_pixels rfx_pixels;
    rdp_rfx_tile_pixels rfx_upgrade_pixels;
    rdp_rfx_progressive_tile_state rfx_progressive_state;
    rdp_license_error_alert alert;
    rdp_license_preamble license_preamble;
    rdp_license_binary_blob license_blob;
    rdp_license_server_request license_request;
    rdp_license_platform_challenge license_challenge;
    rdp_license_new_or_upgrade license_new;
    rdp_license_new_license_info license_info;
    rdp_license_product_certificate_info license_cert_info;
    rdp_license_product_certificate_info parsed_license_cert_info;
    rdp_license_server_info license_server_info;
    rdp_license_server_info parsed_license_server_info;
    rdp_license_hardware_id hardware_id;
    rdp_license_hardware_id parsed_hardware_id;
    rdp_license_platform_challenge_response_data challenge_response_data;
    rdp_license_platform_challenge_response_data parsed_challenge_response_data;
    rdp_license_client_new_license_request client_license_request;
    rdp_license_client_info client_license_info;
    rdp_license_platform_challenge_response client_challenge_response;
    rdp_virtual_channel_packet vc;
    rdp_dynamic_channel_header dyn_header;
    rdp_dynamic_channel_capabilities dyn_parsed_caps;
    rdp_dynamic_channel_create_request dyn_create_request;
    rdp_dynamic_channel_data_pdu dyn_data_pdu;
    rdp_dynamic_channel_data_first_pdu dyn_first_pdu;
    rdp_dynamic_channel_close_pdu dyn_close_pdu;
    rdp_dynamic_channel_compressed_data_pdu dyn_compressed_pdu;
    rdp_dynamic_channel_compressed_data_first_pdu dyn_first_compressed_pdu;
    rdp_dynamic_channel_soft_sync_request dyn_soft_sync;
    rdp_dynamic_channel_soft_sync_channel_list dyn_soft_sync_list;
    rdp_dynamic_channel_soft_sync_response dyn_soft_sync_response;
    rdp_mouse_cursor_header mouse_cursor_header;
    rdp_mouse_cursor_capset mouse_cursor_capset;
    rdp_core_input_header core_header;
    rdp_core_input_init_response core_init_response;
    rdp_core_input_event core_events[8];
    uint8_t core_event_count = 0;
    rdp_input_channel_header input_header;
    rdp_input_channel_sc_ready input_sc_ready;
    rdp_input_channel_cs_ready input_cs_ready;
    rdp_input_channel_touch_contact input_touch_contact;
    rdp_input_channel_touch_frame input_touch_frame;
    rdp_input_channel_touch_event input_touch_event;
    rdp_input_channel_pen_contact input_pen_contact;
    rdp_input_channel_pen_frame input_pen_frame;
    rdp_input_channel_pen_event input_pen_event;
    uint8_t input_contact_id = 0;
    rdp_display_control_caps display_parsed_caps;
    rdp_display_control_monitor display_monitor;
    rdp_display_control_monitor display_monitors[2];
    uint32_t display_monitor_count = 0;
    rdp_graphics_header graphics_header;
    rdp_graphics_caps_confirm graphics_caps_confirm;
    rdp_graphics_capset graphics_capset;
    rdp_graphics_create_surface graphics_create;
    rdp_graphics_delete_surface graphics_delete;
    rdp_graphics_reset graphics_reset;
    rdp_graphics_map_surface_to_output graphics_map;
    rdp_graphics_map_surface_to_scaled_output graphics_scaled_map;
    rdp_graphics_point16 graphics_point;
    rdp_graphics_rect16 graphics_rect;
    rdp_graphics_solid_fill graphics_solid;
    rdp_graphics_wire_to_surface_1 graphics_wire1;
    rdp_graphics_wire_to_surface_2 graphics_wire2;
    rdp_graphics_surface_to_surface graphics_surface_copy;
    rdp_graphics_surface_to_cache graphics_surface_cache;
    rdp_graphics_cache_to_surface graphics_cache_surface;
    rdp_graphics_evict_cache_entry graphics_evict;
    rdp_graphics_delete_encoding_context graphics_delete_context;
    rdp_graphics_start_frame graphics_start;
    rdp_graphics_end_frame graphics_end;
    rdp_graphics_frame_ack graphics_ack;
    rdp_graphics_point16 graphics_points[2];
    rdp_graphics_decompressor graphics_decompressor;
    rdp_graphics_progressive_block graphics_progressive_block;
    rdp_graphics_progressive_context graphics_progressive_context;
    rdp_graphics_progressive_frame_begin graphics_progressive_frame_begin;
    rdp_graphics_progressive_region graphics_progressive_region;
    rdp_graphics_progressive_tile_simple graphics_progressive_simple;
    rdp_graphics_progressive_tile_first graphics_progressive_first;
    rdp_graphics_progressive_tile_upgrade graphics_progressive_upgrade;
    rdp_graphics_rect16 graphics_progressive_rect;
    rdp_graphics_progressive_stream graphics_progressive;
    rdp_graphics_avc420_quant_quality graphics_avc_quant;
    rdp_graphics_avc420_metablock graphics_avc_meta;
    rdp_graphics_avc420_stream graphics_avc420;
    rdp_graphics_avc444_stream graphics_avc444;
    rdp_clearcodec_stream clear_stream;
    rdp_clearcodec_composite_payload clear_payload;
    rdp_clearcodec_subcodec clear_subcodec;
    rdp_clearcodec_context clear_context;
    rdp_nscodec_context nscodec_context;
    rdp_nscodec_stream nscodec_stream;
    rdp_nscodec_capability nscodec_capability;
    rdp_clipboard_packet cb;
    rdp_clipboard_capabilities cb_caps;
    rdp_clipboard_format_list cb_list;
    rdp_clipboard_format_entry cb_entry;
    rdp_clipboard_format_data_request cb_data_request;
    rdp_clipboard_format_data_response cb_data_response;
    rdp_clipboard_file_contents_request cb_file_request;
    rdp_clipboard_file_contents_response cb_file_response;
    rdp_clipboard_lock cb_lock;
    rdp_mcs_send_data_indication indication;
    rdp_credssp_state cred_state;
    rdp_security_public_key public_key;
    rdp_standard_security_context secure_a;
    rdp_standard_security_context secure_b;
    rdp_buffer security;
    rdp_buffer send_data;
    rdp_buffer encrypted;
    rdp_buffer encrypted_info;
    rdp_buffer plain_info_body;
    rdp_buffer expected_cipher;
    rdp_buffer protected_pdu;
    rdp_buffer unwrapped_pdu;
    rdp_buffer plain_security;
    rdp_buffer encrypted_fastpath;
    rdp_buffer decoded_fastpath;
    rdp_buffer confirm_active;
    rdp_buffer client_sync;
    rdp_buffer client_control;
    rdp_buffer client_persistent_keys;
    rdp_buffer client_font_list;
    rdp_buffer client_keyboard_input;
    rdp_buffer client_mouse_input;
    rdp_buffer client_refresh_rect;
    rdp_buffer client_suppress_output;
    rdp_buffer graphics_decoded;
    rdp_buffer planar_pixels;
    rdp_buffer nscodec_pixels;
    rdp_buffer nscodec_capability_buffer;
    rdp_buffer graphics_reset_pdu;
    rdp_buffer decoded_bitmap;
    rdp_buffer decoded_pointer;
    rdp_buffer clear_pixels;
    rdp_buffer x509_chain;
    rdp_buffer ntlm_negotiate;
    rdp_buffer ntlm_authenticate;
    rdp_buffer spnego_negotiate;
    rdp_buffer spnego_authenticate;
    rdp_buffer ntlm_wrapped;
    rdp_buffer ntlm_unwrapped;
    rdp_buffer pub_key_auth;
    rdp_buffer server_pub_key_auth;
    rdp_buffer ts_credentials;
    rdp_buffer auth_info;
    rdp_buffer ts_request;
    rdp_buffer nla_request;
    rdp_buffer license_packet;
    rdp_buffer license_payload;
    rdp_buffer channel_packet;
    rdp_buffer dyn_response;
    rdp_client_info info;
    rdp_client_info no_password_info;
    rdp_client_info_summary info_summary;
    rdp_capability_list confirm_caps;
    const rdp_capability_set* confirm_bitmap_set = NULL;
    const rdp_capability_set* confirm_set = NULL;
    rdp_capability_general confirm_general;
    rdp_capability_bitmap confirm_bitmap;
    rdp_capability_order confirm_order;
    rdp_capability_bitmap_cache_v2 confirm_bitmap_cache;
    rdp_capability_pointer confirm_pointer;
    rdp_capability_large_pointer confirm_large_pointer;
    rdp_capability_input confirm_input;
    rdp_capability_brush confirm_brush;
    rdp_capability_glyph_cache confirm_glyph;
    rdp_capability_virtual_channel confirm_virtual_channel;
    rdp_capability_sound confirm_sound;
    rdp_capability_share confirm_share;
    rdp_capability_font confirm_font;
    rdp_capability_control confirm_control;
    rdp_capability_color_cache confirm_color_cache;
    rdp_capability_activation confirm_activation;
    rdp_capability_bitmap_codecs confirm_bitmap_codecs;
    rdp_nscodec_capability confirm_nscodec;
    rdp_capability_set virtual_channel_minimal_set;
    rdp_credssp_ts_request parsed_ts;
    rdp_ntlm_challenge ntlm_challenge;
    rdp_ntlm_challenge ntlm_v2_challenge;
    rdp_ntlm_authenticate_result ntlm_auth_result;
    rdp_ntlm_security_context ntlm_security;
    rdp_ntlm_security_context server_security;
    const uint8_t* extracted_ntlm = NULL;
    size_t extracted_ntlm_len = 0;
    uint8_t server_hash[32];
    uint16_t lm_len = 0;
    uint16_t nt_len = 0;
    uint16_t key_len = 0;
    uint32_t lm_offset = 0;
    uint32_t nt_offset = 0;
    uint32_t key_offset = 0;
    uint32_t error_info = 0;
    uint16_t security_flags = 0;
    uint8_t signature[8];
    size_t decoded_stride = 0;
    size_t pointer_stride = 0;
    size_t i = 0;
    uint16_t confirm_source_len = 0;
    uint16_t confirm_caps_len = 0;
    uint8_t nscodec_rle_decoded[24];
    const uint16_t expected_confirm_types[] = {
        RDP_CAPABILITY_TYPE_GENERAL,
        RDP_CAPABILITY_TYPE_BITMAP,
        RDP_CAPABILITY_TYPE_ORDER,
        RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2,
        RDP_CAPABILITY_TYPE_POINTER,
        RDP_CAPABILITY_TYPE_LARGE_POINTER,
        RDP_CAPABILITY_TYPE_INPUT,
        RDP_CAPABILITY_TYPE_BRUSH,
        RDP_CAPABILITY_TYPE_GLYPH_CACHE,
        RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL,
        RDP_CAPABILITY_TYPE_SOUND,
        RDP_CAPABILITY_TYPE_SHARE,
        RDP_CAPABILITY_TYPE_FONT,
        RDP_CAPABILITY_TYPE_CONTROL,
        RDP_CAPABILITY_TYPE_COLOR_CACHE,
        RDP_CAPABILITY_TYPE_ACTIVATION,
        RDP_CAPABILITY_TYPE_BITMAP_CODECS
    };
    const uint16_t expected_confirm_lengths[] = {
        24, 28, 88, 40, 10, 6, 88, 8, 52, 12, 8, 8, 8, 12, 8, 12, 27
    };
    const uint8_t virtual_channel_minimal_data[] = {1, 0, 0, 0};
    const uint8_t font_map_payload[] = {1, 0, 2, 0, 3, 0, 4, 0};
    const uint8_t set_error_info_payload[] = {0x34, 0x12, 0, 0};
    const uint8_t save_session_info_payload[] = {1, 0, 0, 0, 0xaa, 0x55};
    const uint8_t orders_update_payload[] = {0, 0, 0, 0};

    rdp_buffer_init(&security);
    rdp_buffer_init(&send_data);
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&encrypted_info);
    rdp_buffer_init(&plain_info_body);
    rdp_buffer_init(&expected_cipher);
    rdp_buffer_init(&protected_pdu);
    rdp_buffer_init(&unwrapped_pdu);
    rdp_buffer_init(&plain_security);
    rdp_buffer_init(&encrypted_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    rdp_buffer_init(&confirm_active);
    rdp_buffer_init(&client_sync);
    rdp_buffer_init(&client_control);
    rdp_buffer_init(&client_persistent_keys);
    rdp_buffer_init(&client_font_list);
    rdp_buffer_init(&client_keyboard_input);
    rdp_buffer_init(&client_mouse_input);
    rdp_buffer_init(&client_refresh_rect);
    rdp_buffer_init(&client_suppress_output);
    rdp_graphics_decompressor_init(&graphics_decompressor);
    rdp_clearcodec_context_init(&clear_context);
    rdp_nscodec_context_init(&nscodec_context);
    rdp_buffer_init(&graphics_decoded);
    rdp_buffer_init(&planar_pixels);
    rdp_buffer_init(&nscodec_pixels);
    rdp_buffer_init(&nscodec_capability_buffer);
    rdp_buffer_init(&graphics_reset_pdu);
    rdp_buffer_init(&decoded_bitmap);
    rdp_buffer_init(&decoded_pointer);
    rdp_buffer_init(&clear_pixels);
    rdp_buffer_init(&x509_chain);
    rdp_buffer_init(&ntlm_negotiate);
    rdp_buffer_init(&ntlm_authenticate);
    rdp_buffer_init(&spnego_negotiate);
    rdp_buffer_init(&spnego_authenticate);
    rdp_buffer_init(&ntlm_wrapped);
    rdp_buffer_init(&ntlm_unwrapped);
    rdp_buffer_init(&pub_key_auth);
    rdp_buffer_init(&server_pub_key_auth);
    rdp_buffer_init(&ts_credentials);
    rdp_buffer_init(&auth_info);
    rdp_buffer_init(&ts_request);
    rdp_buffer_init(&nla_request);
    rdp_buffer_init(&license_packet);
    rdp_buffer_init(&license_payload);
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath,
                                     RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
                                     0,
                                     130) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&decoded_fastpath, fast_payload, sizeof(fast_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_header(decoded_fastpath.data,
                                     decoded_fastpath.length,
                                     &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 133 && fast.header_length == 3 && fast.long_length);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_header(&decoded_fastpath, 2, 0, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 && fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE &&
           fast_updates.updates[0].compression == 0 && fast_updates.updates[0].data_len == 38);
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      fast_updates.count) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 &&
           fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].data_len == 38);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    fast_updates.updates[0].compression = RDP_FASTPATH_OUTPUT_COMPRESSION_USED;
    fast_updates.updates[0].compression_flags = 0x20u;
    PCHECK(rdp_fastpath_write_updates(&decoded_fastpath,
                                      fast_updates.updates,
                                      1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_fastpath_parse_updates(decoded_fastpath.data,
                                      decoded_fastpath.length,
                                      &fast_updates) == LIBRDP_STATUS_OK);
    PCHECK(fast_updates.updates[0].compression == RDP_FASTPATH_OUTPUT_COMPRESSION_USED &&
           fast_updates.updates[0].compression_flags == 0x20u);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_init(&decoded_fastpath);
    PCHECK(rdp_fastpath_write_update(&decoded_fastpath,
                                     0x0fu,
                                     RDP_FASTPATH_FRAGMENT_SINGLE,
                                     0,
                                     0,
                                     NULL,
                                     0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(fast_updates.updates[0].data,
                                            fast_updates.updates[0].data_len,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update) - 1u, &fast_updates) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_parse_updates(fast_bad_update_compression,
                                      sizeof(fast_bad_update_compression),
                                      &fast_updates) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_parse_updates(fast_long, sizeof(fast_long), &fast_updates) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NULL, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_DEFAULT, NULL, 0, &pointer_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_POSITION,
                                      pointer_slow_position + 2,
                                      sizeof(pointer_slow_position) - 2u,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_CACHED,
                                      pointer_shape_32 + 2,
                                      2,
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_32,
                                      sizeof(pointer_shape_32),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 16 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[3] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00 &&
           decoded_pointer.data[7] == 0xff &&
           decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_16,
                                      sizeof(pointer_shape_16),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 16 &&
           pointer_update.cache_index == 8);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_15,
                                      sizeof(pointer_shape_15),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 15 &&
           pointer_update.cache_index == 9);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 &&
           decoded_pointer.length == 8 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0xff &&
           decoded_pointer.data[4] == 0x00 &&
           decoded_pointer.data[5] == 0xff &&
           decoded_pointer.data[6] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_invert,
                                      sizeof(pointer_shape_1bpp_invert),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.xor_bpp == 1 &&
           pointer_update.cache_index == 6);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[0] == 0x00 &&
           decoded_pointer.data[1] == 0x00 &&
           decoded_pointer.data[2] == 0x00 &&
           decoded_pointer.data[3] == 0xff);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_1bpp_transparent,
                                      sizeof(pointer_shape_1bpp_transparent),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 4 &&
           decoded_pointer.length == 4 &&
           decoded_pointer.data[3] == 0x00);
    PCHECK(rdp_pointer_parse_fastpath(RDP_FASTPATH_UPDATE_POINTER_NEW,
                                      pointer_shape_32,
                                      sizeof(pointer_shape_32) - 1u,
                                      &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_position,
                                      sizeof(pointer_slow_position),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_system_default,
                                      sizeof(pointer_slow_system_default),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_pointer_parse_slowpath(pointer_slow_large,
                                      sizeof(pointer_slow_large),
                                      &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);

    PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow), &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 && slow_header.pdu_type == 0x13);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   6,
                                                   (uint16_t)(RDP_SLOWPATH_PDU_VERSION |
                                                              RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE),
                                                   1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(client_refresh_rect.data,
                                                   client_refresh_rect.length,
                                                   &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 &&
           slow_header.pdu_type == (RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE) &&
           slow_header.channel_id == 1004);
    PCHECK(rdp_slowpath_write_share_control_header(&client_refresh_rect,
                                                   5,
                                                   RDP_SLOWPATH_PDU_VERSION,
                                                   1004) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active), &demand) == LIBRDP_STATUS_OK);
    PCHECK(demand.share_id == 0x12345678u);
    PCHECK(demand.source_descriptor_len == 3 && memcmp(demand.source_descriptor, "srv", 3) == 0);
    PCHECK(demand.capabilities.count == 1 && demand.capabilities.sets[0].type == 1);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_GENERAL) == &demand.capabilities.sets[0]);
    PCHECK(rdp_capabilities_find(&demand.capabilities, RDP_CAPABILITY_TYPE_BITMAP) == NULL);
    PCHECK(rdp_slowpath_parse_demand_active(demand_active, sizeof(demand_active) - 1u, &demand) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_capabilities_parse(capability_list_trailing,
                                  sizeof(capability_list_trailing),
                                  &confirm_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u && data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE);
    PCHECK(data_pdu.payload_len == 40);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                data_pdu.stream_id,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                data_pdu.compressed_type,
                                                data_pdu.compressed_length) == LIBRDP_STATUS_OK);
    PCHECK(client_refresh_rect.length == 12 &&
           test_read_u32_le(client_refresh_rect.data) == data_pdu.share_id &&
           client_refresh_rect.data[5] == data_pdu.stream_id &&
           client_refresh_rect.data[8] == data_pdu.pdu_type2);
    PCHECK(rdp_slowpath_write_share_data_header(&client_refresh_rect,
                                                data_pdu.share_id,
                                                0,
                                                data_pdu.uncompressed_length,
                                                data_pdu.pdu_type2,
                                                0,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, data_pdu.payload_len, &bitmap_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_header.update_type == RDP_UPDATE_TYPE_BITMAP && bitmap_header.count == 1);
    PCHECK(rdp_bitmap_parse_update_header(data_pdu.payload, 3, &bitmap_header) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1);
    PCHECK(bitmap_update.rects[0].width == 2 && bitmap_update.rects[0].height == 2);
    PCHECK(bitmap_update.rects[0].bits_per_pixel == 32 && bitmap_update.rects[0].data_len == 16);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_update.rects[0], &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 9 &&
           decoded_bitmap.data[1] == 10 && decoded_bitmap.data[2] == 11 && decoded_bitmap.data[3] == 12);
    bitmap_rect = bitmap_update.rects[0];
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_update(decoded_bitmap.data, decoded_bitmap.length, &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].width == 2 &&
           bitmap_update.rects[0].height == 2 &&
           bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_write_data_pdu(&client_refresh_rect,
                                       data_pdu.share_id,
                                       data_pdu.header.channel_id,
                                       RDP_SLOWPATH_DATA_PDU_UPDATE,
                                       decoded_bitmap.data,
                                       decoded_bitmap.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE &&
           data_pdu.payload_len == decoded_bitmap.length);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &bitmap_update) ==
           LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 && bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_init(&client_refresh_rect);
    PCHECK(rdp_slowpath_parse_data_pdu(bitmap_data_pdu, sizeof(bitmap_data_pdu), &data_pdu) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_fastpath_update(&decoded_bitmap, &bitmap_rect, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_bitmap_parse_fastpath_update(decoded_bitmap.data,
                                            decoded_bitmap.length,
                                            &bitmap_update) == LIBRDP_STATUS_OK);
    PCHECK(bitmap_update.count == 1 &&
           bitmap_update.rects[0].bits_per_pixel == 32 &&
           bitmap_update.rects[0].data_len == 16);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_OK);
    PCHECK(decoded_bitmap.length == 36);
    bitmap_rect.width = 0;
    PCHECK(rdp_bitmap_write_rect(&decoded_bitmap, &bitmap_rect) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_init(&decoded_bitmap);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.data = bitmap_24_data;
    bitmap_rect.data_len = sizeof(bitmap_24_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 7 &&
           decoded_bitmap.data[1] == 8 && decoded_bitmap.data[2] == 9 && decoded_bitmap.data[3] == 0xff);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data = bitmap_16_data;
    bitmap_rect.data_len = sizeof(bitmap_16_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 1;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.data = bitmap_15_data;
    bitmap_rect.data_len = sizeof(bitmap_15_data);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[4] == 0 && decoded_bitmap.data[5] == 255 &&
           decoded_bitmap.data[6] == 0);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 2;
    bitmap_rect.height = 2;
    bitmap_rect.dest_right = 1;
    bitmap_rect.dest_bottom = 1;
    bitmap_rect.bits_per_pixel = 24;
    bitmap_rect.flags = 0x0401;
    bitmap_rect.data = bitmap_24_rle_color_image;
    bitmap_rect.data_len = sizeof(bitmap_24_rle_color_image);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 && decoded_bitmap.length == 16 && decoded_bitmap.data[0] == 1 &&
           decoded_bitmap.data[1] == 2 && decoded_bitmap.data[2] == 3 && decoded_bitmap.data[12] == 10 &&
           decoded_bitmap.data[13] == 11 && decoded_bitmap.data[14] == 12);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_16_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_16_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    memset(&bitmap_rect, 0, sizeof(bitmap_rect));
    bitmap_rect.width = 4;
    bitmap_rect.height = 1;
    bitmap_rect.dest_right = 3;
    bitmap_rect.bits_per_pixel = 15;
    bitmap_rect.flags = 1;
    bitmap_rect.data = bitmap_15_rle_with_header;
    bitmap_rect.data_len = sizeof(bitmap_15_rle_with_header);
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 16 && decoded_bitmap.data[0] == 0 && decoded_bitmap.data[1] == 0 &&
           decoded_bitmap.data[2] == 255 && decoded_bitmap.data[12] == 0 && decoded_bitmap.data[13] == 0 &&
           decoded_bitmap.data[14] == 255);
    bitmap_rect.bits_per_pixel = 14;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    bitmap_rect.bits_per_pixel = 16;
    bitmap_rect.data_len = 7;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_run_positive,
                               sizeof(rfx_rlgr1_run_positive),
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == 5);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_run_negative,
                               sizeof(rfx_rlgr1_run_negative),
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == -5);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_gr_mode,
                               sizeof(rfx_rlgr1_gr_mode),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 3 &&
           rfx_coefficients[0] == 1 &&
           rfx_coefficients[1] == 0 &&
           rfx_coefficients[2] == -2);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR3,
                               rfx_rlgr3_pair,
                               sizeof(rfx_rlgr3_pair),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 3 &&
           rfx_coefficients[0] == 1 &&
           rfx_coefficients[1] == 2 &&
           rfx_coefficients[2] == -1);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               rfx_rlgr1_gr_mode,
                               1,
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_rfx_rlgr_decode((rdp_rfx_rlgr_mode)2,
                               rfx_rlgr1_gr_mode,
                               sizeof(rfx_rlgr1_gr_mode),
                               rfx_coefficients,
                               3,
                               &rfx_written) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_rfx_parse_component_quant(rfx_quant_values,
                                         sizeof(rfx_quant_values),
                                         &rfx_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_quant.ll3 == 0 &&
           rfx_quant.hl3 == 1 &&
           rfx_quant.lh3 == 2 &&
           rfx_quant.hh3 == 3 &&
           rfx_quant.hl2 == 4 &&
           rfx_quant.lh2 == 5 &&
           rfx_quant.hh2 == 6 &&
           rfx_quant.hl1 == 7 &&
           rfx_quant.lh1 == 8 &&
           rfx_quant.hh1 == 9);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_write_component_quant(&graphics_decoded, &rfx_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_quant_values));
    PCHECK(rdp_rfx_parse_component_quant(graphics_decoded.data,
                                         graphics_decoded.length,
                                         &rfx_decode_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_decode_quant.ll3 == rfx_quant.ll3 &&
           rfx_decode_quant.hl3 == rfx_quant.hl3 &&
           rfx_decode_quant.hh1 == rfx_quant.hh1);
    PCHECK(rdp_rfx_parse_progressive_quant(rfx_progressive_quant_values,
                                           sizeof(rfx_progressive_quant_values),
                                           &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_quant.quality == 0x64 &&
           rfx_progressive_quant.y.ll3 == 1 &&
           rfx_progressive_quant.cb.ll3 == 2 &&
           rfx_progressive_quant.cr.ll3 == 3);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_write_progressive_quant(&graphics_decoded, &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_progressive_quant_values));
    PCHECK(rdp_rfx_parse_progressive_quant(graphics_decoded.data,
                                           graphics_decoded.length,
                                           &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_quant.quality == 0x64 &&
           rfx_progressive_quant.y.ll3 == 1 &&
           rfx_progressive_quant.cb.ll3 == 2 &&
           rfx_progressive_quant.cr.ll3 == 3);
    rfx_decode_quant = rfx_quant;
    rfx_decode_quant.ll3 = 16;
    PCHECK(rdp_rfx_write_component_quant(&graphics_decoded, &rfx_decode_quant) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.y,
                                       &rfx_added_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_added_quant.ll3 == 1 &&
           rfx_added_quant.hl3 == 2 &&
           rfx_added_quant.hh1 == 10);
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.cr,
                                       &rfx_added_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_added_quant.hh1 == 12);
    rfx_progressive_quant.cr.hh1 = 8;
    PCHECK(rdp_rfx_add_component_quant(&rfx_quant,
                                       &rfx_progressive_quant.cr,
                                       &rfx_added_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_rfx_parse_progressive_quant(rfx_bad_progressive_quant_values,
                                           sizeof(rfx_bad_progressive_quant_values),
                                           &rfx_progressive_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_rfx_parse_component_quant(rfx_quant_values,
                                         sizeof(rfx_quant_values) - 1u,
                                         &rfx_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rfx_component[0] = 1;
    rfx_component[1] = 2;
    rfx_component[2] = -4;
    PCHECK(rdp_rfx_differential_decode(rfx_component, 3) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 1 && rfx_component[1] == 3 && rfx_component[2] == -1);
    memset(rfx_component, 0, sizeof(rfx_component));
    memset(&rfx_decode_quant, 0, sizeof(rfx_decode_quant));
    rfx_decode_quant.ll3 = 4;
    rfx_decode_quant.hl3 = 1;
    rfx_decode_quant.lh3 = 1;
    rfx_decode_quant.hh3 = 1;
    rfx_decode_quant.hl2 = 1;
    rfx_decode_quant.lh2 = 1;
    rfx_decode_quant.hh2 = 1;
    rfx_decode_quant.hl1 = 3;
    rfx_decode_quant.lh1 = 2;
    rfx_decode_quant.hh1 = 1;
    rfx_component[0] = 1;
    rfx_component[1024] = 1;
    rfx_component[4032] = 1;
    PCHECK(rdp_rfx_inverse_quantize(rfx_component,
                                    RDP_RFX_TILE_COEFFICIENTS,
                                    &rfx_decode_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 4 && rfx_component[1024] == 2 && rfx_component[4032] == 8);
    PCHECK(rdp_rfx_inverse_quantize(rfx_component,
                                    RDP_RFX_TILE_COEFFICIENTS - 1u,
                                    &rfx_decode_quant) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(rfx_component, 0, sizeof(rfx_component));
    PCHECK(rdp_rfx_inverse_dwt_2d(rfx_component, RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK);
    PCHECK(rfx_component[0] == 0 && rfx_component[RDP_RFX_TILE_COEFFICIENTS - 1u] == 0);
    memset(rfx_y, 0, sizeof(rfx_y));
    memset(rfx_cb, 0, sizeof(rfx_cb));
    memset(rfx_cr, 0, sizeof(rfx_cr));
    memset(&rfx_pixels, 0, sizeof(rfx_pixels));
    PCHECK(rdp_rfx_ycbcr_to_bgra(rfx_y, rfx_cb, rfx_cr, rfx_pixels.bgra, 64u * 4u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 128 && rfx_pixels.bgra[1] == 128 &&
           rfx_pixels.bgra[2] == 128 && rfx_pixels.bgra[3] == 0xff);
    rfx_y[0] = -4096;
    PCHECK(rdp_rfx_ycbcr_to_bgra(rfx_y, rfx_cb, rfx_cr, rfx_pixels.bgra, 64u * 4u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 0 && rfx_pixels.bgra[1] == 0 &&
           rfx_pixels.bgra[2] == 0 && rfx_pixels.bgra[3] == 0xff);
    rfx_zero_rlgr[0] = 0x00;
    rfx_zero_rlgr[1] = 0x00;
    rfx_zero_rlgr[2] = 0x08;
    rfx_zero_rlgr[3] = 0x08;
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_rlgr_write_zeroes(&graphics_decoded,
                                     RDP_RFX_TILE_COEFFICIENTS) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(rfx_zero_rlgr) &&
           memcmp(graphics_decoded.data, rfx_zero_rlgr, sizeof(rfx_zero_rlgr)) == 0);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_component,
                               RDP_RFX_TILE_COEFFICIENTS,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == RDP_RFX_TILE_COEFFICIENTS &&
           rfx_component[0] == 0 &&
           rfx_component[RDP_RFX_TILE_COEFFICIENTS - 1u] == 0);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR3,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_component,
                               RDP_RFX_TILE_COEFFICIENTS,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == RDP_RFX_TILE_COEFFICIENTS);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_init(&graphics_decoded);
    PCHECK(rdp_rfx_rlgr_write_zeroes(&graphics_decoded, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_rfx_rlgr_decode(RDP_RFX_RLGR1,
                               graphics_decoded.data,
                               graphics_decoded.length,
                               rfx_coefficients,
                               2,
                               &rfx_written) == LIBRDP_STATUS_OK);
    PCHECK(rfx_written == 2 && rfx_coefficients[0] == 0 && rfx_coefficients[1] == 0);
    PCHECK(rdp_rfx_rlgr_write_zeroes(NULL, 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    graphics_decoded.length = 0;
    memset(&rfx_decode_quant, 0, sizeof(rfx_decode_quant));
    rfx_decode_quant.ll3 = 1;
    rfx_decode_quant.hl3 = 1;
    rfx_decode_quant.lh3 = 1;
    rfx_decode_quant.hh3 = 1;
    rfx_decode_quant.hl2 = 1;
    rfx_decode_quant.lh2 = 1;
    rfx_decode_quant.hh2 = 1;
    rfx_decode_quant.hl1 = 1;
    rfx_decode_quant.lh1 = 1;
    rfx_decode_quant.hh1 = 1;
    PCHECK(rdp_rfx_decode_progressive_tile(rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           0,
                                           &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.stride == 64u * 4u &&
           rfx_pixels.bgra[0] == 128 &&
           rfx_pixels.bgra[1] == 128 &&
           rfx_pixels.bgra[2] == 128 &&
           rfx_pixels.bgra[3] == 0xff);
    PCHECK(rdp_rfx_decode_progressive_tile(rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           rfx_zero_rlgr,
                                           sizeof(rfx_zero_rlgr),
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           &rfx_decode_quant,
                                           1,
                                           &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_pixels.bgra[0] == 128 &&
           rfx_pixels.bgra[(63u * 64u * 4u) + (63u * 4u)] == 128);
    memset(&rfx_zero_delta, 0, sizeof(rfx_zero_delta));
    memset(&rfx_progressive_state, 0, sizeof(rfx_progressive_state));
    memset(&rfx_upgrade_pixels, 0, sizeof(rfx_upgrade_pixels));
    PCHECK(rdp_rfx_decode_progressive_tile_state(rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 1,
                                                 0,
                                                 &rfx_progressive_state,
                                                 &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.valid &&
           rfx_progressive_state.y.valid &&
           rfx_progressive_state.cb.valid &&
           rfx_progressive_state.cr.valid &&
           rfx_progressive_state.pass == 1 &&
           rfx_progressive_state.extrapolate == 1);
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.pass == 2 &&
           rfx_upgrade_pixels.stride == 64u * 4u &&
           rfx_upgrade_pixels.bgra[0] == 128 &&
           rfx_upgrade_pixels.bgra[1] == 128 &&
           rfx_upgrade_pixels.bgra[2] == 128 &&
           rfx_upgrade_pixels.bgra[3] == 0xff);
    rfx_progressive_state.y.current[0] = 64;
    rfx_progressive_state.y.sign[0] = 1;
    PCHECK(rdp_rfx_decode_progressive_tile_state(rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 rfx_zero_rlgr,
                                                 sizeof(rfx_zero_rlgr),
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 &rfx_decode_quant,
                                                 &rfx_zero_delta,
                                                 1,
                                                 1,
                                                 &rfx_progressive_state,
                                                 &rfx_pixels) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_state.pass == 3 &&
           rfx_progressive_state.y.current[0] == 64 &&
           rfx_progressive_state.y.sign[0] == 1);
    memset(&rfx_progressive_state, 0, sizeof(rfx_progressive_state));
    PCHECK(rdp_rfx_decode_progressive_upgrade_tile(NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   NULL,
                                                   0,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   &rfx_decode_quant,
                                                   &rfx_zero_delta,
                                                   1,
                                                   &rfx_progressive_state,
                                                   &rfx_upgrade_pixels) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_planar_decode_argb(planar_no_alpha,
                                  sizeof(planar_no_alpha),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.length == 8 &&
           planar_pixels.data[0] == 0x50 &&
           planar_pixels.data[1] == 0x30 &&
           planar_pixels.data[2] == 0x10 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 0x60 &&
           planar_pixels.data[5] == 0x40 &&
           planar_pixels.data[6] == 0x20 &&
           planar_pixels.data[7] == 0xff);
    planar_pixels.length = 0;
    PCHECK(rdp_planar_decode_argb(planar_alpha_padded,
                                  sizeof(planar_alpha_padded),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(planar_pixels.data[0] == 0x55 &&
           planar_pixels.data[1] == 0x33 &&
           planar_pixels.data[2] == 0x11 &&
           planar_pixels.data[3] == 0x7f &&
           planar_pixels.data[4] == 0x66 &&
           planar_pixels.data[5] == 0x44 &&
           planar_pixels.data[6] == 0x22 &&
           planar_pixels.data[7] == 0x80);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_no_alpha,
                                  sizeof(planar_ycocg_no_alpha),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 90 &&
           planar_pixels.data[1] == 120 &&
           planar_pixels.data[2] == 70 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 110 &&
           planar_pixels.data[5] == 80 &&
           planar_pixels.data[6] == 130 &&
           planar_pixels.data[7] == 0xff);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_alpha_padded,
                                  sizeof(planar_ycocg_alpha_padded),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           planar_pixels.data[0] == 100 &&
           planar_pixels.data[1] == 100 &&
           planar_pixels.data[2] == 100 &&
           planar_pixels.data[3] == 0x7f);
    PCHECK(rdp_planar_decode_argb(planar_ycocg_subsampled,
                                  sizeof(planar_ycocg_subsampled),
                                  3,
                                  3,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 &&
           planar_pixels.data[0] == 100 &&
           planar_pixels.data[2] == 100 &&
           planar_pixels.data[8] == 110 &&
           planar_pixels.data[10] == 90 &&
           planar_pixels.data[24] == 120 &&
           planar_pixels.data[26] == 80 &&
           planar_pixels.data[32] == 130 &&
           planar_pixels.data[34] == 70);
    PCHECK(rdp_planar_decode_argb(planar_rle_argb,
                                  sizeof(planar_rle_argb),
                                  2,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 0x50 &&
           planar_pixels.data[1] == 0x30 &&
           planar_pixels.data[2] == 0x10 &&
           planar_pixels.data[3] == 0xff &&
           planar_pixels.data[4] == 0x60 &&
           planar_pixels.data[5] == 0x40 &&
           planar_pixels.data[6] == 0x20 &&
           planar_pixels.data[7] == 0xff);
    PCHECK(rdp_planar_decode_argb(planar_rle_delta,
                                  sizeof(planar_rle_delta),
                                  2,
                                  2,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           planar_pixels.data[0] == 50 &&
           planar_pixels.data[1] == 30 &&
           planar_pixels.data[2] == 10 &&
           planar_pixels.data[8] == 50 &&
           planar_pixels.data[9] == 30 &&
           planar_pixels.data[10] == 5 &&
           planar_pixels.data[12] == 60 &&
           planar_pixels.data[13] == 40 &&
           planar_pixels.data[14] == 25);
    PCHECK(rdp_planar_decode_argb(planar_reserved,
                                  sizeof(planar_reserved),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_planar_decode_argb(planar_subsample_without_loss,
                                  sizeof(planar_subsample_without_loss),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_planar_decode_argb(planar_rle_bad_zero_control,
                                  sizeof(planar_rle_bad_zero_control),
                                  1,
                                  1,
                                  &planar_pixels,
                                  &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_nscodec_parse_capability(nscodec_capability_data,
                                        sizeof(nscodec_capability_data),
                                        &nscodec_capability) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_capability.allow_dynamic_fidelity == 1 &&
           nscodec_capability.allow_subsampling == 1 &&
           nscodec_capability.color_loss_level == 7);
    PCHECK(rdp_nscodec_parse_capability(nscodec_bad_capability_data,
                                        sizeof(nscodec_bad_capability_data),
                                        &nscodec_capability) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_nscodec_write_capability(&nscodec_capability_buffer,
                                        &(rdp_nscodec_capability){1, 0, 3}) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_capability_buffer.length == 3 &&
           nscodec_capability_buffer.data[0] == 1 &&
           nscodec_capability_buffer.data[1] == 0 &&
           nscodec_capability_buffer.data[2] == 3);
    PCHECK(rdp_nscodec_parse_stream(nscodec_raw_argb,
                                    sizeof(nscodec_raw_argb),
                                    1,
                                    1,
                                    &nscodec_stream) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_stream.luma_len == 1 &&
           nscodec_stream.orange_chroma_len == 1 &&
           nscodec_stream.green_chroma_len == 1 &&
           nscodec_stream.alpha_len == 1 &&
           nscodec_stream.luma[0] == 100);
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_raw_argb,
                                     sizeof(nscodec_raw_argb),
                                     1,
                                     1,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           nscodec_pixels.length == 4 &&
           nscodec_pixels.data[0] == 70 &&
           nscodec_pixels.data[1] == 120 &&
           nscodec_pixels.data[2] == 90 &&
           nscodec_pixels.data[3] == 0x7f);
    PCHECK(rdp_nscodec_decode_rle_plane(nscodec_rle_plane,
                                        sizeof(nscodec_rle_plane),
                                        nscodec_rle_decoded,
                                        7) == LIBRDP_STATUS_OK);
    PCHECK(nscodec_rle_decoded[0] == 0x63 &&
           nscodec_rle_decoded[1] == 0x63 &&
           nscodec_rle_decoded[2] == 0x63 &&
           nscodec_rle_decoded[3] == 0x64 &&
           nscodec_rle_decoded[4] == 0x65 &&
           nscodec_rle_decoded[5] == 0x65 &&
           nscodec_rle_decoded[6] == 0x65);
    nscodec_pixels.length = 0;
    PCHECK(rdp_nscodec_decode_bgra32(&nscodec_context,
                                     nscodec_subsampled_rle,
                                     sizeof(nscodec_subsampled_rle),
                                     3,
                                     3,
                                     &nscodec_pixels,
                                     &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 12 &&
           nscodec_pixels.length == 36 &&
           nscodec_pixels.data[0] == 100 &&
           nscodec_pixels.data[1] == 100 &&
           nscodec_pixels.data[2] == 100 &&
           nscodec_pixels.data[3] == 0xff &&
           nscodec_pixels.data[32] == 100 &&
           nscodec_pixels.data[35] == 0xff);
    PCHECK(rdp_nscodec_parse_stream(nscodec_invalid_stream,
                                    sizeof(nscodec_invalid_stream),
                                    1,
                                    1,
                                    &nscodec_stream) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len - 1u, &bitmap_update) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_bitmap_parse_update(orders_update_payload, sizeof(orders_update_payload), &bitmap_update) ==
           LIBRDP_STATUS_UNSUPPORTED);
    memset(&virtual_channel_minimal_set, 0, sizeof(virtual_channel_minimal_set));
    virtual_channel_minimal_set.type = RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL;
    virtual_channel_minimal_set.length = 8;
    virtual_channel_minimal_set.data = virtual_channel_minimal_data;
    virtual_channel_minimal_set.data_len = sizeof(virtual_channel_minimal_data);
    PCHECK(rdp_slowpath_write_confirm_active(&confirm_active, 0x12345678u, 1004, 800, 600, "librdp") ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_share_control_header(confirm_active.data, confirm_active.length, &slow_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == confirm_active.length);
    PCHECK((slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE);
    PCHECK(slow_header.channel_id == 1004);
    PCHECK(confirm_active.data[6] == 0x78 && confirm_active.data[10] == 0xea);
    confirm_source_len = (uint16_t)(confirm_active.data[12] | ((uint16_t)confirm_active.data[13] << 8));
    confirm_caps_len = (uint16_t)(confirm_active.data[14] | ((uint16_t)confirm_active.data[15] << 8));
    PCHECK(confirm_source_len == 6);
    PCHECK(rdp_capabilities_parse(confirm_active.data + 16u + confirm_source_len,
                                  confirm_caps_len,
                                  &confirm_caps) == LIBRDP_STATUS_OK);
    PCHECK(confirm_caps.count == sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]));
    PCHECK(confirm_caps_len == 443);
    for (i = 0; i < sizeof(expected_confirm_types) / sizeof(expected_confirm_types[0]); i++)
    {
        PCHECK(confirm_caps.sets[i].type == expected_confirm_types[i]);
        PCHECK(confirm_caps.sets[i].length == expected_confirm_lengths[i]);
    }
    confirm_bitmap_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP);
    PCHECK(confirm_bitmap_set != NULL);
    PCHECK(rdp_capability_parse_bitmap(confirm_bitmap_set, &confirm_bitmap) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap.preferred_bits_per_pixel == 32 &&
           confirm_bitmap.desktop_width == 800 &&
           confirm_bitmap.desktop_height == 600 &&
           confirm_bitmap.desktop_resize_flag == 1 &&
           confirm_bitmap.bitmap_compression_flag == 1 &&
           confirm_bitmap.multiple_rectangle_support == 1);
    PCHECK(rdp_capability_parse_bitmap(confirm_caps.sets, &confirm_bitmap) == LIBRDP_STATUS_PROTOCOL_ERROR);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GENERAL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_general(confirm_set, &confirm_general) == LIBRDP_STATUS_OK);
    PCHECK(confirm_general.os_major_type == 1 &&
           confirm_general.os_minor_type == 3 &&
           confirm_general.protocol_version == 0x0200u &&
           confirm_general.extra_flags == 0x0404u &&
           confirm_general.refresh_rect_support == 1 &&
           confirm_general.suppress_output_support == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ORDER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_order(confirm_set, &confirm_order) == LIBRDP_STATUS_OK);
    PCHECK(confirm_order.desktop_save_x_granularity == 1 &&
           confirm_order.desktop_save_y_granularity == 20 &&
           confirm_order.maximum_order_level == 1 &&
           confirm_order.order_flags == 0x002au &&
           confirm_order.desktop_save_size == 230400u &&
           confirm_order.text_ansi_code_page == 65001u);
    for (i = 0; i < sizeof(confirm_order.order_support); i++)
        PCHECK(confirm_order.order_support[i] == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_cache_v2(confirm_set, &confirm_bitmap_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_cache.cache_flags == 2 &&
           confirm_bitmap_cache.num_cell_caches == 5 &&
           confirm_bitmap_cache.cell_info[0] == 600 &&
           confirm_bitmap_cache.cell_info[1] == 600 &&
           confirm_bitmap_cache.cell_info[2] == 2048 &&
           confirm_bitmap_cache.cell_info[3] == 4096 &&
           confirm_bitmap_cache.cell_info[4] == 2048);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_pointer(confirm_set, &confirm_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_pointer.color_pointer_flag == 1 &&
           confirm_pointer.color_pointer_cache_size == 128 &&
           confirm_pointer.pointer_cache_size == 128);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_LARGE_POINTER);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_large_pointer(confirm_set, &confirm_large_pointer) == LIBRDP_STATUS_OK);
    PCHECK(confirm_large_pointer.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_INPUT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_input(confirm_set, &confirm_input) == LIBRDP_STATUS_OK);
    PCHECK(confirm_input.input_flags == 0x0115u &&
           confirm_input.keyboard_layout == 0x00000409u &&
           confirm_input.keyboard_type == 4 &&
           confirm_input.keyboard_subtype == 0 &&
           confirm_input.keyboard_function_key == 12);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BRUSH);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_brush(confirm_set, &confirm_brush) == LIBRDP_STATUS_OK);
    PCHECK(confirm_brush.support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_GLYPH_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_glyph_cache(confirm_set, &confirm_glyph) == LIBRDP_STATUS_OK);
    PCHECK(confirm_glyph.glyph_cache[0].cache_entries == 254 &&
           confirm_glyph.glyph_cache[0].maximum_cell_size == 4 &&
           confirm_glyph.glyph_cache[9].cache_entries == 254 &&
           confirm_glyph.glyph_cache[9].maximum_cell_size == 256 &&
           confirm_glyph.frag_cache_entries == 256 &&
           confirm_glyph.frag_cache_maximum_cell_size == 256 &&
           confirm_glyph.glyph_support_level == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_virtual_channel(confirm_set, &confirm_virtual_channel) == LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 0 &&
           confirm_virtual_channel.has_chunk_size == 1 &&
           confirm_virtual_channel.chunk_size == 1600);
    PCHECK(rdp_capability_parse_virtual_channel(&virtual_channel_minimal_set, &confirm_virtual_channel) ==
           LIBRDP_STATUS_OK);
    PCHECK(confirm_virtual_channel.flags == 1 &&
           confirm_virtual_channel.has_chunk_size == 0 &&
           confirm_virtual_channel.chunk_size == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SOUND);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_sound(confirm_set, &confirm_sound) == LIBRDP_STATUS_OK);
    PCHECK(confirm_sound.flags == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_SHARE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_share(confirm_set, &confirm_share) == LIBRDP_STATUS_OK);
    PCHECK(confirm_share.node_id == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_FONT);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_font(confirm_set, &confirm_font) == LIBRDP_STATUS_OK);
    PCHECK(confirm_font.support_flags == 1);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_CONTROL);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_control(confirm_set, &confirm_control) == LIBRDP_STATUS_OK);
    PCHECK(confirm_control.control_flags == 0 &&
           confirm_control.remote_detach_flag == 0 &&
           confirm_control.control_interest == 2 &&
           confirm_control.detach_interest == 2);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_COLOR_CACHE);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_color_cache(confirm_set, &confirm_color_cache) == LIBRDP_STATUS_OK);
    PCHECK(confirm_color_cache.cache_size == 6);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_ACTIVATION);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_activation(confirm_set, &confirm_activation) == LIBRDP_STATUS_OK);
    PCHECK(confirm_activation.help_key_flag == 0 &&
           confirm_activation.help_key_index_flag == 0 &&
           confirm_activation.help_extended_key_flag == 0 &&
           confirm_activation.window_manager_key_flag == 0);
    confirm_set = rdp_capabilities_find(&confirm_caps, RDP_CAPABILITY_TYPE_BITMAP_CODECS);
    PCHECK(confirm_set != NULL);
    PCHECK(rdp_capability_parse_bitmap_codecs(confirm_set, &confirm_bitmap_codecs) == LIBRDP_STATUS_OK);
    PCHECK(confirm_bitmap_codecs.count == 1 &&
           confirm_bitmap_codecs.codecs[0].codec_id == RDP_NSCODEC_BITMAP_CODEC_ID &&
           confirm_bitmap_codecs.codecs[0].properties_len == RDP_NSCODEC_CAPABILITY_LENGTH &&
           memcmp(confirm_bitmap_codecs.codecs[0].guid, nscodec_guid, sizeof(nscodec_guid)) == 0);
    PCHECK(rdp_nscodec_parse_capability(confirm_bitmap_codecs.codecs[0].properties,
                                        confirm_bitmap_codecs.codecs[0].properties_len,
                                        &confirm_nscodec) == LIBRDP_STATUS_OK);
    PCHECK(confirm_nscodec.allow_dynamic_fidelity == 1 &&
           confirm_nscodec.allow_subsampling == 1 &&
           confirm_nscodec.color_loss_level == 7);
    PCHECK(rdp_capability_parse_general(confirm_bitmap_set, &confirm_general) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(confirm_caps.sets[0].data[0] == 1 && confirm_caps.sets[0].data[2] == 3 &&
           confirm_caps.sets[0].data[4] == 0x00 && confirm_caps.sets[0].data[5] == 0x02);
    PCHECK(confirm_caps.sets[1].data[0] == 32 && confirm_caps.sets[1].data[8] == 0x20 &&
           confirm_caps.sets[1].data[9] == 0x03 && confirm_caps.sets[1].data[10] == 0x58 &&
           confirm_caps.sets[1].data[11] == 0x02);
    PCHECK(confirm_caps.sets[2].data[30] == 0x2a && confirm_caps.sets[2].data[31] == 0x00);
    PCHECK(confirm_caps.sets[5].data[0] == 1 && confirm_caps.sets[5].data[1] == 0);
    PCHECK(confirm_caps.sets[6].data[0] == 0x15 && confirm_caps.sets[6].data[1] == 0x01 &&
           confirm_caps.sets[6].data[4] == 0x09 && confirm_caps.sets[6].data[5] == 0x04);
    PCHECK(rdp_slowpath_write_client_synchronize(&client_sync, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_sync.data, client_sync.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.share_id == 0x12345678u &&
           data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE &&
           data_pdu.payload_len == 4);
    PCHECK(test_read_u16_le(data_pdu.payload) == 1 && test_read_u16_le(data_pdu.payload + 2) == 1004);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload) == 4 &&
           test_read_u16_le(data_pdu.payload + 2) == 0 &&
           test_read_u32_le(data_pdu.payload + 4) == 0);
    client_control.length = 0;
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_control.data, client_control.length, &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL &&
           test_read_u16_le(data_pdu.payload) == 1);
    PCHECK(rdp_slowpath_write_client_control(&client_control, 0x12345678u, 1004, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_persistent_key_list(&client_persistent_keys, 0x12345678u, 1004) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_persistent_keys.data,
                                       client_persistent_keys.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST &&
           data_pdu.payload_len == 24 &&
           data_pdu.payload[20] == 3);
    for (i = 0; i < 20; i++)
        PCHECK(data_pdu.payload[i] == 0);
    PCHECK(data_pdu.payload[21] == 0 && data_pdu.payload[22] == 0 && data_pdu.payload[23] == 0);
    PCHECK(rdp_slowpath_write_client_font_list(&client_font_list, 0x12345678u, 1004) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_font_list.data, client_font_list.length, &data_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST &&
           data_pdu.payload_len == 8 &&
           test_read_u16_le(data_pdu.payload + 4) == 3 &&
           test_read_u16_le(data_pdu.payload + 6) == 50);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0x8000u,
                                                    30) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload) == 1 &&
           test_read_u16_le(data_pdu.payload + 8) == 4 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 30);
    PCHECK(rdp_slowpath_write_client_keyboard_input(&client_keyboard_input,
                                                    0x12345678u,
                                                    1004,
                                                    0,
                                                    256) == LIBRDP_STATUS_INVALID_ARGUMENT);
    client_keyboard_input.length = 0;
    PCHECK(rdp_slowpath_write_client_unicode_keyboard_input(&client_keyboard_input,
                                                            0x12345678u,
                                                            1004,
                                                            0x8000u,
                                                            0x20acu) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_keyboard_input.data,
                                       client_keyboard_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 5 &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8000u &&
           test_read_u16_le(data_pdu.payload + 12) == 0x20acu);
    PCHECK(rdp_slowpath_write_client_mouse_input(&client_mouse_input,
                                                 0x12345678u,
                                                 1004,
                                                 0x9000u,
                                                 10,
                                                 11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x9000u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    client_mouse_input.length = 0;
    PCHECK(rdp_slowpath_write_client_extended_mouse_input(&client_mouse_input,
                                                          0x12345678u,
                                                          1004,
                                                          0x8001u,
                                                          10,
                                                          11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_mouse_input.data,
                                       client_mouse_input.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT &&
           data_pdu.payload_len == 16 &&
           test_read_u16_le(data_pdu.payload + 8) == 0x8002u &&
           test_read_u16_le(data_pdu.payload + 10) == 0x8001u &&
           test_read_u16_le(data_pdu.payload + 12) == 10 &&
           test_read_u16_le(data_pdu.payload + 14) == 11);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  2,
                                                  3,
                                                  800,
                                                  600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_refresh_rect.data,
                                       client_refresh_rect.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    PCHECK(rdp_slowpath_write_client_refresh_rect(&client_refresh_rect,
                                                  0x12345678u,
                                                  1004,
                                                  0xffffu,
                                                  0,
                                                  2,
                                                  1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     2,
                                                     3,
                                                     800,
                                                     600) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 12 &&
           data_pdu.payload[0] == 1 &&
           test_read_u16_le(data_pdu.payload + 4) == 2 &&
           test_read_u16_le(data_pdu.payload + 6) == 3 &&
           test_read_u16_le(data_pdu.payload + 8) == 801 &&
           test_read_u16_le(data_pdu.payload + 10) == 602);
    client_suppress_output.length = 0;
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     0,
                                                     0,
                                                     0,
                                                     0,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_slowpath_parse_data_pdu(client_suppress_output.data,
                                       client_suppress_output.length,
                                       &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT &&
           data_pdu.payload_len == 4 &&
           data_pdu.payload[0] == 0);
    PCHECK(rdp_slowpath_write_client_suppress_output(&client_suppress_output,
                                                     0x12345678u,
                                                     1004,
                                                     1,
                                                     0xffffu,
                                                     0,
                                                     2,
                                                     1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload), &font_map) == LIBRDP_STATUS_OK);
    PCHECK(font_map.number_entries == 1 && font_map.total_entries == 2 && font_map.map_flags == 3 &&
           font_map.entry_size == 4);
    PCHECK(rdp_slowpath_parse_font_map(font_map_payload, sizeof(font_map_payload) - 1u, &font_map) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload),
                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    PCHECK(rdp_slowpath_parse_set_error_info(set_error_info_payload,
                                             sizeof(set_error_info_payload) - 1u,
                                             &error_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload,
                                                sizeof(save_session_info_payload),
                                                &save_info) == LIBRDP_STATUS_OK);
    PCHECK(save_info.info_type == 1 && save_info.data_len == 2 && save_info.data[0] == 0xaa &&
           save_info.data[1] == 0x55);
    PCHECK(rdp_slowpath_parse_save_session_info(save_session_info_payload, 3, &save_info) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_STANDARD) == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_TLS) == RDP_X224_PROTOCOL_TLS);
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_NLA));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_STANDARD));

    memset(&info, 0, sizeof(info));
    info.domain = "D";
    info.username = "user";
    info.password = "secret";
    PCHECK(rdp_security_write_client_info_pdu(&security, &info) == LIBRDP_STATUS_OK);
    PCHECK(security.length > 200u);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.domain_bytes == 2);
    PCHECK(info_summary.username_bytes == 8);
    PCHECK(info_summary.password_bytes == 12);
    PCHECK((info_summary.flags & 0x00000010u) != 0);
    PCHECK((info_summary.flags & 0x00000008u) != 0);
    security.length = 0;
    no_password_info = info;
    no_password_info.password = NULL;
    PCHECK(rdp_security_write_client_info_pdu(&security, &no_password_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.password_bytes == 0);
    PCHECK((info_summary.flags & 0x00000008u) == 0);
    for (i = 0; i < sizeof(client_random); i++)
    {
        client_random[i] = (uint8_t)(i + 1u);
        server_random[i] = (uint8_t)(0xa0u + i);
    }
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 16);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_client_info_body(&plain_info_body, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_mac_signature(&secure_b, plain_info_body.data, plain_info_body.length, signature) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_client_info_pdu(&encrypted_info, &secure_a, &info) == LIBRDP_STATUS_OK);
    PCHECK(encrypted_info.length == plain_info_body.length + 12u);
    PCHECK(encrypted_info.data[0] == (uint8_t)(RDP_SEC_INFO_PKT | RDP_SEC_ENCRYPT));
    PCHECK(memcmp(encrypted_info.data + 4, signature, sizeof(signature)) == 0);
    PCHECK(memcmp(encrypted_info.data + 12, plain_info_body.data, plain_info_body.length) != 0);
    PCHECK(rdp_buffer_append(&expected_cipher, plain_info_body.data, plain_info_body.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(encrypted_info.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_encrypted_pdu(&protected_pdu,
                                            &secure_a,
                                            0,
                                            orders_update_payload,
                                            sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(protected_pdu.length == sizeof(orders_update_payload) + 12u);
    PCHECK((test_read_u16_le(protected_pdu.data) & RDP_SEC_ENCRYPT) != 0);
    expected_cipher.length = 0;
    PCHECK(rdp_buffer_append(&expected_cipher, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_encrypt_payload(&secure_b, expected_cipher.data, expected_cipher.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(protected_pdu.data + 12, expected_cipher.data, expected_cipher.length) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_standard_client_init(&secure_b,
                                             RDP_SECURITY_METHOD_128BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    protected_pdu.length = 0;
    PCHECK(rdp_security_mac_signature(&secure_a,
                                      orders_update_payload,
                                      sizeof(orders_update_payload),
                                      signature) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_write_header(&protected_pdu, RDP_SEC_ENCRYPT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, signature, sizeof(signature)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&protected_pdu, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_security_decrypt_payload(&secure_a,
                                        protected_pdu.data + 12,
                                        sizeof(orders_update_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_unwrap_pdu(&secure_b,
                                   protected_pdu.data,
                                   protected_pdu.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK((security_flags & RDP_SEC_ENCRYPT) != 0);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);
    PCHECK(rdp_security_write_header(&plain_security, RDP_SEC_LICENSE_PKT) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&plain_security, orders_update_payload, sizeof(orders_update_payload)) ==
           LIBRDP_STATUS_OK);
    security_flags = 0;
    unwrapped_pdu.length = 0;
    PCHECK(rdp_security_unwrap_pdu(NULL,
                                   plain_security.data,
                                   plain_security.length,
                                   &unwrapped_pdu,
                                   &security_flags) == LIBRDP_STATUS_OK);
    PCHECK(security_flags == RDP_SEC_LICENSE_PKT);
    PCHECK(unwrapped_pdu.length == sizeof(orders_update_payload) &&
           memcmp(unwrapped_pdu.data, orders_update_payload, sizeof(orders_update_payload)) == 0);
    rdp_security_standard_clear(&secure_a);
    rdp_security_standard_clear(&secure_b);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_40BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1 && secure_a.sign_key[2] == 0x9e);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_56BIT,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_OK);
    PCHECK(secure_a.key_len == 8 && secure_a.sign_key[0] == 0xd1);
    rdp_security_standard_clear(&secure_a);
    PCHECK(rdp_security_standard_client_init(&secure_a,
                                             RDP_SECURITY_METHOD_FIPS,
                                             client_random,
                                             server_random) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_security_write_send_data_request(&send_data, 1004, RDP_MCS_GLOBAL_CHANNEL_ID, security.data,
                                                security.length) == LIBRDP_STATUS_OK);
    PCHECK(send_data.length > security.length);
    PCHECK(send_data.data[0] == 0x64);
    PCHECK(send_data.data[1] == 0x00 && send_data.data[2] == 0x03);
    PCHECK(send_data.data[3] == 0x03 && send_data.data[4] == 0xeb);
    rdp_buffer_free(&security);
    rdp_buffer_init(&security);
    PCHECK(rdp_security_write_exchange_pdu(&security, encrypted_random, sizeof(encrypted_random)) ==
           LIBRDP_STATUS_OK);
    PCHECK(security.length == sizeof(encrypted_random) + 16u);
    PCHECK(test_read_u16_le(security.data) == (RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    PCHECK(security.data[4] == (uint8_t)(sizeof(encrypted_random) + 8u));
    memset(client_random, 0x4a, sizeof(client_random));
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate), &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(public_key.modulus_le[0] == 0xeb && public_key.modulus_le[127] == 0xb2);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    PCHECK(memcmp(encrypted.data, client_random, sizeof(client_random)) != 0);
    rdp_security_public_key_clear(&public_key);
    rdp_buffer_free(&encrypted);
    rdp_buffer_init(&encrypted);
    security.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 6) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&security, 284) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 0x31415352u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 264) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 2048) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 255) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&security, 65537) == LIBRDP_STATUS_OK);
    for (i = 0; i < 256u; i++)
        PCHECK(rdp_buffer_append_u8(&security, (uint8_t)(1u + (i & 0x7fu))) == LIBRDP_STATUS_OK);
    for (i = 0; i < 8u; i++)
        PCHECK(rdp_buffer_append_u8(&security, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(security.data, security.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 2048u && public_key.modulus_len == 256u);
    PCHECK(public_key.modulus_le[0] == 1 && public_key.modulus_le[255] == 128);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&x509_chain, (uint32_t)sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&x509_chain, x509_der, sizeof(x509_der)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length, &public_key) ==
           LIBRDP_STATUS_OK);
    PCHECK(public_key.exponent == 65537u && public_key.bit_len == 1024u && public_key.modulus_len == 128u);
    PCHECK(rdp_security_encrypt_client_random(&public_key, client_random, &encrypted) == LIBRDP_STATUS_OK);
    PCHECK(encrypted.length == public_key.modulus_len);
    rdp_security_public_key_clear(&public_key);
    PCHECK(rdp_security_parse_server_certificate(x509_chain.data, x509_chain.length - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_security_generate_client_random(client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_server_certificate(server_certificate, sizeof(server_certificate) - 1u, &public_key) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_license_parse_error_alert(license, sizeof(license), &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 1 && alert.state_transition == 2 && alert.blob_length == 2 && alert.blob[1] == 8);
    PCHECK(rdp_license_parse_error_alert(license, 15, &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_license_parse_preamble(license, sizeof(license), &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_ERROR_ALERT &&
           license_preamble.payload_len == 14u);
    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         7,
                                         8,
                                         RDP_LICENSE_BLOB_DATA,
                                         "ok",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data, license_packet.length, &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 7 && alert.state_transition == 8 &&
           alert.blob_type == RDP_LICENSE_BLOB_DATA && alert.blob_length == 2);
    license_packet.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_packet,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_binary_blob(license_packet.data,
                                         license_packet.length,
                                         &license_blob) == LIBRDP_STATUS_OK);
    PCHECK(license_blob.type == RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG &&
           license_blob.length == 4 &&
           license_blob.data[0] == 1);
    license_packet.length = 0;
    PCHECK(test_append_zeroes(&license_payload, 32u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0x00060002u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_payload, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_KEY_EXCHANGE_ALG,
                                         "\x01\x00\x00\x00",
                                         4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_CERTIFICATE,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_SCOPE,
                                         license_scope,
                                         (uint16_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_REQUEST,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_request(license_packet.data,
                                            license_packet.length,
                                            &license_request) == LIBRDP_STATUS_OK);
    PCHECK(license_request.product_info.version == 0x00060002u &&
           license_request.key_exchange_list.length == 4 &&
           license_request.scope_list.count == 1 &&
           license_request.scope_list.scopes[0].length == sizeof(license_scope));
    PCHECK(rdp_license_parse_server_request(license_packet.data,
                                            license_packet.length - 1u,
                                            &license_request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_payload, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\xaa\xbb",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge(license_packet.data,
                                                license_packet.length,
                                                &license_challenge) == LIBRDP_STATUS_OK);
    PCHECK(license_challenge.encrypted_challenge.length == 2 &&
           license_challenge.encrypted_challenge.data[1] == 0xbb);
    license_packet.length = 0;
    license_payload.length = 0;
    PCHECK(rdp_license_write_binary_blob(&license_payload,
                                         RDP_LICENSE_BLOB_ENCRYPTED_DATA,
                                         "\x11\x22",
                                         2) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&license_payload, 16u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_write_preamble(&license_packet,
                                      RDP_LICENSE_MESSAGE_NEW_LICENSE,
                                      RDP_LICENSE_VERSION_3,
                                      (uint16_t)license_payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_payload.data, license_payload.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_or_upgrade(license_packet.data,
                                            license_packet.length,
                                            &license_new) == LIBRDP_STATUS_OK);
    PCHECK(license_new.encrypted_license_info.type == RDP_LICENSE_BLOB_ENCRYPTED_DATA);
    license_packet.length = 0;
    PCHECK(rdp_buffer_append_u32_le(&license_packet, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_scope, sizeof(license_scope)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_company, sizeof(license_company)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_product, sizeof(license_product)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&license_packet, (uint32_t)sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&license_packet, license_cal, sizeof(license_cal)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_new_license_info(license_packet.data,
                                              license_packet.length,
                                              &license_info) == LIBRDP_STATUS_OK);
    PCHECK(license_info.scope_len == sizeof(license_scope) &&
           license_info.license_info_len == sizeof(license_cal));
    memset(&license_cert_info, 0, sizeof(license_cert_info));
    license_cert_info.version = 1;
    license_cert_info.license_count = 2;
    license_cert_info.platform_id = 0x03010002u;
    license_cert_info.language_id = 0x0410u;
    license_cert_info.requested_product_id = license_requested_id;
    license_cert_info.requested_product_id_len = sizeof(license_requested_id);
    license_cert_info.adjusted_product_id = license_adjusted_id;
    license_cert_info.adjusted_product_id_len = sizeof(license_adjusted_id);
    license_cert_info.version_info.major_version = 10;
    license_cert_info.version_info.minor_version = 0;
    license_cert_info.version_info.flags = RDP_LICENSE_PRODUCT_INFO_LICENSE_ENFORCED |
                                           RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE;
    license_packet.length = 0;
    PCHECK(rdp_license_write_product_certificate_info(&license_packet,
                                                      &license_cert_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                      license_packet.length,
                                                      &parsed_license_cert_info) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_license_cert_info.license_count == 2 &&
           parsed_license_cert_info.requested_product_id_len == sizeof(license_requested_id) &&
           parsed_license_cert_info.adjusted_product_id[4] == 'A' &&
           parsed_license_cert_info.version_info.major_version == 10 &&
           (parsed_license_cert_info.version_info.flags & RDP_LICENSE_PRODUCT_INFO_RTM_LICENSE));
    license_packet.data[27] = 2;
    PCHECK(rdp_license_parse_product_certificate_info(license_packet.data,
                                                      license_packet.length,
                                                      &parsed_license_cert_info) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;

    memset(&license_server_info, 0, sizeof(license_server_info));
    license_server_info.issuer_name = license_issuer_name;
    license_server_info.issuer_name_len = sizeof(license_issuer_name);
    license_server_info.scope = license_issuer_scope;
    license_server_info.scope_len = sizeof(license_issuer_scope);
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_1 &&
           parsed_license_server_info.issuer_name_len == sizeof(license_issuer_name) &&
           parsed_license_server_info.scope_len == sizeof(license_issuer_scope) &&
           !parsed_license_server_info.has_issuer_id);
    license_packet.data[6] = 0;
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;

    license_server_info.issuer_id = license_issuer_id;
    license_server_info.issuer_id_len = sizeof(license_issuer_id);
    license_server_info.has_issuer_id = 1;
    PCHECK(rdp_license_write_server_info(&license_packet,
                                         &license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_OK);
    PCHECK(parsed_license_server_info.version == RDP_LICENSE_SERVER_INFO_VERSION_2 &&
           parsed_license_server_info.has_issuer_id &&
           parsed_license_server_info.issuer_id_len == sizeof(license_issuer_id));
    license_packet.data[10 + sizeof(license_issuer_name) - 1u] = 1;
    PCHECK(rdp_license_parse_server_info(license_packet.data,
                                         license_packet.length,
                                         &parsed_license_server_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.length = 0;

    PCHECK(rdp_license_write_error_alert(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         9,
                                         0,
                                         RDP_LICENSE_BLOB_ERROR,
                                         NULL,
                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_error_alert(license_packet.data,
                                         license_packet.length,
                                         &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.blob_type == RDP_LICENSE_BLOB_ERROR && alert.blob_length == 0);
    hardware_id.platform_id = 0x01020304u;
    hardware_id.data1 = 1;
    hardware_id.data2 = 2;
    hardware_id.data3 = 3;
    hardware_id.data4 = 4;
    license_packet.length = 0;
    PCHECK(rdp_license_write_hardware_id(&license_packet, &hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_hardware_id(license_packet.data,
                                         license_packet.length,
                                         &parsed_hardware_id) == LIBRDP_STATUS_OK);
    PCHECK(parsed_hardware_id.platform_id == 0x01020304u && parsed_hardware_id.data4 == 4);
    challenge_response_data.version = 0x0100u;
    challenge_response_data.client_type = 0x0100u;
    challenge_response_data.license_detail_level = 3u;
    challenge_response_data.challenge_len = 2u;
    challenge_response_data.challenge = (const uint8_t*)"\x55\x66";
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response_data(&license_packet,
                                                              &challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_platform_challenge_response_data(license_packet.data,
                                                              license_packet.length,
                                                              &parsed_challenge_response_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(parsed_challenge_response_data.challenge_len == 2 &&
           parsed_challenge_response_data.challenge[0] == 0x55);
    license_blob.type = RDP_LICENSE_BLOB_RANDOM;
    license_blob.length = 2;
    license_blob.data = (const uint8_t*)"\x01\x02";
    license_request.key_exchange_list.type = RDP_LICENSE_BLOB_CLIENT_USER_NAME;
    license_request.key_exchange_list.length = 5;
    license_request.key_exchange_list.data = (const uint8_t*)"user";
    license_request.server_certificate.type = RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME;
    license_request.server_certificate.length = 5;
    license_request.server_certificate.data = (const uint8_t*)"host";
    memset(client_random, 0x5a, sizeof(client_random));
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_new_license_request(&license_packet,
                                                        RDP_LICENSE_VERSION_3,
                                                        RDP_LICENSE_KEY_EXCHANGE_RSA,
                                                        0x03000000u,
                                                        client_random,
                                                        &license_blob,
                                                        &license_request.key_exchange_list,
                                                        &license_request.server_certificate) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_NEW_LICENSE_REQUEST);
    PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                        license_packet.length,
                                                        &client_license_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_license_request.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_request.platform_id == 0x03000000u &&
           client_license_request.encrypted_pre_master.length == 2 &&
           client_license_request.user_name.length == 5 &&
           client_license_request.machine_name.type == RDP_LICENSE_BLOB_CLIENT_MACHINE_NAME);
    license_packet.data[44] = 0xff;
    PCHECK(rdp_license_parse_client_new_license_request(license_packet.data,
                                                        license_packet.length,
                                                        &client_license_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.data[44] = RDP_LICENSE_BLOB_RANDOM;
    license_request.scope_list.scopes[0].type = RDP_LICENSE_BLOB_DATA;
    license_request.scope_list.scopes[0].length = (uint16_t)sizeof(license_cal);
    license_request.scope_list.scopes[0].data = license_cal;
    license_challenge.encrypted_challenge.type = RDP_LICENSE_BLOB_ENCRYPTED_DATA;
    license_challenge.encrypted_challenge.length = 20;
    license_challenge.encrypted_challenge.data = client_random;
    license_packet.length = 0;
    PCHECK(rdp_license_write_client_info(&license_packet,
                                         RDP_LICENSE_VERSION_3,
                                         RDP_LICENSE_KEY_EXCHANGE_RSA,
                                         0x03000000u,
                                         client_random,
                                         &license_blob,
                                         &license_request.scope_list.scopes[0],
                                         &license_challenge.encrypted_challenge,
                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_INFO);
    PCHECK(rdp_license_parse_client_info(license_packet.data,
                                         license_packet.length,
                                         &client_license_info) == LIBRDP_STATUS_OK);
    PCHECK(client_license_info.preferred_key_exchange_alg == RDP_LICENSE_KEY_EXCHANGE_RSA &&
           client_license_info.license_info.length == sizeof(license_cal) &&
           client_license_info.encrypted_hardware_id.length == 20 &&
           client_license_info.mac[15] == 0x5a);
    license_packet.data[48 + license_blob.length] = 0xff;
    PCHECK(rdp_license_parse_client_info(license_packet.data,
                                         license_packet.length,
                                         &client_license_info) == LIBRDP_STATUS_PROTOCOL_ERROR);
    license_packet.data[48 + license_blob.length] = RDP_LICENSE_BLOB_DATA;
    license_packet.length = 0;
    PCHECK(rdp_license_write_platform_challenge_response(&license_packet,
                                                         RDP_LICENSE_VERSION_3,
                                                         &license_challenge.encrypted_challenge,
                                                         &license_challenge.encrypted_challenge,
                                                         client_random) == LIBRDP_STATUS_OK);
    PCHECK(rdp_license_parse_preamble(license_packet.data,
                                      license_packet.length,
                                      &license_preamble) == LIBRDP_STATUS_OK);
    PCHECK(license_preamble.message_type == RDP_LICENSE_MESSAGE_PLATFORM_CHALLENGE_RESPONSE);
    PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                         license_packet.length,
                                                         &client_challenge_response) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_challenge_response.encrypted_response.length == 20 &&
           client_challenge_response.encrypted_hardware_id.length == 20 &&
           client_challenge_response.mac[0] == 0x5a);
    license_packet.data[4] = 0;
    PCHECK(rdp_license_parse_platform_challenge_response(license_packet.data,
                                                         license_packet.length,
                                                         &client_challenge_response) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_virtual_channel_parse_packet(channel, sizeof(channel), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 3 && vc.flags == 0x10 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_parse_packet(channel_fragment, sizeof(channel_fragment), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 8 && vc.flags == RDP_VIRTUAL_CHANNEL_FLAG_FIRST && vc.payload_len == 3 && vc.payload[2] == 3);
    PCHECK(rdp_virtual_channel_write_packet(&channel_packet, dyn_create, sizeof(dyn_create), 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_virtual_channel_parse_packet(channel_packet.data, channel_packet.length, &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == sizeof(dyn_create) && vc.flags == 3 && memcmp(vc.payload, dyn_create, sizeof(dyn_create)) == 0);
    PCHECK(rdp_dynamic_channel_parse_header(dyn_caps, sizeof(dyn_caps), &dyn_header) == LIBRDP_STATUS_OK);
    PCHECK(dyn_header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES && dyn_header.channel_id_bytes == 1);
    PCHECK(rdp_dynamic_channel_parse_header(dyn_bad_header, sizeof(dyn_bad_header), &dyn_header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps, sizeof(dyn_caps), &dyn_parsed_caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_parsed_caps.version == 3 &&
           dyn_parsed_caps.has_priority_charges &&
           dyn_parsed_caps.priority_charge[0] == 936 &&
           dyn_parsed_caps.priority_charge[1] == 3276 &&
           dyn_parsed_caps.priority_charge[2] == 9362 &&
           dyn_parsed_caps.priority_charge[3] == 21845);
    PCHECK(rdp_dynamic_channel_parse_capabilities(dyn_caps_zero, sizeof(dyn_caps_zero), &dyn_parsed_caps) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_dynamic_channel_select_version(0) == 0 &&
           rdp_dynamic_channel_select_version(1) == 1 &&
           rdp_dynamic_channel_select_version(2) == 2 &&
           rdp_dynamic_channel_select_version(3) == 2 &&
           rdp_dynamic_channel_select_version(4) == 2);
    PCHECK(rdp_dynamic_channel_select_channel_id_bytes(0xffu) == 1 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x100u) == 2 &&
           rdp_dynamic_channel_select_channel_id_bytes(0x10000u) == 4);
    PCHECK(rdp_dynamic_channel_data_pdu_header_size(1) == 2 &&
           rdp_dynamic_channel_data_pdu_header_size(2) == 3 &&
           rdp_dynamic_channel_data_pdu_header_size(3) == 0 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0xffu) == 3 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x100u) == 4 &&
           rdp_dynamic_channel_data_first_pdu_header_size(1, 0x10000u) == 6);
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 1);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_capabilities_response(&dyn_response, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 4 && dyn_response.data[0] == 0x50 && dyn_response.data[2] == 2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_create_request(dyn_create,
                                                    sizeof(dyn_create),
                                                    &dyn_create_request) == LIBRDP_STATUS_OK);
    PCHECK(dyn_create_request.channel_id == 7 && dyn_create_request.channel_id_bytes == 1 &&
           dyn_create_request.name_len == 4 && memcmp(dyn_create_request.name, "ECHO", 4) == 0);
    PCHECK(rdp_dynamic_channel_write_create_response(&dyn_response,
                                                     dyn_create_request.channel_id,
                                                     dyn_create_request.channel_id_bytes,
                                                     RDP_DYNAMIC_CHANNEL_STATUS_OK) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 && dyn_response.data[0] == 0x10 && dyn_response.data[1] == 7 &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_data, sizeof(dyn_data), &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 7 && dyn_data_pdu.data_len == 3 && dyn_data_pdu.data[0] == 0xaa);
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          dyn_data_pdu.channel_id,
                                          dyn_data_pdu.channel_id_bytes,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data) && memcmp(dyn_response.data, dyn_data, sizeof(dyn_data)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response,
                                          0x00123456u,
                                          4,
                                          dyn_data_pdu.data,
                                          dyn_data_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 && dyn_response.data[0] == 0x32 &&
           test_read_u32_le(dyn_response.data + 1) == 0x00123456u &&
           memcmp(dyn_response.data + 5, dyn_data_pdu.data, dyn_data_pdu.data_len) == 0);
    PCHECK(rdp_dynamic_channel_parse_data(dyn_response.data, dyn_response.length, &dyn_data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_data_pdu.channel_id == 0x00123456u &&
           dyn_data_pdu.channel_id_bytes == 4 &&
           dyn_data_pdu.data_len == 3);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_data(&dyn_response, 0x100u, 1, dyn_data, sizeof(dyn_data)) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first),
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.channel_id == 7 &&
           dyn_first_pdu.channel_id_bytes == 1 &&
           dyn_first_pdu.total_length == 300 &&
           dyn_first_pdu.data_len == 3 &&
           dyn_first_pdu.data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                dyn_first_pdu.channel_id,
                                                dyn_first_pdu.channel_id_bytes,
                                                dyn_first_pdu.total_length,
                                                dyn_first_pdu.data,
                                                dyn_first_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first) &&
           memcmp(dyn_response.data, dyn_data_first, sizeof(dyn_data_first)) == 0);
    PCHECK(rdp_dynamic_channel_parse_data_first(dyn_data_first,
                                                sizeof(dyn_data_first) - 1u,
                                                &dyn_first_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_pdu.data_len == 2);
    PCHECK(rdp_dynamic_channel_write_data_first(&dyn_response,
                                                7,
                                                1,
                                                300,
                                                dyn_data_first,
                                                RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_close, sizeof(dyn_close), &dyn_close_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 7 && dyn_close_pdu.channel_id_bytes == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x1234u, 2) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 3 && dyn_response.data[0] == 0x41 &&
           test_read_u16_le(dyn_response.data + 1) == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_close(dyn_response.data, dyn_response.length, &dyn_close_pdu) ==
           LIBRDP_STATUS_OK);
    PCHECK(dyn_close_pdu.channel_id == 0x1234u && dyn_close_pdu.channel_id_bytes == 2);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_close(&dyn_response, 0x10000u, 2) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data(dyn_data_compressed,
                                                     sizeof(dyn_data_compressed),
                                                     &dyn_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_compressed_pdu.channel_id == 7 &&
           dyn_compressed_pdu.channel_id_bytes == 1 &&
           dyn_compressed_pdu.data_len == 3 &&
           dyn_compressed_pdu.data[0] == 0xe0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     dyn_compressed_pdu.channel_id,
                                                     dyn_compressed_pdu.channel_id_bytes,
                                                     dyn_compressed_pdu.data,
                                                     dyn_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_compressed) &&
           memcmp(dyn_response.data, dyn_data_compressed, sizeof(dyn_data_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data(&dyn_response,
                                                     7,
                                                     1,
                                                     dyn_compressed_pdu.data,
                                                     1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_compressed_data_first(dyn_data_first_compressed,
                                                           sizeof(dyn_data_first_compressed),
                                                           &dyn_first_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_compressed_pdu.channel_id == 7 &&
           dyn_first_compressed_pdu.total_length == 300 &&
           dyn_first_compressed_pdu.data_len == 3 &&
           dyn_first_compressed_pdu.data[1] == 0x06);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           dyn_first_compressed_pdu.channel_id,
                                                           dyn_first_compressed_pdu.channel_id_bytes,
                                                           dyn_first_compressed_pdu.total_length,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(dyn_data_first_compressed) &&
           memcmp(dyn_response.data, dyn_data_first_compressed, sizeof(dyn_data_first_compressed)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_compressed_data_first(&dyn_response,
                                                           7,
                                                           1,
                                                           1,
                                                           dyn_first_compressed_pdu.data,
                                                           dyn_first_compressed_pdu.data_len) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_request,
                                                       sizeof(dyn_soft_sync_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 22 &&
           dyn_soft_sync.flags == (RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                                   RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) &&
           dyn_soft_sync.tunnel_count == 1);
    PCHECK(rdp_dynamic_channel_soft_sync_request_get_list(&dyn_soft_sync,
                                                          0,
                                                          &dyn_soft_sync_list) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_list.tunnel_type == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
           dyn_soft_sync_list.channel_count == 2);
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 7);
    PCHECK(rdp_dynamic_channel_soft_sync_channel_list_get_id(&dyn_soft_sync_list,
                                                             1,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 0x1234u);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_request(dyn_soft_sync_empty_request,
                                                       sizeof(dyn_soft_sync_empty_request),
                                                       &dyn_soft_sync) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync.length == 8 &&
           dyn_soft_sync.flags == RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED &&
           dyn_soft_sync.tunnel_count == 0);
    dyn_response.length = 0;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[0] == (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE << 4) &&
           test_read_u32_le(dyn_response.data + 2) == 0);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_soft_sync_response.tunnel_count == 0);
    dyn_response.length = 0;
    error_info = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY;
    PCHECK(rdp_dynamic_channel_write_soft_sync_response(&dyn_response, &error_info, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_parse_soft_sync_response(dyn_response.data,
                                                        dyn_response.length,
                                                        &dyn_soft_sync_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_dynamic_channel_soft_sync_response_get_tunnel(&dyn_soft_sync_response,
                                                             0,
                                                             &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_mouse_cursor_write_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           dyn_response.data[1] == 0 &&
           test_read_u16_le(dyn_response.data + 2) == 0 &&
           test_read_u32_le(dyn_response.data + 4) == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           test_read_u32_le(dyn_response.data + 8) == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           test_read_u32_le(dyn_response.data + 12) == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    PCHECK(rdp_mouse_cursor_parse_header(dyn_response.data,
                                         dyn_response.length,
                                         &mouse_cursor_header) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_header.pdu_type == RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE &&
           mouse_cursor_header.update_type == 0);
    PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                               sizeof(mouse_cursor_caps_confirm),
                                               &mouse_cursor_capset) == LIBRDP_STATUS_OK);
    PCHECK(mouse_cursor_capset.signature == RDP_MOUSE_CURSOR_CAPSET_SIGNATURE &&
           mouse_cursor_capset.version == RDP_MOUSE_CURSOR_CAPSET_VERSION1 &&
           mouse_cursor_capset.size == RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    PCHECK(rdp_mouse_cursor_parse_caps_confirm(mouse_cursor_caps_confirm,
                                               sizeof(mouse_cursor_caps_confirm) - 1u,
                                               &mouse_cursor_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_hidden,
                                         sizeof(mouse_cursor_hidden),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_NULL);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_default,
                                         sizeof(mouse_cursor_default),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_DEFAULT);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_position,
                                         sizeof(mouse_cursor_position),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_POSITION &&
           pointer_update.x == 0x22 && pointer_update.y == 0x33);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_cached,
                                         sizeof(mouse_cursor_cached),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_CACHED && pointer_update.cache_index == 5);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                         sizeof(mouse_cursor_shape_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.hot_x == 1 &&
           pointer_update.hot_y == 0 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    rdp_buffer_free(&decoded_pointer);
    rdp_buffer_init(&decoded_pointer);
    PCHECK(rdp_pointer_decode_bgra32(&pointer_update, &decoded_pointer, &pointer_stride) == LIBRDP_STATUS_OK);
    PCHECK(pointer_stride == 8 && decoded_pointer.length == 16 && decoded_pointer.data[15] == 0x00);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_large_32,
                                         sizeof(mouse_cursor_large_32),
                                         &pointer_update) == LIBRDP_STATUS_OK);
    PCHECK(pointer_update.kind == RDP_POINTER_UPDATE_KIND_SHAPE &&
           pointer_update.cache_index == 5 &&
           pointer_update.width == 2 &&
           pointer_update.height == 2 &&
           pointer_update.xor_bpp == 32);
    PCHECK(rdp_mouse_cursor_parse_update(mouse_cursor_shape_32,
                                         sizeof(mouse_cursor_shape_32) - 1u,
                                         &pointer_update) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_init_request(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           dyn_response.data[0] == RDP_CORE_INPUT_SIGNATURE &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST &&
           test_read_u16_le(dyn_response.data + 4) == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           test_read_u16_le(dyn_response.data + 6) == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_parse_header(dyn_response.data, dyn_response.length, &core_header) == LIBRDP_STATUS_OK);
    PCHECK(core_header.pdu_type == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST && core_header.event_count == 0);
    PCHECK(rdp_core_input_parse_init_response(core_response,
                                              sizeof(core_response),
                                              &core_init_response) == LIBRDP_STATUS_OK);
    PCHECK(core_init_response.selected_protocol_version == RDP_CORE_INPUT_PROTOCOL_VERSION_100 &&
           core_init_response.protocol_version_max == RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    PCHECK(rdp_core_input_parse_init_response(core_response,
                                              sizeof(core_response) - 1u,
                                              &core_init_response) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 0) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 6 &&
           dyn_response.data[1] == RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE &&
           dyn_response.data[2] == 1 &&
           dyn_response.data[4] == 0 &&
           dyn_response.data[5] == 0x1e);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event(&dyn_response, 0x1e, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.data[4] == RDP_CORE_INPUT_KBDFLAGS_RELEASE);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_mouse_event(&dyn_response, 0x8800u, 10, 11) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 11 &&
           dyn_response.data[4] == (uint8_t)(RDP_CORE_INPUT_EVENT_MOUSE << 5) &&
           test_read_u16_le(dyn_response.data + 5) == 0x8800u &&
           test_read_u16_le(dyn_response.data + 7) == 10 &&
           test_read_u16_le(dyn_response.data + 9) == 11);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSE &&
           core_events[0].pointer_flags == 0x8800u &&
           core_events[0].x == 10 &&
           core_events[0].y == 11);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_keyboard_event_ex(&dyn_response,
                                                  0x1d,
                                                  RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                                  RDP_CORE_INPUT_KBDFLAGS_RELEASE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SCANCODE &&
           core_events[0].flags == (RDP_CORE_INPUT_KBDFLAGS_EXTENDED |
                                    RDP_CORE_INPUT_KBDFLAGS_RELEASE) &&
           core_events[0].scancode == 0x1d);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_unicode_event(&dyn_response, 0x20ac, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_UNICODE &&
           core_events[0].unicode_code == 0x20ac);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_sync_event(&dyn_response,
                                           RDP_CORE_INPUT_SYNC_NUM_LOCK |
                                           RDP_CORE_INPUT_SYNC_CAPS_LOCK) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 1 &&
           core_events[0].type == RDP_CORE_INPUT_EVENT_SYNC &&
           core_events[0].flags == (RDP_CORE_INPUT_SYNC_NUM_LOCK | RDP_CORE_INPUT_SYNC_CAPS_LOCK));
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_extended_mouse_event(&dyn_response, 0x8001u, 12, 13) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_MOUSEX &&
           core_events[0].pointer_flags == 0x8001u &&
           core_events[0].x == 12 &&
           core_events[0].y == 13);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_core_input_write_relative_mouse_event(&dyn_response, 0x0800u, -3, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_events[0].type == RDP_CORE_INPUT_EVENT_RELMOUSE &&
           core_events[0].pointer_flags == 0x0800u &&
           core_events[0].dx == -3 &&
           core_events[0].dy == 4);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    core_events[0].type = RDP_CORE_INPUT_EVENT_SCANCODE;
    core_events[0].flags = 0;
    core_events[0].scancode = 0x1e;
    core_events[1].type = RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP;
    core_events[1].flags = 0;
    core_events[1].timestamp = 0x12345678u;
    PCHECK(rdp_core_input_write_events(&dyn_response, core_events, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_core_input_parse_events(dyn_response.data,
                                       dyn_response.length,
                                       core_events,
                                       8,
                                       &core_event_count) == LIBRDP_STATUS_OK);
    PCHECK(core_event_count == 2 &&
           core_events[0].scancode == 0x1e &&
           core_events[1].type == RDP_CORE_INPUT_EVENT_QOE_TIMESTAMP &&
           core_events[1].timestamp == 0x12345678u);
    PCHECK(rdp_input_channel_parse_header(input_sc_ready_v300,
                                          sizeof(input_sc_ready_v300),
                                          &input_header) == LIBRDP_STATUS_OK);
    PCHECK(input_header.event_id == RDP_INPUT_CHANNEL_EVENT_SC_READY &&
           input_header.pdu_length == sizeof(input_sc_ready_v300));
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                            sizeof(input_sc_ready_v300),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v200,
                                            sizeof(input_sc_ready_v200),
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V200 &&
           !input_sc_ready.has_supported_features);
    PCHECK(rdp_input_channel_parse_sc_ready(input_sc_ready_v300,
                                            sizeof(input_sc_ready_v300) - 1u,
                                            &input_sc_ready) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                                            1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_sc_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_sc_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_sc_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_sc_ready.has_supported_features &&
           input_sc_ready.supported_features == RDP_INPUT_CHANNEL_SC_READY_MULTIPEN);
    PCHECK(rdp_input_channel_write_sc_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            0,
                                            0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V300,
                                            10) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 16 &&
           test_read_u16_le(dyn_response.data) == RDP_INPUT_CHANNEL_EVENT_CS_READY &&
           test_read_u32_le(dyn_response.data + 2) == 16 &&
           test_read_u32_le(dyn_response.data + 6) ==
               (RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION | RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN));
    PCHECK(rdp_input_channel_parse_cs_ready(dyn_response.data,
                                            dyn_response.length,
                                            &input_cs_ready) == LIBRDP_STATUS_OK);
    PCHECK(input_cs_ready.protocol_version == RDP_INPUT_CHANNEL_PROTOCOL_V300 &&
           input_cs_ready.max_touch_contacts == 10);
    PCHECK(rdp_input_channel_write_cs_ready(&dyn_response,
                                            RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN,
                                            RDP_INPUT_CHANNEL_PROTOCOL_V101,
                                            1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_input_channel_write_suspend(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_SUSPEND_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_resume(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_empty(dyn_response.data,
                                         dyn_response.length,
                                         RDP_INPUT_CHANNEL_EVENT_RESUME_INPUT) == LIBRDP_STATUS_OK);
    dyn_response.length = 0;
    PCHECK(rdp_input_channel_write_dismiss_hovering(&dyn_response, 9) == LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_dismiss_hovering(dyn_response.data,
                                                    dyn_response.length,
                                                    &input_contact_id) == LIBRDP_STATUS_OK);
    PCHECK(input_contact_id == 9);
    dyn_response.length = 0;
    memset(&input_touch_contact, 0, sizeof(input_touch_contact));
    input_touch_contact.contact_id = 1;
    input_touch_contact.fields_present = RDP_INPUT_CHANNEL_TOUCH_CONTACTRECT_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_ORIENTATION_PRESENT |
                                         RDP_INPUT_CHANNEL_TOUCH_PRESSURE_PRESENT;
    input_touch_contact.x = 100;
    input_touch_contact.y = 200;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN |
                                        RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                        RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_touch_contact.contact_rect_left = -2;
    input_touch_contact.contact_rect_top = -3;
    input_touch_contact.contact_rect_right = 2;
    input_touch_contact.contact_rect_bottom = 3;
    input_touch_contact.orientation = 90;
    input_touch_contact.pressure = 512;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) == LIBRDP_STATUS_OK);
    memset(&input_touch_frame, 0, sizeof(input_touch_frame));
    input_touch_frame.contact_count = 1;
    input_touch_frame.frame_offset = 0x0102030405060708ull;
    input_touch_frame.contacts = dyn_response.data;
    input_touch_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_touch_event(&channel_packet, 0x11223344u, &input_touch_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_touch_event(channel_packet.data,
                                               channel_packet.length,
                                               &input_touch_event) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_event.encode_time == 0x11223344u && input_touch_event.frame_count == 1);
    PCHECK(rdp_input_channel_touch_event_get_frame(&input_touch_event,
                                                   0,
                                                   &input_touch_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_frame.contact_count == 1 &&
           input_touch_frame.frame_offset == 0x0102030405060708ull);
    PCHECK(rdp_input_channel_touch_frame_get_contact(&input_touch_frame,
                                                     0,
                                                     &input_touch_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_touch_contact.contact_id == 1 &&
           input_touch_contact.x == 100 &&
           input_touch_contact.y == 200 &&
           input_touch_contact.contact_rect_top == -3 &&
           input_touch_contact.orientation == 90 &&
           input_touch_contact.pressure == 512);
    input_touch_contact.pressure = 1025;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    input_touch_contact.pressure = 512;
    input_touch_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_DOWN;
    PCHECK(rdp_input_channel_write_touch_contact(&dyn_response, &input_touch_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    dyn_response.length = 0;
    memset(&input_pen_contact, 0, sizeof(input_pen_contact));
    input_pen_contact.device_id = 2;
    input_pen_contact.fields_present = RDP_INPUT_CHANNEL_PEN_FLAGS_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_PRESSURE_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_ROTATION_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTX_PRESENT |
                                       RDP_INPUT_CHANNEL_PEN_TILTY_PRESENT;
    input_pen_contact.x = -20;
    input_pen_contact.y = 30;
    input_pen_contact.contact_flags = RDP_INPUT_CHANNEL_CONTACT_UPDATE |
                                      RDP_INPUT_CHANNEL_CONTACT_INRANGE |
                                      RDP_INPUT_CHANNEL_CONTACT_INCONTACT;
    input_pen_contact.pen_flags = RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED;
    input_pen_contact.pressure = 700;
    input_pen_contact.rotation = 45;
    input_pen_contact.tilt_x = -10;
    input_pen_contact.tilt_y = 20;
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) == LIBRDP_STATUS_OK);
    memset(&input_pen_frame, 0, sizeof(input_pen_frame));
    input_pen_frame.contact_count = 1;
    input_pen_frame.frame_offset = 7;
    input_pen_frame.contacts = dyn_response.data;
    input_pen_frame.contacts_len = dyn_response.length;
    channel_packet.length = 0;
    PCHECK(rdp_input_channel_write_pen_event(&channel_packet, 0x55667788u, &input_pen_frame, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_input_channel_parse_pen_event(channel_packet.data,
                                             channel_packet.length,
                                             &input_pen_event) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_event.encode_time == 0x55667788u && input_pen_event.frame_count == 1);
    PCHECK(rdp_input_channel_pen_event_get_frame(&input_pen_event,
                                                 0,
                                                 &input_pen_frame) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_frame.contact_count == 1 && input_pen_frame.frame_offset == 7);
    PCHECK(rdp_input_channel_pen_frame_get_contact(&input_pen_frame,
                                                   0,
                                                   &input_pen_contact) == LIBRDP_STATUS_OK);
    PCHECK(input_pen_contact.device_id == 2 &&
           input_pen_contact.x == -20 &&
           input_pen_contact.pen_flags == RDP_INPUT_CHANNEL_PEN_BARREL_PRESSED &&
           input_pen_contact.pressure == 700 &&
           input_pen_contact.rotation == 45 &&
           input_pen_contact.tilt_x == -10 &&
           input_pen_contact.tilt_y == 20);
    input_pen_contact.tilt_y = 91;
    PCHECK(rdp_input_channel_write_pen_contact(&dyn_response, &input_pen_contact) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps),
                                          &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_parsed_caps.max_num_monitors == 16 &&
           display_parsed_caps.max_monitor_area_factor_a == 8192 &&
           display_parsed_caps.max_monitor_area_factor_b == 8192);
    PCHECK(rdp_display_control_parse_caps(display_caps,
                                          sizeof(display_caps) - 1u,
                                          &display_parsed_caps) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_display_control_make_single_monitor(&display_monitor, 801, 199) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor.flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitor.width == 800 &&
           display_monitor.height == 200 &&
           display_monitor.desktop_scale_factor == 100);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 56 &&
           test_read_u32_le(dyn_response.data) == RDP_DISPLAY_CONTROL_PDU_MONITOR_LAYOUT &&
           test_read_u32_le(dyn_response.data + 4) == 56 &&
           test_read_u32_le(dyn_response.data + 8) == RDP_DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE &&
           test_read_u32_le(dyn_response.data + 12) == 1 &&
           test_read_u32_le(dyn_response.data + 16) == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           test_read_u32_le(dyn_response.data + 28) == 800 &&
           test_read_u32_le(dyn_response.data + 32) == 200);
    PCHECK(rdp_display_control_parse_monitor_layout(dyn_response.data,
                                                    dyn_response.length,
                                                    display_monitors,
                                                    2,
                                                    &display_monitor_count) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 1 &&
           display_monitors[0].flags == RDP_DISPLAY_CONTROL_MONITOR_PRIMARY &&
           display_monitors[0].width == 800 &&
           display_monitors[0].height == 200);
    display_monitors[0] = display_monitor;
    display_monitors[1] = display_monitor;
    display_monitors[1].flags = 0;
    display_monitors[1].left = 800;
    display_monitors[1].width = 640;
    display_monitors[1].height = 480;
    display_monitors[1].physical_width = 169;
    display_monitors[1].physical_height = 127;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 96 &&
           test_read_u32_le(dyn_response.data + 12) == 2 &&
           test_read_u32_le(dyn_response.data + 56) == 0 &&
           test_read_u32_le(dyn_response.data + 68) == 640);
    PCHECK(rdp_display_control_parse_monitor_layout_with_caps(dyn_response.data,
                                                              dyn_response.length,
                                                              display_monitors,
                                                              2,
                                                              &display_monitor_count,
                                                              &display_parsed_caps) == LIBRDP_STATUS_OK);
    PCHECK(display_monitor_count == 2 &&
           display_monitors[1].left == 800 &&
           display_monitors[1].width == 640);
    display_monitors[1].left = 700;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, display_monitors, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitors[1].left = 800;
    display_parsed_caps.max_num_monitors = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              display_monitors,
                                                              2,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_num_monitors = 1;
    display_parsed_caps.max_monitor_area_factor_a = 200;
    display_parsed_caps.max_monitor_area_factor_b = 200;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout_with_caps(&dyn_response,
                                                              &display_monitor,
                                                              1,
                                                              &display_parsed_caps) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_parsed_caps.max_monitor_area_factor_a = 8192;
    display_parsed_caps.max_monitor_area_factor_b = 8192;
    display_monitor.left = 1;
    dyn_response.length = 0;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.left = 0;
    display_monitor.device_scale_factor = 120;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    display_monitor.device_scale_factor = 100;
    display_monitor.width = 801;
    PCHECK(rdp_display_control_write_monitor_layout(&dyn_response, &display_monitor, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_default_caps_advertise(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 34 || dyn_response.length == 46);
    PCHECK(test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE);
    PCHECK(test_read_u32_le(dyn_response.data + 4) == dyn_response.length);
    PCHECK(test_read_u16_le(dyn_response.data + 8) == (dyn_response.length == 46 ? 3 : 2));
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 10, dyn_response.length - 10, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_8 &&
           (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    PCHECK(rdp_graphics_parse_capset(dyn_response.data + 22, dyn_response.length - 22, &graphics_capset) ==
           LIBRDP_STATUS_OK);
    if (dyn_response.length == 46)
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_81 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC420_ENABLED) != 0);
        PCHECK(rdp_graphics_parse_capset(dyn_response.data + 34, dyn_response.length - 34, &graphics_capset) ==
               LIBRDP_STATUS_OK);
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) == 0);
    }
    else
    {
        PCHECK(graphics_capset.version == RDP_GRAPHICS_CAPVERSION_10 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0 &&
               (graphics_capset.flags & RDP_GRAPHICS_CAPS_FLAG_AVC_DISABLED) != 0);
    }
    PCHECK(rdp_graphics_parse_capset(graphics_bad_capset,
                                     sizeof(graphics_bad_capset),
                                     &graphics_capset) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_header(graphics_confirm, sizeof(graphics_confirm), &graphics_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM);
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm), &graphics_caps_confirm) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_caps_confirm.selected.version == RDP_GRAPHICS_CAPVERSION_8);
    PCHECK((graphics_caps_confirm.selected.flags & RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE) != 0);
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_single,
                                              sizeof(graphics_segment_single),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_multipart,
                                              sizeof(graphics_segment_multipart),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == sizeof(graphics_confirm));
    PCHECK(memcmp(graphics_decoded.data, graphics_confirm, sizeof(graphics_confirm)) == 0);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_compressed_literal,
                                              sizeof(graphics_segment_compressed_literal),
                                              &graphics_decoded) == LIBRDP_STATUS_OK);
    PCHECK(graphics_decoded.length == 1 && graphics_decoded.data[0] == 0x49);
    graphics_decoded.length = 0;
    PCHECK(rdp_graphics_decode_segmented_data(&graphics_decompressor,
                                              graphics_segment_bad_compression_type,
                                              sizeof(graphics_segment_bad_compression_type),
                                              &graphics_decoded) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_caps_confirm(graphics_confirm, sizeof(graphics_confirm) - 1u, &graphics_caps_confirm) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_create_surface(graphics_create_surface,
                                             sizeof(graphics_create_surface),
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.surface_id == 0x1234 &&
           graphics_create.width == 1024 &&
           graphics_create.height == 768 &&
           graphics_create.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             graphics_create.surface_id,
                                             graphics_create.width,
                                             graphics_create.height,
                                             graphics_create.pixel_format) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_create_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_create) == LIBRDP_STATUS_OK);
    PCHECK(graphics_create.width == 1024 && graphics_create.height == 768);
    PCHECK(rdp_graphics_write_create_surface(&dyn_response,
                                             1,
                                             0,
                                             1,
                                             RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                             sizeof(graphics_delete_surface),
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_surface(&dyn_response, graphics_delete.surface_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_surface(dyn_response.data,
                                             dyn_response.length,
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    PCHECK(rdp_graphics_parse_map_surface_to_output(graphics_map_output,
                                                    sizeof(graphics_map_output),
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.surface_id == 0x1234 &&
           graphics_map.output_origin_x == 10 &&
           graphics_map.output_origin_y == 20);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_output(&dyn_response,
                                                    graphics_map.surface_id,
                                                    graphics_map.output_origin_x,
                                                    graphics_map.output_origin_y) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_output(dyn_response.data,
                                                    dyn_response.length,
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.output_origin_x == 10 && graphics_map.output_origin_y == 20);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(graphics_scaled_map_output,
                                                           sizeof(graphics_scaled_map_output),
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.surface_id == 0x1234 &&
           graphics_scaled_map.output_origin_x == 10 &&
           graphics_scaled_map.output_origin_y == 20 &&
           graphics_scaled_map.target_width == 1024 &&
           graphics_scaled_map.target_height == 768);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response,
                                                           graphics_scaled_map.surface_id,
                                                           graphics_scaled_map.output_origin_x,
                                                           graphics_scaled_map.output_origin_y,
                                                           graphics_scaled_map.target_width,
                                                           graphics_scaled_map.target_height) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(dyn_response.data,
                                                           dyn_response.length,
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.target_width == 1024 && graphics_scaled_map.target_height == 768);
    PCHECK(rdp_graphics_write_map_surface_to_scaled_output(&dyn_response, 1, 0, 0, 0, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                         sizeof(graphics_solid_fill),
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.surface_id == 0x1234 &&
           graphics_solid.fill_pixel == 0xff332211u &&
           graphics_solid.rect_count == 1 &&
           graphics_solid.rects_len == 8);
    PCHECK(rdp_graphics_parse_rect16(graphics_solid.rects,
                                     graphics_solid.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 1 &&
           graphics_rect.top == 2 &&
           graphics_rect.right == 5 &&
           graphics_rect.bottom == 6);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_rect16(&dyn_response, &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_rect16(dyn_response.data, dyn_response.length, &graphics_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.right == 5 && graphics_rect.bottom == 6);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_solid_fill(&dyn_response,
                                         graphics_solid.surface_id,
                                         graphics_solid.fill_pixel,
                                         &graphics_rect,
                                         1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_solid_fill(dyn_response.data,
                                         dyn_response.length,
                                         &graphics_solid) == LIBRDP_STATUS_OK);
    PCHECK(graphics_solid.rect_count == 1 && graphics_solid.fill_pixel == 0xff332211u);
    PCHECK(rdp_graphics_parse_solid_fill(graphics_solid_fill,
                                         sizeof(graphics_solid_fill) - 1u,
                                         &graphics_solid) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_rect16(graphics_bad_rect,
                                     sizeof(graphics_bad_rect),
                                     &graphics_rect) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                sizeof(graphics_wire_to_surface_1),
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.surface_id == 0x1234 &&
           graphics_wire1.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED &&
           graphics_wire1.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888 &&
           graphics_wire1.dest_rect.left == 1 &&
           graphics_wire1.dest_rect.bottom == 4 &&
           graphics_wire1.bitmap_data_length == 16 &&
           graphics_wire1.bitmap_data[15] == 16);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_1(&dyn_response,
                                                graphics_wire1.surface_id,
                                                graphics_wire1.codec_id,
                                                graphics_wire1.pixel_format,
                                                &graphics_wire1.dest_rect,
                                                graphics_wire1.bitmap_data,
                                                graphics_wire1.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire1) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire1.bitmap_data_length == 16 && graphics_wire1.bitmap_data[0] == 1);
    PCHECK(rdp_graphics_parse_wire_to_surface_1(graphics_wire_to_surface_1,
                                                sizeof(graphics_wire_to_surface_1) - 1u,
                                                &graphics_wire1) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(graphics_wire_to_surface_2,
                                                sizeof(graphics_wire_to_surface_2),
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.surface_id == 0x1234 &&
           graphics_wire2.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE &&
           graphics_wire2.codec_context_id == 0x11223344u &&
           graphics_wire2.pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888 &&
           graphics_wire2.bitmap_data_length == 3 &&
           graphics_wire2.bitmap_data[2] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_wire_to_surface_2(&dyn_response,
                                                graphics_wire2.surface_id,
                                                graphics_wire2.codec_id,
                                                graphics_wire2.codec_context_id,
                                                graphics_wire2.pixel_format,
                                                graphics_wire2.bitmap_data,
                                                graphics_wire2.bitmap_data_length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_wire_to_surface_2(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_wire2) == LIBRDP_STATUS_OK);
    PCHECK(graphics_wire2.codec_context_id == 0x11223344u && graphics_wire2.bitmap_data[2] == 0xcc);
    PCHECK(rdp_graphics_parse_avc420_metablock(graphics_avc420_stream,
                                               sizeof(graphics_avc420_stream) - 4u,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_meta.rect_count == 1 &&
           graphics_avc_meta.rects_len == 8 &&
           graphics_avc_meta.quant_quality_len == 2);
    PCHECK(rdp_graphics_parse_rect16(graphics_avc_meta.rects,
                                     graphics_avc_meta.rects_len,
                                     &graphics_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_rect.left == 0 &&
           graphics_rect.top == 0 &&
           graphics_rect.right == 16 &&
           graphics_rect.bottom == 16);
    PCHECK(rdp_graphics_parse_avc420_quant_quality(graphics_avc_meta.quant_quality,
                                                   graphics_avc_meta.quant_quality_len,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc_quant.qp_val == 0x45 &&
           graphics_avc_quant.qp == 5 &&
           graphics_avc_quant.r == 1 &&
           graphics_avc_quant.p == 0 &&
           graphics_avc_quant.quality == 100);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_quant_quality(&dyn_response,
                                                   &graphics_avc_quant) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 2 &&
           memcmp(dyn_response.data, graphics_avc_meta.quant_quality, 2) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_metablock(&dyn_response,
                                               &graphics_avc_meta) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) - 4u &&
           memcmp(dyn_response.data,
                  graphics_avc420_stream,
                  sizeof(graphics_avc420_stream) - 4u) == 0);
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc420.meta.rect_count == 1 &&
           graphics_avc420.bitstream_len == 4 &&
           graphics_avc420.bitstream[3] == 0x65);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc420_stream(&dyn_response,
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc420_stream) &&
           memcmp(dyn_response.data, graphics_avc420_stream, sizeof(graphics_avc420_stream)) == 0);
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_bad_rect,
                                            sizeof(graphics_avc420_bad_rect),
                                            &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_empty_bits,
                                            sizeof(graphics_avc420_empty_bits),
                                            &graphics_avc420) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_both,
                                            sizeof(graphics_avc444_both),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_BOTH &&
           graphics_avc444.stream1_size == sizeof(graphics_avc420_stream) &&
           graphics_avc444.has_stream1 &&
           graphics_avc444.has_stream2 &&
           graphics_avc444.stream2.bitstream[3] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_both) &&
           memcmp(dyn_response.data, graphics_avc444_both, sizeof(graphics_avc444_both)) == 0);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_LUMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_luma) &&
           memcmp(dyn_response.data, graphics_avc444_luma, sizeof(graphics_avc444_luma)) == 0);
    graphics_avc444.has_stream2 = 1;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_chroma,
                                            sizeof(graphics_avc444_chroma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_CHROMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(graphics_avc444_chroma) &&
           memcmp(dyn_response.data, graphics_avc444_chroma, sizeof(graphics_avc444_chroma)) == 0);
    graphics_avc444.lc = RDP_GRAPHICS_AVC444_LC_INVALID;
    PCHECK(rdp_graphics_write_avc444_stream(&dyn_response,
                                            &graphics_avc444) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_invalid_lc,
                                            sizeof(graphics_avc444_invalid_lc),
                                            &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_bad_split,
                                            sizeof(graphics_avc444_bad_split),
                                            &graphics_avc444) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_stream,
                                                sizeof(graphics_progressive_stream),
                                                &graphics_progressive_block) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_CONTEXT &&
           graphics_progressive_block.length == 10 &&
           graphics_progressive_block.payload_len == 4);
    PCHECK(rdp_graphics_progressive_parse_context(graphics_progressive_stream,
                                                  sizeof(graphics_progressive_stream),
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.context_id == 0 &&
           graphics_progressive_context.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_context.flags == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_context(dyn_response.data,
                                                  dyn_response.length,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_context.flags == 1);
    PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_frame_begin) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1 &&
           graphics_progressive_frame_begin.region_count == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_begin(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_size == RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE &&
           graphics_progressive_region.rect_count == 1 &&
           graphics_progressive_region.quant_count == 1 &&
           graphics_progressive_region.progressive_quant_count == 1 &&
           graphics_progressive_region.tile_count == 1 &&
           graphics_progressive_region.tile_data_size == 25 &&
           graphics_progressive_region.tiles_len == 25);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tiles_len == 25);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_empty_region,
                                                 sizeof(graphics_progressive_empty_region),
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_count == 0 &&
           graphics_progressive_region.tile_data_size == 0 &&
           graphics_progressive_region.tiles_len == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_empty_region,
                  sizeof(graphics_progressive_empty_region)) == 0);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                      sizeof(graphics_progressive_region_rect),
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_rect.left == 640 &&
           graphics_progressive_rect.top == 288 &&
           graphics_progressive_rect.right == 704 &&
           graphics_progressive_rect.bottom == 320);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_region_rect(&dyn_response,
                                                      &graphics_progressive_rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_region_rect,
                  sizeof(graphics_progressive_region_rect)) == 0);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect_overflow,
                                                      sizeof(graphics_progressive_region_rect_overflow),
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                      sizeof(graphics_progressive_region_rect) - 1u,
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_progressive_parse_tile_simple(graphics_progressive_stream + 69,
                                                      sizeof(graphics_progressive_stream) - 69u,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE &&
           graphics_progressive_simple.y_len == 1 &&
           graphics_progressive_simple.cb_len == 1 &&
           graphics_progressive_simple.cr_len == 1 &&
           graphics_progressive_simple.y_data[0] == 0xaa &&
           graphics_progressive_simple.cb_data[0] == 0xbb &&
           graphics_progressive_simple.cr_data[0] == 0xcc);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_simple(&dyn_response,
                                                      &graphics_progressive_simple) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_simple(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_progressive_simple) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_simple.y_data[0] == 0xaa);
    PCHECK(rdp_graphics_progressive_parse_frame_end(graphics_progressive_stream + 94,
                                                    sizeof(graphics_progressive_stream) - 94u) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_frame_end(dyn_response.data,
                                                    dyn_response.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_tile_first(graphics_progressive_tile_first,
                                                     sizeof(graphics_progressive_tile_first),
                                                     &graphics_progressive_first) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_first.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST &&
           graphics_progressive_first.x_idx == 1 &&
           graphics_progressive_first.y_idx == 2 &&
           graphics_progressive_first.progressive_quality == 0 &&
           graphics_progressive_first.y_data[0] == 0x11 &&
           graphics_progressive_first.cb_data[0] == 0x22 &&
           graphics_progressive_first.cr_data[0] == 0x33);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_first(&dyn_response,
                                                     &graphics_progressive_first) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_first,
                  sizeof(graphics_progressive_tile_first)) == 0);
    PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                       sizeof(graphics_progressive_tile_upgrade),
                                                       &graphics_progressive_upgrade) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_upgrade.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE &&
           graphics_progressive_upgrade.x_idx == 3 &&
           graphics_progressive_upgrade.y_idx == 4 &&
           graphics_progressive_upgrade.y_srl_data[0] == 0x11 &&
           graphics_progressive_upgrade.cr_raw_data[0] == 0x66);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_tile_upgrade(&dyn_response,
                                                       &graphics_progressive_upgrade) ==
           LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_tile_upgrade,
                  sizeof(graphics_progressive_tile_upgrade)) == 0);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_progressive_write_context(&dyn_response,
                                                  &graphics_progressive_context) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_begin(&dyn_response,
                                                      &graphics_progressive_frame_begin) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_stream + 22,
                                                 sizeof(graphics_progressive_stream) - 22u,
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_region(&dyn_response,
                                                 &graphics_progressive_region) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_progressive_write_frame_end(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(dyn_response.data,
                  graphics_progressive_stream,
                  sizeof(graphics_progressive_stream)) == 0);
    PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                 sizeof(graphics_progressive_stream),
                                                 &graphics_progressive) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive.block_count == 4 &&
           graphics_progressive.known_block_count == 4 &&
           graphics_progressive.region_count == 1 &&
           graphics_progressive.tile_count == 1 &&
           graphics_progressive.simple_tile_count == 1 &&
           graphics_progressive.first_tile_count == 0 &&
           graphics_progressive.upgrade_tile_count == 0 &&
           graphics_progressive.has_context &&
           graphics_progressive.has_frame_begin &&
           graphics_progressive.has_frame_end);
    PCHECK(rdp_graphics_progressive_parse_block(graphics_progressive_bad_block,
                                                sizeof(graphics_progressive_bad_block),
                                                &graphics_progressive_block) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_bad_region,
                                                 sizeof(graphics_progressive_bad_region),
                                                 &graphics_progressive_region) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_progressive_parse_stream(graphics_progressive_stream,
                                                 sizeof(graphics_progressive_stream) - 1u,
                                                 &graphics_progressive) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_surface_to_surface(graphics_surface_to_surface,
                                                 sizeof(graphics_surface_to_surface),
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.surface_id_src == 0x10 &&
           graphics_surface_copy.surface_id_dest == 0x20 &&
           graphics_surface_copy.rect_src.right == 5 &&
           graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points,
                                      graphics_surface_copy.dest_points_len,
                                      &graphics_point) == LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    graphics_points[0] = graphics_point;
    PCHECK(rdp_graphics_parse_point16(graphics_surface_copy.dest_points + 4,
                                      graphics_surface_copy.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_point16(&dyn_response, &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(dyn_response.data, dyn_response.length, &graphics_point) ==
           LIBRDP_STATUS_OK);
    PCHECK(graphics_point.x == 7 && graphics_point.y == 8);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_surface(&dyn_response,
                                                 graphics_surface_copy.surface_id_src,
                                                 graphics_surface_copy.surface_id_dest,
                                                 &graphics_surface_copy.rect_src,
                                                 graphics_points,
                                                 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_surface(dyn_response.data,
                                                 dyn_response.length,
                                                 &graphics_surface_copy) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_copy.dest_points_count == 2 &&
           graphics_surface_copy.rect_src.right == 5);
    PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                               sizeof(graphics_surface_to_cache),
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.surface_id == 0x1234 &&
           graphics_surface_cache.cache_key == 0x0102030405060708ull &&
           graphics_surface_cache.cache_slot == 0x42 &&
           graphics_surface_cache.rect_src.left == 1);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_surface_to_cache(&dyn_response,
                                               graphics_surface_cache.surface_id,
                                               graphics_surface_cache.cache_key,
                                               graphics_surface_cache.cache_slot,
                                               &graphics_surface_cache.rect_src) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_surface_to_cache(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.cache_key == 0x0102030405060708ull);
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface),
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.cache_slot == 0x42 &&
           graphics_cache_surface.surface_id == 0x1234 &&
           graphics_cache_surface.dest_points_count == 2 &&
           graphics_cache_surface.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points,
                                      graphics_cache_surface.dest_points_len,
                                      &graphics_points[0]) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_point16(graphics_cache_surface.dest_points + 4,
                                      graphics_cache_surface.dest_points_len - 4u,
                                      &graphics_points[1]) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_cache_to_surface(&dyn_response,
                                               graphics_cache_surface.cache_slot,
                                               graphics_cache_surface.surface_id,
                                               graphics_points,
                                               2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_cache_to_surface(dyn_response.data,
                                               dyn_response.length,
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.dest_points_count == 2);
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface) - 1u,
                                               &graphics_cache_surface) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                sizeof(graphics_evict_cache),
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_evict_cache_entry(&dyn_response, graphics_evict.cache_slot) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_evict_cache_entry(dyn_response.data,
                                                dyn_response.length,
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                      sizeof(graphics_delete_context_pdu),
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.surface_id == 0x1234 &&
           graphics_delete_context.codec_context_id == 0x11223344u);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_delete_encoding_context(&dyn_response,
                                                      graphics_delete_context.surface_id,
                                                      graphics_delete_context.codec_context_id) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_delete_encoding_context(dyn_response.data,
                                                      dyn_response.length,
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.codec_context_id == 0x11223344u);
    PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                          sizeof(graphics_start_frame),
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.timestamp == 0x01020304 && graphics_start.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_start_frame(&dyn_response,
                                          graphics_start.timestamp,
                                          graphics_start.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_start_frame(dyn_response.data,
                                          dyn_response.length,
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.frame_id == 0x11223344);
    PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                        sizeof(graphics_end_frame),
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_end_frame(&dyn_response, graphics_end.frame_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_end_frame(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_end) == LIBRDP_STATUS_OK);
    PCHECK(graphics_end.frame_id == 0x11223344);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_init(&dyn_response);
    PCHECK(rdp_graphics_write_frame_ack(&dyn_response,
                                        RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                        graphics_end.frame_id,
                                        7) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 20 &&
           test_read_u16_le(dyn_response.data) == RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE &&
           test_read_u32_le(dyn_response.data + 4) == 20 &&
           test_read_u32_le(dyn_response.data + 12) == graphics_end.frame_id &&
           test_read_u32_le(dyn_response.data + 16) == 7);
    PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                        dyn_response.length,
                                        &graphics_ack) == LIBRDP_STATUS_OK);
    PCHECK(graphics_ack.queue_depth == RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE &&
           graphics_ack.frame_id == graphics_end.frame_id &&
           graphics_ack.total_frames_decoded == 7);
    PCHECK(rdp_graphics_parse_frame_ack(dyn_response.data,
                                        dyn_response.length - 1u,
                                        &graphics_ack) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 1024, 768) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                    graphics_reset_pdu.length,
                                    &graphics_reset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_reset.width == 1024 &&
           graphics_reset.height == 768 &&
           graphics_reset.monitor_count == 0);
    PCHECK(graphics_reset_pdu.length == 340);
    PCHECK(rdp_graphics_write_reset(&graphics_reset_pdu, 0, 768) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clearcodec_parse_stream(clear_residual_bitmap,
                                       sizeof(clear_residual_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.flags == 0 &&
           clear_stream.seq_number == 0 &&
           clear_stream.payload_len == 16);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.residual_len == 4 &&
           clear_payload.bands_len == 0 &&
           clear_payload.subcodec_len == 0);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_bitmap,
                                        sizeof(clear_residual_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 8 &&
           clear_pixels.length == 16 &&
           clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[3] == 0xff &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_residual_zero_run_bitmap,
                                        sizeof(clear_residual_zero_run_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[12] == 1 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_raw_subcodec_bitmap,
                                       sizeof(clear_raw_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(clear_stream.seq_number == 1);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 25);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.x == 0 &&
           clear_subcodec.y == 0 &&
           clear_subcodec.width == 2 &&
           clear_subcodec.height == 2 &&
           clear_subcodec.bitmap_data_len == 12 &&
           clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RAW);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_raw_subcodec_bitmap,
                                        sizeof(clear_raw_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 7 &&
           clear_pixels.data[10] == 9 &&
           clear_pixels.data[12] == 10 &&
           clear_pixels.data[14] == 12);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_parse_stream(clear_rlex_subcodec_bitmap,
                                       sizeof(clear_rlex_subcodec_bitmap),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clearcodec_parse_composite_payload(clear_stream.payload,
                                                  clear_stream.payload_len,
                                                  &clear_payload) == LIBRDP_STATUS_OK);
    PCHECK(clear_payload.subcodec_len == 24);
    PCHECK(rdp_clearcodec_parse_subcodec(clear_payload.subcodec,
                                         clear_payload.subcodec_len,
                                         &clear_subcodec) == LIBRDP_STATUS_OK);
    PCHECK(clear_subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RLEX &&
           clear_subcodec.bitmap_data_len == 11);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_rlex_subcodec_bitmap,
                                        sizeof(clear_rlex_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[4] == 4 &&
           clear_pixels.data[5] == 5 &&
           clear_pixels.data[6] == 6 &&
           clear_pixels.data[8] == 1 &&
           clear_pixels.data[12] == 4);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_nsc_subcodec_bitmap,
                                        sizeof(clear_nsc_subcodec_bitmap),
                                        1,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(decoded_stride == 4 &&
           clear_pixels.data[0] == 10 &&
           clear_pixels.data[1] == 10 &&
           clear_pixels.data[2] == 10 &&
           clear_pixels.data[3] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_miss_bitmap,
                                        sizeof(clear_band_miss_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[4] == 1 &&
           clear_pixels.data[5] == 2 &&
           clear_pixels.data[6] == 3 &&
           clear_pixels.data[12] == 4 &&
           clear_pixels.data[13] == 5 &&
           clear_pixels.data[14] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_band_hit_bitmap,
                                        sizeof(clear_band_hit_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 1 &&
           clear_pixels.data[1] == 2 &&
           clear_pixels.data[2] == 3 &&
           clear_pixels.data[8] == 4 &&
           clear_pixels.data[9] == 5 &&
           clear_pixels.data[10] == 6);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_band_bitmap,
                                        sizeof(clear_missing_band_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 16 &&
           clear_pixels.data[0] == 0 &&
           clear_pixels.data[8] == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_store_bitmap,
                                        sizeof(clear_glyph_store_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[1] == 8 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[15] == 0xff);
    PCHECK(rdp_clearcodec_parse_stream(clear_glyph_hit,
                                       sizeof(clear_glyph_hit),
                                       &clear_stream) == LIBRDP_STATUS_OK);
    PCHECK((clear_stream.flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 &&
           clear_stream.has_glyph_index &&
           clear_stream.payload_len == 0);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[12] == 9 &&
           clear_pixels.data[15] == 0xff);
    clear_pixels.length = 0;
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_glyph_hit,
                                        sizeof(clear_glyph_hit),
                                        2,
                                        1,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_OK);
    PCHECK(clear_pixels.length == 8 &&
           clear_pixels.data[0] == 9 &&
           clear_pixels.data[2] == 7 &&
           clear_pixels.data[7] == 0xff);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_missing_glyph_hit,
                                        sizeof(clear_missing_glyph_hit),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_empty_payload,
                                        sizeof(clear_empty_payload),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clearcodec_decode_bitmap(&clear_context,
                                        clear_unknown_subcodec_bitmap,
                                        sizeof(clear_unknown_subcodec_bitmap),
                                        2,
                                        2,
                                        &clear_pixels,
                                        &decoded_stride) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_clipboard_parse_packet(clip, sizeof(clip), &cb) == LIBRDP_STATUS_OK);
    PCHECK(cb.type == 1 && cb.flags == 2 && cb.payload_len == 3 && cb.payload[0] == 4);
    PCHECK(rdp_clipboard_parse_packet(clip_caps, sizeof(clip_caps), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_capabilities(&cb, &cb_caps) == LIBRDP_STATUS_OK);
    PCHECK(cb_caps.count == 1 && cb_caps.has_general &&
           cb_caps.general.version == RDP_CLIPBOARD_CAPS_VERSION_2 &&
           cb_caps.general.general_flags == (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                             RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED |
                                             RDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA));
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_capabilities(&dyn_response,
                                            RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES |
                                            RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_caps) &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_CLIP_CAPS &&
           test_read_u32_le(dyn_response.data + 4) == 16 &&
           test_read_u32_le(dyn_response.data + 20) ==
               (RDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES | RDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED));
    PCHECK(rdp_clipboard_parse_packet(clip_format_long, sizeof(clip_format_long), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 4);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc004u && cb_entry.name_len == 12 &&
           memcmp(cb_entry.name, "N\0a\0t\0i\0v\0e\0", 12) == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 3, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0x11u && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 4, &cb_entry) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_format_short_ascii,
                                      sizeof(clip_format_short_ascii),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 0, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 0, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == 0xc0aau && cb_entry.name_len == 6 &&
           memcmp(cb_entry.name, "Custom", 6) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_list_response(&dyn_response, 1) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE &&
           test_read_u16_le(dyn_response.data + 2) == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    dyn_response.length = 0;
    cb_entry.format_id = RDP_CLIPBOARD_FORMAT_UNICODETEXT;
    cb_entry.name = NULL;
    cb_entry.name_len = 0;
    PCHECK(rdp_clipboard_write_format_list(&dyn_response, &cb_entry, 1, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_list(&cb, &cb_list) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_format_list_entry_count(&cb_list, 1, &error_info) == LIBRDP_STATUS_OK);
    PCHECK(error_info == 1);
    PCHECK(rdp_clipboard_format_list_get_entry(&cb_list, 1, 0, &cb_entry) == LIBRDP_STATUS_OK);
    PCHECK(cb_entry.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT && cb_entry.name_len == 0);
    PCHECK(rdp_clipboard_parse_packet(clip_data_request, sizeof(clip_data_request), &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_request(&cb, &cb_data_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_request.format_id == RDP_CLIPBOARD_FORMAT_UNICODETEXT);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_request(&dyn_response,
                                                   RDP_CLIPBOARD_FORMAT_UNICODETEXT) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == sizeof(clip_data_request) &&
           memcmp(dyn_response.data, clip_data_request, sizeof(clip_data_request)) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 1, "abc", 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_data_response.data_len == 3 &&
           memcmp(cb_data_response.data, "abc", 3) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, NULL, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_format_data_response(&cb, &cb_data_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_data_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_data_response.data_len == 0);
    PCHECK(rdp_clipboard_write_format_data_response(&dyn_response, 0, "x", 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_clipboard_parse_packet(clip_file_size_request,
                                      sizeof(clip_file_size_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x1122u &&
           cb_file_request.lindex == -1 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_SIZE &&
           cb_file_request.position == 0 &&
           cb_file_request.requested == 8 &&
           !cb_file_request.has_clip_data_id);
    PCHECK(rdp_clipboard_parse_packet(clip_file_range_request,
                                      sizeof(clip_file_range_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_request.stream_id == 0x2233u &&
           cb_file_request.lindex == 2 &&
           cb_file_request.flags == RDP_CLIPBOARD_FILECONTENTS_RANGE &&
           cb_file_request.position == 0x0000000112345678ull &&
           cb_file_request.requested == 0x40 &&
           cb_file_request.has_clip_data_id &&
           cb_file_request.clip_data_id == 0x99);
    PCHECK(rdp_clipboard_parse_packet(clip_file_bad_request,
                                      sizeof(clip_file_bad_request),
                                      &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_request(&cb, &cb_file_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 1, 0x1122u, "data", 4) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_OK &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 4 &&
           memcmp(cb_file_response.data, "data", 4) == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_file_contents_response(&dyn_response, 0, 0x1122u, NULL, 0) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_file_contents_response(&cb, &cb_file_response) == LIBRDP_STATUS_OK);
    PCHECK(cb_file_response.response_flags == RDP_CLIPBOARD_CB_RESPONSE_FAIL &&
           cb_file_response.stream_id == 0x1122u &&
           cb_file_response.data_len == 0);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_lock(&dyn_response, 0x99887766u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_lock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x99887766u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_unlock(&dyn_response, 0x66554433u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_packet(dyn_response.data, dyn_response.length, &cb) == LIBRDP_STATUS_OK);
    PCHECK(rdp_clipboard_parse_unlock(&cb, &cb_lock) == LIBRDP_STATUS_OK);
    PCHECK(cb_lock.clip_data_id == 0x66554433u);
    dyn_response.length = 0;
    PCHECK(rdp_clipboard_write_monitor_ready(&dyn_response) == LIBRDP_STATUS_OK);
    PCHECK(dyn_response.length == 8 &&
           test_read_u16_le(dyn_response.data) == RDP_CLIPBOARD_CB_MONITOR_READY &&
           test_read_u32_le(dyn_response.data + 4) == 0);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu), &indication) ==
           LIBRDP_STATUS_OK);
    PCHECK(indication.initiator == 1004 && indication.channel_id == RDP_MCS_GLOBAL_CHANNEL_ID);
    PCHECK(indication.payload_len == 4 && indication.payload[0] == 1 && indication.payload[3] == 4);
    PCHECK(rdp_mcs_parse_send_data_indication(indication_pdu, sizeof(indication_pdu) - 1u, &indication) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_credssp_begin(false, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_DISABLED);
    PCHECK(rdp_credssp_begin(true, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_NEGOTIATING);
    PCHECK(rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(ntlm_negotiate.length == 47);
    PCHECK(memcmp(ntlm_negotiate.data, "NTLMSSP", 7) == 0);
    PCHECK(ntlm_negotiate.data[8] == 1 && ntlm_negotiate.data[16] == 3 && ntlm_negotiate.data[24] == 4);
    PCHECK(memcmp(ntlm_negotiate.data + 40, "DOMHOST", 7) == 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                   ntlm_negotiate.data,
                                                   ntlm_negotiate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_negotiate.length > ntlm_negotiate.length && spnego_negotiate.data[0] == 0x60);
    PCHECK(rdp_credssp_write_ts_request(&ts_request,
                                        6,
                                        spnego_negotiate.data,
                                        spnego_negotiate.length,
                                        NULL,
                                        0,
                                        NULL,
                                        0,
                                        credssp_client_nonce,
                                        sizeof(credssp_client_nonce)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len == spnego_negotiate.length);
    PCHECK(memcmp(parsed_ts.nego_token, spnego_negotiate.data, spnego_negotiate.length) == 0);
    PCHECK(parsed_ts.client_nonce_len == sizeof(credssp_client_nonce));
    PCHECK(memcmp(parsed_ts.client_nonce, credssp_client_nonce, sizeof(credssp_client_nonce)) == 0);
    PCHECK(rdp_credssp_parse_ts_request(ts_request.data, ts_request.length - 1u, &parsed_ts) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_credssp_write_negotiate_request(&nla_request, "host", "dom") == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ts_request(nla_request.data, nla_request.length, &parsed_ts) == LIBRDP_STATUS_OK);
    PCHECK(parsed_ts.version == 6 && parsed_ts.nego_token_len > 0);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token),
                                            &ntlm_challenge) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_challenge.flags == 0x04030201u);
    PCHECK(ntlm_challenge.server_challenge[0] == 0x10 && ntlm_challenge.server_challenge[7] == 0x17);
    PCHECK(ntlm_challenge.target_name_len == 4 && ntlm_challenge.target_info_len == 8);
    PCHECK(rdp_credssp_extract_ntlm_challenge(wrapped_ntlm_challenge,
                                              sizeof(wrapped_ntlm_challenge),
                                              &extracted_ntlm,
                                              &extracted_ntlm_len) == LIBRDP_STATUS_OK);
    PCHECK(extracted_ntlm_len == sizeof(ntlm_challenge_token));
    PCHECK(rdp_credssp_parse_ntlm_challenge(extracted_ntlm, extracted_ntlm_len, &ntlm_challenge) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_parse_ntlm_challenge(ntlm_challenge_token,
                                            sizeof(ntlm_challenge_token) - 1u,
                                            &ntlm_challenge) == LIBRDP_STATUS_PROTOCOL_ERROR);
    memset(&ntlm_v2_challenge, 0, sizeof(ntlm_v2_challenge));
    ntlm_v2_challenge.flags = 0xe2888235u;
    memcpy(ntlm_v2_challenge.server_challenge, ntlm_v2_server_challenge, sizeof(ntlm_v2_server_challenge));
    ntlm_v2_challenge.target_name = ntlm_v2_target_name;
    ntlm_v2_challenge.target_name_len = sizeof(ntlm_v2_target_name);
    ntlm_v2_challenge.target_info = ntlm_v2_target_info;
    ntlm_v2_challenge.target_info_len = sizeof(ntlm_v2_target_info);
    PCHECK(rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                               &ntlm_v2_challenge,
                                               "user",
                                               "SecREt01",
                                               "DOMAIN",
                                               "COMPUTER",
                                               0x01c334b736d39000ull,
                                               ntlm_v2_client_challenge,
                                               ntlm_v2_session_key,
                                               &ntlm_auth_result) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_authenticate.length > 88);
    PCHECK(memcmp(ntlm_authenticate.data, "NTLMSSP", 7) == 0);
    PCHECK(test_read_u32_le(ntlm_authenticate.data + 8) == 3);
    lm_len = test_read_u16_le(ntlm_authenticate.data + 12);
    lm_offset = test_read_u32_le(ntlm_authenticate.data + 16);
    nt_len = test_read_u16_le(ntlm_authenticate.data + 20);
    nt_offset = test_read_u32_le(ntlm_authenticate.data + 24);
    key_len = test_read_u16_le(ntlm_authenticate.data + 52);
    key_offset = test_read_u32_le(ntlm_authenticate.data + 56);
    PCHECK(test_read_u32_le(ntlm_authenticate.data + 60) == ntlm_auth_result.flags);
    PCHECK(lm_len == sizeof(ntlm_v2_expected_lm));
    PCHECK(nt_len > sizeof(ntlm_v2_expected_proof));
    PCHECK(key_len == sizeof(ntlm_v2_session_key));
    PCHECK((size_t)lm_offset + lm_len <= ntlm_authenticate.length);
    PCHECK((size_t)nt_offset + nt_len <= ntlm_authenticate.length);
    PCHECK((size_t)key_offset + key_len <= ntlm_authenticate.length);
    PCHECK(memcmp(ntlm_authenticate.data + lm_offset, ntlm_v2_expected_lm, sizeof(ntlm_v2_expected_lm)) == 0);
    PCHECK(memcmp(ntlm_authenticate.data + nt_offset,
                  ntlm_v2_expected_proof,
                  sizeof(ntlm_v2_expected_proof)) == 0);
    PCHECK(memcmp(ntlm_auth_result.session_key, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) == 0);
    PCHECK(memcmp(ntlm_authenticate.data + key_offset, ntlm_v2_session_key, sizeof(ntlm_v2_session_key)) != 0);
    PCHECK(rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                      ntlm_authenticate.data,
                                                      ntlm_authenticate.length) == LIBRDP_STATUS_OK);
    PCHECK(spnego_authenticate.length > ntlm_authenticate.length && spnego_authenticate.data[0] == 0xa1);
    PCHECK(rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_ntlm_wrap(&ntlm_security, "data", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_wrapped.length == 20);
    PCHECK(test_read_u32_le(ntlm_wrapped.data) == 1);
    PCHECK(test_read_u32_le(ntlm_wrapped.data + 12) == 0);
    PCHECK(memcmp(ntlm_wrapped.data + 16, "data", 4) != 0);
    PCHECK(ntlm_security.send_seq == 1);
    PCHECK(rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                               credssp_client_nonce,
                                               sizeof(credssp_client_nonce),
                                               credssp_public_key,
                                               sizeof(credssp_public_key),
                                               &pub_key_auth) == LIBRDP_STATUS_OK);
    PCHECK(pub_key_auth.length == 48 && ntlm_security.send_seq == 2);
    server_security = ntlm_security;
    memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
    server_security.send_rc4 = ntlm_security.recv_rc4;
    server_security.send_seq = 0;
    PCHECK(test_sha256_three((const uint8_t*)"CredSSP Server-To-Client Binding Hash",
                             sizeof("CredSSP Server-To-Client Binding Hash"),
                             credssp_client_nonce,
                             sizeof(credssp_client_nonce),
                             credssp_public_key,
                             sizeof(credssp_public_key),
                             server_hash));
    PCHECK(rdp_credssp_ntlm_wrap(&server_security,
                                 server_hash,
                                 sizeof(server_hash),
                                 &server_pub_key_auth) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_verify_public_key_hash(&ntlm_security,
                                              credssp_client_nonce,
                                              sizeof(credssp_client_nonce),
                                              credssp_public_key,
                                              sizeof(credssp_public_key),
                                              server_pub_key_auth.data,
                                              server_pub_key_auth.length) == LIBRDP_STATUS_OK);
    server_security = ntlm_security;
    memcpy(server_security.client_signing_key, ntlm_security.server_signing_key, sizeof(server_security.client_signing_key));
    server_security.send_rc4 = ntlm_security.recv_rc4;
    server_security.send_seq = ntlm_security.recv_seq;
    PCHECK(rdp_credssp_ntlm_wrap(&server_security, "peer", 4, &ntlm_wrapped) == LIBRDP_STATUS_OK);
    PCHECK(rdp_credssp_ntlm_unwrap(&ntlm_security,
                                   ntlm_wrapped.data + 20,
                                   ntlm_wrapped.length - 20,
                                   &ntlm_unwrapped) == LIBRDP_STATUS_OK);
    PCHECK(ntlm_unwrapped.length == 4 && memcmp(ntlm_unwrapped.data, "peer", 4) == 0);
    PCHECK(rdp_credssp_write_password_credentials(&ts_credentials,
                                                  "DOMAIN",
                                                  "user",
                                                  "SecREt01") == LIBRDP_STATUS_OK);
    PCHECK(ts_credentials.length > 32 && ts_credentials.data[0] == 0x30);
    PCHECK(rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                    "DOMAIN",
                                                    "user",
                                                    "SecREt01",
                                                    &auth_info) == LIBRDP_STATUS_OK);
    PCHECK(auth_info.length == ts_credentials.length + 16u);
    PCHECK(test_read_u32_le(auth_info.data) == 1);
    PCHECK(test_read_u32_le(auth_info.data + 12) == 2);
    PCHECK(memcmp(auth_info.data + 16, ts_credentials.data, ts_credentials.length < 8u ? ts_credentials.length : 8u) !=
           0);
    rdp_buffer_free(&nla_request);
    rdp_buffer_free(&dyn_response);
    rdp_buffer_free(&channel_packet);
    rdp_buffer_free(&license_payload);
    rdp_buffer_free(&license_packet);
    rdp_buffer_free(&ts_request);
    rdp_buffer_free(&auth_info);
    rdp_buffer_free(&ts_credentials);
    rdp_buffer_free(&server_pub_key_auth);
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&ntlm_unwrapped);
    rdp_buffer_free(&ntlm_wrapped);
    rdp_buffer_free(&spnego_authenticate);
    rdp_buffer_free(&spnego_negotiate);
    rdp_buffer_free(&ntlm_authenticate);
    rdp_buffer_free(&ntlm_negotiate);
    rdp_buffer_free(&x509_chain);
    rdp_clearcodec_context_free(&clear_context);
    rdp_nscodec_context_free(&nscodec_context);
    rdp_graphics_decompressor_free(&graphics_decompressor);
    rdp_buffer_free(&graphics_reset_pdu);
    rdp_buffer_free(&nscodec_capability_buffer);
    rdp_buffer_free(&nscodec_pixels);
    rdp_buffer_free(&planar_pixels);
    rdp_buffer_free(&graphics_decoded);
    rdp_buffer_free(&client_refresh_rect);
    rdp_buffer_free(&client_suppress_output);
    rdp_buffer_free(&decoded_bitmap);
    rdp_buffer_free(&decoded_pointer);
    rdp_buffer_free(&clear_pixels);
    rdp_buffer_free(&client_mouse_input);
    rdp_buffer_free(&client_keyboard_input);
    rdp_buffer_free(&client_font_list);
    rdp_buffer_free(&client_persistent_keys);
    rdp_buffer_free(&client_control);
    rdp_buffer_free(&client_sync);
    rdp_buffer_free(&expected_cipher);
    rdp_buffer_free(&decoded_fastpath);
    rdp_buffer_free(&encrypted_fastpath);
    rdp_buffer_free(&plain_security);
    rdp_buffer_free(&unwrapped_pdu);
    rdp_buffer_free(&protected_pdu);
    rdp_buffer_free(&plain_info_body);
    rdp_buffer_free(&encrypted_info);
    rdp_buffer_free(&confirm_active);
    rdp_buffer_free(&encrypted);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security);
    return 0;
}

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
    PCHECK((general.extended_pdu & RDP_DEVICE_REDIRECTION_EXT_USER_LOGGEDON) != 0);
    PCHECK(caps.capabilities[1].type == RDP_DEVICE_REDIRECTION_CAP_DRIVE);
    PCHECK(caps.capabilities[1].version == RDP_DEVICE_REDIRECTION_CAP_VERSION_2);
    PCHECK(caps.capabilities[2].type == RDP_DEVICE_REDIRECTION_CAP_SMARTCARD);
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
    rdp_filesystem_redirection_create_response create_response;
    rdp_filesystem_redirection_length_response length_response;
    rdp_device_redirection_io_completion completion_response;
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
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    PCHECK(rdp_filesystem_redirection_write_notify_change_request(&request,
                                                                  1,
                                                                  2,
                                                                  3,
                                                                  1u,
                                                                  0x11223344u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) == LIBRDP_STATUS_OK);
    PCHECK(notify_request.watch_tree == 1u);
    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
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
    PCHECK(rdp_buffer_append_u32_le(&request, 0x11223344u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&request, 27u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_filesystem_redirection_parse_notify_change_request(request.data,
                                                                  request.length,
                                                                  &notify_request) == LIBRDP_STATUS_OK);
    PCHECK(notify_request.watch_tree == 1u && notify_request.completion_filter == 0x11223344u);
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
    PCHECK(rdp_filesystem_redirection_parse_close_response(response.data,
                                                           response.length,
                                                           &completion_response) == LIBRDP_STATUS_OK);
    PCHECK(completion_response.device_id == 1u && completion_response.completion_id == 3u);
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
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_cache_delete(&packet,
                                                      printer,
                                                      sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_DELETE);
    PCHECK(event.printer_name_len == sizeof(printer));
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
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_xps_mode(&packet, 0x10203040u, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_xps_mode(packet.data, packet.length, &mode) ==
           LIBRDP_STATUS_OK);
    PCHECK(mode.printer_id == 0x10203040u && mode.flags == 1u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

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
    PCHECK(rdp_printer_redirection_write_write_response(&packet, 1, 2, 0, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_write_response(packet.data,
                                                        packet.length,
                                                        &printer_completion,
                                                        &printer_value) == LIBRDP_STATUS_OK);
    PCHECK(printer_value == 4u);
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

    PCHECK(rdp_multiparty_write_filter_state(&buffer, RDP_MULTIPARTY_FILTER_ENABLED) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_filter_state(buffer.data, buffer.length, &filter) == LIBRDP_STATUS_OK);
    PCHECK(filter.flags == RDP_MULTIPARTY_FILTER_ENABLED);
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.type == RDP_MULTIPARTY_TYPE_FILTER_STATE_UPDATED &&
           message.body.filter_state.flags == RDP_MULTIPARTY_FILTER_ENABLED);
    buffer.data[4] = 0x80;
    PCHECK(rdp_multiparty_parse_filter_state(buffer.data, buffer.length, &filter) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
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
    PCHECK(rdp_multiparty_parse_app_created(buffer.data, buffer.length, &app) == LIBRDP_STATUS_OK);
    PCHECK(app.flags == RDP_MULTIPARTY_APPLICATION_SHARED &&
           app.app_id == 0x11223344u &&
           app.name.char_count == 1 &&
           app.name.utf16[0] == 'A');
    PCHECK(rdp_multiparty_parse_app_created(buffer.data,
                                            buffer.length - 1u,
                                            &app) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_id_message(&buffer, RDP_MULTIPARTY_TYPE_WND_SHOW, 7u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_id_message(buffer.data,
                                           buffer.length,
                                           RDP_MULTIPARTY_TYPE_WND_SHOW,
                                           &id_message) == LIBRDP_STATUS_OK);
    PCHECK(id_message.id == 7u);
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
    PCHECK(rdp_multiparty_parse_message(buffer.data, buffer.length, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.type == RDP_MULTIPARTY_TYPE_WND_CREATED &&
           message.body.window_created.window_id == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_region_update(&buffer, 1, 2, 10, 20) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_region_update(buffer.data, buffer.length, &region) == LIBRDP_STATUS_OK);
    PCHECK(region.left == 1 && region.bottom == 20);
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
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_participant_removed(&buffer, 3u, 2u, 0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_participant_removed(buffer.data, buffer.length, &removed) ==
           LIBRDP_STATUS_OK);
    PCHECK(removed.participant_id == 3u && removed.disconnect_type == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_control_change(&buffer,
                                               RDP_MULTIPARTY_REQUEST_VIEW |
                                                   RDP_MULTIPARTY_ALLOW_CONTROL_REQUESTS,
                                               3u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_control_change(buffer.data, buffer.length, &change) ==
           LIBRDP_STATUS_OK);
    PCHECK(change.participant_id == 3u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multiparty_write_control_change_response(&buffer,
                                                        RDP_MULTIPARTY_REQUEST_INTERACT,
                                                        3u,
                                                        0u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multiparty_parse_control_change_response(buffer.data, buffer.length, &response) ==
           LIBRDP_STATUS_OK);
    PCHECK(response.flags == RDP_MULTIPARTY_REQUEST_INTERACT && response.reason_code == 0);
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
    rdp_smartcard_redirection_long_return long_result;
    rdp_smartcard_redirection_count_return count_result;
    rdp_smartcard_redirection_buffer_return buffer_result;
    rdp_smartcard_redirection_establish_context_return establish_result;
    rdp_smartcard_redirection_connect_return connect_result;
    rdp_smartcard_redirection_status_return status_result;
    rdp_smartcard_redirection_transmit_return transmit_result;
    rdp_device_redirection_io_request io_request;
    rdp_device_redirection_io_completion io_completion;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_auth_redirection_kerb_call_id_valid(RDP_AUTH_REDIRECTION_CALL_KERB_FINALIZE_KEY_AGREEMENT));
    PCHECK(rdp_auth_redirection_ntlm_call_id_valid(
        RDP_AUTH_REDIRECTION_CALL_NTLM_CALCULATE_USER_SESSION_KEY_NT));
    PCHECK(!rdp_auth_redirection_ecdh_key_bits_valid(255));

    PCHECK(rdp_auth_redirection_write_call(&buffer,
                                           RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS,
                                           call_payload,
                                           sizeof(call_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_auth_redirection_parse_call(buffer.data, buffer.length, &auth_call) == LIBRDP_STATUS_OK);
    PCHECK(auth_call.call_id == RDP_AUTH_REDIRECTION_CALL_NTLM_COMPARE_CREDENTIALS &&
           auth_call.payload_len == sizeof(call_payload) &&
           memcmp(auth_call.payload, call_payload, sizeof(call_payload)) == 0);
    PCHECK(rdp_auth_redirection_write_call(&packet, 0x00000300u, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
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
           outer.length == buffer.length &&
           outer.payload_len == sizeof(call_payload));
    buffer.data[8] = 1;
    PCHECK(rdp_auth_redirection_parse_outer_packet(buffer.data, buffer.length, &outer) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_smartcard_redirection_ioctl_valid(RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT));
    PCHECK(!rdp_smartcard_redirection_ioctl_valid(0x0009010cu));
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

    memset(status_readers, 0, sizeof(status_readers));
    status_readers[0].reader_name_is_null = 0;
    status_readers[0].reader_name = (const uint8_t*)"Reader A";
    status_readers[0].reader_name_len = 8u;
    status_readers[0].state.current_state = 0x10u;
    status_readers[0].state.event_state = 0x20u;
    status_readers[0].state.atr_len = sizeof(scard_extra);
    memcpy(status_readers[0].state.atr, scard_extra, sizeof(scard_extra));
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

static int test_desktop_composition_channel(void)
{
    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    rdp_desktop_composition_header header;
    rdp_desktop_composition_toggle toggle;
    rdp_desktop_composition_lsurface lsurface;
    rdp_desktop_composition_surfobj surfobj;
    rdp_desktop_composition_assoc assoc;
    rdp_desktop_composition_u64_order u64_order;
    rdp_desktop_composition_u32_order u32_order;
    rdp_desktop_composition_opaque opaque;
    rdp_buffer buffer;

    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_operation_valid(RDP_DESKTOP_COMPOSITION_OP_TOGGLE));
    PCHECK(!rdp_desktop_composition_operation_valid(0));
    PCHECK(rdp_desktop_composition_parse_header(payload, sizeof(payload), &header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_desktop_composition_write_toggle(&buffer,
                                                RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON) ==
           LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 5u);
    PCHECK(rdp_desktop_composition_parse_toggle(buffer.data, buffer.length, &toggle) ==
           LIBRDP_STATUS_OK);
    PCHECK(toggle.header.size == 1u && toggle.event_type == RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON);
    buffer.data[4] = 0xffu;
    PCHECK(rdp_desktop_composition_parse_toggle(buffer.data, buffer.length, &toggle) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_lsurface(&buffer,
                                                  1,
                                                  RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                                                      RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION,
                                                  0x0102030405060708ull,
                                                  1024,
                                                  768,
                                                  0x1112131415161718ull,
                                                  0x2122232425262728ull) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 38u);
    PCHECK(rdp_desktop_composition_parse_lsurface(buffer.data, buffer.length, &lsurface) ==
           LIBRDP_STATUS_OK);
    PCHECK(lsurface.create == 1u &&
           lsurface.flags == (RDP_DESKTOP_COMPOSITION_LSURFACE_COMPOSE_ONCE |
                              RDP_DESKTOP_COMPOSITION_LSURFACE_REDIRECTION) &&
           lsurface.surface_id == 0x0102030405060708ull &&
           lsurface.width == 1024u &&
           lsurface.height == 768u &&
           lsurface.window_id == 0x1112131415161718ull &&
           lsurface.luid == 0x2122232425262728ull);
    PCHECK(rdp_desktop_composition_write_lsurface(&buffer, 1, 0x80, 1, 1, 1, 1, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_surfobj(&buffer,
                                                 0x8f,
                                                 32,
                                                 0x3132333435363738ull,
                                                 64,
                                                 32) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 26u);
    PCHECK(rdp_desktop_composition_parse_surfobj(buffer.data, buffer.length, &surfobj) ==
           LIBRDP_STATUS_OK);
    PCHECK(surfobj.cache_id == 0x8fu &&
           surfobj.surface_bpp == 32u &&
           surfobj.surface_id == 0x3132333435363738ull &&
           surfobj.width == 64u &&
           surfobj.height == 32u);
    buffer.data[9] = 1u;
    PCHECK(rdp_desktop_composition_parse_surfobj(buffer.data, buffer.length, &surfobj) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_assoc(&buffer,
                                               1,
                                               0x4142434445464748ull,
                                               0x5152535455565758ull) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 21u);
    PCHECK(rdp_desktop_composition_parse_assoc(buffer.data, buffer.length, &assoc) ==
           LIBRDP_STATUS_OK);
    PCHECK(assoc.associate == 1u &&
           assoc.logical_surface_id == 0x4142434445464748ull &&
           assoc.redirection_surface_id == 0x5152535455565758ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_compref(&buffer, 0x6162636465666768ull) ==
           LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 12u);
    PCHECK(rdp_desktop_composition_parse_compref(buffer.data, buffer.length, &u64_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(u64_order.value == 0x6162636465666768ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_switch_surfobj(&buffer, 0x44u) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 8u);
    PCHECK(rdp_desktop_composition_parse_switch_surfobj(buffer.data, buffer.length, &u32_order) ==
           LIBRDP_STATUS_OK);
    PCHECK(u32_order.value == 0x44u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_desktop_composition_write_opaque(&buffer,
                                                RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE,
                                                payload,
                                                sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 8u);
    PCHECK(rdp_desktop_composition_parse_opaque(buffer.data, buffer.length, &opaque) ==
           LIBRDP_STATUS_OK);
    PCHECK(opaque.header.operation == RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE &&
           opaque.payload_len == sizeof(payload) &&
           memcmp(opaque.payload, payload, sizeof(payload)) == 0);
    buffer.data[2] = 0xffu;
    PCHECK(rdp_desktop_composition_parse_opaque(buffer.data, buffer.length, &opaque) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    return 0;
}

static int test_composited_remoting_channel(void)
{
    const uint8_t color[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x3f};
    uint8_t surfaces[RDP_COMPOSITED_TEXTURE_SLOT_COUNT * RDP_COMPOSITED_TEXTURE_SLOT_BYTES] = {0};
    uint32_t versions[1] = {RDP_COMPOSITED_PROTOCOL_VERSION};
    uint32_t glyphs[3] = {0x21, 0x22, 0x23};
    rdp_composited_control control;
    rdp_composited_version_reply reply;
    rdp_composited_resource_order resource;
    rdp_composited_duplicate_handle duplicate;
    rdp_composited_u32_target_order u32_order;
    rdp_composited_window_node_create window_node;
    rdp_composited_target_create target;
    rdp_composited_glyph_run glyph_run;
    rdp_composited_gdi_sprite_bitmap sprite;
    rdp_composited_gdi_surface_update surface_update;
    rdp_composited_meta_target meta;
    rdp_composited_batch_reader reader;
    rdp_composited_channel_message message;
    rdp_composited_render_tree tree;
    const rdp_composited_render_resource* render_resource = NULL;
    rdp_buffer buffer;
    rdp_buffer batch;
    rdp_buffer wrapped;

    rdp_composited_render_tree_init(&tree);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&batch);
    rdp_buffer_init(&wrapped);

    PCHECK(rdp_composited_control_code_valid(RDP_COMPOSITED_CONTROL_OPEN_CHANNEL));
    PCHECK(!rdp_composited_control_code_valid(0x08u));
    PCHECK(rdp_composited_channel_command_known(RDP_COMPOSITED_CMD_GDI_SPRITE_BITMAP_UPDATE_SURFACE));
    PCHECK(rdp_composited_notification_code_valid(RDP_COMPOSITED_MSG_VERSION_REPLY));

    PCHECK(rdp_composited_write_control_fixed(&buffer,
                                              RDP_COMPOSITED_CONTROL_VERSION_REQUEST,
                                              0,
                                              0) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 16u);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_VERSION_REQUEST &&
           control.message_size == 16u);
    buffer.data[4] = 0xffu;
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_version_reply(&buffer, versions, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(buffer.data, buffer.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_CONNECTION_NOTIFICATION);
    PCHECK(rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply) ==
           LIBRDP_STATUS_OK);
    PCHECK(reply.version_count == 1u &&
           rdp_composited_version_reply_has(&reply, RDP_COMPOSITED_PROTOCOL_VERSION));
    ((uint8_t*)control.payload)[8] = RDP_COMPOSITED_MAX_VERSION_COUNT + 1u;
    PCHECK(rdp_composited_parse_version_reply(control.payload, control.payload_len, &reply) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                               0x10u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_resource_order(buffer.data,
                                               buffer.length,
                                               RDP_COMPOSITED_CMD_CREATE_RESOURCE,
                                               &resource) == LIBRDP_STATUS_OK);
    PCHECK(resource.resource == 0x10u && resource.resource_type == RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
    PCHECK(rdp_composited_write_resource_order(&buffer, 0xffffffffu, 1, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_buffer_append(&batch, buffer.data, buffer.length) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_duplicate_handle(&buffer, 0x10u, 0x20u, 0x30u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_duplicate_handle(buffer.data, buffer.length, &duplicate) ==
           LIBRDP_STATUS_OK);
    PCHECK(duplicate.original == 0x10u &&
           duplicate.target_channel == 0x20u &&
           duplicate.duplicate == 0x30u);
    PCHECK(rdp_buffer_append(&batch, buffer.data, buffer.length) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                 0x44u,
                                                 0x55u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_u32_target_order(buffer.data,
                                                 buffer.length,
                                                 RDP_COMPOSITED_CMD_WINDOW_NODE_SET_LOGICAL_SURFACE_IMAGE,
                                                 &u32_order) == LIBRDP_STATUS_OK);
    PCHECK(u32_order.target_resource == 0x44u && u32_order.value == 0x55u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_window_node_create(&buffer,
                                                   0x11u,
                                                   0x0102030405060708ull,
                                                   0x1112131415161718ull,
                                                   2u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_window_node_create(buffer.data, buffer.length, &window_node) ==
           LIBRDP_STATUS_OK);
    PCHECK(window_node.target_resource == 0x11u &&
           window_node.sprite_id == 0x0102030405060708ull &&
           window_node.window_id == 0x1112131415161718ull &&
           window_node.caching_mode == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_create(&buffer, 0x12u, 1280u, 720u, color) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_target_create(buffer.data, buffer.length, &target) ==
           LIBRDP_STATUS_OK);
    PCHECK(target.target_resource == 0x12u &&
           target.width == 1280u &&
           target.height == 720u &&
           memcmp(target.clear_color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_glyph_run(&buffer, 0x13u, 0x14u, 2, glyphs, 3) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_glyph_run(buffer.data, buffer.length, &glyph_run) ==
           LIBRDP_STATUS_OK);
    PCHECK(glyph_run.target_resource == 0x13u &&
           glyph_run.glyph_cache == 0x14u &&
           glyph_run.glyph_count == 3u &&
           glyph_run.precontrast_level == 2 &&
           glyph_run.glyph_indices_len == 12u);
    PCHECK(rdp_composited_write_glyph_run(&buffer, 0x13u, 0x14u, 7, glyphs, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_sprite_bitmap(&buffer,
                                                  0x15u,
                                                  0x2122232425262728ull,
                                                  0x3132333435363738ull) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_gdi_sprite_bitmap(buffer.data, buffer.length, &sprite) ==
           LIBRDP_STATUS_OK);
    PCHECK(sprite.target_resource == 0x15u &&
           sprite.sprite_id == 0x2122232425262728ull &&
           sprite.logical_surface_id == 0x3132333435363738ull);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_gdi_surface_update(&buffer, 0x16u, 0x57u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_gdi_surface_update(buffer.data,
                                                   buffer.length,
                                                   &surface_update) == LIBRDP_STATUS_OK);
    PCHECK(surface_update.target_resource == 0x16u && surface_update.dxgi_format == 0x57u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    surfaces[0] = 1u;
    PCHECK(rdp_composited_write_meta_target(&buffer,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            0x17u,
                                            1u,
                                            0x57u,
                                            1920u,
                                            1080u,
                                            surfaces) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 0xe4u);
    PCHECK(rdp_composited_parse_meta_target(buffer.data,
                                            buffer.length,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            &meta) == LIBRDP_STATUS_OK);
    PCHECK(meta.target_resource == 0x17u &&
           meta.textures.surface_count == 1u &&
           meta.textures.dxgi_format == 0x57u &&
           meta.textures.width == 1920u &&
           meta.textures.height == 1080u &&
           meta.textures.surfaces[0] == 1u);
    PCHECK(rdp_composited_write_meta_target(&buffer,
                                            RDP_COMPOSITED_CMD_META_TARGET_CREATE,
                                            0x17u,
                                            9u,
                                            0x57u,
                                            1u,
                                            1u,
                                            surfaces) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_batch_init(&reader, batch.data, batch.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.control_code == RDP_COMPOSITED_CMD_CREATE_RESOURCE);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_OK);
    PCHECK(message.control_code == RDP_COMPOSITED_CMD_DUPLICATE_HANDLE);
    PCHECK(rdp_composited_batch_next(&reader, &message) == LIBRDP_STATUS_AGAIN);
    PCHECK(rdp_composited_render_tree_apply_batch(&tree, batch.data, batch.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(tree.command_count == 2u && tree.resource_count == 2u);
    render_resource = rdp_composited_render_tree_find(&tree, 0x10u);
    PCHECK(render_resource && render_resource->resource_type == RDP_COMPOSITED_RESOURCE_WINDOW_NODE);
    render_resource = rdp_composited_render_tree_find(&tree, 0x30u);
    PCHECK(render_resource && render_resource->duplicate_source == 0x10u &&
           render_resource->duplicate_target_channel == 0x20u);
    PCHECK(rdp_composited_write_data_on_channel(&wrapped, 7u, batch.data, batch.length) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_control(wrapped.data, wrapped.length, &control) == LIBRDP_STATUS_OK);
    PCHECK(control.control_code == RDP_COMPOSITED_CONTROL_DATA_ON_CHANNEL &&
           control.word0 == 7u &&
           control.payload_len == batch.length);
    wrapped.data[7] = 1u;
    PCHECK(rdp_composited_parse_control(wrapped.data, wrapped.length, &control) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_target_create(&buffer, 0x40u, 640u, 480u, color) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->resource_type == RDP_COMPOSITED_RESOURCE_HWND_TARGET &&
           render_resource->width == 640u && render_resource->height == 480u &&
           memcmp(render_resource->clear_color, color, sizeof(color)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_u32_target_order(&buffer,
                                                 RDP_COMPOSITED_CMD_TARGET_SET_ROOT,
                                                 0x40u,
                                                 0x10u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    render_resource = rdp_composited_render_tree_find(&tree, 0x40u);
    PCHECK(render_resource && render_resource->root_resource == 0x10u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_composited_write_resource_order(&buffer,
                                               RDP_COMPOSITED_CMD_DELETE_RESOURCE,
                                               0x10u,
                                               RDP_COMPOSITED_RESOURCE_WINDOW_NODE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_parse_channel_message(buffer.data, buffer.length, &message) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, &message) == LIBRDP_STATUS_OK);
    PCHECK(rdp_composited_render_tree_find(&tree, 0x10u) == NULL);
    PCHECK(rdp_composited_render_tree_apply_message(&tree, NULL) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&wrapped);
    rdp_buffer_free(&batch);
    rdp_buffer_free(&buffer);
    return 0;
}

static int test_video_redirection_channel(void)
{
    const uint8_t guid[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t format[] = {0xde, 0xad, 0xbe, 0xef};
    const uint8_t sample_data[] = {1, 2, 3, 4, 5};
    const uint8_t event_data[] = {9, 8};
    rdp_buffer buffer;
    rdp_buffer payload;
    rdp_buffer nested;
    rdp_video_redirection_header header;
    rdp_video_redirection_capability_message caps;
    rdp_video_redirection_rim_capability rim;
    rdp_video_redirection_playback_ack ack;
    rdp_video_redirection_client_event event;
    rdp_video_redirection_stream stream;
    rdp_video_redirection_presentation presentation;
    rdp_video_redirection_media_type media_type;
    rdp_video_redirection_data_sample data_sample;
    rdp_video_redirection_playback_started started;
    rdp_video_redirection_playback_rate rate;
    rdp_video_redirection_window window;
    rdp_video_redirection_geometry_update geometry_update;
    rdp_video_redirection_geometry_info geometry_info;
    rdp_video_redirection_rect rect;
    rdp_video_redirection_volume volume;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_header(&buffer,
                                              RDP_VIDEO_REDIRECTION_INTERFACE_DEFAULT,
                                              RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY,
                                              0,
                                              1,
                                              RDP_VIDEO_REDIRECTION_FUNC_EXCHANGE_CAPABILITIES_REQ) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_write_u32_capability(&buffer,
                                                      RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION,
                                                      RDP_VIDEO_REDIRECTION_PROTOCOL_VERSION_2) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_write_u32_capability(&buffer,
                                                      RDP_VIDEO_REDIRECTION_CAPABILITY_PLATFORM,
                                                      RDP_VIDEO_REDIRECTION_PLATFORM_MF) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_request(buffer.data,
                                                                     buffer.length,
                                                                     &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.capabilities.count == 2 &&
           caps.capabilities.capabilities[0].type == RDP_VIDEO_REDIRECTION_CAPABILITY_PROTOCOL_VERSION &&
           test_read_u32_le(caps.capabilities.capabilities[1].data) == RDP_VIDEO_REDIRECTION_PLATFORM_MF);
    PCHECK(rdp_video_redirection_write_exchange_capabilities_request(&payload,
                                                                     2,
                                                                     caps.capabilities.capabilities,
                                                                     caps.capabilities.count) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_request(payload.data,
                                                                     payload.length,
                                                                     &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.header.message_id == 2 && caps.capabilities.count == 2);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_video_redirection_write_exchange_capabilities_response(&payload,
                                                                      0,
                                                                      caps.capabilities.capabilities,
                                                                      caps.capabilities.count,
                                                                      0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_response(payload.data,
                                                                      payload.length,
                                                                      &caps) ==
           LIBRDP_STATUS_OK);
    PCHECK(caps.has_result && caps.result == 0);
    payload.data[3] = 0x40;
    PCHECK(rdp_video_redirection_parse_exchange_capabilities_response(payload.data,
                                                                      payload.length,
                                                                      &caps) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_redirection_write_rim_capability_request(
               &buffer,
               3,
               RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rim_capability_request(buffer.data, buffer.length, &rim) ==
           LIBRDP_STATUS_OK);
    PCHECK(rim.header.message_id == 3 && rim.capability == RDP_VIDEO_REDIRECTION_RIM_CAPABILITY_VERSION_01);
    PCHECK(rdp_video_redirection_write_rim_capability_response(&payload,
                                                               rim.header.message_id,
                                                               rim.capability,
                                                               0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rim_capability_response(payload.data,
                                                               payload.length,
                                                               &rim) ==
           LIBRDP_STATUS_OK);
    PCHECK(rim.has_result && rim.result == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_redirection_write_playback_ack(&buffer, 4, 1, 0x51615u, 0x7e2u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_ack(buffer.data, buffer.length, &ack) ==
           LIBRDP_STATUS_OK);
    PCHECK(ack.stream_id == 1 && ack.data_duration == 0x51615u && ack.data_len == 0x7e2u);
    PCHECK(rdp_video_redirection_write_client_event(&payload,
                                                    5,
                                                    0,
                                                    RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED,
                                                    event_data,
                                                    sizeof(event_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_client_event(payload.data, payload.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_VIDEO_REDIRECTION_CLIENT_EVENT_START_COMPLETED &&
           event.data_len == sizeof(event_data) &&
           event.data[1] == 8);
    payload.data[20] = 9;
    PCHECK(rdp_video_redirection_parse_client_event(payload.data, payload.length, &event) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_redirection_write_set_channel_params(&buffer, 6, guid, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_set_channel_params(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 0 && stream.presentation_id[15] == 15);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_new_presentation(&buffer,
                                                        7,
                                                        guid,
                                                        RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_new_presentation(buffer.data,
                                                        buffer.length,
                                                        &presentation) ==
           LIBRDP_STATUS_OK);
    PCHECK(presentation.platform_cookie == RDP_VIDEO_REDIRECTION_PLATFORM_COOKIE_MF);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0x1000) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, guid, sizeof(guid)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, sizeof(format)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, format, sizeof(format)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_media_type(nested.data, nested.length, &media_type) ==
           LIBRDP_STATUS_OK);
    PCHECK(media_type.format_len == sizeof(format) && media_type.format[0] == 0xde);
    PCHECK(rdp_video_redirection_write_media_type(&payload,
                                                  media_type.major_type,
                                                  media_type.sub_type,
                                                  media_type.fixed_size_samples,
                                                  media_type.temporal_compression,
                                                  media_type.sample_size,
                                                  media_type.format_type,
                                                  media_type.format,
                                                  media_type.format_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_media_type(payload.data, payload.length, &media_type) ==
           LIBRDP_STATUS_OK);
    PCHECK(media_type.format_len == sizeof(format) && media_type.format[3] == 0xef);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_video_redirection_write_add_stream(&buffer,
                                                  8,
                                                  guid,
                                                  11,
                                                  nested.data,
                                                  (uint32_t)nested.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_add_stream(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 11 && stream.data_len == nested.length);
    PCHECK(rdp_video_redirection_write_add_stream(&payload, 8, guid, 11, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(test_append_u64_le(&nested, 0x37u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&nested, 0x38u) == LIBRDP_STATUS_OK);
    PCHECK(test_append_u64_le(&nested, 0x55u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&nested, sizeof(sample_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&nested, sample_data, sizeof(sample_data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_data_sample(nested.data, nested.length, &data_sample) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_sample.sample_end_time == 0x38u &&
           data_sample.data_len == sizeof(sample_data) &&
           data_sample.data[4] == 5);
    PCHECK(rdp_video_redirection_write_data_sample(&payload,
                                                   data_sample.sample_start_time,
                                                   data_sample.sample_end_time,
                                                   data_sample.throttle_duration,
                                                   data_sample.sample_flags,
                                                   data_sample.sample_extensions,
                                                   data_sample.data,
                                                   data_sample.data_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_data_sample(payload.data, payload.length, &data_sample) ==
           LIBRDP_STATUS_OK);
    PCHECK(data_sample.sample_start_time == 0x37u &&
           data_sample.data_len == sizeof(sample_data) &&
           data_sample.data[0] == 1);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&payload);
    PCHECK(rdp_video_redirection_write_sample_message(&buffer,
                                                      9,
                                                      guid,
                                                      11,
                                                      nested.data,
                                                      (uint32_t)nested.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_sample_message(buffer.data, buffer.length, &stream) ==
           LIBRDP_STATUS_OK);
    PCHECK(stream.stream_id == 11 && stream.data_len == nested.length);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_presentation_only(&buffer,
                                                         10,
                                                         RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                                         guid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_presentation_only(buffer.data,
                                                         buffer.length,
                                                         RDP_VIDEO_REDIRECTION_FUNC_SET_TOPOLOGY_REQ,
                                                         &presentation) ==
           LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_stream_only(&buffer,
                                                   11,
                                                   RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                                   guid,
                                                   11) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_stream_only(buffer.data,
                                                   buffer.length,
                                                   RDP_VIDEO_REDIRECTION_FUNC_ON_FLUSH,
                                                   &stream) == LIBRDP_STATUS_OK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_playback_started(&buffer,
                                                        12,
                                                        guid,
                                                        0x21e25d8320u,
                                                        1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_started(buffer.data,
                                                        buffer.length,
                                                        &started) == LIBRDP_STATUS_OK);
    PCHECK(started.playback_start_offset == 0x21e25d8320u && started.is_seek == 1);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_playback_rate(&buffer, 13, guid, 0x3f800000u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_playback_rate(buffer.data, buffer.length, &rate) ==
           LIBRDP_STATUS_OK);
    PCHECK(rate.rate_bits == 0x3f800000u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_set_video_window(&buffer,
                                                        14,
                                                        guid,
                                                        0x11223344u,
                                                        0x55667788u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_set_video_window(buffer.data, buffer.length, &window) ==
           LIBRDP_STATUS_OK);
    PCHECK(window.video_window_id == 0x11223344u && window.parent_window_id == 0x55667788u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&geometry_info, 0, sizeof(geometry_info));
    geometry_info.video_window_id = 0x11223344u;
    geometry_info.window_state = RDP_VIDEO_REDIRECTION_WINDOW_NEW;
    geometry_info.width = 640;
    geometry_info.height = 480;
    geometry_info.left = 10;
    geometry_info.top = 20;
    geometry_info.client_left = 12;
    geometry_info.client_top = 22;
    PCHECK(rdp_video_redirection_write_geometry_info(&nested, &geometry_info) == LIBRDP_STATUS_OK);
    memset(&geometry_info, 0, sizeof(geometry_info));
    PCHECK(rdp_video_redirection_parse_geometry_info(nested.data,
                                                     nested.length,
                                                     &geometry_info) == LIBRDP_STATUS_OK);
    PCHECK(geometry_info.width == 640 && geometry_info.client_top == 22);
    PCHECK(rdp_video_redirection_write_rect(&payload, 1, 2, 3, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_rect(payload.data, payload.length, &rect) ==
           LIBRDP_STATUS_OK);
    PCHECK(rect.top == 1 && rect.right == 4);
    PCHECK(rdp_video_redirection_write_geometry_update(&buffer,
                                                       15,
                                                       guid,
                                                       nested.data,
                                                       (uint32_t)nested.length,
                                                       payload.data,
                                                       (uint32_t)payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_geometry_update(buffer.data,
                                                       buffer.length,
                                                       &geometry_update) == LIBRDP_STATUS_OK);
    PCHECK(geometry_update.geometry_len == nested.length &&
           geometry_update.visible_rect_len == payload.length);
    PCHECK(rdp_video_redirection_write_geometry_update(&payload,
                                                       15,
                                                       guid,
                                                       nested.data,
                                                       (uint32_t)nested.length,
                                                       NULL,
                                                       1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&nested);

    PCHECK(rdp_video_redirection_write_stream_volume(&buffer, 16, guid, 0x834u, 1) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_stream_volume(buffer.data, buffer.length, &volume) ==
           LIBRDP_STATUS_OK);
    PCHECK(volume.value == 0x834u && volume.second_value == 1);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_redirection_write_channel_volume(&buffer, 17, guid, 0x2710u, 2) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_video_redirection_parse_channel_volume(buffer.data, buffer.length, &volume) ==
           LIBRDP_STATUS_OK);
    PCHECK(volume.value == 0x2710u && volume.second_value == 2);
    PCHECK(rdp_video_redirection_parse_header(buffer.data,
                                              buffer.length,
                                              1,
                                              &header) == LIBRDP_STATUS_OK);
    PCHECK(header.raw_interface_id == RDP_VIDEO_REDIRECTION_STREAM_ID_PROXY);

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&nested);
    return 0;
}

static int test_video_optimized_channel(void)
{
    const uint8_t extra[] = {0x67, 0x42, 0xc0, 0x15};
    const uint8_t sample[] = {0x00, 0x00, 0x01, 0x65, 0x88, 0x80};
    const uint8_t* h264 = rdp_video_optimized_h264_subtype_guid();
    rdp_buffer buffer;
    rdp_buffer payload;
    rdp_video_optimized_header header;
    rdp_video_optimized_presentation_request request;
    rdp_video_optimized_presentation_response response;
    rdp_video_optimized_client_notification notification;
    rdp_video_optimized_framerate_override framerate;
    rdp_video_optimized_video_data video;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_presentation_start_request(&buffer,
                                                                3,
                                                                29,
                                                                4800,
                                                                480,
                                                                244,
                                                                480,
                                                                244,
                                                                66609445540u,
                                                                0x80007aba00040222u,
                                                                h264,
                                                                extra,
                                                                sizeof(extra)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_header(buffer.data, buffer.length, &header) ==
           LIBRDP_STATUS_OK);
    PCHECK(header.size == buffer.length &&
           header.packet_type == RDP_VIDEO_OPTIMIZED_PACKET_PRESENTATION_REQUEST);
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) == LIBRDP_STATUS_OK);
    PCHECK(request.presentation_id == 3 &&
           request.command == RDP_VIDEO_OPTIMIZED_COMMAND_START &&
           request.extra_len == sizeof(extra) &&
           request.geometry_mapping_id == 0x80007aba00040222u);
    buffer.data[28] = 0x81;
    buffer.data[29] = 0x07;
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_video_optimized_write_presentation_start_request(
               &payload,
               3,
               29,
               4800,
               480,
               244,
               RDP_VIDEO_OPTIMIZED_MAX_SCALED_WIDTH + 1u,
               244,
               0,
               0,
               h264,
               NULL,
               0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_presentation_stop_request(&buffer, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) == LIBRDP_STATUS_OK);
    PCHECK(request.command == RDP_VIDEO_OPTIMIZED_COMMAND_STOP);
    PCHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_presentation_request(buffer.data,
                                                          buffer.length,
                                                          &request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_presentation_response(&buffer, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_presentation_response(buffer.data,
                                                           buffer.length,
                                                           &response) == LIBRDP_STATUS_OK);
    PCHECK(response.presentation_id == 3 && response.result_flags == 0);
    buffer.data[9] = 1;
    PCHECK(rdp_video_optimized_parse_presentation_response(buffer.data,
                                                           buffer.length,
                                                           &response) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_framerate_override(&payload,
                                                        RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE,
                                                        15) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_framerate_override(payload.data,
                                                        payload.length,
                                                        &framerate) == LIBRDP_STATUS_OK);
    PCHECK(framerate.flags == RDP_VIDEO_OPTIMIZED_FRAMERATE_OVERRIDE &&
           framerate.desired_frame_rate == 15);
    PCHECK(rdp_video_optimized_write_client_notification(
               &buffer,
               3,
               RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE,
               payload.data,
               (uint32_t)payload.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_client_notification(buffer.data,
                                                         buffer.length,
                                                         &notification) == LIBRDP_STATUS_OK);
    PCHECK(notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_FRAMERATE_OVERRIDE &&
           notification.data_len == 16u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&payload);

    PCHECK(rdp_video_optimized_write_client_notification(&buffer,
                                                         3,
                                                         RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR,
                                                         NULL,
                                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_client_notification(buffer.data,
                                                         buffer.length,
                                                         &notification) == LIBRDP_STATUS_OK);
    PCHECK(notification.notification_type == RDP_VIDEO_OPTIMIZED_NOTIFICATION_NETWORK_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_video_optimized_write_video_data(
               &buffer,
               3,
               RDP_VIDEO_OPTIMIZED_DATA_FLAG_HAS_TIMESTAMPS | RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
               444103u,
               0,
               1,
               1,
               1,
               sample,
               sizeof(sample)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_video_optimized_parse_video_data(buffer.data, buffer.length, &video) ==
           LIBRDP_STATUS_OK);
    PCHECK(video.timestamp == 444103u &&
           video.sample_len == sizeof(sample) &&
           video.sample[3] == 0x65);
    buffer.data[28] = 2;
    PCHECK(rdp_video_optimized_parse_video_data(buffer.data, buffer.length, &video) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_video_optimized_write_video_data(&payload,
                                                3,
                                                RDP_VIDEO_OPTIMIZED_DATA_FLAG_KEYFRAME,
                                                0,
                                                0,
                                                2,
                                                1,
                                                1,
                                                sample,
                                                sizeof(sample)) == LIBRDP_STATUS_INVALID_ARGUMENT);

    rdp_buffer_free(&buffer);
    rdp_buffer_free(&payload);
    return 0;
}

static int test_gdi_orders(void)
{
    const uint8_t secondary_payload[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const uint8_t primary_order[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_DSTBLT,
        0x0cu,
        0xaau,
        0xbbu
    };
    const uint8_t primary_bounds[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x0fu,
        0x03u,
        0x34u,
        0x12u,
        0x78u,
        0x56u,
        0xdeu,
        0xadu
    };
    const uint8_t bad_bounds[] = {
        RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS | RDP_GDI_TS_TYPE_CHANGE,
        RDP_GDI_ORDER_OPAQUERECT,
        0x01u,
        0x11u
    };
    const uint8_t altsec_order[] = {
        (uint8_t)((RDP_GDI_ALTSEC_SWITCH_SURFACE << 2u) | RDP_GDI_TS_SECONDARY),
        0x34u,
        0x12u
    };
    rdp_buffer secondary;
    rdp_buffer slow;
    rdp_buffer fast;
    rdp_buffer mixed;
    rdp_buffer payload;
    rdp_buffer capability;
    rdp_gdi_orders_update update;
    rdp_gdi_order_list list;
    rdp_gdi_primary_order_header primary;
    rdp_gdi_secondary_order_header secondary_header;
    rdp_gdi_altsec_order_header altsec;
    rdp_gdi_bitmap_cache_error bitmap_error;
    rdp_gdi_bitmap_cache_error parsed_error;
    rdp_gdi_color_cache_capability color;
    rdp_gdi_ninegrid_capability ninegrid;
    rdp_gdi_gdiplus_capability gdiplus;
    uint32_t flags = 0;
    size_t i = 0;

    rdp_buffer_init(&secondary);
    rdp_buffer_init(&slow);
    rdp_buffer_init(&fast);
    rdp_buffer_init(&mixed);
    rdp_buffer_init(&payload);
    rdp_buffer_init(&capability);

    PCHECK(rdp_gdi_write_secondary_order(&secondary,
                                         0x0400u,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                         secondary_payload,
                                         sizeof(secondary_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_write_secondary_order(&payload,
                                         0,
                                         RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED,
                                         secondary_payload,
                                         6) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_gdi_parse_secondary_order(secondary.data,
                                         secondary.length,
                                         &secondary_header) == LIBRDP_STATUS_OK);
    PCHECK(secondary_header.actual_length == secondary.length &&
           secondary_header.payload_len == sizeof(secondary_payload) &&
           secondary_header.order_type == RDP_GDI_SECONDARY_CACHE_BITMAP_COMPRESSED);

    PCHECK(rdp_gdi_write_slow_orders_update_payload(&slow,
                                                    1,
                                                    secondary.data,
                                                    secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_slow_orders_update_payload(slow.data,
                                                    slow.length,
                                                    &update) == LIBRDP_STATUS_OK);
    PCHECK(update.update_type == RDP_GDI_UPDATE_TYPE_ORDERS &&
           update.number_orders == 1 &&
           update.order_data_len == secondary.length);
    PCHECK(rdp_gdi_parse_order_list(update.order_data,
                                    update.order_data_len,
                                    update.number_orders,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 1 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_SECONDARY &&
           list.orders[0].length == secondary.length);

    PCHECK(rdp_gdi_write_fast_orders_update_payload(&fast,
                                                    1,
                                                    secondary.data,
                                                    secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_fast_orders_update_payload(fast.data,
                                                    fast.length,
                                                    &update) == LIBRDP_STATUS_OK);
    PCHECK(update.number_orders == 1 && update.order_data_len == secondary.length);

    PCHECK(rdp_gdi_parse_primary_order(primary_order,
                                       sizeof(primary_order),
                                       RDP_GDI_ORDER_PATBLT,
                                       &primary) == LIBRDP_STATUS_OK);
    PCHECK(primary.order_type == RDP_GDI_ORDER_DSTBLT &&
           primary.field_flags == 0x0cu &&
           primary.payload_len == 2u &&
           primary.payload[0] == 0xaau);
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_DSTBLT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_TYPE_CHANGE,
                                       0x0cu,
                                       NULL,
                                       0,
                                       primary_order + 3u,
                                       2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(primary_order) &&
           memcmp(payload.data, primary_order, sizeof(primary_order)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_parse_primary_order(primary_bounds,
                                       sizeof(primary_bounds),
                                       RDP_GDI_ORDER_PATBLT,
                                       &primary) == LIBRDP_STATUS_OK);
    PCHECK(primary.order_type == RDP_GDI_ORDER_OPAQUERECT &&
           primary.bounds_flags == 0x03u &&
           primary.bounds_len == 5u &&
           primary.payload_len == 2u);
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_OPAQUERECT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS |
                                           RDP_GDI_TS_TYPE_CHANGE,
                                       0x0fu,
                                       primary_bounds + 3u,
                                       5u,
                                       primary_bounds + 8u,
                                       2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(primary_bounds) &&
           memcmp(payload.data, primary_bounds, sizeof(primary_bounds)) == 0);
    payload.length = 0;
    PCHECK(rdp_gdi_parse_primary_order(bad_bounds,
                                       sizeof(bad_bounds),
                                       RDP_GDI_ORDER_PATBLT,
                                       &primary) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_gdi_write_primary_order(&payload,
                                       RDP_GDI_ORDER_PATBLT,
                                       RDP_GDI_ORDER_OPAQUERECT,
                                       RDP_GDI_TS_STANDARD | RDP_GDI_TS_BOUNDS |
                                           RDP_GDI_TS_TYPE_CHANGE,
                                       0x01u,
                                       bad_bounds + 3u,
                                       1u,
                                       NULL,
                                       0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_gdi_parse_altsec_order(altsec_order,
                                      sizeof(altsec_order),
                                      &altsec) == LIBRDP_STATUS_OK);
    PCHECK(altsec.order_type == RDP_GDI_ALTSEC_SWITCH_SURFACE &&
           altsec.payload_len == 2u);
    PCHECK(rdp_gdi_write_altsec_order(&payload,
                                      RDP_GDI_ALTSEC_SWITCH_SURFACE,
                                      altsec_order + 1u,
                                      2u) == LIBRDP_STATUS_OK);
    PCHECK(payload.length == sizeof(altsec_order) &&
           memcmp(payload.data, altsec_order, sizeof(altsec_order)) == 0);
    payload.length = 0;

    PCHECK(rdp_buffer_append(&mixed, secondary.data, secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&mixed, altsec_order, sizeof(altsec_order)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                    mixed.length,
                                    2,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_OK);
    PCHECK(list.count == 2 &&
           list.orders[0].kind == RDP_GDI_ORDER_KIND_SECONDARY &&
           list.orders[1].kind == RDP_GDI_ORDER_KIND_ALTSEC);
    mixed.length = 0;
    PCHECK(rdp_buffer_append(&mixed, primary_order, sizeof(primary_order)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&mixed, secondary.data, secondary.length) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_order_list(mixed.data,
                                    mixed.length,
                                    2,
                                    RDP_GDI_ORDER_PATBLT,
                                    &list) == LIBRDP_STATUS_UNSUPPORTED);
    PCHECK(rdp_gdi_parse_order_list(NULL, 0, 0, RDP_GDI_ORDER_PATBLT, &list) == LIBRDP_STATUS_OK);

    memset(&bitmap_error, 0, sizeof(bitmap_error));
    bitmap_error.count = 2;
    bitmap_error.infos[0].cache_id = 1;
    bitmap_error.infos[0].flags = RDP_GDI_BITMAP_CACHE_ERROR_FLUSH_CACHE;
    bitmap_error.infos[0].new_num_entries = 128;
    bitmap_error.infos[1].cache_id = 2;
    bitmap_error.infos[1].flags = RDP_GDI_BITMAP_CACHE_ERROR_NEWNUMENTRIES_VALID;
    bitmap_error.infos[1].new_num_entries = 256;
    PCHECK(rdp_gdi_write_bitmap_cache_error_payload(&payload, &bitmap_error) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_bitmap_cache_error_payload(payload.data,
                                                    payload.length,
                                                    &parsed_error) == LIBRDP_STATUS_OK);
    PCHECK(parsed_error.count == 2 &&
           parsed_error.infos[1].cache_id == 2 &&
           parsed_error.infos[1].new_num_entries == 256);
    payload.data[5] = 0x80u;
    PCHECK(rdp_gdi_parse_bitmap_cache_error_payload(payload.data,
                                                    payload.length,
                                                    &parsed_error) == LIBRDP_STATUS_PROTOCOL_ERROR);
    payload.length = 0;
    PCHECK(rdp_gdi_write_cache_error_flags(&payload,
                                           RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_cache_error_flags(payload.data,
                                           payload.length,
                                           RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE,
                                           &flags) == LIBRDP_STATUS_OK);
    PCHECK(flags == RDP_GDI_OFFSCREEN_CACHE_ERROR_FLUSH_AND_DISABLE);
    PCHECK(rdp_gdi_parse_cache_error_flags(payload.data,
                                           payload.length,
                                           RDP_GDI_GDIPLUS_CACHE_ERROR_FLUSH_AND_DISABLE + 1u,
                                           &flags) == LIBRDP_STATUS_PROTOCOL_ERROR);

    color.color_table_cache_size = 6;
    PCHECK(rdp_gdi_write_color_cache_capability(&capability, &color) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_color_cache_capability(capability.data,
                                                capability.length,
                                                &color) == LIBRDP_STATUS_OK);
    PCHECK(color.color_table_cache_size == 6);
    rdp_buffer_free(&capability);
    rdp_buffer_init(&capability);

    ninegrid.support_level = RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2;
    ninegrid.cache_size = 2560;
    ninegrid.cache_entries = 256;
    PCHECK(rdp_gdi_write_ninegrid_capability(&capability, &ninegrid) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_ninegrid_capability(capability.data,
                                             capability.length,
                                             &ninegrid) == LIBRDP_STATUS_OK);
    PCHECK(ninegrid.support_level == RDP_GDI_NINEGRID_SUPPORT_SUPPORTED_REV2 &&
           ninegrid.cache_size == 2560 &&
           ninegrid.cache_entries == 256);
    capability.data[8] = 1;
    capability.data[9] = 10;
    PCHECK(rdp_gdi_parse_ninegrid_capability(capability.data,
                                             capability.length,
                                             &ninegrid) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&capability);
    rdp_buffer_init(&capability);

    memset(&gdiplus, 0, sizeof(gdiplus));
    gdiplus.support_level = RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED;
    gdiplus.version = 1;
    gdiplus.cache_level = RDP_GDI_GDIPLUS_CACHE_LEVEL_ONE;
    for (i = 0; i < 5u; i++)
    {
        static const uint16_t entries[5] = {10u, 5u, 5u, 10u, 2u};

        gdiplus.cache_entries[i] = entries[i];
    }
    gdiplus.cache_chunk_size[0] = 512;
    gdiplus.cache_chunk_size[1] = 2048;
    gdiplus.cache_chunk_size[2] = 1024;
    gdiplus.cache_chunk_size[3] = 64;
    gdiplus.image_cache_properties[0] = 4096;
    gdiplus.image_cache_properties[1] = 256;
    gdiplus.image_cache_properties[2] = 128;
    PCHECK(rdp_gdi_write_gdiplus_capability(&capability, &gdiplus) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gdi_parse_gdiplus_capability(capability.data,
                                            capability.length,
                                            &gdiplus) == LIBRDP_STATUS_OK);
    PCHECK(gdiplus.support_level == RDP_GDI_GDIPLUS_SUPPORT_SUPPORTED &&
           gdiplus.cache_entries[0] == 10 &&
           gdiplus.cache_chunk_size[1] == 2048 &&
           gdiplus.image_cache_properties[2] == 128);
    capability.data[16] = 11;
    capability.data[17] = 0;
    PCHECK(rdp_gdi_parse_gdiplus_capability(capability.data,
                                            capability.length,
                                            &gdiplus) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&capability);
    rdp_buffer_free(&payload);
    rdp_buffer_free(&mixed);
    rdp_buffer_free(&fast);
    rdp_buffer_free(&slow);
    rdp_buffer_free(&secondary);
    return 0;
}

static int test_usb_redirection_channel(void)
{
    const uint8_t text[] = {'D', 0, 0, 0};
    const uint8_t instance[] = {'U', 0, 'S', 0, 'B', 0, 0, 0};
    const uint8_t ids[] = {'I', 0, 'D', 0, 0, 0, 0, 0};
    const uint8_t container[] = {'{', 0, '1', 0, '}', 0, 0, 0};
    const uint8_t payload[] = {1, 2, 3, 4};
    const uint8_t urb_result[] = {8, 0, 0, 0, 0, 0, 0, 0};
    rdp_buffer buffer;
    rdp_buffer packet;
    rdp_usb_redirection_header header;
    rdp_usb_redirection_capability_exchange exchange;
    rdp_usb_redirection_channel_created created;
    rdp_usb_redirection_device_capabilities capabilities;
    rdp_usb_redirection_add_device device;
    rdp_usb_redirection_register_callback callback;
    rdp_usb_redirection_cancel_request cancel;
    rdp_usb_redirection_io_control control;
    rdp_usb_redirection_query_device_text query;
    rdp_usb_redirection_transfer transfer;
    rdp_usb_redirection_retract_device retract;
    rdp_usb_redirection_io_completion io_completion;
    rdp_usb_redirection_urb_completion urb_completion;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            9,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            0x11223344u,
                                            1,
                                            RDP_USB_REDIRECTION_FN_IO_CONTROL) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.interface_id == 9);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_PROXY);
    PCHECK(header.message_id == 0x11223344u);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL);
    buffer.data[3] = 0xffu;
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_capability_request(&packet,
                                                        1,
                                                        RDP_USB_REDIRECTION_CAPABILITY_VERSION_01) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_capability_request(packet.data, packet.length, &exchange) ==
           LIBRDP_STATUS_OK);
    PCHECK(exchange.capability_value == RDP_USB_REDIRECTION_CAPABILITY_VERSION_01);
    PCHECK(rdp_usb_redirection_write_capability_request(&buffer, 1, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_usb_redirection_write_capability_response(&buffer,
                                                         exchange.header.message_id,
                                                         exchange.capability_value,
                                                         0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 0, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_NONE && header.payload_len == 8u);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_add_virtual_channel(&buffer, 2) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_ADD_VIRTUAL_CHANNEL);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_channel_created(&buffer,
                                                     RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                     3,
                                                     0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_channel_created(buffer.data,
                                                     buffer.length,
                                                     RDP_USB_REDIRECTION_INTERFACE_CHANNEL_NOTIFY_SERVER,
                                                     &created) == LIBRDP_STATUS_OK);
    PCHECK(created.major_version == RDP_USB_REDIRECTION_VERSION_MAJOR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    capabilities.cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
    capabilities.usb_bus_interface_version = 2;
    capabilities.usbdi_version = 0x00000600u;
    capabilities.supported_usb_version = 0x00000200u;
    capabilities.hcd_capabilities = 0;
    capabilities.device_is_high_speed = 1;
    capabilities.no_ack_isoch_write_jitter_buffer_size_ms = 0;
    PCHECK(rdp_usb_redirection_write_add_device(&buffer,
                                                4,
                                                7,
                                                instance,
                                                (uint32_t)sizeof(instance),
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                container,
                                                (uint32_t)sizeof(container),
                                                &capabilities) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_add_device(buffer.data, buffer.length, &device) == LIBRDP_STATUS_OK);
    PCHECK(device.num_usb_device == 1 && device.usb_device == 7);
    PCHECK(device.device_instance_id_len == sizeof(instance));
    PCHECK(device.capabilities.supported_usb_version == 0x00000200u);
    capabilities.usb_bus_interface_version = 0;
    PCHECK(rdp_usb_redirection_write_add_device(&packet,
                                                4,
                                                7,
                                                instance,
                                                (uint32_t)sizeof(instance),
                                                NULL,
                                                0,
                                                ids,
                                                (uint32_t)sizeof(ids),
                                                container,
                                                (uint32_t)sizeof(container),
                                                &capabilities) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_register_callback(&buffer, 7, 8, 9, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_register_callback(buffer.data, buffer.length, &callback) ==
           LIBRDP_STATUS_OK);
    PCHECK(callback.has_request_completion && callback.request_completion == 9);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_register_callback(&buffer, 7, 8, 0, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_register_callback(buffer.data, buffer.length, &callback) ==
           LIBRDP_STATUS_OK);
    PCHECK(!callback.has_request_completion && callback.num_request_completion == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_cancel_request(&buffer, 7, 9, 55) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_cancel_request(buffer.data, buffer.length, &cancel) == LIBRDP_STATUS_OK);
    PCHECK(cancel.request_id == 55);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                RDP_USB_REDIRECTION_FN_IO_CONTROL,
                                                RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB,
                                                payload,
                                                (uint32_t)sizeof(payload),
                                                16,
                                                56) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_io_control(buffer.data,
                                                buffer.length,
                                                RDP_USB_REDIRECTION_FN_IO_CONTROL,
                                                &control) == LIBRDP_STATUS_OK);
    PCHECK(control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB &&
           control.request_id == 56);
    PCHECK(control.input_buffer_len == sizeof(payload) &&
           memcmp(control.input_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL,
                                                0x220004u,
                                                NULL,
                                                0,
                                                0,
                                                57) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_io_control(buffer.data,
                                                buffer.length,
                                                RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL,
                                                &control) == LIBRDP_STATUS_OK);
    PCHECK(control.input_buffer_len == 0 && control.output_buffer_size == 0 && control.request_id == 57);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_io_control(&buffer,
                                                7,
                                                10,
                                                0,
                                                0,
                                                NULL,
                                                1,
                                                0,
                                                0) == LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_usb_redirection_write_query_device_text(&buffer, 7, 11, 1, 0x409) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_query_device_text(buffer.data, buffer.length, &query) ==
           LIBRDP_STATUS_OK);
    PCHECK(query.text_type == 1 && query.locale_id == 0x409);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_in_request(&buffer,
                                                         7,
                                                         12,
                                                         0x0008u,
                                                         99,
                                                         0,
                                                         64) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.request_id == 99 && transfer.output_buffer_size == 64);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_urb_header(&buffer, 8, 0x0008u, 99, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_urb_header(buffer.data, buffer.length, &transfer.urb) ==
           LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.size == 8 && transfer.urb.function == 0x0008u);
    PCHECK(rdp_usb_redirection_write_urb_header(&packet, 9, 0x0008u, 99, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_out_request(&buffer,
                                                          7,
                                                          13,
                                                          0x0009u,
                                                          100,
                                                          1,
                                                          payload,
                                                          (uint32_t)sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.urb.no_ack && transfer.output_buffer_len == sizeof(payload));
    PCHECK(memcmp(transfer.output_buffer, payload, sizeof(payload)) == 0);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length - 1u,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            21,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 24) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 101) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x01) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0x02) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, (uint32_t)sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&buffer, payload, sizeof(payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.cb_ts_urb == 24 &&
           transfer.urb.size == 24 &&
           transfer.urb.function == RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER &&
           transfer.output_buffer_len == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_header(&buffer,
                                            7,
                                            RDP_USB_REDIRECTION_MASK_PROXY,
                                            22,
                                            1,
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 28) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 28) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 102) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 0x80) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u8(&buffer, 6) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0x0100) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&buffer, 18) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&buffer, 18) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_transfer(buffer.data,
                                              buffer.length,
                                              RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST,
                                              &transfer) == LIBRDP_STATUS_OK);
    PCHECK(transfer.cb_ts_urb == 28 &&
           transfer.urb.size == 28 &&
           transfer.urb.function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER &&
           transfer.output_buffer_size == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_transfer_out_request(&buffer, 7, 13, 0x0009u, 100, 0, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);

    PCHECK(rdp_usb_redirection_write_retract_device(&buffer,
                                                    7,
                                                    14,
                                                    RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_retract_device(buffer.data, buffer.length, &retract) ==
           LIBRDP_STATUS_OK);
    PCHECK(retract.reason == RDP_USB_REDIRECTION_RETRACT_BLOCKED_BY_POLICY);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_usb_redirection_write_query_device_text_response(&buffer,
                                                                7,
                                                                15,
                                                                text,
                                                                (uint32_t)sizeof(text),
                                                                0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 0, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.mask == RDP_USB_REDIRECTION_MASK_STUB);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    io_completion.request_id = 1;
    io_completion.hresult = 0;
    io_completion.information = sizeof(payload);
    io_completion.output_buffer = payload;
    io_completion.output_buffer_len = sizeof(payload);
    PCHECK(rdp_usb_redirection_write_io_control_completion(&buffer, 9, 16, &io_completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_IOCONTROL_COMPLETION);
    memset(&io_completion, 0, sizeof(io_completion));
    PCHECK(rdp_usb_redirection_parse_io_control_completion(buffer.data,
                                                           buffer.length,
                                                           &io_completion) == LIBRDP_STATUS_OK);
    PCHECK(io_completion.request_id == 1 &&
           io_completion.hresult == 0 &&
           io_completion.information == sizeof(payload) &&
           io_completion.output_buffer_len == sizeof(payload) &&
           memcmp(io_completion.output_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    urb_completion.request_id = 2;
    urb_completion.ts_urb_result = payload;
    urb_completion.cb_ts_urb_result = sizeof(payload);
    urb_completion.hresult = 0;
    urb_completion.output_buffer = payload;
    urb_completion.output_buffer_len = sizeof(payload);
    PCHECK(rdp_usb_redirection_write_urb_completion(&buffer, 9, 17, &urb_completion) ==
           LIBRDP_STATUS_OK);
    memset(&urb_completion, 0, sizeof(urb_completion));
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                    &urb_completion) == LIBRDP_STATUS_OK);
    PCHECK(urb_completion.request_id == 2 &&
           urb_completion.cb_ts_urb_result == sizeof(payload) &&
           urb_completion.hresult == 0 &&
           urb_completion.output_buffer_len == sizeof(payload) &&
           memcmp(urb_completion.ts_urb_result, payload, sizeof(payload)) == 0 &&
           memcmp(urb_completion.output_buffer, payload, sizeof(payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    urb_completion.output_buffer_len = 0;
    urb_completion.ts_urb_result = urb_result;
    urb_completion.cb_ts_urb_result = sizeof(urb_result);
    PCHECK(rdp_usb_redirection_write_urb_completion_no_data(&buffer, 9, 18, &urb_completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_usb_redirection_parse_header(buffer.data, buffer.length, 1, &header) == LIBRDP_STATUS_OK);
    PCHECK(header.function_id == RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA);
    PCHECK(header.payload_len == 24u);
    PCHECK(header.payload[4] == sizeof(urb_result));
    PCHECK(memcmp(header.payload + 8u, urb_result, sizeof(urb_result)) == 0);
    memset(&urb_completion, 0, sizeof(urb_completion));
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION_NO_DATA,
                                                    &urb_completion) == LIBRDP_STATUS_OK);
    PCHECK(urb_completion.request_id == 2 &&
           urb_completion.cb_ts_urb_result == sizeof(urb_result) &&
           urb_completion.output_buffer_len == 0 &&
           memcmp(urb_completion.ts_urb_result, urb_result, sizeof(urb_result)) == 0);
    PCHECK(rdp_usb_redirection_parse_urb_completion(buffer.data,
                                                    buffer.length,
                                                    RDP_USB_REDIRECTION_FN_URB_COMPLETION,
                                                    &urb_completion) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

static int test_pnp_redirection_channel(void)
{
    const uint8_t hwid[] = {'H', 0, 'W', 0, 0, 0, 0, 0};
    const uint8_t desc[] = {'D', 0, 'e', 0, 'v', 0};
    const uint8_t data[] = {9, 8, 7, 6};
    uint8_t guid[16] = {0x10, 0x20, 0x30, 0x40};
    rdp_buffer buffer;
    rdp_buffer packet;
    rdp_pnp_redirection_info_header info;
    rdp_pnp_redirection_version version;
    rdp_pnp_redirection_device_description device;
    rdp_pnp_redirection_device_addition addition;
    rdp_pnp_redirection_device_removal removal;
    rdp_pnp_redirection_server_io_header server_header;
    rdp_pnp_redirection_client_io_header client_header;
    rdp_pnp_redirection_io_version io_version;
    rdp_pnp_redirection_create_request create_request;
    rdp_pnp_redirection_read_request read_request;
    rdp_pnp_redirection_write_request write_request;
    rdp_pnp_redirection_control_request control_request;
    rdp_pnp_redirection_cancel_request cancel_request;
    rdp_pnp_redirection_custom_event event;

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);
    memset(&device, 0, sizeof(device));

    PCHECK(rdp_pnp_redirection_write_version(&buffer,
                                             1,
                                             0,
                                             RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_version(buffer.data, buffer.length, &version) == LIBRDP_STATUS_OK);
    PCHECK(version.major_version == 1 && version.capabilities == RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    buffer.data[0] = 1;
    PCHECK(rdp_pnp_redirection_parse_version(buffer.data, buffer.length, &version) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_authenticated(&buffer) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_authenticated(buffer.data, buffer.length, &info) == LIBRDP_STATUS_OK);
    PCHECK(info.packet_id == RDP_PNP_REDIRECTION_INFO_SERVER_LOGON && info.payload_len == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    device.client_device_id = 0x44;
    device.hardware_id = hwid;
    device.hardware_id_len = sizeof(hwid);
    device.compatibility_id = hwid;
    device.compatibility_id_len = sizeof(hwid);
    device.device_description = desc;
    device.device_description_len = sizeof(desc);
    device.custom_flag = RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_1;
    device.container_id = guid;
    device.container_id_len = sizeof(guid);
    device.has_container_id = 1;
    device.device_caps = RDP_PNP_REDIRECTION_DEVCAPS_REMOVABLE |
                         RDP_PNP_REDIRECTION_DEVCAPS_SURPRISEREMOVALOK;
    device.has_device_caps = 1;
    PCHECK(rdp_pnp_redirection_write_device_addition(&buffer, &device, 1) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_device_addition(buffer.data, buffer.length, &addition) ==
           LIBRDP_STATUS_OK);
    PCHECK(addition.device_count == 1);
    PCHECK(addition.devices[0].client_device_id == 0x44);
    PCHECK(addition.devices[0].has_container_id && addition.devices[0].has_device_caps);
    PCHECK(addition.devices[0].hardware_id_len == sizeof(hwid));
    PCHECK(rdp_pnp_redirection_parse_device_addition(buffer.data,
                                                     buffer.length - 1u,
                                                     &addition) == LIBRDP_STATUS_PROTOCOL_ERROR);
    device.interface_guids = guid;
    device.interface_guids_len = 4;
    PCHECK(rdp_pnp_redirection_write_device_addition(&packet, &device, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_device_removal(&buffer, 0x44) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_device_removal(buffer.data, buffer.length, &removal) ==
           LIBRDP_STATUS_OK);
    PCHECK(removal.client_device_id == 0x44);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet,
                                                      0x00a1b2u,
                                                      7,
                                                      RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_server_io_header(packet.data, packet.length, &server_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(server_header.request_id == 0x00a1b2u && server_header.unused == 7);
    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet,
                                                      0x01000000u,
                                                      0,
                                                      RDP_PNP_REDIRECTION_IO_READ_REQUEST) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_server_io_header(&packet, 1, 0, 0xffffffffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_capabilities_request(&buffer,
                                                          0x00a1b2u,
                                                          0,
                                                          RDP_PNP_REDIRECTION_IO_VERSION_6) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_capabilities_request(buffer.data, buffer.length, &io_version) ==
           LIBRDP_STATUS_OK);
    PCHECK(io_version.header.request_id == 0x00a1b2u);
    PCHECK(rdp_pnp_redirection_write_capabilities_request(&packet, 0, 0, 0xffffu) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_capabilities_reply(&packet,
                                                        io_version.header.request_id,
                                                        io_version.version) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_client_io_header(packet.data, packet.length, &client_header) ==
           LIBRDP_STATUS_OK);
    PCHECK(client_header.request_id == 0x00a1b2u && client_header.payload_len == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_create_request(&buffer,
                                                    1,
                                                    0,
                                                    0x44,
                                                    0xc0000000u,
                                                    3,
                                                    3,
                                                    0x40) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_create_request(buffer.data, buffer.length, &create_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(create_request.device_id == 0x44 && create_request.desired_access == 0xc0000000u);
    PCHECK(rdp_pnp_redirection_write_status_reply(&packet, 1, 0) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 8u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_read_request(&buffer, 2, 0, 32, 0, 4) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_read_request(buffer.data, buffer.length, &read_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(read_request.bytes_to_read == 32 && read_request.offset_low == 4);
    PCHECK(rdp_pnp_redirection_write_read_reply(&packet, 2, 0, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 17u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_write_request(&buffer, 3, 0, 0, 8, data, sizeof(data)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_write_request(buffer.data, buffer.length, &write_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(write_request.bytes_to_write == sizeof(data) && write_request.offset_low == 8);
    PCHECK(memcmp(write_request.data, data, sizeof(data)) == 0);
    PCHECK(rdp_pnp_redirection_write_write_request(&packet, 3, 0, 0, 8, NULL, 1) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_write_reply(&packet, 3, 0, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 12u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_control_request(&buffer, 4, 0, 0x1020, data, 2, 4, data, 4) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_control_request(buffer.data, buffer.length, &control_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(control_request.input_len == 2 && control_request.actual_output_len == 4);
    PCHECK(control_request.io_code == 0x1020 && memcmp(control_request.output, data, 4) == 0);
    PCHECK(rdp_pnp_redirection_write_control_request(&packet, 4, 0, 0x1020, data, 2, 1, data, 2) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_pnp_redirection_write_control_reply(&packet, 4, 0, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 17u);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_cancel_request(&buffer, 5, 0, 0, 0x070809u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_cancel_request(buffer.data, buffer.length, &cancel_request) ==
           LIBRDP_STATUS_OK);
    PCHECK(cancel_request.id_to_cancel == 0x070809u);
    PCHECK(rdp_pnp_redirection_write_cancel_request(&packet, 5, 0, 0, 0x01000000u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&buffer);
    rdp_buffer_init(&packet);

    PCHECK(rdp_pnp_redirection_write_custom_event(&buffer, guid, data, sizeof(data)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_pnp_redirection_parse_custom_event(buffer.data, buffer.length, &event) == LIBRDP_STATUS_OK);
    PCHECK(event.header.packet_type == RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT);
    PCHECK(event.data_len == sizeof(data));
    PCHECK(memcmp(event.event_guid, guid, sizeof(guid)) == 0);
    buffer.data[3] = 0xffu;
    PCHECK(rdp_pnp_redirection_parse_custom_event(buffer.data, buffer.length, &event) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_pnp_redirection_parse_server_io_header(data, sizeof(data), &server_header) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

int test_protocol(void)
{
    if (test_session_selection_and_echo() != 0)
        return 1;
    if (test_tpkt_x224() != 0)
        return 1;
    if (test_mcs_gcc_capabilities() != 0)
        return 1;
    if (test_audio_channels() != 0)
        return 1;
    if (test_path_security_license_channels() != 0)
        return 1;
    if (test_device_redirection_channel() != 0)
        return 1;
    if (test_filesystem_redirection_channel() != 0)
        return 1;
    if (test_port_redirection_channel() != 0)
        return 1;
    if (test_printer_redirection_channel() != 0)
        return 1;
    if (test_telemetry_multiparty_channels() != 0)
        return 1;
    if (test_xps_print_channel() != 0)
        return 1;
    if (test_auth_smartcard_redirection_channels() != 0)
        return 1;
    if (test_video_capture_channel() != 0)
        return 1;
    if (test_webauthn_channel() != 0)
        return 1;
    if (test_remote_programs_channel() != 0)
        return 1;
    if (test_desktop_composition_channel() != 0)
        return 1;
    if (test_composited_remoting_channel() != 0)
        return 1;
    if (test_video_redirection_channel() != 0)
        return 1;
    if (test_video_optimized_channel() != 0)
        return 1;
    if (test_gdi_orders() != 0)
        return 1;
    if (test_usb_redirection_channel() != 0)
        return 1;
    if (test_pnp_redirection_channel() != 0)
        return 1;
    return 0;
}
