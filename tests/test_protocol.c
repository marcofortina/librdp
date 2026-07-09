#include "channels/virtual_channel.h"
#include "channels/audio_format.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/core_input.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/filesystem_redirection.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/printer_redirection.h"
#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "common/stream.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
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
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_device_redirection_write_header(buffer,
                                                 RDP_DEVICE_REDIRECTION_COMPONENT_CORE,
                                                 RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, file_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, completion_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, major);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, minor);
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
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.channel_count == 4);
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
    rdp_audio_format pcm;
    rdp_audio_format parsed_pcm;
    rdp_audio_output_formats output_formats;
    rdp_audio_output_training training;
    rdp_audio_output_wave_info wave_info;
    rdp_audio_output_wave_data wave_data;
    rdp_audio_output_wave2 wave2;
    rdp_audio_input_formats input_formats;
    rdp_audio_input_open input_open;
    rdp_audio_input_data input_data;
    rdp_buffer out;
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

    PCHECK(rdp_audio_output_parse_training(training_pdu, sizeof(training_pdu), &training) == LIBRDP_STATUS_OK);
    PCHECK(training.timestamp == 0x1234 && training.packet_size == 2);
    PCHECK(training.data_len == 2 && training.data[0] == 0xaa && training.data[1] == 0xbb);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_training_confirm(&out, training.timestamp, training.packet_size) ==
           LIBRDP_STATUS_OK);
    PCHECK(out.length == 8 && out.data[0] == RDP_AUDIO_OUTPUT_TRAINING && test_read_u16_le(out.data + 4) == 0x1234);

    PCHECK(rdp_audio_output_parse_wave_info(wave_info_pdu, sizeof(wave_info_pdu), &wave_info) == LIBRDP_STATUS_OK);
    PCHECK(wave_info.timestamp == 0xadd7 && wave_info.format_no == 15 && wave_info.block_no == 8);
    PCHECK(wave_info.expected_data_len == 8 && wave_info.first_data_len == 4 && wave_info.first_data[0] == 0x20);
    PCHECK(rdp_audio_output_parse_wave_data(wave_data_pdu, sizeof(wave_data_pdu), &wave_data) ==
           LIBRDP_STATUS_OK);
    PCHECK(wave_data.data_len == 3 && wave_data.data[0] == 0x84);
    PCHECK(rdp_audio_output_parse_wave2(wave2_pdu, sizeof(wave2_pdu), &wave2) == LIBRDP_STATUS_OK);
    PCHECK(wave2.timestamp == 0xa116 && wave2.format_no == 3 && wave2.block_no == 2);
    PCHECK(wave2.audio_timestamp == 0x0dacb8c2u && wave2.data_len == 3 && wave2.data[2] == 0x45);
    rdp_buffer_free(&out);
    rdp_buffer_init(&out);
    PCHECK(rdp_audio_output_write_wave_confirm(&out, 0x5ab7, 8) == LIBRDP_STATUS_OK);
    PCHECK(out.length == 8 && out.data[0] == RDP_AUDIO_OUTPUT_WAVECONFIRM &&
           test_read_u16_le(out.data + 4) == 0x5ab7 && out.data[6] == 8);

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
    PCHECK(input_formats.format_count == 1 && input_formats.formats_len == sizeof(pcm_format));
    PCHECK(input_formats.formats_packet_size == out.length && input_formats.extra_data_len == 0);

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
    const uint8_t bitmap_16_data[] = {0x00, 0xf8, 0xe0, 0x07};
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
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&dyn_response);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_fastpath_parse_updates(fast_bitmap_update, sizeof(fast_bitmap_update), &fast_updates) ==
           LIBRDP_STATUS_OK);
    PCHECK(fast_updates.count == 1 && fast_updates.updates[0].update_code == RDP_FASTPATH_UPDATE_BITMAP &&
           fast_updates.updates[0].fragmentation == RDP_FASTPATH_FRAGMENT_SINGLE &&
           fast_updates.updates[0].compression == 0 && fast_updates.updates[0].data_len == 38);
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
    bitmap_rect.flags = 1;
    PCHECK(rdp_bitmap_decode_rect_bgra32(&bitmap_rect, &decoded_bitmap, &decoded_stride) == LIBRDP_STATUS_UNSUPPORTED);
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
    PCHECK(rdp_rfx_parse_progressive_quant(rfx_progressive_quant_values,
                                           sizeof(rfx_progressive_quant_values),
                                           &rfx_progressive_quant) == LIBRDP_STATUS_OK);
    PCHECK(rfx_progressive_quant.quality == 0x64 &&
           rfx_progressive_quant.y.ll3 == 1 &&
           rfx_progressive_quant.cb.ll3 == 2 &&
           rfx_progressive_quant.cr.ll3 == 3);
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
    PCHECK(rdp_dynamic_channel_parse_compressed_data_first(dyn_data_first_compressed,
                                                           sizeof(dyn_data_first_compressed),
                                                           &dyn_first_compressed_pdu) == LIBRDP_STATUS_OK);
    PCHECK(dyn_first_compressed_pdu.channel_id == 7 &&
           dyn_first_compressed_pdu.total_length == 300 &&
           dyn_first_compressed_pdu.data_len == 3 &&
           dyn_first_compressed_pdu.data[1] == 0x06);
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
    PCHECK(rdp_graphics_parse_delete_surface(graphics_delete_surface,
                                             sizeof(graphics_delete_surface),
                                             &graphics_delete) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete.surface_id == 0x1234);
    PCHECK(rdp_graphics_parse_map_surface_to_output(graphics_map_output,
                                                    sizeof(graphics_map_output),
                                                    &graphics_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_map.surface_id == 0x1234 &&
           graphics_map.output_origin_x == 10 &&
           graphics_map.output_origin_y == 20);
    PCHECK(rdp_graphics_parse_map_surface_to_scaled_output(graphics_scaled_map_output,
                                                           sizeof(graphics_scaled_map_output),
                                                           &graphics_scaled_map) == LIBRDP_STATUS_OK);
    PCHECK(graphics_scaled_map.surface_id == 0x1234 &&
           graphics_scaled_map.output_origin_x == 10 &&
           graphics_scaled_map.output_origin_y == 20 &&
           graphics_scaled_map.target_width == 1024 &&
           graphics_scaled_map.target_height == 768);
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
    PCHECK(rdp_graphics_parse_avc420_stream(graphics_avc420_stream,
                                            sizeof(graphics_avc420_stream),
                                            &graphics_avc420) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc420.meta.rect_count == 1 &&
           graphics_avc420.bitstream_len == 4 &&
           graphics_avc420.bitstream[3] == 0x65);
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
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_luma,
                                            sizeof(graphics_avc444_luma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_LUMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
    PCHECK(rdp_graphics_parse_avc444_stream(graphics_avc444_chroma,
                                            sizeof(graphics_avc444_chroma),
                                            &graphics_avc444) == LIBRDP_STATUS_OK);
    PCHECK(graphics_avc444.lc == RDP_GRAPHICS_AVC444_LC_CHROMA &&
           graphics_avc444.has_stream1 &&
           !graphics_avc444.has_stream2);
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
    PCHECK(rdp_graphics_progressive_parse_frame_begin(graphics_progressive_stream + 10,
                                                      sizeof(graphics_progressive_stream) - 10u,
                                                      &graphics_progressive_frame_begin) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_frame_begin.frame_index == 1 &&
           graphics_progressive_frame_begin.region_count == 1);
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
    PCHECK(rdp_graphics_progressive_parse_region(graphics_progressive_empty_region,
                                                 sizeof(graphics_progressive_empty_region),
                                                 &graphics_progressive_region) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_region.tile_count == 0 &&
           graphics_progressive_region.tile_data_size == 0 &&
           graphics_progressive_region.tiles_len == 0);
    PCHECK(rdp_graphics_progressive_parse_region_rect(graphics_progressive_region_rect,
                                                      sizeof(graphics_progressive_region_rect),
                                                      &graphics_progressive_rect) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_rect.left == 640 &&
           graphics_progressive_rect.top == 288 &&
           graphics_progressive_rect.right == 704 &&
           graphics_progressive_rect.bottom == 320);
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
    PCHECK(rdp_graphics_progressive_parse_frame_end(graphics_progressive_stream + 94,
                                                    sizeof(graphics_progressive_stream) - 94u) ==
           LIBRDP_STATUS_OK);
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
    PCHECK(rdp_graphics_progressive_parse_tile_upgrade(graphics_progressive_tile_upgrade,
                                                       sizeof(graphics_progressive_tile_upgrade),
                                                       &graphics_progressive_upgrade) == LIBRDP_STATUS_OK);
    PCHECK(graphics_progressive_upgrade.block_type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE &&
           graphics_progressive_upgrade.x_idx == 3 &&
           graphics_progressive_upgrade.y_idx == 4 &&
           graphics_progressive_upgrade.y_srl_data[0] == 0x11 &&
           graphics_progressive_upgrade.cr_raw_data[0] == 0x66);
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
    PCHECK(rdp_graphics_parse_surface_to_cache(graphics_surface_to_cache,
                                               sizeof(graphics_surface_to_cache),
                                               &graphics_surface_cache) == LIBRDP_STATUS_OK);
    PCHECK(graphics_surface_cache.surface_id == 0x1234 &&
           graphics_surface_cache.cache_key == 0x0102030405060708ull &&
           graphics_surface_cache.cache_slot == 0x42 &&
           graphics_surface_cache.rect_src.left == 1);
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface),
                                               &graphics_cache_surface) == LIBRDP_STATUS_OK);
    PCHECK(graphics_cache_surface.cache_slot == 0x42 &&
           graphics_cache_surface.surface_id == 0x1234 &&
           graphics_cache_surface.dest_points_count == 2 &&
           graphics_cache_surface.dest_points_len == 8);
    PCHECK(rdp_graphics_parse_cache_to_surface(graphics_cache_to_surface,
                                               sizeof(graphics_cache_to_surface) - 1u,
                                               &graphics_cache_surface) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_graphics_parse_evict_cache_entry(graphics_evict_cache,
                                                sizeof(graphics_evict_cache),
                                                &graphics_evict) == LIBRDP_STATUS_OK);
    PCHECK(graphics_evict.cache_slot == 0x42);
    PCHECK(rdp_graphics_parse_delete_encoding_context(graphics_delete_context_pdu,
                                                      sizeof(graphics_delete_context_pdu),
                                                      &graphics_delete_context) == LIBRDP_STATUS_OK);
    PCHECK(graphics_delete_context.surface_id == 0x1234 &&
           graphics_delete_context.codec_context_id == 0x11223344u);
    PCHECK(rdp_graphics_parse_start_frame(graphics_start_frame,
                                          sizeof(graphics_start_frame),
                                          &graphics_start) == LIBRDP_STATUS_OK);
    PCHECK(graphics_start.timestamp == 0x01020304 && graphics_start.frame_id == 0x11223344);
    PCHECK(rdp_graphics_parse_end_frame(graphics_end_frame,
                                        sizeof(graphics_end_frame),
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
    PCHECK(rdp_buffer_append_u16_le(&graphics_reset_pdu, RDP_GRAPHICS_CMDID_RESET_GRAPHICS) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u16_le(&graphics_reset_pdu, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&graphics_reset_pdu, 340) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&graphics_reset_pdu, 1024) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&graphics_reset_pdu, 768) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&graphics_reset_pdu, 0) == LIBRDP_STATUS_OK);
    while (graphics_reset_pdu.length < 340)
        PCHECK(rdp_buffer_append_u8(&graphics_reset_pdu, 0) == LIBRDP_STATUS_OK);
    PCHECK(rdp_graphics_parse_reset(graphics_reset_pdu.data,
                                    graphics_reset_pdu.length,
                                    &graphics_reset) == LIBRDP_STATUS_OK);
    PCHECK(graphics_reset.width == 1024 &&
           graphics_reset.height == 768 &&
           graphics_reset.monitor_count == 0);
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
    uint32_t remove_ids[2] = {0x10203040u, 0x50607080u};

    rdp_buffer_init(&buffer);

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

    PCHECK(rdp_device_redirection_write_io_completion(&buffer,
                                                      request.device_id,
                                                      request.completion_id,
                                                      RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                      request.payload,
                                                      request.payload_len) == LIBRDP_STATUS_OK);
    PCHECK(rdp_device_redirection_parse_io_completion(buffer.data, buffer.length, &completion) ==
           LIBRDP_STATUS_OK);
    PCHECK(completion.device_id == request.device_id);
    PCHECK(completion.completion_id == request.completion_id);
    PCHECK(completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS);
    PCHECK(completion.payload_len == 2 && completion.payload[0] == 0xaa && completion.payload[1] == 0xbb);

    rdp_buffer_free(&buffer);
    return 0;
}

static int test_filesystem_redirection_channel(void)
{
    const uint8_t path[] = {'f', 0, 'i', 0, 'l', 0, 'e', 0, 0, 0};
    const uint8_t data[] = {'a', 'b', 'c'};
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
    rdp_buffer request;
    rdp_buffer response;

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
    PCHECK(response.length == 20u);
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
    PCHECK(response.length == 21u);

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
    rdp_printer_redirection_announce announce;
    rdp_printer_redirection_announce parsed_announce;
    rdp_printer_redirection_cache_event event;
    rdp_printer_redirection_xps_mode mode;
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

    PCHECK(rdp_device_redirection_write_header(&packet,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, RDP_PRINTER_REDIRECTION_CACHE_ADD) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, "PRN1", 5) == LIBRDP_STATUS_OK);
    PCHECK(test_append_zeroes(&packet, 3) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(pnp)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(driver)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(cache)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, pnp, sizeof(pnp)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, driver, sizeof(driver)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, printer, sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, cache, sizeof(cache)) == LIBRDP_STATUS_OK);
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

    PCHECK(rdp_device_redirection_write_header(&packet,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, RDP_PRINTER_REDIRECTION_CACHE_UPDATE) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(cache)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, printer, sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, cache, sizeof(cache)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_UPDATE);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_device_redirection_write_header(&packet,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, RDP_PRINTER_REDIRECTION_CACHE_RENAME) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, (uint32_t)sizeof(driver)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, printer, sizeof(printer)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append(&packet, driver, sizeof(driver)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_cache_event(packet.data, packet.length, &event) ==
           LIBRDP_STATUS_OK);
    PCHECK(event.event_id == RDP_PRINTER_REDIRECTION_CACHE_RENAME);
    PCHECK(event.old_printer_name_len == sizeof(printer));
    PCHECK(event.new_printer_name_len == sizeof(driver));
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_device_redirection_write_header(&packet,
                                               RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER,
                                               RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, 0x10203040u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_buffer_append_u32_le(&packet, 1u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_printer_redirection_parse_xps_mode(packet.data, packet.length, &mode) ==
           LIBRDP_STATUS_OK);
    PCHECK(mode.printer_id == 0x10203040u && mode.flags == 1u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);

    PCHECK(rdp_printer_redirection_write_create_response(&packet, 1, 2, 0, 3) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 20u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_close_response(&packet, 1, 2, 0) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 20u);
    rdp_buffer_free(&packet);
    rdp_buffer_init(&packet);
    PCHECK(rdp_printer_redirection_write_write_response(&packet, 1, 2, 0, 4) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == 21u);

    rdp_buffer_free(&packet);
    rdp_buffer_free(&buffer);
    return 0;
}

int test_protocol(void)
{
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
    if (test_printer_redirection_channel() != 0)
        return 1;
    return 0;
}
