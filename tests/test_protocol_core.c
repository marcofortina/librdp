/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: protocol-core conformance vectors.
 * Coverage: TPKT, X.224, GCC client naming, MCS, and capability-set vectors.
 * Bug classes: malformed handshake PDUs, duplicate capabilities, and fixed-field bounds.
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
#include <stdlib.h>
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

/*
 * Covers TPKT/X.224 framing variants that influence security negotiation and
 * server activation. The fixture keeps standard no-negotiation, explicit
 * standard negotiation, TLS/NLA negotiation, malformed TPKT length, and X.224
 * data wrapping in one sequence so parser offsets and selectedProtocol handling
 * cannot drift independently.
 */
static int test_tpkt_x224(void)
{
    rdp_buffer x224;
    rdp_buffer standard_x224;
    rdp_buffer standard_confirm;
    rdp_buffer x224_data;
    rdp_buffer packet;
    rdp_tpkt parsed;
    rdp_x224_connection_request request;
    rdp_x224_connection_confirm confirm;
    const uint8_t* mcs_payload = NULL;
    size_t mcs_payload_len = 0;
    const uint8_t cc_payload[] = {
        0x0e, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00,
        0x02, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t cc_no_negotiation[] = {
        0x06, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00
    };
    const uint8_t cc_tls_selected[] = {
        0x0e, 0xd0, 0x12, 0x34, 0x56, 0x78, 0x00,
        0x02, 0x00, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    const uint8_t cr_standard_negotiation[] = {
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const uint8_t bad_tpkt[] = {0x03, 0x00, 0x00, 0x03};

    rdp_buffer_init(&x224);
    rdp_buffer_init(&standard_x224);
    rdp_buffer_init(&standard_confirm);
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    PCHECK(rdp_x224_build_connection_request(&standard_x224, NULL, RDP_X224_PROTOCOL_STANDARD) ==
           LIBRDP_STATUS_OK);
    PCHECK(standard_x224.length == 7);
    PCHECK(standard_x224.data[0] == 6 && standard_x224.data[1] == 0xe0);
    PCHECK(rdp_x224_parse_connection_request(cr_standard_negotiation,
                                             sizeof(cr_standard_negotiation),
                                             &request) == LIBRDP_STATUS_OK);
    PCHECK(request.negotiation.present);
    PCHECK(request.requested_protocols == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_x224_build_connection_confirm_ex(&standard_confirm,
                                                RDP_X224_PROTOCOL_STANDARD,
                                                true) == LIBRDP_STATUS_OK);
    PCHECK(rdp_tpkt_parse(standard_confirm.data, standard_confirm.length, &parsed) == LIBRDP_STATUS_OK);
    PCHECK(rdp_x224_parse_connection_confirm(parsed.payload,
                                             parsed.payload_len,
                                             &confirm) == LIBRDP_STATUS_OK);
    PCHECK(confirm.negotiation.present);
    PCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_STANDARD);

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
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO,
                                         confirm.negotiation.present,
                                         confirm.negotiation.selected_protocol) == false);
    PCHECK(rdp_x224_parse_connection_confirm(cc_no_negotiation,
                                             sizeof(cc_no_negotiation),
                                             &confirm) == LIBRDP_STATUS_OK);
    PCHECK(!confirm.negotiation.present);
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_AUTO,
                                         confirm.negotiation.present,
                                         RDP_X224_PROTOCOL_STANDARD) == false);
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_STANDARD,
                                         confirm.negotiation.present,
                                         RDP_X224_PROTOCOL_STANDARD) == true);
    PCHECK(rdp_x224_parse_connection_confirm(cc_tls_selected,
                                             sizeof(cc_tls_selected),
                                             &confirm) == LIBRDP_STATUS_OK);
    PCHECK(confirm.negotiation.present);
    PCHECK(confirm.negotiation.selected_protocol == RDP_X224_PROTOCOL_TLS);
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_NLA,
                                         confirm.negotiation.present,
                                         confirm.negotiation.selected_protocol) == false);
    PCHECK(rdp_security_protocol_allowed(LIBRDP_SECURITY_TLS,
                                         confirm.negotiation.present,
                                         confirm.negotiation.selected_protocol) == true);
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
    rdp_buffer_free(&standard_confirm);
    rdp_buffer_free(&standard_x224);
    rdp_buffer_free(&x224);
    return 0;
}

/*
 * Covers the complete 16-bit TPKT wire-length boundary and verifies that
 * rejected lengths cannot alter a caller buffer that already contains data.
 */
static int test_tpkt_write_boundaries(void)
{
    const size_t maximum_payload = (size_t)UINT16_MAX - 4u;
    const uint8_t prefix[] = {0xa5u, 0x5au, 0x11u};
    uint8_t marker = 0x7cu;
    uint8_t* payload = NULL;
    uint8_t* original_data = NULL;
    size_t original_length = 0;
    size_t original_capacity = 0;
    rdp_buffer packet;
    rdp_tpkt parsed;

    rdp_buffer_init(&packet);
    PCHECK(rdp_buffer_append(&packet, prefix, sizeof(prefix)) == LIBRDP_STATUS_OK);
    original_data = packet.data;
    original_length = packet.length;
    original_capacity = packet.capacity;

    PCHECK(rdp_tpkt_write(&packet, &marker, maximum_payload + 1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(packet.data == original_data);
    PCHECK(packet.length == original_length);
    PCHECK(packet.capacity == original_capacity);
    PCHECK(memcmp(packet.data, prefix, sizeof(prefix)) == 0);

    PCHECK(rdp_tpkt_write(&packet, &marker, SIZE_MAX) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(packet.data == original_data);
    PCHECK(packet.length == original_length);
    PCHECK(packet.capacity == original_capacity);
    PCHECK(memcmp(packet.data, prefix, sizeof(prefix)) == 0);
    rdp_buffer_free(&packet);

    payload = (uint8_t*)malloc(maximum_payload);
    PCHECK(payload != NULL);
    memset(payload, 0x3cu, maximum_payload);
    rdp_buffer_init(&packet);
    PCHECK(rdp_tpkt_write(&packet, payload, maximum_payload) == LIBRDP_STATUS_OK);
    PCHECK(packet.length == (size_t)UINT16_MAX);
    PCHECK(packet.data[0] == 3u && packet.data[1] == 0u);
    PCHECK(packet.data[2] == 0xffu && packet.data[3] == 0xffu);
    PCHECK(rdp_tpkt_parse(packet.data, packet.length, &parsed) == LIBRDP_STATUS_OK);
    PCHECK(parsed.payload_len == maximum_payload);
    PCHECK(parsed.payload[0] == 0x3cu && parsed.payload[maximum_payload - 1u] == 0x3cu);

    rdp_buffer_free(&packet);
    free(payload);
    return 0;
}

#define TEST_GCC_BASE_CLIENT_BLOCKS_WIRE_LENGTH 254u
#define TEST_GCC_CORE_CLIENT_NAME_OFFSET 24u
#define TEST_GCC_CORE_CLIENT_NAME_BYTES 32u

/*
 * Regression: GCC client-name serialization keeps a fixed 32-byte UTF-16LE
 * field for NULL, empty, short, exact-fit, and overlong names. The test locks
 * the total wire length so ASan/UBSan builds catch stale reads, missing
 * terminators, and buffer growth regressions.
 */
static int test_gcc_client_name_regression(void)
{
    const struct
    {
        const char* name;
        const char* wire_name;
        size_t wire_chars;
    } cases[] = {
        {NULL, "librdp", 6u},
        {"", "", 0u},
        {"a", "a", 1u},
        {"exactly-15-char", "exactly-15-char", 15u},
        {"this-client-name-is-longer-than-the-fixed-field", "this-client-nam", 15u}
    };
    rdp_gcc_client_config config;
    rdp_gcc_client_data_summary summary;
    size_t i = 0;

    memset(&config, 0, sizeof(config));
    config.desktop_width = 1024;
    config.desktop_height = 768;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        rdp_buffer client_blocks;

        rdp_buffer_init(&client_blocks);
        config.client_name = cases[i].name;
        PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
        PCHECK(client_blocks.length == TEST_GCC_BASE_CLIENT_BLOCKS_WIRE_LENGTH);
        PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) ==
               LIBRDP_STATUS_OK);
        PCHECK(summary.has_core && summary.has_security && summary.has_network);
        PCHECK(summary.desktop_width == 1024 && summary.desktop_height == 768);
        for (size_t j = 0; j < TEST_GCC_CORE_CLIENT_NAME_BYTES / 2u; j++)
        {
            uint8_t expected = j < cases[i].wire_chars ? (uint8_t)cases[i].wire_name[j] : 0;

            PCHECK(client_blocks.data[TEST_GCC_CORE_CLIENT_NAME_OFFSET + (j * 2u)] == expected);
            PCHECK(client_blocks.data[TEST_GCC_CORE_CLIENT_NAME_OFFSET + (j * 2u) + 1u] == 0);
        }
        rdp_buffer_free(&client_blocks);
    }

    return 0;
}

/*
 * Coverage: validates MCS, GCC, and capability vectors, including nested
 * length fields and capability serialization round trips.
 */
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
    const uint8_t duplicate_caps[] = {
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x04, 0x00,
        0x01, 0x00, 0x04, 0x00
    };
    const uint8_t unknown_caps[] = {
        0x01, 0x00, 0x00, 0x00,
        0xfe, 0x7f, 0x04, 0x00
    };
    rdp_stream stream;
    size_t length = 0;
    rdp_mcs_connect_response response;
    rdp_gcc_user_data_block block;
    rdp_capability_list list;
    rdp_buffer ber;
    rdp_buffer client_blocks;
    rdp_buffer server_blocks;
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
    rdp_buffer_init(&server_blocks);
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
    {
        const uint8_t multitransport_block[] = {
            0x08, 0x0c, 0x08, 0x00, 0x05, 0x03, 0x00, 0x00
        };

        PCHECK(rdp_buffer_append(&server_blocks,
                                 gcc_server_blocks,
                                 sizeof(gcc_server_blocks)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_buffer_append(&server_blocks,
                                 multitransport_block,
                                 sizeof(multitransport_block)) == LIBRDP_STATUS_OK);
        PCHECK(rdp_gcc_parse_server_data_blocks(server_blocks.data,
                                                server_blocks.length,
                                                &server_data) == LIBRDP_STATUS_OK);
        PCHECK(server_data.has_multitransport &&
               server_data.multitransport_flags ==
                   (RDP_GCC_MULTITRANSPORT_UDP_FECR |
                    RDP_GCC_MULTITRANSPORT_UDP_FECL |
                    RDP_GCC_MULTITRANSPORT_UDP_PREFERRED |
                    RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP));
        server_blocks.data[sizeof(gcc_server_blocks) + 4u] = 0x00u;
        server_blocks.data[sizeof(gcc_server_blocks) + 5u] = 0x01u;
        PCHECK(rdp_gcc_parse_server_data_blocks(server_blocks.data,
                                                server_blocks.length,
                                                &server_data) == LIBRDP_STATUS_PROTOCOL_ERROR);
        server_blocks.data[sizeof(gcc_server_blocks) + 5u] = 0x00u;
        server_blocks.data[sizeof(gcc_server_blocks) + 7u] = 0x80u;
        PCHECK(rdp_gcc_parse_server_data_blocks(server_blocks.data,
                                                server_blocks.length,
                                                &server_data) == LIBRDP_STATUS_PROTOCOL_ERROR);
        rdp_buffer_free(&server_blocks);
        rdp_buffer_init(&server_blocks);
    }
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
    {
        const rdp_capability_list valid_list = list;

        PCHECK(rdp_capabilities_parse(caps, 5, &list) == LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&list, &valid_list, sizeof(list)) == 0);
        PCHECK(rdp_capabilities_parse(duplicate_caps, sizeof(duplicate_caps), &list) ==
               LIBRDP_STATUS_PROTOCOL_ERROR);
        PCHECK(memcmp(&list, &valid_list, sizeof(list)) == 0);
    }
    PCHECK(rdp_capabilities_parse(unknown_caps, sizeof(unknown_caps), &list) ==
           LIBRDP_STATUS_OK);
    PCHECK(list.count == 1u && list.sets[0].type == 0x7ffeu);
    PCHECK(rdp_capabilities_find(&list, RDP_CAPABILITY_TYPE_GENERAL) == NULL);

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
    {
        const char* const names[] = {
            NULL,
            "",
            "a",
            "exactly-15-char",
            "this-client-name-is-longer-than-the-fixed-field"
        };
        size_t expected_length = 0;
        size_t i = 0;

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        {
            config.client_name = names[i];
            rdp_buffer_free(&client_blocks);
            rdp_buffer_init(&client_blocks);
            PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
            PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) ==
                   LIBRDP_STATUS_OK);
            if (i == 0)
                expected_length = client_blocks.length;
            PCHECK(client_blocks.length == expected_length);
        }
    }
    rdp_buffer_free(&client_blocks);
    rdp_buffer_init(&client_blocks);
    config.client_name = "librdp";
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
    config.enable_multitransport = 1;
    config.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                  RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                  RDP_GCC_MULTITRANSPORT_UDP_PREFERRED;
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.channel_count == 6);
    PCHECK(summary.has_multitransport &&
           summary.multitransport_flags == config.multitransport_flags);
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
    config.multitransport_flags = 0x80000000u;
    rdp_buffer_free(&client_blocks);
    rdp_buffer_init(&client_blocks);
    PCHECK(rdp_buffer_append_u8(&client_blocks, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(client_blocks.length == 1 && client_blocks.data[0] == 0xa5u);
    config.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                  RDP_GCC_MULTITRANSPORT_UDP_FECL |
                                  RDP_GCC_MULTITRANSPORT_UDP_PREFERRED;
    rdp_buffer_free(&client_blocks);
    rdp_buffer_init(&client_blocks);
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
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
    rdp_buffer_free(&server_blocks);
    rdp_buffer_free(&client_blocks);
    rdp_buffer_free(&ber);
    return 0;
}

/*
 * Coverage: validates audio input/output format negotiation, data framing, UDP
 * audio payloads, and channel close semantics.
 */

int test_protocol_core_vectors(void)
{
    if (test_tpkt_x224() != 0)
        return 1;
    if (test_tpkt_write_boundaries() != 0)
        return 1;
    if (test_gcc_client_name_regression() != 0)
        return 1;
    if (test_mcs_gcc_capabilities() != 0)
        return 1;
    return 0;
}
