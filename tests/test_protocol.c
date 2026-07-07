#include "channels/virtual_channel.h"
#include "clipboard/clipboard.h"
#include "common/buffer.h"
#include "common/stream.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/capabilities.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

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

static int test_tpkt_x224(void)
{
    rdp_buffer x224;
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
    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

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
    config.requested_protocols = 0;
    config.client_name = "librdp";
    PCHECK(rdp_gcc_write_client_data_blocks(&client_blocks, &config) == LIBRDP_STATUS_OK);
    PCHECK(rdp_gcc_parse_client_data_blocks(client_blocks.data, client_blocks.length, &summary) == LIBRDP_STATUS_OK);
    PCHECK(summary.has_core && summary.has_security && summary.has_network);
    PCHECK(summary.desktop_width == 1024 && summary.desktop_height == 768);
    PCHECK(summary.version == 0x00080004u);
    PCHECK(summary.channel_count == 0);
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

static int test_path_security_license_channels(void)
{
    const uint8_t fast_short[] = {0x00, 0x06, 1, 2, 3, 4};
    const uint8_t fast_long[] = {0x40, 0x80, 0x08, 1, 2, 3, 4, 5};
    const uint8_t slow[] = {0x06, 0x00, 0x13, 0x00, 0xea, 0x03};
    const uint8_t license[] = {
        0xff, 0x03, 0x12, 0x00,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 2, 0,
        9, 8
    };
    const uint8_t channel[] = {3, 0, 0, 0, 0x10, 0, 0, 0, 1, 2, 3};
    const uint8_t clip[] = {1, 0, 2, 0, 3, 0, 0, 0, 4, 5, 6};
    const uint8_t encrypted_random[] = {1, 2, 3, 4, 5};
    rdp_fastpath_header fast;
    rdp_slowpath_share_control_header slow_header;
    rdp_license_error_alert alert;
    rdp_virtual_channel_packet vc;
    rdp_clipboard_packet cb;
    rdp_credssp_state cred_state;
    rdp_buffer security;
    rdp_buffer send_data;
    rdp_client_info info;
    rdp_client_info_summary info_summary;

    rdp_buffer_init(&security);
    rdp_buffer_init(&send_data);

    PCHECK(rdp_fastpath_parse_header(fast_short, sizeof(fast_short), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 6 && fast.header_length == 2 && !fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, sizeof(fast_long), &fast) == LIBRDP_STATUS_OK);
    PCHECK(fast.length == 8 && fast.header_length == 3 && fast.long_length);
    PCHECK(rdp_fastpath_parse_header(fast_long, 2, &fast) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_slowpath_parse_share_control_header(slow, sizeof(slow), &slow_header) == LIBRDP_STATUS_OK);
    PCHECK(slow_header.total_length == 6 && slow_header.pdu_type == 0x13);

    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_STANDARD) == RDP_X224_PROTOCOL_STANDARD);
    PCHECK(rdp_security_protocol_mask(LIBRDP_SECURITY_TLS) == RDP_X224_PROTOCOL_TLS);
    PCHECK(!rdp_security_protocol_supported(RDP_X224_PROTOCOL_TLS));
    PCHECK(rdp_security_protocol_supported(RDP_X224_PROTOCOL_STANDARD));

    memset(&info, 0, sizeof(info));
    info.domain = "D";
    info.username = "user";
    info.password = "secret";
    PCHECK(rdp_security_write_client_info_pdu(&security, &info) == LIBRDP_STATUS_OK);
    PCHECK(rdp_security_parse_client_info_pdu(security.data, security.length, &info_summary) == LIBRDP_STATUS_OK);
    PCHECK(info_summary.domain_bytes == 2);
    PCHECK(info_summary.username_bytes == 8);
    PCHECK(info_summary.password_bytes == 12);
    PCHECK((info_summary.flags & 0x00000010u) != 0);
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
    PCHECK(security.data[0] == 0x01 && security.data[1] == 0x00);
    PCHECK(security.data[4] == (uint8_t)(sizeof(encrypted_random) + 8u));

    PCHECK(rdp_license_parse_error_alert(license, sizeof(license), &alert) == LIBRDP_STATUS_OK);
    PCHECK(alert.error_code == 1 && alert.state_transition == 2 && alert.blob_length == 2 && alert.blob[1] == 8);
    PCHECK(rdp_license_parse_error_alert(license, 15, &alert) == LIBRDP_STATUS_PROTOCOL_ERROR);

    PCHECK(rdp_virtual_channel_parse_packet(channel, sizeof(channel), &vc) == LIBRDP_STATUS_OK);
    PCHECK(vc.length == 3 && vc.flags == 0x10 && vc.payload[2] == 3);
    PCHECK(rdp_clipboard_parse_packet(clip, sizeof(clip), &cb) == LIBRDP_STATUS_OK);
    PCHECK(cb.type == 1 && cb.flags == 2 && cb.payload_len == 3 && cb.payload[0] == 4);

    PCHECK(rdp_credssp_begin(false, &cred_state) == LIBRDP_STATUS_OK && cred_state == RDP_CREDSSP_DISABLED);
    PCHECK(rdp_credssp_begin(true, &cred_state) == LIBRDP_STATUS_UNSUPPORTED && cred_state == RDP_CREDSSP_FAILED);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security);
    return 0;
}

int test_protocol(void)
{
    if (test_tpkt_x224() != 0)
        return 1;
    if (test_mcs_gcc_capabilities() != 0)
        return 1;
    if (test_path_security_license_channels() != 0)
        return 1;
    return 0;
}
