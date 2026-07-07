#include <librdp/session.h>

#include "client/settings_internal.h"
#include "common/trace.h"
#include "graphics/bitmap.h"
#include "nla/credssp.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/transport.h"
#include "input/input.h"

#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct librdp_session
{
    librdp_settings* settings;
    librdp_surface* surface;
    rdp_transport transport;
    uint16_t mcs_user_id;
    librdp_session_state state;
    librdp_event_callback callback;
    void* callback_data;
};

static void rdp_session_emit(librdp_session* session, const librdp_event* event)
{
    if (session && session->callback && event)
        session->callback(session, event, session->callback_data);
}

static void rdp_session_set_state(librdp_session* session, librdp_session_state state)
{
    librdp_event event;
    librdp_session_state old_state = LIBRDP_SESSION_IDLE;

    if (!session || session->state == state)
        return;

    old_state = session->state;
    session->state = state;

    event.type = LIBRDP_EVENT_STATE_CHANGED;
    event.data.state.old_state = (int)old_state;
    event.data.state.new_state = (int)state;
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_fail(librdp_session* session, librdp_status status)
{
    librdp_event event;

    rdp_session_set_state(session, LIBRDP_SESSION_FAILED);
    event.type = LIBRDP_EVENT_ERROR;
    event.data.error.status = status;
    rdp_session_emit(session, &event);
    return status;
}

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
            rdp_trace_hexdump(event, packet.data, packet.length);
        status = rdp_transport_write_all(&session->transport, packet.data, packet.length);
    }

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
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
    rdp_trace_hexdump(event, packet->data, packet->length);
    status = rdp_tpkt_parse(packet->data, packet->length, &parsed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_x224_parse_data(parsed.payload, parsed.payload_len, pdu, pdu_len);
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
        uint32_t row = 0;
        size_t stride = 0;

        if (rect->bits_per_pixel != 32 || rect->flags != 0)
            return LIBRDP_STATUS_UNSUPPORTED;
        stride = (size_t)rect->width * 4u;
        if ((size_t)rect->height > SIZE_MAX / stride || rect->data_len < stride * rect->height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (row = 0; row < rect->height; row++)
        {
            const uint8_t* src = rect->data + ((size_t)(rect->height - 1u - row) * stride);
            librdp_status status = librdp_surface_blit_bgra32(session->surface,
                                                              rect->dest_left,
                                                              (uint32_t)rect->dest_top + row,
                                                              rect->width,
                                                              1,
                                                              src,
                                                              stride);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        {
            librdp_event event;
            event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
            event.data.surface.x = rect->dest_left;
            event.data.surface.y = rect->dest_top;
            event.data.surface.width = rect->width;
            event.data.surface.height = rect->height;
            rdp_session_emit(session, &event);
        }
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

librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    rdp_transport_init(&session->transport);
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
    rdp_transport_close(&session->transport);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    free(session);
}

void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data)
{
    if (!session)
        return;
    session->callback = callback;
    session->callback_data = user_data;
}

librdp_status librdp_session_connect(librdp_session* session)
{
    librdp_event event;
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
    rdp_mcs_channel_join_confirm join_confirm;
    rdp_standard_security_context standard_security;
    rdp_credssp_state credssp_state = RDP_CREDSSP_DISABLED;
    const uint8_t* mcs_pdu = NULL;
    size_t mcs_pdu_len = 0;
    uint32_t protocols = 0;
    uint32_t selected_protocol = 0;
    uint32_t server_encryption_method = 0;
    uint32_t server_encryption_level = 0;
    int standard_security_ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_IDLE && session->state != LIBRDP_SESSION_CLOSED &&
        session->state != LIBRDP_SESSION_FAILED)
        return LIBRDP_STATUS_STATE;
    if (!librdp_settings_target(session->settings))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

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
    memset(&standard_security, 0, sizeof(standard_security));

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTING);

    status = rdp_transport_connect(&session->transport,
                                   librdp_settings_target(session->settings),
                                   librdp_settings_port(session->settings),
                                   5000);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    protocols = rdp_security_protocol_mask(librdp_settings_security_mode(session->settings));
    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.start", "protocols=%u", protocols);
    status = rdp_x224_build_connection_request(&x224, librdp_settings_username(session->settings), protocols);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_tpkt_write(&request, x224.data, x224.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.request", request.data, request.length);
    status = rdp_transport_write_all(&session->transport, request.data, request.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_transport_read_tpkt(&session->transport, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.response", reply.data, reply.length);
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
    if (confirm.negotiation.present && !rdp_security_protocol_supported(confirm.negotiation.selected_protocol))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.unsupported", "selected_protocol=%u",
                        confirm.negotiation.selected_protocol);
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto fail;
    }

    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.done", "selected_protocol=%u",
                    confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0);
    selected_protocol = confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0;
    if (selected_protocol == RDP_X224_PROTOCOL_TLS || selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        status = rdp_transport_start_tls(&session->transport, librdp_settings_target(session->settings));
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "transport.tls.ready", "selected_protocol=%u", selected_protocol);
    }
    if (selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        rdp_buffer credssp_request;
        rdp_buffer credssp_reply;
        rdp_credssp_ts_request ts_response;

        rdp_buffer_init(&credssp_request);
        rdp_buffer_init(&credssp_reply);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.start", "state=begin");
        status = rdp_credssp_begin(true, &credssp_state);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_negotiate_request(&credssp_request,
                                                         "librdp",
                                                         librdp_settings_domain(session->settings));
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.negotiate",
                            "token_len=%u",
                            (unsigned)credssp_request.length);
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
        }
        rdp_buffer_free(&credssp_reply);
        rdp_buffer_free(&credssp_request);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.failed", "status=%d", (int)status);
            goto fail;
        }
        status = LIBRDP_STATUS_UNSUPPORTED;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.failed", "status=%d", (int)status);
        goto fail;
    }

    {
        rdp_gcc_client_config config;
        config.desktop_width = (uint16_t)librdp_settings_width(session->settings);
        config.desktop_height = (uint16_t)librdp_settings_height(session->settings);
        config.requested_protocols = selected_protocol;
        config.client_name = "librdp";

        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.initial", "width=%u height=%u selected_protocol=%u",
                        (unsigned)config.desktop_width,
                        (unsigned)config.desktop_height,
                        config.requested_protocols);
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
        if (server_data.has_network)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.network",
                            "mcs_channel_id=%u channel_count=%u",
                            server_data.mcs_channel_id,
                            server_data.channel_count);
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

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_channel_join_request(&mcs, session->mcs_user_id, session->mcs_user_id);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.channel_join.request", "channel_id=%u", session->mcs_user_id);
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.channel_join.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.channel_join.confirm");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_channel_join_confirm(mcs_pdu, mcs_pdu_len, &join_confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (join_confirm.result != 0 || join_confirm.initiator != session->mcs_user_id ||
        join_confirm.channel_id != session->mcs_user_id)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.channel_join.failed",
                        "result=%u initiator=%u channel_id=%u",
                        join_confirm.result,
                        join_confirm.initiator,
                        join_confirm.channel_id);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.channel_join.confirm", "channel_id=%u", join_confirm.channel_id);

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_channel_join_request(&mcs, session->mcs_user_id, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.channel_join.request", "channel_id=%u", RDP_MCS_GLOBAL_CHANNEL_ID);
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.channel_join.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.channel_join.confirm");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_channel_join_confirm(mcs_pdu, mcs_pdu_len, &join_confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (join_confirm.result != 0 || join_confirm.initiator != session->mcs_user_id ||
        join_confirm.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.channel_join.failed",
                        "result=%u initiator=%u channel_id=%u",
                        join_confirm.result,
                        join_confirm.initiator,
                        join_confirm.channel_id);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.channel_join.confirm", "channel_id=%u", join_confirm.channel_id);

    if (server_encryption_method != 0 || server_encryption_level != 0)
    {
        uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
        rdp_security_public_key public_key;
        rdp_buffer encrypted_client_random;

        memset(&public_key, 0, sizeof(public_key));
        rdp_buffer_init(&encrypted_client_random);
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
            status = rdp_security_standard_client_init(&standard_security,
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
    }

    {
        rdp_client_info info;
        memset(&info, 0, sizeof(info));
        info.domain = librdp_settings_domain(session->settings);
        info.username = librdp_settings_username(session->settings);
        info.password = rdp_settings_password_internal(session->settings);
        info.alternate_shell = NULL;
        info.working_dir = NULL;
        if (standard_security_ready)
            status = rdp_security_write_encrypted_client_info_pdu(&security_payload, &standard_security, &info);
        else
            status = rdp_security_write_client_info_pdu(&security_payload, &info);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
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
                    librdp_settings_domain(session->settings) ? 1u : 0u,
                    librdp_settings_username(session->settings) ? 1u : 0u,
                    standard_security_ready ? 1u : 0u);
    status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.client_info.pdu", 0);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.client_info.done", "status=sent");

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);

    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = 0;
    event.data.surface.y = 0;
    event.data.surface.width = librdp_surface_width(session->surface);
    event.data.surface.height = librdp_surface_height(session->surface);
    rdp_session_emit(session, &event);

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
    rdp_security_standard_clear(&standard_security);
    return LIBRDP_STATUS_OK;

fail:
    rdp_transport_close(&session->transport);
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
    rdp_security_standard_clear(&standard_security);
    return rdp_session_fail(session, status);
}

librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms)
{
    short revents = 0;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&packet);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.start", "timeout_ms=%d", timeout_ms);
    if (session->state == LIBRDP_SESSION_CONNECTED)
        rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.done", "status=timeout");
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&packet);
        return status;
    }
    if ((revents & POLLIN) != 0)
    {
        const uint8_t* pdu = NULL;
        size_t pdu_len = 0;
        rdp_mcs_send_data_indication indication;
        rdp_slowpath_share_control_header slow_header;
        status = rdp_session_read_mcs_pdu(session, &packet, &pdu, &pdu_len, "rdp.slowpath.pdu");
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        status = rdp_mcs_parse_send_data_indication(pdu, pdu_len, &indication);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.send_data.indication",
                        "initiator=%u channel_id=%u payload_len=%u",
                        indication.initiator,
                        indication.channel_id,
                        (unsigned)indication.payload_len);
        status = rdp_slowpath_parse_share_control_header(indication.payload, indication.payload_len, &slow_header);
        if (status == LIBRDP_STATUS_OK &&
            (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        {
            rdp_slowpath_demand_active demand;
            rdp_buffer confirm;
            rdp_buffer send_data;

            rdp_buffer_init(&confirm);
            rdp_buffer_init(&send_data);
            status = rdp_slowpath_parse_demand_active(indication.payload, indication.payload_len, &demand);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.activation.demand_active",
                                "share_id=%u capabilities=%u",
                                demand.share_id,
                                demand.capabilities.count);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_slowpath_write_confirm_active(&confirm,
                                                           demand.share_id,
                                                           session->mcs_user_id,
                                                           (uint16_t)librdp_surface_width(session->surface),
                                                           (uint16_t)librdp_surface_height(session->surface),
                                                           "librdp");
            if (status == LIBRDP_STATUS_OK)
                status = rdp_security_write_send_data_request(&send_data,
                                                              session->mcs_user_id,
                                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                              confirm.data,
                                                              confirm.length);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_mcs_pdu(session, &send_data, "rdp.activation.confirm_active", 1);
            rdp_buffer_free(&send_data);
            rdp_buffer_free(&confirm);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.confirm_active", "share_id=%u", demand.share_id);
        }
        else if (status == LIBRDP_STATUS_OK && (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
        {
            rdp_slowpath_data_pdu data_pdu;

            status = rdp_slowpath_parse_data_pdu(indication.payload, indication.payload_len, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.slowpath.data",
                            "type=%u compressed_type=%u payload_len=%u",
                            data_pdu.pdu_type2,
                            data_pdu.compressed_type,
                            (unsigned)data_pdu.payload_len);
            if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE && data_pdu.compressed_type == 0)
            {
                rdp_bitmap_update update;
                status = rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &update);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_bitmap_update(session, &update);
                if (status != LIBRDP_STATUS_OK)
                {
                    rdp_buffer_free(&packet);
                    return rdp_session_fail(session, status);
                }
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.bitmap_update", "rectangles=%u", update.count);
            }
        }
    }

    rdp_buffer_free(&packet);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.done", "status=idle");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE)
        return LIBRDP_STATUS_OK;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_transport_close(&session->transport);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = librdp_surface_resize(session->surface, width, height);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = 0;
    event.data.surface.y = 0;
    event.data.surface.width = width;
    event.data.surface.height = height;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.display_control.layout_sent", "width=%u height=%u", width, height);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* key)
{
    uint16_t flags = 0;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    status = rdp_input_make_keyboard_flags(key, &flags);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_KEY_SENT;
    event.data.key = *key;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.input.send", "kind=keyboard scancode=%u flags=%u", key->scancode, flags);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* mouse)
{
    uint16_t flags = 0;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    status = rdp_input_make_pointer_flags(mouse, &flags);
    if (status != LIBRDP_STATUS_OK)
        return status;

    event.type = LIBRDP_EVENT_MOUSE_SENT;
    event.data.mouse = *mouse;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.input.send", "kind=mouse x=%u y=%u flags=%u", mouse->x, mouse->y, flags);
    return LIBRDP_STATUS_OK;
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

const librdp_surface* librdp_session_get_surface(const librdp_session* session)
{
    return session ? session->surface : NULL;
}
